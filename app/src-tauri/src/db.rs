//! SQLite event store. One connection guarded by a mutex; writes are batched
//! by the pipeline so the lock is held briefly. Page cache is capped at 2 MB.

use oph_proto::{now_ms, severity_rank, WireEvent};
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value as J};
use std::path::Path;

pub struct Db {
    pub conn: Connection,
}

#[derive(Serialize, Clone, Debug)]
pub struct Alert {
    pub id: i64,
    pub ts: i64,
    pub last_ts: i64,
    pub severity: String,
    pub title: String,
    pub indicator: String,
    pub indicator_type: String,
    pub feed: String,
    pub host: String,
    pub src_ip: Option<String>,
    pub count: i64,
    pub status: String,
    pub explanation: String,
}

pub struct NewAlert<'a> {
    pub severity: &'a str,
    pub title: String,
    pub indicator: &'a str,
    pub indicator_type: &'a str,
    pub feed: &'a str,
    pub host: &'a str,
    pub src_ip: Option<&'a str>,
    pub status: &'a str,
    pub explanation: String,
}

fn kv(rows: Vec<(String, i64)>) -> J {
    J::Array(rows.into_iter().map(|(k, c)| json!({"key": k, "count": c})).collect())
}

impl Db {
    /// Two files:
    /// - `events_dir/events.db` — the event log (big; lives on the chosen storage drive)
    /// - `state_dir/state.db`   — alerts, lists, devices, agent keys, feeds, kv (small; always on this PC)
    /// The state file is ATTACHed as `st`; unqualified table names resolve to whichever
    /// database holds them, so queries need no prefixes.
    pub fn open_split(state_dir: &Path, events_dir: &Path) -> rusqlite::Result<Db> {
        std::fs::create_dir_all(events_dir).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        migrate_legacy(state_dir);
        let conn = Connection::open(events_dir.join("events.db"))?;
        conn.execute_batch(
            "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-2048;
             PRAGMA temp_store=FILE; PRAGMA mmap_size=0;
             CREATE TABLE IF NOT EXISTS events(
               id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL,
               severity TEXT NOT NULL, sev INTEGER NOT NULL, host TEXT, src_ip TEXT, dst_ip TEXT,
               dst_port INTEGER, domain TEXT, process TEXT, message TEXT, raw TEXT);
             CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
             CREATE INDEX IF NOT EXISTS ev_kind_ts ON events(kind, ts);
             CREATE INDEX IF NOT EXISTS ev_src_ts ON events(src_ip, ts);
             CREATE INDEX IF NOT EXISTS ev_host_ts ON events(host, ts);",
        )?;
        conn.execute("ATTACH DATABASE ?1 AS st", [state_dir.join("state.db").to_string_lossy()])?;
        conn.execute_batch(
            "PRAGMA st.journal_mode=WAL; PRAGMA st.synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS st.alerts(
               id INTEGER PRIMARY KEY, ts INTEGER, last_ts INTEGER, severity TEXT, title TEXT,
               indicator TEXT, indicator_type TEXT, feed TEXT, host TEXT, src_ip TEXT,
               count INTEGER, status TEXT, explanation TEXT, UNIQUE(indicator, host));
             CREATE INDEX IF NOT EXISTS st.al_status ON alerts(status, last_ts);
             CREATE TABLE IF NOT EXISTS st.lists(list TEXT, value TEXT, kind TEXT, note TEXT, added INTEGER,
               PRIMARY KEY(list, value));
             CREATE TABLE IF NOT EXISTS st.devices(mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT,
               first_seen INTEGER, last_seen INTEGER);
             CREATE TABLE IF NOT EXISTS st.agent_keys(id TEXT PRIMARY KEY, name TEXT, platform TEXT, token_hash TEXT UNIQUE,
               created INTEGER, revoked INTEGER DEFAULT 0, last_seen INTEGER, events INTEGER DEFAULT 0, ip TEXT, version TEXT);
             CREATE TABLE IF NOT EXISTS st.feeds(id TEXT PRIMARY KEY, enabled INTEGER, entries INTEGER,
               last_update INTEGER, last_error TEXT);
             CREATE TABLE IF NOT EXISTS st.kv(k TEXT PRIMARY KEY, v TEXT);",
        )?;
        // events written by v0.1 into the state file move to the event log once
        let legacy: i64 = conn.query_row("SELECT count(*) FROM st.sqlite_master WHERE type='table' AND name='events'", [], |r| r.get(0))?;
        if legacy > 0 {
            conn.execute_batch(
                "INSERT INTO main.events(ts,source,kind,severity,sev,host,src_ip,dst_ip,dst_port,domain,process,message,raw)
                   SELECT ts,source,kind,severity,sev,host,src_ip,dst_ip,dst_port,domain,process,message,raw FROM st.events;
                 DROP TABLE st.events;",
            )?;
        }
        // v0.2.7: Leak Check
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS st.dns_hourly(dev TEXT, hour INTEGER, n INTEGER, PRIMARY KEY(dev, hour));
             CREATE TABLE IF NOT EXISTS st.leaks(id INTEGER PRIMARY KEY, dev TEXT, dev_name TEXT, actor TEXT, class TEXT, sev TEXT,
               first_ts INTEGER, last_ts INTEGER, count INTEGER, samples TEXT, status TEXT, UNIQUE(dev, actor, class));",
        )?;
        // v0.2.5: user-chosen device names
        let has_label: i64 = conn.query_row("SELECT count(*) FROM pragma_table_info('devices', 'st') WHERE name = 'label'", [], |r| r.get(0)).unwrap_or(0);
        if has_label == 0 {
            conn.execute_batch("ALTER TABLE st.devices ADD COLUMN label TEXT;")?;
        }
        register_functions(&conn)?;
        Ok(Db { conn })
    }

    /// Copy every event from another events.db (the fallback) into this one.
    pub fn merge_from(&self, other_events_db: &Path) -> rusqlite::Result<usize> {
        self.conn.execute("ATTACH DATABASE ?1 AS fb", [other_events_db.to_string_lossy()])?;
        let n = self.conn.execute(
            "INSERT INTO main.events(ts,source,kind,severity,sev,host,src_ip,dst_ip,dst_port,domain,process,message,raw)
             SELECT ts,source,kind,severity,sev,host,src_ip,dst_ip,dst_port,domain,process,message,raw FROM fb.events",
            [],
        );
        let _ = self.conn.execute("DETACH DATABASE fb", []);
        n
    }

    pub fn events_bytes(&self) -> i64 {
        let pc = self.scalar("PRAGMA main.page_count", []);
        let fl = self.scalar("PRAGMA main.freelist_count", []);
        let ps = self.scalar("PRAGMA main.page_size", []);
        (pc - fl).max(0) * ps
    }

    pub fn insert_events(&mut self, evs: &[WireEvent]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO events(ts,source,kind,severity,sev,host,src_ip,dst_ip,dst_port,domain,process,message,raw)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )?;
            for e in evs {
                let raw = if e.raw.is_null() { None } else { Some(e.raw.to_string()) };
                st.execute(params![
                    e.ts, e.source, e.kind, e.severity, severity_rank(&e.severity), e.host, e.src_ip, e.dst_ip,
                    e.dst_port, e.domain, e.process, e.message, raw
                ])?;
            }
        }
        tx.commit()
    }

    /// Retention by age, then by size: oldest events go first until the log fits `max_bytes`.
    pub fn prune(&self, retention_days: u32, max_bytes: i64) -> rusqlite::Result<usize> {
        let cutoff = now_ms() - retention_days as i64 * 86_400_000;
        let mut n = self.conn.execute("DELETE FROM main.events WHERE ts < ?", [cutoff])?;
        let mut guard = 0;
        while max_bytes > 0 && self.events_bytes() > max_bytes && guard < 50 {
            let total = self.scalar("SELECT count(*) FROM main.events", []);
            if total == 0 {
                break;
            }
            let chunk = (total / 20).max(1000);
            n += self.conn.execute("DELETE FROM main.events WHERE id IN (SELECT id FROM main.events ORDER BY ts LIMIT ?)", [chunk])?;
            self.conn.execute_batch("PRAGMA main.incremental_vacuum(20000);")?;
            guard += 1;
        }
        self.conn.execute_batch("PRAGMA main.incremental_vacuum(2000); PRAGMA shrink_memory;")?;
        Ok(n)
    }

    // ------------------------------------------------------------ search

    pub fn search(&self, query: &str, from: i64, to: i64, limit: usize) -> J {
        let started = std::time::Instant::now();
        let c = match crate::query::compile(query) {
            Ok(c) => c,
            Err(e) => {
                return json!({"events": [], "total": 0, "histogram": [], "fields": {}, "stats": null, "took_ms": 0, "error": e})
            }
        };
        let to = if to <= 0 { now_ms() } else { to };
        let from = from.max(0);
        let where_sql = format!("ts >= ? AND ts <= ? AND ({})", c.where_sql);
        let mut base: Vec<Value> = vec![Value::Integer(from), Value::Integer(to)];
        base.extend(c.params.iter().cloned());

        let run = || -> rusqlite::Result<J> {
            let total: i64 = self.conn.query_row(
                &format!("SELECT count(*) FROM events WHERE {where_sql}"),
                params_from_iter(base.iter()),
                |r| r.get(0),
            )?;
            let lim = c.head.unwrap_or(limit).min(limit.max(1)).min(1000);
            let order = if c.asc { "ASC" } else { "DESC" };
            let mut st = self.conn.prepare(&format!(
                "SELECT id,ts,source,kind,severity,host,src_ip,dst_ip,dst_port,domain,process,message,raw
                 FROM events WHERE {where_sql} ORDER BY ts {order} LIMIT {lim}"
            ))?;
            let events: Vec<J> = st.query_map(params_from_iter(base.iter()), row_to_event)?.filter_map(Result::ok).collect();

            // histogram: 60 buckets over [from, to] (or over the data range for "all time")
            let (hfrom, hto) = if from == 0 {
                let mn: Option<i64> = self.conn.query_row(
                    &format!("SELECT min(ts) FROM events WHERE {where_sql}"),
                    params_from_iter(base.iter()),
                    |r| r.get(0),
                )?;
                (mn.unwrap_or(to - 3_600_000), to)
            } else {
                (from, to)
            };
            let span = (hto - hfrom).max(60);
            let mut buckets = vec![0i64; 60];
            {
                let mut hp = vec![Value::Integer(hfrom), Value::Integer(span)];
                hp.extend(base.iter().cloned());
                let mut st = self.conn.prepare(&format!(
                    "SELECT min(59, max(0, ((ts - ?1) * 60) / ?2)) b, count(*) FROM events WHERE {} GROUP BY b",
                    where_sql.replacen("ts >= ?", "ts >= ?3", 1).replacen("ts <= ?", "ts <= ?4", 1)
                        .chars().collect::<String>()
                ))?;
                // positional params after ?4 continue at ?5…; rusqlite maps plain ? to the next index
                let rows = st.query_map(params_from_iter(hp.iter()), |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
                for (b, n) in rows.flatten() {
                    buckets[b.clamp(0, 59) as usize] = n;
                }
            }
            let histogram: Vec<J> = buckets
                .iter()
                .enumerate()
                .map(|(i, n)| json!({"t": hfrom + span * i as i64 / 60, "count": n}))
                .collect();

            let mut fields = serde_json::Map::new();
            for f in ["source", "kind", "severity", "host", "domain", "process", "src_ip", "dst_ip"] {
                let mut st = self.conn.prepare_cached(&format!(
                    "SELECT {f}, count(*) c FROM (SELECT {f} FROM events WHERE {where_sql} ORDER BY ts DESC LIMIT 20000)
                     WHERE {f} IS NOT NULL AND {f} != '' GROUP BY {f} ORDER BY c DESC LIMIT 10"
                ))?;
                let rows: Vec<(String, i64)> = st
                    .query_map(params_from_iter(base.iter()), |r| Ok((r.get::<_, String>(0)?, r.get(1)?)))?
                    .filter_map(Result::ok)
                    .collect();
                fields.insert(f.into(), kv(rows));
            }

            let stats = if let Some(by) = &c.stats_by {
                let mut st = self.conn.prepare(&format!(
                    "SELECT coalesce(CAST({by} AS TEXT), '(empty)') k, count(*) c FROM events WHERE {where_sql} GROUP BY k ORDER BY c DESC LIMIT {}",
                    c.stats_limit
                ))?;
                let rows: Vec<(String, i64)> = st
                    .query_map(params_from_iter(base.iter()), |r| Ok((r.get(0)?, r.get(1)?)))?
                    .filter_map(Result::ok)
                    .collect();
                json!({"by": by, "rows": kv(rows)})
            } else {
                J::Null
            };
            Ok(json!({"events": events, "total": total, "histogram": histogram, "fields": fields,
                      "stats": stats, "took_ms": started.elapsed().as_millis() as u64, "error": null}))
        };
        run().unwrap_or_else(|e| json!({"events": [], "total": 0, "histogram": [], "fields": {}, "stats": null, "took_ms": 0, "error": e.to_string()}))
    }

    pub fn recent_for_ip(&self, ip: &str, limit: usize) -> J {
        let mut st = match self.conn.prepare(
            "SELECT id,ts,source,kind,severity,host,src_ip,dst_ip,dst_port,domain,process,message,raw
             FROM events WHERE src_ip = ?1 OR host = ?1 ORDER BY ts DESC LIMIT ?2",
        ) {
            Ok(s) => s,
            Err(_) => return json!([]),
        };
        let v: Vec<J> = st
            .query_map(params![ip, limit as i64], row_to_event)
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default();
        J::Array(v)
    }

    pub fn top_domains_for_ip(&self, ip: &str, since: i64) -> J {
        kv(self.group(
            "SELECT domain, count(*) c FROM events WHERE src_ip = ?1 AND ts >= ?2 AND kind LIKE 'dns.%' AND domain IS NOT NULL GROUP BY domain ORDER BY c DESC LIMIT 15",
            params![ip, since],
        ))
    }

    pub fn group(&self, sql: &str, p: impl rusqlite::Params) -> Vec<(String, i64)> {
        let Ok(mut st) = self.conn.prepare_cached(sql) else { return vec![] };
        st.query_map(p, |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    pub fn group_str(&self, sql: &str, p: impl rusqlite::Params) -> Vec<(String, String)> {
        let Ok(mut st) = self.conn.prepare_cached(sql) else { return vec![] };
        st.query_map(p, |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    pub fn scalar(&self, sql: &str, p: impl rusqlite::Params) -> i64 {
        self.conn.query_row(sql, p, |r| r.get::<_, Option<i64>>(0)).ok().flatten().unwrap_or(0)
    }

    pub fn overview_parts(&self) -> J {
        let now = now_ms();
        let day = now - 86_400_000;
        let hour0 = now - (now % 3_600_000) - 23 * 3_600_000;
        let mut series = vec![(0i64, 0i64); 24];
        if let Ok(mut st) = self.conn.prepare_cached(
            "SELECT (ts - ?1) / 3600000 b, count(*), sum(CASE WHEN sev >= 2 THEN 1 ELSE 0 END)
             FROM events WHERE ts >= ?1 GROUP BY b",
        ) {
            if let Ok(rows) = st.query_map([hour0], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                for (b, t, a) in rows.flatten() {
                    if (0..24).contains(&b) {
                        series[b as usize] = (t, a);
                    }
                }
            }
        }
        let series: Vec<J> = series
            .iter()
            .enumerate()
            .map(|(i, (t, a))| json!({"t": hour0 + i as i64 * 3_600_000, "total": t, "alerts": a}))
            .collect();
        json!({
            "events_24h": self.scalar("SELECT count(*) FROM events WHERE ts >= ?", [day]),
            "alerts_open": self.scalar("SELECT count(*) FROM alerts WHERE status = 'open'", []),
            "blocked_24h": self.scalar("SELECT count(*) FROM events WHERE ts >= ? AND kind IN ('dns.blocked','firewall.block')", [day]),
            "series": series,
            "top_domains": kv(self.group("SELECT domain, count(*) c FROM events WHERE ts >= ? AND domain IS NOT NULL AND kind LIKE 'dns.%' GROUP BY domain ORDER BY c DESC LIMIT 10", [day])),
            "top_hosts": kv(self.group("SELECT host, count(*) c FROM events WHERE ts >= ? AND host IS NOT NULL AND host != '' GROUP BY host ORDER BY c DESC LIMIT 10", [day])),
            "severity": kv(self.group("SELECT severity, count(*) c FROM events WHERE ts >= ? GROUP BY severity ORDER BY max(sev) DESC", [day])),
            "recent_alerts": serde_json::to_value(self.alerts("open", 6)).unwrap_or(J::Null),
        })
    }

    // ------------------------------------------------------------ alerts

    /// Insert or bump an alert. Returns (alert, is_new_or_reopened).
    pub fn upsert_alert(&self, a: &NewAlert) -> rusqlite::Result<(Alert, bool)> {
        let now = now_ms();
        let existing: Option<(i64, String)> = self
            .conn
            .query_row("SELECT id, status FROM alerts WHERE indicator = ? AND host = ?", params![a.indicator, a.host], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let fresh = match existing {
            Some((id, status)) => {
                let reopen = status == "dismissed";
                self.conn.execute(
                    "UPDATE alerts SET last_ts = ?, count = count + 1, status = CASE WHEN status='dismissed' THEN ? ELSE status END,
                     src_ip = coalesce(?, src_ip) WHERE id = ?",
                    params![now, a.status, a.src_ip, id],
                )?;
                reopen
            }
            None => {
                self.conn.execute(
                    "INSERT INTO alerts(ts,last_ts,severity,title,indicator,indicator_type,feed,host,src_ip,count,status,explanation)
                     VALUES(?,?,?,?,?,?,?,?,?,1,?,?)",
                    params![now, now, a.severity, a.title, a.indicator, a.indicator_type, a.feed, a.host, a.src_ip, a.status, a.explanation],
                )?;
                true
            }
        };
        let al = self
            .conn
            .query_row(&format!("{ALERT_SELECT} WHERE indicator = ? AND host = ?"), params![a.indicator, a.host], row_to_alert)?;
        Ok((al, fresh))
    }

    pub fn alerts(&self, status: &str, limit: usize) -> Vec<Alert> {
        let (sql, all) = if status == "all" {
            (format!("{ALERT_SELECT} ORDER BY last_ts DESC LIMIT ?1"), true)
        } else {
            (format!("{ALERT_SELECT} WHERE status = ?1 ORDER BY last_ts DESC LIMIT ?2"), false)
        };
        let Ok(mut st) = self.conn.prepare_cached(&sql) else { return vec![] };
        let rows = if all {
            st.query_map(params![limit as i64], row_to_alert)
        } else {
            st.query_map(params![status, limit as i64], row_to_alert)
        };
        rows.map(|r| r.filter_map(Result::ok).collect()).unwrap_or_default()
    }

    pub fn alert(&self, id: i64) -> Option<Alert> {
        self.conn.query_row(&format!("{ALERT_SELECT} WHERE id = ?"), [id], row_to_alert).ok()
    }

    /// Set status on this alert and on every alert for the same indicator
    /// (a decision on a domain applies to all devices).
    pub fn set_alert_status(&self, indicator: &str, status: &str) -> rusqlite::Result<usize> {
        self.conn.execute("UPDATE alerts SET status = ? WHERE indicator = ?", params![status, indicator])
    }

    pub fn alert_counts(&self) -> J {
        let rows = self.group("SELECT status, count(*) FROM alerts GROUP BY status", []);
        let mut m = serde_json::Map::new();
        let mut all = 0;
        for (k, v) in rows {
            all += v;
            m.insert(k, json!(v));
        }
        m.insert("all".into(), json!(all));
        J::Object(m)
    }

    // ------------------------------------------------------------ lists

    pub fn list_entries(&self, list: &str) -> Vec<(String, String, String, i64)> {
        let Ok(mut st) = self.conn.prepare_cached("SELECT value, kind, note, added FROM lists WHERE list = ? ORDER BY added DESC") else {
            return vec![];
        };
        st.query_map([list], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<String>>(2)?.unwrap_or_default(), r.get(3)?)))
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }
    pub fn list_add(&self, list: &str, value: &str, kind: &str, note: &str) -> rusqlite::Result<()> {
        // a value lives in exactly one list
        self.conn.execute("DELETE FROM lists WHERE value = ?", [value])?;
        self.conn.execute(
            "INSERT INTO lists(list,value,kind,note,added) VALUES(?,?,?,?,?)",
            params![list, value, kind, note, now_ms()],
        )?;
        Ok(())
    }
    pub fn list_remove(&self, list: &str, value: &str) -> rusqlite::Result<usize> {
        self.conn.execute("DELETE FROM lists WHERE list = ? AND value = ?", params![list, value])
    }

    // ------------------------------------------------------------ kv

    pub fn kv_get(&self, k: &str) -> Option<String> {
        self.conn.query_row("SELECT v FROM kv WHERE k = ?", [k], |r| r.get(0)).ok()
    }
    pub fn kv_set(&self, k: &str, v: &str) {
        let _ = self.conn.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v]);
    }
}

const ALERT_SELECT: &str =
    "SELECT id,ts,last_ts,severity,title,indicator,indicator_type,feed,host,src_ip,count,status,explanation FROM alerts";

fn row_to_alert(r: &rusqlite::Row) -> rusqlite::Result<Alert> {
    Ok(Alert {
        id: r.get(0)?,
        ts: r.get(1)?,
        last_ts: r.get(2)?,
        severity: r.get(3)?,
        title: r.get(4)?,
        indicator: r.get(5)?,
        indicator_type: r.get(6)?,
        feed: r.get(7)?,
        host: r.get(8)?,
        src_ip: r.get(9)?,
        count: r.get(10)?,
        status: r.get(11)?,
        explanation: r.get(12)?,
    })
}

fn row_to_event(r: &rusqlite::Row) -> rusqlite::Result<J> {
    let raw: Option<String> = r.get(12)?;
    Ok(json!({
        "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "source": r.get::<_, String>(2)?,
        "kind": r.get::<_, String>(3)?, "severity": r.get::<_, String>(4)?, "host": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
        "src_ip": r.get::<_, Option<String>>(6)?, "dst_ip": r.get::<_, Option<String>>(7)?, "dst_port": r.get::<_, Option<i64>>(8)?,
        "domain": r.get::<_, Option<String>>(9)?, "process": r.get::<_, Option<String>>(10)?,
        "message": r.get::<_, Option<String>>(11)?.unwrap_or_default(),
        "raw": raw.and_then(|s| serde_json::from_str::<J>(&s).ok()).unwrap_or(J::Null),
    }))
}

/// v0.1 kept everything in `sentinel.db`; it becomes the state file.
fn migrate_legacy(state_dir: &Path) {
    let old = state_dir.join("sentinel.db");
    let new = state_dir.join("state.db");
    if old.exists() && !new.exists() {
        if let Ok(c) = Connection::open(&old) {
            let _ = c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
        let _ = std::fs::rename(&old, &new);
        let _ = std::fs::remove_file(state_dir.join("sentinel.db-wal"));
        let _ = std::fs::remove_file(state_dir.join("sentinel.db-shm"));
    }
}

/// `ulower(x)`: Unicode-aware lower-casing, so searches ignore case for any script
/// (SQLite's built-in lower()/NOCASE only fold ASCII).
fn register_functions(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function("ulower", 1, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
        // accept any column type (numbers too) so a search never fails on a non-text value
        use rusqlite::types::ValueRef;
        Ok(match ctx.get_raw(0) {
            ValueRef::Text(t) => Some(String::from_utf8_lossy(t).to_lowercase()),
            ValueRef::Integer(i) => Some(i.to_string()),
            ValueRef::Real(f) => Some(f.to_string()),
            ValueRef::Blob(_) | ValueRef::Null => None,
        })
    })?;
    // vpn(domain, dst_port, process): VPN-related event (list domain, VPN-only port or VPN client)
    conn.create_scalar_function("vpn", 3, FunctionFlags::SQLITE_UTF8, |ctx| {
        let d = ctx.get::<Option<String>>(0)?;
        let port = ctx.get::<Option<i64>>(1)?;
        let proc_ = ctx.get::<Option<String>>(2)?;
        let set = crate::intel::VPN_INDEX.read().unwrap().clone().unwrap_or_default();
        Ok(crate::intel::is_vpn(&set, d.as_deref(), port, proc_.as_deref()) as i64)
    })?;
    // pd(domain): 1 when the domain is on the PD adult-content list (works on historic events)
    conn.create_scalar_function("pd", 1, FunctionFlags::SQLITE_UTF8, |ctx| {
        let Some(d) = ctx.get::<Option<String>>(0)? else { return Ok(0i64) };
        let idx = crate::intel::PD_INDEX.read().unwrap().clone();
        Ok(idx.map(|set| crate::intel::is_adult_in(&set, &d) as i64).unwrap_or(0))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn alerts_listing_all_and_by_status() {
        let base = std::env::temp_dir().join(format!("oph-db-test-{}", std::process::id()));
        let (st, ev) = (base.join("state"), base.join("events"));
        std::fs::create_dir_all(&st).unwrap();
        let db = Db::open_split(&st, &ev).unwrap();
        for (ind, status) in [("a.example", "open"), ("b.example", "blocked")] {
            db.upsert_alert(&NewAlert { severity: "high", title: format!("t {ind}"), indicator: ind, indicator_type: "domain", feed: "test",
                host: "this-pc", src_ip: None, status, explanation: String::new() }).unwrap();
        }
        assert_eq!(db.alerts("all", 50).len(), 2, "the Alerts page lists all alerts");
        assert_eq!(db.alerts("open", 50).len(), 1);
        assert_eq!(db.alerts("blocked", 50).len(), 1);
        // QA-1: port searches must work (numbers through ulower and direct compare)
        let mut e = oph_proto::WireEvent::new("conn", "conn.open", "info", "x");
        e.dst_port = Some(443);
        e.domain = Some("Example.COM".into());
        let mut dbm = db;
        dbm.insert_events(&[e]).unwrap();
        for q in ["dst_port=443", "dst_port!=80", "dst_port=44*", "NOT dst_port=443", "domain=example.com", "443"] {
            let r = dbm.search(q, 0, 0, 10);
            assert!(r["error"].is_null(), "query {q} failed: {}", r["error"]);
        }
        assert_eq!(dbm.search("dst_port=443", 0, 0, 10)["total"], 1);
        let db = dbm;
        drop(db);
        let _ = std::fs::remove_dir_all(base);
    }
}
