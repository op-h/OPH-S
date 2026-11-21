//! Background services: threat-feed refresh, maintenance, scheduled cleanup, autostart.

use crate::core::Core;
use crate::intel::{self, Intel, FEEDS};
use oph_proto::now_ms;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub fn feed_enabled(core: &Core, id: &str) -> bool {
    let def = FEEDS.iter().find(|f| f.id == id).map(|f| f.default_enabled).unwrap_or(false);
    let db = core.db.lock().unwrap();
    // NULL / missing row = user never toggled it: use the feed's default
    let v: Option<i64> = db.conn.query_row("SELECT enabled FROM feeds WHERE id = ?", [id], |r| r.get(0)).ok().flatten();
    v.map(|v| v == 1).unwrap_or(def)
}

pub fn rebuild_index(core: &Arc<Core>) {
    let enabled: Vec<(String, bool)> = FEEDS.iter().map(|f| (f.id.to_string(), feed_enabled(core, f.id))).collect();
    let it = Intel::build(&core.dir, &|id| enabled.iter().any(|(i, e)| i == id && *e));
    {
        let db = core.db.lock().unwrap();
        for (id, n) in &it.counts {
            let _ = db.conn.execute(
                "INSERT INTO feeds(id, enabled, entries) VALUES(?1, NULL, ?2) ON CONFLICT(id) DO UPDATE SET entries = ?2",
                rusqlite::params![id, *n as i64],
            );
        }
        for (id, e) in &enabled {
            if !*e {
                let _ = db.conn.execute("UPDATE feeds SET entries = 0 WHERE id = ?", [id]);
            }
        }
    }
    *crate::intel::PD_INDEX.write().unwrap() = Some(Arc::new(it.adult.clone()));
    *crate::intel::VPN_INDEX.write().unwrap() = Some(Arc::new(it.vpn.clone()));
    *core.intel.write().unwrap() = Arc::new(it);
    close_stale_alerts(core);
}

/// Download stale (or all, when `force`) enabled feeds, then rebuild the index.
pub fn refresh(core: Arc<Core>, force: bool) {
    {
        let mut st = core.status.lock().unwrap();
        if st.intel_updating {
            return;
        }
        st.intel_updating = true;
    }
    std::thread::spawn(move || {
        crate::native::background(|| {
            let s = core.settings();
            let max_age = s.intel_interval_hours as i64 * 3_600_000;
            let mut updated = Vec::new();
            let mut failed = Vec::new();
            for f in FEEDS {
                if !feed_enabled(&core, f.id) {
                    continue;
                }
                let age = intel::feed_cache_age(&core.dir, f.id);
                let stale = age.map(|a| a > if f.kind == "oui" || f.kind == "popular" { 7 * 86_400_000 } else { max_age }).unwrap_or(true);
                if !force && !stale {
                    continue;
                }
                let res = intel::download(&core.dir, f, &s.abuse_ch_key);
                let db = core.db.lock().unwrap();
                match &res {
                    Ok(_) => {
                        let _ = db.conn.execute(
                            "INSERT INTO feeds(id, enabled, last_update, last_error) VALUES(?1, NULL, ?2, NULL)
                             ON CONFLICT(id) DO UPDATE SET last_update = ?2, last_error = NULL",
                            rusqlite::params![f.id, now_ms()],
                        );
                        updated.push(f.id);
                    }
                    Err(e) => {
                        let _ = db.conn.execute(
                            "INSERT INTO feeds(id, enabled, last_error) VALUES(?1, NULL, ?2) ON CONFLICT(id) DO UPDATE SET last_error = ?2",
                            rusqlite::params![f.id, e],
                        );
                        failed.push(format!("{}: {e}", f.id));
                    }
                }
            }
            rebuild_index(&core);
            let total = core.intel.read().unwrap().total();
            if !updated.is_empty() || !failed.is_empty() {
                let sev = if failed.is_empty() { "info" } else { "low" };
                let mut e = oph_proto::WireEvent::new("intel", "intel.update", sev, format!("Threat feeds refreshed: {} updated, {} failed, {} indicators loaded", updated.len(), failed.len(), total));
                e.host = "this-pc".into();
                e.raw = json!({"updated": updated, "failed": failed, "indicators": total});
                core.emit(e);
            }
        });
        core.status.lock().unwrap().intel_updating = false;
        crate::native::trim_self();
    });
}

/// Open alerts raised by a threat feed whose indicator no longer matches any feed (e.g. the
/// false-positive guards now exclude it) are closed as "dismissed" with an explanation event.
fn close_stale_alerts(core: &Arc<Core>) {
    let open: Vec<(String, String)> = core.db.lock().unwrap().group_str(
        "SELECT indicator, indicator_type FROM alerts WHERE status = 'open' AND feed NOT IN ('Manual blocklist', 'Suricata IDS') GROUP BY indicator",
        [],
    );
    let intel = core.intel.read().unwrap().clone();
    for (ind, typ) in open {
        let still = if typ == "ip" { intel.match_ip(&ind).is_some() } else { intel.match_domain(&ind).is_some() };
        if !still {
            let _ = core.db.lock().unwrap().set_alert_status(&ind, "dismissed");
            core.sys("intel.update", "info", format!("Alert for {ind} closed automatically: no threat feed lists it any more (false-positive guard or list update)"));
        }
    }
}

pub fn intel_status(core: &Core) -> Value {
    let db = core.db.lock().unwrap();
    let mut feeds = Vec::new();
    for f in FEEDS {
        let row: Option<(Option<i64>, Option<i64>, Option<i64>, Option<String>)> = db
            .conn
            .query_row("SELECT enabled, entries, last_update, last_error FROM feeds WHERE id = ?", [f.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .ok();
        let (en, entries, last, err) = row.unwrap_or((None, None, None, None));
        let enabled = en.map(|v| v == 1).unwrap_or(f.default_enabled);
        let last = last.or_else(|| intel::feed_cache_age(&core.dir, f.id).map(|a| now_ms() - a));
        feeds.push(json!({"id": f.id, "name": f.name, "url": f.url.replace("{key}", "<key>"), "kind": f.kind, "category": f.category,
            "enabled": enabled, "entries": entries.unwrap_or(0), "last_update": last, "last_error": err, "needs_key": f.needs_key}));
    }
    let to_json = |list: &str| -> Value {
        Value::Array(db.list_entries(list).into_iter().map(|(v, k, n, a)| json!({"value": v, "kind": k, "note": n, "added": a})).collect())
    };
    json!({"feeds": feeds, "manual_block": to_json("block"), "manual_allow": to_json("allow"),
           "total": core.intel.read().unwrap().total(), "updating": core.status.lock().unwrap().intel_updating})
}

pub async fn maintenance(core: Arc<Core>) {
    let mut tick: u64 = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(if tick == 0 { 20 } else { 600 })).await;
        let s = core.settings();
        // feeds: refresh check every 30 min (downloads only what is stale)
        if tick.is_multiple_of(3) {
            refresh(core.clone(), false);
        }
        // hourly: retention + quarantine expiry
        if tick.is_multiple_of(6) {
            let c = core.clone();
            let _ = tokio::task::spawn_blocking(move || {
                crate::native::background(|| {
                    let n = c.db.lock().unwrap().prune(s.retention_days, s.max_store_mb as i64 * 1_048_576).unwrap_or(0);
                    let freed = crate::cleaner::purge(&c.dir.join("quarantine"), true).freed_bytes;
                    if n > 0 || freed > 0 {
                        c.sys("cleaner.run", "info", format!("Maintenance: {n} events past retention removed, {} MB of expired quarantine purged", freed / 1_048_576));
                    }
                })
            })
            .await;
        }
        // scheduled cleanup: safe categories only, always to quarantine (undoable)
        if s.cleaner_schedule != "off" {
            let every = if s.cleaner_schedule == "daily" { 86_400_000 } else { 7 * 86_400_000 };
            let last: i64 = core.db.lock().unwrap().kv_get("cleaner_last").and_then(|v| v.parse().ok()).unwrap_or(0);
            if now_ms() - last > every {
                core.db.lock().unwrap().kv_set("cleaner_last", &now_ms().to_string());
                let c = core.clone();
                let r = tokio::task::spawn_blocking(move || crate::cleaner::run(&c.dir.join("quarantine"), &crate::cleaner::auto_categories())).await.unwrap_or(Value::Null);
                let mb = r["moved_bytes"].as_u64().unwrap_or(0) / 1_048_576;
                core.sys("cleaner.run", "info", format!("Scheduled cleanup moved {} files ({mb} MB) to quarantine. Undo is available on the Cleaner page for 7 days.", r["moved_files"]));
            }
        }
        crate::native::trim_self();
        tick += 1;
    }
}

/// Start with Windows. Elevated: a logon scheduled task with highest privileges
/// (so enforcement works without a UAC prompt). Otherwise: HKCU Run key.
pub fn set_autostart(enable: bool, admin: bool) -> Result<(), String> {
    if !cfg!(windows) {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
    let run = |args: &[&str]| crate::native::run_hidden(args[0], &args[1..]).map_err(|e| e.to_string());
    let _ = run(&["schtasks", "/delete", "/tn", "OPH Sentinel", "/f"]);
    let _ = run(&["reg", "delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "OPH Sentinel", "/f"]);
    if !enable {
        return Ok(());
    }
    let cmdline = format!("\"{exe}\" --minimized");
    let (ok, out) = if admin {
        run(&["schtasks", "/create", "/tn", "OPH Sentinel", "/tr", &cmdline, "/sc", "onlogon", "/rl", "highest", "/f"])?
    } else {
        run(&["reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "OPH Sentinel", "/t", "REG_SZ", "/d", &cmdline, "/f"])?
    };
    if ok { Ok(()) } else { Err(out.trim().to_string()) }
}
