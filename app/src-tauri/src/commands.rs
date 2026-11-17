//! Tauri IPC commands (contract: docs/API.md). Heavy work runs on the
//! blocking pool so the UI thread and the async runtime stay responsive.

use crate::core::{Core, Lists};
use crate::intel;
use crate::services;
use crate::settings::Settings;
use oph_proto::now_ms;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;

type R = Result<Value, String>;
type S<'a> = State<'a, Arc<Core>>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn overview(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let mut v = c.db.lock().unwrap().overview_parts();
        let dev = crate::netmon::devices_json(&c);
        let list = dev["devices"].as_array().cloned().unwrap_or_default();
        v["devices_total"] = json!(list.len());
        v["devices_online"] = json!(list.iter().filter(|d| d["online"] == true).count());
        v["agents_online"] = json!(c.agents_online.lock().unwrap().len());
        v["intel_entries"] = json!(c.intel.read().unwrap().total());
        v["protection_mode"] = json!(c.settings.read().unwrap().mode);
        v["dns_running"] = json!(c.status.lock().unwrap().dns_running);
        v["network_monitoring"] = json!(c.monitoring_on());
        v
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchReq {
    query: String,
    #[serde(default)]
    from_ts: i64,
    #[serde(default)]
    to_ts: i64,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    200
}

#[tauri::command]
pub async fn search(core: S<'_>, req: SearchReq) -> R {
    let c = core.inner().clone();
    blocking(move || c.db.lock().unwrap().search(&req.query, req.from_ts, req.to_ts, req.limit.clamp(1, 1000))).await
}

#[derive(Deserialize)]
pub struct StatusReq {
    status: String,
}

#[tauri::command]
pub async fn alerts(core: S<'_>, req: StatusReq) -> R {
    let c = core.inner().clone();
    blocking(move || serde_json::to_value(c.db.lock().unwrap().alerts(&req.status, 5000)).unwrap_or(Value::Null)).await
}

#[tauri::command]
pub async fn alert_counts(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || c.db.lock().unwrap().alert_counts()).await
}

#[derive(Deserialize)]
pub struct DecideReq {
    id: i64,
    action: String,
}

fn reload_lists(core: &Core) {
    let l = Lists::load(&core.db.lock().unwrap());
    *core.lists.write().unwrap() = l;
}

#[tauri::command]
pub async fn alert_decide(core: S<'_>, req: DecideReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let alert = c.db.lock().unwrap().alert(req.id).ok_or("Alert not found")?;
        let listable = matches!(alert.indicator_type.as_str(), "domain" | "ip");
        let status = match req.action.as_str() {
            "block" => "blocked",
            "allow" => "allowed",
            "dismiss" => "dismissed",
            "reopen" => "open",
            _ => return Err("Unknown action".to_string()),
        };
        {
            let db = c.db.lock().unwrap();
            db.set_alert_status(&alert.indicator, status).map_err(|e| e.to_string())?;
            if listable {
                let note = format!("Decision on alert #{} ({})", alert.id, alert.feed);
                match status {
                    "blocked" => db.list_add("block", &alert.indicator, &alert.indicator_type, &note).map_err(|e| e.to_string())?,
                    "allowed" => db.list_add("allow", &alert.indicator, &alert.indicator_type, &note).map_err(|e| e.to_string())?,
                    _ => {
                        db.list_remove("block", &alert.indicator).ok();
                        db.list_remove("allow", &alert.indicator).ok();
                    }
                }
            }
        }
        reload_lists(&c);
        if listable {
            crate::firewall::request_sync(&c);
        }
        let mut e = oph_proto::WireEvent::new("firewall", if status == "blocked" { "firewall.block" } else { "firewall.unblock" }, "info",
            format!("User decision: {} {} ({})", req.action, alert.indicator, alert.feed));
        e.host = "this-pc".into();
        e.domain = (alert.indicator_type == "domain").then(|| alert.indicator.clone());
        e.dst_ip = (alert.indicator_type == "ip").then(|| alert.indicator.clone());
        e.raw = json!({"alert_id": alert.id, "action": req.action});
        c.emit(e);
        let a = c.db.lock().unwrap().alert(req.id).ok_or("Alert not found")?;
        Ok(serde_json::to_value(a).unwrap())
    })
    .await?
}

#[tauri::command]
pub async fn devices(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || crate::netmon::devices_json(&c)).await
}

#[derive(Deserialize)]
pub struct IpReq {
    ip: String,
}

#[tauri::command]
pub async fn device_detail(core: S<'_>, req: IpReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let db = c.db.lock().unwrap();
        json!({"top_domains": db.top_domains_for_ip(&req.ip, now_ms() - 86_400_000), "recent": db.recent_for_ip(&req.ip, 50)})
    })
    .await
}

#[tauri::command]
pub async fn connections(core: S<'_>) -> R {
    Ok(Value::Array(core.conns.lock().unwrap().clone()))
}

#[tauri::command]
pub async fn intel_status(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || services::intel_status(&c)).await
}

#[tauri::command]
pub async fn intel_update(core: S<'_>) -> R {
    let c = core.inner().clone();
    services::refresh(c.clone(), true);
    blocking(move || services::intel_status(&c)).await
}

#[derive(Deserialize)]
pub struct FeedReq {
    id: String,
    enabled: bool,
}

#[tauri::command]
pub async fn feed_toggle(core: S<'_>, req: FeedReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        if !intel::FEEDS.iter().any(|f| f.id == req.id) {
            return Err("Unknown feed".to_string());
        }
        c.db.lock()
            .unwrap()
            .conn
            .execute(
                "INSERT INTO feeds(id, enabled) VALUES(?1, ?2) ON CONFLICT(id) DO UPDATE SET enabled = ?2",
                rusqlite::params![req.id, req.enabled as i64],
            )
            .map_err(|e| format!("Could not save the feed setting: {e}"))?;
        if req.enabled && intel::feed_cache_age(&c.dir, &req.id).is_none() {
            services::refresh(c.clone(), false); // downloads it, then rebuilds
        } else {
            services::rebuild_index(&c);
        }
        Ok(services::intel_status(&c))
    })
    .await?
}

#[derive(Deserialize)]
pub struct ListReq {
    list: String,
    value: String,
    #[serde(default)]
    note: String,
}

pub fn classify(value: &str) -> Result<(String, &'static str), String> {
    let mut v = value.trim().to_ascii_lowercase();
    if v.contains("://") {
        v = intel::host_from_url(&v).ok_or("Could not read a host name from that URL")?;
    }
    let v = v.trim_end_matches('.').trim_start_matches("*.").to_string();
    if v.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok((v, "ip"));
    }
    if crate::core::parse_cidr(&v).is_some() {
        return Ok((v, "cidr"));
    }
    if intel::valid_domain(&v) {
        return Ok((v, "domain"));
    }
    Err("Enter a domain (example.com), an IPv4 address (203.0.113.7) or a CIDR range (203.0.113.0/24)".into())
}

#[tauri::command]
pub async fn list_add(core: S<'_>, req: ListReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        if req.list != "block" && req.list != "allow" {
            return Err("Unknown list".to_string());
        }
        let (v, kind) = classify(&req.value)?;
        let note: String = req.note.chars().take(200).collect();
        c.db.lock().unwrap().list_add(&req.list, &v, kind, &note).map_err(|e| e.to_string())?;
        reload_lists(&c);
        crate::firewall::request_sync(&c);
        Ok(services::intel_status(&c))
    })
    .await?
}

#[tauri::command]
pub async fn list_remove(core: S<'_>, req: ListReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        c.db.lock().unwrap().list_remove(&req.list, &req.value).map_err(|e| e.to_string())?;
        reload_lists(&c);
        crate::firewall::request_sync(&c);
        Ok(services::intel_status(&c))
    })
    .await?
}

fn agents_json(c: &Core) -> Value {
    let online = c.agents_online.lock().unwrap().clone();
    let db = c.db.lock().unwrap();
    let mut rows = Vec::new();
    if let Ok(mut st) = db.conn.prepare("SELECT id, name, platform, created, last_seen, events, revoked, ip, version FROM agent_keys ORDER BY revoked, created DESC") {
        if let Ok(it) = st.query_map([], |r| {
            Ok(json!({"id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "platform": r.get::<_, Option<String>>(2)?,
                "created": r.get::<_, Option<i64>>(3)?, "last_seen": r.get::<_, Option<i64>>(4)?, "events": r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                "revoked": r.get::<_, i64>(6)? != 0, "ip": r.get::<_, Option<String>>(7)?, "version": r.get::<_, Option<String>>(8)?}))
        }) {
            for mut a in it.flatten() {
                a["online"] = json!(online.contains_key(a["id"].as_str().unwrap_or("")));
                rows.push(a);
            }
        }
    }
    let s = c.settings();
    let st = c.status.lock().unwrap().clone();
    json!({"agents": rows, "server": {"running": st.ingest_running, "error": st.ingest_error, "port": s.ingest_port,
        "fingerprint": c.fingerprint, "lan_ip": c.net.lock().unwrap().local_ip,
        "syslog_running": st.syslog_running, "syslog_port": s.syslog_port, "syslog_error": st.syslog_error}})
}

#[tauri::command]
pub async fn agents(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || agents_json(&c)).await
}

#[derive(Deserialize)]
pub struct EnrollReq {
    name: String,
    platform: String,
}

fn url_enc(v: &str) -> String {
    v.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Create a per-device key and the ready-to-paste install commands for it.
#[tauri::command]
pub async fn device_enroll(core: S<'_>, req: EnrollReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let name: String = req.name.trim().chars().filter(|ch| ch.is_alphanumeric() || " -_.".contains(*ch)).take(48).collect();
        if name.trim().is_empty() {
            return Err("Give the device a name (letters, numbers, spaces, - _ .)".to_string());
        }
        let platform = match req.platform.as_str() {
            p @ ("windows" | "android" | "iphone" | "linux") => p.to_string(),
            _ => return Err("Unknown platform".into()),
        };
        let token = crate::core::random_token();
        let id = crate::core::random_token()[..12].to_string();
        c.db.lock()
            .unwrap()
            .conn
            .execute(
                "INSERT INTO agent_keys(id, name, platform, token_hash, created, revoked) VALUES(?1, ?2, ?3, ?4, ?5, 0)",
                rusqlite::params![id, name, platform, crate::ingest::token_hash(&token), now_ms()],
            )
            .map_err(|e| e.to_string())?;
        let s = c.settings();
        let host = c.net.lock().unwrap().local_ip.clone().unwrap_or_else(|| "THIS-PC-IP".into());
        let port = s.ingest_port;
        let fp = c.fingerprint.clone();
        let args = format!("--server {host}:{port} --token {token} --fingerprint {fp} --name \"{name}\"");
        // Windows: use the installed copy if OPH-S is on that PC, else download it from this PC
        // (the share is started automatically for 15 min), verify SHA-256, register for logon, start now.
        let sha = crate::share::sha256_of("oph-agent.exe").unwrap_or_default();
        let sp = crate::share::PORT;
        if platform == "windows" || platform == "android" {
            if crate::share::active().is_none() {
                let _ = crate::share::set(&c, true);
            }
            crate::firewall::ensure_inbound(&c);
        }
        let args_sq = args.replace('\'', "''");
        let windows_install_cmd = format!(
            "$d=\"$env:LOCALAPPDATA\\OPH-S\"; New-Item -ItemType Directory -Force $d | Out-Null; $f=\"$d\\oph-agent.exe\"; $src='C:\\Program Files\\OPH-S\\oph-agent.exe'; \
if (Test-Path $src) {{ Copy-Item $src $f -Force }} else {{ try {{ Invoke-WebRequest http://{host}:{sp}/oph-agent.exe -OutFile $f -UseBasicParsing -ErrorAction Stop }} catch {{ throw 'OPH-S: cannot download the agent from {host}:{sp}. On the OPH-S PC open Devices > Add device (it shares the download for 15 minutes) and run this again.' }} }}; \
if ((Get-FileHash $f -Algorithm SHA256).Hash -ne '{sha}') {{ Remove-Item $f; throw 'OPH-S: the downloaded agent does not match - do not run it' }}; \
& $f {args} --install; if ($LASTEXITCODE -ne 0) {{ throw 'OPH-S: the agent could not be registered to start at logon' }}; Start-Process $f -ArgumentList '{args_sq}' -WindowStyle Hidden; 'OPH-S agent installed and running.'"
        );
        let windows_cmd = format!("& \"$env:LOCALAPPDATA\\OPH-S\\oph-agent.exe\" {args}");
        let termux_cmd = format!("./oph-agent {args} --logcat --install");
        let linux_cmd = format!("./oph-agent {args} --tail /var/log/syslog --install");
        let android_uri = format!("ophs://enroll?host={}&port={port}&token={token}&fp={}&name={}", url_enc(&host), url_enc(&fp), url_enc(&name));
        c.sys("agent.log", "info", format!("Device key created for {name} ({platform})"));
        Ok(json!({"id": id, "name": name, "platform": platform, "token": token, "host": host, "port": port, "fingerprint": fp,
            "windows_cmd": windows_cmd, "windows_install_cmd": windows_install_cmd, "termux_cmd": termux_cmd, "linux_cmd": linux_cmd,
            "android_uri": android_uri, "apk_url": crate::share::url(&c, "OPH-S.apk"), "agent_sha256": sha,
            "share_expires": crate::share::active(),
            "this_pc_note": if platform == "windows" { Some(format!("Run this on your other Windows PCs. This PC ({host}) runs OPH-S and is already monitored directly.")) } else { None }}))
    })
    .await?
}

#[derive(Deserialize)]
pub struct IdReq {
    id: String,
}

#[tauri::command]
pub async fn device_revoke(core: S<'_>, req: IdReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let n = c.db.lock().unwrap().conn.execute("UPDATE agent_keys SET revoked = 1 WHERE id = ?", [&req.id]).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Device not found".to_string());
        }
        c.sys("agent.log", "low", format!("Device key {} revoked; the device is disconnected at its next batch", req.id));
        Ok(agents_json(&c))
    })
    .await?
}

#[derive(Deserialize)]
pub struct ShareReq {
    enable: bool,
}

#[tauri::command]
pub async fn apk_share(core: S<'_>, req: ShareReq) -> R {
    let c = core.inner().clone();
    crate::share::set(&c, req.enable)?;
    Ok(json!({"url": crate::share::url(&c, "OPH-S.apk"), "agent_url": crate::share::url(&c, "oph-agent.exe"),
              "expires": crate::share::active(), "apk_available": crate::share::find("OPH-S.apk").is_some()}))
}

#[tauri::command]
pub async fn drives_list() -> R {
    blocking(crate::storage::drives_list).await
}

#[tauri::command]
pub async fn storage_status(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || crate::storage::status_json(&c)).await
}

#[tauri::command]
pub async fn router_info(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || crate::router::info(&c)).await
}

#[tauri::command]
pub async fn cleaner_last(core: S<'_>) -> R {
    Ok(core.cleaner_last.lock().unwrap().clone().unwrap_or(Value::Null))
}

/// Remove every block: manual blocklist, blocked alerts (back to open), hosts section, firewall rules.
#[tauri::command]
pub async fn unblock_all(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let (lists, alerts) = {
            let db = c.db.lock().unwrap();
            let l = db.conn.execute("DELETE FROM lists WHERE list = 'block'", []).map_err(|e| e.to_string())?;
            let a = db.conn.execute("UPDATE alerts SET status = 'open' WHERE status = 'blocked'", []).map_err(|e| e.to_string())?;
            (l, a)
        };
        reload_lists(&c);
        crate::firewall::sync(&c);
        let msg = format!("Removed {lists} blocklist entries and reopened {alerts} blocked alerts. Hosts file entries and firewall rules cleared.");
        c.sys("firewall.unblock", "info", msg.clone());
        Ok::<_, String>(json!({"ok": true, "message": msg}))
    })
    .await?
}

#[tauri::command]
pub async fn cleaner_scan(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let v = crate::cleaner::scan(&c.dir.join("quarantine"));
        *c.cleaner_last.lock().unwrap() = Some(v.clone());
        v
    })
    .await
}

#[derive(Deserialize)]
pub struct CleanReq {
    categories: Vec<String>,
}

#[tauri::command]
pub async fn cleaner_run(core: S<'_>, req: CleanReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let r = crate::cleaner::run(&c.dir.join("quarantine"), &req.categories);
        let mut e = oph_proto::WireEvent::new("cleaner", "cleaner.run", "info",
            format!("Cleanup moved {} files ({} MB) to quarantine", r["moved_files"], r["moved_bytes"].as_u64().unwrap_or(0) / 1_048_576));
        e.host = "this-pc".into();
        e.raw = json!({"categories": req.categories, "result": r.clone()});
        c.emit(e);
        r
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoReq {
    run_id: String,
}

#[tauri::command]
pub async fn cleaner_undo(core: S<'_>, req: UndoReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let r = crate::cleaner::undo(&c.dir.join("quarantine"), &req.run_id);
        c.sys("cleaner.undo", "info", format!("Cleanup {} undone: {} files restored", req.run_id, r["restored"]));
        r
    })
    .await
}

#[tauri::command]
pub async fn cleaner_purge(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let freed = crate::cleaner::purge(&c.dir.join("quarantine"), false);
        c.sys("cleaner.run", "info", format!("Quarantine purged: {} MB freed permanently", freed / 1_048_576));
        json!({"freed_bytes": freed})
    })
    .await
}

#[tauri::command]
pub async fn memory_status() -> R {
    blocking(crate::cleaner::memory_status).await
}

#[tauri::command]
pub async fn memory_trim() -> R {
    blocking(crate::cleaner::memory_trim).await
}

#[tauri::command]
pub async fn settings_get(core: S<'_>) -> R {
    Ok(serde_json::to_value(core.settings()).unwrap())
}

#[derive(Deserialize)]
pub struct SettingsReq {
    settings: Settings,
}

#[tauri::command]
pub async fn settings_set(core: S<'_>, req: SettingsReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let new = req.settings.validated();
        let old = c.settings();
        new.save(&c.dir)?;
        *c.settings.write().unwrap() = new.clone();
        if old.autostart != new.autostart {
            services::set_autostart(new.autostart, c.admin)?;
        }
        let net_changed = old.dns_enabled != new.dns_enabled || old.dns_bind != new.dns_bind || old.dns_upstream != new.dns_upstream
            || old.ingest_enabled != new.ingest_enabled || old.ingest_port != new.ingest_port
            || old.syslog_enabled != new.syslog_enabled || old.syslog_port != new.syslog_port;
        if net_changed {
            crate::restart_network_services(c.clone());
        }
        if old.abuse_ch_key != new.abuse_ch_key || old.intel_interval_hours != new.intel_interval_hours {
            services::refresh(c.clone(), false);
        }
        if old.storage_primary != new.storage_primary || old.storage_primary_serial != new.storage_primary_serial || old.storage_fallback != new.storage_fallback {
            crate::storage::check(&c);
        }
        if old.network_monitoring != new.network_monitoring {
            c.monitoring.store(new.network_monitoring, std::sync::atomic::Ordering::Relaxed);
        }
        if old.fim_enabled != new.fim_enabled || old.fim_paths != new.fim_paths {
            crate::fim::start(c.clone());
        }
        if old.icon_style != new.icon_style {
            crate::set_app_icon(&c, &new.icon_style);
        }
        if old.mode != new.mode {
            c.sys("system.start", "info", format!("Protection mode changed to {}", new.mode.to_uppercase()));
        }
        Ok(serde_json::to_value(new).unwrap())
    })
    .await?
}

#[tauri::command]
pub async fn app_info(core: S<'_>) -> R {
    let st = core.status.lock().unwrap().clone();
    let mut st = serde_json::to_value(&st).unwrap_or(Value::Null);
    st["network_monitoring"] = json!(core.monitoring_on());
    Ok(json!({"version": env!("CARGO_PKG_VERSION"), "data_dir": core.dir.display().to_string(), "admin": core.admin,
        "platform": std::env::consts::OS, "status": st, "dropped_events": core.dropped.load(std::sync::atomic::Ordering::Relaxed),
        "net": core.net.lock().unwrap().clone()}))
}

#[tauri::command]
pub async fn firewall_setup(core: S<'_>) -> R {
    let c = core.inner().clone();
    let (ok, message) = blocking(move || crate::firewall::setup_ports(&c)).await?;
    Ok(json!({"ok": ok, "message": message}))
}

#[derive(Deserialize)]
pub struct RouterReq {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    remember: bool,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    apply: bool,
}

/// Automatic TP-Link Deco setup. apply=false is a read-only check.
#[tauri::command]
pub async fn router_configure(core: S<'_>, req: RouterReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let mode = if req.mode == "strict" { "strict" } else { "safe" };
        crate::router::configure(&c, req.password, req.remember, mode, req.apply)
    })
    .await
}

#[tauri::command]
pub async fn router_undo(core: S<'_>, req: RouterReq) -> R {
    let c = core.inner().clone();
    blocking(move || crate::router::undo(&c, req.password)).await
}

#[tauri::command]
pub async fn router_forget(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || {
        crate::router::forget_password(&c);
        json!({"ok": true})
    })
    .await
}

#[derive(Deserialize)]
pub struct MonitorReq {
    enabled: bool,
}

/// Top-bar switch: pause / resume recording of network activity (DNS keeps resolving).
#[tauri::command]
pub async fn set_monitoring(core: S<'_>, req: MonitorReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let mut s = c.settings();
        s.network_monitoring = req.enabled;
        s.save(&c.dir)?;
        *c.settings.write().unwrap() = s;
        c.monitoring.store(req.enabled, std::sync::atomic::Ordering::Relaxed);
        // the switch itself is always recorded, so a pause is visible in the timeline
        let msg = if req.enabled { "Network monitoring resumed" } else { "Network monitoring paused by the user (DNS keeps working; lookups and connections are not recorded)" };
        c.sys("system.start", if req.enabled { "info" } else { "low" }, msg);
        Ok(json!({"network_monitoring": req.enabled}))
    })
    .await?
}

#[derive(Deserialize)]
pub struct SuggestReq {
    field: String,
    #[serde(default)]
    prefix: String,
}

/// Autocomplete values for `field=` in the search bar (last 7 days, most frequent first).
#[tauri::command]
pub async fn search_suggest(core: S<'_>, req: SuggestReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let field = req.field.to_ascii_lowercase();
        if !matches!(field.as_str(), "source" | "kind" | "severity" | "host" | "src_ip" | "dst_ip" | "dst_port" | "domain" | "process") {
            return json!({"values": []});
        }
        let pat = format!("%{}%", req.prefix.to_lowercase().replace('\\', "").replace('%', "").replace('_', ""));
        let since = now_ms() - 7 * 86_400_000;
        let db = c.db.lock().unwrap();
        let rows = db.group(
            &format!("SELECT CAST({field} AS TEXT) v, count(*) c FROM (SELECT {field} FROM events WHERE ts >= ?1 ORDER BY ts DESC LIMIT 50000)
                      WHERE {field} IS NOT NULL AND ulower(CAST({field} AS TEXT)) LIKE ?2 GROUP BY v ORDER BY c DESC LIMIT 15"),
            rusqlite::params![since, pat],
        );
        json!({"values": rows.into_iter().map(|(k, n)| json!({"key": k, "count": n})).collect::<Vec<_>>()})
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReq {
    query: String,
    #[serde(default)]
    from_ts: i64,
    #[serde(default)]
    to_ts: i64,
}

/// Save the current search as CSV in the user's Downloads folder.
#[tauri::command]
pub async fn export_search(core: S<'_>, req: ExportReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let compiled = crate::query::compile(&req.query)?;
        let to = if req.to_ts <= 0 { now_ms() } else { req.to_ts };
        let mut params: Vec<rusqlite::types::Value> = vec![req.from_ts.max(0).into(), to.into()];
        params.extend(compiled.params.iter().cloned());
        let sql = format!(
            "SELECT ts, source, kind, severity, host, src_ip, dst_ip, dst_port, domain, process, message FROM events
             WHERE ts >= ? AND ts <= ? AND ({}) ORDER BY ts DESC LIMIT 100000",
            compiled.where_sql
        );
        let dir = std::env::var_os("USERPROFILE").map(|h| std::path::PathBuf::from(h).join("Downloads")).filter(|p| p.is_dir()).unwrap_or_else(|| c.dir.clone());
        let path = dir.join(format!("OPH-S-search-{}.csv", now_ms()));
        let esc = |v: String| if v.contains([',', '"', '\n', '\r']) { format!("\"{}\"", v.replace('"', "\"\"")) } else { v };
        let mut out = String::from("\u{feff}time_utc,source,kind,severity,host,src_ip,dst_ip,dst_port,domain,process,message\r\n");
        let db = c.db.lock().unwrap();
        let mut st = db.conn.prepare(&sql).map_err(|e| e.to_string())?;
        let mut rows = st.query(rusqlite::params_from_iter(params.iter())).map_err(|e| e.to_string())?;
        let mut n = 0;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let ts: i64 = r.get(0).unwrap_or(0);
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(ts as u64);
            let secs = t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let (d, h, m, s2) = (secs / 86400, (secs / 3600) % 24, (secs / 60) % 60, secs % 60);
            // civil date from days since epoch (Howard Hinnant's algorithm)
            let z = d as i64 + 719_468;
            let era = z.div_euclid(146_097);
            let doe = z - era * 146_097;
            let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let day = doy - (153 * mp + 2) / 5 + 1;
            let month = if mp < 10 { mp + 3 } else { mp - 9 };
            let year = yoe + era * 400 + (month <= 2) as i64;
            let mut line = vec![format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s2:02}")];
            for i in 1..11 {
                let v: Option<String> = r.get::<_, Option<String>>(i).ok().flatten().or_else(|| r.get::<_, Option<i64>>(i).ok().flatten().map(|x| x.to_string()));
                line.push(esc(v.unwrap_or_default()));
            }
            out.push_str(&line.join(","));
            out.push_str("\r\n");
            n += 1;
        }
        drop(rows);
        drop(st);
        drop(db);
        std::fs::write(&path, out).map_err(|e| e.to_string())?;
        Ok(json!({"path": path.display().to_string(), "rows": n}))
    })
    .await?
}

#[derive(Deserialize)]
pub struct AskReq {
    #[serde(default)]
    question: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    data: Value,
}

/// Ask the configured AI about a search, event, alert or device.
#[tauri::command]
pub async fn ai_ask(core: S<'_>, req: AskReq) -> R {
    let c = core.inner().clone();
    blocking(move || crate::ai::ask(&c, &req.question, &req.kind, &req.data)).await
}

/// Exactly the log text that would be sent with a question.
#[tauri::command]
pub async fn ai_preview(core: S<'_>, req: AskReq) -> R {
    let c = core.inner().clone();
    blocking(move || crate::ai::preview(&c, &req.kind, &req.data)).await
}

#[derive(Deserialize)]
pub struct KeyReq {
    #[serde(default)]
    key: String,
}

#[tauri::command]
pub async fn ai_set_key(core: S<'_>, req: KeyReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        crate::ai::set_key(&c, &req.key)?;
        Ok(json!({"key_saved": crate::ai::stored_key(&c).is_some()}))
    })
    .await?
}

#[tauri::command]
pub async fn ai_status(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let s = c.settings();
        let key = crate::ai::stored_key(&c).is_some();
        let ready = key || s.ai_provider == "openai"; // local endpoints such as Ollama need no key
        json!({"provider": s.ai_provider, "model": s.ai_model, "base_url": s.ai_base_url, "key_saved": key, "ready": ready, "redact": s.ai_redact})
    })
    .await
}

#[derive(Deserialize)]
pub struct RenameReq {
    /// device MAC ("aa:bb:..") or IP
    id: String,
    #[serde(default)]
    name: String,
}

/// Give a LAN device your own name (empty = back to the automatic name).
#[tauri::command]
pub async fn device_rename(core: S<'_>, req: RenameReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let name: String = req.name.trim().chars().filter(|ch| !ch.is_control()).take(48).collect();
        let n = c
            .db
            .lock()
            .unwrap()
            .conn
            .execute("UPDATE devices SET label = nullif(?1, '') WHERE mac = ?2 OR ip = ?2", rusqlite::params![name, req.id])
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Device not found (it may not have been seen in the network table yet)".to_string());
        }
        // refresh the ip -> label map used in new events right away
        if let Some(ip) = c.db.lock().unwrap().group_str("SELECT ip, ip FROM devices WHERE mac = ?1 OR ip = ?1", [&req.id]).first().map(|r| r.0.clone()) {
            let mut hl = c.host_labels.write().unwrap();
            if name.is_empty() { hl.remove(&ip); } else { hl.insert(ip, name.clone()); }
        }
        Ok(crate::netmon::devices_json(&c))
    })
    .await?
}

/// Leak Check: device coverage, open leak cards, fix state.
#[tauri::command]
pub async fn leak_status(core: S<'_>) -> R {
    let c = core.inner().clone();
    blocking(move || crate::leak::status(&c)).await
}

#[derive(Deserialize)]
pub struct LeakActionReq {
    id: i64,
    action: String,
}

/// ignore | reopen | recheck a leak card.
#[tauri::command]
pub async fn leak_action(core: S<'_>, req: LeakActionReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let message = match req.action.as_str() {
            "ignore" => {
                crate::leak::set_status(&c, req.id, "ignored")?;
                "Ignored. This program/device will not raise this leak again.".to_string()
            }
            "reopen" => {
                crate::leak::set_status(&c, req.id, "open")?;
                "Reopened.".to_string()
            }
            "recheck" => crate::leak::recheck(&c, req.id),
            _ => return Err("Unknown action".to_string()),
        };
        let mut v = crate::leak::status(&c);
        v["message"] = json!(message);
        Ok(v)
    })
    .await?
}

#[derive(Deserialize)]
pub struct LeakFixReq {
    fix: String,
}

/// canaries | doh_names | firewall_doh (and undo_*).
#[tauri::command]
pub async fn leak_fix(core: S<'_>, req: LeakFixReq) -> R {
    let c = core.inner().clone();
    blocking(move || {
        let msg = crate::leak::apply_fix(&c, &req.fix)?;
        let mut v = crate::leak::status(&c);
        v["message"] = json!(msg);
        Ok::<_, String>(v)
    })
    .await?
}
