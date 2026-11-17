//! Event-log location management.
//!
//! The event log (events.db) lives on a *primary* folder — typically an
//! external drive — identified by its volume GUID so a changed drive letter is
//! followed automatically. If the drive is missing, unplugged or not writable,
//! logging continues on the *fallback* folder; when the primary returns, the
//! fallback events are merged into it and the fallback file is removed.
//! State (alerts, lists, devices, keys) always stays in the app data folder.

use crate::core::Core;
use crate::db::Db;
use crate::settings::Settings;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct StorageState {
    pub active: String, // "primary" | "fallback"
    pub path: String,
    pub primary_path: String,
    pub primary_online: bool,
    pub fallback_path: String,
}

/// Resolve the primary folder to its current location (following a drive-letter change).
pub fn resolve_primary(s: &Settings) -> Option<PathBuf> {
    if s.storage_primary.is_empty() {
        return None;
    }
    let mut p = PathBuf::from(&s.storage_primary);
    if !s.storage_primary_serial.is_empty() {
        let letter = crate::native::letter_for_volume(&s.storage_primary_serial)?;
        let rest: String = s.storage_primary.chars().skip(1).collect(); // ":\OPH-S\logs"
        p = PathBuf::from(format!("{letter}{rest}"));
    }
    Some(p)
}

pub fn fallback_dir(s: &Settings, state_dir: &Path) -> PathBuf {
    if !s.storage_fallback.is_empty() {
        let p = PathBuf::from(&s.storage_fallback);
        if usable(&p) {
            return p;
        }
    }
    state_dir.join("logs")
}

/// The folder exists (or can be created) and accepts a write.
pub fn usable(p: &Path) -> bool {
    if std::fs::create_dir_all(p).is_err() {
        return false;
    }
    let probe = p.join(".oph-write-test");
    let ok = std::fs::write(&probe, b"ok").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// Which folder should hold the event log right now.
pub fn choose(s: &Settings, state_dir: &Path) -> (PathBuf, bool) {
    if let Some(p) = resolve_primary(s) {
        if usable(&p) {
            return (p, true);
        }
    }
    (fallback_dir(s, state_dir), false)
}

pub fn open_initial(s: &Settings, state_dir: &Path) -> (Db, StorageState) {
    let (dir, primary) = choose(s, state_dir);
    let db = Db::open_split(state_dir, &dir)
        .or_else(|_| Db::open_split(state_dir, &state_dir.join("logs")))
        .expect("open event store");
    // events logged to the fallback while the primary was away (e.g. app restarted
    // after the drive came back) are merged now, not stranded
    if primary {
        let fb_dir = fallback_dir(s, state_dir);
        let fb = fb_dir.join("events.db");
        if fb_dir != dir && fb.exists() && db.merge_from(&fb).is_ok() {
            for f in ["events.db", "events.db-wal", "events.db-shm"] {
                let _ = std::fs::remove_file(fb_dir.join(f));
            }
        }
    }
    let st = StorageState {
        active: if primary { "primary" } else { "fallback" }.into(),
        path: dir.display().to_string(),
        primary_path: resolve_primary(s).map(|p| p.display().to_string()).unwrap_or_default(),
        primary_online: primary,
        fallback_path: fallback_dir(s, state_dir).display().to_string(),
    };
    (db, st)
}

/// Re-evaluate the location and switch the live database if needed. Called every
/// 20 s, after a failed write, and after storage settings change.
pub fn check(core: &Arc<Core>) {
    let s = core.settings();
    let (want, primary) = choose(&s, &core.dir);
    let current = core.storage.lock().unwrap().path.clone();
    let mut st = core.storage.lock().unwrap().clone();
    st.primary_online = primary;
    st.primary_path = resolve_primary(&s).map(|p| p.display().to_string()).unwrap_or_default();
    st.fallback_path = fallback_dir(&s, &core.dir).display().to_string();
    if PathBuf::from(&current) == want {
        *core.storage.lock().unwrap() = st;
        return;
    }
    let new_db = match Db::open_split(&core.dir, &want) {
        Ok(d) => d,
        Err(e) => {
            core.sys("system.error", "high", format!("Could not open the event log at {}: {e}", want.display()));
            return;
        }
    };
    let old_path = PathBuf::from(&current);
    let mut merged = 0;
    {
        let mut db = core.db.lock().unwrap();
        *db = new_db; // the previous connection closes here (its WAL is checkpointed)
        if primary && old_path != want {
            // coming back to the primary: pull in what was written to the fallback meanwhile
            let fb = old_path.join("events.db");
            if fb.exists() {
                match db.merge_from(&fb) {
                    Ok(n) => {
                        merged = n;
                        for f in ["events.db", "events.db-wal", "events.db-shm"] {
                            let _ = std::fs::remove_file(old_path.join(f));
                        }
                    }
                    Err(e) => core.sys("system.error", "medium", format!("Fallback events could not be merged yet ({e}); they stay in {}", old_path.display())),
                }
            }
        }
    }
    st.active = if primary { "primary" } else { "fallback" }.into();
    st.path = want.display().to_string();
    *core.storage.lock().unwrap() = st;
    if primary {
        core.sys("system.start", "info", format!("Event log on primary storage {} ({merged} events merged back from the fallback)", want.display()));
    } else {
        core.sys("system.error", "medium", format!("Primary log storage is unavailable (drive disconnected?). Logging continues on {} and will be merged back automatically.", want.display()));
        core.notify("storage", "Log drive disconnected", &format!("OPH-S keeps logging on {}.", want.display()));
    }
}

pub fn status_json(core: &Core) -> Value {
    let st = core.storage.lock().unwrap().clone();
    let s = core.settings();
    let db = core.db.lock().unwrap();
    let oldest = db.scalar("SELECT min(ts) FROM main.events", []);
    let free = free_bytes(Path::new(&st.path));
    json!({"active": st.active, "path": st.path, "primary_path": st.primary_path, "primary_online": st.primary_online,
           "fallback_path": st.fallback_path, "events_bytes": db.events_bytes(), "max_bytes": s.max_store_mb as i64 * 1_048_576,
           "oldest_ts": if oldest > 0 { Some(oldest) } else { None }, "free_bytes": free, "retention_days": s.retention_days})
}

fn free_bytes(p: &Path) -> Option<u64> {
    let letter = p.to_string_lossy().chars().next().filter(|c| c.is_ascii_alphabetic())?;
    let (ok, out) = crate::native::run_hidden("powershell", &["-NoProfile", "-Command", &format!("(Get-PSDrive -Name '{letter}').Free")]).ok()?;
    if !ok {
        return None;
    }
    out.trim().parse().ok()
}

/// Drives for the location picker (PowerShell storage cmdlets: label, bus, size, free, volume GUID).
pub fn drives_list() -> Value {
    let ps = "Get-Partition | Where-Object DriveLetter | ForEach-Object { $d = Get-Disk -Number $_.DiskNumber; $v = Get-Volume -DriveLetter $_.DriveLetter; \
              [pscustomobject]@{ letter = [string]$_.DriveLetter; label = $v.FileSystemLabel; bus = [string]$d.BusType; model = $d.FriendlyName; \
              removable = ([string]$d.BusType -eq 'USB'); size = $v.Size; free = $v.SizeRemaining; serial = $v.UniqueId } } | ConvertTo-Json -Compress";
    match crate::native::run_hidden("powershell", &["-NoProfile", "-NonInteractive", "-Command", ps]) {
        Ok((true, out)) => {
            let v: Value = serde_json::from_str(out.trim()).unwrap_or(Value::Null);
            match v {
                Value::Array(_) => v,
                Value::Object(_) => Value::Array(vec![v]),
                _ => json!([]),
            }
        }
        _ => json!([]),
    }
}

/// First run: if no primary is configured and a large external (USB) drive is present,
/// propose it automatically so logs land on the big disk.
pub fn auto_configure(s: &mut Settings) -> bool {
    if !s.storage_primary.is_empty() {
        return false;
    }
    let drives = drives_list();
    let best = drives
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| d["bus"] == "USB" && d["size"].as_u64().unwrap_or(0) > 500_000_000_000)
        .max_by_key(|d| d["free"].as_u64().unwrap_or(0));
    let Some(d) = best else { return false };
    let (Some(letter), Some(serial)) = (d["letter"].as_str(), d["serial"].as_str()) else { return false };
    s.storage_primary = format!("{letter}:\\OPH-S\\logs");
    s.storage_primary_serial = serial.to_string();
    // fallback: another internal drive with space, else app data
    let fb = drives
        .as_array()
        .into_iter()
        .flatten()
        .filter(|x| x["bus"] != "USB" && x["letter"].as_str() != Some("C") && x["free"].as_u64().unwrap_or(0) > 20_000_000_000)
        .max_by_key(|x| x["free"].as_u64().unwrap_or(0));
    if let Some(l) = fb.and_then(|x| x["letter"].as_str()) {
        s.storage_fallback = format!("{l}:\\OPH-S\\logs");
    }
    true
}
