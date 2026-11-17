//! File integrity monitoring (FIM) for the folders malware uses most:
//! Desktop, Downloads, Documents, Startup folders, the scheduled-task store and
//! the hosts file. Built on the `notify` crate (ReadDirectoryChangesW on
//! Windows), so watching costs no polling and almost no memory.
//!
//! Severity:  high   — anything new in a Startup folder / Tasks store, hosts changes
//!            medium — executables & scripts appearing in user folders
//!            info   — other files
//! Executables/scripts ≤ 50 MB get a SHA-256 (search it on VirusTotal / MalwareBazaar).

use crate::core::Core;
use notify::event::{EventKind, ModifyKind, RenameMode};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use oph_proto::{now_ms, WireEvent};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const EXEC_EXT: &[&str] = &["exe", "dll", "msi", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "scr", "lnk", "hta", "com", "pif", "jar", "sys"];
const NOISE_EXT: &[&str] = &["tmp", "crdownload", "part", "partial", "download", "lock", "~tmp"];

static WATCHER: Mutex<Option<RecommendedWatcher>> = Mutex::new(None);

#[derive(Clone)]
struct Root {
    path: PathBuf,
    label: String,
    critical: bool, // Startup / Tasks / hosts
    recursive: bool,
}

fn env(k: &str) -> Option<PathBuf> {
    std::env::var_os(k).map(PathBuf::from)
}

fn default_roots() -> Vec<Root> {
    let mut v = Vec::new();
    let mut add = |p: Option<PathBuf>, label: &str, critical: bool, recursive: bool| {
        if let Some(p) = p {
            v.push(Root { path: p, label: label.into(), critical, recursive });
        }
    };
    // Ask Windows where each folder really is: OneDrive-redirected Desktop/Documents,
    // Downloads moved to another drive, etc. Fall back to the profile defaults.
    let kf = crate::native::known_folder;
    let home = env("USERPROFILE");
    let desktop = kf(0).or_else(|| home.as_ref().map(|h| h.join("Desktop")));
    let downloads = kf(2).or_else(|| home.as_ref().map(|h| h.join("Downloads")));
    add(desktop.clone(), "Desktop", false, true);
    add(downloads.clone(), "Downloads", false, true);
    add(kf(1).or_else(|| home.as_ref().map(|h| h.join("Documents"))), "Documents", false, true);
    add(kf(3).or_else(|| env("APPDATA").map(|a| a.join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"))), "Startup (you)", true, false);
    add(kf(4).or_else(|| env("ProgramData").map(|a| a.join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"))), "Startup (all users)", true, false);
    // the plain profile folders as well when redirected (some programs still write there)
    if let Some(h) = &home {
        for (p, real, label) in [(h.join("Desktop"), desktop, "Desktop (profile)"), (h.join("Downloads"), downloads, "Downloads (profile)")] {
            if real.as_ref() != Some(&p) {
                add(Some(p), label, false, true);
            }
        }
    }
    add(env("SystemRoot").map(|s| s.join("System32\\Tasks")), "Scheduled tasks", true, true);
    add(env("SystemRoot").map(|s| s.join("System32\\drivers\\etc")), "hosts file", true, false);
    v
}

fn roots(core: &Core) -> Vec<Root> {
    let s = core.settings();
    let mut r: Vec<Root> = if s.fim_paths.is_empty() {
        default_roots()
    } else {
        s.fim_paths.iter().map(|p| Root { path: PathBuf::from(p), label: Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone()), critical: false, recursive: true }).collect()
    };
    r.retain(|x| x.path.is_dir());
    r
}

/// Never watch our own data/log folders (would log our own writes forever).
fn excluded(core: &Core, p: &Path) -> bool {
    // take the lock once (two locks in one statement would deadlock: std Mutex is not re-entrant)
    let (active, fallback) = {
        let st = core.storage.lock().unwrap();
        (PathBuf::from(&st.path), PathBuf::from(&st.fallback_path))
    };
    let own = [core.dir.clone(), active, fallback];
    own.iter().any(|o| !o.as_os_str().is_empty() && p.starts_with(o))
}

fn ext_of(p: &Path) -> String {
    p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

fn noise(p: &Path) -> bool {
    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    name.starts_with("~$") || name.starts_with(".~") || name.eq_ignore_ascii_case("desktop.ini") || name.eq_ignore_ascii_case("thumbs.db") || NOISE_EXT.contains(&ext_of(p).as_str())
}

fn sha256_file(p: &Path) -> Option<String> {
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > 50 * 1024 * 1024 {
        return None;
    }
    use std::io::Read;
    let mut f = std::fs::File::open(p).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn start(core: Arc<Core>) {
    let mut guard = WATCHER.lock().unwrap();
    *guard = None; // drop any previous watcher (settings changed)
    if !core.settings().fim_enabled {
        return;
    }
    let roots = roots(&core);
    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
    let mut w = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            core.sys("system.error", "low", format!("File monitoring could not start: {e}"));
            return;
        }
    };
    let mut watching = Vec::new();
    for r in &roots {
        let mode = if r.recursive { RecursiveMode::Recursive } else { RecursiveMode::NonRecursive };
        if w.watch(&r.path, mode).is_ok() {
            watching.push(r.label.clone());
        }
    }
    *guard = Some(w);
    drop(guard);
    core.sys("system.start", "info", format!("File monitoring active: {}", watching.join(", ")));

    std::thread::Builder::new()
        .name("oph-fim".into())
        .spawn(move || {
            // debounce: editors and downloads fire many events per file
            let mut last: HashMap<(PathBuf, &'static str), i64> = HashMap::new();
            let mut pending_rename: Option<PathBuf> = None;
            while let Ok(res) = rx.recv() {
                let Ok(ev) = res else { continue };
                let kind: &'static str = match ev.kind {
                    EventKind::Create(_) => "file.created",
                    EventKind::Remove(_) => "file.deleted",
                    EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
                        pending_rename = ev.paths.first().cloned();
                        continue;
                    }
                    EventKind::Modify(ModifyKind::Name(_)) => "file.renamed",
                    EventKind::Modify(_) => "file.modified",
                    _ => continue,
                };
                let Some(path) = ev.paths.last().cloned() else { continue };
                if excluded(&core, &path) || noise(&path) || path.is_dir() {
                    continue;
                }
                let now = now_ms();
                let key = (path.clone(), kind);
                let window = if kind == "file.modified" { 10_000 } else { 2_000 };
                if last.get(&key).map(|t| now - t < window).unwrap_or(false) {
                    continue;
                }
                last.insert(key, now);
                if last.len() > 5000 {
                    last.retain(|_, t| now - *t < 60_000);
                }
                // a "created" event right after we logged the same file as created is the write finishing
                if kind == "file.modified" && last.get(&(path.clone(), "file.created")).map(|t| now - t < 10_000).unwrap_or(false) {
                    continue;
                }
                let root = roots.iter().find(|r| path.starts_with(&r.path));
                let label = root.map(|r| r.label.clone()).unwrap_or_else(|| "watched folder".into());
                let critical = root.map(|r| r.critical).unwrap_or(false);
                let ext = ext_of(&path);
                let exec = EXEC_EXT.contains(&ext.as_str());
                let hosts = path.file_name().map(|n| n.eq_ignore_ascii_case("hosts")).unwrap_or(false);
                if label == "hosts file" && !hosts {
                    continue; // only the hosts file itself in that folder
                }
                let sev = if critical && kind != "file.deleted" {
                    "high"
                } else if exec && kind != "file.deleted" {
                    "medium"
                } else {
                    "info"
                };
                // give the writer a moment, then hash finished executables
                let sha = if exec && kind != "file.deleted" {
                    std::thread::sleep(Duration::from_millis(300));
                    sha256_file(&path)
                } else {
                    None
                };
                let size = std::fs::metadata(&path).map(|m| m.len()).ok();
                let verb = match kind {
                    "file.created" => "created",
                    "file.deleted" => "deleted",
                    "file.renamed" => "renamed",
                    _ => "modified",
                };
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let mut e = WireEvent::new("file", kind, sev, format!("{name} {verb} in {label}{}", if exec { " (executable/script)" } else { "" }));
                e.host = "this-pc".into();
                e.process = None;
                e.raw = serde_json::json!({
                    "path": path.display().to_string(), "folder": label, "size": size, "ext": ext,
                    "sha256": sha, "executable": exec,
                    "old_path": if kind == "file.renamed" { pending_rename.take().map(|p| p.display().to_string()) } else { None },
                });
                core.emit(e);
                if sev == "high" {
                    core.notify(&format!("fim:{}", path.display()), "Persistence location changed", &format!("{name} {verb} in {label}. Programs placed here run automatically; open OPH-S → Search (source=file) if you didn't do this."));
                }
            }
        })
        .expect("spawn fim");
}
