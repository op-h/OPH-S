//! Storage cleaner with explicit rules, preview, quarantine and undo.
//!
//! Nothing is deleted directly: files are moved to a quarantine folder on
//! the same volume (instant rename), can be restored with Undo, and are
//! purged after 7 days or when the user chooses "Purge". Scans and moves
//! run in Windows background-priority mode (lowest CPU / disk / memory).

use oph_proto::now_ms;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BinaryHeap;
use std::cmp::Reverse;
use std::io::Write;
use std::path::{Path, PathBuf};

const QUARANTINE_DAYS: i64 = 7;
const MAX_FILES_PER_CATEGORY: usize = 300_000;

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub risk: &'static str,
    pub min_age_hours: u64,
    /// process image names that must not be running (their caches are in use)
    pub requires_closed: &'static [&'static str],
    pub auto: bool,
}

pub const RULES: &[Rule] = &[
    Rule { id: "user_temp", name: "User temporary files", description: "Files programs left in your %TEMP% folder. Only files untouched for 24 hours are included.", risk: "safe", min_age_hours: 24, requires_closed: &[], auto: true },
    Rule { id: "windows_temp", name: "Windows temporary files", description: "System-wide temporary files in C:\\Windows\\Temp older than 24 hours. Some need administrator rights.", risk: "safe", min_age_hours: 24, requires_closed: &[], auto: true },
    Rule { id: "crash_dumps", name: "Crash dumps and error reports", description: "Memory dumps and Windows Error Reporting archives created when programs crash. Only useful for debugging a specific crash.", risk: "safe", min_age_hours: 1, requires_closed: &[], auto: true },
    Rule { id: "thumbnails", name: "Thumbnail cache", description: "Explorer picture previews. Windows rebuilds them when you open a folder. Files in use are skipped.", risk: "safe", min_age_hours: 0, requires_closed: &[], auto: true },
    Rule { id: "browser_cache", name: "Browser caches", description: "Cached web content for Chrome, Edge, Brave, Opera, Vivaldi and Firefox. Pages may load slower once. Browsers must be closed; passwords, history and cookies are never touched.", risk: "safe", min_age_hours: 1, requires_closed: &["chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "firefox.exe"], auto: false },
    Rule { id: "dev_caches", name: "Developer package caches", description: "npm, Yarn, pip and Cargo download caches. Packages are downloaded again when a project needs them.", risk: "review", min_age_hours: 24, requires_closed: &[], auto: false },
    Rule { id: "update_cache", name: "Windows Update download cache", description: "Installer files Windows Update already applied. Requires administrator rights; Windows re-downloads anything still needed.", risk: "review", min_age_hours: 72, requires_closed: &[], auto: false },
];

fn env(k: &str) -> Option<PathBuf> {
    std::env::var_os(k).map(PathBuf::from)
}

fn chromium_profiles(user_data: PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&user_data) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n == "Default" || n.starts_with("Profile ") || n == "Guest Profile" {
                let p = e.path();
                for sub in ["Cache", "Code Cache", "GPUCache", "Service Worker\\CacheStorage"] {
                    out.push(p.join(sub));
                }
            }
        }
    }
    for sub in ["ShaderCache", "GrShaderCache"] {
        out.push(user_data.join(sub));
    }
    out
}

/// Root folders for a rule plus an optional file-name filter.
fn roots(rule: &str) -> (Vec<PathBuf>, Option<fn(&str) -> bool>) {
    let la = env("LOCALAPPDATA");
    let ra = env("APPDATA");
    let pd = env("ProgramData");
    let sr = env("SystemRoot");
    let home = env("USERPROFILE");
    let mut v = Vec::new();
    let mut filter: Option<fn(&str) -> bool> = None;
    match rule {
        "user_temp" => v.extend(env("TEMP")),
        "windows_temp" => v.extend(sr.map(|s| s.join("Temp"))),
        "crash_dumps" => {
            if let Some(l) = &la {
                v.push(l.join("CrashDumps"));
                v.push(l.join("Microsoft\\Windows\\WER\\ReportArchive"));
                v.push(l.join("Microsoft\\Windows\\WER\\ReportQueue"));
            }
            if let Some(p) = &pd {
                v.push(p.join("Microsoft\\Windows\\WER\\ReportArchive"));
                v.push(p.join("Microsoft\\Windows\\WER\\ReportQueue"));
            }
        }
        "thumbnails" => {
            v.extend(la.map(|l| l.join("Microsoft\\Windows\\Explorer")));
            filter = Some(|n| (n.starts_with("thumbcache_") || n.starts_with("iconcache_")) && n.ends_with(".db"));
        }
        "browser_cache" => {
            if let Some(l) = &la {
                for ud in ["Google\\Chrome\\User Data", "Microsoft\\Edge\\User Data", "BraveSoftware\\Brave-Browser\\User Data", "Vivaldi\\User Data"] {
                    v.extend(chromium_profiles(l.join(ud)));
                }
                if let Ok(rd) = std::fs::read_dir(l.join("Mozilla\\Firefox\\Profiles")) {
                    for e in rd.flatten() {
                        v.push(e.path().join("cache2"));
                    }
                }
            }
            if let Some(r) = &ra {
                v.extend(chromium_profiles(r.join("Opera Software\\Opera Stable")));
            }
        }
        "dev_caches" => {
            if let Some(l) = &la {
                v.push(l.join("npm-cache"));
                v.push(l.join("Yarn\\Cache"));
                v.push(l.join("pip\\cache"));
            }
            if let Some(h) = &home {
                v.push(h.join(".cargo\\registry\\cache"));
            }
        }
        "update_cache" => v.extend(sr.map(|s| s.join("SoftwareDistribution\\Download"))),
        _ => {}
    }
    v.retain(|p| p.is_dir() && safe_root(p));
    (v, filter)
}

/// Refuse roots that are too broad to clean (TEMP pointed at a drive root, the
/// profile folder, Windows or Program Files): a misconfigured variable must never
/// turn the cleaner into "quarantine my documents".
fn safe_root(p: &Path) -> bool {
    let Ok(c) = p.canonicalize() else { return false };
    if c.components().count() < 4 {
        return false; // drive root or the Users folder level
    }
    // allow-list by folder name: every legitimate root is a temp / cache / dump folder
    let s = c.to_string_lossy().to_ascii_lowercase();
    let last = c.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let known = matches!(last.as_str(), "temp" | "tmp" | "crashdumps" | "reportarchive" | "reportqueue" | "explorer" | "download" | "cache2" | "npm-cache")
        || last.contains("cache")
        || s.ends_with("\\yarn\\cache") || s.ends_with("\\pip\\cache");
    if !known {
        return false;
    }
    let forbidden = ["USERPROFILE", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA", "OneDrive"];
    !forbidden.iter().filter_map(std::env::var_os).filter_map(|v| PathBuf::from(v).canonicalize().ok()).any(|f| f == c)
}

/// Every folder any rule may touch: the only places undo is allowed to write.
fn all_roots() -> Vec<PathBuf> {
    RULES.iter().flat_map(|r| roots(r.id).0).filter_map(|p| p.canonicalize().ok()).collect()
}

/// Top-level folders of `root` that contain anything modified within the last 24 hours.
fn active_dirs(root: &Path, now: i64) -> std::collections::HashSet<PathBuf> {
    let mut out = std::collections::HashSet::new();
    let Ok(rd) = std::fs::read_dir(root) else { return out };
    for top in rd.flatten() {
        let Ok(m) = std::fs::symlink_metadata(top.path()) else { continue };
        if !m.is_dir() || is_reparse(&m) {
            continue;
        }
        let mut stack = vec![top.path()];
        let mut seen = 0usize;
        'scan: while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                seen += 1;
                let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
                let mt = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64).unwrap_or(0);
                if now - mt < 86_400_000 || seen > 200_000 {
                    out.insert(top.path());
                    break 'scan;
                }
                if m.is_dir() && !is_reparse(&m) {
                    stack.push(e.path());
                }
            }
        }
    }
    out
}

#[cfg(windows)]
fn is_reparse(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x400 != 0
}
#[cfg(not(windows))]
fn is_reparse(m: &std::fs::Metadata) -> bool {
    m.file_type().is_symlink()
}

/// Walk without following symlinks / junctions. Calls `f(path, size, mtime_ms)` per eligible file.
fn walk(rule: &Rule, mut f: impl FnMut(&Path, u64, i64)) {
    let (roots, filter) = roots(rule.id);
    let min_age = rule.min_age_hours as i64 * 3_600_000;
    let now = now_ms();
    let mut count = 0usize;
    for root in roots {
        // Temp roots: a top-level folder where anything changed in the last 24 h belongs to a
        // program that is still using it (app sessions, sandboxes, node_modules) -> skip it whole.
        let skip: std::collections::HashSet<PathBuf> = if matches!(rule.id, "user_temp" | "windows_temp") { active_dirs(&root, now) } else { Default::default() };
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
                if is_reparse(&m) {
                    continue;
                }
                if m.is_dir() {
                    if filter.is_none() && !skip.contains(&e.path()) {
                        stack.push(e.path());
                    }
                    continue;
                }
                if let Some(fl) = filter {
                    if !fl(&e.file_name().to_string_lossy()) {
                        continue;
                    }
                }
                let mt = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64).unwrap_or(now);
                if now - mt < min_age {
                    continue;
                }
                f(&e.path(), m.len(), mt);
                count += 1;
                if count >= MAX_FILES_PER_CATEGORY {
                    return;
                }
            }
        }
    }
}

fn running_blockers(rule: &Rule) -> Vec<String> {
    if rule.requires_closed.is_empty() {
        return vec![];
    }
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut out: Vec<String> = sys
        .processes()
        .values()
        .map(|p| p.name().to_string_lossy().to_ascii_lowercase())
        .filter(|n| rule.requires_closed.contains(&n.as_str()))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Item {
    bytes: u64,
    path: String,
    modified: i64,
}

pub fn scan(qdir: &Path) -> Value {
    crate::native::background(|| {
        let mut cats = Vec::new();
        let mut total = 0u64;
        for r in RULES {
            let mut files = 0u64;
            let mut bytes = 0u64;
            let mut top: BinaryHeap<Reverse<Item>> = BinaryHeap::new();
            walk(r, |p, sz, mt| {
                files += 1;
                bytes += sz;
                top.push(Reverse(Item { bytes: sz, path: p.display().to_string(), modified: mt }));
                if top.len() > 40 {
                    top.pop();
                }
            });
            let mut items: Vec<Item> = top.into_iter().map(|r| r.0).collect();
            items.sort_by(|a, b| b.bytes.cmp(&a.bytes));
            let blockers = running_blockers(r);
            total += bytes;
            cats.push(json!({"id": r.id, "name": r.name, "description": r.description, "risk": r.risk, "files": files, "bytes": bytes,
                "items": items, "blocked_by": blockers}));
        }
        json!({"categories": cats, "total_bytes": total, "quarantine": quarantine_info(qdir)})
    })
}

/// What is really in quarantine: counts and sizes from the files on disk (not from run.json),
/// so a partly purged run shows exactly what is left.
pub fn quarantine_info(qdir: &Path) -> Value {
    let mut runs = Vec::new();
    let mut all = 0u64;
    if let Ok(rd) = std::fs::read_dir(qdir) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            let id = e.file_name().to_string_lossy().into_owned();
            let v: Value = std::fs::read_to_string(e.path().join("run.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
            let (mut files, mut bytes) = (0u64, 0u64);
            if let Ok(fs) = std::fs::read_dir(e.path()) {
                for f in fs.flatten() {
                    if f.file_name().to_string_lossy().ends_with(".q") {
                        files += 1;
                        bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                }
            }
            if files == 0 {
                let _ = std::fs::remove_dir_all(e.path()); // nothing left but bookkeeping
                continue;
            }
            all += bytes;
            let ts = v["ts"].as_i64().or_else(|| id.get(..13).and_then(|x| x.parse().ok()));
            runs.push(json!({"id": id, "ts": ts, "files": files, "bytes": bytes, "categories": v["categories"],
                "partial": v["files"].as_u64().map(|n| n != files).unwrap_or(false)}));
        }
    }
    runs.sort_by(|a, b| b["ts"].as_i64().cmp(&a["ts"].as_i64()));
    json!({"runs": runs, "bytes": all})
}

pub fn run(qdir: &Path, categories: &[String]) -> Value {
    crate::native::background(|| {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let run_id = format!("{}{:03}", now_ms(), SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 1000);
        let rdir = qdir.join(&run_id);
        if let Err(e) = std::fs::create_dir_all(&rdir) {
            return json!({"run_id": null, "moved_files": 0, "moved_bytes": 0, "skipped": 0, "errors": [e.to_string()]});
        }
        let mut manifest = std::fs::File::create(rdir.join("manifest.jsonl")).ok();
        let (mut moved, mut bytes, mut skipped, mut n) = (0u64, 0u64, 0u64, 0u64);
        let mut errors: Vec<String> = Vec::new();
        let mut done_cats = Vec::new();
        // Programs that are running right now: Windows lets you move their .exe but never delete
        // it, so quarantining one leaves a file that can't be purged. Skip their whole folder.
        let running: Vec<PathBuf> = {
            let mut sys = sysinfo::System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            sys.processes().values().filter_map(|p| p.exe().and_then(|e| e.parent()).map(|d| d.to_path_buf())).collect()
        };
        for r in RULES.iter().filter(|r| categories.iter().any(|c| c == r.id)) {
            let blockers = running_blockers(r);
            if !blockers.is_empty() {
                errors.push(format!("{} skipped: close {} first", r.name, blockers.join(", ")));
                continue;
            }
            done_cats.push(r.id);
            walk(r, |p, sz, _| {
                if running.iter().any(|d| p.starts_with(d)) {
                    skipped += 1;
                    return;
                }
                n += 1;
                let dest = rdir.join(format!("{n}.q"));
                let ok = std::fs::rename(p, &dest).is_ok()
                    || (std::fs::copy(p, &dest).is_ok() && std::fs::remove_file(p).map_err(|_| { let _ = std::fs::remove_file(&dest); }).is_ok());
                if ok {
                    moved += 1;
                    bytes += sz;
                    if let Some(m) = manifest.as_mut() {
                        let _ = writeln!(m, "{}", json!({"o": p.display().to_string(), "q": format!("{n}.q"), "b": sz}));
                    }
                } else {
                    skipped += 1; // in use or access denied
                }
            });
        }
        drop(manifest);
        let _ = std::fs::write(rdir.join("run.json"), json!({"ts": now_ms(), "files": moved, "bytes": bytes, "categories": done_cats}).to_string());
        if moved == 0 {
            let _ = std::fs::remove_dir_all(&rdir);
        }
        if skipped > 0 {
            errors.push(format!("{skipped} files were in use or protected and were left in place"));
        }
        json!({"run_id": if moved > 0 { Some(run_id) } else { None }, "moved_files": moved, "moved_bytes": bytes, "skipped": skipped, "errors": errors})
    })
}

pub fn undo(qdir: &Path, run_id: &str) -> Value {
    if !run_id.chars().all(|c| c.is_ascii_digit()) || run_id.is_empty() {
        return json!({"restored": 0, "errors": ["invalid run id"]});
    }
    let rdir = qdir.join(run_id);
    let Ok(text) = std::fs::read_to_string(rdir.join("manifest.jsonl")) else {
        return json!({"restored": 0, "errors": ["this cleanup can no longer be undone"]});
    };
    let roots = all_roots();
    let (mut restored, mut errors) = (0u64, Vec::<String>::new());
    let mut remaining: Vec<String> = Vec::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        let (Some(o), Some(q)) = (v["o"].as_str(), v["q"].as_str()) else { continue };
        // the stored name must be exactly "<digits>.q" inside this run folder
        let valid_q = q.strip_suffix(".q").map(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false);
        let orig = PathBuf::from(o);
        // and the destination must lie inside a folder a cleaner rule owns
        let parent_ok = orig.is_absolute()
            && !o.contains("..")
            && orig.parent().and_then(nearest_existing).map(|p| roots.iter().any(|r| p.starts_with(r))).unwrap_or(false);
        if !valid_q || !parent_ok {
            remaining.push(line.to_string()); // refused ≠ discarded: the file stays in quarantine
            if errors.len() < 5 {
                errors.push(format!("refused unsafe manifest entry (kept in quarantine): {o}"));
            }
            continue;
        }
        let src = rdir.join(q);
        if !src.exists() {
            continue;
        }
        if orig.exists() {
            remaining.push(line.to_string()); // keep both: never overwrite, never discard
            if errors.len() < 5 {
                errors.push(format!("kept in quarantine (a newer file exists at the original path): {o}"));
            }
            continue;
        }
        if let Some(parent) = orig.parent() {
            let _ = std::fs::create_dir_all(parent);
            // re-check after creating folders, immediately before the move: closes the
            // window where a junction could be planted to redirect the restore
            let still_inside = parent.canonicalize().map(|p| roots.iter().any(|r| p.starts_with(r))).unwrap_or(false);
            let is_junction = std::fs::symlink_metadata(parent).map(|m| is_reparse(&m)).unwrap_or(true);
            if !still_inside || is_junction {
                remaining.push(line.to_string());
                if errors.len() < 5 {
                    errors.push(format!("destination changed during restore, refused (kept in quarantine): {o}"));
                }
                continue;
            }
        }
        if std::fs::rename(&src, &orig).is_ok() || (std::fs::copy(&src, &orig).is_ok() && std::fs::remove_file(&src).is_ok()) {
            restored += 1;
        } else {
            remaining.push(line.to_string());
            if errors.len() < 5 {
                errors.push(format!("could not restore {o}; it stays in quarantine"));
            }
        }
    }
    if remaining.is_empty() {
        let _ = std::fs::remove_dir_all(&rdir);
    } else {
        // shrink the run to what is still there so a later undo can retry
        let _ = std::fs::write(rdir.join("manifest.jsonl"), remaining.join("\n") + "\n");
    }
    json!({"restored": restored, "remaining": remaining.len(), "errors": errors})
}

/// The deepest existing ancestor (canonicalized): the original folder may have been removed.
fn nearest_existing(p: &Path) -> Option<PathBuf> {
    let mut cur = Some(p);
    while let Some(c) = cur {
        if let Ok(x) = c.canonicalize() {
            return Some(x);
        }
        cur = c.parent();
    }
    None
}

/// Permanently delete quarantined runs (all, or only those older than 7 days).
#[derive(Default, Serialize)]
pub struct PurgeResult {
    pub freed_bytes: u64,
    pub deleted: u64,
    /// files another program protects (e.g. an AI-tool sandbox filter): removed at next restart
    pub pending_reboot: u64,
    pub failed: u64,
}

/// Delete every file under `dir` one by one (never stop at the first failure).
/// Read-only flags are cleared; files that still refuse are scheduled for deletion at restart.
fn delete_tree(dir: &Path, r: &mut PurgeResult) {
    let mut stack = vec![dir.to_path_buf()];
    let mut dirs = Vec::new();
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        dirs.push(d);
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
            if m.is_dir() && !is_reparse(&m) {
                stack.push(p);
                continue;
            }
            let size = m.len();
            let mut ok = std::fs::remove_file(&p).is_ok();
            if !ok {
                let mut perm = m.permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                perm.set_readonly(false);
                let _ = std::fs::set_permissions(&p, perm);
                ok = std::fs::remove_file(&p).is_ok();
            }
            if ok {
                r.deleted += 1;
                r.freed_bytes += size;
            } else if crate::native::delete_on_reboot(&p) {
                // free the space now: emptying the file is allowed even where deleting is blocked
                if std::fs::OpenOptions::new().write(true).open(&p).and_then(|f| f.set_len(0)).is_ok() {
                    r.freed_bytes += size;
                }
                r.pending_reboot += 1;
            } else {
                r.failed += 1;
            }
        }
    }
    // remove now-empty folders, deepest first; folders with pending files go at restart too
    for d in dirs.iter().rev() {
        if std::fs::remove_dir(d).is_err() && r.pending_reboot > 0 {
            crate::native::delete_on_reboot(d);
        }
    }
}

/// Permanently delete quarantined runs (all, or only those older than 7 days).
pub fn purge(qdir: &Path, only_expired: bool) -> PurgeResult {
    let mut r = PurgeResult::default();
    let cutoff = now_ms() - QUARANTINE_DAYS * 86_400_000;
    if let Ok(rd) = std::fs::read_dir(qdir) {
        for e in rd.flatten() {
            let meta: Value = std::fs::read_to_string(e.path().join("run.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
            if only_expired && meta["ts"].as_i64().unwrap_or(0) > cutoff {
                continue;
            }
            // runs with pending restart deletions are marked so they stop showing as normal runs
            delete_tree(&e.path(), &mut r);
        }
    }
    r
}

pub fn auto_categories() -> Vec<String> {
    RULES.iter().filter(|r| r.auto).map(|r| r.id.to_string()).collect()
}

// ------------------------------------------------------------------ memory

pub fn memory_status() -> Value {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let me = sysinfo::get_current_pid().ok();
    // our process + WebView2 children (two levels: browser process → renderers)
    let mut app = 0u64;
    if let Some(me) = me {
        let mut tree = vec![me];
        for _ in 0..3 {
            for (pid, p) in sys.processes() {
                if let Some(parent) = p.parent() {
                    if tree.contains(&parent) && !tree.contains(pid) {
                        tree.push(*pid);
                    }
                }
            }
        }
        app = tree.iter().filter_map(|p| sys.process(*p)).map(|p| p.memory()).sum();
    }
    json!({"total": sys.total_memory(), "used": sys.used_memory(), "available": sys.available_memory(),
           "app_bytes": app, "swap_total": sys.total_swap(), "swap_used": sys.used_swap()})
}

pub fn memory_trim() -> Value {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let before = sys.available_memory();
    let n = crate::native::trim_working_sets();
    std::thread::sleep(std::time::Duration::from_millis(400));
    sys.refresh_memory();
    json!({"before_available": before, "after_available": sys.available_memory(), "processes": n})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roots_must_be_temp_or_cache() {
        let base = std::env::temp_dir().join(format!("oph-roots-{}", std::process::id()));
        let ok = base.join("a").join("Temp");
        let cache = base.join("a").join("GPUCache");
        let docs = base.join("a").join("Documents");
        for d in [&ok, &cache, &docs] {
            std::fs::create_dir_all(d).unwrap();
        }
        assert!(safe_root(&ok));
        assert!(safe_root(&cache));
        assert!(!safe_root(&docs), "a Documents folder must never be a cleanup root");
        let _ = std::fs::remove_dir_all(base);
    }
}

#[cfg(test)]
mod purge_tests {
    use super::*;

    #[test]
    fn purge_removes_readonly_files_and_info_reflects_disk() {
        let q = std::env::temp_dir().join(format!("oph-purge-test-{}", std::process::id()));
        let run = q.join("1700000000000001");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(run.join("run.json"), r#"{"ts":1700000000000,"files":3,"bytes":30}"#).unwrap();
        for i in 0..3 {
            std::fs::write(run.join(format!("{i}.q")), b"0123456789").unwrap();
        }
        // a read-only file used to stop remove_dir_all and leave the whole run behind
        let ro = run.join("1.q");
        let mut p = std::fs::metadata(&ro).unwrap().permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&ro, p).unwrap();
        std::fs::remove_file(run.join("2.q")).unwrap(); // partly purged run: info must count disk, not run.json
        let info = quarantine_info(&q);
        assert_eq!(info["runs"][0]["files"], 2);
        assert_eq!(info["bytes"], 20);
        let r = purge(&q, false);
        assert_eq!((r.deleted, r.failed, r.pending_reboot), (3, 0, 0)); // 2 .q files + run.json
        assert_eq!(r.freed_bytes, 20 + 41);
        assert!(!run.exists());
        assert_eq!(quarantine_info(&q)["runs"].as_array().unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(&q);
    }
}
