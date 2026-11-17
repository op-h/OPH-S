//! Enforcement on this PC, using what Windows already provides (no driver):
//! - domains → a marked section in the hosts file (0.0.0.0 sinkhole)
//! - IPs     → Windows Firewall (WFP) rules via `netsh advfirewall`
//! LAN devices are protected separately by the DNS resolver (dns.rs).
//!
//! The block set is derived from one source of truth: the manual blocklist
//! plus every alert whose status is "blocked".

use crate::core::Core;
use crate::native::run_hidden;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const RULE: &str = "OPH Sentinel - blocked IPs";
const BEGIN: &str = "# >>> OPH Sentinel blocklist (managed automatically — do not edit) >>>";
const END: &str = "# <<< OPH Sentinel blocklist <<<";
const MAX_HOSTS: usize = 5000;

static PENDING: AtomicBool = AtomicBool::new(false);

pub fn request_sync(core: &Core) {
    if PENDING.swap(true, Ordering::SeqCst) {
        return; // a sync is already scheduled
    }
    let Some(app) = core.app.get().cloned() else {
        PENDING.store(false, Ordering::SeqCst);
        return;
    };
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2)); // debounce bursts
        PENDING.store(false, Ordering::SeqCst);
        use tauri::Manager;
        let core = app.state::<Arc<Core>>();
        sync(&core);
    });
}

fn block_sets(core: &Core) -> (BTreeSet<String>, BTreeSet<String>) {
    let db = core.db.lock().unwrap();
    let mut doms = BTreeSet::new();
    let mut ips = BTreeSet::new();
    for (v, kind, _, _) in db.list_entries("block") {
        match kind.as_str() {
            "domain" => {
                doms.insert(v);
            }
            "ip" | "cidr" => {
                ips.insert(v);
            }
            _ => {}
        }
    }
    let rows = db.group("SELECT indicator, CASE indicator_type WHEN 'domain' THEN 1 ELSE 0 END FROM alerts WHERE status = 'blocked' AND indicator_type IN ('domain','ip')", []);
    for (v, is_dom) in rows {
        if is_dom == 1 {
            doms.insert(v);
        } else {
            ips.insert(v);
        }
    }
    let l = core.lists.read().unwrap();
    // strict validation: only well-formed names / addresses may reach the hosts file or netsh
    // The hosts file has no wildcards: every blocked name (parent and each seen subdomain)
    // needs its own line. Our DNS resolver covers subdomains via suffix matching.
    let doms: BTreeSet<String> = doms.into_iter().filter_map(|d| oph_proto::normalize_domain(&d)).filter(|d| d.contains('.') && !l.domain_allowed(d)).collect();
    let ips: BTreeSet<String> = ips
        .into_iter()
        .filter(|v| {
            if let Ok(ip) = v.parse::<std::net::Ipv4Addr>() {
                !l.ip_allowed(u32::from(ip)) && !ip.is_private() && !ip.is_loopback()
            } else {
                crate::core::parse_cidr(v).map(|(n, _)| !l.ip_allowed(n)).unwrap_or(false)
            }
        })
        .collect();
    (doms, ips)
}

pub fn sync(core: &Core) {
    if !cfg!(windows) {
        return;
    }
    let (doms, ips) = block_sets(core);
    if !core.admin {
        if !doms.is_empty() || !ips.is_empty() {
            core.sys(
                "firewall.error",
                "low",
                "Administrator rights are needed to enforce blocks on this PC (hosts file + Windows Firewall). Devices using OPH DNS are still protected. Restart OPH Sentinel as administrator or enable Start with Windows.",
            );
        }
        return;
    }
    let mut errors = Vec::new();
    match write_hosts(&doms) {
        Ok(n) if n < doms.len() => errors.push(format!("hosts file holds the first {n} of {} blocked domains; LAN devices using OPH DNS are protected against all of them", doms.len())),
        Ok(_) => {}
        Err(e) => errors.push(format!("hosts file: {e}")),
    }
    let _ = run_hidden("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={RULE}")]);
    let list: Vec<&String> = ips.iter().collect();
    for chunk in list.chunks(400) {
        let joined = chunk.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",");
        for dir in ["out", "in"] {
            match run_hidden("netsh", &["advfirewall", "firewall", "add", "rule", &format!("name={RULE}"), &format!("dir={dir}"), "action=block", "enable=yes", "profile=any", &format!("remoteip={joined}")]) {
                Ok((true, _)) => {}
                Ok((false, out)) => errors.push(format!("firewall: {}", out.trim())),
                Err(e) => errors.push(format!("firewall: {e}")),
            }
        }
    }
    if errors.is_empty() {
        let mut e = oph_proto::WireEvent::new("firewall", "firewall.sync", "info", format!("Enforcement updated on this PC: {} domains in hosts file, {} addresses in Windows Firewall", doms.len().min(MAX_HOSTS), ips.len()));
        e.host = "this-pc".into();
        e.raw = serde_json::json!({"domains": doms.len(), "ips": ips.len()});
        core.emit(e);
    } else {
        core.sys("firewall.error", "medium", errors.join("; "));
    }
}

fn hosts_path() -> std::path::PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    std::path::Path::new(&root).join("System32\\drivers\\etc\\hosts")
}

fn write_hosts(doms: &BTreeSet<String>) -> std::io::Result<usize> {
    let n = write_hosts_at(&hosts_path(), doms)?;
    let _ = run_hidden("ipconfig", &["/flushdns"]);
    Ok(n)
}

/// Remove only the OPH section (used by the uninstaller); never touches other lines.
pub fn remove_hosts_section(path: &std::path::Path) {
    let _ = write_hosts_at(path, &BTreeSet::new());
}

fn write_hosts_at(path: &std::path::Path, doms: &BTreeSet<String>) -> std::io::Result<usize> {
    use std::io::{Error, ErrorKind};
    // Read raw bytes and refuse to continue on any problem: a failed or partial read
    // must never turn into "rewrite the file with only our section".
    let bytes = std::fs::read(path)?;
    let current = String::from_utf8(bytes).map_err(|_| Error::new(ErrorKind::InvalidData, "hosts file is not UTF-8/ASCII; left unchanged"))?;
    if doms.is_empty() && !current.contains(BEGIN) {
        return Ok(0); // nothing of ours to add or remove: never touch the file
    }
    let mut out = String::with_capacity(current.len() + doms.len() * 32);
    let mut inside = false;
    for line in current.split_inclusive('\n') {
        let t = line.trim();
        if t == BEGIN {
            inside = true;
            continue;
        }
        if t == END {
            inside = false;
            continue;
        }
        if !inside {
            out.push_str(line); // preserve other content byte-for-byte
        }
    }
    if inside {
        return Err(Error::new(ErrorKind::InvalidData, "hosts file has an unterminated OPH section; left unchanged"));
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str("\r\n");
    }
    let mut written = 0;
    if !doms.is_empty() {
        out.push_str(BEGIN);
        out.push_str("\r\n");
        for d in doms.iter().take(MAX_HOSTS) {
            out.push_str("0.0.0.0 ");
            out.push_str(d);
            out.push_str("\r\n");
            written += 1;
        }
        out.push_str(END);
        out.push_str("\r\n");
    }
    if out == current {
        return Ok(written);
    }
    let bak = path.with_extension("oph.bak");
    if !bak.exists() {
        std::fs::write(&bak, current.as_bytes())?; // one-time backup of the user's original file
    }
    let tmp = path.with_extension("oph.tmp");
    std::fs::write(&tmp, out.as_bytes())?;
    std::fs::rename(&tmp, path)?; // atomic replace on the same volume
    Ok(written)
}

/// Make sure the inbound rule exists with the current ports (silent; the app runs elevated).
pub fn ensure_inbound(core: &Core) {
    if !cfg!(windows) || !core.admin {
        return;
    }
    let s = core.settings();
    let present = run_hidden("netsh", &["advfirewall", "firewall", "show", "rule", "name=OPH Sentinel - inbound"])
        .map(|(ok, out)| ok && out.contains(&crate::share::PORT.to_string()) && out.contains(&s.ingest_port.to_string()) && out.contains(&s.syslog_port.to_string()))
        .unwrap_or(false);
    if !present {
        let (ok, msg) = setup_ports(core);
        if !ok {
            core.sys("system.error", "low", format!("Could not open OPH-S firewall ports: {msg}"));
        }
    }
}

/// Open the inbound ports OPH-S listens on (direct when elevated, UAC prompt otherwise).
pub fn setup_ports(core: &Core) -> (bool, String) {
    if !cfg!(windows) {
        return (false, "Only needed on Windows".into());
    }
    let s = core.settings();
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    let dns_port = s.dns_bind.rsplit(':').next().unwrap_or("53").to_string();
    let rule = "OPH Sentinel - inbound";
    let script = [
        "@echo off".to_string(),
        format!("netsh advfirewall firewall delete rule name=\"{rule}\" >nul 2>&1"),
        format!("netsh advfirewall firewall add rule name=\"{rule}\" dir=in action=allow protocol=UDP localport={dns_port},{} profile=private program=\"{exe}\"", s.syslog_port),
        format!("netsh advfirewall firewall add rule name=\"{rule}\" dir=in action=allow protocol=TCP localport={},{},{dns_port} profile=private program=\"{exe}\"", s.ingest_port, crate::share::PORT),
        String::new(),
    ]
    .join("\r\n");
    let path = core.dir.join("open-ports.cmd");
    if let Err(e) = std::fs::write(&path, &script) {
        return (false, e.to_string());
    }
    if core.admin {
        // already elevated: run directly, no UAC prompt
        return match run_hidden("cmd", &["/c", &path.display().to_string()]) {
            Ok((true, _)) => (true, format!("Inbound rules set for UDP {dns_port}, {} and TCP {}, {} (private networks only).", s.syslog_port, s.ingest_port, crate::share::PORT)),
            Ok((false, out)) => (false, out.lines().next().unwrap_or("netsh failed").trim().to_string()),
            Err(e) => (false, e.to_string()),
        };
    }
    let ps = format!(
        "$p = Start-Process -FilePath cmd.exe -ArgumentList '/c \"{}\"' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode",
        path.display()
    );
    match run_hidden("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps]) {
        Ok((true, _)) => (true, format!("Inbound rules added for UDP {dns_port}, {} and TCP {} (private networks only).", s.syslog_port, s.ingest_port)),
        Ok((false, out)) if out.contains("canceled") || out.contains("cancelled") => (false, "Administrator approval was declined.".into()),
        Ok((false, out)) => (false, format!("Windows refused the change: {}", out.lines().next().unwrap_or("").trim())),
        Err(e) => (false, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hosts_rewrite_is_safe() {
        let dir = std::env::temp_dir().join(format!("oph-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("hosts");
        let orig = "# comment\r\n127.0.0.1 localhost\r\n\r\n# TailscaleHostsSection\r\n100.1.2.3 x.ts.net.\r\n# TailscaleHostsSectionEnd\r\n";
        std::fs::write(&p, orig).unwrap();
        // nothing to do -> untouched
        assert_eq!(write_hosts_at(&p, &BTreeSet::new()).unwrap(), 0);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), orig);
        // add, then remove: original restored byte-for-byte
        let d: BTreeSet<String> = ["evil.example".to_string()].into();
        write_hosts_at(&p, &d).unwrap();
        let with = std::fs::read_to_string(&p).unwrap();
        assert!(with.starts_with(orig) && with.contains("0.0.0.0 evil.example\r\n"));
        write_hosts_at(&p, &BTreeSet::new()).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), orig);
        assert!(p.with_extension("oph.bak").exists());
        // non-UTF-8 file -> error, file unchanged
        std::fs::write(&p, [0xff, 0xfe, 0x31, 0x00]).unwrap();
        assert!(write_hosts_at(&p, &d).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), vec![0xff, 0xfe, 0x31, 0x00]);
        // missing file -> error, nothing created
        let _ = std::fs::remove_file(&p);
        assert!(write_hosts_at(&p, &d).is_err());
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
