//! Leak Check — which devices get around your protection, and why.
//!
//! Every other filter shows what it blocked; OPH-S shows what got around it, by
//! comparing independent views of the same household traffic:
//!   resolver (dns.rs) · Windows DNS client via ETW (etw.rs) · sockets (netstat2)
//!
//! A  hidden lookup on this PC   resolver saw a query from this PC that Windows never sent
//!                               (ETW 3019/3010 within ±2 s) → a program with its own DNS
//! B  this PC asks another server ETW 3010 to a server that is not OPH-S, or a socket to
//!                               a DoH resolver IP on :443 / any :853 ("Secure DNS in X")
//! C  went quiet                 ARP-online device, no resolver query for N min while its
//!                               14-day baseline for this hour is ≥ 30 (Private DNS / VPN)
//! D  encrypted-DNS attempt      device resolved a canary or DoH bootstrap name
//!
//! Hot-path rule: dns.rs only calls `on_query`, which does a few atomic/short-mutex
//! operations and a non-blocking `try_send` into a bounded ring. All matching runs on
//! the `oph-leak` worker thread. Everything is warn-only.

use crate::core::Core;
use oph_proto::{now_ms, WireEvent};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Off-switch names that must get NXDOMAIN (a 0.0.0.0 answer does NOT disable them):
/// Firefox DoH canary and Apple iCloud Private Relay.
pub const CANARIES: &[&str] = &["use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com"];

/// DoH / DoT bootstrap names of public encrypted-DNS services.
pub const DOH_NAMES: &[&str] = &[
    "dns.google", "dns.google.com", "8888.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
    "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "dns.nextdns.io",
    "doh.cleanbrowsing.org", "dns.adguard-dns.com", "dns.adguard.com", "unfiltered.adguard-dns.com", "doh.dns.sb",
    "dns.controld.com", "freedns.controld.com", "doh.mullvad.net", "dns.mullvad.net", "dns.alidns.com", "doh.pub",
    "dns.twnic.tw", "ordns.he.net", "dns.brahma.world", "doh.libredns.gr", "dns.switch.ch", "doh.ffmuc.net",
];

/// Public DoH/DoT resolver IPs (for "Secure DNS in <program>" via the socket table).
pub const DOH_IPS: &[&str] = &[
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "9.9.9.9", "149.112.112.112",
    "9.9.9.10", "9.9.9.11", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15", "94.140.14.140",
    "185.228.168.9", "185.228.169.9", "76.76.2.0", "76.76.10.0", "45.90.28.0", "45.90.30.0", "194.242.2.2", "223.5.5.5",
    "223.6.6.6", "185.222.222.222", "45.11.45.11", "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111",
    "2606:4700:4700::1001", "2620:fe::fe", "2620:fe::9",
];

/// Virtual machines / containers doing their own DNS (WSL, Android subsystem, Hyper-V, Docker).
const VM_PROCESSES: &[&str] = &["crosvm.exe", "vmmem", "vmmemws", "vmwp.exe", "wslhost.exe", "wslservice.exe", "com.docker.backend.exe", "vpnkit.exe", "virtualboxvm.exe", "vmware-vmx.exe"];

/// Tools that legitimately talk DNS themselves.
const DNS_TOOLS: &[&str] = &["nslookup.exe", "dig.exe", "kdig.exe", "drill.exe", "dnslookup.exe", "q.exe", "resolve-dnsname", "pwsh.exe"];

struct Tap {
    ts: i64,
    port: u16,
    tcp: bool,
    name: String,
}

struct EtwWire {
    ts: i64,
    pid: u32,
    name: String,
    server: Option<String>,
}

pub struct Engine {
    tap_tx: SyncSender<Tap>,
    tap_rx: Mutex<Option<Receiver<Tap>>>,
    etw: Mutex<VecDeque<EtwWire>>,
    pub dropped: AtomicU64,
    /// (client ip) → (hour start ms, queries this hour) — flushed to st.dns_hourly
    hourly: Mutex<HashMap<String, (i64, u32)>>,
    /// last encrypted-DNS attempt per client (for C escalation)
    enc: Mutex<HashMap<String, (i64, String)>>,
    emitted: Mutex<HashMap<String, i64>>,
}

impl Default for Engine {
    fn default() -> Self {
        let (tap_tx, rx) = sync_channel(4096);
        Engine {
            tap_tx,
            tap_rx: Mutex::new(Some(rx)),
            etw: Mutex::new(VecDeque::with_capacity(1024)),
            dropped: AtomicU64::new(0),
            hourly: Mutex::new(HashMap::new()),
            enc: Mutex::new(HashMap::new()),
            emitted: Mutex::new(HashMap::new()),
        }
    }
}

/// mDNS (224.0.0.251, ff02::fb) and LLMNR (224.0.0.252, ff02::1:3): local-network name discovery.
fn is_multicast(server: &str) -> bool {
    server.parse::<std::net::IpAddr>().map(|ip| ip.is_multicast()).unwrap_or(false)
}

pub fn is_canary(name: &str) -> bool {
    CANARIES.contains(&name)
}

fn is_doh_name(name: &str) -> bool {
    DOH_NAMES.contains(&name) || is_canary(name)
}

impl Engine {
    /// Hot path (dns.rs handle): must stay cheap and never block.
    pub fn on_query(&self, core: &Core, client: &str, port: u16, tcp: bool, name: &str, is_self: bool) {
        let now = now_ms();
        {
            let hour = now - now % 3_600_000;
            let mut h = self.hourly.lock().unwrap();
            let e = h.entry(client.to_string()).or_insert((hour, 0));
            if e.0 != hour {
                // previous hour is flushed by the worker; keep counting the new one
                *e = (hour, 0);
            }
            e.1 += 1;
        }
        if is_self && self.tap_tx.try_send(Tap { ts: now, port, tcp, name: name.to_string() }).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        if is_doh_name(name) {
            self.enc.lock().unwrap().insert(client.to_string(), (now, name.to_string()));
            if self.once(&format!("D|{client}|{name}"), 3_600_000) && core.monitoring_on() {
                let label = core.host_label(client);
                let what = if is_canary(name) { "an encrypted-DNS / Private Relay check name" } else { "an encrypted-DNS (DoH/DoT) service" };
                let mut e = WireEvent::new("leak", "leak.encrypted_dns", "info", format!("{label} looked up {name}, {what}. If it switches to encrypted DNS, OPH-S can no longer see or filter its lookups."));
                e.host = label.clone();
                e.src_ip = Some(client.to_string());
                e.domain = Some(name.to_string());
                e.raw = json!({"class": "D", "name": name});
                core.emit(e);
                record(core, client, &label, name, "D", "info", name);
            }
        }
    }

    /// ETW thread: 3019 (query sent on the wire) / 3010 (sent to server X).
    pub fn on_etw(&self, pid: u32, name: &str, server: Option<String>) {
        let mut r = self.etw.lock().unwrap();
        if r.len() >= 4096 {
            r.pop_front();
        }
        r.push_back(EtwWire { ts: now_ms(), pid, name: name.trim_end_matches('.').to_ascii_lowercase(), server });
    }

    fn once(&self, key: &str, window_ms: i64) -> bool {
        let now = now_ms();
        let mut m = self.emitted.lock().unwrap();
        if m.len() > 5000 {
            m.retain(|_, t| now - *t < 86_400_000);
        }
        match m.get(key) {
            Some(t) if now - t < window_ms => false,
            _ => {
                m.insert(key.to_string(), now);
                true
            }
        }
    }
}

/// Upsert a leak card (st.leaks) — one row per (device, actor, class).
fn record(core: &Core, dev: &str, dev_name: &str, actor: &str, class: &str, sev: &str, sample: &str) {
    let now = now_ms();
    let db = core.db.lock().unwrap();
    let cur: Option<(i64, String, String)> = db
        .conn
        .query_row("SELECT id, samples, status FROM leaks WHERE dev = ?1 AND actor = ?2 AND class = ?3", rusqlite::params![dev, actor, class], |r| {
            Ok((r.get(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default(), r.get(2)?))
        })
        .ok();
    match cur {
        Some((id, samples, status)) => {
            if status == "ignored" {
                return;
            }
            let mut s: Vec<String> = serde_json::from_str(&samples).unwrap_or_default();
            if !sample.is_empty() && !s.iter().any(|x| x == sample) {
                s.insert(0, sample.to_string());
                s.truncate(5);
            }
            let rank = |v: &str| oph_proto::severity_rank(v);
            let _ = db.conn.execute(
                "UPDATE leaks SET last_ts = ?1, count = count + 1, samples = ?2, status = 'open', dev_name = ?3,
                 sev = CASE WHEN ?4 > (CASE sev WHEN 'info' THEN 0 WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 ELSE 4 END) THEN ?5 ELSE sev END
                 WHERE id = ?6",
                rusqlite::params![now, serde_json::to_string(&s).unwrap(), dev_name, rank(sev), sev, id],
            );
        }
        None => {
            let _ = db.conn.execute(
                "INSERT INTO leaks(dev, dev_name, actor, class, sev, first_ts, last_ts, count, samples, status) VALUES(?1,?2,?3,?4,?5,?6,?6,1,?7,'open')",
                rusqlite::params![dev, dev_name, actor, class, sev, now, serde_json::to_string(&vec![sample]).unwrap()],
            );
        }
    }
}

fn mark_fixed(core: &Core, id: i64, why: &str) {
    let row: Option<(String, String, String)> = core
        .db
        .lock()
        .unwrap()
        .conn
        .query_row("SELECT dev_name, actor, class FROM leaks WHERE id = ? AND status = 'open'", [id], |r| Ok((r.get::<_, Option<String>>(0)?.unwrap_or_default(), r.get(1)?, r.get(2)?)))
        .ok();
    if let Some((dev, actor, class)) = row {
        let _ = core.db.lock().unwrap().conn.execute("UPDATE leaks SET status = 'fixed', last_ts = ? WHERE id = ?", rusqlite::params![now_ms(), id]);
        let mut e = WireEvent::new("leak", "leak.fixed", "info", format!("Leak closed on {dev}: {actor} ({class}) — {why}"));
        e.host = dev;
        e.raw = json!({"class": class, "leak_id": id});
        core.emit(e);
    }
}

fn hidden_severity(core: &Core, process: &str, name: &str, misses: usize) -> &'static str {
    let p = process.to_ascii_lowercase();
    if matches!(core.domain_verdict(name), crate::core::Verdict::Intel(_) | crate::core::Verdict::Manual) {
        return "high";
    }
    // a program FIM saw arrive in the last 7 days
    let since = now_ms() - 7 * 86_400_000;
    if !p.is_empty() && !p.starts_with("unknown") {
        let n = core.db.lock().unwrap().scalar(
            "SELECT count(*) FROM events WHERE source = 'file' AND kind = 'file.created' AND ts >= ?1 AND ulower(json_extract(raw, '$.path')) LIKE ?2",
            rusqlite::params![since, format!("%\\{p}")],
        );
        if n > 0 {
            return "high";
        }
    }
    if DNS_TOOLS.contains(&p.as_str()) || VM_PROCESSES.contains(&p.as_str()) {
        return "info";
    }
    if misses >= 3 {
        "medium"
    } else {
        "low"
    }
}

/// Owner table: local port → pid for UDP/TCP sockets on this PC.
fn port_map() -> HashMap<(bool, u16), u32> {
    let mut m = HashMap::new();
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    {
        use netstat2::*;
        if let Ok(socks) = get_sockets_info(AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6, ProtocolFlags::TCP | ProtocolFlags::UDP) {
            for s in socks {
                let pid = s.associated_pids.first().copied().unwrap_or(0);
                match s.protocol_socket_info {
                    ProtocolSocketInfo::Udp(u) => {
                        m.insert((false, u.local_port), pid);
                    }
                    ProtocolSocketInfo::Tcp(t) => {
                        m.insert((true, t.local_port), pid);
                    }
                }
            }
        }
    }
    m
}

pub fn start(core: Arc<Core>) {
    let Some(rx) = core.leak.tap_rx.lock().unwrap().take() else { return };
    std::thread::Builder::new()
        .name("oph-leak".into())
        .spawn(move || worker(core, rx))
        .expect("spawn leak worker");
}

fn worker(core: Arc<Core>, rx: Receiver<Tap>) {
    let mut names = oph_proto::ProcessNames::new();
    let mut pending: VecDeque<(Tap, Option<u32>, Option<String>)> = VecDeque::new();
    let mut misses: HashMap<String, VecDeque<i64>> = HashMap::new();
    let mut ports = port_map();
    let mut last_ports = now_ms();
    let mut tick: u64 = 0;
    let mut next_tick = now_ms() + 250;
    loop {
        // wake immediately when a lookup from this PC arrives: short-lived tools (nslookup)
        // close their socket within milliseconds, so the owner table must be read right away
        let mut fresh = Vec::new();
        let wait = (next_tick - now_ms()).clamp(0, 250) as u64;
        if let Ok(t) = rx.recv_timeout(Duration::from_millis(wait)) {
            fresh.push(t);
        }
        while let Ok(t) = rx.try_recv() {
            fresh.push(t);
        }
        let now = now_ms();
        let ticked = now >= next_tick;
        if ticked {
            next_tick = now + 250;
            tick += 1;
        }
        if !fresh.is_empty() || now - last_ports > 5_000 {
            ports = port_map();
            last_ports = now;
        }
        for t in fresh {
            if t.name.ends_with(".arpa") {
                continue; // reverse lookups by diagnostic tools are not leaks
            }
            let pid = ports.get(&(t.tcp, t.port)).copied();
            // name the program now, while it is still running
            let pname = pid.filter(|p| *p > 4).map(|p| names.name(p));
            pending.push_back((t, pid, pname));
        }
        while pending.front().map(|(t, _, _)| now - t.ts > 2_500).unwrap_or(false) {
            let (t, pid, pname) = pending.pop_front().unwrap();
            let matched = core.leak.etw.lock().unwrap().iter().any(|w| w.name == t.name && (w.ts - t.ts).abs() <= 2_500);
            if matched {
                continue;
            }
            let process = pname.filter(|n| !n.starts_with("pid ")).unwrap_or_else(|| "unknown program".to_string());
            // count unknown programs together (the port differs on every query)
            let key = process.to_ascii_lowercase();
            let q = misses.entry(key.clone()).or_default();
            q.push_back(now);
            while q.front().map(|x| now - x > 600_000).unwrap_or(false) {
                q.pop_front();
            }
            let n = q.len();
            let sev = hidden_severity(&core, &process, &t.name, n);
            if sev != "low" && core.monitoring_on() {
                let local = core.net.lock().unwrap().local_ip.clone().unwrap_or_default();
                record(&core, &local, "this-pc", &process, "A", sev, &t.name);
                if core.leak.once(&format!("A|{key}"), 600_000) {
                    let mut e = WireEvent::new("leak", "leak.hidden_lookup", sev, format!("{process} resolved {} without going through Windows' DNS client ({n} times in 10 min). It uses its own DNS code.", t.name));
                    e.host = "this-pc".into();
                    e.src_ip = Some(local);
                    e.domain = Some(t.name.clone());
                    e.process = Some(process.clone());
                    e.raw = json!({"class": "A", "port": t.port, "tcp": t.tcp, "pid": pid, "misses_10min": n,
                        "note": if pid.is_none() { "the program closed its socket before it could be identified (typical for nslookup-style tools)" } else { "" }});
                    core.emit(e);
                }
            }
        }
        if misses.len() > 500 {
            misses.retain(|_, q| q.back().map(|x| now - x < 600_000).unwrap_or(false));
        }

        if !ticked {
            continue;
        }
        // --- B: Windows sent a query to a server that is not OPH-S
        let ours: HashSet<String> = {
            let mut s: HashSet<String> = ["127.0.0.1", "::1"].iter().map(|x| x.to_string()).collect();
            if let Some(l) = core.net.lock().unwrap().local_ip.clone() {
                s.insert(l);
            }
            s
        };
        let other: Vec<(u32, String, String)> = {
            let mut r = core.leak.etw.lock().unwrap();
            let cutoff = now - 30_000;
            while r.front().map(|w| w.ts < cutoff).unwrap_or(false) {
                r.pop_front();
            }
            r.iter()
                .filter(|w| now - w.ts < 1_000)
                .filter_map(|w| w.server.as_ref().filter(|s| !ours.contains(s.as_str()) && !s.is_empty() && !is_multicast(s)).map(|s| (w.pid, s.clone(), w.name.clone())))
                .collect()
        };
        for (pid, server, name) in other {
            let process = names.name(pid);
            if !core.leak.once(&format!("B|{process}|{server}"), 1_800_000) || !core.monitoring_on() {
                continue;
            }
            let overlay = server.starts_with("100.") || server.starts_with("fd") || server.starts_with("fe80");
            let sev = if overlay { "info" } else { "medium" };
            let why = if overlay { "a VPN / overlay network DNS (e.g. Tailscale)".to_string() } else { format!("DNS server {server}") };
            let local = core.net.lock().unwrap().local_ip.clone().unwrap_or_default();
            record(&core, &local, "this-pc", &format!("{process} → {server}"), "B", sev, &name);
            let mut e = WireEvent::new("leak", "leak.other_server", sev, format!("Windows sent a lookup for {name} ({process}) to {why} instead of OPH-S, so OPH-S cannot see or filter it."));
            e.host = "this-pc".into();
            e.domain = Some(name);
            e.process = Some(process);
            e.dst_ip = Some(server.clone());
            e.dst_port = Some(53);
            e.raw = json!({"class": "B", "server": server, "pid": pid});
            core.emit(e);
        }

        // --- B': encrypted DNS sockets (Secure DNS in a program): every 5 s
        if tick % 20 == 0 {
            let conns = core.conns.lock().unwrap().clone();
            for c in conns {
                let ip = c["remote_ip"].as_str().unwrap_or("");
                let port = c["remote_port"].as_u64().unwrap_or(0);
                let process = c["process"].as_str().unwrap_or("").to_string();
                let doh = (port == 443 && DOH_IPS.contains(&ip)) || port == 853;
                let pid = c["pid"].as_u64().unwrap_or(0);
                // pid 0/4 = sockets already closing (TIME_WAIT) owned by "System": not a real program
                if !doh || pid <= 4 || process.eq_ignore_ascii_case("System") || process.eq_ignore_ascii_case("OPH-S.exe") || !core.monitoring_on() {
                    continue;
                }
                if !core.leak.once(&format!("B2|{process}|{ip}"), 1_800_000) {
                    continue;
                }
                let local = core.net.lock().unwrap().local_ip.clone().unwrap_or_default();
                record(&core, &local, "this-pc", &format!("Secure DNS in {process}"), "B", "medium", ip);
                let mut e = WireEvent::new("leak", "leak.other_server", "medium", format!("{process} is using encrypted DNS ({ip}:{port}). Its lookups bypass OPH-S. In browsers: Settings → Privacy → Use secure DNS → Off (or OS default)."));
                e.host = "this-pc".into();
                e.process = Some(process);
                e.dst_ip = Some(ip.to_string());
                e.dst_port = Some(port as u16);
                e.raw = json!({"class": "B", "encrypted": true});
                core.emit(e);
            }
        }

        // --- every minute: flush hourly counters; every 5 min: C (went quiet) + auto-recheck
        if tick % 240 == 0 {
            flush_hourly(&core);
        }
        if tick % 1200 == 600 {
            check_quiet(&core);
            auto_recheck(&core);
        }
    }
}

fn flush_hourly(core: &Core) {
    let snapshot: Vec<(String, i64, u32)> = {
        let mut h = core.leak.hourly.lock().unwrap();
        let v = h.iter().map(|(k, (hr, n))| (k.clone(), *hr, *n)).collect();
        for (_, e) in h.iter_mut() {
            e.1 = 0; // counted into the DB below
        }
        v
    };
    let db = core.db.lock().unwrap();
    for (dev, hour, n) in snapshot {
        if n > 0 {
            let _ = db.conn.execute(
                "INSERT INTO dns_hourly(dev, hour, n) VALUES(?1, ?2, ?3) ON CONFLICT(dev, hour) DO UPDATE SET n = n + ?3",
                rusqlite::params![dev, hour, n],
            );
        }
    }
    let _ = db.conn.execute("DELETE FROM dns_hourly WHERE hour < ?", [now_ms() - 15 * 86_400_000]);
}

/// Median queries/hour for this device at this hour of day over the last 14 days, and its history length.
fn baseline(core: &Core, dev: &str) -> (Option<u32>, i64) {
    let now = now_ms();
    let hod = (now / 3_600_000) % 24;
    let db = core.db.lock().unwrap();
    let first = db.scalar("SELECT min(hour) FROM dns_hourly WHERE dev = ?", [dev]);
    let mut v: Vec<u32> = db
        .group("SELECT CAST(hour AS TEXT), n FROM dns_hourly WHERE dev = ?1 AND hour >= ?2 AND (hour / 3600000) % 24 = ?3", rusqlite::params![dev, now - 14 * 86_400_000, hod])
        .into_iter()
        .map(|(_, n)| n as u32)
        .collect();
    if v.len() < 3 {
        return (None, first);
    }
    v.sort_unstable();
    (Some(v[v.len() / 2]), first)
}

fn check_quiet(core: &Core) {
    let now = now_ms();
    let quiet_ms = core.settings().leak_quiet_minutes as i64 * 60_000;
    let local = core.net.lock().unwrap().local_ip.clone().unwrap_or_default();
    let online: Vec<(String, String)> = core.db.lock().unwrap().group_str(
        "SELECT ip, coalesce(nullif(label, ''), hostname, ip) FROM devices WHERE last_seen >= ?",
        [now - 600_000],
    );
    let last_q = core.dns_clients.lock().unwrap().clone();
    for (ip, name) in online {
        if ip == local {
            continue; // this PC is covered by A/B
        }
        let last = last_q.get(&ip).copied().unwrap_or(0);
        if now - last < quiet_ms {
            continue;
        }
        let (median, first) = baseline(core, &ip);
        if first == 0 || now - first < 3 * 86_400_000 {
            continue; // "too new": not enough history
        }
        let Some(m) = median.filter(|m| *m >= 30) else { continue };
        let enc = core.leak.enc.lock().unwrap().get(&ip).cloned().filter(|(t, _)| last > 0 && (last - t).abs() <= 600_000);
        let sev = if enc.is_some() { "high" } else { "medium" };
        let since = if last > 0 { format!("{} min", (now - last) / 60_000) } else { "a while".into() };
        let why = match &enc {
            Some((_, n)) => format!("it looked up {n} just before going quiet: it most likely switched to encrypted DNS (Android Private DNS, iCloud Private Relay, a browser's Secure DNS) or a VPN"),
            None => "likely causes: Android Private DNS, a VPN app, iCloud Private Relay, or DNS set manually on the device".into(),
        };
        record(core, &ip, &name, "all lookups", "C", sev, enc.as_ref().map(|(_, n)| n.as_str()).unwrap_or(""));
        if core.leak.once(&format!("C|{ip}"), 3_600_000) && core.monitoring_on() {
            let mut e = WireEvent::new("leak", "leak.quiet", sev, format!("{name} is online but has sent no lookups to OPH-S for {since} (it normally sends about {m} an hour at this time). {why}."));
            e.host = name.clone();
            e.src_ip = Some(ip.clone());
            e.raw = json!({"class": "C", "baseline_per_hour": m, "silent_minutes": (now - last) / 60_000, "encrypted_dns_before": enc.map(|(_, n)| n)});
            core.emit(e);
            core.notify(&format!("leak:{ip}"), "A device stopped using OPH-S", &format!("{name} is online but no longer uses OPH-S DNS. Open OPH-S → Leak Check."));
        }
    }
}

/// Close leaks whose cause is gone (C: lookups resumed; A/B: no new evidence for 24 h is NOT enough —
/// those close only via Recheck, so a quiet program is not mistaken for a fixed one).
fn auto_recheck(core: &Core) {
    let open: Vec<(i64, String)> = core.db.lock().unwrap().group_str("SELECT CAST(id AS TEXT), dev FROM leaks WHERE status = 'open' AND class = 'C'", []).into_iter().filter_map(|(i, d)| i.parse().ok().map(|i| (i, d))).collect();
    let now = now_ms();
    let last_q = core.dns_clients.lock().unwrap().clone();
    for (id, dev) in open {
        if last_q.get(&dev).map(|t| now - t < 300_000).unwrap_or(false) {
            mark_fixed(core, id, "the device is using OPH-S DNS again");
        }
    }
}

/// Manual Recheck from the UI.
pub fn recheck(core: &Core, id: i64) -> String {
    let row: Option<(String, String, String, i64)> = core
        .db
        .lock()
        .unwrap()
        .conn
        .query_row("SELECT dev, actor, class, last_ts FROM leaks WHERE id = ?", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .ok();
    let Some((dev, _actor, class, last_ts)) = row else { return "Leak not found".into() };
    let now = now_ms();
    let ok = match class.as_str() {
        "C" | "D" => core.dns_clients.lock().unwrap().get(&dev).map(|t| now - t < 300_000).unwrap_or(false),
        _ => now - last_ts > 600_000, // A/B: no new evidence for 10 minutes
    };
    if ok {
        mark_fixed(core, id, "Recheck passed");
        "Fixed: no new evidence of this leak.".into()
    } else if class == "C" || class == "D" {
        "Still leaking: the device has not used OPH-S DNS in the last 5 minutes.".into()
    } else {
        "Still leaking: new evidence in the last 10 minutes. Apply a fix, then Recheck again.".into()
    }
}

pub fn status(core: &Core) -> Value {
    let now = now_ms();
    let local = core.net.lock().unwrap().local_ip.clone().unwrap_or_default();
    let devices = crate::netmon::devices_json(core);
    let last_q = core.dns_clients.lock().unwrap().clone();
    let agents_online: Vec<String> = core.agents_online.lock().unwrap().values().map(|(n, ip)| format!("{n}|{ip}")).collect();
    let db = core.db.lock().unwrap();
    let mut leaks = Vec::new();
    if let Ok(mut st) = db.conn.prepare("SELECT id, dev, coalesce(dev_name, dev), actor, class, sev, first_ts, last_ts, count, samples, status FROM leaks WHERE status != 'ignored' OR last_ts > ?1 ORDER BY status = 'open' DESC, last_ts DESC LIMIT 200") {
        if let Ok(rows) = st.query_map([now - 7 * 86_400_000], |r| {
            Ok(json!({"id": r.get::<_, i64>(0)?, "dev": r.get::<_, String>(1)?, "dev_name": r.get::<_, String>(2)?, "actor": r.get::<_, String>(3)?,
                "class": r.get::<_, String>(4)?, "severity": r.get::<_, String>(5)?, "first_ts": r.get::<_, i64>(6)?, "last_ts": r.get::<_, i64>(7)?,
                "count": r.get::<_, i64>(8)?, "samples": serde_json::from_str::<Value>(&r.get::<_, Option<String>>(9)?.unwrap_or_default()).unwrap_or(json!([])),
                "status": r.get::<_, String>(10)?}))
        }) {
            leaks = rows.flatten().collect();
        }
    }
    let open_by_dev: HashMap<String, (bool, bool)> = leaks.iter().filter(|l| l["status"] == "open").fold(HashMap::new(), |mut m, l| {
        let e = m.entry(l["dev"].as_str().unwrap_or("").to_string()).or_insert((false, false));
        if l["class"] == "C" {
            e.1 = true;
        } else if l["class"] != "D" {
            e.0 = true;
        }
        m
    });
    let mut out = Vec::new();
    let (mut covered, mut leaking, mut quiet, mut too_new) = (0, 0, 0, 0);
    for d in devices["devices"].as_array().cloned().unwrap_or_default() {
        if d["online"] != true {
            continue;
        }
        let ip = d["ip"].as_str().unwrap_or("").to_string();
        let first = db.scalar("SELECT min(hour) FROM dns_hourly WHERE dev = ?", [&ip]);
        let is_self = ip == local || d["is_self"] == true;
        let (lk, qt) = open_by_dev.get(&ip).copied().unwrap_or((false, false));
        let state = if qt {
            quiet += 1;
            "quiet"
        } else if lk {
            leaking += 1;
            "leaking"
        } else if !is_self && (first == 0 || now - first < 3 * 86_400_000) {
            too_new += 1;
            "too_new"
        } else {
            covered += 1;
            "covered"
        };
        let name = d["hostname"].as_str().unwrap_or(&ip).to_string();
        let app = agents_online.iter().any(|a| a.ends_with(&format!("|{ip}")));
        out.push(json!({"ip": ip, "name": name, "vendor": d["vendor"], "state": state,
            "seen_by": {"resolver": last_q.get(&ip).map(|t| now - t < 86_400_000).unwrap_or(false),
                        "windows": is_self && core.etw_active.load(Ordering::Relaxed),
                        "app": if app { json!("online") } else { Value::Null },
                        "encrypted_dns": core.leak.enc.lock().unwrap().get(&ip).map(|(t, _)| now - t < 86_400_000).unwrap_or(false)}}));
    }
    let total = out.len();
    let block: HashSet<String> = db.list_entries("block").into_iter().map(|e| e.0).collect();
    drop(db); // never hold the DB lock across a process spawn
    json!({"coverage": {"covered": covered, "total": total, "leaking": leaking, "quiet": quiet, "too_new": too_new},
           "devices": out, "leaks": leaks, "quiet_minutes": core.settings().leak_quiet_minutes,
           "fixes": fixes_state(&block), "tap_dropped": core.leak.dropped.load(Ordering::Relaxed)})
}

fn fixes_state(block: &HashSet<String>) -> Value {
    json!({
        "canaries": CANARIES.iter().all(|c| block.contains(*c)),
        "doh_names": DOH_NAMES.iter().all(|c| block.contains(*c)),
        "firewall_doh": crate::native::run_hidden("netsh", &["advfirewall", "firewall", "show", "rule", "name=OPH-S block encrypted DNS"]).map(|(ok, _)| ok).unwrap_or(false),
    })
}

/// One-click fixes. Each one is real and reversible.
pub fn apply_fix(core: &Core, fix: &str) -> Result<String, String> {
    let add = |vals: &[&str], note: &str| -> Result<(), String> {
        let db = core.db.lock().unwrap();
        for v in vals {
            db.list_add("block", v, "domain", note).map_err(|e| e.to_string())?;
        }
        Ok(())
    };
    let remove = |vals: &[&str]| {
        let db = core.db.lock().unwrap();
        for v in vals {
            let _ = db.list_remove("block", v);
        }
    };
    let msg = match fix {
        "canaries" => {
            add(CANARIES, "Leak Check: tells Firefox and iCloud Private Relay to keep using the network's DNS")?;
            "Firefox automatic DoH and iCloud Private Relay are now told to use the house DNS (their check names get NXDOMAIN).".to_string()
        }
        "doh_names" => {
            add(DOH_NAMES, "Leak Check: encrypted-DNS services blocked house-wide")?;
            "Encrypted-DNS services are blocked for every device using OPH-S DNS. Note: a phone with Android Private DNS set to a specific provider will show 'No internet' until Private DNS is set to Off or Automatic.".to_string()
        }
        "firewall_doh" => {
            if !core.admin {
                return Err("Administrator rights are needed for the Windows Firewall rule.".into());
            }
            let ips = DOH_IPS.join(",");
            let _ = crate::native::run_hidden("netsh", &["advfirewall", "firewall", "delete", "rule", "name=OPH-S block encrypted DNS"]);
            for (proto, ports) in [("TCP", "443,853"), ("UDP", "443,853")] {
                let (ok, out) = crate::native::run_hidden("netsh", &["advfirewall", "firewall", "add", "rule", "name=OPH-S block encrypted DNS", "dir=out", "action=block",
                    &format!("protocol={proto}"), &format!("remoteport={ports}"), &format!("remoteip={ips}"), "profile=any"]).map_err(|e| e.to_string())?;
                if !ok {
                    return Err(format!("Windows Firewall refused the rule: {}", out.trim()));
                }
            }
            "Encrypted DNS (DoH/DoT/DoQ) to public resolvers is blocked on this PC. Programs fall back to normal DNS through OPH-S. Plain DNS on port 53 is not affected.".to_string()
        }
        "undo_canaries" => {
            remove(CANARIES);
            "Check names are answered normally again.".to_string()
        }
        "undo_doh_names" => {
            remove(DOH_NAMES);
            "Encrypted-DNS services are no longer blocked house-wide.".to_string()
        }
        "undo_firewall_doh" => {
            let _ = crate::native::run_hidden("netsh", &["advfirewall", "firewall", "delete", "rule", "name=OPH-S block encrypted DNS"]);
            "The encrypted-DNS firewall rule on this PC was removed.".to_string()
        }
        _ => return Err("Unknown fix".into()),
    };
    let l = crate::core::Lists::load(&core.db.lock().unwrap());
    *core.lists.write().unwrap() = l;
    crate::firewall::request_sync(core);
    core.sys("firewall.sync", "info", format!("Leak Check fix applied: {fix}"));
    Ok(msg)
}

/// Make a leak card ignored / reopened.
pub fn set_status(core: &Core, id: i64, status: &str) -> Result<(), String> {
    core.db.lock().unwrap().conn.execute("UPDATE leaks SET status = ? WHERE id = ?", rusqlite::params![status, id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multicast_is_not_a_dns_server() {
        assert!(is_multicast("224.0.0.251") && is_multicast("ff02::fb") && is_multicast("224.0.0.252") && is_multicast("ff02::1:3"));
        assert!(!is_multicast("192.168.68.1") && !is_multicast("1.1.1.1"));
    }
    #[test]
    fn lists_are_sane() {
        assert!(is_canary("use-application-dns.net") && is_canary("mask.icloud.com"));
        assert!(is_doh_name("dns.google") && !is_doh_name("google.com"));
        for n in DOH_NAMES.iter().chain(CANARIES) {
            assert!(oph_proto::normalize_domain(n).as_deref() == Some(*n), "{n}");
        }
        for ip in DOH_IPS {
            assert!(ip.parse::<std::net::IpAddr>().is_ok(), "{ip}");
        }
    }
}
