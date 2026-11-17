//! Network monitoring for this PC and the home LAN.
//!
//! - LAN devices: the OS ARP/neighbour table (refreshed by a cheap UDP sweep
//!   of the /24), names via the router's reverse DNS, vendors via IEEE OUI.
//! - This PC: socket table with owning process every 5 s.
//! - This PC's DNS: the Windows resolver cache, so dangerous lookups are
//!   caught even when the router has not been pointed at OPH DNS.

use crate::core::{Core, Verdict};
use crate::native::run_hidden;
use oph_proto::{now_ms, ProcessNames, WireEvent};
use serde_json::json;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

pub fn local_ipv4() -> Option<Ipv4Addr> {
    // No packet is sent: connect() on UDP only selects the outbound interface.
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v) if !v.is_unspecified() => Some(v),
        _ => None,
    }
}

pub fn default_gateway() -> Option<Ipv4Addr> {
    if cfg!(windows) {
        let (_, out) = run_hidden("route", &["print", "-4", "0.0.0.0"]).ok()?;
        // "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.10     25"
        out.lines().find_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.len() >= 5 && c[0] == "0.0.0.0" && c[1] == "0.0.0.0").then(|| c[2].parse().ok()).flatten()
        })
    } else {
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        text.lines().skip(1).find_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.len() > 2 && c[1] == "00000000").then(|| u32::from_str_radix(c[2], 16).ok().map(|n| Ipv4Addr::from(n.swap_bytes()))).flatten()
        })
    }
}

/// (ip, mac) pairs from the neighbour table for the interface that owns `local`.
fn arp_table(local: Ipv4Addr) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    if cfg!(windows) {
        let Ok((_, text)) = run_hidden("arp", &["-a"]) else { return out };
        let mut in_iface = false;
        for l in text.lines() {
            let t = l.trim();
            if t.starts_with("Interface:") {
                in_iface = t.split_whitespace().nth(1) == Some(&local.to_string());
                continue;
            }
            if !in_iface {
                continue;
            }
            let c: Vec<&str> = t.split_whitespace().collect();
            if c.len() >= 2 {
                if let Ok(ip) = c[0].parse::<Ipv4Addr>() {
                    out.push((ip, c[1].replace('-', ":").to_ascii_lowercase()));
                }
            }
        }
    } else if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
        for l in text.lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() >= 4 {
                if let Ok(ip) = c[0].parse::<Ipv4Addr>() {
                    out.push((ip, c[3].to_ascii_lowercase()));
                }
            }
        }
    }
    let same_net = |ip: &Ipv4Addr| ip.octets()[..3] == local.octets()[..3];
    out.retain(|(ip, mac)| {
        same_net(ip) && !ip.is_multicast() && ip.octets()[3] != 255 && mac != "ff:ff:ff:ff:ff:ff" && mac != "00:00:00:00:00:00" && !mac.starts_with("01:00:5e")
    });
    out
}

/// Touch every address in the /24 so the OS resolves (ARP) live hosts.
fn sweep(local: Ipv4Addr) {
    let Ok(s) = UdpSocket::bind("0.0.0.0:0") else { return };
    let o = local.octets();
    for i in 1..255u8 {
        if i == o[3] {
            continue;
        }
        let _ = s.send_to(&[0], SocketAddr::from(([o[0], o[1], o[2], i], 9))); // discard port
    }
}

pub fn randomized_mac(mac: &str) -> bool {
    // locally administered bit set (2nd hex digit is 2, 6, A or E): iOS/Android/Windows private addresses
    mac.chars().nth(1).map(|c| matches!(c.to_ascii_lowercase(), '2' | '6' | 'a' | 'e')).unwrap_or(false)
}

pub async fn run_lan(core: Arc<Core>) {
    let mut ptr_tried: HashMap<String, i64> = HashMap::new();
    let mut tick = 0u64;
    loop {
        let local = local_ipv4();
        let gw = tokio::task::spawn_blocking(default_gateway).await.ok().flatten();
        {
            let mut n = core.net.lock().unwrap();
            n.local_ip = local.map(|v| v.to_string());
            n.gateway = gw.map(|v| v.to_string());
            n.subnet = local.map(|v| {
                let o = v.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            });
        }
        if let Some(l) = local {
            core.host_labels.write().unwrap().insert(l.to_string(), "this-pc".into());
            if tick.is_multiple_of(10) {
                let _ = tokio::task::spawn_blocking(move || sweep(l)).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            let table = tokio::task::spawn_blocking(move || arp_table(l)).await.unwrap_or_default();
            let now = now_ms();
            let intel = core.intel.read().unwrap().clone();
            let mut new_devices = Vec::new();
            {
                let db = core.db.lock().unwrap();
                for (ip, mac) in &table {
                    let vendor = if randomized_mac(mac) { Some("Private (randomized) address") } else { intel.vendor(mac) };
                    let existed: bool = db.scalar("SELECT count(*) FROM devices WHERE mac = ?", [mac]) > 0;
                    let _ = db.conn.execute(
                        "INSERT INTO devices(mac,ip,hostname,vendor,first_seen,last_seen) VALUES(?1,?2,NULL,?3,?4,?4)
                         ON CONFLICT(mac) DO UPDATE SET ip=?2, vendor=coalesce(?3, vendor), last_seen=?4",
                        rusqlite::params![mac, ip.to_string(), vendor, now],
                    );
                    if !existed {
                        new_devices.push((ip.to_string(), mac.clone(), vendor.map(String::from)));
                    }
                }
            }
            // first run populates silently; afterwards a new MAC is worth an event
            let first_run = core.db.lock().unwrap().kv_get("lan_seeded").is_none();
            for (ip, mac, vendor) in new_devices {
                if first_run {
                    continue;
                }
                let mut e = WireEvent::new("system", "device.new", "low", format!("New device joined the network: {ip} ({mac}{})", vendor.as_deref().map(|v| format!(", {v}")).unwrap_or_default()));
                e.host = ip.clone();
                e.src_ip = Some(ip);
                e.raw = json!({"mac": mac, "vendor": vendor, "randomized_mac": randomized_mac(&mac)});
                core.emit(e);
            }
            if first_run && !table.is_empty() {
                core.db.lock().unwrap().kv_set("lan_seeded", "1");
            }
            // friendly names via the router (PTR), at most once an hour per device
            if let Some(g) = gw {
                for (ip, mac) in &table {
                    let key = ip.to_string();
                    if ptr_tried.get(&key).map(|t| now - t < 3_600_000).unwrap_or(false) {
                        continue;
                    }
                    ptr_tried.insert(key.clone(), now);
                    // 1) the router's reverse DNS (DHCP names), 2) mDNS / Bonjour asked to the device
                    // itself (phones, Macs, Linux, printers, smart-home devices answer it)
                    let mut name = crate::dns::ptr_lookup(*ip, SocketAddr::from((g, 53))).await;
                    if name.is_none() {
                        name = crate::dns::ptr_lookup(*ip, SocketAddr::from((*ip, 5353))).await;
                    }
                    if let Some(name) = name {
                        let _ = core.db.lock().unwrap().conn.execute("UPDATE devices SET hostname = ? WHERE mac = ? AND (hostname IS NULL OR hostname = '')", rusqlite::params![name, mac]);
                    }
                }
            }
            // refresh ip → label map used by DNS / syslog events
            let labels: Vec<(String, String)> = core.db.lock().unwrap().group_str("SELECT ip, coalesce(nullif(label, ''), hostname) FROM devices WHERE coalesce(nullif(label, ''), hostname) IS NOT NULL", []);
            let mut hl = core.host_labels.write().unwrap();
            for (ip, name) in labels {
                if Some(ip.as_str()) != local.map(|l| l.to_string()).as_deref() {
                    hl.insert(ip, name);
                }
            }
        }
        tick += 1;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

pub fn run_local_connections(core: Arc<Core>) {
    std::thread::Builder::new()
        .name("oph-conn".into())
        .spawn(move || {
            let mut names = ProcessNames::new();
            let mut seen: HashMap<(String, String, u16), i64> = HashMap::new();
            loop {
                let conns = oph_proto::snapshot_connections(&mut names);
                let now = now_ms();
                let mut views = Vec::with_capacity(conns.len());
                for c in &conns {
                    let domain = core.ip_names.lock().unwrap().get(&c.remote_ip);
                    let mut verdict = match core.ip_verdict(&c.remote_ip) {
                        Verdict::Allowed => "allowed",
                        Verdict::Manual => "blocked",
                        Verdict::Intel(_) => "malicious",
                        Verdict::Clean => "ok",
                    };
                    if verdict == "ok" {
                        if let Some(d) = &domain {
                            verdict = match core.domain_verdict(d) {
                                Verdict::Manual => "blocked",
                                Verdict::Intel(_) => "malicious",
                                Verdict::Allowed => "allowed",
                                Verdict::Clean => "ok",
                            };
                        }
                    }
                    views.push(json!({"proto": c.proto, "local": c.local, "remote_ip": c.remote_ip, "remote_port": c.remote_port,
                        "state": c.state, "pid": c.pid, "process": c.process, "domain": domain, "verdict": verdict}));
                    let key = (c.process.clone(), c.remote_ip.clone(), c.remote_port);
                    if !core.monitoring_on() || seen.get(&key).map(|t| now - t < 600_000).unwrap_or(false) {
                        continue;
                    }
                    seen.insert(key, now);
                    let mut e = WireEvent::new("conn", "conn.open", "info", format!("{} → {}:{}{}", c.process, c.remote_ip, c.remote_port, domain.as_deref().map(|d| format!(" ({d})")).unwrap_or_default()));
                    e.host = "this-pc".into();
                    e.src_ip = core.net.lock().unwrap().local_ip.clone();
                    e.dst_ip = Some(c.remote_ip.clone());
                    e.dst_port = Some(c.remote_port);
                    e.domain = domain;
                    e.process = Some(c.process.clone());
                    e.raw = json!({"proto": c.proto, "local": c.local, "pid": c.pid, "state": c.state});
                    core.emit(e);
                }
                seen.retain(|_, t| now - *t < 600_000);
                *core.conns.lock().unwrap() = views;
                std::thread::sleep(Duration::from_secs(5));
            }
        })
        .expect("spawn conn monitor");
}

/// Windows DNS client cache → dns.query events for this PC.
pub fn run_local_dns_watch(core: Arc<Core>) {
    if !cfg!(windows) {
        return;
    }
    match crate::etw::start(core.clone()) {
        Ok(()) => {
            core.etw_active.store(true, std::sync::atomic::Ordering::Relaxed);
            core.sys("system.start", "info", "Watching this PC's DNS lookups in real time (ETW, per process)");
            return;
        }
        Err(e) => core.sys("system.start", "info", format!("ETW DNS tracing unavailable ({e}); polling the Windows DNS cache instead")),
    }
    std::thread::Builder::new()
        .name("oph-dnscache".into())
        .spawn(move || {
            let mut seen: HashMap<String, i64> = HashMap::new();
            loop {
                if core.settings.read().unwrap().watch_local_dns && core.monitoring_on() {
                    if let Ok((_, text)) = run_hidden("ipconfig", &["/displaydns"]) {
                        let now = now_ms();
                        let mut cur: Option<String> = None;
                        let mut found: Vec<(String, Option<String>)> = Vec::new();
                        for l in text.lines() {
                            let t = l.trim();
                            if let Some(v) = field(t, "Record Name") {
                                cur = oph_proto::normalize_domain(v);
                            } else if let Some(v) = field(t, "A (Host) Record").or_else(|| field(t, "AAAA Record")) {
                                if let Some(n) = &cur {
                                    core.ip_names.lock().unwrap().put(v.to_string(), n.clone());
                                    found.push((n.clone(), Some(v.to_string())));
                                }
                            } else if t.starts_with("----") {
                                if let Some(n) = &cur {
                                    found.push((n.clone(), None));
                                }
                            }
                        }
                        found.sort();
                        found.dedup_by(|a, b| a.0 == b.0);
                        let local = core.net.lock().unwrap().local_ip.clone();
                        for (name, ip) in found {
                            if name.ends_with(".arpa") || name.ends_with(".local") || !name.contains('.') {
                                continue;
                            }
                            if seen.get(&name).map(|t| now - t < 600_000).unwrap_or(false) {
                                continue;
                            }
                            seen.insert(name.clone(), now);
                            let mut e = WireEvent::new("dns", "dns.query", "info", format!("this-pc resolved {name}{}", ip.as_deref().map(|i| format!(" → {i}")).unwrap_or_default()));
                            e.host = "this-pc".into();
                            e.src_ip = local.clone();
                            e.domain = Some(name);
                            e.dst_ip = ip;
                            e.raw = json!({"via": "windows-dns-cache"});
                            core.emit(e);
                        }
                        seen.retain(|_, t| now - *t < 600_000);
                    }
                }
                std::thread::sleep(Duration::from_secs(15));
            }
        })
        .expect("spawn dns watch");
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    // "Record Name . . . . . : example.com" (localised output keeps the dotted layout)
    line.strip_prefix(name)?.split_once(':').map(|(_, v)| v.trim()).filter(|v| !v.is_empty())
}

pub fn devices_json(core: &Core) -> serde_json::Value {
    let now = now_ms();
    let day = now - 86_400_000;
    let net = core.net.lock().unwrap().clone();
    let dns_clients = core.dns_clients.lock().unwrap().clone();
    let db = core.db.lock().unwrap();
    let q: HashMap<String, i64> = db.group("SELECT src_ip, count(*) FROM events WHERE ts >= ? AND kind = 'dns.query' AND src_ip IS NOT NULL GROUP BY src_ip", [day]).into_iter().collect();
    let b: HashMap<String, i64> = db.group("SELECT src_ip, count(*) FROM events WHERE ts >= ? AND kind = 'dns.blocked' AND src_ip IS NOT NULL GROUP BY src_ip", [day]).into_iter().collect();
    let a: HashMap<String, i64> = db.group("SELECT src_ip, count(*) FROM alerts WHERE status = 'open' AND src_ip IS NOT NULL GROUP BY src_ip", []).into_iter().collect();
    let mut rows = Vec::new();
    let mut ips = std::collections::HashSet::new();
    if let Ok(mut st) = db.conn.prepare("SELECT ip, mac, coalesce(nullif(label, ''), hostname), vendor, first_seen, last_seen FROM devices ORDER BY last_seen DESC") {
        let it = st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?))
        });
        if let Ok(it) = it {
            for (ip, mac, host, vendor, first, last) in it.flatten() {
                if !ips.insert(ip.clone()) {
                    continue; // an IP re-used by a newer MAC: newest wins
                }
                let dns_last = dns_clients.get(&ip).copied().unwrap_or(0);
                let last = last.max(dns_last);
                rows.push(json!({"ip": ip, "mac": mac, "hostname": host, "vendor": vendor, "randomized_mac": randomized_mac(&mac),
                    "first_seen": first, "last_seen": last, "online": now - last < 600_000,
                    "queries_24h": q.get(&ip).copied().unwrap_or(0), "blocked_24h": b.get(&ip).copied().unwrap_or(0),
                    "alerts_open": a.get(&ip).copied().unwrap_or(0), "is_self": false}));
            }
        }
    }
    // DNS clients not in the ARP table (other subnets / VPN) and this PC itself
    let mut extra: Vec<(String, i64)> = dns_clients.into_iter().filter(|(ip, _)| !ips.contains(ip)).collect();
    if let Some(l) = &net.local_ip {
        if !ips.contains(l) && !extra.iter().any(|(i, _)| i == l) {
            extra.push((l.clone(), now));
        }
    }
    for (ip, last) in extra {
        let is_self = net.local_ip.as_deref() == Some(ip.as_str()) || ip == "127.0.0.1";
        rows.push(json!({"ip": ip, "mac": null, "hostname": if is_self { Some("This PC".to_string()) } else { None }, "vendor": null, "randomized_mac": false,
            "first_seen": last, "last_seen": if is_self { now } else { last }, "online": is_self || now - last < 600_000,
            "queries_24h": q.get(&ip).copied().unwrap_or(0), "blocked_24h": b.get(&ip).copied().unwrap_or(0),
            "alerts_open": a.get(&ip).copied().unwrap_or(0), "is_self": is_self}));
    }
    for r in rows.iter_mut() {
        if net.local_ip.as_deref() == r["ip"].as_str() {
            r["is_self"] = json!(true);
            r["hostname"] = json!("This PC");
            r["online"] = json!(true);
        }
    }
    json!({"gateway": net.gateway, "subnet": net.subnet, "devices": rows})
}
