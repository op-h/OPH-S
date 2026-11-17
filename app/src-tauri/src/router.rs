//! Router detection for the setup guide: gateway, its MAC vendor (IEEE OUI),
//! a family guess (TP-Link Deco, Archer, ASUS, …) and whether LAN devices are
//! already resolving through OPH DNS.

use crate::core::Core;
use oph_proto::now_ms;
use serde_json::{json, Value};

fn family(vendor: &str, gateway: &str, page: &str) -> &'static str {
    let v = vendor.to_ascii_lowercase();
    let p = page.to_ascii_lowercase();
    if v.contains("tp-link") || v.contains("tp link") || p.contains("tp-link") {
        // Deco mesh uses 192.168.68.0/22 by default and an HTTPS-only UI
        if gateway.starts_with("192.168.68.") || gateway.starts_with("192.168.69.") || p.contains("deco") {
            return "tplink-deco";
        }
        return "tplink";
    }
    if v.contains("asustek") || p.contains("asus") {
        "asus"
    } else if v.contains("netgear") || p.contains("netgear") {
        "netgear"
    } else if v.contains("huawei") || p.contains("huawei") {
        "huawei"
    } else if v.contains("zte") || p.contains("zte") {
        "zte"
    } else if v.contains("routerboard") || v.contains("mikrotik") || p.contains("routeros") {
        "mikrotik"
    } else {
        "generic"
    }
}

/// Fetch the router's start page title (HTTP, then HTTPS with an untrusted cert allowed) — best effort.
fn probe_page(gateway: &str) -> (String, &'static str) {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{gateway}/");
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(3)).tls_config(insecure_tls()).build();
        if let Ok(r) = agent.get(&url).call() {
            let body = r.into_string().unwrap_or_default();
            return (body.chars().take(20_000).collect(), if scheme == "https" { "https" } else { "http" });
        }
    }
    (String::new(), "http")
}

/// Router admin pages use self-signed certificates; we only read a title for detection.
pub fn insecure_tls() -> std::sync::Arc<rustls::ClientConfig> {
    #[derive(Debug)]
    struct AnyCert(std::sync::Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for AnyCert {
        fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>], _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("tls")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    std::sync::Arc::new(cfg)
}

fn deco_handshake(gw: &str) -> bool {
    let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(3)).tls_config(insecure_tls()).build();
    agent
        .post(&format!("https://{gw}/cgi-bin/luci/;stok=/login?form=keys"))
        .set("Content-Type", "application/json")
        .send_string(r#"{"operation":"read"}"#)
        .ok()
        .and_then(|r| r.into_string().ok())
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .map(|v| v.pointer("/result/password").and_then(|p| p.as_array()).map(|a| a.len() == 2).unwrap_or(false))
        .unwrap_or(false)
}

fn pc_dns_servers() -> Vec<String> {
    let ps = "(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -and $_.InterfaceAlias -notmatch 'Loopback|vEthernet|Tailscale' }).ServerAddresses -join ','";
    crate::native::run_hidden("powershell", &["-NoProfile", "-Command", ps])
        .ok()
        .map(|(_, o)| o.trim().split(',').filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default()
}

pub fn info(core: &Core) -> Value {
    let net = core.net.lock().unwrap().clone();
    let gw = net.gateway.clone().unwrap_or_default();
    let mac: Option<String> = if gw.is_empty() {
        None
    } else {
        core.db.lock().unwrap().group_str("SELECT ip, mac FROM devices WHERE ip = ?", [&gw]).into_iter().next().map(|(_, m)| m)
    };
    let vendor = mac.as_deref().and_then(|m| core.intel.read().unwrap().vendor(m).map(String::from)).unwrap_or_default();
    let (page, scheme) = if gw.is_empty() { (String::new(), "http") } else { probe_page(&gw) };
    let mut fam = family(&vendor, &gw, &page);
    // Definitive check when the vendor database isn't loaded yet: a Deco answers the
    // public, read-only login handshake with its RSA password key (changes nothing).
    if fam == "generic" && !gw.is_empty() && deco_handshake(&gw) {
        fam = "tplink-deco";
    }
    let now = now_ms();
    let local = net.local_ip.clone().unwrap_or_default();
    let clients = core
        .dns_clients
        .lock()
        .unwrap()
        .iter()
        .filter(|(ip, t)| now - **t < 600_000 && ip.as_str() != local && ip.as_str() != "127.0.0.1" && !ip.starts_with("::"))
        .count();
    let st = core.status.lock().unwrap().clone();
    let s = core.settings();
    json!({
        "gateway": net.gateway, "gateway_mac": mac, "vendor": vendor, "family": fam,
        "admin_url": if gw.is_empty() { Value::Null } else { json!(format!("{scheme}://{gw}/")) },
        "pc_ip": net.local_ip, "pc_dns_servers": pc_dns_servers(),
        "dns_running": st.dns_running, "dns_error": st.dns_error, "dns_bind": s.dns_bind, "lan_clients_10m": clients,
        "auto_supported": fam == "tplink-deco", "credential_saved": core.db.lock().unwrap().kv_get("router_cred").is_some(), "backup": backup(core),
        "reserved_hint": format!("Reserve {} for this PC so the router always gives it the same address.", net.local_ip.unwrap_or_default()),
    })
}

// ------------------------------------------------------------------ automatic Deco setup

struct Steps(Vec<Value>);
impl Steps {
    fn ok(&mut self, name: &str, detail: impl Into<String>) {
        self.0.push(json!({"name": name, "ok": true, "detail": detail.into()}));
    }
    fn fail(&mut self, name: &str, detail: impl Into<String>) {
        self.0.push(json!({"name": name, "ok": false, "detail": detail.into()}));
    }
}

fn mac_of_local_ip(ip: &str) -> Option<String> {
    let ps = format!("(Get-NetIPAddress -IPAddress '{ip}' -ErrorAction Stop | Get-NetAdapter).MacAddress");
    let (ok, out) = crate::native::run_hidden("powershell", &["-NoProfile", "-Command", &ps]).ok()?;
    let m = out.trim().to_ascii_uppercase().replace(':', "-");
    (ok && m.len() == 17).then_some(m)
}

/// Ask our own resolver on the LAN address (what devices will use) for a real name.
fn dns_answers_on(ip: &str) -> bool {
    use std::net::UdpSocket;
    let Ok(s) = UdpSocket::bind("0.0.0.0:0") else { return false };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(3)));
    let q: &[u8] = &[0x4f, 0x50, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1];
    if s.send_to(q, (ip, 53)).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(s.recv_from(&mut buf), Ok((n, _)) if n > 12 && buf[0] == 0x4f && buf[3] & 0x0f == 0)
}

fn firewall_rule_present() -> bool {
    crate::native::run_hidden("netsh", &["advfirewall", "firewall", "show", "rule", "name=OPH Sentinel - inbound"]).map(|(ok, _)| ok).unwrap_or(false)
}

fn stored_password(core: &Core) -> Option<String> {
    let hex = core.db.lock().unwrap().kv_get("router_cred")?;
    let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect();
    String::from_utf8(crate::native::dpapi(&bytes, true)?).ok()
}

fn store_password(core: &Core, pw: &str) {
    if let Some(enc) = crate::native::dpapi(pw.as_bytes(), false) {
        let hex: String = enc.iter().map(|b| format!("{b:02x}")).collect();
        core.db.lock().unwrap().kv_set("router_cred", &hex);
    }
}

pub fn forget_password(core: &Core) {
    let _ = core.db.lock().unwrap().conn.execute("DELETE FROM kv WHERE k = 'router_cred'", []);
}

pub fn backup(core: &Core) -> Value {
    core.db.lock().unwrap().kv_get("router_backup").and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
}

/// `apply = false`: read-only check (login, read DHCP/DNS + reservations, logout).
/// `apply = true`: reserve this PC's IP, point DHCP DNS at it, verify, keep a backup for Undo.
pub fn configure(core: &Core, password: Option<String>, remember: bool, mode: &str, apply: bool) -> Value {
    let mut st = Steps(Vec::new());
    let net = core.net.lock().unwrap().clone();
    let (Some(gw), Some(pc)) = (net.gateway.clone(), net.local_ip.clone()) else {
        return json!({"ok": false, "applied": false, "steps": st.0, "error": "This PC has no network gateway right now."});
    };
    let info = info(core);
    if info["family"] != "tplink-deco" {
        return json!({"ok": false, "applied": false, "steps": st.0,
            "error": format!("Automatic setup supports TP-Link Deco. Detected: {}. Use the manual steps for your router.", info["vendor"].as_str().filter(|v| !v.is_empty()).unwrap_or("unknown router"))});
    }

    // Safety gates: never point the network at a resolver that is not answering.
    let s = core.settings();
    let port53 = s.dns_bind.ends_with(":53") && !s.dns_bind.starts_with("127.");
    if !(s.dns_enabled && core.status.lock().unwrap().dns_running && port53) {
        st.fail("OPH-S DNS ready", format!("The DNS resolver must run on port 53 for the whole network (now: {}). Settings → DNS resolver → bind 0.0.0.0:53.", s.dns_bind));
        return json!({"ok": false, "applied": false, "steps": st.0, "error": "OPH-S DNS is not ready for the network yet."});
    }
    if !dns_answers_on(&pc) {
        st.fail("OPH-S DNS ready", format!("No answer from {pc}:53. Check that nothing blocks the port."));
        return json!({"ok": false, "applied": false, "steps": st.0, "error": "OPH-S DNS did not answer on this PC's network address."});
    }
    st.ok("OPH-S DNS ready", format!("Answering on {pc}:53"));
    if apply && !firewall_rule_present() {
        let (ok, msg) = crate::firewall::setup_ports(core);
        if ok { st.ok("Firewall", msg) } else {
            st.fail("Firewall", msg);
            return json!({"ok": false, "applied": false, "steps": st.0, "error": "Other devices could not reach OPH-S DNS through Windows Firewall."});
        }
    }
    let Some(mac) = mac_of_local_ip(&pc) else {
        return json!({"ok": false, "applied": false, "steps": st.0, "error": "Could not read this PC's network adapter address."});
    };

    let pw = match password.filter(|p| !p.is_empty()).or_else(|| stored_password(core)) {
        Some(p) => p,
        None => return json!({"ok": false, "applied": false, "steps": st.0, "error": "Enter the Deco owner password (the one for your TP-Link ID / Deco app)."}),
    };
    let mut d = match crate::deco::Deco::login(&gw, &pw) {
        Ok(d) => {
            st.ok("Log in to Deco", format!("Signed in to {gw} (the Deco app may sign out; that is normal)"));
            d
        }
        Err(e) => {
            st.fail("Log in to Deco", e.to_string());
            return json!({"ok": false, "applied": false, "steps": st.0, "error": e.to_string()});
        }
    };
    if remember {
        store_password(core, &pw);
    }

    let result = (|| -> Result<Value, String> {
        let dhcp = d.dhcp_read().map_err(|e| e.to_string())?;
        let cur_p = dhcp["primaryDns"].as_str().unwrap_or("").to_string();
        let cur_s = dhcp["secondaryDns"].as_str().unwrap_or("").to_string();
        st.ok("Read DHCP settings", format!("Primary DNS {}, secondary DNS {}", if cur_p.is_empty() { "automatic" } else { &cur_p }, if cur_s.is_empty() { "none" } else { &cur_s }));
        // while signed in: take the device names from the Deco app's client list
        if let Ok(names) = d.client_names() {
            let db = core.db.lock().unwrap();
            let mut n = 0;
            for (mac, name) in &names {
                let m = mac.replace('-', ":").to_ascii_lowercase();
                n += db.conn.execute("UPDATE devices SET hostname = ? WHERE mac = ?", rusqlite::params![name, m]).unwrap_or(0);
            }
            drop(db);
            st.ok("Device names", format!("{n} devices named from the Deco app ({} clients listed)", names.len()));
        }
        let res = d.reservations().map_err(|e| e.to_string())?;
        let mine = res.iter().find(|(m, _)| *m == mac).cloned();
        let secondary = if mode == "strict" { String::new() } else { gw.clone() };
        let planned = json!({"primaryDns": pc, "secondaryDns": secondary, "reservation": {"mac": mac, "ip": pc}});
        let current = json!({"primaryDns": cur_p, "secondaryDns": cur_s, "reservation": mine.as_ref().map(|(m, i)| json!({"mac": m, "ip": i}))});
        if !apply {
            return Ok(json!({"current": current, "planned": planned}));
        }
        // backup the user's original values once (never overwrite it with our own settings)
        if cur_p != pc {
            core.db.lock().unwrap().kv_set("router_backup", &json!({"primaryDns": cur_p, "secondaryDns": cur_s, "ts": oph_proto::now_ms(), "gateway": gw}).to_string());
            st.ok("Backup", "Saved the current DNS settings so you can undo");
        }
        match &mine {
            Some((_, ip)) if *ip == pc => st.ok("Reserve this PC's IP", format!("{pc} is already reserved for {mac}")),
            Some((_, ip)) => st.fail("Reserve this PC's IP", format!("{mac} is reserved for {ip}, not {pc}; left unchanged")),
            None => {
                d.reserve(&mac, &pc).map_err(|e| e.to_string())?;
                st.ok("Reserve this PC's IP", format!("{pc} reserved for {mac}"));
            }
        }
        d.dhcp_set_dns(&dhcp, &pc, &secondary).map_err(|e| e.to_string())?;
        let after = d.dhcp_read().map_err(|e| e.to_string())?;
        if after["primaryDns"].as_str() != Some(pc.as_str()) {
            return Err(format!("The Deco accepted the change but still reports primary DNS {}", after["primaryDns"]));
        }
        st.ok("Set DNS", format!("Primary DNS {pc}{}", if secondary.is_empty() { ", no secondary (strict)".to_string() } else { format!(", secondary {secondary} (safe fallback)") }));
        Ok(json!({"current": {"primaryDns": after["primaryDns"], "secondaryDns": after["secondaryDns"], "reservation": {"mac": mac, "ip": pc}}, "planned": planned}))
    })();
    d.logout();
    st.ok("Log out", "Deco session closed");
    match result {
        Ok(v) => {
            if apply {
                core.sys("system.start", "info", format!("Router configured automatically: DNS → {pc} ({mode} mode)"));
            }
            json!({"ok": true, "applied": apply, "steps": st.0, "current": v["current"], "planned": v["planned"], "backup": backup(core), "error": null})
        }
        Err(e) => {
            st.fail("Router change", e.clone());
            json!({"ok": false, "applied": false, "steps": st.0, "error": e, "backup": backup(core)})
        }
    }
}

/// Put the Deco's DNS back to what it was before OPH-S changed it.
pub fn undo(core: &Core, password: Option<String>) -> Value {
    let mut st = Steps(Vec::new());
    let b = backup(core);
    if b.is_null() {
        return json!({"ok": false, "steps": st.0, "error": "There is no saved router backup to restore."});
    }
    let gw = b["gateway"].as_str().map(String::from).or_else(|| core.net.lock().unwrap().gateway.clone()).unwrap_or_default();
    let Some(pw) = password.filter(|p| !p.is_empty()).or_else(|| stored_password(core)) else {
        return json!({"ok": false, "steps": st.0, "error": "Enter the Deco owner password."});
    };
    let mut d = match crate::deco::Deco::login(&gw, &pw) {
        Ok(d) => d,
        Err(e) => return json!({"ok": false, "steps": st.0, "error": e.to_string()}),
    };
    st.ok("Log in to Deco", gw.clone());
    let r = d.dhcp_read().and_then(|cur| d.dhcp_set_dns(&cur, b["primaryDns"].as_str().unwrap_or(""), b["secondaryDns"].as_str().unwrap_or("")));
    d.logout();
    match r {
        Ok(()) => {
            st.ok("Restore DNS", format!("Primary {}, secondary {}", b["primaryDns"], b["secondaryDns"]));
            let _ = core.db.lock().unwrap().conn.execute("DELETE FROM kv WHERE k = 'router_backup'", []);
            core.sys("system.start", "info", "Router DNS restored to its previous settings");
            json!({"ok": true, "steps": st.0, "error": null})
        }
        Err(e) => {
            st.fail("Restore DNS", e.to_string());
            json!({"ok": false, "steps": st.0, "error": e.to_string()})
        }
    }
}
