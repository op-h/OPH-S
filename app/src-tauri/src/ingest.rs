//! Agent intake (TLS + token, certificate pinned by the agent) and a plain
//! syslog receiver so standard tools (router firmware, rsyslog, Fluent Bit,
//! Vector, NAS boxes) can feed OPH Sentinel without a custom agent.

use crate::core::Core;
use oph_proto::{now_ms, Frame, WireEvent, MAX_BATCH, MAX_LINE, PROTOCOL_VERSION};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;

pub fn load_or_create_cert(dir: &Path) -> (Vec<u8>, Vec<u8>, String) {
    let (cp, kp) = (dir.join("server-cert.der"), dir.join("server-key.der"));
    let (cert, key) = match (std::fs::read(&cp), std::fs::read(&kp)) {
        (Ok(c), Ok(k)) if !c.is_empty() && !k.is_empty() => (c, k),
        _ => {
            let ck = rcgen::generate_simple_self_signed(vec!["oph-sentinel".to_string()]).expect("generate certificate");
            let c = ck.cert.der().to_vec();
            let k = ck.key_pair.serialize_der();
            let _ = std::fs::write(&cp, &c);
            let _ = std::fs::write(&kp, &k);
            (c, k)
        }
    };
    let fp = Sha256::digest(&cert).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    (cert, key, fp)
}

/// Per-IP connection counting and failed-token backoff (5 failures -> 5 min ban).
#[derive(Default)]
struct AuthGuard {
    inner: std::sync::Mutex<GuardState>,
}
#[derive(Default)]
struct GuardState {
    /// unauthenticated connections per IP (connection ids), so authenticated agents behind one NAT are never capped
    open: HashMap<String, std::collections::HashSet<u64>>,
    next: u64,
    fails: HashMap<String, (u32, i64)>,
}
impl AuthGuard {
    fn enter(&self, ip: &str) -> Option<u64> {
        let mut g = self.inner.lock().unwrap();
        g.next += 1;
        let id = g.next;
        let set = g.open.entry(ip.to_string()).or_default();
        if set.len() >= 8 {
            return None;
        }
        set.insert(id);
        Some(id)
    }
    /// Idempotent: called once auth succeeds and again when the task ends.
    fn leave(&self, ip: &str, id: u64) {
        let mut g = self.inner.lock().unwrap();
        if let Some(set) = g.open.get_mut(ip) {
            set.remove(&id);
            if set.is_empty() {
                g.open.remove(ip);
            }
        }
    }
    fn fail(&self, ip: &str) {
        let now = now_ms();
        let mut g = self.inner.lock().unwrap();
        let e = g.fails.entry(ip.to_string()).or_insert((0, now));
        if now - e.1 > 60_000 && e.0 < 5 {
            *e = (0, now);
        }
        e.0 += 1;
        e.1 = now;
        if g.fails.len() > 4096 {
            g.fails.retain(|_, (_, t)| now - *t < 300_000);
        }
    }
    fn banned(&self, ip: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.fails.get(ip).map(|(n, t)| *n >= 5 && now_ms() - t < 300_000).unwrap_or(false)
    }
    fn ok(&self, ip: &str) {
        self.inner.lock().unwrap().fails.remove(ip);
    }
}

/// What an agent is allowed to report. Anything else is downgraded to agent.log,
/// so a compromised agent cannot forge IDS alerts or system events.
const AGENT_KINDS: &[(&str, &str)] = &[("conn", "conn.open"), ("agent", "agent.log"), ("dns", "dns.query")];

pub fn token_hash(token: &str) -> String {
    Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// (key id, device name) for an active key.
fn lookup_key(core: &Core, token: &str) -> Option<(String, String)> {
    if token.len() < 16 || token.len() > 128 {
        return None;
    }
    let h = token_hash(token);
    let db = core.db.lock().unwrap();
    let row: Option<(String, String, String)> = db
        .conn
        .query_row("SELECT id, name, token_hash FROM agent_keys WHERE token_hash = ? AND revoked = 0", [&h], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .ok();
    // constant-time confirmation of the stored hash
    row.filter(|(_, _, stored)| ct_eq(stored, &h)).map(|(id, name, _)| (id, name))
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn run_agent_server(core: Arc<Core>) {
    let s = core.settings();
    if !s.ingest_enabled {
        return;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = match rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![CertificateDer::from(core.cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(core.key_der.clone())),
            )
        }) {
        Ok(c) => c,
        Err(e) => {
            core.status.lock().unwrap().ingest_error = Some(format!("TLS setup failed: {e}"));
            return;
        }
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", s.ingest_port)).await {
        Ok(l) => l,
        Err(e) => {
            let msg = format!("Agent intake port {} unavailable: {e}", s.ingest_port);
            core.status.lock().unwrap().ingest_error = Some(msg.clone());
            core.sys("system.error", "medium", msg);
            return;
        }
    };
    {
        let mut st = core.status.lock().unwrap();
        st.ingest_running = true;
        st.ingest_error = None;
    }
    // Pre-auth handshakes are cheap and time-limited (5 s, <=128 at once, <=8 per IP);
    // a session slot (<=32) is only taken after the token checks out, so idle or
    // unauthenticated sockets can never lock real agents out.
    let pre_auth = Arc::new(Semaphore::new(128));
    let sessions = Arc::new(Semaphore::new(32));
    let guard = Arc::new(AuthGuard::default());
    loop {
        let Ok((tcp, peer)) = listener.accept().await else { continue };
        let ip = peer.ip().to_string();
        if guard.banned(&ip) {
            continue; // drop immediately: no slot, no sleep
        }
        let Some(conn_id) = guard.enter(&ip) else { continue };
        let Ok(permit) = pre_auth.clone().try_acquire_owned() else {
            guard.leave(&ip, conn_id);
            continue;
        };
        let (core, acceptor, sessions, guard) = (core.clone(), acceptor.clone(), sessions.clone(), guard.clone());
        tokio::spawn(async move {
            let res = async {
                let tls = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp))
                    .await
                    .map_err(|_| "tls timeout".to_string())?
                    .map_err(|e| e.to_string())?;
                agent_session(&core, tls, ip.clone(), permit, &sessions, &guard, conn_id).await
            }
            .await;
            guard.leave(&ip, conn_id);
            if let Err(e) = res {
                eprintln!("agent {peer}: {e}");
            }
        });
    }
}

async fn read_frame<R: AsyncBufReadExt + Unpin>(r: &mut R, line: &mut String, secs: u64) -> Result<Option<Frame>, String> {
    line.clear();
    let n = tokio::time::timeout(Duration::from_secs(secs), (&mut *r).take(MAX_LINE as u64).read_line(line))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') {
        return Err("frame too large".into());
    }
    serde_json::from_str(line).map(Some).map_err(|e| format!("bad frame: {e}"))
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, f: &Frame) -> Result<(), String> {
    let mut s = serde_json::to_string(f).map_err(|e| e.to_string())?;
    s.push('\n');
    w.write_all(s.as_bytes()).await.map_err(|e| e.to_string())
}

async fn agent_session(
    core: &Arc<Core>,
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ip: String,
    pre_auth: tokio::sync::OwnedSemaphorePermit,
    sessions: &Arc<Semaphore>,
    guard: &AuthGuard,
    conn_id: u64,
) -> Result<(), String> {
    let (r, mut w) = tokio::io::split(tls);
    let mut r = BufReader::new(r);
    let mut line = String::new();
    let Some(Frame::Hello { proto, token, agent_id: _, name: _, platform, version }) = read_frame(&mut r, &mut line, 5).await? else {
        return Err("expected hello".into());
    };
    // Every device has its own key (stored as SHA-256). The identity comes from the
    // key row, never from what the client claims; a revoked key is refused.
    let key = lookup_key(core, &token);
    if key.is_none() || proto != PROTOCOL_VERSION {
        guard.fail(&ip); // repeated failures ban the IP for 5 minutes; no slot is held meanwhile
        let err = if proto != PROTOCOL_VERSION { "protocol version mismatch" } else { "invalid or revoked device key" };
        let _ = write_frame(&mut w, &Frame::Welcome { ok: false, error: Some(err.into()), heartbeat_secs: 0 }).await;
        let mut e = WireEvent::new("agent", "agent.disconnect", "medium", format!("Rejected agent connection from {ip}: {err}"));
        e.host = ip.clone();
        e.src_ip = Some(ip);
        core.emit(e);
        return Ok(());
    }
    guard.ok(&ip);
    guard.leave(&ip, conn_id); // authenticated: no longer counts toward the per-IP pre-auth cap
    drop(pre_auth);
    let Ok(_session) = sessions.clone().try_acquire_owned() else {
        let _ = write_frame(&mut w, &Frame::Welcome { ok: false, error: Some("server busy: too many agents".into()), heartbeat_secs: 0 }).await;
        return Err("session limit reached".into());
    };
    let (agent_id, name) = key.unwrap();
    let platform: String = platform.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
    let version: String = version.chars().filter(|c| !c.is_control()).take(32).collect();
    write_frame(&mut w, &Frame::Welcome { ok: true, error: None, heartbeat_secs: 30 }).await?;
    core.agents_online.lock().unwrap().insert(agent_id.clone(), (name.clone(), ip.clone()));
    {
        let db = core.db.lock().unwrap();
        let _ = db.conn.execute(
            "UPDATE agent_keys SET version = ?2, ip = ?3, last_seen = ?4, platform = coalesce(nullif(?5, ''), platform) WHERE id = ?1",
            rusqlite::params![agent_id, version, ip, now_ms(), platform],
        );
    }
    let mut e = WireEvent::new("agent", "agent.connect", "info", format!("Agent {name} ({platform} {version}) connected from {ip}"));
    e.host = name.clone();
    e.src_ip = Some(ip.clone());
    core.emit(e);

    let result: Result<(), String> = async {
        loop {
            match read_frame(&mut r, &mut line, 120).await? {
                None => return Ok(()),
                Some(Frame::Ping) => {}
                Some(Frame::Batch { mut events }) => {
                    events.truncate(MAX_BATCH);
                    let n = events.len();
                    for mut ev in events {
                        ev.sanitize();
                        if !AGENT_KINDS.iter().any(|(src, k)| *src == ev.source && *k == ev.kind) {
                            ev.raw = serde_json::json!({"claimed_source": ev.source, "claimed_kind": ev.kind});
                            ev.source = "agent".into();
                            ev.kind = "agent.log".into();
                        }
                        ev.host = name.clone(); // never trust a host claim from the wire
                        if ev.src_ip.is_none() {
                            ev.src_ip = Some(ip.clone());
                        }
                        core.emit(ev);
                    }
                    {
                        let db = core.db.lock().unwrap();
                        let _ = db.conn.execute("UPDATE agent_keys SET last_seen = ?, events = events + ? WHERE id = ?", rusqlite::params![now_ms(), n as i64, agent_id]);
                        // revocation takes effect immediately, even mid-session
                        let revoked = db.scalar("SELECT revoked FROM agent_keys WHERE id = ?", [&agent_id]);
                        if revoked != 0 {
                            drop(db);
                            return Err("device key revoked".into());
                        }
                    }
                    write_frame(&mut w, &Frame::Ack { received: n }).await?;
                }
                Some(_) => return Err("unexpected frame".into()),
            }
        }
    }
    .await;
    core.agents_online.lock().unwrap().remove(&agent_id);
    let mut e = WireEvent::new("agent", "agent.disconnect", "low", format!("Agent {name} disconnected"));
    e.host = name;
    e.src_ip = Some(ip);
    if let Err(err) = &result {
        e.raw = serde_json::json!({"reason": err});
    }
    core.emit(e);
    result
}

// ------------------------------------------------------------------ syslog

/// Parse a syslog datagram (RFC 5424 or RFC 3164) with the `syslog_loose` crate.
/// Returns (severity, facility, hostname, app, message, timestamp_ms), or None for junk.
type Syslog = (&'static str, u32, Option<String>, Option<String>, String, Option<i64>);

fn parse_syslog(raw: &str) -> Option<Syslog> {
    let text = raw.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if text.is_empty() {
        return None;
    }
    // PRI must be 0..=191 when present (facility 0..=23)
    let mut pri_val: Option<u32> = None;
    if let Some(rest) = text.strip_prefix('<') {
        let end = rest.find('>')?;
        let pri: u32 = rest[..end].parse().ok()?;
        if pri > 191 {
            return None;
        }
        pri_val = Some(pri);
    }
    let m = syslog_loose::parse_message(text, syslog_loose::Variant::Either);
    // severity: from the parser when it understood the header, else straight from PRI
    let sev = match m.severity.map(|s| s as u32).or(pri_val.map(|p| p % 8)) {
        Some(0..=2) => "critical",
        Some(3) => "high",
        Some(4) => "medium",
        Some(5) => "low",
        _ => "info",
    };
    let fac = m.facility.map(|f| f as u32).unwrap_or(1);
    let clean = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>();
    let host = m.hostname.map(clean).filter(|h| !h.is_empty() && h != "-");
    let app = m.appname.map(clean).filter(|a| !a.is_empty() && a != "-");
    let mut msg = clean(m.msg);
    if msg.starts_with('<') {
        if let Some(i) = msg.find('>') {
            if msg[1..i].parse::<u32>().is_ok() {
                msg = msg[i + 1..].trim_start().to_string(); // parser left the PRI in place
            }
        }
    }
    let ts = m.timestamp.map(|t| t.timestamp_millis());
    if msg.trim().is_empty() && app.is_none() {
        return None;
    }
    Some((sev, fac, host, app, msg, ts))
}

pub async fn run_syslog(core: Arc<Core>) {
    let s = core.settings();
    if !s.syslog_enabled {
        return;
    }
    let sock = match tokio::net::UdpSocket::bind(("0.0.0.0", s.syslog_port)).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("Syslog port UDP {} unavailable: {e}", s.syslog_port);
            core.status.lock().unwrap().syslog_error = Some(msg.clone());
            core.sys("system.error", "medium", msg);
            return;
        }
    };
    core.status.lock().unwrap().syslog_running = true;
    let mut buf = vec![0u8; 65_536]; // max UDP payload: oversize datagrams are not silently lost
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
        let text = String::from_utf8_lossy(&buf[..n]);
        let Some((sev, fac, host, app, msg, ts)) = parse_syslog(&text) else { continue };
        let ip = peer.ip().to_string();
        let mut e = WireEvent::new("syslog", "syslog.message", sev, msg);
        e.host = core.host_label(&ip);
        e.src_ip = Some(ip);
        e.process = app.clone();
        if let Some(t) = ts {
            e.ts = t;
        }
        e.raw = serde_json::json!({"facility": fac, "transport": "udp", "hostname": host, "app": app, "bytes": n});
        e.sanitize();
        core.emit(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn syslog_parsing() {
        let (sev, _, host, app, msg, _) = parse_syslog("<11>Nov 14 10:00:00 router kernel: DROP IN=eth0").unwrap();
        assert_eq!(sev, "high");
        assert_eq!(host.as_deref(), Some("router"));
        assert_eq!(app.as_deref(), Some("kernel"));
        assert!(msg.contains("DROP"));
        let r = parse_syslog("<165>1 2026-11-14T10:00:00Z nas01 sshd 123 ID47 - Failed password for root").unwrap();
        assert_eq!(r.0, "low");
        assert_eq!(r.2.as_deref(), Some("nas01"));
        assert!(r.5.is_some());
        assert!(parse_syslog("\0\0").is_none());
        assert!(parse_syslog("").is_none());
        assert!(parse_syslog("<999>x").is_none());
        let bare = parse_syslog("<13>disk almost full").unwrap();
        assert_eq!(bare.0, "low");
        assert!(!bare.4.starts_with('<'));
    }
}
