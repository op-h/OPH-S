//! Shared data model and wire protocol for OPH Sentinel.
//!
//! One event format is used everywhere: the desktop core, the PC agent and the
//! Android (Termux) agent all emit [`WireEvent`]s. Agents speak a line-delimited
//! JSON protocol over TLS (see [`Frame`]).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROTOCOL_VERSION: u32 = 1;
/// Max bytes accepted for one protocol line (one batch). Protects the server's memory.
pub const MAX_LINE: usize = 512 * 1024;
/// Max events per batch frame.
pub const MAX_BATCH: usize = 500;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

pub fn severity_rank(s: &str) -> i32 {
    SEVERITIES.iter().position(|x| *x == s).map(|p| p as i32).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WireEvent {
    pub ts: i64,
    pub source: String,
    pub kind: String,
    pub severity: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub process: Option<String>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub raw: serde_json::Value,
}

impl WireEvent {
    pub fn new(source: &str, kind: &str, severity: &str, message: impl Into<String>) -> Self {
        WireEvent {
            ts: now_ms(),
            source: source.into(),
            kind: kind.into(),
            severity: severity.into(),
            message: message.into(),
            raw: serde_json::Value::Null,
            ..Default::default()
        }
    }
    /// Clamp and validate untrusted input coming from the network.
    /// Values that later reach the hosts file, firewall or SQL must be strictly
    /// shaped here: domains/IPs that fail validation are dropped.
    pub fn sanitize(&mut self) {
        fn cut(s: &mut String, n: usize) {
            if s.len() > n {
                let mut i = n;
                while !s.is_char_boundary(i) {
                    i -= 1;
                }
                s.truncate(i);
            }
        }
        fn clean(s: &mut String) {
            if s.chars().any(|c| c.is_control()) {
                *s = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
            }
        }
        cut(&mut self.source, 16);
        cut(&mut self.kind, 48);
        cut(&mut self.host, 128);
        clean(&mut self.host);
        cut(&mut self.message, 4096);
        if let Some(p) = &mut self.process {
            cut(p, 256);
            clean(p);
        }
        self.domain = self.domain.take().and_then(|d| normalize_domain(&d));
        self.src_ip = self.src_ip.take().filter(|v| v.parse::<std::net::IpAddr>().is_ok());
        self.dst_ip = self.dst_ip.take().filter(|v| v.parse::<std::net::IpAddr>().is_ok());
        if !SEVERITIES.contains(&self.severity.as_str()) {
            self.severity = "info".into();
        }
        let now = now_ms();
        if self.ts <= now - 86_400_000 || self.ts > now + 86_400_000 {
            self.ts = now; // clamp clock skew / forged timestamps to ±1 day
        }
        if self.raw.to_string().len() > 8192 {
            self.raw = serde_json::json!({"truncated": true});
        }
    }

    /// Approximate serialized size, used to keep frames under [`MAX_LINE`].
    pub fn approx_size(&self) -> usize {
        128 + self.message.len() + self.host.len() + self.kind.len()
            + self.domain.as_ref().map_or(0, |s| s.len())
            + self.process.as_ref().map_or(0, |s| s.len())
            + if self.raw.is_null() { 0 } else { self.raw.to_string().len() }
    }
}

/// Lower-case, strip one trailing dot, and accept only LDH(+underscore) labels.
/// Returns None for anything that is not a plausible DNS name.
pub fn normalize_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
    ok.then_some(d)
}

/// Frames exchanged over the agent channel, one JSON object per line.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    Hello {
        proto: u32,
        token: String,
        agent_id: String,
        name: String,
        platform: String,
        version: String,
    },
    Welcome {
        ok: bool,
        #[serde(default)]
        error: Option<String>,
        /// Domains/IPs the server wants the agent to treat as blocked (informational).
        #[serde(default)]
        heartbeat_secs: u64,
    },
    Batch {
        events: Vec<WireEvent>,
    },
    Ack {
        received: usize,
    },
    Ping,
}

/// One socket owned by a local process.
#[derive(Debug, Clone, Serialize)]
pub struct Conn {
    pub proto: &'static str,
    pub local: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process: String,
}

/// Snapshot of established/outbound sockets with owning process names.
/// Cheap enough to call every few seconds. Returns an empty list where the OS
/// forbids socket enumeration (e.g. unrooted Android 10+).
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub fn snapshot_connections(names: &mut ProcessNames) -> Vec<Conn> {
    use netstat2::*;
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let pf = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let Ok(sockets) = get_sockets_info(af, pf) else { return Vec::new() };
    let mut out = Vec::with_capacity(sockets.len());
    for s in sockets {
        let pid = s.associated_pids.first().copied().unwrap_or(0);
        match s.protocol_socket_info {
            ProtocolSocketInfo::Tcp(t) => {
                let ip = t.remote_addr;
                if ip.is_unspecified() || ip.is_loopback() {
                    continue;
                }
                out.push(Conn {
                    proto: "tcp",
                    local: format!("{}:{}", t.local_addr, t.local_port),
                    remote_ip: ip.to_string(),
                    remote_port: t.remote_port,
                    state: format!("{:?}", t.state),
                    pid,
                    process: names.name(pid),
                });
            }
            ProtocolSocketInfo::Udp(_) => {} // UDP has no peer in the socket table
        }
    }
    out
}

/// Android: netlink socket diagnostics are blocked for apps, so read /proc/net/tcp{,6}.
/// Since Android 10 this is also denied without root; we then return an empty list.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn snapshot_connections(_names: &mut ProcessNames) -> Vec<Conn> {
    let mut out = Vec::new();
    for (path, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 || cols[3] != "01" {
                continue; // 01 = ESTABLISHED
            }
            if let (Some(l), Some((ip, port))) = (Some(cols[1]), parse_proc_addr(cols[2], v6)) {
                if ip.is_loopback() || ip.is_unspecified() {
                    continue;
                }
                out.push(Conn {
                    proto: "tcp",
                    local: l.to_string(),
                    remote_ip: ip.to_string(),
                    remote_port: port,
                    state: "Established".into(),
                    pid: 0,
                    process: "unknown".into(),
                });
            }
        }
    }
    out
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn parse_proc_addr(s: &str, v6: bool) -> Option<(std::net::IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    if !v6 {
        let n = u32::from_str_radix(a, 16).ok()?;
        return Some((std::net::IpAddr::V4(std::net::Ipv4Addr::from(n.swap_bytes())), port));
    }
    if a.len() != 32 {
        return None;
    }
    let mut b = [0u8; 16];
    for w in 0..4 {
        let n = u32::from_str_radix(&a[w * 8..w * 8 + 8], 16).ok()?.swap_bytes();
        b[w * 4..w * 4 + 4].copy_from_slice(&n.to_be_bytes());
    }
    Some((std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)), port))
}

/// Small pid→name cache backed by sysinfo; refreshed lazily on misses.
pub struct ProcessNames {
    sys: sysinfo::System,
    cache: HashMap<u32, String>,
    last_refresh: i64,
}

impl Default for ProcessNames {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessNames {
    pub fn new() -> Self {
        ProcessNames { sys: sysinfo::System::new(), cache: HashMap::new(), last_refresh: 0 }
    }
    pub fn name(&mut self, pid: u32) -> String {
        if pid == 0 {
            return "System".into();
        }
        if let Some(n) = self.cache.get(&pid) {
            return n.clone();
        }
        // targeted refresh of just this pid: catches processes that live < 2 s
        let p = sysinfo::Pid::from_u32(pid);
        self.sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[p]), true);
        if let Some(proc_) = self.sys.process(p) {
            let n = proc_.name().to_string_lossy().into_owned();
            if self.cache.len() > 4096 {
                self.cache.clear();
            }
            self.cache.insert(pid, n.clone());
            return n;
        }
        let now = now_ms();
        if now - self.last_refresh > 2000 {
            self.sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            self.last_refresh = now;
            // keep the cache bounded: rebuild from the live process list
            self.cache.clear();
            for (p, proc_) in self.sys.processes() {
                self.cache.insert(p.as_u32(), proc_.name().to_string_lossy().into_owned());
            }
        }
        self.cache.get(&pid).cloned().unwrap_or_else(|| format!("pid {pid}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_roundtrip() {
        let f = Frame::Batch { events: vec![WireEvent::new("agent", "agent.log", "low", "x")] };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains("\"type\":\"batch\""));
        let back: Frame = serde_json::from_str(&s).unwrap();
        matches!(back, Frame::Batch { .. });
    }
    #[test]
    fn sanitize_clamps() {
        let mut e = WireEvent::new("agent", "k", "bogus", "m".repeat(10_000));
        e.domain = Some("x\r\n1.2.3.4 www.bank.example".into());
        e.dst_ip = Some("1.2.3.4\r\n".into());
        e.ts = 1;
        e.sanitize();
        assert_eq!(e.severity, "info");
        assert_eq!(e.message.len(), 4096);
        assert!(e.domain.is_none(), "CRLF domain must be rejected");
        assert!(e.dst_ip.is_none());
        assert!(e.ts > 1);
        assert_eq!(normalize_domain("Example.COM.").as_deref(), Some("example.com"));
    }
}
