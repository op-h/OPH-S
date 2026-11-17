//! LAN DNS resolver / sinkhole (the Pi-hole / AdGuard Home approach).
//!
//! Point the router's DHCP "DNS server" at this PC and every device on the
//! network (phones, TVs, consoles, IoT) resolves through OPH Sentinel. That
//! gives a per-device query log and network-wide blocking with no software on
//! the devices. Message parsing uses `hickory-proto` (the Hickory DNS project).
//!
//! Design follows AdGuard dnsproxy / Pi-hole FTL:
//! - a small pool of long-lived upstream sockets, responses matched by a
//!   random 16-bit ID + source address (anti-spoofing), no socket per query;
//! - a TTL-respecting answer cache (positive + negative) with TTL decrement;
//! - only LAN / loopback clients are served (never an open resolver);
//! - malformed packets get FORMERR, response packets are dropped.

use crate::core::Core;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use oph_proto::{now_ms, WireEvent};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{oneshot, Semaphore};

/// Same (client, name) pair is logged at most once per window to keep the store small.
const LOG_WINDOW_MS: i64 = 60_000;
const UPSTREAM_SOCKETS: usize = 4;
const CACHE_MAX: usize = 10_000;
/// how long past its TTL an answer may still be served when every upstream is down (RFC 8767)
const STALE_SECS: u64 = 86_400;

struct Dedupe(Mutex<HashMap<(String, String), i64>>);

impl Dedupe {
    fn should_log(&self, client: &str, name: &str) -> bool {
        let now = now_ms();
        let mut m = self.0.lock().unwrap();
        if m.len() > 20_000 {
            m.retain(|_, t| now - *t < LOG_WINDOW_MS);
        }
        let k = (client.to_string(), name.to_string());
        match m.get(&k) {
            Some(t) if now - *t < LOG_WINDOW_MS => false,
            _ => {
                m.insert(k, now);
                true
            }
        }
    }
}

// ------------------------------------------------------------------ upstream pool

/// Pool of long-lived UDP sockets to one upstream resolver.
///
/// Self-healing: on Windows a *connected* UDP socket can get stuck after a
/// network change (adapter switch, VPN/Tailscale route change, ICMP errors) and
/// then fails every send instantly. Any send error, or several timeouts in a
/// row, rebuilds the whole pool with fresh sockets. Readers of replaced sockets
/// notice and exit.
struct Upstream {
    addr: SocketAddr,
    /// pool sockets with their own consecutive-miss counters: one bad socket is replaced
    /// even while the others keep answering
    socks: std::sync::RwLock<Vec<(Arc<UdpSocket>, Arc<std::sync::atomic::AtomicU32>)>>,
    pending: Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>,
    next: AtomicUsize,
    failures: AtomicUsize,
    rebuilding: std::sync::atomic::AtomicBool,
}

fn random_u16() -> u16 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 2];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    u16::from_le_bytes(b)
}

impl Upstream {
    async fn new(addr: SocketAddr) -> std::io::Result<Arc<Upstream>> {
        let up = Arc::new(Upstream {
            addr,
            socks: std::sync::RwLock::new(Vec::new()),
            pending: Mutex::new(HashMap::new()),
            next: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            rebuilding: std::sync::atomic::AtomicBool::new(false),
        });
        Upstream::rebuild(&up).await?;
        Ok(up)
    }

    /// Replace every socket with a fresh one and start its reader.
    async fn rebuild(up: &Arc<Upstream>) -> std::io::Result<()> {
        let local: SocketAddr = if up.addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let mut fresh = Vec::new();
        for _ in 0..UPSTREAM_SOCKETS {
            let s = UdpSocket::bind(local).await?;
            s.connect(up.addr).await?; // kernel drops datagrams from any other source
            fresh.push(Arc::new(s));
        }
        *up.socks.write().unwrap() = fresh.iter().map(|s| (s.clone(), Arc::new(std::sync::atomic::AtomicU32::new(0)))).collect();
        up.failures.store(0, Ordering::Relaxed);
        for s in fresh {
            let weak = Arc::downgrade(up);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let r = tokio::time::timeout(Duration::from_secs(30), s.recv(&mut buf)).await;
                    let Some(up) = weak.upgrade() else { return };
                    // this socket was replaced by a rebuild: stop reading it
                    if !up.socks.read().unwrap().iter().any(|(x, _)| Arc::ptr_eq(x, &s)) {
                        return;
                    }
                    let n = match r {
                        Ok(Ok(n)) => n,
                        Ok(Err(_)) => {
                            tokio::time::sleep(Duration::from_millis(50)).await; // ICMP error etc.: never spin
                            continue;
                        }
                        Err(_) => continue, // idle
                    };
                    if n < 12 {
                        continue;
                    }
                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                    let tx = up.pending.lock().unwrap().remove(&id);
                    if let Some(tx) = tx {
                        let _ = tx.send(buf[..n].to_vec());
                    }
                }
            });
        }
        Ok(())
    }

    fn heal(up: &Arc<Upstream>) {
        if up.rebuilding.swap(true, Ordering::SeqCst) {
            return;
        }
        let up = up.clone();
        tokio::spawn(async move {
            let _ = Upstream::rebuild(&up).await;
            up.rebuilding.store(false, Ordering::SeqCst);
        });
    }

    /// Send one query (raw bytes, any ID) and return the raw response with the
    /// caller's original ID restored. Two attempts on different sockets.
    async fn query(up: &Arc<Upstream>, q: &[u8]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let orig = [q[0], q[1]];
        for attempt in 0..2 {
            let (tx, rx) = oneshot::channel();
            let id = {
                let mut p = up.pending.lock().unwrap();
                let mut id = random_u16();
                let mut tries = 0;
                while p.contains_key(&id) && tries < 16 {
                    id = random_u16();
                    tries += 1;
                }
                if p.contains_key(&id) {
                    return None;
                }
                p.insert(id, tx);
                id
            };
            let mut out = q.to_vec();
            out[..2].copy_from_slice(&id.to_be_bytes());
            let sock = {
                let socks = up.socks.read().unwrap();
                if socks.is_empty() {
                    None
                } else {
                    let (s, m) = &socks[up.next.fetch_add(1, Ordering::Relaxed) % socks.len()];
                    Some((s.clone(), m.clone()))
                }
            };
            let sent = match &sock {
                Some((s, _)) => s.send(&out).await.is_ok(),
                None => false,
            };
            if !sent {
                up.pending.lock().unwrap().remove(&id);
                Upstream::heal(up); // a socket that cannot send is broken: replace the pool now
                continue;
            }
            if let Ok(Ok(mut resp)) = tokio::time::timeout(Duration::from_millis(if attempt == 0 { 1000 } else { 1500 }), rx).await {
                up.failures.store(0, Ordering::Relaxed);
                if let Some((_, m)) = &sock {
                    m.store(0, Ordering::Relaxed);
                }
                resp[..2].copy_from_slice(&orig);
                return Some(resp);
            }
            up.pending.lock().unwrap().remove(&id);
            // this socket missed: 3 misses in a row on the same socket -> rebuild the pool,
            // even if the other sockets still answer (a single stuck socket used to hide forever)
            let sock_misses = sock.as_ref().map(|(_, m)| m.fetch_add(1, Ordering::Relaxed) + 1).unwrap_or(0);
            if sock_misses >= 3 || up.failures.fetch_add(1, Ordering::Relaxed) + 1 >= 8 {
                Upstream::heal(up);
            }
        }
        None
    }
}

/// Fallback resolvers tried (with fresh one-off sockets) when the main upstream
/// fails, so a single broken path never takes the whole network's DNS down.
fn fallbacks(primary: SocketAddr, gateway: Option<&str>) -> Vec<SocketAddr> {
    let mut v: Vec<SocketAddr> = vec![primary, "9.9.9.9:53".parse().unwrap(), "1.0.0.1:53".parse().unwrap()];
    if let Some(gw) = gateway.and_then(|g| format!("{g}:53").parse().ok()) {
        v.push(gw);
    }
    v.dedup();
    v
}

// ------------------------------------------------------------------ cache

struct Entry {
    resp: Vec<u8>,
    stored: Instant,
    ttl: u32,
}

#[derive(Default)]
struct Cache {
    map: Mutex<HashMap<(String, u16, u16), Entry>>,
}

impl Cache {
    fn get(&self, key: &(String, u16, u16), id: [u8; 2]) -> Option<Vec<u8>> {
        let m = self.map.lock().unwrap();
        let e = m.get(key)?;
        let age = e.stored.elapsed().as_secs() as u32;
        if age >= e.ttl {
            return None; // expired: kept for serve-stale, see get_stale()
        }
        let (bytes, remaining) = (e.resp.clone(), e.ttl - age);
        drop(m);
        // serve with decremented TTLs so clients never cache past the authority's TTL
        let mut msg = Message::from_vec(&bytes).ok()?;
        let fix = |v: Vec<Record>| -> Vec<Record> {
            v.into_iter()
                .map(|mut r| {
                    let t = r.ttl().min(remaining).max(1);
                    r.set_ttl(t);
                    r
                })
                .collect()
        };
        let a = fix(msg.take_answers());
        let ns = fix(msg.take_name_servers());
        msg.insert_answers(a);
        msg.insert_name_servers(ns);
        msg.set_id(u16::from_be_bytes(id));
        msg.to_vec().ok()
    }

    /// RFC 8767 serve-stale: when every upstream is unreachable, answer from an expired entry
    /// (up to 1 day old) with a 30 s TTL instead of failing. Only used after all resolvers failed.
    fn get_stale(&self, key: &(String, u16, u16), id: [u8; 2]) -> Option<Vec<u8>> {
        let m = self.map.lock().unwrap();
        let e = m.get(key)?;
        if e.stored.elapsed().as_secs() > e.ttl as u64 + STALE_SECS {
            return None;
        }
        let bytes = e.resp.clone();
        drop(m);
        let mut msg = Message::from_vec(&bytes).ok()?;
        let fix = |v: Vec<Record>| -> Vec<Record> {
            v.into_iter()
                .map(|mut r| {
                    r.set_ttl(30);
                    r
                })
                .collect()
        };
        let a = fix(msg.take_answers());
        let ns = fix(msg.take_name_servers());
        msg.insert_answers(a);
        msg.insert_name_servers(ns);
        msg.set_id(u16::from_be_bytes(id));
        msg.to_vec().ok()
    }

    fn put(&self, key: (String, u16, u16), resp: &[u8], parsed: &Message) {
        if parsed.truncated() {
            return;
        }
        let ttl = match parsed.response_code() {
            ResponseCode::NoError if !parsed.answers().is_empty() => parsed.answers().iter().map(|r| r.ttl()).min().unwrap_or(60),
            // negative answers: SOA minimum when present (RFC 2308), else 60 s
            ResponseCode::NoError | ResponseCode::NXDomain => parsed
                .name_servers()
                .iter()
                .find_map(|r| match r.data() {
                    Some(RData::SOA(soa)) => Some(soa.minimum().min(r.ttl())),
                    _ => None,
                })
                .unwrap_or(60),
            _ => return, // never cache SERVFAIL / REFUSED
        };
        let ttl = ttl.clamp(5, 3600);
        let mut m = self.map.lock().unwrap();
        if m.len() >= CACHE_MAX {
            m.retain(|_, e| e.stored.elapsed().as_secs() < e.ttl as u64 + STALE_SECS);
            if m.len() >= CACHE_MAX {
                m.clear(); // bounded memory beats perfect hit rate
            }
        }
        m.insert(key, Entry { resp: resp.to_vec(), stored: Instant::now(), ttl });
    }
}

// ------------------------------------------------------------------ server

/// Clients we serve: loopback, RFC 1918, link-local, CGNAT (Tailscale), IPv6 ULA / link-local.
fn lan_client(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback() || v.is_private() || v.is_link_local() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return lan_client(IpAddr::V4(m));
            }
            let s = v.segments()[0];
            v.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

type Key = (String, u16, u16);

struct Ctx {
    core: Arc<Core>,
    dedupe: Dedupe,
    cache: Cache,
    upstream: Arc<Upstream>,
    /// identical questions already on their way upstream: later askers wait for the first answer
    inflight: Mutex<HashMap<Key, Vec<oneshot::Sender<Option<Vec<u8>>>>>>,
    /// first time resolution started failing (0 = healthy), and when we last reported it
    failing_since: std::sync::atomic::AtomicI64,
    reported: std::sync::atomic::AtomicBool,
    last_fallback_note: std::sync::atomic::AtomicI64,
    /// skip the pool until this time (ms) after it failed; the watchdog clears it once healed
    pool_sick_until: std::sync::atomic::AtomicI64,
}

impl Ctx {
    /// Track resolver health; raise one clear alert if DNS has been failing for 20 s.
    fn health(&self, ok: bool) {
        use std::sync::atomic::Ordering as O;
        let now = now_ms();
        if ok {
            if self.failing_since.swap(0, O::Relaxed) != 0 && self.reported.swap(false, O::Relaxed) {
                self.core.sys("system.start", "info", "DNS resolution recovered");
            }
            return;
        }
        let since = self.failing_since.load(O::Relaxed);
        if since == 0 {
            self.failing_since.store(now, O::Relaxed);
        } else if now - since > 20_000 && !self.reported.swap(true, O::Relaxed) {
            let msg = format!("DNS lookups have been failing for {} s: every upstream resolver is unreachable. Devices using OPH-S DNS have no internet until this recovers.", (now - since) / 1000);
            self.core.sys("system.error", "critical", msg.clone());
            self.core.notify("dns-down", "OPH-S DNS is failing", &msg);
        }
    }

    fn note_fallback(&self, alt: SocketAddr) {
        use std::sync::atomic::Ordering as O;
        let now = now_ms();
        if now - self.last_fallback_note.load(O::Relaxed) > 300_000 {
            self.last_fallback_note.store(now, O::Relaxed);
            self.core.sys("system.error", "low", format!("Main DNS upstream {} did not answer; served from fallback {alt}. The connection pool is being rebuilt.", self.upstream.addr));
        }
    }

    /// Resolve upstream with request coalescing (one upstream query per name/type in flight).
    async fn resolve(&self, key: &Key, q: &[u8], tcp: bool) -> Option<Vec<u8>> {
        let waiter = {
            let mut m = self.inflight.lock().unwrap();
            match m.get_mut(key) {
                Some(list) if list.len() < 256 => {
                    let (tx, rx) = oneshot::channel();
                    list.push(tx);
                    Some(rx)
                }
                Some(_) => None,
                None => {
                    m.insert(key.clone(), Vec::new());
                    None
                }
            }
        };
        if let Some(rx) = waiter {
            let mut r = tokio::time::timeout(Duration::from_secs(4), rx).await.ok()?.ok()??;
            r[..2].copy_from_slice(&q[..2]);
            return Some(r);
        }
        // while the connection pool is known to be broken, go straight to the fallbacks (no 2.5 s wait)
        let pool_sick = now_ms() < self.pool_sick_until.load(std::sync::atomic::Ordering::Relaxed);
        let mut r = if pool_sick && !tcp {
            None
        } else if tcp {
            match forward_tcp(q, self.upstream.addr).await {
                Some(r) => Some(r),
                // fall back to UDP when TCP upstream fails, but a truncated (TC) answer is useless to a TCP client
                None => Upstream::query(&self.upstream, q).await.filter(|r| r.len() < 3 || r[2] & 0x02 == 0),
            }
        } else {
            Upstream::query(&self.upstream, q).await
        };
        if r.is_none() && !pool_sick {
            self.pool_sick_until.store(now_ms() + 30_000, std::sync::atomic::Ordering::Relaxed);
        }
        if r.is_none() {
            // main path failed: race fresh sockets to the primary and the other resolvers; first answer wins
            let gw = self.core.net.lock().unwrap().gateway.clone();
            let mut set = tokio::task::JoinSet::new();
            for alt in fallbacks(self.upstream.addr, gw.as_deref()) {
                let q = q.to_vec();
                set.spawn(async move { forward_once(&q, alt, Duration::from_millis(1500)).await.map(|a| (alt, a)) });
            }
            while let Some(res) = set.join_next().await {
                if let Ok(Some((alt, ans))) = res {
                    self.note_fallback(alt);
                    r = Some(ans);
                    break;
                }
            }
            set.abort_all();
        }
        self.health(r.is_some());
        let waiters = self.inflight.lock().unwrap().remove(key).unwrap_or_default();
        for w in waiters {
            let _ = w.send(r.clone());
        }
        r
    }
}

pub async fn run(core: Arc<Core>) {
    let s = core.settings();
    if !s.dns_enabled {
        return;
    }
    let bind: SocketAddr = s.dns_bind.parse().unwrap();
    let upstream_addr: SocketAddr = s.dns_upstream.parse().unwrap();
    let udp = match UdpSocket::bind(bind).await {
        Ok(u) => Arc::new(u),
        Err(e) => {
            let hint = if e.kind() == std::io::ErrorKind::AddrInUse || e.raw_os_error() == Some(10048) {
                " — another DNS service is using the port (Internet Connection Sharing, Hyper-V, or another resolver)."
            } else if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(10013) {
                " — access denied. Run as administrator or choose another port."
            } else {
                ""
            };
            let msg = format!("DNS resolver cannot listen on {bind}: {e}{hint}");
            core.status.lock().unwrap().dns_error = Some(msg.clone());
            core.sys("system.error", "high", msg);
            return;
        }
    };
    let upstream = match Upstream::new(upstream_addr).await {
        Ok(u) => u,
        Err(e) => {
            let msg = format!("DNS resolver cannot reach upstream {upstream_addr}: {e}");
            core.status.lock().unwrap().dns_error = Some(msg.clone());
            core.sys("system.error", "high", msg);
            return;
        }
    };
    {
        let mut st = core.status.lock().unwrap();
        st.dns_running = true;
        st.dns_error = None;
    }
    core.sys("system.start", "info", format!("DNS resolver listening on {bind}, upstream {upstream_addr}"));
    let ctx = Arc::new(Ctx { core, dedupe: Dedupe(Mutex::new(HashMap::new())), cache: Cache::default(), upstream, inflight: Mutex::new(HashMap::new()),
        failing_since: Default::default(), reported: Default::default(), last_fallback_note: Default::default(), pool_sick_until: Default::default() });
    let limit = Arc::new(Semaphore::new(2048));
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            // a fixed query for a stable name; any answer (even NXDOMAIN) proves the path works
            let probe: [u8; 29] = [0x0b, 0xad, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1];
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if Upstream::query(&ctx.upstream, &probe).await.is_none() {
                    Upstream::heal(&ctx.upstream);
                } else {
                    ctx.pool_sick_until.store(0, std::sync::atomic::Ordering::Relaxed); // healed: use the fast path again
                }
            }
        });
    } // tasks are tiny; cached answers return in microseconds

    // TCP (truncated answers / clients preferring TCP) and UDP run in this one task,
    // so aborting the service releases both ports.
    let tcp_loop = {
        let ctx = ctx.clone();
        async move {
            let Ok(tcp) = TcpListener::bind(bind).await else { return };
            let conns = Arc::new(Semaphore::new(64));
            loop {
                let Ok((mut stream, peer)) = tcp.accept().await else { continue };
                if !lan_client(peer.ip()) {
                    continue;
                }
                let Ok(permit) = conns.clone().try_acquire_owned() else { continue };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(Duration::from_secs(10), async {
                        let mut len = [0u8; 2];
                        stream.read_exact(&mut len).await?;
                        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                        stream.read_exact(&mut q).await?;
                        if let Some(resp) = handle(&ctx, &q, peer, true).await {
                            stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
                            stream.write_all(&resp).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    })
                    .await;
                });
            }
        }
    };
    let udp_loop = async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf).await else { continue };
            if !lan_client(peer.ip()) {
                continue; // never act as an open resolver for the internet
            }
            let Ok(permit) = limit.clone().try_acquire_owned() else { continue }; // overload: drop, client retries
            let q = buf[..n].to_vec();
            let (ctx, udp) = (ctx.clone(), udp.clone());
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(resp) = handle(&ctx, &q, peer, false).await {
                    let _ = udp.send_to(&resp, peer).await;
                }
            });
        }
    };
    tokio::join!(tcp_loop, udp_loop);
}

/// Minimal FORMERR reply echoing the request ID (RFC 1035 §4.1.1).
fn formerr(q: &[u8]) -> Option<Vec<u8>> {
    if q.len() < 12 {
        return None;
    }
    let mut r = vec![0u8; 12];
    r[0] = q[0];
    r[1] = q[1];
    r[2] = 0x80 | (q[2] & 0x79); // QR=1, keep opcode + RD
    r[3] = 0x80 | 1; // RA=1, RCODE=FORMERR
    Some(r)
}

async fn handle(ctx: &Ctx, q: &[u8], peer: SocketAddr, tcp: bool) -> Option<Vec<u8>> {
    let core = &ctx.core;
    if q.len() >= 3 && q[2] & 0x80 != 0 {
        return None; // a response, not a query: drop (reflection / loops)
    }
    let Ok(msg) = Message::from_vec(q) else { return formerr(q) };
    let Some(query) = msg.queries().first().cloned() else { return formerr(q) };
    let raw_name = query.name().to_utf8();
    let name = raw_name.trim_end_matches('.').to_ascii_lowercase();
    let qtype = query.query_type();
    let client = match peer.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v| v.to_string()).unwrap_or_else(|| v6.to_string()),
        ip => ip.to_string(),
    };
    core.dns_clients.lock().unwrap().insert(client.clone(), now_ms());
    // Leak Check tap: cheap counters + bounded non-blocking queue (never stalls answering)
    let is_self = client == "127.0.0.1" || client == "::1" || core.net.lock().unwrap().local_ip.as_deref() == Some(client.as_str());
    core.leak.on_query(core, &client, peer.port(), tcp, &name, is_self);

    if let Some(reason) = core.sinkhole(&name) {
        let mut r = Message::new();
        r.set_id(msg.id())
            .set_message_type(MessageType::Response)
            .set_op_code(msg.op_code())
            .set_recursion_desired(msg.recursion_desired())
            .set_recursion_available(true)
            .add_query(query.clone());
        // off-switch names (Firefox DoH canary, iCloud Private Relay) only work with NXDOMAIN
        let canary = crate::leak::is_canary(&name);
        match qtype {
            _ if canary => {
                r.set_response_code(ResponseCode::NXDomain);
            }
            RecordType::A => {
                r.add_answer(Record::from_rdata(query.name().clone(), 60, RData::A(A(Ipv4Addr::UNSPECIFIED))));
            }
            RecordType::AAAA => {
                r.add_answer(Record::from_rdata(query.name().clone(), 60, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))));
            }
            _ => {
                r.set_response_code(ResponseCode::NXDomain);
            }
        }
        if ctx.dedupe.should_log(&client, &format!("blocked:{name}")) {
            let label = core.host_label(&client);
            let mut e = WireEvent::new("dns", "dns.blocked", "medium", format!("Blocked {name} ({qtype}) for {label} — {reason}"));
            e.host = label;
            e.src_ip = Some(client);
            e.domain = oph_proto::normalize_domain(&name);
            e.raw = serde_json::json!({"qtype": qtype.to_string(), "reason": reason, "answer": "0.0.0.0"});
            core.emit(e);
        }
        return r.to_vec().ok();
    }

    let started = Instant::now();
    let key: Key = (name.clone(), u16::from(qtype), u16::from(query.query_class()));
    let (resp, cached) = match ctx.cache.get(&key, [q[0], q[1]]) {
        Some(r) => (r, true),
        None => match ctx.resolve(&key, q, tcp).await {
            Some(r) => (r, false),
            None => {
                // every resolver failed: serve the last known answer rather than break the device
                if let Some(stale) = ctx.cache.get_stale(&key, [q[0], q[1]]) {
                    if ctx.dedupe.should_log("oph", "serve-stale") {
                        core.sys("system.error", "medium", format!("All upstream resolvers unreachable; answering from cache (stale) to keep devices online. Example: {name}"));
                    }
                    return Some(stale);
                }
                if core.monitoring_on() && ctx.dedupe.should_log(&client, &format!("servfail:{name}")) {
                    let label = core.host_label(&client);
                    let mut e = WireEvent::new("dns", "dns.query", "medium", format!("{label} could not resolve {name}: no upstream resolver answered (SERVFAIL)"));
                    e.host = label;
                    e.src_ip = Some(client.clone());
                    e.domain = oph_proto::normalize_domain(&name);
                    e.raw = serde_json::json!({"qtype": qtype.to_string(), "rcode": "SERVFAIL", "reason": "upstream unreachable"});
                    core.emit(e);
                }
                return servfail(&msg);
            }
        },
    };
    let mut answers: Vec<String> = Vec::new();
    let mut rcode = String::from("NOERROR");
    if let Ok(parsed) = Message::from_vec(&resp) {
        rcode = parsed.response_code().to_string();
        if !cached {
            ctx.cache.put(key, &resp, &parsed);
        }
        let mut names = core.ip_names.lock().unwrap();
        for rec in parsed.answers() {
            let ip = match rec.data() {
                Some(RData::A(a)) => Some(a.0.to_string()),
                Some(RData::AAAA(a)) => Some(a.0.to_string()),
                _ => None,
            };
            if let Some(ip) = ip {
                names.put(ip.clone(), name.clone());
                if answers.len() < 8 {
                    answers.push(ip);
                }
            }
        }
    }
    // this PC's own lookups are already recorded by ETW (with the process name): don't log them twice
    let local_dup = core.etw_active.load(std::sync::atomic::Ordering::Relaxed)
        && (client == "127.0.0.1" || client == "::1" || core.net.lock().unwrap().local_ip.as_deref() == Some(client.as_str()));
    let skip = local_dup || !core.monitoring_on() || matches!(qtype, RecordType::PTR | RecordType::SOA) || name.ends_with(".local") || name.ends_with(".arpa");
    if !skip && ctx.dedupe.should_log(&client, &name) {
        let label = core.host_label(&client);
        let mut e = WireEvent::new("dns", "dns.query", "info", format!("{label} resolved {name} ({qtype}) → {}", if answers.is_empty() { rcode.clone() } else { answers.join(", ") }));
        e.host = label;
        e.src_ip = Some(client);
        e.domain = oph_proto::normalize_domain(&name);
        e.dst_ip = answers.first().cloned();
        e.raw = serde_json::json!({"qtype": qtype.to_string(), "rcode": rcode, "answers": answers, "latency_ms": started.elapsed().as_millis() as u64,
            "transport": if tcp {"tcp"} else {"udp"}, "cached": cached});
        core.emit(e);
    }
    Some(resp)
}

fn servfail(msg: &Message) -> Option<Vec<u8>> {
    let mut r = Message::new();
    r.set_id(msg.id()).set_message_type(MessageType::Response).set_op_code(msg.op_code()).set_recursion_desired(msg.recursion_desired()).set_recursion_available(true).set_response_code(ResponseCode::ServFail);
    for q in msg.queries() {
        r.add_query(q.clone());
    }
    r.to_vec().ok()
}

/// Single fresh-socket attempt with a deadline (fallback path).
async fn forward_once(q: &[u8], upstream: SocketAddr, wait: Duration) -> Option<Vec<u8>> {
    let local: SocketAddr = if upstream.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = UdpSocket::bind(local).await.ok()?;
    sock.connect(upstream).await.ok()?;
    sock.send(q).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(wait, sock.recv(&mut buf)).await.ok()?.ok()?;
    (n >= 12 && buf[..2] == q[..2]).then(|| {
        buf.truncate(n);
        buf
    })
}

/// One-off UDP exchange (used for PTR lookups to the router, not the hot path).
async fn forward_udp(q: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let local: SocketAddr = if upstream.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = UdpSocket::bind(local).await.ok()?;
    sock.connect(upstream).await.ok()?;
    let mut buf = vec![0u8; 4096];
    for _ in 0..2 {
        sock.send(q).await.ok()?;
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(1500), sock.recv(&mut buf)).await {
            buf.truncate(n);
            return Some(buf);
        }
    }
    None
}

async fn forward_tcp(q: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut s = tokio::net::TcpStream::connect(upstream).await.ok()?;
        s.write_all(&(q.len() as u16).to_be_bytes()).await.ok()?;
        s.write_all(q).await.ok()?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.ok()?;
        let mut r = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut r).await.ok()?;
        Some(r)
    })
    .await
    .ok()
    .flatten()
}

/// Reverse lookup (PTR) through the router: most home routers answer with the
/// DHCP hostname a device announced, which gives friendly device names.
pub async fn ptr_lookup(ip: Ipv4Addr, server: SocketAddr) -> Option<String> {
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    let o = ip.octets();
    let name = Name::from_ascii(format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])).ok()?;
    let mut m = Message::new();
    m.set_id(random_u16()).set_recursion_desired(true).add_query(Query::query(name, RecordType::PTR));
    let resp = forward_udp(&m.to_vec().ok()?, server).await?;
    let parsed = Message::from_vec(&resp).ok()?;
    parsed.answers().iter().find_map(|r| match r.data() {
        Some(RData::PTR(p)) => {
            let n = p.0.to_utf8();
            let n = n.trim_end_matches('.');
            let short = n.split('.').next().unwrap_or(n);
            (oph_proto::normalize_domain(short).is_some() && short.parse::<u8>().is_err()).then(|| short.to_string())
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lan_only() {
        assert!(lan_client("192.168.1.5".parse().unwrap()));
        assert!(lan_client("127.0.0.1".parse().unwrap()));
        assert!(lan_client("100.100.1.1".parse().unwrap()));
        assert!(lan_client("fd00::1".parse().unwrap()));
        assert!(!lan_client("8.8.8.8".parse().unwrap()));
        assert!(!lan_client("2001:4860::1".parse().unwrap()));
    }
    #[test]
    fn serve_stale_only_after_expiry() {
        use hickory_proto::op::Query;
        use hickory_proto::rr::Name;
        let name = Name::from_ascii("example.com.").unwrap();
        let mut m = Message::new();
        m.set_id(7).set_message_type(MessageType::Response).add_query(Query::query(name.clone(), RecordType::A));
        m.add_answer(Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))));
        let bytes = m.to_vec().unwrap();
        let c = Cache::default();
        let key = ("example.com".to_string(), 1u16, 1u16);
        c.put(key.clone(), &bytes, &m);
        assert!(c.get(&key, [0, 9]).is_some());
        // age the entry past its TTL
        c.map.lock().unwrap().get_mut(&key).unwrap().ttl = 0;
        assert!(c.get(&key, [0, 9]).is_none(), "expired entries are not served normally");
        let stale = Message::from_vec(&c.get_stale(&key, [0, 9]).unwrap()).unwrap();
        assert_eq!(stale.id(), 9);
        assert_eq!(stale.answers()[0].ttl(), 30);
    }
    #[test]
    fn formerr_echoes_id() {
        let r = formerr(&[0xab, 0xcd, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(&r[..2], &[0xab, 0xcd]);
        assert_eq!(r[3] & 0x0f, 1);
        assert!(r[2] & 0x80 != 0);
        assert!(formerr(&[1, 2, 3]).is_none());
    }
}
