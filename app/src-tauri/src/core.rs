//! Shared state and the event pipeline.
//!
//! Producers (DNS resolver, connection monitor, agents, syslog, Suricata)
//! call [`Core::emit`]. A single low-priority thread enriches events, runs
//! threat matching, raises alerts / notifications and writes to SQLite in
//! batches (≤500 events or 1 s), so the database lock is held briefly.

use crate::db::{Db, NewAlert};
use crate::intel::{self, Intel};
use crate::settings::Settings;
use oph_proto::{now_ms, WireEvent};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

#[derive(Default)]
pub struct Lists {
    pub block_domains: HashSet<String>,
    pub allow_domains: HashSet<String>,
    pub block_ips: HashSet<u32>,
    pub allow_ips: HashSet<u32>,
    pub block_cidrs: Vec<(u32, u32)>,
    pub allow_cidrs: Vec<(u32, u32)>,
}

pub fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let (n, l) = s.split_once('/')?;
    let ip: Ipv4Addr = n.parse().ok()?;
    let l: u32 = l.parse().ok()?;
    if l > 32 {
        return None;
    }
    let mask = if l == 0 { 0 } else { !(u32::MAX >> l) };
    Some((u32::from(ip) & mask, mask))
}

fn domain_in(set: &HashSet<String>, d: &str) -> bool {
    let mut cur = d;
    loop {
        if set.contains(cur) {
            return true;
        }
        match cur.find('.') {
            Some(i) => cur = &cur[i + 1..],
            None => return false,
        }
    }
}

impl Lists {
    pub fn load(db: &Db) -> Lists {
        let mut l = Lists::default();
        for (list, (v, kind, _, _)) in db.list_entries("block").into_iter().map(|e| ("block", e)).chain(db.list_entries("allow").into_iter().map(|e| ("allow", e))) {
            let b = list == "block";
            match kind.as_str() {
                "domain" => {
                    if b { l.block_domains.insert(v) } else { l.allow_domains.insert(v) };
                }
                "ip" => {
                    if let Ok(ip) = v.parse::<Ipv4Addr>() {
                        if b { l.block_ips.insert(ip.into()) } else { l.allow_ips.insert(ip.into()) };
                    }
                }
                "cidr" => {
                    if let Some(c) = parse_cidr(&v) {
                        if b { l.block_cidrs.push(c) } else { l.allow_cidrs.push(c) }
                    }
                }
                _ => {}
            }
        }
        l
    }
    pub fn domain_allowed(&self, d: &str) -> bool {
        domain_in(&self.allow_domains, d)
    }
    pub fn domain_blocked(&self, d: &str) -> bool {
        domain_in(&self.block_domains, d)
    }
    pub fn ip_allowed(&self, ip: u32) -> bool {
        self.allow_ips.contains(&ip) || self.allow_cidrs.iter().any(|(n, m)| ip & m == *n)
    }
    pub fn ip_blocked(&self, ip: u32) -> bool {
        self.block_ips.contains(&ip) || self.block_cidrs.iter().any(|(n, m)| ip & m == *n)
    }
}

pub enum Verdict {
    Allowed,
    Manual,
    Intel(&'static intel::FeedDef),
    Clean,
}

#[derive(Default, Clone, serde::Serialize)]
pub struct ServiceStatus {
    pub dns_running: bool,
    pub dns_error: Option<String>,
    pub ingest_running: bool,
    pub ingest_error: Option<String>,
    pub syslog_running: bool,
    pub syslog_error: Option<String>,
    pub intel_updating: bool,
}

#[derive(Default, Clone, serde::Serialize)]
pub struct NetInfo {
    pub local_ip: Option<String>,
    pub gateway: Option<String>,
    pub subnet: Option<String>,
}

/// Bounded ip → domain map filled from DNS answers (attributes connections to names).
#[derive(Default)]
pub struct IpNames {
    map: HashMap<String, String>,
    order: VecDeque<String>,
}
impl IpNames {
    pub fn put(&mut self, ip: String, domain: String) {
        if self.map.insert(ip.clone(), domain).is_none() {
            self.order.push_back(ip);
            if self.order.len() > 8192 {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
    pub fn get(&self, ip: &str) -> Option<String> {
        self.map.get(ip).cloned()
    }
}

pub struct Core {
    pub dir: PathBuf,
    pub db: Mutex<Db>,
    pub settings: RwLock<Settings>,
    pub intel: RwLock<Arc<Intel>>,
    pub lists: RwLock<Lists>,
    tx: SyncSender<WireEvent>,
    pub status: Mutex<ServiceStatus>,
    pub net: Mutex<NetInfo>,
    pub ip_names: Mutex<IpNames>,
    /// ip → (hostname label, last DNS activity)
    pub dns_clients: Mutex<HashMap<String, i64>>,
    pub host_labels: RwLock<HashMap<String, String>>,
    pub conns: Mutex<Vec<serde_json::Value>>,
    pub agents_online: Mutex<HashMap<String, (String, String)>>,
    pub fingerprint: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub app: OnceLock<tauri::AppHandle>,
    notified: Mutex<HashMap<String, i64>>,
    pub dropped: std::sync::atomic::AtomicU64,
    pub admin: bool,
    pub storage: Mutex<crate::storage::StorageState>,
    /// last cleaner scan, so the Cleaner page survives navigation
    pub cleaner_last: Mutex<Option<serde_json::Value>>,
    /// network monitoring switch (top bar). DNS keeps resolving when off.
    pub monitoring: std::sync::atomic::AtomicBool,
    /// ETW DNS-client tracing is active: this PC's own lookups are recorded there (with process)
    pub etw_active: std::sync::atomic::AtomicBool,
    /// Leak Check engine (cross-view coverage)
    pub leak: crate::leak::Engine,
}

impl Core {
    pub fn new(dir: PathBuf) -> (Arc<Core>, Receiver<WireEvent>) {
        let mut settings = Settings::load(&dir);
        if crate::storage::auto_configure(&mut settings) {
            let _ = settings.save(&dir); // first run: put logs on the large external drive
        }
        let (db, storage) = crate::storage::open_initial(&settings, &dir);
        let lists = Lists::load(&db);
        let (cert_der, key_der, fingerprint) = crate::ingest::load_or_create_cert(&dir);
        let (tx, rx) = sync_channel(20_000);
        let core = Arc::new(Core {
            dir,
            db: Mutex::new(db),
            settings: RwLock::new(settings),
            intel: RwLock::new(Arc::new(Intel::default())),
            lists: RwLock::new(lists),
            tx,
            status: Mutex::new(ServiceStatus::default()),
            net: Mutex::new(NetInfo::default()),
            ip_names: Mutex::new(IpNames::default()),
            dns_clients: Mutex::new(HashMap::new()),
            host_labels: RwLock::new(HashMap::new()),
            conns: Mutex::new(Vec::new()),
            agents_online: Mutex::new(HashMap::new()),
            fingerprint,
            cert_der,
            key_der,
            app: OnceLock::new(),
            notified: Mutex::new(HashMap::new()),
            dropped: Default::default(),
            admin: crate::native::is_elevated(),
            storage: Mutex::new(storage),
            cleaner_last: Mutex::new(None),
            monitoring: std::sync::atomic::AtomicBool::new(true),
            etw_active: std::sync::atomic::AtomicBool::new(false),
            leak: crate::leak::Engine::default(),
        });
        core.monitoring.store(core.settings().network_monitoring, std::sync::atomic::Ordering::Relaxed);
        (core, rx)
    }

    /// Is network activity being recorded right now?
    pub fn monitoring_on(&self) -> bool {
        self.monitoring.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap().clone()
    }

    /// Non-blocking: if the pipeline is saturated the event is dropped and counted.
    pub fn emit(&self, e: WireEvent) {
        if self.tx.try_send(e).is_err() {
            self.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn sys(&self, kind: &str, sev: &str, msg: impl Into<String>) {
        let mut e = WireEvent::new(kind.split('.').next().unwrap_or("system"), kind, sev, msg);
        e.host = "this-pc".into();
        self.emit(e);
    }

    pub fn domain_verdict(&self, d: &str) -> Verdict {
        // one normalisation point: lower-case, no trailing dot, valid labels only
        let Some(d) = oph_proto::normalize_domain(d) else { return Verdict::Clean };
        let d = d.as_str();
        let l = self.lists.read().unwrap();
        if l.domain_allowed(d) {
            return Verdict::Allowed;
        }
        if l.domain_blocked(d) {
            return Verdict::Manual;
        }
        drop(l);
        match self.intel.read().unwrap().match_domain(d) {
            Some(h) => Verdict::Intel(h.feed),
            None => Verdict::Clean,
        }
    }

    pub fn ip_verdict(&self, ip: &str) -> Verdict {
        let Ok(a) = ip.parse::<Ipv4Addr>() else { return Verdict::Clean };
        let n = u32::from(a);
        if a.is_private() || a.is_loopback() || a.is_link_local() || a.is_multicast() {
            return Verdict::Clean;
        }
        let l = self.lists.read().unwrap();
        if l.ip_allowed(n) {
            return Verdict::Allowed;
        }
        if l.ip_blocked(n) {
            return Verdict::Manual;
        }
        drop(l);
        match self.intel.read().unwrap().match_ip(ip) {
            Some(h) => Verdict::Intel(h.feed),
            None => Verdict::Clean,
        }
    }

    /// Should the DNS resolver answer 0.0.0.0 for this name?
    pub fn sinkhole(&self, d: &str) -> Option<String> {
        match self.domain_verdict(d) {
            Verdict::Manual => Some("Manual blocklist".into()),
            Verdict::Intel(f) if self.settings.read().unwrap().block_mode() => Some(f.name.to_string()),
            _ => None,
        }
    }

    pub fn host_label(&self, ip: &str) -> String {
        self.host_labels.read().unwrap().get(ip).cloned().unwrap_or_else(|| ip.to_string())
    }

    pub fn notify(&self, key: &str, title: &str, body: &str) {
        if !self.settings.read().unwrap().notifications {
            return;
        }
        let now = now_ms();
        {
            let mut n = self.notified.lock().unwrap();
            if n.get(key).map(|t| now - t < 30 * 60_000).unwrap_or(false) {
                return;
            }
            n.insert(key.to_string(), now);
            if n.len() > 2000 {
                n.retain(|_, t| now - *t < 30 * 60_000);
            }
        }
        if let Some(app) = self.app.get() {
            use tauri_plugin_notification::NotificationExt;
            let _ = app.notification().builder().title(title).body(body).show();
        }
    }
}

pub fn random_token() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 24];
    ring::rand::SystemRandom::new().fill(&mut b).expect("rng");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ------------------------------------------------------------------ pipeline

const SKIP_MATCH: &[&str] = &["threat.match", "intel.update", "cleaner.run", "cleaner.undo", "system.start", "firewall.block", "firewall.unblock", "firewall.error", "firewall.sync"];

pub fn run_pipeline(core: Arc<Core>, rx: Receiver<WireEvent>) {
    std::thread::Builder::new()
        .name("oph-pipeline".into())
        .spawn(move || {
            let mut batch: Vec<WireEvent> = Vec::with_capacity(512);
            loop {
                match rx.recv_timeout(std::time::Duration::from_secs(1)) {
                    Ok(e) => {
                        batch.push(e);
                        while batch.len() < 500 {
                            match rx.try_recv() {
                                Ok(e) => batch.push(e),
                                Err(_) => break,
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => return,
                }
                if batch.is_empty() {
                    continue;
                }
                let mut extra = Vec::new();
                for e in batch.iter_mut() {
                    process(&core, e, &mut extra);
                }
                batch.extend(extra);
                let res = core.db.lock().unwrap().insert_events(&batch);
                if let Err(err) = res {
                    // the log drive may have been unplugged: switch location and retry once
                    eprintln!("event store write failed: {err}");
                    crate::storage::check(&core);
                    if core.db.lock().unwrap().insert_events(&batch).is_err() {
                        core.dropped.fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                batch.clear();
                if batch.capacity() > 4096 {
                    batch.shrink_to(512);
                }
            }
        })
        .expect("spawn pipeline");
}

fn process(core: &Core, e: &mut WireEvent, extra: &mut Vec<WireEvent>) {
    if e.source == "conn" && e.domain.is_none() {
        if let Some(ip) = &e.dst_ip {
            e.domain = core.ip_names.lock().unwrap().get(ip);
        }
    }
    if SKIP_MATCH.contains(&e.kind.as_str()) {
        return;
    }
    if e.kind == "ids.alert" {
        let sig = e.message.clone();
        raise(core, e, extra, &sig, "signature", "Suricata IDS", "ids", &e.severity.clone(), false);
        return;
    }
    let blocked_now = e.kind == "dns.blocked";
    if let Some(d) = e.domain.clone() {
        match core.domain_verdict(&d) {
            Verdict::Manual => raise(core, e, extra, &d, "domain", "Manual blocklist", "manual", "high", blocked_now),
            Verdict::Intel(f) => raise(core, e, extra, &d, "domain", f.name, f.category, f.severity, blocked_now),
            _ => {}
        }
    }
    if let Some(ip) = e.dst_ip.clone() {
        match core.ip_verdict(&ip) {
            Verdict::Manual => raise(core, e, extra, &ip, "ip", "Manual blocklist", "manual", "high", false),
            Verdict::Intel(f) => raise(core, e, extra, &ip, "ip", f.name, f.category, f.severity, false),
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn raise(core: &Core, e: &WireEvent, extra: &mut Vec<WireEvent>, indicator: &str, itype: &str, feed: &str, category: &str, sev: &str, blocked: bool) {
    let block_mode = core.settings.read().unwrap().block_mode();
    let host = if e.host.is_empty() { "unknown".to_string() } else { e.host.clone() };
    let status = if blocked || category == "manual" || (block_mode && category != "ids") { "blocked" } else { "open" };
    let title = match category {
        "phishing" => format!("Phishing site: {indicator}"),
        "malware" => format!("Malware site: {indicator}"),
        "botnet" => format!("Botnet C2 contact: {indicator}"),
        "hijacked" => format!("Hijacked network: {indicator}"),
        "manual" => format!("Blocklisted: {indicator}"),
        "ids" => format!("IDS: {indicator}"),
        _ => format!("Threat: {indicator}"),
    };
    let res = core.db.lock().unwrap().upsert_alert(&NewAlert {
        severity: sev,
        title: title.clone(),
        indicator,
        indicator_type: itype,
        feed,
        host: &host,
        src_ip: e.src_ip.as_deref(),
        status,
        explanation: intel::explain(category, indicator, feed, &host),
    });
    if category != "ids" {
        let mut m = WireEvent::new("intel", "threat.match", sev, format!("{indicator} matched {feed} (seen from {host})"));
        m.ts = e.ts;
        m.host = host.clone();
        m.src_ip = e.src_ip.clone();
        m.domain = if itype == "domain" { Some(indicator.to_string()) } else { e.domain.clone() };
        m.dst_ip = if itype == "ip" { Some(indicator.to_string()) } else { e.dst_ip.clone() };
        m.process = e.process.clone();
        m.raw = serde_json::json!({"feed": feed, "category": category, "indicator": indicator, "trigger_kind": e.kind, "action": status});
        extra.push(m);
    }
    if let Ok((alert, fresh)) = res {
        // enforce on this PC (hosts file + Windows Firewall) whenever something new is blocked
        if fresh && alert.status == "blocked" && category != "ids" {
            crate::firewall::request_sync(core);
        }
        if fresh || alert.count == 10 || alert.count == 100 {
            let verb = if alert.status == "blocked" { "Blocked" } else { "Dangerous site detected" };
            let body = if alert.status == "blocked" {
                format!("{indicator} was blocked for {host}. Source: {feed}.")
            } else {
                format!("{host} contacted {indicator} ({feed}). Open OPH Sentinel → Alerts to block or allow it.")
            };
            core.notify(indicator, &format!("{verb} — {}", sev.to_uppercase()), &body);
        }
    }
}
