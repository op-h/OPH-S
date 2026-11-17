//! oph-agent — lightweight collector that ships events to OPH Sentinel over TLS.
//!
//! Runs on a single-threaded Tokio runtime with bounded buffers so the resident
//! footprint stays at a few MB. Usage:
//!
//! ```text
//! oph-agent --server 192.168.1.10:8443 --token <TOKEN> --fingerprint <SHA256> [--name laptop]
//!           [--no-conn] [--no-winlog] [--logcat] [--tail <file>]... [--interval 10]
//! ```

// GUI subsystem on Windows: no console window flashes at logon. When started from a
// terminal we attach to its console so usage text and status still print.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(pid: u32) -> i32;
}

use oph_proto::{now_ms, Frame, ProcessNames, WireEvent, MAX_BATCH, PROTOCOL_VERSION};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const BUFFER_CAP: usize = 5000;
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
struct Args {
    server: String,
    token: String,
    fingerprint: [u8; 32],
    name: String,
    conn: bool,
    winlog: bool,
    winlog_channels: Vec<String>,
    logcat: bool,
    tails: Vec<String>,
    interval: u64,
}

fn usage() -> ! {
    eprintln!(
        "oph-agent {VERSION} — OPH Sentinel collector\n\n\
         Required:\n  --server HOST:PORT     address of the OPH Sentinel desktop (Agents page)\n  \
         --token TOKEN          enrollment token (Agents page)\n  \
         --fingerprint SHA256   server certificate fingerprint (Agents page)\n\n\
         Optional:\n  --name NAME            display name (default: hostname)\n  \
         --no-conn              do not report network connections\n  \
         --winlog CHANNELS      Windows Event Log channels, comma separated (default System,Application)\n  \
         --no-winlog            do not read Windows Event Log (Windows only)\n  \
         --install              start automatically (Windows: logon task; Android: Termux:Boot)\n  \
         --uninstall            remove automatic start\n  \
         --logcat               read Android logcat (Termux; needs READ_LOGS grant)\n  \
         --tail FILE            ship new lines of FILE (repeatable)\n  \
         --interval SECS        connection poll interval (default 10)\n\nDONE by OPH"
    );
    std::process::exit(2)
}

/// Arguments, with `--config FILE` expanded (one argument per line). Used by --install so the
/// scheduled task command stays far below Windows' 261-character /tr limit.
fn expanded_args() -> Vec<String> {
    let mut out = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == "--config" {
            let path = it.next().unwrap_or_else(|| usage());
            match std::fs::read_to_string(&path) {
                Ok(t) => out.extend(t.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty())),
                Err(e) => {
                    eprintln!("cannot read config {path}: {e}");
                    std::process::exit(2)
                }
            }
        } else {
            out.push(a);
        }
    }
    out
}

fn parse_args() -> Args {
    let mut it = expanded_args().into_iter();
    let mut server = None;
    let mut token = None;
    let mut fp = None;
    let mut install = false;
    let mut a = Args {
        server: String::new(),
        token: String::new(),
        fingerprint: [0; 32],
        name: hostname(),
        conn: true,
        winlog: cfg!(windows),
        winlog_channels: vec!["System".into(), "Application".into()],
        logcat: false,
        tails: vec![],
        interval: 10,
    };
    while let Some(k) = it.next() {
        match k.as_str() {
            "--server" => server = it.next(),
            "--token" => token = it.next(),
            "--fingerprint" => fp = it.next(),
            "--name" => a.name = it.next().unwrap_or_else(|| usage()),
            "--no-conn" => a.conn = false,
            "--no-winlog" => a.winlog = false,
            "--winlog" => {
                let v = it.next().unwrap_or_else(|| usage());
                a.winlog = cfg!(windows);
                a.winlog_channels = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            "--install" => install = true,
            "--uninstall" => {
                uninstall();
                std::process::exit(0)
            }
            "--logcat" => a.logcat = true,
            "--tail" => a.tails.push(it.next().unwrap_or_else(|| usage())),
            "--interval" => {
                let v: Option<u64> = it.next().and_then(|v| v.parse().ok());
                a.interval = v.unwrap_or_else(|| usage()).max(2);
            }
            "-h" | "--help" => usage(),
            "-V" | "--version" => {
                println!("oph-agent {VERSION}");
                std::process::exit(0)
            }
            other => {
                eprintln!("unknown argument: {other}");
                usage()
            }
        }
    }
    a.server = server.unwrap_or_else(|| usage());
    a.token = token.unwrap_or_else(|| usage());
    let hex: String = fp.unwrap_or_else(|| usage()).chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 64 {
        eprintln!("--fingerprint must be a SHA-256 hex string (64 hex digits)");
        std::process::exit(2)
    }
    for i in 0..32 {
        a.fingerprint[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    if install {
        install_autostart();
        std::process::exit(0)
    }
    a
}

fn quote(a: &str) -> String {
    if a.contains(' ') {
        format!("\"{a}\"")
    } else {
        a.to_string()
    }
}

/// Register the agent to start automatically with the same arguments (minus --install).
fn install_autostart() {
    let exe = std::env::current_exe().expect("exe path");
    let raw: Vec<String> = expanded_args().into_iter().filter(|a| a != "--install").collect();
    let args: Vec<String> = raw.iter().map(|a| quote(a)).collect();
    let termux = std::env::var("PREFIX").map(|p| p.contains("com.termux")).unwrap_or(false);
    if cfg!(windows) {
        // keep the token out of the task definition and the command short: args go to a file
        let cfg = exe.with_file_name("oph-agent.cfg");
        if let Err(e) = std::fs::write(&cfg, raw.join("\n")) {
            eprintln!("Could not write {}: {e}", cfg.display());
            std::process::exit(1);
        }
        let tr = format!("\"{}\" --config \"{}\"", exe.display(), cfg.display());
        let st = std::process::Command::new("schtasks")
            .args(["/create", "/tn", "OPH-S Agent", "/tr", &tr, "/sc", "onlogon", "/rl", "limited", "/f"])
            .status();
        match st {
            Ok(s) if s.success() => println!("Installed: OPH-S Agent starts at logon. Remove with --uninstall."),
            _ => {
                eprintln!("Could not create the scheduled task (try an elevated prompt).");
                std::process::exit(1);
            }
        }
    } else if cfg!(target_os = "android") || termux {
        // Termux:Boot runs every script in ~/.termux/boot when the phone starts
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let dir = std::path::Path::new(&home).join(".termux/boot");
        let _ = std::fs::create_dir_all(&dir);
        let script = format!(
            "#!/data/data/com.termux/files/usr/bin/sh\ntermux-wake-lock\nexec \"{}\" {} >> \"$HOME/oph-agent.log\" 2>&1\n",
            exe.display(),
            args.join(" ")
        );
        let p = dir.join("oph-agent");
        if std::fs::write(&p, script).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
            }
            println!("Installed {} — install the Termux:Boot app and open it once to enable start at boot.", p.display());
        }
    } else {
        eprintln!("--install supports Windows and Android (Termux). On Linux, create a systemd user service.");
    }
}

fn uninstall() {
    if cfg!(windows) {
        let _ = std::process::Command::new("schtasks").args(["/delete", "/tn", "OPH-S Agent", "/f"]).status();
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let _ = std::fs::remove_file(std::path::Path::new(&home).join(".termux/boot/oph-agent"));
    }
    println!("OPH-S Agent autostart removed.");
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| if cfg!(target_os = "android") { "android".into() } else { "agent".into() })
}

fn platform() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

// ---------------------------------------------------------------- TLS pinning

#[derive(Debug)]
struct Pinned {
    fp: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let h = Sha256::digest(end_entity.as_ref());
        if h.as_slice() == self.fp {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server certificate fingerprint mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_connector(fp: [u8; 32]) -> tokio_rustls::TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { fp, provider }))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

// ---------------------------------------------------------------- collectors

fn ev(host: &str, source: &str, kind: &str, sev: &str, msg: String) -> WireEvent {
    let mut e = WireEvent::new(source, kind, sev, msg);
    e.host = host.to_string();
    e
}

async fn collect_connections(a: Args, tx: mpsc::Sender<WireEvent>) {
    let mut names = ProcessNames::new();
    let mut seen: HashMap<(String, String, u16), i64> = HashMap::new();
    let mut warned = false;
    loop {
        let conns = tokio::task::block_in_place(|| oph_proto::snapshot_connections(&mut names));
        if conns.is_empty() && !warned && cfg!(target_os = "android") {
            warned = true;
            let _ = tx
                .send(ev(&a.name, "agent", "agent.log", "low",
                    "Android blocks socket enumeration for non-root apps; connection monitoring is limited. Route the phone's DNS through OPH Sentinel to see its traffic.".into()))
                .await;
        }
        let now = now_ms();
        for c in conns {
            let key = (c.process.clone(), c.remote_ip.clone(), c.remote_port);
            if seen.get(&key).map(|t| now - t < 600_000).unwrap_or(false) {
                continue;
            }
            seen.insert(key, now);
            let mut e = ev(&a.name, "conn", "conn.open", "info",
                format!("{} → {}:{} ({})", c.process, c.remote_ip, c.remote_port, c.state));
            e.dst_ip = Some(c.remote_ip.clone());
            e.dst_port = Some(c.remote_port);
            e.process = Some(c.process.clone());
            e.raw = serde_json::json!({"proto": c.proto, "local": c.local, "pid": c.pid, "state": c.state});
            if tx.send(e).await.is_err() {
                return;
            }
        }
        seen.retain(|_, t| now - *t < 600_000);
        tokio::time::sleep(Duration::from_secs(a.interval)).await;
    }
}

#[cfg(windows)]
fn run_hidden(cmd: &str, args: &[&str]) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(cmd).args(args).creation_flags(CREATE_NO_WINDOW).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Polls Windows System/Application logs for Critical/Error/Warning entries.
#[cfg(windows)]
async fn collect_winlog(a: Args, tx: mpsc::Sender<WireEvent>) {
    let mut seen: VecDeque<String> = VecDeque::new();
    loop {
        for log in a.winlog_channels.iter().map(String::as_str) {
            let q = "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 120000]]]";
            let text = tokio::task::block_in_place(|| {
                run_hidden("wevtutil", &["qe", log, &format!("/q:{q}"), "/f:text", "/rd:true", "/c:50"])
            });
            let Some(text) = text else { continue };
            for block in text.split("Event[").skip(1) {
                let field = |name: &str| {
                    block.lines().find_map(|l| l.trim_start().strip_prefix(name).map(|v| v.trim().to_string()))
                };
                let source = field("Source:").unwrap_or_default();
                let id = field("Event ID:").unwrap_or_default();
                let date = field("Date:").unwrap_or_default();
                let level = field("Level:").unwrap_or_default();
                let key = format!("{log}|{source}|{id}|{date}");
                if seen.contains(&key) {
                    continue;
                }
                seen.push_back(key);
                if seen.len() > 500 {
                    seen.pop_front();
                }
                let desc = block
                    .split_once("Description:")
                    .map(|(_, d)| d.trim().lines().take(4).collect::<Vec<_>>().join(" "))
                    .unwrap_or_default();
                let sev = match level.as_str() {
                    "Critical" => "high",
                    "Error" => "medium",
                    _ => "low",
                };
                let mut e = ev(&a.name, "agent", "agent.log", sev, format!("[{log}] {source} {id}: {desc}"));
                e.process = Some(source.clone());
                e.raw = serde_json::json!({"channel": log, "provider": source, "event_id": id, "level": level, "date": date});
                if tx.send(e).await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Android logcat (warnings and above). In Termux grant access once from a PC:
/// `adb shell pm grant com.termux android.permission.READ_LOGS`
async fn collect_logcat(a: Args, tx: mpsc::Sender<WireEvent>) {
    loop {
        let child = tokio::process::Command::new("logcat")
            .args(["-v", "epoch", "-T", "1", "*:W"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let Ok(mut child) = child else {
            let _ = tx.send(ev(&a.name, "agent", "agent.log", "low", "logcat is not available on this device".into())).await;
            return;
        };
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // "  1731500000.123  1234  1250 W Tag: message"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let sev = match parts[3] {
                "F" | "A" => "high",
                "E" => "medium",
                _ => "low",
            };
            let rest = parts[4..].join(" ");
            let (tag, msg) = rest.split_once(':').map(|(t, m)| (t.trim().to_string(), m.trim().to_string())).unwrap_or((String::new(), rest.clone()));
            let mut e = ev(&a.name, "agent", "agent.log", sev, format!("{tag}: {msg}"));
            if let Ok(secs) = parts[0].parse::<f64>() {
                e.ts = (secs * 1000.0) as i64;
            }
            e.process = Some(tag.clone());
            e.raw = serde_json::json!({"channel": "logcat", "pid": parts[1], "tid": parts[2], "level": parts[3], "tag": tag});
            if tx.send(e).await.is_err() {
                return;
            }
        }
        let _ = child.kill().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn collect_tail(a: Args, path: String, tx: mpsc::Sender<WireEvent>) {
    let mut pos = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut partial = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if meta.len() < pos {
            pos = 0; // rotated / truncated
        }
        if meta.len() == pos {
            continue;
        }
        let read = tokio::task::block_in_place(|| -> std::io::Result<Vec<u8>> {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(&path)?;
            f.seek(SeekFrom::Start(pos))?;
            let mut buf = Vec::new();
            f.take(256 * 1024).read_to_end(&mut buf)?;
            Ok(buf)
        });
        let Ok(buf) = read else { continue };
        pos += buf.len() as u64;
        partial.push_str(&String::from_utf8_lossy(&buf));
        if partial.len() > 64 * 1024 && !partial.contains('\n') {
            partial.clear(); // a "line" this long is binary junk: drop it, keep memory bounded
        }
        while let Some(i) = partial.find('\n') {
            let line: String = partial.drain(..=i).collect();
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            let sev = if lower.contains("critical") || lower.contains("fatal") {
                "high"
            } else if lower.contains("error") || lower.contains("denied") || lower.contains("fail") {
                "medium"
            } else if lower.contains("warn") {
                "low"
            } else {
                "info"
            };
            let mut e = ev(&a.name, "agent", "agent.log", sev, line.to_string());
            e.raw = serde_json::json!({"channel": "file", "path": path});
            if tx.send(e).await.is_err() {
                return;
            }
        }
    }
}

// ---------------------------------------------------------------- shipping

async fn session(a: &Args, connector: &tokio_rustls::TlsConnector, buf: &mut VecDeque<WireEvent>, rx: &mut mpsc::Receiver<WireEvent>) -> Result<(), String> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(&a.server))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    tcp.set_nodelay(true).ok();
    let name = ServerName::try_from("oph-sentinel").unwrap();
    let tls = match connector.connect(name, tcp).await {
        Ok(t) => t,
        Err(e) if e.to_string().contains("fingerprint mismatch") => {
            eprintln!("The server certificate does not match --fingerprint. Either the fingerprint was mistyped or something is intercepting the connection. Copy the command again from the Agents page. Exiting.");
            std::process::exit(3);
        }
        Err(e) => return Err(format!("tls: {e}")),
    };
    let (r, mut w) = tokio::io::split(tls);
    let mut r = BufReader::new(r);
    let agent_id = {
        let h = Sha256::digest(format!("{}|{}", hostname(), a.name).as_bytes());
        h[..8].iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let hello = Frame::Hello {
        proto: PROTOCOL_VERSION,
        token: a.token.clone(),
        agent_id,
        name: a.name.clone(),
        platform: platform().into(),
        version: VERSION.into(),
    };
    send(&mut w, &hello).await?;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), r.read_line(&mut line)).await.map_err(|_| "no welcome".to_string())?.map_err(|e| e.to_string())?;
    match serde_json::from_str::<Frame>(&line) {
        Ok(Frame::Welcome { ok: true, .. }) => eprintln!("connected to {}", a.server),
        Ok(Frame::Welcome { error, .. }) => return Err(format!("rejected: {}", error.unwrap_or_default())),
        _ => return Err("bad welcome".into()),
    }
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut idle = 0u32;
    loop {
        tokio::select! {
            m = rx.recv() => match m {
                Some(e) => { push(buf, e); if buf.len() < MAX_BATCH { continue; } }
                None => return Ok(()),
            },
            _ = tick.tick() => {}
        }
        if buf.is_empty() {
            idle += 1;
            if idle >= 15 {
                idle = 0;
                send(&mut w, &Frame::Ping).await?;
            }
            continue;
        }
        idle = 0;
        // keep each frame well under the server's MAX_LINE (bytes) and MAX_BATCH (count)
        let mut n = 0;
        let mut bytes = 0;
        for e in buf.iter().take(MAX_BATCH) {
            let sz = e.approx_size();
            if n > 0 && bytes + sz > oph_proto::MAX_LINE / 2 {
                break;
            }
            bytes += sz;
            n += 1;
        }
        let events: Vec<WireEvent> = buf.iter().take(n).cloned().collect();
        send(&mut w, &Frame::Batch { events }).await?;
        line.clear();
        tokio::time::timeout(Duration::from_secs(15), r.read_line(&mut line)).await.map_err(|_| "ack timeout".to_string())?.map_err(|e| e.to_string())?;
        match serde_json::from_str::<Frame>(&line) {
            Ok(Frame::Ack { .. }) => {
                buf.drain(..n);
            }
            _ => return Err("bad ack".into()),
        }
    }
}

fn push(buf: &mut VecDeque<WireEvent>, mut e: WireEvent) {
    e.sanitize(); // same limits the server applies: no frame can exceed MAX_LINE
    if buf.len() >= BUFFER_CAP {
        buf.pop_front(); // bounded memory while offline: drop oldest
    }
    buf.push_back(e);
}

async fn send<W: AsyncWriteExt + Unpin>(w: &mut W, f: &Frame) -> Result<(), String> {
    let mut s = serde_json::to_string(f).map_err(|e| e.to_string())?;
    s.push('\n');
    w.write_all(s.as_bytes()).await.map_err(|e| e.to_string())?;
    w.flush().await.map_err(|e| e.to_string())
}

fn main() {
    #[cfg(windows)]
    unsafe {
        AttachConsole(u32::MAX); // ATTACH_PARENT_PROCESS; harmless when there is no parent console
    }
    let a = parse_args();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).max_blocking_threads(2).enable_all().build().expect("runtime");
    rt.block_on(async move {
        let (tx, mut rx) = mpsc::channel::<WireEvent>(1024);
        if a.conn {
            tokio::spawn(collect_connections(a.clone(), tx.clone()));
        }
        #[cfg(windows)]
        if a.winlog {
            tokio::spawn(collect_winlog(a.clone(), tx.clone()));
        }
        if a.logcat {
            tokio::spawn(collect_logcat(a.clone(), tx.clone()));
        }
        for t in a.tails.clone() {
            tokio::spawn(collect_tail(a.clone(), t, tx.clone()));
        }
        let mut start = ev(&a.name, "agent", "agent.log", "info", format!("oph-agent {VERSION} started on {}", platform()));
        start.raw = serde_json::json!({"conn": a.conn, "winlog": a.winlog, "logcat": a.logcat, "tails": a.tails});
        let _ = tx.send(start).await;
        drop(tx);
        let connector = tls_connector(a.fingerprint);
        let mut buf = VecDeque::new();
        let mut backoff = 5u64;
        loop {
            let began = std::time::Instant::now();
            match session(&a, &connector, &mut buf, &mut rx).await {
                Ok(()) => return,
                Err(e) => eprintln!("session ended: {e}; retrying in {backoff}s ({} events buffered)", buf.len()),
            }
            if began.elapsed() > Duration::from_secs(60) {
                backoff = 5; // the link was healthy for a while: start over
            }
            // keep collecting while offline
            let deadline = tokio::time::Instant::now() + Duration::from_secs(backoff);
            loop {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(e)) => push(&mut buf, e),
                    Ok(None) => { tokio::time::sleep_until(deadline).await; break; }
                    Err(_) => break,
                }
            }
            backoff = (backoff * 2).min(60);
        }
    });
}
