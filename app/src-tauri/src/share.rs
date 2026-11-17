//! Temporary LAN download point for the Android APK and the Windows agent, so a
//! phone can install OPH-S by scanning a QR code. Plain HTTP (phones reject
//! self-signed TLS for downloads), LAN clients only, two fixed files, read-only,
//! and it switches itself off after 15 minutes. Integrity is protected by the
//! SHA-256 shown in the app / checked by the install command.

use crate::core::Core;
use oph_proto::now_ms;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const PORT: u16 = 8099;
const TTL_MS: i64 = 15 * 60_000;
static EXPIRES: AtomicI64 = AtomicI64::new(0);
static TASK: Mutex<Option<tauri::async_runtime::JoinHandle<()>>> = Mutex::new(None);

/// Where the shipped files are: next to the exe (installed), its resources folder,
/// or the repository's dist/target folders (development).
pub fn find(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.to_path_buf();
    let mut c = vec![dir.join(name), dir.join("resources").join(name)];
    let mut up = Some(dir.as_path());
    for _ in 0..4 {
        if let Some(u) = up {
            c.push(u.join("dist").join(name));
            c.push(u.join("target").join("release").join(name));
            up = u.parent();
        }
    }
    c.into_iter().find(|p| p.is_file())
}

pub fn sha256_of(name: &str) -> Option<String> {
    let bytes = std::fs::read(find(name)?).ok()?;
    Some(Sha256::digest(&bytes).iter().map(|b| format!("{b:02X}")).collect())
}

pub fn active() -> Option<i64> {
    let e = EXPIRES.load(Ordering::Relaxed);
    (e > now_ms()).then_some(e)
}

pub fn url(core: &Core, file: &str) -> Option<String> {
    active()?;
    let ip = core.net.lock().unwrap().local_ip.clone()?;
    Some(format!("http://{ip}:{PORT}/{file}"))
}

pub fn set(core: &Arc<Core>, enable: bool) -> Result<(), String> {
    let mut t = TASK.lock().unwrap();
    if let Some(h) = t.take() {
        h.abort();
    }
    EXPIRES.store(0, Ordering::Relaxed);
    if !enable {
        return Ok(());
    }
    let std_listener = std::net::TcpListener::bind(("0.0.0.0", PORT)).map_err(|e| format!("port {PORT} unavailable: {e}"))?;
    std_listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    EXPIRES.store(now_ms() + TTL_MS, Ordering::Relaxed);
    let core = core.clone();
    *t = Some(tauri::async_runtime::spawn(async move {
        let Ok(listener) = tokio::net::TcpListener::from_std(std_listener) else { return };
        core.sys("system.start", "info", format!("Sharing OPH-S downloads on the LAN (port {PORT}) for 15 minutes"));
        loop {
            if active().is_none() {
                return;
            }
            let accept = tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await;
            let Ok(Ok((mut s, peer))) = accept else { continue };
            let ip = peer.ip();
            let lan = match ip {
                std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
                std::net::IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00,
            };
            if !lan {
                continue;
            }
            let core = core.clone();
            tokio::spawn(async move {
                let mut req = vec![0u8; 2048];
                let n = match tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut req)).await {
                    Ok(Ok(n)) => n,
                    _ => return,
                };
                let head = String::from_utf8_lossy(&req[..n]);
                let path = head.split_whitespace().nth(1).unwrap_or("/");
                let (file, ctype) = match path {
                    "/OPH-S.apk" => ("OPH-S.apk", "application/vnd.android.package-archive"),
                    "/oph-agent.exe" => ("oph-agent.exe", "application/vnd.microsoft.portable-executable"),
                    _ => {
                        let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                        return;
                    }
                };
                let Some(p) = find(file) else {
                    let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    return;
                };
                let Ok(body) = tokio::fs::read(&p).await else { return };
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nContent-Disposition: attachment; filename=\"{file}\"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if s.write_all(hdr.as_bytes()).await.is_ok() && s.write_all(&body).await.is_ok() {
                    let mut e = oph_proto::WireEvent::new("agent", "agent.log", "info", format!("{file} downloaded by {ip}"));
                    e.host = "this-pc".into();
                    e.src_ip = Some(ip.to_string());
                    core.emit(e);
                }
            });
        }
    }));
    Ok(())
}
