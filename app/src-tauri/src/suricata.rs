//! Suricata IDS integration. OPH Sentinel does not ship its own detection
//! engine: it tails Suricata's standard EVE JSON log (eve.json) and turns
//! `alert` records into events + alerts, so the community / ET Open rulesets
//! (60k+ signatures maintained by the Suricata ecosystem) do the detection.

use crate::core::Core;
use oph_proto::WireEvent;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::time::Duration;

pub fn run(core: Arc<Core>) {
    std::thread::Builder::new()
        .name("oph-suricata".into())
        .spawn(move || {
            let mut pos: Option<u64> = None;
            let mut current = String::new();
            let mut partial = String::new();
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let path = core.settings.read().unwrap().suricata_eve_path.clone();
                if path.is_empty() {
                    continue;
                }
                if path != current {
                    current = path.clone();
                    pos = None;
                    partial.clear();
                }
                let Ok(meta) = std::fs::metadata(&path) else { continue };
                let p = pos.get_or_insert(meta.len()); // start at the end: only new alerts
                if meta.len() < *p {
                    *p = 0; // rotated
                }
                if meta.len() == *p {
                    continue;
                }
                let Ok(mut f) = std::fs::File::open(&path) else { continue };
                if f.seek(SeekFrom::Start(*p)).is_err() {
                    continue;
                }
                let mut buf = Vec::new();
                let _ = f.by_ref().take(4 * 1024 * 1024).read_to_end(&mut buf);
                *p += buf.len() as u64;
                partial.push_str(&String::from_utf8_lossy(&buf));
                if partial.len() > 1024 * 1024 && !partial.contains('\n') {
                    partial.clear(); // not EVE JSON: never let the buffer grow without bound
                }
                let mut lines: Vec<String> = Vec::new();
                while let Some(i) = partial.find('\n') {
                    lines.push(partial.drain(..=i).collect());
                }
                for l in lines {
                    if let Some(e) = parse_eve(&l) {
                        core.emit(e);
                    }
                }
            }
        })
        .expect("spawn suricata tail");
}

pub fn parse_eve(line: &str) -> Option<WireEvent> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if v["event_type"] != "alert" {
        return None;
    }
    let a = &v["alert"];
    let sig = a["signature"].as_str().unwrap_or("Unknown signature").to_string();
    let sev = match a["severity"].as_i64().unwrap_or(3) {
        1 => "high",
        2 => "medium",
        _ => "low",
    };
    let src = v["src_ip"].as_str().map(String::from);
    let mut e = WireEvent::new("ids", "ids.alert", sev, sig);
    e.host = src.clone().unwrap_or_else(|| "network".into());
    e.src_ip = src;
    e.dst_ip = v["dest_ip"].as_str().map(String::from);
    e.dst_port = v["dest_port"].as_u64().map(|p| p as u16);
    e.domain = v["dns"]["rrname"].as_str().or(v["http"]["hostname"].as_str()).or(v["tls"]["sni"].as_str()).map(String::from);
    e.process = Some("suricata".into());
    e.raw = serde_json::json!({
        "signature_id": a["signature_id"], "category": a["category"], "action": a["action"], "proto": v["proto"],
        "src_port": v["src_port"], "flow_id": v["flow_id"], "app_proto": v["app_proto"]
    });
    Some(e)
}

#[cfg(test)]
mod tests {
    #[test]
    fn eve_alert() {
        let l = r#"{"timestamp":"2026-11-14T10:00:00","event_type":"alert","src_ip":"192.168.1.20","dest_ip":"1.2.3.4","dest_port":443,"proto":"TCP","alert":{"signature":"ET MALWARE Test","signature_id":1,"severity":1,"category":"A Network Trojan was detected"},"tls":{"sni":"bad.example"}}"#;
        let e = super::parse_eve(l).unwrap();
        assert_eq!(e.severity, "high");
        assert_eq!(e.domain.as_deref(), Some("bad.example"));
        assert!(super::parse_eve(r#"{"event_type":"flow"}"#).is_none());
    }
}
