use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// "warn" = alert only, "block" = sinkhole / firewall automatically.
    pub mode: String,
    pub dns_enabled: bool,
    pub dns_bind: String,
    pub dns_upstream: String,
    pub ingest_enabled: bool,
    pub ingest_port: u16,
    pub retention_days: u32,
    pub notifications: bool,
    pub intel_interval_hours: u32,
    pub abuse_ch_key: String,
    pub suricata_eve_path: String,
    pub cleaner_schedule: String,
    pub autostart: bool,
    /// Watch this PC's Windows DNS cache for dangerous domains (works without router changes).
    pub watch_local_dns: bool,
    /// Standard syslog intake (RFC 3164/5424 over UDP) for routers, NAS, Fluent Bit, rsyslog…
    pub syslog_enabled: bool,
    pub syslog_port: u16,
    /// Event-log capacity cap in MB (oldest events are dropped first).
    pub max_store_mb: u64,
    /// Preferred event-log folder, e.g. on the external 2 TB drive.
    pub storage_primary: String,
    /// Volume GUID path of the primary drive, so it is found even if its letter changes.
    pub storage_primary_serial: String,
    /// Used while the primary drive is missing; merged back when it returns.
    pub storage_fallback: String,
    pub icon_style: String,
    /// Record DNS lookups / connections and raise alerts from them (DNS keeps resolving when off).
    pub network_monitoring: bool,
    /// File integrity monitoring of important folders.
    pub fim_enabled: bool,
    /// Folders to watch; empty = built-in defaults.
    pub fim_paths: Vec<String>,
    /// Named searches for the Search page.
    pub saved_searches: Vec<SavedSearch>,
    /// Ask AI: "anthropic" (Claude) or "openai" (any OpenAI-compatible endpoint, incl. Ollama)
    pub ai_provider: String,
    pub ai_model: String,
    pub ai_base_url: String,
    /// mask private IPs / MACs before sending log context to the AI
    pub ai_redact: bool,
    /// Leak Check: minutes of silence before an online device counts as "went quiet" (2 = demo)
    pub leak_quiet_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SavedSearch {
    pub name: String,
    pub query: String,
    #[serde(default)]
    pub range: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            mode: "warn".into(),
            dns_enabled: true,
            dns_bind: "0.0.0.0:53".into(),
            dns_upstream: "1.1.1.1:53".into(),
            ingest_enabled: true,
            ingest_port: 8443,
            retention_days: 7,
            notifications: true,
            intel_interval_hours: 6,
            abuse_ch_key: String::new(),
            suricata_eve_path: String::new(),
            cleaner_schedule: "off".into(),
            autostart: false,
            watch_local_dns: true,
            syslog_enabled: true,
            syslog_port: 5514,
            max_store_mb: 20_480,
            storage_primary: String::new(),
            storage_primary_serial: String::new(),
            storage_fallback: String::new(),
            icon_style: "op-shield".into(),
            network_monitoring: true,
            fim_enabled: true,
            fim_paths: Vec::new(),
            saved_searches: Vec::new(),
            ai_provider: "anthropic".into(),
            ai_model: crate::ai::DEFAULT_CLAUDE_MODEL.into(),
            ai_base_url: "https://api.openai.com/v1".into(),
            ai_redact: false,
            leak_quiet_minutes: 60,
        }
    }
}

impl Settings {
    pub fn load(dir: &Path) -> Settings {
        std::fs::read_to_string(dir.join("settings.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<Settings>(&s).ok())
            .unwrap_or_default()
            .validated()
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let tmp = dir.join("settings.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dir.join("settings.json")).map_err(|e| e.to_string())
    }
    pub fn validated(mut self) -> Settings {
        if self.mode != "block" {
            self.mode = "warn".into();
        }
        if !["off", "daily", "weekly"].contains(&self.cleaner_schedule.as_str()) {
            self.cleaner_schedule = "off".into();
        }
        if self.dns_bind.parse::<std::net::SocketAddr>().is_err() {
            self.dns_bind = "0.0.0.0:53".into();
        }
        if self.dns_upstream.parse::<std::net::SocketAddr>().is_err() {
            self.dns_upstream = "1.1.1.1:53".into();
        }
        if self.ingest_port < 1024 {
            self.ingest_port = 8443;
        }
        if self.syslog_port == 0 {
            self.syslog_port = 5514;
        }
        self.retention_days = self.retention_days.clamp(1, 365);
        self.max_store_mb = self.max_store_mb.clamp(256, 2_000_000);
        self.fim_paths.retain(|p| !p.trim().is_empty() && !p.contains(".."));
        self.fim_paths.truncate(32);
        self.saved_searches.retain(|s| !s.name.trim().is_empty() && s.query.len() <= 2000);
        self.saved_searches.truncate(100);
        self.leak_quiet_minutes = self.leak_quiet_minutes.clamp(2, 1440);
        if self.ai_provider != "openai" {
            self.ai_provider = "anthropic".into();
        }
        self.ai_model = self.ai_model.trim().chars().filter(|c| !c.is_control()).take(100).collect();
        let base = self.ai_base_url.trim().trim_end_matches('/').to_string();
        self.ai_base_url = if base.starts_with("https://") || base.starts_with("http://") { base } else { "https://api.openai.com/v1".into() };
        const ICONS: [&str; 6] = ["op-shield", "op-radar", "op-hex", "op-eye", "op-bracket", "op-orbit"];
        if !ICONS.contains(&self.icon_style.as_str()) {
            self.icon_style = "op-shield".into();
        }
        for p in [&mut self.storage_primary, &mut self.storage_fallback] {
            *p = p.trim().trim_end_matches(['\\', '/']).to_string();
            if p.contains("..") {
                p.clear();
            }
        }
        self.intel_interval_hours = self.intel_interval_hours.clamp(1, 168);
        self.abuse_ch_key = self.abuse_ch_key.trim().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        self
    }
    pub fn block_mode(&self) -> bool {
        self.mode == "block"
    }
}

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("XDG_DATA_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    let d = base.join("OPHSentinel");
    let _ = std::fs::create_dir_all(d.join("feeds"));
    let _ = std::fs::create_dir_all(d.join("quarantine"));
    d
}
