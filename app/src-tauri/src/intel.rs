//! Threat intelligence: downloads public blocklists, keeps them in a compact
//! in-memory index (8-byte hashes, sorted — ~9 bytes per entry), matches
//! domains (with parent-domain suffix matching), IPv4 addresses and CIDRs.

use oph_proto::now_ms;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::Path;

pub struct FeedDef {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub kind: &'static str, // domains | urls | ips | cidr | oui
    pub category: &'static str,
    pub severity: &'static str,
    pub default_enabled: bool,
    pub needs_key: bool,
}

/// Feed URLs verified on 2026-11-14. URLhaus moved its exports behind a free
/// abuse.ch Auth-Key in 2025; the old /downloads/ endpoints return 410 Gone.
pub const FEEDS: &[FeedDef] = &[
    FeedDef { id: "phishdb", name: "Phishing.Database — active phishing domains", url: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", kind: "domains", category: "phishing", severity: "high", default_enabled: true, needs_key: false },
    FeedDef { id: "openphish", name: "OpenPhish Community — phishing URLs", url: "https://openphish.com/feed.txt", kind: "urls", category: "phishing", severity: "high", default_enabled: true, needs_key: false },
    FeedDef { id: "feodo", name: "abuse.ch Feodo Tracker — botnet C2 servers", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", kind: "ips", category: "botnet", severity: "critical", default_enabled: true, needs_key: false },
    FeedDef { id: "spamhaus_drop", name: "Spamhaus DROP — hijacked networks", url: "https://www.spamhaus.org/drop/drop_v4.json", kind: "cidr", category: "hijacked", severity: "high", default_enabled: true, needs_key: false },
    FeedDef { id: "urlhaus", name: "abuse.ch URLhaus — malware distribution", url: "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv", kind: "urls", category: "malware", severity: "critical", default_enabled: false, needs_key: true },
    FeedDef { id: "pd", name: "PD — OISD NSFW adult-site list (for the PD search filter, never alerts)", url: "https://nsfw.oisd.nl/domainswild", kind: "domains", category: "adult", severity: "info", default_enabled: true, needs_key: false },
    FeedDef { id: "vpn", name: "VPN — hagezi DoH/VPN/Proxy bypass list (for the VPN search filter, never alerts)", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt", kind: "domains", category: "vpn", severity: "info", default_enabled: true, needs_key: false },
    FeedDef { id: "tranco", name: "Tranco top sites — false-positive guard (entries on the 20,000 most-used sites are ignored)", url: "https://tranco-list.eu/top-1m.csv.zip", kind: "popular", category: "reference", severity: "info", default_enabled: true, needs_key: false },
    FeedDef { id: "oui", name: "IEEE OUI — device manufacturer database", url: "https://standards-oui.ieee.org/oui/oui.csv", kind: "oui", category: "reference", severity: "info", default_enabled: true, needs_key: false },
];

/// Hosts shared by millions of users. URL feeds frequently list a single
/// malicious *path* on these; flagging the whole host would be a false positive.
const SHARED_HOSTS: &[&str] = &[
    "google.com", "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "goo.gl",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "googleusercontent.com", "translate.goog",
    "dropbox.com", "dl.dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "live.com", "microsoft.com",
    "sharepoint.com", "github.com", "raw.githubusercontent.com", "gitlab.com", "bit.ly", "t.co", "tinyurl.com",
    "linkedin.com", "facebook.com", "instagram.com", "t.me", "telegram.org", "discord.com", "cdn.discordapp.com",
    "ipfs.io", "cloudflare-ipfs.com", "blogspot.com", "wixsite.com", "weebly.com", "pages.dev", "workers.dev",
    "vercel.app", "netlify.app", "web.app", "firebaseapp.com", "amazonaws.com", "s3.amazonaws.com",
    "notion.site", "canva.com", "office.com", "wordpress.com", "medium.com", "youtube.com", "apple.com",
    "telegra.ph", "dweb.link", "ipfs.dweb.link", "w3s.link", "nftstorage.link", "r2.dev", "glitch.me",
    "github.io", "gitbook.io", "herokuapp.com", "azurewebsites.net", "blob.core.windows.net", "web.core.windows.net",
    "cloudfront.net", "appspot.com", "googleapis.com", "sharepoint.com", "my.sharepoint.com", "jimdosite.com",
    "webflow.io", "framer.app", "carrd.co", "square.site", "mailchimpsites.com", "typeform.com", "jotform.com",
    "formstack.com", "surveymonkey.com", "zoho.com", "hubspot.com", "hs-sites.com", "000webhostapp.com",
    "replit.app", "repl.co", "onrender.com", "fly.dev", "railway.app", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
];

/// True when blocking `d` would hit a whole shared platform rather than one site:
/// the name is a public suffix (Mozilla Public Suffix List, incl. private section
/// such as s3.amazonaws.com / blogspot.com) or a known multi-tenant host.
pub fn is_shared_root(d: &str) -> bool {
    let bare = d.strip_prefix("www.").unwrap_or(d);
    SHARED_HOSTS.contains(&bare) || psl::suffix_str(bare) == Some(bare)
}

/// Total entries across every index: one function for both sides of the per-feed count
/// (two hand-written sums drifted apart once and mis-counted the VPN/Tranco/OUI feeds).
fn size(it: &Intel, doms: &[(u64, u8)], ips: &[(u32, u8)]) -> usize {
    doms.len() + ips.len() + it.cidr.len() + it.oui.len() + it.adult.len() + it.vpn.len() + it.popular
}

/// A popular site with at least this many different listed subdomains is treated as a hosting
/// platform (user content) rather than a first-party service.
const PLATFORM_MIN_HOSTS: usize = 6;

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[derive(Default)]
pub struct Intel {
    dom_hash: Vec<u64>,
    dom_feed: Vec<u8>,
    ip: Vec<u32>,
    ip_feed: Vec<u8>,
    cidr: Vec<(u32, u32, u8)>, // network, mask, feed
    oui: std::collections::HashMap<u32, Box<str>>,
    pub counts: Vec<(String, usize)>,
    /// adult-content domains (PD search filter); kept apart so they never raise threat alerts
    pub adult: Vec<u64>,
    /// VPN / proxy / encrypted-DNS service domains (VPN search filter; never alerts)
    pub vpn: Vec<u64>,
    /// number of popular registrable domains in the false-positive guard
    pub popular: usize,
    /// feed entries ignored because they name a shared platform (false-positive guard)
    pub guarded: usize,
}

pub struct Hit {
    pub feed: &'static FeedDef,
}

impl Intel {
    pub fn total(&self) -> usize {
        self.dom_hash.len() + self.ip.len() + self.cidr.len()
    }

    pub fn match_domain(&self, domain: &str) -> Option<Hit> {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut cur = d.as_str();
        loop {
            let h = fnv1a(cur);
            if let Ok(i) = self.dom_hash.binary_search(&h) {
                return Some(Hit { feed: &FEEDS[self.dom_feed[i] as usize] });
            }
            match cur.find('.') {
                Some(i) if cur[i + 1..].contains('.') => cur = &cur[i + 1..],
                _ => return None,
            }
        }
    }

    /// PD: is this name (or a parent domain) on the adult-content list?
    pub fn is_adult(&self, domain: &str) -> bool {
        is_adult_in(&self.adult, domain)
    }

    pub fn match_ip(&self, ip: &str) -> Option<Hit> {
        let a: Ipv4Addr = ip.parse().ok()?;
        let n = u32::from(a);
        if let Ok(i) = self.ip.binary_search(&n) {
            return Some(Hit { feed: &FEEDS[self.ip_feed[i] as usize] });
        }
        // cidr list is small (~1.5k); linear scan is fine
        self.cidr.iter().find(|(net, mask, _)| n & mask == *net).map(|(_, _, f)| Hit { feed: &FEEDS[*f as usize] })
    }

    pub fn vendor(&self, mac: &str) -> Option<&str> {
        let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).take(6).collect();
        let k = u32::from_str_radix(&hex, 16).ok()?;
        self.oui.get(&k).map(|s| &**s)
    }

    /// Rebuild the index from cached feed files. Runs on a background thread.
    pub fn build(dir: &Path, enabled: &dyn Fn(&str) -> bool) -> Intel {
        let mut doms: Vec<(u64, u8)> = Vec::new();
        let mut ips: Vec<(u32, u8)> = Vec::new();
        let mut it = Intel::default();
        // Popular-site guard (Maltrail-style): a threat-feed entry whose registrable domain is one of
        // the most-used sites (instagram.com, yandex.ru, ...) is a list artefact — link shims,
        // analytics, CDNs — and is never used as a block root.
        let popular: std::collections::HashSet<u64> = if enabled("tranco") {
            std::fs::read_to_string(dir.join("feeds").join("tranco.txt"))
                .map(|t| t.lines().map(|l| fnv1a(l.trim())).collect())
                .unwrap_or_default()
        } else {
            Default::default()
        };
        let is_popular = |d: &str| !popular.is_empty() && popular.contains(&fnv1a(psl::domain_str(d).unwrap_or(d)));
        // entries on popular sites are decided after all feeds are read (see below)
        let mut popular_hits: Vec<(String, u8)> = Vec::new();
        for (fi, f) in FEEDS.iter().enumerate() {
            if !enabled(f.id) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(dir.join("feeds").join(format!("{}.txt", f.id))) else { continue };
            let before = size(&it, &doms, &ips);
            match f.kind {
                "domains" if f.category == "vpn" => {
                    for d in text.lines().filter_map(parse_domain_line) {
                        it.vpn.push(fnv1a(&d));
                    }
                }
                "domains" if f.category == "adult" => {
                    for d in text.lines().filter_map(parse_domain_line) {
                        if !is_shared_root(&d) {
                            it.adult.push(fnv1a(&d));
                        }
                    }
                }
                "domains" => {
                    for d in text.lines().filter_map(parse_domain_line) {
                        if is_shared_root(&d) {
                            it.guarded += 1;
                        } else if is_popular(&d) {
                            popular_hits.push((d, fi as u8));
                        } else {
                            doms.push((fnv1a(&d), fi as u8));
                        }
                    }
                }
                "urls" => {
                    for d in text.lines().filter_map(host_from_url) {
                        if let Ok(ip) = d.parse::<Ipv4Addr>() {
                            ips.push((u32::from(ip), fi as u8));
                        } else if is_shared_root(&d) {
                            it.guarded += 1;
                        } else if is_popular(&d) {
                            popular_hits.push((d, fi as u8));
                        } else {
                            doms.push((fnv1a(&d), fi as u8));
                        }
                    }
                }
                "ips" => {
                    for l in text.lines() {
                        let t = l.split(['#', ',', ' ', '\t', ';']).next().unwrap_or("").trim();
                        if let Ok(ip) = t.parse::<Ipv4Addr>() {
                            ips.push((u32::from(ip), fi as u8));
                        }
                    }
                }
                "cidr" => {
                    for l in text.lines() {
                        let c = if l.trim_start().starts_with('{') {
                            serde_json::from_str::<serde_json::Value>(l).ok().and_then(|v| v["cidr"].as_str().map(String::from))
                        } else {
                            l.split([';', ' ', '#']).next().map(|s| s.trim().to_string())
                        };
                        if let Some((net, len)) = c.as_deref().and_then(|c| c.split_once('/')) {
                            if let (Ok(ip), Ok(len)) = (net.parse::<Ipv4Addr>(), len.parse::<u32>()) {
                                if (8..=32).contains(&len) {
                                    let mask = if len == 32 { u32::MAX } else { !(u32::MAX >> len) };
                                    it.cidr.push((u32::from(ip) & mask, mask, fi as u8));
                                }
                            }
                        }
                    }
                }
                "popular" => {
                    it.popular = popular.len();
                }
                "oui" => {
                    // Registry,Assignment,Organization Name,Organization Address
                    for l in text.lines().skip(1) {
                        let mut cols = csv_cols(l);
                        if cols.len() >= 3 {
                            if let Ok(k) = u32::from_str_radix(&cols[1], 16) {
                                it.oui.insert(k, std::mem::take(&mut cols[2]).into_boxed_str());
                            }
                        }
                    }
                }
                _ => {}
            }
            let after = size(&it, &doms, &ips);
            it.counts.push((f.id.to_string(), after - before));
        }
        // Popular site, many different listed subdomains (weebly.com, godaddysites.com, ...): a hosting
        // platform whose customers' pages can be phishing -> keep the entries. Popular site with only a
        // handful listed (l.instagram.com link shim, mc.yandex.ru analytics) -> list artefact -> ignore.
        {
            let mut per_site: std::collections::HashMap<String, std::collections::HashSet<&str>> = std::collections::HashMap::new();
            for (d, _) in &popular_hits {
                let reg = psl::domain_str(d).unwrap_or(d).to_string();
                per_site.entry(reg).or_default().insert(d.as_str());
            }
            for (d, fi) in &popular_hits {
                let reg = psl::domain_str(d).unwrap_or(d);
                let platform = per_site.get(reg).map(|s| s.len() >= PLATFORM_MIN_HOSTS).unwrap_or(false);
                if platform && d.as_str() != reg {
                    doms.push((fnv1a(d), *fi));
                    // count it for its feed (feed counts were taken before this second pass)
                    if let Some(c) = it.counts.iter_mut().find(|(id, _)| id == FEEDS[*fi as usize].id) {
                        c.1 += 1;
                    }
                } else {
                    it.guarded += 1;
                }
            }
        }
        it.vpn.sort_unstable();
        it.vpn.dedup();
        it.vpn.shrink_to_fit();
        it.adult.sort_unstable();
        it.adult.dedup();
        it.adult.shrink_to_fit();
        doms.sort_unstable_by_key(|x| x.0);
        doms.dedup_by_key(|x| x.0);
        ips.sort_unstable_by_key(|x| x.0);
        ips.dedup_by_key(|x| x.0);
        it.dom_hash = doms.iter().map(|x| x.0).collect();
        it.dom_feed = doms.iter().map(|x| x.1).collect();
        it.ip = ips.iter().map(|x| x.0).collect();
        it.ip_feed = ips.iter().map(|x| x.1).collect();
        it.oui.shrink_to_fit();
        it
    }
}

pub fn is_adult_in(set: &[u64], domain: &str) -> bool {
    if set.is_empty() {
        return false;
    }
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    let mut cur = d.as_str();
    loop {
        if set.binary_search(&fnv1a(cur)).is_ok() {
            return true;
        }
        match cur.find('.') {
            Some(i) if cur[i + 1..].contains('.') => cur = &cur[i + 1..],
            _ => return false,
        }
    }
}

/// Snapshot of the VPN index for the SQL function `vpn(domain, dst_port, process)`.
pub static VPN_INDEX: std::sync::RwLock<Option<std::sync::Arc<Vec<u64>>>> = std::sync::RwLock::new(None);

/// Ports used only by VPN protocols: PPTP 1723, OpenVPN 1194, L2TP 1701, IPsec IKE 500 / NAT-T 4500,
/// WireGuard 51820, Tailscale 41641.
pub const VPN_PORTS: &[i64] = &[1723, 1194, 1701, 500, 4500, 51820, 41641];

/// VPN client programs (Windows process names, lower-case, without .exe) and Android app hints.
const VPN_PROCESSES: &[&str] = &[
    "openvpn", "openvpn-gui", "openvpnserv", "wireguard", "wg", "nordvpn", "nordvpn-service", "expressvpn", "expressvpnd",
    "protonvpn", "protonvpnservice", "mullvad-daemon", "mullvad-vpn", "surfshark", "surfshark.service", "windscribe",
    "windscribeservice", "tailscaled", "tailscale-ipn", "warp-svc", "cloudflare warp", "zerotier-one", "zerotier_desktop_ui",
    "hotspotshield", "hsscp", "cyberghost", "psiphon3", "tunnelbear", "hola", "hola_svc", "pia-service", "pia-client",
    "ivpn-service", "privadovpn", "hide.me", "vyprvpn", "softether", "vpnclient", "forticlient", "fortisslvpn", "pangps",
    "vpnagent", "vpnui", "nmcli", "outline", "lantern", "1.1.1.1",
];

/// Is this event VPN-related? domain on the VPN list, a VPN-only port, or a VPN client process/app.
pub fn is_vpn(set: &[u64], domain: Option<&str>, port: Option<i64>, process: Option<&str>) -> bool {
    if let Some(p) = port {
        if VPN_PORTS.contains(&p) {
            return true;
        }
    }
    if let Some(pr) = process {
        let p = pr.to_ascii_lowercase();
        let base = p.trim_end_matches(".exe");
        if base.contains("vpn") || VPN_PROCESSES.contains(&base) {
            return true;
        }
    }
    if let Some(d) = domain {
        return is_adult_in(set, d); // same suffix-walk lookup, different set
    }
    false
}

/// Snapshot of the PD index for the SQL function `pd(domain)` (search works on old logs too).
pub static PD_INDEX: std::sync::RwLock<Option<std::sync::Arc<Vec<u64>>>> = std::sync::RwLock::new(None);

fn csv_cols(l: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut q = false;
    for c in l.chars() {
        match c {
            '"' => q = !q,
            ',' if !q => out.push(String::new()),
            c => out.last_mut().unwrap().push(c),
        }
    }
    out
}

pub fn valid_domain(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

fn parse_domain_line(l: &str) -> Option<String> {
    let l = l.split('#').next()?.trim();
    if l.is_empty() {
        return None;
    }
    // accept "domain", "0.0.0.0 domain" and "127.0.0.1 domain"
    let d = l.split_whitespace().last()?.trim_start_matches("*.").trim_start_matches("||").trim_end_matches('^').trim_end_matches('.').to_ascii_lowercase();
    (valid_domain(&d) && d != "localhost").then_some(d)
}

pub fn host_from_url(l: &str) -> Option<String> {
    let i = l.find("://")?;
    let rest = &l[i + 3..];
    let end = rest.find(['/', ':', '?', '#', '"', ',', ' ']).unwrap_or(rest.len());
    let host = rest[..end].rsplit('@').next()?.trim_end_matches('.').to_ascii_lowercase();
    (valid_domain(&host) || host.parse::<Ipv4Addr>().is_ok()).then_some(host)
}

/// Download one feed into the cache directory (blocking; call from a worker thread).
pub fn download(dir: &Path, f: &FeedDef, key: &str) -> Result<usize, String> {
    if f.needs_key && key.is_empty() {
        return Err("Requires a free abuse.ch Auth-Key (Settings → Threat intel)".into());
    }
    let url = f.url.replace("{key}", key);
    let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(90)).build();
    let resp = agent
        .get(&url)
        .set("User-Agent", "OPH-Sentinel/0.1 (+threat-feed-sync)")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("HTTP {code} from feed server"),
            other => format!("download failed: {}", other.kind()),
        })?;
    let mut body = Vec::new();
    resp.into_reader().take(64 * 1024 * 1024).read_to_end(&mut body).map_err(|e| e.to_string())?;
    if f.kind == "popular" {
        body = tranco_top(&body, 20_000)?;
    }
    if body.len() < 16 {
        return Err("feed returned an empty file".into());
    }
    let text = String::from_utf8_lossy(&body);
    if text.trim_start().starts_with("<!") || text.trim_start().starts_with("<html") {
        return Err("feed returned an HTML page instead of a list".into());
    }
    let path = dir.join("feeds").join(format!("{}.txt", f.id));
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(text.lines().count())
}

/// Unzip the Tranco list ("rank,domain" per line) and keep the top `n` registrable domains.
fn tranco_top(zip_bytes: &[u8], n: usize) -> Result<Vec<u8>, String> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).map_err(|e| format!("Tranco zip: {e}"))?;
    let mut f = z.by_index(0).map_err(|e| format!("Tranco zip: {e}"))?;
    let mut csv = String::new();
    f.by_ref().take(64 * 1024 * 1024).read_to_string(&mut csv).map_err(|e| e.to_string())?;
    let mut seen = std::collections::HashSet::new();
    let mut out = String::new();
    for line in csv.lines() {
        let Some(d) = line.split(',').nth(1) else { continue };
        let d = d.trim().to_ascii_lowercase();
        let reg = psl::domain_str(&d).unwrap_or(&d).to_string();
        if valid_domain(&reg) && seen.insert(reg.clone()) {
            out.push_str(&reg);
            out.push('\n');
            if seen.len() >= n {
                break;
            }
        }
    }
    if seen.len() < 1000 {
        return Err("Tranco list looked empty".into());
    }
    Ok(out.into_bytes())
}

pub fn feed_cache_age(dir: &Path, id: &str) -> Option<i64> {
    let m = std::fs::metadata(dir.join("feeds").join(format!("{id}.txt"))).ok()?;
    let t = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as i64;
    Some(now_ms() - t)
}

/// Plain-language explanation for an alert, by category.
pub fn explain(category: &str, indicator: &str, feed: &str, host: &str) -> String {
    let what = match category {
        "phishing" => format!("{indicator} is listed by {feed} as a phishing site. Phishing pages imitate real services (banks, email, delivery, social networks) to steal passwords, codes or card details."),
        "malware" => format!("{indicator} is listed by {feed} as distributing malware. Visiting it can download harmful files or exploit the browser."),
        "botnet" => format!("{indicator} is a known command-and-control server ({feed}). A connection to it usually means a device is already infected and is receiving instructions."),
        "hijacked" => format!("{indicator} belongs to a network that {feed} reports as hijacked or operated by criminals. Legitimate services do not run there."),
        "manual" => format!("{indicator} is on your manual blocklist."),
        "ids" => format!("Suricata matched the signature \"{indicator}\" on traffic from {host}. Signatures describe known attack or malware behaviour."),
        _ => format!("{indicator} matched {feed}."),
    };
    let todo = match category {
        "botnet" | "malware" => "What to do: block it, then scan the device with Microsoft Defender (full scan) or your phone's security scanner. If it repeats after blocking, the device is likely infected.",
        "phishing" => "What to do: block it unless you trust the site. If you typed a password on that page, change it now and enable two-factor authentication.",
        "ids" => "What to do: open the event to see source and destination. If the source is a device on your network, scan it; if it is external, blocking the address is usually enough.",
        _ => "What to do: block it unless you recognise it. Use Allow if you are sure it is safe (false positive).",
    };
    format!("{what} Seen from {host}. {todo}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses() {
        assert_eq!(parse_domain_line("0.0.0.0 evil.example.com").as_deref(), Some("evil.example.com"));
        assert_eq!(parse_domain_line("# comment"), None);
        assert_eq!(parse_domain_line("*.adult-example.com").as_deref(), Some("adult-example.com"));
        assert_eq!(host_from_url("http://user@Evil.com:8080/x?y").as_deref(), Some("evil.com"));
        assert_eq!(host_from_url("\"1\",\"2025\",\"https://bad.net/a\",\"online\"").as_deref(), Some("bad.net"));
    }
    #[test]
    fn suffix_match() {
        let dir = std::env::temp_dir().join(format!("oph-intel-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("feeds")).unwrap();
        std::fs::write(dir.join("feeds/phishdb.txt"), "evil.com\nbad.example.org\nsites.google.com\nfirebasestorage.googleapis.com\ns3.us-east-1.amazonaws.com\n").unwrap();
        std::fs::write(dir.join("feeds/openphish.txt"), "https://docs.google.com/forms/x\nhttps://login-bank.xyz/a\n").unwrap();
        std::fs::write(dir.join("feeds/spamhaus_drop.txt"), "{\"cidr\":\"10.20.0.0/16\",\"sblid\":\"x\"}\n").unwrap();
        let it = Intel::build(&dir, &|_| true);
        assert!(it.match_domain("a.b.evil.com").is_some());
        assert!(it.match_domain("evil.com.").is_some());
        assert!(it.match_domain("notevil.com").is_none());
        assert!(it.match_domain("example.org").is_none());
        assert!(it.match_domain("docs.google.com").is_none(), "shared host must not be flagged");
        assert!(it.match_domain("sites.google.com").is_none());
        assert!(it.match_domain("mybucket.s3.us-east-1.amazonaws.com").is_none());
        assert!(it.guarded >= 3);
        assert!(it.match_domain("login-bank.xyz").is_some());
        assert!(is_shared_root("sites.google.com") && is_shared_root("s3.us-east-1.amazonaws.com") && is_shared_root("telegra.ph") && is_shared_root("co.uk"));
        assert!(!is_shared_root("evil.com"));
        assert!(it.match_ip("10.20.3.4").is_some());
        assert!(it.match_ip("10.21.0.1").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn popular_sites_are_never_threat_roots() {
        let dir = std::env::temp_dir().join(format!("oph-pop-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("feeds")).unwrap();
        std::fs::write(dir.join("feeds/tranco.txt"), "instagram.com\nyandex.ru\nbuilder-example.com\n").unwrap();
        let mut phish = String::from("l.instagram.com\nmc.yandex.ru\nreal-phish.xyz\nbuilder-example.com\n");
        for i in 0..25 {
            phish.push_str(&format!("fake-bank-{i}.builder-example.com\n"));
        }
        std::fs::write(dir.join("feeds/phishdb.txt"), phish).unwrap();
        let it = Intel::build(&dir, &|_| true);
        assert!(it.match_domain("l.instagram.com").is_none(), "Instagram's link shim is not phishing");
        assert!(it.match_domain("mc.yandex.ru").is_none());
        assert!(it.match_domain("real-phish.xyz").is_some());
        assert!(it.match_domain("fake-bank-3.builder-example.com").is_some(), "phishing pages on a hosting platform stay detected");
        assert!(it.match_domain("builder-example.com").is_none(), "the platform itself is not blocked");
        assert_eq!(it.counts.iter().find(|(id, _)| id == "phishdb").map(|x| x.1), Some(26), "1 real + 25 platform pages");
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn vpn_detection_signals() {
        let dir = std::env::temp_dir().join(format!("oph-vpn-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("feeds")).unwrap();
        std::fs::write(dir.join("feeds/vpn.txt"), "nordvpn.com\nmullvad.net\n").unwrap();
        let it = Intel::build(&dir, &|_| true);
        assert!(is_vpn(&it.vpn, Some("api.nordvpn.com"), None, None));
        assert!(is_vpn(&it.vpn, None, Some(51820), None));
        assert!(is_vpn(&it.vpn, None, None, Some("WireGuard.exe")));
        assert!(is_vpn(&it.vpn, None, None, Some("Proton VPN")));
        assert!(!is_vpn(&it.vpn, Some("example.com"), Some(443), Some("chrome.exe")));
        assert!(it.match_domain("nordvpn.com").is_none(), "VPN is a filter, never a threat");
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn pd_is_separate_from_threats() {
        let dir = std::env::temp_dir().join(format!("oph-pd-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("feeds")).unwrap();
        std::fs::write(dir.join("feeds/pd.txt"), "*.adult-example.com
nsfw-sample.org
").unwrap();
        let it = Intel::build(&dir, &|_| true);
        assert!(it.is_adult("adult-example.com") && it.is_adult("www.adult-example.com") && it.is_adult("nsfw-sample.org"));
        assert!(!it.is_adult("example.com"));
        assert!(it.match_domain("adult-example.com").is_none(), "PD must never raise a threat");
        assert_eq!(it.counts.iter().find(|(id, _)| id == "pd").map(|x| x.1), Some(2));
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod live_feed_check {
    /// Diagnostic: `OPH_FEEDS_DIR=<dir containing feeds\> cargo test live_counts -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_counts() {
        let dir = std::path::PathBuf::from(std::env::var("OPH_FEEDS_DIR").expect("set OPH_FEEDS_DIR"));
        let it = super::Intel::build(&dir, &|_| true);
        println!("counts: {:?}", it.counts);
        println!("popular={} adult={} vpn={} guarded={}", it.popular, it.adult.len(), it.vpn.len(), it.guarded);
    }
}
