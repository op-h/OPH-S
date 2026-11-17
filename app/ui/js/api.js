/* Core bridge. Uses Tauri invoke when available, otherwise a deterministic mock backend
   (browser preview only — never shipped behaviour). */
(function () {
  "use strict";
  const tauri = window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;

  async function call(name, req) {
    if (tauri) {
      try { return await tauri(name, req === undefined ? {} : { req }); }
      catch (e) { throw new Error(typeof e === "string" ? e : (e && e.message) || String(e)); }
    }
    await new Promise(r => setTimeout(r, name === "ai_ask" ? 1800 : 60 + Math.random() * 120));
    const fn = Mock[name];
    if (!fn) throw new Error("Unknown command: " + name);
    return JSON.parse(JSON.stringify(fn(req || {})));
  }

  window.API = {
    isMock: !tauri,
    overview: () => call("overview"),
    search: (query, fromTs, toTs, limit) => call("search", { query, fromTs, toTs, limit }),
    searchSuggest: (field, prefix) => call("search_suggest", { field, prefix }),
    exportSearch: (query, fromTs, toTs) => call("export_search", { query, fromTs, toTs }),
    alerts: status => call("alerts", { status }),
    alertCounts: () => call("alert_counts"),
    alertDecide: (id, action) => call("alert_decide", { id, action }),
    devices: () => call("devices"),
    deviceRename: (id, name) => call("device_rename", { id, name }),
    deviceDetail: ip => call("device_detail", { ip }),
    connections: () => call("connections"),
    intelStatus: () => call("intel_status"),
    intelUpdate: () => call("intel_update"),
    feedToggle: (id, enabled) => call("feed_toggle", { id, enabled }),
    listAdd: (list, value, note) => call("list_add", { list, value, note }),
    listRemove: (list, value) => call("list_remove", { list, value }),
    agents: () => call("agents"),
    cleanerScan: () => call("cleaner_scan"),
    cleanerRun: categories => call("cleaner_run", { categories }),
    cleanerUndo: runId => call("cleaner_undo", { runId }),
    cleanerPurge: () => call("cleaner_purge"),
    memoryStatus: () => call("memory_status"),
    memoryTrim: () => call("memory_trim"),
    settingsGet: () => call("settings_get"),
    settingsSet: settings => call("settings_set", { settings }),
    appInfo: () => call("app_info"),
    setMonitoring: enabled => call("set_monitoring", { enabled }),
    aiStatus: () => call("ai_status"),
    aiSetKey: key => call("ai_set_key", { key }),
    aiPreview: (kind, data) => call("ai_preview", { kind, data }),
    aiAsk: (question, kind, data) => call("ai_ask", { question, kind, data }),
    firewallSetup: () => call("firewall_setup"),
    drivesList: () => call("drives_list"),
    storageStatus: () => call("storage_status"),
    cleanerLast: () => call("cleaner_last"),
    unblockAll: () => call("unblock_all"),
    routerInfo: () => call("router_info"),
    routerConfigure: (password, remember, mode, apply) => call("router_configure", { password, remember, mode, apply }),
    routerUndo: password => call("router_undo", { password }),
    routerForget: () => call("router_forget"),
    deviceEnroll: (name, platform) => call("device_enroll", { name, platform }),
    deviceRevoke: id => call("device_revoke", { id }),
    apkShare: enable => call("apk_share", { enable }),
    leakStatus: () => call("leak_status"),
    leakAction: (id, action) => call("leak_action", { id, action }),
    leakFix: fix => call("leak_fix", { fix }),
  };

  /* ====================== MOCK BACKEND ====================== */
  let seed = 7;
  const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  const pick = a => a[Math.floor(rnd() * a.length)];
  const NOW = Date.now();
  const H = 3600e3;

  const devices = [
    { ip: "192.168.1.1", mac: "C8:3A:35:12:0A:01", vendor: "Tenda", hostname: "router.lan" },
    { ip: "192.168.1.10", mac: "3C:52:82:4E:91:7B", vendor: "Hewlett Packard", hostname: "oph-desktop", is_self: true },
    { ip: "192.168.1.23", mac: "DA:A1:19:5F:22:C4", vendor: "", hostname: "Galaxy-S23" },
    { ip: "192.168.1.31", mac: "F0:18:98:7A:11:02", vendor: "Apple", hostname: "iPad" },
    { ip: "192.168.1.42", mac: "B8:27:EB:33:44:55", vendor: "Raspberry Pi Foundation", hostname: "pi-hole" },
    { ip: "192.168.1.57", mac: "50:C7:BF:9D:20:1E", vendor: "TP-Link", hostname: "smart-plug" },
    { ip: "192.168.1.64", mac: "7A:2F:0C:88:E1:90", vendor: "", hostname: "" },
    { ip: "192.168.1.77", mac: "00:1A:11:6B:3C:08", vendor: "Google", hostname: "chromecast" },
  ];
  const domains = ["www.google.com", "api.github.com", "graph.microsoft.com", "i.ytimg.com", "edge.microsoft.com", "dns.msftncsi.com", "play.googleapis.com", "cdn.discordapp.com", "static.whatsapp.net", "connectivitycheck.gstatic.com", "time.windows.com", "update.googleapis.com", "settings-win.data.microsoft.com", "spclient.wg.spotify.com", "netflix.com"];
  const bad = [
    { d: "secure-paypa1-login.top", feed: "OpenPhish", sev: "high" },
    { d: "update-flashplayer.xyz", feed: "Phishing.Database", sev: "high" },
    { d: "cdn-dl.malwr-host.ru", feed: "URLhaus", sev: "critical" },
  ];
  const procs = ["chrome.exe", "brave.exe", "svchost.exe", "Discord.exe", "Code.exe", "spotify.exe", "OneDrive.exe", "msedgewebview2.exe"];

  const events = [];
  let eid = 1;
  function push(e) { events.push(Object.assign({ id: eid++, src_ip: null, dst_ip: null, dst_port: null, domain: null, process: null, raw: {} }, e)); }
  for (let i = 0; i < 1400; i++) {
    const ts = NOW - Math.floor(Math.pow(rnd(), 1.3) * 24 * H);
    const r = rnd();
    const dev = pick(devices.slice(1));
    if (r < 0.55) {
      const d = pick(domains);
      push({ ts, source: "dns", kind: "dns.query", severity: "info", host: dev.ip, src_ip: dev.ip, domain: d, message: `${dev.ip} query ${d} A -> NOERROR`, raw: { client: dev.ip, qname: d, qtype: "A", rcode: "NOERROR", upstream_ms: Math.floor(rnd() * 40) + 4 } });
    } else if (r < 0.85) {
      const p = pick(procs), ip = `${pick([13, 20, 52, 104, 142, 151])}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}`;
      const d = pick(domains);
      push({ ts, source: "conn", kind: "conn.open", severity: "info", host: "this-pc", src_ip: "192.168.1.10", dst_ip: ip, dst_port: pick([443, 443, 443, 80, 5228]), domain: d, process: p, message: `${p} -> ${ip}:443 (${d})`, raw: { proto: "tcp", pid: 1000 + Math.floor(rnd() * 9000), state: "ESTABLISHED" } });
    } else if (r < 0.93) {
      const lvl = pick(["Warning", "Error", "Information"]);
      push({ ts, source: "agent", kind: "agent.log", severity: lvl === "Error" ? "medium" : lvl === "Warning" ? "low" : "info", host: pick(["oph-laptop", "Galaxy-S23"]), message: lvl === "Error" ? "Service Control Manager: The Windows Update service terminated unexpectedly." : "ActivityManager: Start proc com.whatsapp for service", raw: { channel: "System", event_id: 7031, level: lvl } });
    } else if (r < 0.97) {
      const b = pick(bad);
      push({ ts, source: "dns", kind: "dns.blocked", severity: b.sev, host: dev.ip, src_ip: dev.ip, domain: b.d, message: `${dev.ip} query ${b.d} blocked (sinkhole 0.0.0.0) — ${b.feed}`, raw: { client: dev.ip, qname: b.d, qtype: "A", action: "sinkhole", feed: b.feed } });
    } else {
      const b = pick(bad);
      push({ ts, source: "intel", kind: "threat.match", severity: b.sev, host: dev.ip, src_ip: dev.ip, domain: b.d, message: `Threat match ${b.d} (${b.feed}) from ${dev.ip}`, raw: { indicator: b.d, indicator_type: "domain", feed: b.feed } });
    }
  }
  push({ ts: NOW - 5 * 60e3, source: "ids", kind: "ids.alert", severity: "high", host: "this-pc", src_ip: "192.168.1.10", dst_ip: "185.220.101.4", dst_port: 9001, message: "ET POLICY TOR Known Tor Relay/Router (Not Exit) Node Traffic", raw: { signature_id: 2522000, category: "Misc Attack", proto: "TCP" } });
  push({ ts: NOW - 2 * H, source: "intel", kind: "intel.update", severity: "info", host: "this-pc", message: "Threat feeds refreshed: 5 feeds, 184,312 indicators", raw: { feeds: 5, entries: 184312 } });
  push({ ts: NOW - 3 * H, source: "system", kind: "device.new", severity: "low", host: "192.168.1.64", src_ip: "192.168.1.64", message: "New device 192.168.1.64 (7A:2F:0C:88:E1:90, randomized MAC)", raw: { mac: "7A:2F:0C:88:E1:90" } });
  // VPN demo activity (for the VPN search filter)
  for (let i = 0; i < 6; i++) push({ ts: NOW - (2 + i * 3) * H, source: "dns", kind: "dns.query", severity: "info", host: "Galaxy-S23", src_ip: "192.168.1.23", domain: i % 2 ? "api.nordvpn.com" : "nordvpn.com", process: "NordVPN", message: "Galaxy-S23 resolved nordvpn.com (A) -> 104.17.49.74", raw: { app: "com.nordvpn.android" } });
  for (let i = 0; i < 4; i++) push({ ts: NOW - (1 + i * 5) * H, source: "conn", kind: "conn.open", severity: "info", host: "this-pc", src_ip: "192.168.1.10", dst_ip: "100.101.12.4", dst_port: 41641, process: "tailscaled.exe", message: "tailscaled.exe -> 100.101.12.4:41641", raw: { proto: "udp" } });
  push({ ts: NOW - 7 * H, source: "conn", kind: "conn.open", severity: "info", host: "oph-laptop", src_ip: "192.168.1.88", dst_ip: "185.65.135.50", dst_port: 51820, process: "wireguard.exe", message: "wireguard.exe -> 185.65.135.50:51820", raw: { proto: "udp" } });
  push({ ts: NOW - 20 * H, source: "system", kind: "system.start", severity: "info", host: "this-pc", message: "OPH-S core started", raw: { version: "0.2.7" } });
  push({ ts: NOW - 6 * H, source: "firewall", kind: "firewall.block", severity: "medium", host: "this-pc", dst_ip: "45.9.148.108", message: "Windows Firewall rule added: block 45.9.148.108 (Feodo Tracker)", raw: { rule: "OPH Sentinel block 45.9.148.108" } });
  push({ ts: NOW - 9 * H, source: "agent", kind: "agent.connect", severity: "info", host: "Galaxy-S23", src_ip: "192.168.1.23", message: "Agent Galaxy-S23 (android) connected", raw: { platform: "android", version: "0.2.7" } });
  push({ ts: NOW - 50 * 60e3, source: "syslog", kind: "syslog.message", severity: "low", host: "192.168.1.1", src_ip: "192.168.1.1", message: "dropbear[2231]: Bad password attempt for 'root' from 192.168.1.64:51522", raw: { facility: "authpriv", priority: 4, app: "dropbear", pid: 2231 } });
  [
    [NOW - 12 * 60e3, "file.created", "medium", "C:\\Users\\OPH\\Downloads\\invoice_2026.pdf.exe", "Downloads", 812344, "9f2c1e0a4b77d3a8e5f61c2b0d9a8e7f6c5b4a3928170e6d5c4b3a2918070605"],
    [NOW - 40 * 60e3, "file.created", "high", "C:\\Users\\OPH\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk", "Startup (you)", 1422, "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"],
    [NOW - 2 * H, "file.modified", "info", "C:\\Users\\OPH\\Documents\\budget.xlsx", "Documents", 48211, null],
    [NOW - 3 * H, "file.deleted", "info", "C:\\Users\\OPH\\Desktop\\old-notes.txt", "Desktop", 0, null],
    [NOW - 5 * H, "file.modified", "high", "C:\\Windows\\System32\\drivers\\etc\\hosts", "hosts file", 1240, null],
  ].forEach(([ts, kind, sev, p, folder, size, sha]) => push({ ts, source: "file", kind, severity: sev, host: "this-pc", process: null,
    message: `${kind.split(".")[1]} ${p}`, raw: Object.assign({ path: p, folder, size }, sha ? { sha256: sha } : {}) }));
  [["192.168.1.64", "adult-videos.example", 3], ["192.168.1.23", "xxcams.example", 9], ["192.168.1.64", "nsfw-gallery.example", 20]].forEach(([ip, d, h]) =>
    push({ ts: NOW - h * H, source: "dns", kind: "dns.query", severity: "info", host: ip, src_ip: ip, domain: d, message: `${ip} query ${d} A -> NOERROR`, raw: { client: ip, qname: d, qtype: "A", rcode: "NOERROR" } }));
  push({ ts: NOW - 4 * H, source: "file", kind: "file.renamed", severity: "medium", host: "this-pc", message: "renamed C:\\Users\\OPH\\Downloads\\setup.tmp -> C:\\Users\\OPH\\Downloads\\setup.ps1", raw: { path: "C:\\Users\\OPH\\Downloads\\setup.ps1", old_path: "C:\\Users\\OPH\\Downloads\\setup.tmp", folder: "Downloads", size: 2210, sha256: "77aa01bc22cd33de44ef5501aa66bb77cc88dd99ee00ff1122334455667788aa" } });
  push({ ts: NOW - 30 * H, source: "cleaner", kind: "cleaner.run", severity: "info", host: "this-pc", message: "Cleaner moved 4,812 files (1.3 GB) to quarantine", raw: { run_id: "r-1731400000", files: 4812 } });
  [
    [NOW - 3 * 60e3, "leak.hidden_lookup", "medium", "192.168.1.10", "steamwebhelper.exe resolved api.steampowered.com without the Windows DNS client", { class: "A", actor: "steamwebhelper.exe", leak_id: 1 }],
    [NOW - 9 * 60e3, "leak.other_server", "high", "192.168.1.80", "chrome.exe on oph-laptop sent lookups to 1.1.1.1 instead of OPH-S", { class: "B", actor: "chrome.exe → 1.1.1.1", leak_id: 2 }],
    [NOW - 60e3, "leak.quiet", "high", "192.168.1.23", "Galaxy-S23 is online but made no lookups through OPH-S for 60 minutes", { class: "C", actor: "Android Private DNS", leak_id: 3 }],
    [NOW - 3 * H, "leak.encrypted_dns", "info", "192.168.1.23", "Galaxy-S23 looked up dns.google (encrypted-DNS provider)", { class: "D", actor: "dns.google", leak_id: 4 }],
    [NOW - 2 * 24 * H, "leak.fixed", "info", "192.168.1.10", "Secure DNS in brave.exe: oph-desktop uses OPH-S DNS again", { class: "B", actor: "Secure DNS in brave.exe", leak_id: 5 }],
  ].forEach(([ts, kind, sev, ip, msg, r]) => push({ ts, source: "leak", kind, severity: sev, host: ip, src_ip: ip, process: /\.exe/.test(r.actor) ? r.actor.match(/[\w.-]+\.exe/)[0] : null, message: msg, raw: r }));
  events.sort((a, b) => b.ts - a.ts);

  const alerts = [
    { id: 1, ts: NOW - 40 * 60e3, last_ts: NOW - 4 * 60e3, severity: "critical", title: "Malware distribution domain contacted", indicator: "cdn-dl.malwr-host.ru", indicator_type: "domain", feed: "URLhaus", host: "192.168.1.23", src_ip: "192.168.1.23", count: 14, status: "open", explanation: "Galaxy-S23 looked up a domain that URLhaus lists as actively serving malware. This usually means a malicious app, ad, or link tried to download a payload. Block it, then check which app on the phone made the request (recently installed apps first)." },
    { id: 2, ts: NOW - 2 * H, last_ts: NOW - 30 * 60e3, severity: "high", title: "Phishing site lookup", indicator: "secure-paypa1-login.top", indicator_type: "domain", feed: "OpenPhish", host: "192.168.1.10", src_ip: "192.168.1.10", count: 3, status: "open", explanation: "This PC resolved a domain that imitates PayPal and is listed by OpenPhish. If you opened a link from an email or message, do not enter credentials. Blocking prevents any device using OPH DNS from reaching it." },
    { id: 3, ts: NOW - 5 * 60e3, last_ts: NOW - 5 * 60e3, severity: "high", title: "ET POLICY TOR Known Tor Relay Traffic", indicator: "2522000", indicator_type: "signature", feed: "Suricata", host: "this-pc", src_ip: "192.168.1.10", count: 1, status: "open", explanation: "Suricata saw traffic to a known Tor relay. This is expected if you use Tor Browser; otherwise it may indicate malware using Tor for command-and-control." },
    { id: 4, ts: NOW - 6 * H, last_ts: NOW - 6 * H, severity: "medium", title: "Botnet C2 IP contacted", indicator: "45.9.148.108", indicator_type: "ip", feed: "Feodo Tracker", host: "this-pc", src_ip: "192.168.1.10", count: 2, status: "blocked", explanation: "A process on this PC connected to an IP that Feodo Tracker lists as a botnet command server. A firewall rule now blocks it." },
    { id: 5, ts: NOW - 22 * H, last_ts: NOW - 21 * H, severity: "low", title: "Listed domain lookup", indicator: "tracker.ads-metrics.net", indicator_type: "domain", feed: "Phishing.Database", host: "192.168.1.31", src_ip: "192.168.1.31", count: 9, status: "allowed", explanation: "Marked as allowed by you. OPH keeps logging lookups but will not alert again." },
    { id: 6, ts: NOW - 26 * H, last_ts: NOW - 26 * H, severity: "medium", title: "Phishing site lookup", indicator: "update-flashplayer.xyz", indicator_type: "domain", feed: "Phishing.Database", host: "192.168.1.57", src_ip: "192.168.1.57", count: 1, status: "dismissed", explanation: "Dismissed. A new lookup will reopen the alert." },
  ];

  const feeds = [
    { id: "openphish", name: "OpenPhish Community", url: "https://openphish.com/feed.txt", kind: "urls", category: "phishing", enabled: true, entries: 512, last_update: NOW - 2 * H, last_error: null },
    { id: "phishdb", name: "Phishing.Database (active domains)", url: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", kind: "domains", category: "phishing", enabled: true, entries: 158420, last_update: NOW - 2 * H, last_error: null },
    { id: "feodo", name: "Feodo Tracker botnet C2", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", kind: "ips", category: "botnet", enabled: true, entries: 38, last_update: NOW - 2 * H, last_error: null },
    { id: "spamhaus_drop", name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop_v4.json", kind: "cidr", category: "hijacked", enabled: true, entries: 1342, last_update: NOW - 2 * H, last_error: null },
    { id: "vpn", name: "VPN — hagezi DoH/VPN/Proxy bypass list", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt", kind: "domains", category: "vpn", enabled: true, entries: 16682, last_update: NOW - 5 * H, last_error: null },
    { id: "pd", name: "OISD NSFW (adult sites)", url: "https://nsfw.oisd.nl/domainswild", kind: "domains", category: "adult", enabled: true, entries: 489733, last_update: NOW - 5 * H, last_error: null },
    { id: "tranco", name: "Tranco top sites — false-positive guard", url: "https://tranco-list.eu/top-1m.csv.zip", kind: "popular", category: "reference", enabled: true, entries: 20000, last_update: NOW - 2 * 24 * H, last_error: null },
    { id: "oui", name: "IEEE OUI vendor database", url: "https://standards-oui.ieee.org/oui/oui.csv", kind: "oui", category: "reference", enabled: true, entries: 38212, last_update: NOW - 4 * 24 * H, last_error: null },
    { id: "urlhaus", name: "URLhaus (requires free Auth-Key)", url: "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/hostfile.txt", kind: "hosts", category: "malware", enabled: false, entries: 0, last_update: null, last_error: "No abuse.ch Auth-Key configured" },
  ];
  const manual_block = [{ value: "badsite.example", kind: "domain", note: "Reported by ISP", added: NOW - 3 * 24 * H }, { value: "203.0.113.0/24", kind: "cidr", note: "Scanner range", added: NOW - 9 * 24 * H }];
  const manual_allow = [{ value: "tracker.ads-metrics.net", kind: "domain", note: "Needed for work app", added: NOW - 21 * H }];

  let settings = { mode: "warn", dns_enabled: true, dns_bind: "0.0.0.0:53", dns_upstream: "1.1.1.1:53", ingest_enabled: true, ingest_port: 8443, retention_days: 7, notifications: true, intel_interval_hours: 6, suricata_eve_path: "", cleaner_schedule: "weekly", autostart: true, abuse_ch_key: "", watch_local_dns: true, syslog_enabled: false, syslog_port: 5514,
    max_store_mb: 20480, storage_primary: "", storage_primary_serial: "", storage_fallback: "", icon_style: "op-shield",
    network_monitoring: true, fim_enabled: true, fim_paths: [],
    saved_searches: [{ name: "Blocked lookups today", query: "kind=dns.blocked", range: "24h" }],
    ai_provider: "anthropic", ai_model: "claude-opus-5-5", ai_base_url: "https://api.openai.com/v1", ai_redact: true, leak_quiet_minutes: 60 };
  const aiMock = { key: false };
  const ADULT = new Set(["adult-videos.example", "xxcams.example", "nsfw-gallery.example"]);
  // VPN demo signals (mirrors the core: VPN/proxy list domains, VPN-only ports, VPN client programs)
  const VPN_DOMAINS = new Set(["nordvpn.com", "api.nordvpn.com", "protonvpn.com", "mullvad.net", "tailscale.com", "controlplane.tailscale.com", "dns.google"]);
  const VPN_PORTS = new Set([1723, 1194, 1701, 500, 4500, 51820, 41641]);
  const isVpn = e => (!!e.domain && VPN_DOMAINS.has(e.domain)) || (e.dst_port != null && VPN_PORTS.has(+e.dst_port)) || /vpn|wireguard|tailscale|openvpn|warp-svc/i.test(e.process || "");
  let devicesList = [
    { id: "d-7f3a", name: "oph-laptop", platform: "windows", created: NOW - 12 * 24 * H, last_seen: NOW - 20e3, online: true, events: 18342, revoked: false },
    { id: "d-91bc", name: "Galaxy-S23", platform: "android", created: NOW - 6 * 24 * H, last_seen: NOW - 45e3, online: true, events: 6120, revoked: false },
    { id: "d-22e0", name: "work-vm", platform: "windows", created: NOW - 30 * 24 * H, last_seen: NOW - 3 * 24 * H, online: false, events: 902, revoked: false },
  ];
  let lastScan = null, apk = { url: null, expires: null };
  const routerMock = { saved: false, applied: false, backup: null };
  let token = "k7Qm2vX9pL4sT8wB1nE6rY3uH0cJ5aZd";
  const fp = "4F:9A:1C:7E:22:B0:3D:88:61:F5:0A:CE:94:17:2B:6D:E3:58:A0:4C:91:0F:7B:D2:36:E8:15:AA:C9:44:5B:02";
  let quarantine = [{ id: "r-1731400000", ts: NOW - 30 * H, files: 4812, bytes: 1395864371 }];


  /* Leak Check mock: 13 devices in all four states, one leak per class, mixed statuses. */
  const leakMock = {
    fixes: { canaries: false, doh_names: false, firewall_doh: false }, tap_dropped: 0,
    devices: [
      ["192.168.1.1", "router.lan", "Tenda", "covered", { resolver: true, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.10", "oph-desktop", "Hewlett Packard", "leaking", { resolver: true, windows: true, app: "online", encrypted_dns: true }],
      ["192.168.1.23", "Galaxy-S23", "", "quiet", { resolver: false, windows: false, app: "online", encrypted_dns: true }],
      ["192.168.1.31", "iPad", "Apple", "quiet", { resolver: false, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.42", "pi-hole", "Raspberry Pi Foundation", "covered", { resolver: true, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.57", "smart-plug", "TP-Link", "covered", { resolver: true, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.64", "", "", "too_new", { resolver: false, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.77", "chromecast", "Google", "covered", { resolver: true, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.80", "oph-laptop", "Lenovo", "leaking", { resolver: true, windows: true, app: "online", encrypted_dns: false }],
      ["192.168.1.91", "living-room-tv", "LG Electronics", "covered", { resolver: true, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.95", "printer", "Brother", "covered", { resolver: true, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.102", "kitchen-speaker", "Amazon", "covered", { resolver: true, windows: false, app: null, encrypted_dns: false }],
      ["192.168.1.110", "work-vm", "Microsoft", "covered", { resolver: true, windows: true, app: null, encrypted_dns: false }],
    ].map(([ip, name, vendor, state, seen_by]) => ({ ip, name, vendor, state, seen_by })),
    leaks: [
      { id: 1, dev: "192.168.1.10", dev_name: "oph-desktop", actor: "steamwebhelper.exe", class: "A", severity: "medium", first_ts: NOW - 5 * H, last_ts: NOW - 3 * 60e3, count: 214, samples: ["api.steampowered.com", "steamcdn-a.akamaihd.net", "community.cloudflare.steamstatic.com"], status: "open" },
      { id: 2, dev: "192.168.1.80", dev_name: "oph-laptop", actor: "chrome.exe → 1.1.1.1", class: "B", severity: "high", first_ts: NOW - 26 * H, last_ts: NOW - 9 * 60e3, count: 1832, samples: ["www.youtube.com", "mail.google.com", "fonts.gstatic.com", "accounts.google.com"], status: "open" },
      { id: 3, dev: "192.168.1.23", dev_name: "Galaxy-S23", actor: "Android Private DNS", class: "C", severity: "high", first_ts: NOW - 3 * H, last_ts: NOW - 60e3, count: 1, samples: [], status: "open" },
      { id: 4, dev: "192.168.1.23", dev_name: "Galaxy-S23", actor: "dns.google", class: "D", severity: "info", first_ts: NOW - 3 * H - 2 * 60e3, last_ts: NOW - 3 * H, count: 3, samples: ["dns.google", "use-application-dns.net"], status: "open" },
      { id: 5, dev: "192.168.1.10", dev_name: "oph-desktop", actor: "Secure DNS in brave.exe", class: "B", severity: "medium", first_ts: NOW - 4 * 24 * H, last_ts: NOW - 2 * 24 * H, count: 640, samples: ["search.brave.com", "github.com"], status: "fixed" },
      { id: 6, dev: "192.168.1.10", dev_name: "oph-desktop", actor: "Spotify.exe", class: "A", severity: "low", first_ts: NOW - 6 * 24 * H, last_ts: NOW - 20 * H, count: 57, samples: ["apresolve.spotify.com", "spclient.wg.spotify.com"], status: "ignored" },
      { id: 7, dev: "192.168.1.31", dev_name: "iPad", actor: "iCloud Private Relay", class: "C", severity: "medium", first_ts: NOW - 50 * 60e3, last_ts: NOW - 2 * 60e3, count: 1, samples: [], status: "open" },
    ],
  };

  function counts(list, field, top) {
    const m = new Map();
    list.forEach(e => { const k = e[field]; if (k === null || k === undefined || k === "") return; m.set(k, (m.get(k) || 0) + 1); });
    return Array.from(m, ([key, count]) => ({ key: String(key), count })).sort((a, b) => b.count - a.count).slice(0, top || 10);
  }
  const SEVR = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

  /* Mock query engine — Splunk semantics: implicit AND, OR binds tighter than AND, NOT negates the next term. */
  const QFIELDS = ["source", "kind", "severity", "host", "src_ip", "dst_ip", "dst_port", "domain", "process", "pd", "vpn"];
  function lev(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return d[a.length][b.length];
  }
  function unknownField(f) {
    const best = QFIELDS.map(x => [x, lev(f.toLowerCase(), x)]).sort((a, b) => a[1] - b[1])[0];
    return `Unknown field "${f}".` + (best && best[1] <= 3 ? ` Did you mean "${best[0]}"?` : ` Valid fields: ${QFIELDS.join(", ")}`);
  }
  function parseQuery(q) {
    const [main, ...pipes] = q.split("|").map(s => s.trim());
    const re = /"([^"]*)"|(\w+)\s*(!=|>=|<=|=|>|<)\s*("[^"]*"|[^\s()]+)|(\S+)/g;
    const groups = []; let neg = false, orNext = false, m;
    while ((m = re.exec(main || ""))) {
      let t = null;
      if (m[1] !== undefined) t = { free: m[1].toLowerCase() };
      else if (m[2]) {
        if (!QFIELDS.includes(m[2])) return { error: unknownField(m[2]) };
        t = { f: m[2], op: m[3], v: m[4].replace(/^"|"$/g, "") };
      } else {
        const w = m[5].replace(/^\(+|\)+$/g, "");
        if (w === "NOT") { neg = true; continue; }
        if (w === "OR") { orNext = true; continue; }
        if (!w || w === "*" || w === "AND") continue;
        t = { free: w.toLowerCase() };
      }
      t.neg = neg; neg = false;
      if (orNext && groups.length) groups[groups.length - 1].push(t); else groups.push([t]);
      orNext = false;
    }
    let stats = null, head = null, sortAsc = false, top = false;
    for (const p of pipes) {
      let mm;
      if ((mm = /^stats\s+count\s+by\s+(\w+)$/i.exec(p))) { if (!QFIELDS.includes(mm[1])) return { error: unknownField(mm[1]) }; stats = mm[1]; }
      else if ((mm = /^top\s+(\w+)$/i.exec(p))) { if (!QFIELDS.includes(mm[1])) return { error: unknownField(mm[1]) }; stats = mm[1]; top = true; }
      else if ((mm = /^head\s+(\d+)$/i.exec(p))) head = +mm[1];
      else if ((mm = /^sort\s+(-?)ts$/i.exec(p))) sortAsc = mm[1] !== "-";
      else return { error: `Unsupported command "${p.split(/\s/)[0]}". Supported: stats count by <field>, top <field>, head N, sort ts|-ts` };
    }
    return { groups, stats, head, sortAsc, top };
  }
  function wild(pat, val) {
    if (val === null || val === undefined) return false;
    const r = new RegExp("^" + pat.toLowerCase().replace(/[.+?^${}()[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$");
    return r.test(String(val).toLowerCase());
  }
  function termMatch(t, e) {
    let ok;
    if (t.free !== undefined) { const w = t.free.replace(/\*/g, ""); ok = [e.message, e.domain, e.process, e.host].some(x => x && String(x).toLowerCase().includes(w)); }
    else if (t.f === "severity" && /[<>]/.test(t.op)) {
      const a = SEVR[e.severity], b = SEVR[t.v];
      ok = b !== undefined && (t.op === ">=" ? a >= b : t.op === ">" ? a > b : t.op === "<=" ? a <= b : a < b);
    } else if (t.f === "vpn") { const hit = isVpn(e); ok = /^(yes|true|1)$/i.test(t.v) ? hit : !hit; if (t.op === "!=") ok = !ok;
    } else if (t.f === "pd") { const hit = !!e.domain && ADULT.has(e.domain); ok = /^(yes|true|1)$/i.test(t.v) ? hit : !hit; if (t.op === "!=") ok = !ok; }
    else { ok = wild(t.v, e[t.f]); if (t.op === "!=") ok = !ok; }
    return t.neg ? !ok : ok;
  }

  const Mock = {
    overview() {
      const day = events.filter(e => e.ts >= NOW - 24 * H);
      const series = [];
      for (let i = 23; i >= 0; i--) {
        const t0 = NOW - (i + 1) * H, t1 = NOW - i * H;
        const b = day.filter(e => e.ts >= t0 && e.ts < t1);
        series.push({ t: t0, total: b.length, alerts: b.filter(e => SEVR[e.severity] >= 2).length });
      }
      return {
        events_24h: day.length, alerts_open: alerts.filter(a => a.status === "open").length,
        blocked_24h: day.filter(e => e.kind === "dns.blocked").length,
        devices_online: devices.length - 1, devices_total: devices.length, agents_online: 2,
        intel_entries: feeds.reduce((s, f) => s + (f.enabled && f.category !== "adult" && f.category !== "reference" ? f.entries : 0), 0) + manual_block.length,
        protection_mode: settings.mode, dns_running: settings.dns_enabled, network_monitoring: settings.network_monitoring,
        series, top_domains: counts(day.filter(e => e.source === "dns"), "domain", 8), top_hosts: counts(day, "host", 8),
        severity: counts(day, "severity", 5), recent_alerts: alerts.filter(a => a.status === "open").slice(0, 6),
      };
    },
    search(r) {
      const t0 = performance.now();
      const p = parseQuery(r.query || "");
      const empty = { events: [], total: 0, histogram: [], fields: {}, stats: null, took_ms: 0 };
      if (p.error) return Object.assign(empty, { error: p.error });
      const from = r.fromTs || 0, to = r.toTs || Date.now();
      let list = events.filter(e => e.ts >= from && e.ts <= to);
      list = list.filter(e => p.groups.every(g => g.some(t => termMatch(t, e))));
      if (p.sortAsc) list = list.slice().reverse();
      const span = Math.max(1, (to - (from || (list.length ? Math.min(...list.map(e => e.ts)) : to - H))));
      const start = from || to - span;
      const bw = (to - start) / 60;
      const histogram = Array.from({ length: 60 }, (_, i) => ({ t: Math.round(start + i * bw), count: 0 }));
      list.forEach(e => { const i = Math.min(59, Math.floor((e.ts - start) / bw)); if (i >= 0) histogram[i].count++; });
      const fields = {};
      ["source", "kind", "severity", "host", "domain", "process"].forEach(f => (fields[f] = counts(list, f, 10)));
      const total = list.length;
      if (p.head) list = list.slice(0, p.head);
      const stats = p.stats ? { by: p.stats, rows: counts(list, p.stats, p.top ? 10 : 50) } : null;
      return { events: list.slice(0, r.limit || 200), total, histogram, fields, stats, took_ms: Math.round(performance.now() - t0) + 3, error: null };
    },
    search_suggest(r) {
      if (!QFIELDS.includes(r.field)) throw new Error("Unknown field " + r.field);
      if (r.field === "vpn") return { values: [{ key: "yes", count: events.filter(isVpn).length }, { key: "no", count: events.filter(e => !isVpn(e)).length }].filter(v => v.key.startsWith(String(r.prefix || "").toLowerCase())) };
      if (r.field === "pd") return { values: [{ key: "yes", count: events.filter(e => e.domain && ADULT.has(e.domain)).length }, { key: "no", count: events.filter(e => !(e.domain && ADULT.has(e.domain))).length }].filter(v => v.key.startsWith(String(r.prefix || "").toLowerCase())) };
      const pre = String(r.prefix || "").toLowerCase();
      const recent = events.filter(e => e.ts >= NOW - 7 * 24 * H && e[r.field] !== null && e[r.field] !== undefined && String(e[r.field]).toLowerCase().includes(pre));
      const rows = counts(recent, r.field, 100).sort((x, y) => (y.key.toLowerCase().startsWith(pre) - x.key.toLowerCase().startsWith(pre)) || y.count - x.count);
      return { values: rows.slice(0, 15) };
    },
    export_search(r) {
      const res = Mock.search({ query: r.query, fromTs: r.fromTs, toTs: r.toTs, limit: 100000 });
      if (res.error) throw new Error(res.error);
      const d = new Date(), pad = n => String(n).padStart(2, "0");
      return { path: `C:\\Users\\OPH\\Downloads\\ophs-search-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}.csv`, rows: Math.min(res.total, 100000) };
    },
    alert_counts() { const c = { open: 0, blocked: 0, allowed: 0, dismissed: 0, all: alerts.length }; alerts.forEach(a => { c[a.status] = (c[a.status] || 0) + 1; }); return c; },
    alerts(r) { return r.status === "all" || !r.status ? alerts : alerts.filter(a => a.status === r.status); },
    alert_decide(r) {
      const a = alerts.find(x => x.id === r.id); if (!a) throw new Error("Alert not found");
      a.status = { block: "blocked", allow: "allowed", dismiss: "dismissed", reopen: "open" }[r.action];
      if (r.action === "block" && a.indicator_type !== "signature" && !manual_block.find(m => m.value === a.indicator)) manual_block.push({ value: a.indicator, kind: a.indicator_type, note: "Blocked from alert #" + a.id, added: Date.now() });
      if (r.action === "allow" && !manual_allow.find(m => m.value === a.indicator)) manual_allow.push({ value: a.indicator, kind: a.indicator_type, note: "Allowed from alert #" + a.id, added: Date.now() });
      return a;
    },
    device_rename(r) {
      const d = devices.find(x => x.mac === r.id || x.ip === r.id);
      if (!d) throw new Error("Device not found (it may not have been seen in the network table yet)");
      d.label = String(r.name || "").trim().slice(0, 48);
      return Mock.devices();
    },
    devices() {
      return {
        gateway: "192.168.1.1", subnet: "192.168.1.0/24",
        devices: devices.map((d, i) => {
          const de = events.filter(e => e.src_ip === d.ip && e.ts >= NOW - 24 * H);
          return {
            ip: d.ip, mac: d.mac, vendor: d.vendor, hostname: d.label || d.hostname,
            randomized_mac: (parseInt(d.mac.slice(0, 2), 16) & 2) === 2,
            first_seen: NOW - (10 - i) * 24 * H, last_seen: i === 6 ? NOW - 5 * H : NOW - Math.floor(rnd() * 600e3),
            online: i !== 6, queries_24h: de.filter(e => e.source === "dns").length,
            blocked_24h: de.filter(e => e.kind === "dns.blocked").length,
            alerts_open: alerts.filter(a => a.src_ip === d.ip && a.status === "open").length, is_self: !!d.is_self,
          };
        }),
      };
    },
    device_detail(r) {
      const de = events.filter(e => e.src_ip === r.ip || e.host === r.ip);
      return { top_domains: counts(de, "domain", 10), recent: de.slice(0, 25) };
    },
    connections() {
      const rows = [];
      for (let i = 0; i < 46; i++) {
        const p = pick(procs);
        rows.push({ proto: pick(["tcp", "tcp", "tcp", "udp"]), local: `192.168.1.10:${50000 + Math.floor(rnd() * 15000)}`, remote_ip: `${pick([13, 20, 52, 104, 142, 151])}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}`, remote_port: pick([443, 443, 443, 80, 5228, 3478]), state: pick(["ESTABLISHED", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"]), pid: 1000 + Math.floor(rnd() * 9000), process: p, domain: rnd() > 0.3 ? pick(domains) : null, verdict: "ok" });
      }
      rows[3].verdict = "malicious"; rows[3].remote_ip = "185.220.101.4"; rows[3].remote_port = 9001; rows[3].domain = null;
      rows[9].verdict = "blocked"; rows[9].remote_ip = "45.9.148.108"; rows[9].state = "SYN_SENT";
      rows[12].verdict = "allowed"; rows[12].domain = "tracker.ads-metrics.net";
      return rows;
    },
    intel_status() { return { feeds, manual_block, manual_allow, total: feeds.reduce((s, f) => s + (f.enabled && f.category !== "adult" && f.category !== "reference" ? f.entries : 0), 0) + manual_block.length, updating: false }; },
    intel_update() { feeds.forEach(f => { if (f.enabled) f.last_update = Date.now(); }); return Object.assign(Mock.intel_status(), { updating: true }); },
    feed_toggle(r) { const f = feeds.find(x => x.id === r.id); if (f) f.enabled = r.enabled; return Mock.intel_status(); },
    list_add(r) {
      const L = r.list === "block" ? manual_block : manual_allow;
      const v = r.value.trim().toLowerCase();
      if (L.find(x => x.value === v)) throw new Error(v + " is already in the " + r.list + "list");
      L.unshift({ value: v, kind: v.includes("/") ? "cidr" : /^[\d.:]+$/.test(v) ? "ip" : "domain", note: r.note || "", added: Date.now() });
      return Mock.intel_status();
    },
    list_remove(r) { const L = r.list === "block" ? manual_block : manual_allow; const i = L.findIndex(x => x.value === r.value); if (i >= 0) L.splice(i, 1); return Mock.intel_status(); },
    agents() {
      return { agents: devicesList, server: { running: settings.ingest_enabled, error: null, port: settings.ingest_port, fingerprint: fp, lan_ip: "192.168.68.110", syslog_running: settings.syslog_enabled, syslog_port: settings.syslog_port, syslog_error: null } };
    },
    device_enroll(r) {
      if (!r.name || !r.name.trim()) throw new Error("Enter a device name");
      const id = "d-" + Math.random().toString(16).slice(2, 6);
      const tok = Array.from({ length: 32 }, () => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[Math.floor(Math.random() * 57)]).join("");
      const host = "192.168.68.110", port = settings.ingest_port;
      devicesList.push({ id, name: r.name, platform: r.platform, created: Date.now(), last_seen: null, online: false, events: 0, revoked: false });
      const base = `--server ${host}:${port} --token ${tok} --fingerprint ${fp} --name ${r.name}`;
      return { id, name: r.name, platform: r.platform, token: tok, host, port, fingerprint: fp,
        windows_cmd: `& "C:\\Program Files\\OPH-S\\oph-agent.exe" ${base} --winlog System,Application`,
        windows_install_cmd: `& "C:\\Program Files\\OPH-S\\oph-agent.exe" ${base} --winlog System,Application --install`,
        termux_cmd: `./oph-agent ${base} --logcat`,
        android_uri: `ophs://enroll?host=${host}&port=${port}&token=${tok}&fp=${fp}&name=${encodeURIComponent(r.name)}`,
        apk_url: apk.url,
        this_pc_note: /^(oph-desktop|this-pc)$/i.test(r.name) ? "This is the PC running OPH-S; it is already monitored directly — use the command on your other PCs." : null,
        share_expires: r.platform === "windows" ? Date.now() + 15 * 60e3 : null };
    },
    device_revoke(r) { devicesList = devicesList.filter(d => d.id !== r.id); return Mock.agents(); },
    apk_share(r) { apk = r.enable ? { url: "http://192.168.68.110:8099/OPH-S.apk", expires: Date.now() + 15 * 60e3 } : { url: null, expires: null }; return apk; },
    router_configure(r) {
      if (!r.password && !routerMock.saved) return { ok: false, applied: false, steps: [{ name: "Sign in", ok: false, detail: "No password given and none saved" }], current: null, planned: null, backup: routerMock.backup, error: "Enter the Deco owner password." };
      if (r.password === "wrong") return { ok: false, applied: false, steps: [{ name: "Connect to 192.168.68.1", ok: true, detail: "" }, { name: "Sign in", ok: false, detail: "Password rejected" }], current: null, planned: null, backup: routerMock.backup, error: "The Deco rejected the password (owner account required)." };
      if (r.password === "old") return { ok: false, applied: false, steps: [{ name: "Sign in", ok: true, detail: "" }, { name: "Read DHCP settings", ok: false, detail: "Endpoint not available" }], current: null, planned: null, backup: routerMock.backup, error: "This firmware does not allow DHCP changes over the local API." };
      if (r.remember && r.password) routerMock.saved = true;
      const planned = { primaryDns: "192.168.68.110", secondaryDns: r.mode === "strict" ? "" : "192.168.68.1", reservation: { mac: "AA-BB-CC-DD-EE-FF", ip: "192.168.68.110" } };
      const current = routerMock.applied ? planned : { primaryDns: "", secondaryDns: "", reservation: null };
      const steps = [{ name: "Connect to 192.168.68.1", ok: true, detail: "TP-Link Deco X55, firmware 1.3.2" }, { name: "Sign in as owner", ok: true, detail: "" }, { name: "Read DHCP settings", ok: true, detail: "DNS automatic (ISP)" }, { name: "Read address reservations", ok: true, detail: "12 entries" }];
      if (r.apply) {
        routerMock.backup = { primaryDns: "", secondaryDns: "", ts: Date.now(), gateway: "192.168.68.1" }; routerMock.applied = true;
        steps.push({ name: "Reserve 192.168.68.110 for AA-BB-CC-DD-EE-FF", ok: true, detail: "" }, { name: "Set DHCP DNS", ok: true, detail: `Primary 192.168.68.110, secondary ${planned.secondaryDns || "none"}` }, { name: "Sign out", ok: true, detail: "" });
        return { ok: true, applied: true, steps, current: planned, planned, backup: routerMock.backup, error: null };
      }
      steps.push({ name: "Sign out", ok: true, detail: "Nothing was changed" });
      return { ok: true, applied: false, steps, current, planned, backup: routerMock.backup, error: null };
    },
    router_undo() { const had = !!routerMock.backup; routerMock.applied = false; routerMock.backup = null; return { ok: had, steps: [{ name: "Sign in as owner", ok: true, detail: "" }, { name: "Restore DHCP DNS", ok: had, detail: had ? "Back to automatic" : "No backup" }, { name: "Sign out", ok: true, detail: "" }], error: had ? null : "No backup to restore." }; },
    router_forget() { routerMock.saved = false; return { ok: true }; },
    router_info() {
      return { gateway: "192.168.68.1", gateway_mac: "3C:52:A1:6E:20:01", vendor: "TP-Link (Deco)", family: "tplink-deco", admin_url: "http://192.168.68.1",
        pc_ip: "192.168.68.110", pc_dns_servers: ["192.168.68.1", "192.168.1.1"], dns_running: settings.dns_enabled, dns_bind: settings.dns_bind,
        lan_clients_10m: routerMock.applied ? 3 + Math.floor(Math.random() * 4) : 0, auto_supported: true, credential_saved: routerMock.saved, backup: routerMock.backup, reserved_hint: "Reserve 192.168.68.110 for MAC 3C:52:82:4E:91:7B so this PC keeps its address." };
    },
    drives_list() {
      return [
        { letter: "C", label: "Windows", bus: "NVMe", removable: false, size: 512e9, free: 141e9, serial: "A1B2-C3D4" },
        { letter: "D", label: "Data", bus: "SATA", removable: false, size: 1000e9, free: 612e9, serial: "5E6F-7A8B" },
        { letter: "E", label: "Seagate Expansion", bus: "USB", removable: true, size: 2000e9, free: 1740e9, serial: "9C0D-1E2F" },
      ];
    },
    storage_status() {
      const prim = settings.storage_primary;
      return { active: prim ? "primary" : "fallback", path: prim || "C:\\Users\\OPH\\AppData\\Local\\OPHSentinel\\logs", primary_path: prim || null, primary_online: !!prim,
        fallback_path: settings.storage_fallback || "C:\\Users\\OPH\\AppData\\Local\\OPHSentinel\\logs", events_bytes: 812e6, max_bytes: settings.max_store_mb * 1048576,
        oldest_ts: NOW - 6.5 * 24 * H, free_bytes: prim ? 1740e9 : 141e9, retention_days: settings.retention_days };
    },
    cleaner_last() { return lastScan; },
    unblock_all() { manual_block.length = 0; alerts.forEach(a => { if (a.status === "blocked") a.status = "open"; }); return { ok: true, message: "Removed all blocks: lists cleared, 1 alert reopened, 2 firewall rules deleted" }; },
    cleaner_scan() {
      const mk = (id, name, description, risk, files, bytes, paths) => ({ id, name, description, risk, files, bytes, items: paths.map((p, i) => ({ path: p, bytes: Math.floor(bytes / (i + 3)), modified: NOW - (i + 2) * 24 * H })) });
      const categories = [
        mk("user_temp", "User temporary files", "Files in %TEMP% older than 24 hours. Installers and apps leave these behind.", "safe", 3214, 1840000000, ["C:\\Users\\OPH\\AppData\\Local\\Temp\\vs_setup_bootstrapper.tmp", "C:\\Users\\OPH\\AppData\\Local\\Temp\\chrome_installer.log", "C:\\Users\\OPH\\AppData\\Local\\Temp\\{A1B2}\\setup.cab"]),
        mk("win_temp", "Windows temporary files", "C:\\Windows\\Temp. Some files need administrator rights; locked files are skipped.", "safe", 418, 312000000, ["C:\\Windows\\Temp\\MpCmdRun.log", "C:\\Windows\\Temp\\DMI1A2B.tmp"]),
        mk("browser_cache", "Browser caches", "Cache, Code Cache and GPUCache for Brave, Chrome, Edge and Firefox. Close browsers first; sites will load slower once.", "safe", 22981, 2950000000, ["C:\\Users\\OPH\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache\\Cache_Data\\data_3", "C:\\Users\\OPH\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Code Cache\\js\\index"]),
        mk("crash_dumps", "Crash dumps & error reports", "%LOCALAPPDATA%\\CrashDumps and Windows Error Reporting archives.", "safe", 37, 905000000, ["C:\\Users\\OPH\\AppData\\Local\\CrashDumps\\Discord.exe.14520.dmp"]),
        mk("thumb_cache", "Thumbnail cache", "Explorer thumbnail databases. Rebuilt automatically; files in use are skipped.", "safe", 9, 188000000, ["C:\\Users\\OPH\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_256.db"]),
        mk("dev_caches", "Developer package caches", "npm and pip download caches. Safe to remove but packages will re-download on the next install.", "review", 51230, 3410000000, ["C:\\Users\\OPH\\AppData\\Local\\npm-cache\\_cacache\\content-v2\\sha512\\4f\\a1", "C:\\Users\\OPH\\AppData\\Local\\pip\\cache\\http-v2\\a\\b"]),
        mk("sentinel_logs", "OPH-S old data", "Events older than the retention period and compaction of the event database.", "safe", 1, 64000000, ["C:\\Users\\OPH\\AppData\\Local\\OPHSentinel\\events.db"]),
      ];
      lastScan = { categories, total_bytes: categories.reduce((s, c) => s + c.bytes, 0), quarantine: { runs: quarantine, bytes: quarantine.reduce((s, r) => s + r.bytes, 0) } };
      return lastScan;
    },
    cleaner_run(r) { const id = "r-" + Math.floor(Date.now() / 1000); const files = r.categories.length * 1200, b = r.categories.length * 410000000; quarantine.unshift({ id, ts: Date.now(), files, bytes: b }); return { run_id: id, moved_files: files, moved_bytes: b, skipped: 14, errors: ["C:\\Windows\\Temp\\locked.etl: file in use"] }; },
    cleaner_undo(r) { const q = quarantine.find(x => x.id === r.runId); quarantine = quarantine.filter(x => x.id !== r.runId); return { restored: q ? q.files : 0, errors: [] }; },
    cleaner_purge() { const b = quarantine.reduce((s, r) => s + r.bytes, 0); quarantine = []; return { freed_bytes: b }; },
    memory_status() { return { total: 17079869440, used: 11240000000, available: 5839869440, app_bytes: 23400000, swap_total: 4294967296, swap_used: 812000000 }; },
    memory_trim() { return { before_available: 5839869440, after_available: 6720000000, processes: 143 }; },
    leak_status() {
      const L = leakMock, c = { covered: 0, leaking: 0, quiet: 0, too_new: 0 };
      L.devices.forEach(d => { c[d.state]++; });
      return { coverage: Object.assign({ total: L.devices.length }, c), devices: L.devices, leaks: L.leaks, quiet_minutes: settings.leak_quiet_minutes, fixes: L.fixes, tap_dropped: L.tap_dropped };
    },
    leak_action(r) {
      const l = leakMock.leaks.find(x => x.id === r.id); if (!l) throw new Error("Leak not found");
      let message;
      if (r.action === "ignore") { l.status = "ignored"; message = `Ignoring ${l.actor} on ${l.dev_name || l.dev}`; }
      else if (r.action === "reopen") { l.status = "open"; message = `Reopened ${l.actor} on ${l.dev_name || l.dev}`; }
      else if (r.action === "recheck") {
        const f = leakMock.fixes, cured = (l.class === "B" && f.firewall_doh) || ((l.class === "C" || l.class === "D") && (f.canaries || f.doh_names));
        if (cured) { l.status = "fixed"; message = `${l.dev_name || l.dev} is using OPH-S DNS again. Marked as fixed.`; }
        else { l.last_ts = Date.now() - 30e3; message = `Still leaking: ${l.dev_name || l.dev} was seen bypassing OPH-S 30 s ago.`; }
      } else throw new Error("Unknown action " + r.action);
      return Object.assign(Mock.leak_status(), { message });
    },
    leak_fix(r) {
      const names = { canaries: "Canary answers", doh_names: "Encrypted-DNS names blocked", firewall_doh: "Encrypted DNS blocked on this PC" };
      const undo = /^undo_/.test(r.fix), k = r.fix.replace(/^undo_/, "");
      if (!(k in leakMock.fixes)) throw new Error("Unknown fix " + r.fix);
      leakMock.fixes[k] = !undo;
      return Object.assign(Mock.leak_status(), { message: undo ? `${names[k]}: undone` : `${names[k]}: applied` });
    },
    settings_get() { return settings; },
    settings_set(r) { settings = Object.assign({}, settings, r.settings); return settings; },
    ai_status() {
      const p = settings.ai_provider;
      return { provider: p, model: settings.ai_model, base_url: settings.ai_base_url, key_saved: aiMock.key, ready: p === "openai" ? !!settings.ai_base_url && !!settings.ai_model : aiMock.key, redact: settings.ai_redact };
    },
    ai_set_key(r) { aiMock.key = !!(r.key && r.key.trim()); return { key_saved: aiMock.key }; },
    ai_preview(r) {
      if (!r.kind) return { ok: true, context: "No logs attached", text: "", chars: 0 };
      let lines = [];
      if (r.kind === "search") { const s = Mock.search({ query: r.data.query, fromTs: r.data.fromTs, toTs: r.data.toTs, limit: 60 }); lines = s.events.map(e => `${new Date(e.ts).toISOString()} ${e.severity} ${e.kind} host=${e.host} ${e.message}`); }
      else if (r.kind === "event" || r.kind === "alert") { const e = r.kind === "event" ? events.find(x => x.id === r.data.id) : alerts.find(x => x.id === r.data.id); lines = [JSON.stringify(e, null, 2)]; }
      else if (r.kind === "device") lines = events.filter(e => e.src_ip === r.data.ip).slice(0, 60).map(e => `${new Date(e.ts).toISOString()} ${e.kind} ${e.message}`);
      let text = lines.join("\n");
      if (settings.ai_redact) text = text.replace(/\b192\.168\.\d+\.(\d+)\b/g, "192.168.x.$1").replace(/\b([0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi, "xx:xx:xx:xx:xx:xx");
      return { ok: true, context: `${r.kind}: ${lines.length} records`, text, chars: text.length };
    },
    ai_ask(r) {
      const st = Mock.ai_status();
      if (!st.ready) return { ok: false, error: "Add an API key in Settings → Ask AI first." };
      const pv = Mock.ai_preview({ kind: r.kind, data: r.data });
      const answer = "**Short answer:** nothing here looks actively dangerous, but two things deserve a look.\n\n"
        + "- **192.168.1.23** looked up `cdn-dl.malwr-host.ru` 14 times. URLhaus lists it as a malware host, so check recently installed apps on that phone.\n"
        + "- One process (`spotify.exe`) talked to a Tor relay on port 9001. That's unusual for Spotify; verify the file's location.\n\n"
        + "### What to do\n1. Block the URLhaus domain from the alert.\n2. Run a malware scan on the phone.\n3. Keep Warn mode for another week to spot false positives.";
      return { ok: true, answer, model: st.model, usage: { input_tokens: Math.round(pv.chars / 4) + 300, output_tokens: 180 }, context: pv.context, seconds: 7.4 };
    },
    set_monitoring(r) { settings.network_monitoring = !!r.enabled; return { network_monitoring: settings.network_monitoring }; },
    firewall_setup() { return { ok: true, message: "Firewall rules added for 53/UDP, 8443/TCP and 5514/UDP" }; },
    app_info() { return { version: "0.2.7", data_dir: "C:\\Users\\OPH\\AppData\\Local\\OPHSentinel", admin: false, platform: "windows", status: { network_monitoring: settings.network_monitoring } }; },
  };
})();
