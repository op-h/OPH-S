# OPH Sentinel — UI ⇄ Core contract

The UI calls the Rust core with `window.__TAURI__.core.invoke(name, args)`.
All timestamps are **unix milliseconds**. All sizes are **bytes**.
Arguments are passed as a single object; key names are camelCase in JS (Tauri converts to snake_case args).
Every command takes one argument named `req` (object) when it has inputs: `invoke("search", { req: {...} })`.

Severity scale (ordered): `info` < `low` < `medium` < `high` < `critical`.

## Types

```ts
Event = {
  id: number, ts: number,
  source: "dns" | "conn" | "ids" | "agent" | "system" | "intel" | "cleaner" | "firewall",
  kind: string,          // see catalog below
  severity: Severity,
  host: string,          // device/agent that produced it ("this-pc", agent name, LAN client ip)
  src_ip: string | null, dst_ip: string | null, dst_port: number | null,
  domain: string | null, process: string | null,
  message: string,
  raw: object            // original structured payload
}

Alert = {
  id: number, ts: number, last_ts: number, severity: Severity,
  title: string, indicator: string, indicator_type: "domain" | "ip" | "url" | "signature",
  feed: string,          // which intel source matched ("URLhaus", "Manual", "Suricata", ...)
  host: string, src_ip: string | null, count: number,
  status: "open" | "blocked" | "allowed" | "dismissed",
  explanation: string    // plain-language what/why/what-to-do
}
```

## Event kind catalog (used by Help page)
| kind | source | meaning |
|---|---|---|
| dns.query | dns | A LAN device asked the OPH DNS resolver for a name |
| dns.blocked | dns | The resolver answered 0.0.0.0 because the name is blocked |
| conn.open | conn | A new outbound connection from a process on a monitored PC |
| threat.match | intel | A domain/IP matched a threat-intel list |
| ids.alert | ids | Suricata IDS signature fired |
| agent.connect / agent.disconnect | agent | A remote agent (PC/Android) connected / dropped |
| agent.log | agent | A log line shipped by an agent (Windows Event Log, logcat, file tail) |
| device.new | system | A device appeared on the LAN for the first time |
| firewall.block / firewall.unblock | firewall | Windows Firewall rule added/removed by OPH |
| intel.update | intel | Threat feeds refreshed |
| cleaner.run / cleaner.undo | cleaner | Storage cleanup executed / reverted |
| system.start | system | Service started |
| system.error | system | A service could not start (port in use, missing rights) |
| syslog.message | syslog | Line received from a syslog sender (router, NAS, forwarder) |

## Commands

| name | req | returns |
|---|---|---|
| `overview` | – | `{events_24h, alerts_open, blocked_24h, devices_online, devices_total, agents_online, intel_entries, protection_mode, dns_running, series:[{t,total,alerts}] (24 hourly buckets, oldest first), top_domains:[{key,count}], top_hosts:[{key,count}], severity:[{key,count}], recent_alerts: Alert[] (≤6)}` |
| `search` | `{query: string, fromTs: number, toTs: number, limit: number}` | `{events: Event[], total: number, histogram:[{t,count}] (60 buckets across range), fields: {source:[{key,count}], kind:[...], severity:[...], host:[...], domain:[...], process:[...]}, stats: null \| {by: string, rows:[{key,count}]}, took_ms: number, error: string\|null}` |
| `alerts` | `{status: "open"\|"blocked"\|"allowed"\|"dismissed"\|"all"}` | `Alert[]` |
| `alert_decide` | `{id: number, action: "block"\|"allow"\|"dismiss"\|"reopen"}` | `Alert` |
| `devices` | – | `{gateway: string\|null, subnet: string\|null, devices: [{ip, mac, vendor, hostname, randomized_mac: bool, first_seen, last_seen, online: bool, queries_24h, blocked_24h, alerts_open, is_self: bool}]}` |
| `device_detail` | `{ip: string}` | `{top_domains:[{key,count}], recent: Event[]}` |
| `connections` | – | `[{proto, local, remote_ip, remote_port, state, pid, process, domain: string\|null, verdict: "ok"\|"malicious"\|"allowed"\|"blocked"}]` |
| `intel_status` | – | `{feeds:[{id,name,url,kind:"domains"\|"hosts"\|"urls"\|"ips"\|"cidr",enabled,entries,last_update,last_error}], manual_block:[{value,kind,note,added}], manual_allow:[...], total, updating: bool}` |
| `intel_update` | – | same as `intel_status` (starts refresh, returns immediately with updating=true) |
| `feed_toggle` | `{id: string, enabled: bool}` | `intel_status` |
| `list_add` | `{list: "block"\|"allow", value: string, note: string}` | `intel_status` |
| `list_remove` | `{list: "block"\|"allow", value: string}` | `intel_status` |
| `agents` | – | `{agents:[{id,name,platform,version,ip,last_seen,events,online}], server:{running, port, fingerprint, token, lan_ip}}` |
| `agent_rotate_token` | – | same as `agents` |
| `cleaner_scan` | – | `{categories:[{id,name,description,risk:"safe"\|"review",files,bytes,items:[{path,bytes,modified}] (largest ≤40)}], total_bytes, quarantine:{runs:[{id,ts,files,bytes}], bytes}}` |
| `cleaner_run` | `{categories: string[]}` | `{run_id, moved_files, moved_bytes, skipped, errors: string[]}` |
| `cleaner_undo` | `{runId: string}` | `{restored, remaining, errors: string[]}` (files that could not be restored stay in quarantine) |
| `cleaner_purge` | – | `{freed_bytes}` |
| `memory_status` | – | `{total, used, available, app_bytes, swap_total, swap_used}` |
| `memory_trim` | – | `{before_available, after_available, processes}` |
| `settings_get` | – | `Settings` |
| `settings_set` | `{settings: Settings}` | `Settings` |
| `app_info` | – | `{version, data_dir, admin: bool, platform}` |

```ts
Settings = {
  mode: "warn" | "block",        // warn = alert only; block = sinkhole/firewall automatically
  dns_enabled: bool, dns_bind: string, dns_upstream: string,
  ingest_enabled: bool, ingest_port: number,
  retention_days: number, notifications: bool,
  intel_interval_hours: number, suricata_eve_path: string,
  cleaner_schedule: "off" | "daily" | "weekly", autostart: bool,
  abuse_ch_key: string, watch_local_dns: bool, syslog_enabled: bool, syslog_port: number
}
```

Query language (search bar), Splunk-style:
`kind=dns.query host=192.168.1.20 severity>=medium domain=*google* "free text" | stats count by domain | head 20`
- `field=value`, `field!=value`, `*` wildcard, `severity>=X`, bare words = full-text on message/domain/process.
- Fields: source, kind, severity, host, src_ip, dst_ip, dst_port, domain, process.
- Pipes: `stats count by <field>`, `head N`, `sort -ts|ts`.

## v0.2 additions

### Branding
Product name shown in UI: **OPH-S** (top bar, window title). On hover the name expands to **OPH-Sentinel**. Footer keeps "DONE by OPH".
Icon concepts live in `app/ui/icons/<id>.svg` (ids `op-shield`, `op-radar`, `op-hex`, `op-eye`, `op-bracket`, `op-orbit`) plus `app/ui/icons/index.json` `[{id,name,description}]`.
Setting `icon_style: string` (one of the ids). On change the core swaps the tray + window icon at runtime.

### Settings additions
`retention_days` (default 7), `max_store_mb: number` (capacity cap, default 20480), `storage_primary: string` (folder, e.g. `E:\OPH-S\logs`), `storage_primary_serial: string` (volume serial, survives drive-letter changes), `storage_fallback: string` (used when primary is missing/disconnected; events are merged back into primary when it returns), `icon_style: string`.

| name | req | returns |
|---|---|---|
| `drives_list` | – | `[{letter, label, bus: "USB"\|"SATA"\|"NVMe"\|..., removable: bool, size, free, serial}]` |
| `storage_status` | – | `{active: "primary"\|"fallback", path, primary_path, primary_online, fallback_path, events_bytes, max_bytes, oldest_ts, free_bytes, retention_days}` |
| `cleaner_last` | – | last `cleaner_scan` result or `null` (kept in the core so leaving the page never loses it) |
| `unblock_all` | – | `{ok, message}` removes every block (lists, blocked alerts → open, hosts section, firewall rules) |
| `router_info` | – | `{gateway, gateway_mac, vendor, family: "tplink-deco"\|"tplink"\|"asus"\|"netgear"\|"huawei"\|"zte"\|"mikrotik"\|"generic", admin_url, pc_ip, pc_dns_servers: string[], dns_running, dns_bind, lan_clients_10m: number, reserved_hint}` |
| `device_enroll` | `{name: string, platform: "windows"\|"android"\|"iphone"\|"linux"}` | `{id, name, platform, token, host, port, fingerprint, windows_cmd, windows_install_cmd, termux_cmd, android_uri, apk_url: string\|null}` |
| `device_revoke` | `{id: string}` | same as `agents` |
| `apk_share` | `{enable: bool}` | `{url: string\|null, expires: number\|null}` — serves `OPH-S.apk` over plain HTTP on the LAN (port 8099) for 15 min |
| `agents` (changed) | – | `{agents:[{id,name,platform,created,last_seen,online,events,revoked}], server:{running, error, port, fingerprint, lan_ip, syslog_running, syslog_port, syslog_error}}` (no shared token any more: every device gets its own revocable key) |

Android enrollment URI (QR code): `ophs://enroll?host=<lan_ip>&port=<port>&token=<token>&fp=<sha256 hex with colons>&name=<name>`

## v0.2.1 – v0.2.5 additions

| name | req | returns |
|---|---|---|
| `set_monitoring` | `{enabled}` | `{network_monitoring}` (DNS keeps resolving when paused) |
| `search_suggest` | `{field, prefix}` | `{values:[{key,count}]}` |
| `export_search` | `{query, fromTs, toTs}` | `{path, rows}` (CSV in Downloads) |
| `alert_counts` | – | `{open, blocked, allowed, dismissed, all}` |
| `firewall_setup` | – | `{ok, message}` |
| `router_configure` | `{password, remember, mode:"safe"\|"strict", apply}` | `{ok, applied, steps, current, planned, backup, error}` |
| `router_undo` | `{password}` | `{ok, steps, error}` |
| `router_forget` | – | `{ok}` |
| `device_rename` | `{id: mac\|ip, name}` | same as `devices` (empty name = automatic name) |
| `ai_status` | – | `{provider, model, base_url, key_saved, ready, redact}` |
| `ai_set_key` | `{key}` | `{key_saved}` |
| `ai_preview` | `{kind, data}` | `{ok, context, text, chars}` |
| `ai_ask` | `{question, kind, data}` | `{ok, answer, model, usage, context, seconds, error}` |

`intel_status.feeds[]` items also carry `category` (phishing, malware, botnet, hijacked, reference, adult) and `needs_key`; feed kinds include `popular` (Tranco guard) and `oui`. Only `category == "adult"` (PD) is a content list.
Search: virtual field `pd=yes|no`; `dst_port` compares as a number. Event kinds: `file.*` (file monitoring), `firewall.sync` (enforcement refreshed; `firewall.block` = a block decision).
