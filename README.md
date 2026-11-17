# OPH-S (OPH Sentinel)

Personal SIEM + IDPS for your PC, your phone and every device on your home router.
Rust core, Tauri v2 desktop shell (WebView2, not Electron), C++ native helpers, Splunk-style dark UI.

**DONE by OPH**

## What it does

| Area | How | Reused open source |
|---|---|---|
| Monitor every device on the router | Built-in DNS resolver/sinkhole. Point the router's DHCP DNS at this PC → per-device query log, network-wide blocking. | Pi-hole / AdGuard Home approach; DNS parsing by **hickory-proto** |
| Device inventory | ARP/neighbour table + cheap /24 sweep, names from the router's reverse DNS, vendor from the **IEEE OUI** registry, randomized-MAC detection | IEEE OUI database |
| This PC | Live sockets with owning process every 5 s; real-time DNS lookups **per process** from the Windows DNS-Client ETW provider (falls back to the DNS cache when not elevated) | `netstat2`, `sysinfo`, **ferrisetw** |
| Threat intel | Phishing.Database, OpenPhish, abuse.ch Feodo Tracker, Spamhaus DROP, URLhaus (free abuse.ch key). Auto-refresh, compact 9-byte/entry index, false-positive guard: entries naming a shared platform (Public Suffix List + multi-tenant hosts such as sites.google.com, s3 buckets) are never used as block roots | public feeds, **psl** (Mozilla PSL) |
| IDS | Tails **Suricata** `eve.json` — detection by the ET Open / community rulesets, not a home-made engine | Suricata |
| Enforcement | Warn (default) or Block. Blocks via DNS sinkhole (all LAN devices), hosts file + Windows Firewall/WFP rules (this PC). Every decision is shown to you before it applies. | Windows Firewall |
| Log intake | `oph-agent` (TLS 1.3, pinned certificate, token, per-IP failed-auth ban) for PCs and Android/Termux; plus standard **syslog** (RFC 5424/3164, UDP) for routers, NAS, rsyslog, Fluent Bit, Vector | rustls, ring, **syslog_loose** |
| Cleaner | Explicit rules (temp, crash dumps, thumbnails, browser caches, dev caches, Windows Update cache), preview, quarantine with **Undo**, auto-purge after 7 days, background I/O priority | — |
| Memory | Working-set trim via Win32 (C++ helper); the UI WebView is destroyed when the window closes so only the ~15 MB core stays resident | — |

Measured on Windows 11 (debug build, 392k phishing domains loaded): core process **≈13 MB working set / 19 MB private** idle in the tray.

## Install (v0.2)
- **Windows:** run the newest `dist\OPH-S_<version>_x64-setup.exe`. It installs to `C:\Program Files\OPH-S`, starts with Windows (logon task, elevated, no UAC prompt each boot) and bundles `oph-agent.exe` + `OPH-S.apk` for the Add device page. Uninstalling removes hosts entries, firewall rules and autostart first.
- **Android:** `dist\OPH-S.apk` (signed release, 1.4 MB). Easiest: Devices → Add device → Android → "Share APK on Wi-Fi", scan the download QR, install, then scan the enrollment QR. Keep `android\keystore\` backed up — updates must be signed with the same key.
- **iPhone:** iOS allows no background agents; protect it through DNS (router setup covers it, or Wi-Fi → Configure DNS → Manual → this PC's IP).
- **Storage:** first run detects the large USB drive (by volume GUID) for logs (`E:\OPH-S\logs`), with a fallback on another internal drive; retention 7 days + capacity cap, both in Settings.
- **Router:** see the Router page in the app (TP-Link Deco steps included) or docs/SETUP.md.

## Build

Requirements: Rust (MSVC toolchain), Visual Studio Build Tools (C++), WebView2 (preinstalled on Windows 11).

```powershell
cargo build --release -p oph-sentinel -p oph-agent
# installer (needs dist\OPH-S.apk): powershell -ExecutionPolicy Bypass -File scriptsuild-installer.ps1
```

Binaries: `target\release\oph-sentinel.exe`, `target\release\oph-agent.exe`.
Data: `%LOCALAPPDATA%\OPHSentinel` (SQLite store, feeds cache, quarantine, server certificate).

Run as administrator (or enable *Start with Windows* once from an elevated run) so blocks can be enforced on this PC.

## Setup guides
See [docs/SETUP.md](docs/SETUP.md): router DNS, Android, Suricata, syslog, agents.

## Layout
```
crates/oph-proto   shared event model + wire protocol + socket snapshot
crates/oph-agent   collector for Windows / Linux / Android (Termux)
app/src-tauri      desktop core: dns, intel, ingest, netmon, firewall, cleaner, db, query, suricata
app/src-tauri/native/oph_native.cpp   Win32 helpers (working-set trim, background priority, elevation)
app/ui             static UI (no bundler): tokens.css design system, uPlot, Lucide, IBM Plex
docs/API.md        UI ⇄ core contract
```

## Quality process
Every change goes through an adversarial QA agent (DNS floods, malformed packets, TLS slot exhaustion, CRLF/hosts injection, poison batches, path traversal in undo manifests, feed false positives) and an independent verifier agent that re-derives each finding before it is fixed. Round 1 found 15 defects (3 critical); all were fixed and re-attacked.

## Tests
`cargo test --workspace` — query compiler (escaping, literal %, OR rules), feed parsing, suffix matching and shared-platform guard, hosts-file rewrite safety (byte-exact preservation, non-UTF-8 and missing-file refusal), DNS FORMERR and LAN-only policy, syslog RFC 5424/3164, Suricata EVE parsing, protocol sanitising (CRLF injection, timestamp clamping).
