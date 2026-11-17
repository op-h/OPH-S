# OPH Sentinel — setup guide

## 1. Monitor every device on your router (recommended)

**TP-Link Deco: automatic.** Router page → "Set up my Deco automatically": enter the Deco owner password, press *Check first* (read-only), then *Apply to router*. OPH-S reserves this PC's IP and sets it as the network's DNS, verifies the change, keeps a backup and offers *Undo*. Safe mode keeps the Deco as backup DNS so the internet works when the PC is off; Strict mode sends every lookup through OPH-S. The Deco app on your phone is signed out when OPH-S logs in (Deco allows one admin session). Protocol: port of the open-source Deco clients (ha-tplink-deco, tplinkrouterc6u, tplink-deco-api). If your firmware does not expose the DNS setting locally, OPH-S says so and you use the manual steps below.

**Other routers / manual:**

OPH Sentinel includes a DNS resolver. When devices use it, you see every name each device looks up and can block dangerous sites for the whole network. Nothing is installed on the devices.

1. Give this PC a fixed LAN address: in the router's DHCP page, reserve the PC's current IP (shown on **Network** page).
2. In OPH Sentinel → **Network** → *Open firewall ports* (Windows asks for administrator approval; rules are limited to *Private* networks).
3. In the router's DHCP / LAN settings set **Primary DNS = this PC's IP**. Leave *Secondary DNS* empty (otherwise devices bypass OPH when they feel like it). Save; devices pick it up when they renew their lease (reconnect Wi-Fi or reboot them).
4. Devices appear on **Network → Devices** with names (from the router), vendor and query counts.

Notes
- If the PC is off, devices lose DNS. Keep the PC on, or set the router's secondary DNS to the router itself and accept partial visibility.
- Browsers with *Secure DNS / DNS-over-HTTPS* bypass any LAN resolver. In Chrome/Edge/Brave: Settings → Privacy → *Use secure DNS* → off (or choose "current service provider").
- Port 53 must be free. Windows *Internet Connection Sharing* and Hyper-V can occupy it; the **Search** page shows a `system.error` event if the resolver cannot start.
- Per-device bandwidth (bytes) needs router support (OpenWrt + softflowd/NetFlow). ARP spoofing is deliberately not used: it breaks the network when the PC sleeps and looks exactly like an attack.

## 2. Android

Two complementary options:

**a) DNS through OPH (no app, recommended):** on home Wi-Fi the phone already uses OPH if step 1 is done. Turn off *Settings → Network → Private DNS* (set to *Off* or *Automatic*), because Private DNS bypasses the LAN resolver.

**b) Agent in Termux (logs from the phone):**
1. Install **Termux** and **Termux:Boot** from F-Droid (the Play Store build is outdated).
2. In Termux: `pkg install rust git` then copy the `crates` folder and the root `Cargo.toml` to the phone (or `git clone` your copy) and run `cargo build --release -p oph-agent`.
3. Optional – allow reading system logs (once, from a PC with adb): `adb shell pm grant com.termux android.permission.READ_LOGS`
4. Copy the Android command from **Agents** page, add `--install`, run it. Open Termux:Boot once so it starts at boot.

Limits: since Android 10 non-root apps cannot list other apps' connections. Per-app traffic on Android requires a local-VPN app (the approach of RethinkDNS / PCAPdroid / NetGuard); OPH's DNS view covers the phone at network level instead.

## 3. Other Windows PCs
Copy `oph-agent.exe`, run the Windows command from the **Agents** page (append `--install` to start at logon). It ships new outbound connections (with process names) and Windows Event Log errors/warnings.

## 4. Router / NAS logs (syslog)
Set the router's *Remote syslog server* to this PC's IP, port **5514/UDP** (Settings → Agent ingest). Logins, DHCP leases and firewall drops appear as `syslog.message`.

## 5. Suricata IDS (optional, deep packet inspection)
1. Install **Npcap** (https://npcap.com) and **Suricata for Windows** (https://suricata.io/download/).
2. `suricata-update` to fetch ET Open rules, then run `suricata -c suricata.yaml -i <your-LAN-IP>`.
3. In OPH Settings set *Suricata eve.json path* (default `C:\Program Files\Suricata\log\eve.json`).
Suricata alerts become `ids.alert` events and Alerts. Expect 300+ MB RAM for Suricata with full rulesets — it is optional for that reason.

## 6. Threat feeds
Enabled by default: Phishing.Database, OpenPhish (non-commercial use), Feodo Tracker (CC0), Spamhaus DROP (non-commercial), IEEE OUI.
URLhaus: create a free key at https://auth.abuse.ch and paste it in Settings → Threat intel.

## 7. Warn vs Block
- **Warn (default):** you get a notification and an Alert; nothing is blocked until you press *Block*.
- **Block:** matches are sinkholed for LAN devices and added to the hosts file / Windows Firewall on this PC automatically. Use *Allow* on an alert to fix a false positive; it is remembered.
