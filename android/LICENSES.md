# Third-party licences — OPH-S (Android)

| Component | Use in OPH-S | Licence |
|---|---|---|
| [zxing-android-embedded](https://github.com/journeyapps/zxing-android-embedded) 4.3.0 | QR scanner (`ScanContract`, `CaptureActivity`) | Apache-2.0 |
| [ZXing core](https://github.com/zxing/zxing) 3.4.1 (transitive) | QR decoding | Apache-2.0 |
| AndroidX (core, activity, lifecycle), Jetpack Compose, Material 3 | UI | Apache-2.0 |
| [kotlinx.serialization-json](https://github.com/Kotlin/kotlinx.serialization) 1.7.3 | JSON frames (tree API only) | Apache-2.0 |
| Kotlin stdlib / coroutines | runtime | Apache-2.0 |
| [IBM Plex Sans](https://github.com/IBM/plex) via `@fontsource/ibm-plex-sans` 5.3.0 | UI font (`res/font/ibm_plex_sans_*.ttf`, latin subset, converted losslessly from the package's WOFF files) | SIL Open Font License 1.1 |
| Material Icons "verified_user" glyph | notification icon path | Apache-2.0 |

## Techniques reused (no code copied)

- **DNS-only VpnService** — the approach of [DNS66](https://github.com/julian-klode/dns66) (GPL-3.0),
  [personalDNSfilter](https://github.com/IngoZenz/personaldnsfilter) (GPL-2.0) and
  [RethinkDNS](https://github.com/celzero/rethink-app) (Apache-2.0): give the TUN a /32 address, set a
  virtual DNS server, route only that /32, answer DNS from user space, wake the TUN reader with a pipe + `poll()`.
  OPH-S re-implements this in its own code (`vpn/DnsVpnService.kt`, `core/Packet.kt`, `core/Dns.kt`); no GPL source is included.
- **Certificate pinning** by SHA-256 of the leaf DER — same model as `crates/oph-agent` (rustls) in this repository.
