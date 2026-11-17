# OPH-S for Android

Companion app for OPH Sentinel (package `com.oph.sentinel`, Kotlin + Jetpack Compose, minSdk 26, targetSdk 35). **DONE by OPH**

## Build

```powershell
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
cd android
.\gradlew test assembleRelease        # -> app\build\outputs\apk\release\app-release.apk (copy to ..\dist\OPH-S.apk)
```

Signing reads `keystore\keystore.properties` (`storeFile`, `storePassword`, `keyAlias`, `keyPassword`).
`keystore\` is git-ignored. Back it up: updates must be signed with the same key.

Interop test against a running core (skipped otherwise):
`.\gradlew :app:testDebugUnitTest --tests *InteropTest -Pophs.it.host=127.0.0.1 -Pophs.it.port=8443 -Pophs.it.token=<device key> -Pophs.it.fp=<SHA-256>`

## Layout

| File | Role |
|---|---|
| `core/Packet.kt`, `core/Dns.kt` | IPv4/UDP parse + build (RFC 1071/768 checksums), DNS question parsing, SERVFAIL |
| `core/Wire.kt` | `WireEvent`, `Frame` JSON (mirror of `crates/oph-proto`), `ophs://enroll` parsing |
| `core/AgentConnection.kt` | TLS socket, SHA-256 leaf pin, SNI `oph-sentinel`, hello/welcome, batch/ack, ping |
| `net/AgentChannel.kt` | worker: outbox (2000, drop oldest, persisted), backoff 5→60 s, fatal on pin mismatch / rejected key |
| `vpn/DnsVpnService.kt` | DNS-only VPN, per-app attribution, app install/remove, network change, VPN revoked |
| `BootReceiver.kt` | boot event + restart protection if it was on |

## DNS-only VPN

TUN address `10.111.222.1/32`, DNS server `10.111.222.2`, only `10.111.222.2/32` routed; OPH-S itself is excluded.
Queries are forwarded with `protect()`ed UDP sockets to the enrolled PC on port 53 (2 s timeout; after a failure the
PC is skipped for 30 s), else to the fallback resolver (default `1.1.1.1`), else SERVFAIL.

**IPv6:** no IPv6 address, route or DNS server is added to the VPN, so Android sends all lookups (A *and* AAAA) to
the IPv4 virtual server and IPv6 traffic keeps using the normal network. Any IPv6 packet that reaches the TUN is dropped.

Not seen by design: apps using their own DoH/DoT (e.g. Chrome "Secure DNS"), and Android *Private DNS* in strict
mode (hostname set). TCP DNS fallback (truncated answers) to the virtual server is not handled.

## Swapping the launcher icon

The adaptive icon is `app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml` (+ `_round`):
- foreground / monochrome: `app/src/main/res/mipmap-xxxhdpi/ic_launcher_foreground.png` — replace it with a
  **432×432 transparent PNG**, mark inside the central 288×288 (copied from
  `app/src-tauri/icons/android/ic_launcher_foreground.png`);
- background colour: `ic_launcher_background` in `app/src/main/res/values/resources.xml`.

Then rebuild. To use a vector instead, drop `ic_launcher_foreground.xml` in `res/drawable/`, delete the PNG and point
`<foreground>` at `@drawable/ic_launcher_foreground`.
