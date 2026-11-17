package com.oph.sentinel.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.oph.sentinel.AppState
import com.oph.sentinel.BuildConfig
import com.oph.sentinel.Config
import com.oph.sentinel.DnsEntry
import com.oph.sentinel.MainActivity
import com.oph.sentinel.core.AgentConnection
import com.oph.sentinel.core.Enrollment
import com.oph.sentinel.core.Packet
import com.oph.sentinel.core.WelcomeRejected
import com.oph.sentinel.net.AgentChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Shape = RoundedCornerShape(4.dp)

@Composable
fun OphRoot(act: MainActivity) {
    val cfg = remember { Config(act) }
    var rev by remember { mutableIntStateOf(0) } // bump after config changes
    val enrolled = remember(rev) { cfg.enrollment != null }
    var screen by rememberSaveable { mutableStateOf(if (cfg.enrollment == null) "enroll" else "home") }
    val pending by act.pendingEnroll
    LaunchedEffect(pending) { if (pending != null) screen = "enroll" }

    Column(Modifier.fillMaxSize().background(Oph.page).statusBarsPadding().navigationBarsPadding()) {
        Row(
            Modifier.fillMaxWidth().background(Oph.appbar).padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("OPH-S", color = Oph.text, fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
            Spacer(Modifier.width(8.dp))
            Text(
                when (screen) { "enroll" -> "Enroll"; "settings" -> "Settings"; "about" -> "About"; else -> "Protection" },
                color = Oph.text2, fontSize = 14.sp,
            )
        }
        HorizontalDivider(color = Oph.border)
        Box(Modifier.weight(1f)) {
            when (screen) {
                "enroll" -> EnrollScreen(act, cfg) { rev++; screen = "home" }
                "settings" -> SettingsScreen(act, cfg, onReEnroll = { screen = "enroll" }, onChanged = { rev++ })
                "about" -> AboutScreen()
                else -> HomeScreen(act, enrolled, onEnroll = { screen = "enroll" })
            }
        }
        HorizontalDivider(color = Oph.border)
        Row(Modifier.fillMaxWidth().background(Oph.appbar)) {
            listOf("home" to "Home", "settings" to "Settings", "about" to "About").forEach { (id, label) ->
                val sel = screen == id
                Column(
                    Modifier.weight(1f).clickable { screen = id }.padding(vertical = 10.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(label, color = if (sel) Oph.text else Oph.text2, fontWeight = if (sel) FontWeight.SemiBold else FontWeight.Normal, fontSize = 14.sp)
                    Spacer(Modifier.height(4.dp))
                    Box(Modifier.width(32.dp).height(2.dp).background(if (sel) Oph.accent else Color.Transparent))
                }
            }
        }
    }
}

@Composable
private fun Panel(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Column(
        modifier.fillMaxWidth().background(Oph.panel, Shape).border(1.dp, Oph.border, Shape).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) { content() }
}

@Composable
private fun Kv(k: String, v: String, color: Color = Oph.text) {
    Row(Modifier.fillMaxWidth()) {
        Text(k, color = Oph.text2, fontSize = 13.sp, modifier = Modifier.weight(1f))
        Text(v, color = color, fontSize = 13.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun Dot(c: Color) = Box(Modifier.size(10.dp).background(c, CircleShape))

// ------------------------------------------------------------------ Home

@Composable
private fun HomeScreen(act: MainActivity, enrolled: Boolean, onEnroll: () -> Unit) {
    val st by AppState.status.collectAsStateWithLifecycle()
    val recent by AppState.recent.collectAsStateWithLifecycle()
    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Panel {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Dot(if (st.protecting) Oph.ok else Oph.danger)
                    Spacer(Modifier.width(10.dp))
                    Text(
                        if (st.protecting) "Protected" else "Not protected",
                        style = androidx.compose.material3.MaterialTheme.typography.titleLarge,
                        color = Oph.text, modifier = Modifier.weight(1f),
                    )
                    Switch(
                        checked = st.protecting,
                        onCheckedChange = { act.setProtection(it) },
                        modifier = Modifier.size(width = 64.dp, height = 40.dp),
                        colors = SwitchDefaults.colors(
                            checkedTrackColor = Oph.accent, checkedThumbColor = Oph.text,
                            uncheckedTrackColor = Oph.raised, uncheckedThumbColor = Oph.text2, uncheckedBorderColor = Oph.borderStrong,
                        ),
                    )
                }
                HorizontalDivider(color = Oph.border)
                Kv("Connected to PC", if (st.connected) "Yes" else "No", if (st.connected) Oph.ok else Oph.text2)
                Kv("Events sent today", st.sentToday.toString())
                Kv("DNS queries (this session)", st.queries.toString())
                if (st.buffered > 0) Kv("Waiting to send", st.buffered.toString(), Oph.warn)
                val err = st.lastError
                if (err != null) {
                    Text("Last error", color = Oph.text2, fontSize = 13.sp)
                    Text(err, color = if (st.fatal) Oph.danger else Oph.warn, fontSize = 13.sp)
                }
                if (!enrolled) {
                    Button(onClick = onEnroll, shape = Shape, modifier = Modifier.fillMaxWidth()) { Text("Enroll with your OPH PC") }
                }
            }
        }
        item {
            Text("Recent DNS queries", color = Oph.text2, fontSize = 12.sp, fontWeight = FontWeight.Medium,
                modifier = Modifier.padding(top = 4.dp))
        }
        if (recent.isEmpty()) item {
            Text(
                if (st.protecting) "Waiting for the first query…" else "Turn protection on to see which app looks up which domain.",
                color = Oph.muted, fontSize = 13.sp,
            )
        }
        items(recent, key = { "${it.ts}-${it.domain}-${it.pkg}-${it.qtype}" }) { QueryRow(it) }
    }
}

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
private fun QueryRow(e: DnsEntry) {
    Row(
        Modifier.fillMaxWidth().background(Oph.panel, Shape).border(1.dp, Oph.border, Shape).padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(e.domain, color = Oph.text, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text("${e.app} · ${e.qtype}", color = Oph.text2, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Column(horizontalAlignment = Alignment.End) {
            Text(timeFmt.format(Date(e.ts)), color = Oph.muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            Text(e.via, color = if (e.via == "pc") Oph.accent else if (e.via == "servfail") Oph.danger else Oph.text2, fontSize = 11.sp)
        }
    }
}

// ------------------------------------------------------------------ Enroll

@Composable
private fun field(value: String, onChange: (String) -> Unit, label: String, kb: KeyboardType = KeyboardType.Text) =
    OutlinedTextField(
        value, onChange, label = { Text(label) }, singleLine = true, shape = Shape,
        keyboardOptions = KeyboardOptions(keyboardType = kb),
        modifier = Modifier.fillMaxWidth(),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Oph.accent, unfocusedBorderColor = Oph.border,
            focusedLabelColor = Oph.accent, unfocusedLabelColor = Oph.text2, cursorColor = Oph.accent,
        ),
    )

@Composable
private fun EnrollScreen(act: MainActivity, cfg: Config, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var pending by act.pendingEnroll
    var linkErr by act.deepLinkError
    var host by rememberSaveable { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf("8443") }
    var token by rememberSaveable { mutableStateOf("") }
    var fp by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf(cfg.deviceName) }
    var result by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var busy by remember { mutableStateOf(false) }

    val scan = rememberLauncherForActivityResult(ScanContract()) { r ->
        val text = r.contents ?: return@rememberLauncherForActivityResult
        val e = Enrollment.parseUri(text)
        if (e == null) linkErr = "That QR code is not an OPH-S enrollment code." else pending = e
    }

    fun save(e: Enrollment) {
        cfg.enroll(e)
        AgentChannel.kick(clearFatal = true)
        AppState.update { it.copy(lastError = null, fatal = false) }
        busy = true
        result = null
        scope.launch {
            val r = withContext(Dispatchers.IO) {
                try {
                    AgentConnection.open(e.host, e.port, e.fingerprint, e.token, cfg.agentId, cfg.deviceName, "OPH-S ${BuildConfig.VERSION_NAME}").close()
                    true to "Connected: the PC accepted this device."
                } catch (x: Exception) {
                    false to when {
                        AgentConnection.pinFailure(x) != null -> "Certificate fingerprint mismatch: this is not the OPH PC from the QR code."
                        x is WelcomeRejected -> "PC rejected the key: ${x.reason}"
                        else -> "Saved, but the PC is not reachable right now (${x.message ?: x.javaClass.simpleName}). OPH-S keeps retrying."
                    }
                }
            }
            busy = false
            result = r
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        linkErr?.let { Text(it, color = Oph.danger, fontSize = 13.sp) }
        val p = pending
        if (p != null) {
            Panel {
                Text("Enroll this phone?", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
                Text("Only accept if this matches what your OPH Sentinel PC shows.", color = Oph.text2, fontSize = 13.sp)
                Kv("PC", "${p.host}:${p.port}")
                Kv("Device name", p.name.ifBlank { cfg.deviceName })
                Text("Certificate SHA-256", color = Oph.text2, fontSize = 13.sp)
                Text(Enrollment.prettyFp(p.fingerprint), color = Oph.text, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { pending = null; save(p) }, shape = Shape) { Text("Enroll") }
                    OutlinedButton(onClick = { pending = null }, shape = Shape) { Text("Cancel") }
                }
            }
        }
        Panel {
            Text("Scan the QR code", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
            Text("On the PC: OPH-S → Agents → Add device → Android.", color = Oph.text2, fontSize = 13.sp)
            Button(
                onClick = {
                    linkErr = null
                    scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Scan the OPH-S enrollment QR code")
                        .setBeepEnabled(false).setOrientationLocked(false))
                },
                shape = Shape, modifier = Modifier.fillMaxWidth(),
            ) { Text("Scan QR code") }
        }
        Panel {
            Text("Manual entry", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
            field(host, { host = it }, "PC address (LAN IP)", KeyboardType.Uri)
            field(port, { port = it }, "Port", KeyboardType.Number)
            field(token, { token = it }, "Device key (token)")
            field(fp, { fp = it }, "Certificate fingerprint (SHA-256)")
            field(name, { name = it }, "Device name")
            val e = Enrollment.validate(host, port, token, fp, name)
            Button(onClick = { e?.let { save(it) } }, enabled = e != null && !busy, shape = Shape, modifier = Modifier.fillMaxWidth()) {
                Text(if (busy) "Connecting…" else "Save and test connection")
            }
            if (e == null && (host + token + fp).isNotEmpty()) {
                Text("Fill in all fields; the fingerprint is 64 hex digits (colons optional).", color = Oph.muted, fontSize = 12.sp)
            }
        }
        result?.let { (ok, msg) ->
            Panel {
                Text(msg, color = if (ok) Oph.ok else Oph.warn, fontSize = 14.sp)
                Button(onClick = onDone, shape = Shape) { Text("Continue") }
            }
        }
    }
}

// ------------------------------------------------------------------ Settings

@Composable
private fun SettingsScreen(act: MainActivity, cfg: Config, onReEnroll: () -> Unit, onChanged: () -> Unit) {
    var dns by rememberSaveable { mutableStateOf(cfg.fallbackDns) }
    var name by rememberSaveable { mutableStateOf(cfg.deviceName) }
    var saved by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf(false) }
    val en = cfg.enrollment

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Panel {
            Text("DNS", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
            Text("Queries go to your OPH PC when reachable, otherwise to this fallback resolver.", color = Oph.text2, fontSize = 13.sp)
            field(dns, { dns = it }, "Fallback DNS (IPv4)", KeyboardType.Uri)
            val ok = Packet.ipBytes(dns) != null
            Button(onClick = { cfg.fallbackDns = dns.trim(); saved = "Fallback DNS saved" }, enabled = ok, shape = Shape) { Text("Save") }
        }
        Panel {
            Text("Device", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
            field(name, { name = it }, "Device name shown on the PC")
            Button(onClick = {
                cfg.deviceName = name
                AgentChannel.kick()
                saved = "Name saved (applies on next connection)"
            }, enabled = name.isNotBlank(), shape = Shape) { Text("Save") }
        }
        saved?.let { Text(it, color = Oph.ok, fontSize = 13.sp) }
        Panel {
            Text("Enrollment", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
            if (en != null) {
                Kv("PC", "${en.host}:${en.port}")
                Text(Enrollment.prettyFp(en.fingerprint), color = Oph.text2, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            } else Text("Not enrolled", color = Oph.text2, fontSize = 13.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onReEnroll, shape = Shape) { Text(if (en != null) "Re-enroll" else "Enroll") }
                if (en != null) OutlinedButton(
                    onClick = { confirm = true }, shape = Shape,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Oph.danger),
                ) { Text("Unenroll") }
            }
        }
    }
    if (confirm) AlertDialog(
        onDismissRequest = { confirm = false },
        title = { Text("Unenroll this phone?") },
        text = { Text("Protection stops and the device key is deleted from this phone. Revoke it on the PC too.") },
        confirmButton = {
            TextButton(onClick = {
                confirm = false
                act.setProtection(false)
                cfg.unenroll()
                AgentChannel.buffer.clear()
                AppState.update { it.copy(lastError = null, fatal = false, buffered = 0) }
                onChanged()
                saved = "Unenrolled"
            }) { Text("Unenroll", color = Oph.danger) }
        },
        dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
        containerColor = Oph.panel,
    )
}

// ------------------------------------------------------------------ About

@Composable
private fun AboutScreen() {
    val ctx = LocalContext.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Panel {
            Text("OPH-S", style = androidx.compose.material3.MaterialTheme.typography.headlineSmall)
            Text("Android companion for OPH Sentinel", color = Oph.text2, fontSize = 14.sp)
            Kv("Version", BuildConfig.VERSION_NAME)
            Kv("Agent id", remember { Config(ctx).agentId })
            HorizontalDivider(color = Oph.border)
            Text("DONE by OPH", color = Oph.accent, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
        }
        Panel {
            Text("How it works", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
            Text(
                "A local DNS-only VPN (the DNS66 / personalDNSfilter technique) sees each DNS lookup and which app made it. " +
                    "Only DNS enters the VPN; all other traffic is untouched. Lookups are answered by your OPH PC when reachable, " +
                    "else by the fallback resolver, and logged to the PC over TLS pinned to its certificate.",
                color = Oph.text2, fontSize = 13.sp,
            )
            Text("Open source: zxing-android-embedded (Apache-2.0), ZXing (Apache-2.0), IBM Plex Sans (OFL-1.1), AndroidX & Jetpack Compose (Apache-2.0), kotlinx.serialization (Apache-2.0).",
                color = Oph.muted, fontSize = 12.sp)
        }
    }
}
