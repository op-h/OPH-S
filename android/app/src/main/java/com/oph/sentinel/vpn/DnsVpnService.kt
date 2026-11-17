package com.oph.sentinel.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.oph.sentinel.AppState
import com.oph.sentinel.Config
import com.oph.sentinel.DnsEntry
import com.oph.sentinel.MainActivity
import com.oph.sentinel.R
import com.oph.sentinel.core.Deduper
import com.oph.sentinel.core.Dns
import com.oph.sentinel.core.Packet
import com.oph.sentinel.core.WireEvent
import com.oph.sentinel.net.AgentChannel
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * DNS-only VPN (technique of DNS66 / personalDNSfilter / RethinkDNS): the TUN gets
 * 10.111.222.1/32, the system DNS server becomes the virtual 10.111.222.2 and only
 * 10.111.222.2/32 is routed into the TUN. All other traffic never touches us.
 *
 * IPv6: no IPv6 address, route or DNS server is configured, so Android sends every
 * lookup (A and AAAA) to the IPv4 virtual server; any IPv6 packet that still arrives is dropped.
 */
class DnsVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.oph.sentinel.START"
        const val ACTION_STOP = "com.oph.sentinel.STOP"
        const val VPN_ADDR = "10.111.222.1"
        const val VPN_DNS = "10.111.222.2"
        private const val CHANNEL = "protection"
        private const val NOTIF_ID = 1
        private const val PC_TIMEOUT_MS = 2_000
        private const val FALLBACK_TIMEOUT_MS = 3_000

        fun start(ctx: Context) {
            Config(ctx).protect = true
            ContextCompat.startForegroundService(ctx, Intent(ctx, DnsVpnService::class.java).setAction(ACTION_START))
        }

        fun stop(ctx: Context) {
            Config(ctx).protect = false
            ctx.startService(Intent(ctx, DnsVpnService::class.java).setAction(ACTION_STOP))
        }

        fun ensureChannel(ctx: Context) {
            if (Build.VERSION.SDK_INT >= 26) {
                val nm = ctx.getSystemService(NotificationManager::class.java)
                nm.createNotificationChannel(NotificationChannel(CHANNEL, "Protection", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Shown while OPH-S protection is on"
                    setShowBadge(false)
                })
            }
        }
    }

    private lateinit var cfg: Config
    private var tun: ParcelFileDescriptor? = null
    private var wakeFds: Array<FileDescriptor>? = null
    private var reader: Thread? = null
    private var pool: ExecutorService? = null
    private var tunOut: FileOutputStream? = null
    @Volatile private var active = false
    @Volatile private var pcDownUntil = 0L
    private val dedupe = Deduper()
    private val ipId = AtomicInteger(1)
    private val apps = ConcurrentHashMap<Int, Pair<String, String>>() // uid -> (package, label)
    private var lastNotify = 0L
    private var pkgReceiver: BroadcastReceiver? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var lastTransport: String? = null

    override fun onCreate() {
        super.onCreate()
        cfg = Config(this)
        ensureChannel(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown("Protection turned off")
            stopSelf()
            return START_NOT_STICKY
        }
        // ACTION_START, "android.net.VpnService" (always-on) or a sticky restart with null intent
        ServiceCompat.startForeground(this, NOTIF_ID, notification(), if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0)
        if (!active) startProtection()
        return START_STICKY
    }

    private fun startProtection() {
        if (prepare(this) != null) {
            fail("VPN permission missing: open OPH-S and turn protection on")
            return
        }
        val b = Builder()
            .setSession("OPH-S")
            .addAddress(VPN_ADDR, 32)
            .addDnsServer(VPN_DNS)
            .addRoute(VPN_DNS, 32) // only DNS enters the TUN
            .setMtu(1500)
            .setBlocking(true)
            .setConfigureIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
        runCatching { b.addDisallowedApplication(packageName) } // our own forwarding/agent sockets bypass the VPN
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        val fd = runCatching { b.establish() }.getOrNull()
        if (fd == null) {
            fail("Could not start the VPN (another always-on VPN may be active)")
            return
        }
        tun = fd
        tunOut = FileOutputStream(fd.fileDescriptor)
        wakeFds = Os.pipe()
        active = true
        pcDownUntil = 0
        pool = ThreadPoolExecutor(2, 8, 30, TimeUnit.SECONDS, LinkedBlockingQueue(256), ThreadPoolExecutor.DiscardOldestPolicy())
        reader = Thread({ readLoop(fd.fileDescriptor) }, "ophs-tun").apply { start() }
        AgentChannel.protector = { s -> protect(s) }
        AgentChannel.start(this)
        registerWatchers()
        AppState.update { it.copy(protecting = true) }
        AgentChannel.emit(this, WireEvent.log("OPH-S protection started (DNS monitoring on)", "info"))
        updateNotification(force = true)
    }

    private fun fail(msg: String) {
        cfg.lastError = msg
        AppState.update { it.copy(protecting = false, lastError = msg) }
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ---------------------------------------------------------------- TUN

    /** Poll the TUN and a wake pipe (DNS66 pattern) so shutdown never blocks on read(). */
    private fun readLoop(fd: FileDescriptor) {
        val input = FileInputStream(fd)
        val buf = ByteArray(32767)
        val wake = wakeFds?.get(0) ?: return
        try {
            while (active) {
                val pTun = StructPollfd().apply { this.fd = fd; events = OsConstants.POLLIN.toShort() }
                val pWake = StructPollfd().apply { this.fd = wake; events = OsConstants.POLLIN.toShort() }
                Os.poll(arrayOf(pTun, pWake), 5_000)
                if (!active || pWake.revents.toInt() != 0) break
                if ((pTun.revents.toInt() and OsConstants.POLLIN) == 0) continue
                val n = input.read(buf)
                if (n <= 0) continue
                val pkt = Packet.parseUdp4(buf, n) ?: continue // IPv6, TCP (DoT/TCP DNS) and junk are dropped
                if (Packet.ipString(pkt.dstIp) != VPN_DNS || pkt.dstPort != 53) continue
                pool?.execute { handle(pkt) }
            }
        } catch (_: Exception) {
        }
    }

    private fun handle(pkt: Packet.Udp4) {
        val q = Dns.parseQuestion(pkt.payload)
        var via = "pc"
        var resp: ByteArray? = null
        val pcHost = cfg.enrollment?.host
        if (pcHost != null && System.currentTimeMillis() >= pcDownUntil) {
            resp = exchange(pcHost, pkt.payload, PC_TIMEOUT_MS)
            if (resp == null) pcDownUntil = System.currentTimeMillis() + 30_000
        }
        if (resp == null) {
            via = "fallback"
            resp = exchange(cfg.fallbackDns.ifBlank { "1.1.1.1" }, pkt.payload, FALLBACK_TIMEOUT_MS)
        }
        if (resp == null) {
            via = "servfail"
            resp = Dns.servfail(pkt.payload)
        }
        writeTun(Packet.reply(pkt, resp, ipId.getAndIncrement()))
        if (q != null) record(pkt, q, via)
    }

    private fun exchange(server: String, query: ByteArray, timeoutMs: Int): ByteArray? = try {
        DatagramSocket().use { s ->
            protect(s)
            s.soTimeout = timeoutMs
            val addr = Packet.ipBytes(server)?.let { InetAddress.getByAddress(it) } ?: InetAddress.getByName(server)
            s.send(DatagramPacket(query, query.size, InetSocketAddress(addr, 53)))
            val buf = ByteArray(8192)
            val dp = DatagramPacket(buf, buf.size)
            var out: ByteArray? = null
            val deadline = System.currentTimeMillis() + timeoutMs
            while (out == null && System.currentTimeMillis() < deadline) {
                s.receive(dp)
                // accept only an answer with our transaction id
                if (dp.length >= 12 && buf[0] == query[0] && buf[1] == query[1]) out = buf.copyOf(dp.length)
            }
            out
        }
    } catch (_: Exception) {
        null
    }

    private fun writeTun(p: ByteArray) {
        val o = tunOut ?: return
        synchronized(o) { runCatching { o.write(p) } }
    }

    // ---------------------------------------------------------------- attribution + events

    private fun owner(pkt: Packet.Udp4): Pair<String, String> {
        if (Build.VERSION.SDK_INT < 29) return "unknown" to "unknown"
        val uid = try {
            getSystemService(ConnectivityManager::class.java).getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(InetAddress.getByAddress(pkt.srcIp), pkt.srcPort),
                InetSocketAddress(InetAddress.getByAddress(pkt.dstIp), pkt.dstPort),
            )
        } catch (_: Exception) {
            Process.INVALID_UID
        }
        if (uid == Process.INVALID_UID || uid < 0) return "unknown" to "unknown"
        return apps.getOrPut(uid) {
            val pm = packageManager
            val pkg = pm.getPackagesForUid(uid)?.firstOrNull()
            if (pkg == null) {
                val n = pm.getNameForUid(uid) ?: "uid $uid"
                n to if (uid == 0) "root" else if (uid == 1000) "Android System" else n
            } else {
                val label = runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
                pkg to label
            }
        }
    }

    private fun record(pkt: Packet.Udp4, q: Dns.Question, via: String) {
        val (pkg, label) = owner(pkt)
        val type = Dns.typeName(q.qtype)
        AppState.addQuery(DnsEntry(System.currentTimeMillis(), label, pkg, q.name, type, via))
        val emit = synchronized(dedupe) { dedupe.shouldEmit(pkg, q.name) }
        if (emit) AgentChannel.emit(this, WireEvent.dnsQuery(q.name, label, pkg, type, via))
        updateNotification()
    }

    private fun registerWatchers() {
        pkgReceiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                val pkg = i.data?.schemeSpecificPart ?: return
                val replacing = i.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                val label = runCatching {
                    packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
                }.getOrDefault(pkg)
                val msg = when (i.action) {
                    Intent.ACTION_PACKAGE_ADDED -> if (replacing) "App updated: $label ($pkg)" else "App installed: $label ($pkg)"
                    Intent.ACTION_PACKAGE_REMOVED -> if (replacing) return else "App removed: $pkg"
                    else -> return
                }
                apps.clear()
                AgentChannel.emit(c, WireEvent.log(msg, if (replacing) "info" else "low",
                    buildJsonObject { put("package", pkg); put("event", i.action); put("replacing", replacing) }))
            }
        }
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(this, pkgReceiver, f, ContextCompat.RECEIVER_EXPORTED)

        val cm = getSystemService(ConnectivityManager::class.java)
        lastTransport = null
        netCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val t = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "bluetooth"
                    else -> "other"
                }
                val prev = lastTransport
                if (t == prev) return
                lastTransport = t
                pcDownUntil = 0
                AgentChannel.kick()
                if (prev != null) AgentChannel.emit(this@DnsVpnService,
                    WireEvent.log("Network changed: $prev → $t", "info", buildJsonObject { put("transport", t); put("previous", prev) }))
            }

            override fun onLost(network: Network) {
                if (lastTransport != null) AgentChannel.emit(this@DnsVpnService,
                    WireEvent.log("Network lost (${lastTransport})", "info", buildJsonObject { put("transport", "none") }))
                lastTransport = null
            }
        }
        runCatching { cm.registerDefaultNetworkCallback(netCallback!!) }
    }

    private fun unregisterWatchers() {
        pkgReceiver?.let { runCatching { unregisterReceiver(it) } }
        pkgReceiver = null
        netCallback?.let { runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }
        netCallback = null
    }

    // ---------------------------------------------------------------- notification

    private fun notification(): Notification {
        val n = AppState.status.value.queries
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle("OPH-S protecting · $n queries")
            .setContentText(if (AppState.status.value.connected) "Connected to OPH PC" else "Not connected to OPH PC")
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    @Synchronized private fun updateNotification(force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force && now - lastNotify < 5_000) return
        lastNotify = now
        if (!active) return
        if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED || Build.VERSION.SDK_INT < 33) {
            getSystemService(NotificationManager::class.java).notify(NOTIF_ID, notification())
        }
    }

    // ---------------------------------------------------------------- lifecycle

    override fun onRevoke() {
        AgentChannel.emit(this, WireEvent.log("VPN permission revoked: OPH-S protection stopped (another VPN took over or the user revoked it)", "medium"))
        cfg.protect = false
        shutdown(null)
        stopSelf()
    }

    override fun onDestroy() {
        shutdown(null)
        super.onDestroy()
    }

    @Synchronized private fun shutdown(reason: String?) {
        if (!active) return
        if (reason != null) AgentChannel.emit(this, WireEvent.log("OPH-S: $reason", "low"))
        active = false
        wakeFds?.let { fds -> runCatching { Os.write(fds[1], byteArrayOf(1), 0, 1) } }
        runCatching { reader?.join(1_000) }
        pool?.shutdownNow()
        runCatching { tun?.close() }
        wakeFds?.forEach { runCatching { Os.close(it) } }
        wakeFds = null
        tun = null
        tunOut = null
        unregisterWatchers()
        AgentChannel.stop()
        AgentChannel.protector = null
        AppState.update { it.copy(protecting = false, connected = false) }
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }
}
