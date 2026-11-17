package com.oph.sentinel.net

import android.content.Context
import com.oph.sentinel.AppState
import com.oph.sentinel.BuildConfig
import com.oph.sentinel.Config
import com.oph.sentinel.core.AgentConnection
import com.oph.sentinel.core.EventBuffer
import com.oph.sentinel.core.WelcomeRejected
import com.oph.sentinel.core.WireEvent
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.io.File
import java.net.Socket

/**
 * Ships events to the enrolled OPH PC. One worker thread: connect -> hello/welcome -> batch/ack,
 * ping after 30 s idle, exponential backoff 5 -> 60 s. Pin mismatch and key rejection are fatal
 * (no retry, so a bad key never trips the server's failed-auth ban) until the user re-enrolls.
 * The outbox (<=2000 events, oldest dropped) is persisted to filesDir/outbox.jsonl.
 */
object AgentChannel {
    private const val IDLE_PING_MS = 30_000L
    private const val BACKOFF_MIN = 5_000L
    private const val BACKOFF_MAX = 60_000L

    val buffer = EventBuffer(2000)
    private lateinit var app: Context
    private lateinit var cfg: Config
    private var loaded = false
    @Volatile private var dirty = false
    @Volatile private var running = false
    @Volatile private var fatal = false
    @Volatile private var thread: Thread? = null
    private var old: Thread? = null
    @Volatile var protector: ((Socket) -> Unit)? = null
    private val signal = Object()
    private var pending = false
    @Volatile private var resetBackoff = false

    @Synchronized fun init(ctx: Context) {
        if (loaded) return
        app = ctx.applicationContext
        cfg = Config(app)
        loaded = true
        runCatching {
            outbox().takeIf { it.exists() }?.readLines()?.forEach { line ->
                runCatching { WireEvent.fromJson(Json.parseToJsonElement(line).jsonObject) }.getOrNull()?.let(buffer::add)
            }
        }
        AppState.update { it.copy(sentToday = cfg.sentToday, buffered = buffer.size(), lastError = cfg.lastError) }
    }

    /** Queue an event (works with or without a running channel; persisted lazily). */
    fun emit(ctx: Context, e: WireEvent) {
        init(ctx)
        buffer.add(e)
        dirty = true
        AppState.update { it.copy(buffered = buffer.size()) }
        if (thread == null) save() else wake()
    }

    @Synchronized fun start(ctx: Context) {
        init(ctx)
        if (running) return
        old?.let { runCatching { it.join(3_000) } } // previous worker finishing its final flush
        running = true
        thread = Thread(::loop, "ophs-agent").apply { isDaemon = true; start() }
    }

    /** Stop after a best-effort flush of what is buffered. */
    @Synchronized fun stop() {
        running = false
        wake()
        old = thread
        thread = null
    }

    /** Network changed or user re-enrolled: retry immediately. */
    fun kick(clearFatal: Boolean = false) {
        if (clearFatal) fatal = false
        resetBackoff = true
        wake()
    }

    private fun wake() = synchronized(signal) { pending = true; signal.notifyAll() }

    private fun waitFor(ms: Long) = synchronized(signal) {
        if (!pending && ms > 0) signal.wait(ms)
        pending = false
    }

    private fun loop() {
        var backoff = BACKOFF_MIN
        while (running) {
            if (fatal) { waitFor(60_000); continue }
            val en = cfg.enrollment
            if (en == null) {
                AppState.update { it.copy(connected = false, lastError = "Not enrolled with an OPH PC") }
                waitFor(30_000)
                continue
            }
            try {
                AgentConnection.open(
                    en.host, en.port, en.fingerprint, en.token, cfg.agentId, cfg.deviceName,
                    "OPH-S ${BuildConfig.VERSION_NAME}", protect = { s -> protector?.invoke(s) },
                ).use { conn ->
                    backoff = BACKOFF_MIN
                    setError(null)
                    AppState.update { it.copy(connected = true, fatal = false) }
                    var lastTx = System.currentTimeMillis()
                    var lastSave = 0L
                    while (true) {
                        val batch = buffer.takeBatch()
                        if (batch.isNotEmpty()) {
                            val n = try { conn.sendBatch(batch) } catch (e: Exception) { buffer.requeue(batch); throw e }
                            cfg.addSent(n)
                            dirty = true
                            lastTx = System.currentTimeMillis()
                            AppState.update { it.copy(sentToday = cfg.sentToday, buffered = buffer.size()) }
                            continue
                        }
                        if (!running) break
                        val now = System.currentTimeMillis()
                        if (dirty && now - lastSave > 15_000) { save(); lastSave = now }
                        if (now - lastTx >= IDLE_PING_MS) { conn.ping(); lastTx = now }
                        waitFor(IDLE_PING_MS - (System.currentTimeMillis() - lastTx))
                    }
                }
            } catch (e: Exception) {
                AppState.update { it.copy(connected = false) }
                val pin = AgentConnection.pinFailure(e)
                when {
                    pin != null -> {
                        fatal = true
                        setError("Certificate fingerprint mismatch: this is not the enrolled OPH PC (or its certificate changed). Re-enroll from the PC's QR code.", fatal = true)
                    }
                    e is WelcomeRejected && !e.reason.contains("busy", true) -> {
                        fatal = true
                        setError("PC rejected this device: ${e.reason}. Re-enroll with a new key.", fatal = true)
                    }
                    else -> {
                        setError("PC not reachable (${en.host}:${en.port}): ${e.message ?: e.javaClass.simpleName}. Retrying in ${backoff / 1000} s")
                        if (!running) break
                        resetBackoff = false
                        val until = System.currentTimeMillis() + backoff
                        // new events wake us too; only stop/kick may cut the backoff short
                        while (running && !resetBackoff && System.currentTimeMillis() < until) {
                            waitFor(until - System.currentTimeMillis())
                        }
                        backoff = if (resetBackoff) BACKOFF_MIN else (backoff * 2).coerceAtMost(BACKOFF_MAX)
                    }
                }
            }
        }
        save()
        AppState.update { it.copy(connected = false) }
    }

    private fun setError(msg: String?, fatal: Boolean = false) {
        cfg.lastError = msg
        AppState.update { it.copy(lastError = msg, fatal = fatal) }
    }

    private fun outbox() = File(app.filesDir, "outbox.jsonl")

    @Synchronized private fun save() {
        if (!loaded) return
        runCatching {
            val tmp = File(app.filesDir, "outbox.tmp")
            tmp.bufferedWriter().use { w -> buffer.snapshot().forEach { w.write(it.toJson().toString()); w.write("\n") } }
            tmp.renameTo(outbox())
            dirty = false
        }
    }
}
