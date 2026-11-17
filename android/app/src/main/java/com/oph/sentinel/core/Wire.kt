package com.oph.sentinel.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/** Mirror of oph-proto `WireEvent` (crates/oph-proto/src/lib.rs). */
data class WireEvent(
    val ts: Long,
    val source: String,
    val kind: String,
    val severity: String,
    val host: String = "",
    val srcIp: String? = null,
    val dstIp: String? = null,
    val dstPort: Int? = null,
    val domain: String? = null,
    val process: String? = null,
    val message: String = "",
    val raw: JsonObject = JsonObject(emptyMap()),
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("ts", ts)
        put("source", source)
        put("kind", kind)
        put("severity", severity)
        put("host", host)
        put("src_ip", srcIp)
        put("dst_ip", dstIp)
        put("dst_port", dstPort)
        put("domain", domain)
        put("process", process)
        put("message", message)
        put("raw", raw)
    }

    /** Serialized size in bytes; used to keep a batch line under 200 KB. */
    fun approxSize(): Int = toJson().toString().toByteArray(Charsets.UTF_8).size

    companion object {
        /** The only (source, kind) pairs the server accepts from agents (ingest.rs AGENT_KINDS). */
        val ALLOWED = setOf("dns" to "dns.query", "agent" to "agent.log", "conn" to "conn.open")
        val SEVERITIES = listOf("info", "low", "medium", "high", "critical")

        fun dnsQuery(domain: String, app: String, pkg: String, qtype: String, via: String) = WireEvent(
            ts = System.currentTimeMillis(), source = "dns", kind = "dns.query", severity = "info",
            domain = domain, process = app, message = "$app → $domain ($qtype)",
            raw = buildJsonObject { put("package", pkg); put("qtype", qtype); put("via", via) },
        )

        fun log(message: String, severity: String = "info", raw: JsonObject = JsonObject(emptyMap())) = WireEvent(
            ts = System.currentTimeMillis(), source = "agent", kind = "agent.log",
            severity = if (severity in SEVERITIES) severity else "info",
            process = "OPH-S", message = message, raw = raw,
        )

        fun fromJson(o: JsonObject): WireEvent? = runCatching {
            fun s(k: String) = (o[k] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull
            WireEvent(
                ts = (o["ts"] as JsonPrimitive).longOrNull!!,
                source = s("source")!!, kind = s("kind")!!, severity = s("severity") ?: "info",
                host = s("host") ?: "", srcIp = s("src_ip"), dstIp = s("dst_ip"),
                dstPort = (o["dst_port"] as? JsonPrimitive)?.intOrNull, domain = s("domain"),
                process = s("process"), message = s("message") ?: "",
                raw = (o["raw"] as? JsonObject) ?: JsonObject(emptyMap()),
            )
        }.getOrNull()
    }
}

/** Frames of the line-delimited agent protocol (oph-proto `Frame`, serde tag = "type", snake_case). */
object Frames {
    const val PROTO = 1
    const val MAX_EVENTS = 200
    const val MAX_BYTES = 200 * 1024

    fun hello(token: String, agentId: String, name: String, version: String): String = buildJsonObject {
        put("type", "hello")
        put("proto", PROTO)
        put("token", token)
        put("agent_id", agentId)
        put("name", name)
        put("platform", "android")
        put("version", version)
    }.toString()

    fun batch(events: List<WireEvent>): String =
        JsonObject(mapOf("type" to JsonPrimitive("batch"), "events" to JsonArray(events.map { it.toJson() }))).toString()

    fun ping(): String = """{"type":"ping"}"""

    /** How many events from the front of [events] fit in one batch (<=200 events, <=200 KB line). */
    fun takeBatch(events: List<WireEvent>): Int {
        var bytes = 32 // {"type":"batch","events":[]} + newline
        var n = 0
        for (e in events) {
            if (n >= MAX_EVENTS) break
            val s = e.approxSize() + 1
            if (bytes + s > MAX_BYTES) break
            bytes += s
            n++
        }
        return n
    }

    sealed class Incoming {
        data class Welcome(val ok: Boolean, val error: String?) : Incoming()
        data class Ack(val received: Int) : Incoming()
        data class Other(val type: String?) : Incoming()
    }

    fun parse(line: String): Incoming? {
        val o = runCatching { Json.parseToJsonElement(line).jsonObject }.getOrNull() ?: return null
        return when (val type = (o["type"] as? JsonPrimitive)?.contentOrNull) {
            "welcome" -> Incoming.Welcome(
                (o["ok"] as? JsonPrimitive)?.booleanOrNull ?: false,
                (o["error"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull,
            )
            "ack" -> Incoming.Ack((o["received"] as? JsonPrimitive)?.intOrNull ?: 0)
            else -> Incoming.Other(type)
        }
    }
}

/** Parsed `ophs://enroll?host=..&port=..&token=..&fp=..&name=..` link. */
data class Enrollment(val host: String, val port: Int, val token: String, val fingerprint: String, val name: String) {
    companion object {
        /** Normalise a SHA-256 fingerprint ("AB:CD:.." or "abcd..") to 64 lower-case hex chars, or null. */
        fun normalizeFp(fp: String): String? {
            val h = fp.filter { it != ':' && !it.isWhitespace() }.lowercase()
            return h.takeIf { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
        }

        /** "abcd.." -> "AB:CD:.." (the format the desktop UI shows). */
        fun prettyFp(fp: String): String = fp.uppercase().chunked(2).joinToString(":")

        fun parseUri(uri: String): Enrollment? {
            val s = uri.trim()
            if (!s.startsWith("ophs://enroll", ignoreCase = true)) return null
            val q = s.substringAfter('?', "")
            val m = q.split('&').filter { it.contains('=') }.associate {
                val (k, v) = it.split('=', limit = 2)
                k to runCatching { java.net.URLDecoder.decode(v, "UTF-8") }.getOrDefault(v)
            }
            return validate(m["host"], m["port"], m["token"], m["fp"], m["name"])
        }

        fun validate(host: String?, port: String?, token: String?, fp: String?, name: String?): Enrollment? {
            val h = host?.trim().orEmpty()
            if (h.isEmpty() || h.length > 253 || h.any { it.isWhitespace() || it == '/' || it == '@' }) return null
            val p = port?.trim()?.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            val t = token?.trim().orEmpty().takeIf { it.isNotEmpty() && it.length <= 512 } ?: return null
            val f = normalizeFp(fp.orEmpty()) ?: return null
            val n = name?.trim().orEmpty().filter { !it.isISOControl() }.take(64)
            return Enrollment(h, p, t, f, n)
        }
    }
}
