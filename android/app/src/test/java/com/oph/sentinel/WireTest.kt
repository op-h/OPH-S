package com.oph.sentinel

import com.oph.sentinel.core.Deduper
import com.oph.sentinel.core.Enrollment
import com.oph.sentinel.core.EventBuffer
import com.oph.sentinel.core.Frames
import com.oph.sentinel.core.WireEvent
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WireTest {
    private fun obj(s: String) = Json.parseToJsonElement(s).jsonObject

    @Test fun helloMatchesOphProtoFrame() {
        val h = obj(Frames.hello("tok\"en", "0123456789abcdef", "Pixel 8", "OPH-S 0.2.0"))
        assertEquals("hello", h["type"]!!.jsonPrimitive.content)
        assertEquals(1L, h["proto"]!!.jsonPrimitive.long)
        assertTrue(h["proto"]!!.jsonPrimitive.isString.not()) // u32, not "1"
        assertEquals("tok\"en", h["token"]!!.jsonPrimitive.content)
        assertEquals("0123456789abcdef", h["agent_id"]!!.jsonPrimitive.content)
        assertEquals("android", h["platform"]!!.jsonPrimitive.content)
        assertEquals(setOf("type", "proto", "token", "agent_id", "name", "platform", "version"), h.keys)
    }

    @Test fun batchEventsUseSnakeCaseAndNulls() {
        val e = WireEvent.dnsQuery("example.com", "Chrome", "com.android.chrome", "A", "pc")
        val b = obj(Frames.batch(listOf(e, WireEvent.log("App installed: X", "low"))))
        assertEquals("batch", b["type"]!!.jsonPrimitive.content)
        val ev = b["events"]!!.jsonArray[0].jsonObject
        assertEquals(setOf("ts", "source", "kind", "severity", "host", "src_ip", "dst_ip", "dst_port", "domain", "process", "message", "raw"), ev.keys)
        assertEquals("dns", ev["source"]!!.jsonPrimitive.content)
        assertEquals("dns.query", ev["kind"]!!.jsonPrimitive.content)
        assertEquals("info", ev["severity"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, ev["src_ip"])
        assertEquals(JsonNull, ev["dst_port"])
        assertEquals("Chrome", ev["process"]!!.jsonPrimitive.content)
        val raw = ev["raw"]!!.jsonObject
        assertEquals("com.android.chrome", raw["package"]!!.jsonPrimitive.content)
        assertEquals("A", raw["qtype"]!!.jsonPrimitive.content)
        assertEquals("pc", raw["via"]!!.jsonPrimitive.content)
        assertTrue(ev["ts"]!!.jsonPrimitive.long > 1_600_000_000_000)
        for (x in b["events"]!!.jsonArray) {
            val o = x.jsonObject
            assertTrue((o["source"]!!.jsonPrimitive.content to o["kind"]!!.jsonPrimitive.content) in WireEvent.ALLOWED)
        }
        assertEquals("""{"type":"ping"}""", Frames.ping())
    }

    @Test fun parsesServerFrames() {
        assertEquals(Frames.Incoming.Welcome(true, null), Frames.parse("""{"type":"welcome","ok":true,"error":null,"heartbeat_secs":30}"""))
        assertEquals(Frames.Incoming.Welcome(false, "invalid token"), Frames.parse("""{"type":"welcome","ok":false,"error":"invalid token","heartbeat_secs":0}"""))
        assertEquals(Frames.Incoming.Ack(17), Frames.parse("""{"type":"ack","received":17}"""))
        assertNull(Frames.parse("garbage"))
    }

    @Test fun eventJsonRoundTrip() {
        val e = WireEvent.log("hi", "medium")
        assertEquals(e, WireEvent.fromJson(e.toJson()))
    }

    @Test fun batchLimits() {
        val small = List(450) { WireEvent.log("m$it") }
        assertEquals(200, Frames.takeBatch(small))
        val big = List(10) { WireEvent.log("x".repeat(50_000)) }
        val n = Frames.takeBatch(big)
        assertTrue(n in 1..4)
        assertTrue(Frames.batch(big.take(n)).toByteArray().size + 1 <= Frames.MAX_BYTES)
    }

    @Test fun bufferIsBoundedDropOldest() {
        val b = EventBuffer(2000)
        repeat(2500) { b.add(WireEvent.log("e$it")) }
        assertEquals(2000, b.size())
        assertEquals(500L, b.dropped)
        val first = b.takeBatch()
        assertEquals(200, first.size)
        assertEquals("e500", first[0].message)
        b.requeue(first)
        assertEquals(2000, b.size())
        assertEquals("e500", b.snapshot()[0].message)
    }

    @Test fun dedupePerAppDomainPerMinute() {
        val d = Deduper()
        assertTrue(d.shouldEmit("a", "x.com", 0))
        assertFalse(d.shouldEmit("a", "x.com", 59_000))
        assertTrue(d.shouldEmit("b", "x.com", 59_000))
        assertTrue(d.shouldEmit("a", "x.com", 60_000))
    }

    @Test fun enrollmentUri() {
        val fp = "AB:CD:" + List(30) { "0F" }.joinToString(":")
        val e = Enrollment.parseUri("ophs://enroll?host=192.168.1.10&port=8443&token=abc%2Bdef&fp=$fp&name=My%20Phone")
        assertNotNull(e)
        assertEquals("192.168.1.10", e!!.host)
        assertEquals(8443, e.port)
        assertEquals("abc+def", e.token)
        assertEquals("abcd" + "0f".repeat(30), e.fingerprint)
        assertEquals("My Phone", e.name)
        assertEquals(fp, Enrollment.prettyFp(e.fingerprint))
        assertNull(Enrollment.parseUri("ophs://enroll?host=1.2.3.4&port=99999&token=a&fp=$fp"))
        assertNull(Enrollment.parseUri("ophs://enroll?host=1.2.3.4&port=1&token=a&fp=abc"))
        assertNull(Enrollment.parseUri("https://evil/?host=1.2.3.4"))
    }

    @Suppress("unused") private val keep = JsonObject(emptyMap())
}
