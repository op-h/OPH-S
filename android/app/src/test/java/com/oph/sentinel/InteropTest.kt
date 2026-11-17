package com.oph.sentinel

import com.oph.sentinel.core.AgentConnection
import com.oph.sentinel.core.WelcomeRejected
import com.oph.sentinel.core.WireEvent
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Talks to a real OPH Sentinel core (app/src-tauri/src/ingest.rs) with the exact code the app uses.
 * Skipped unless run with:
 *   gradlew test -Pophs.it.host=127.0.0.1 -Pophs.it.port=18443 -Pophs.it.token=<key> -Pophs.it.fp=<sha256>
 */
class InteropTest {
    private val host = System.getProperty("ophs.it.host")
    private val port = System.getProperty("ophs.it.port")?.toInt() ?: 8443
    private val token = System.getProperty("ophs.it.token")
    private val fp = System.getProperty("ophs.it.fp")?.filter { it != ':' }?.lowercase()

    @Test fun helloBatchAckPing() {
        assumeTrue("set -Pophs.it.host to run", host != null && token != null && fp != null)
        AgentConnection.open(host!!, port, fp!!, token!!, "0a1b2c3d4e5f6789", "OPH-S interop", "OPH-S test").use { c ->
            val events = listOf(
                WireEvent.dnsQuery("interop-test.example.com", "Interop", "com.oph.sentinel.test", "A", "pc"),
                WireEvent.log("OPH-S interop test event", "low", buildJsonObject { put("test", true) }),
                WireEvent(ts = System.currentTimeMillis(), source = "conn", kind = "conn.open", severity = "info",
                    dstIp = "1.1.1.1", dstPort = 443, process = "Interop", message = "conn test"),
            )
            assertEquals(3, c.sendBatch(events))
            c.ping()
            assertEquals(1, c.sendBatch(listOf(WireEvent.log("after ping"))))
            println("INTEROP OK: hello/welcome, batch/ack(3), ping, batch/ack(1)")
        }
    }

    @Test fun wrongPinIsRejected() {
        assumeTrue(host != null && token != null && fp != null)
        try {
            AgentConnection.open(host!!, port, "00".repeat(32), token!!, "0a1b2c3d4e5f6789", "x", "x").close()
            fail("connected despite wrong pin")
        } catch (e: Exception) {
            assertNotNull("pin failure expected, got $e", AgentConnection.pinFailure(e))
            println("INTEROP OK: wrong fingerprint -> ${e.javaClass.simpleName}: fingerprint mismatch")
        }
    }

    @Test fun badTokenGetsWelcomeFalse() {
        assumeTrue(host != null && token != null && fp != null)
        try {
            AgentConnection.open(host!!, port, fp!!, "definitely-wrong-token", "0a1b2c3d4e5f6789", "x", "x").close()
            fail("connected with a wrong token")
        } catch (e: WelcomeRejected) {
            println("INTEROP OK: bad token -> welcome ok=false error='${e.reason}'")
        }
    }
}
