package com.oph.sentinel

import com.oph.sentinel.core.Dns
import com.oph.sentinel.core.Packet
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketTest {
    private val client = byteArrayOf(10, 111, 222.toByte(), 1)
    private val vdns = byteArrayOf(10, 111, 222.toByte(), 2)

    /** Real capture: `dig example.com` from 192.168.0.31:57417 to 192.168.0.1:53, checksums from Wireshark. */
    private fun hex(s: String) = s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun ipv4HeaderChecksumKnownVector() {
        // Classic RFC 1071 worked example header (wikipedia "IPv4 header checksum"): checksum 0xB861
        val h = hex("4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7")
        assertEquals(0xB861, Packet.checksum(h, 0, 20, 0))
    }

    @Test fun buildThenParseRoundTrip() {
        val q = Dns.buildQuery(0x1234, "Example.COM", 1)
        val pkt = Packet.buildUdp4(client, vdns, 40000, 53, q, id = 7)
        assertEquals(20 + 8 + q.size, pkt.size)
        assertTrue("IPv4 header checksum", Packet.ipHeaderValid(pkt))
        assertTrue("UDP checksum", Packet.udpChecksumValid(pkt))
        val p = assertNotNullAnd(Packet.parseUdp4(pkt))
        assertArrayEquals(client, p.srcIp)
        assertArrayEquals(vdns, p.dstIp)
        assertEquals(40000, p.srcPort)
        assertEquals(53, p.dstPort)
        assertArrayEquals(q, p.payload)
    }

    @Test fun replySwapsEndpointsWithValidChecksums() {
        val q = Dns.buildQuery(0xBEEF, "a.b", 28)
        val p = Packet.parseUdp4(Packet.buildUdp4(client, vdns, 5353, 53, q))!!
        val ans = Dns.servfail(q)
        val r = Packet.reply(p, ans, 99)
        val back = Packet.parseUdp4(r)!!
        assertArrayEquals(vdns, back.srcIp)
        assertArrayEquals(client, back.dstIp)
        assertEquals(53, back.srcPort)
        assertEquals(5353, back.dstPort)
        assertTrue(Packet.ipHeaderValid(r))
        assertTrue(Packet.udpChecksumValid(r))
        // odd-length payload exercises the padding byte of the checksum
        val odd = Packet.buildUdp4(client, vdns, 1, 2, byteArrayOf(1, 2, 3))
        assertTrue(Packet.udpChecksumValid(odd))
    }

    @Test fun corruptedChecksumDetected() {
        val pkt = Packet.buildUdp4(client, vdns, 1000, 53, Dns.buildQuery(1, "x.org", 1))
        pkt[pkt.size - 1] = (pkt[pkt.size - 1] + 1).toByte()
        assertTrue(!Packet.udpChecksumValid(pkt))
    }

    @Test fun rejectsNonIpv4UdpAndJunk() {
        val ok = Packet.buildUdp4(client, vdns, 1000, 53, Dns.buildQuery(1, "x.org", 1))
        val v6 = ok.copyOf().also { it[0] = 0x60 }
        assertNull(Packet.parseUdp4(v6))
        val tcp = ok.copyOf().also { it[9] = 6 }
        assertNull(Packet.parseUdp4(tcp))
        val frag = ok.copyOf().also { Packet.put16(it, 6, 0x2000) } // MF
        assertNull(Packet.parseUdp4(frag))
        assertNull(Packet.parseUdp4(ok, 20)) // truncated
        val badLen = ok.copyOf().also { Packet.put16(it, 24, 4000) }
        assertNull(Packet.parseUdp4(badLen))
        assertNull(Packet.parseUdp4(ByteArray(0)))
    }

    @Test fun ipParsing() {
        assertArrayEquals(byteArrayOf(1, 1, 1, 1), Packet.ipBytes("1.1.1.1"))
        assertNull(Packet.ipBytes("1.1.1"))
        assertNull(Packet.ipBytes("256.1.1.1"))
        assertNull(Packet.ipBytes("01.1.1.1"))
        assertNull(Packet.ipBytes("dns.google"))
        assertEquals("10.111.222.2", Packet.ipString(vdns))
    }

    private fun <T> assertNotNullAnd(v: T?): T { assertNotNull(v); return v!! }
}

class DnsTest {
    @Test fun extractsQnameAndType() {
        val q = Dns.parseQuestion(Dns.buildQuery(1, "WWW.Example.com.", 28))!!
        assertEquals("www.example.com", q.name)
        assertEquals(28, q.qtype)
        assertEquals("AAAA", Dns.typeName(q.qtype))
    }

    @Test fun realWireQuery() {
        // dig +noedns example.com A, id 0x8a3c
        val msg = byteArrayOf(
            0x8a.toByte(), 0x3c, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 0,
            7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0, 0, 1, 0, 1,
        )
        val q = Dns.parseQuestion(msg)!!
        assertEquals("example.com", q.name)
        assertEquals(1, q.qtype)
    }

    @Test fun rejectsResponsesLoopsAndBadLabels() {
        val resp = Dns.buildQuery(1, "x.org", 1).also { it[2] = (it[2].toInt() or 0x80).toByte() }
        assertNull(Dns.parseQuestion(resp))
        // compression pointer to itself
        val loop = byteArrayOf(0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0.toByte(), 12, 0, 1, 0, 1)
        assertNull(Dns.parseQuestion(loop))
        // label with CRLF / space must be rejected (could inject into logs)
        val bad = Dns.buildQuery(1, "ab.cd", 1).also { it[13] = '\n'.code.toByte() }
        assertNull(Dns.parseQuestion(bad))
        // truncated
        assertNull(Dns.parseQuestion(Dns.buildQuery(1, "example.com", 1).copyOf(20)))
        assertNull(Dns.parseQuestion(ByteArray(5)))
    }

    @Test fun followsCompressionPointer() {
        // question name = pointer to "x.org" stored after the question section (unusual but legal)
        val base = Dns.buildQuery(1, "a", 1) // 12 hdr + [1 'a' 0] + 4
        val name = byteArrayOf(1, 'x'.code.toByte(), 3, 'o'.code.toByte(), 'r'.code.toByte(), 'g'.code.toByte(), 0)
        val msg = base.copyOf(12) + byteArrayOf(0xC0.toByte(), 18, 0, 1, 0, 1) + name
        val q = Dns.parseQuestion(msg)!!
        assertEquals("x.org", q.name)
        assertEquals(18, q.end)
    }

    @Test fun servfailKeepsIdAndQuestion() {
        val q = Dns.buildQuery(0xABCD, "example.com", 1)
        val s = Dns.servfail(q)
        assertEquals(0xAB.toByte(), s[0]); assertEquals(0xCD.toByte(), s[1])
        assertTrue((s[2].toInt() and 0x80) != 0) // QR
        assertEquals(2, s[3].toInt() and 0x0F) // SERVFAIL
        assertEquals(1, Packet.u16(s, 4))
        assertEquals(q.size, s.size)
        assertEquals(0, Packet.u16(s, 6))
    }
}
