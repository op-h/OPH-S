package com.oph.sentinel.core

/**
 * Minimal IPv4 + UDP handling for the DNS-only TUN (same technique as DNS66 /
 * personalDNSfilter: only the virtual DNS server address is routed into the TUN,
 * so every packet we see is a DNS query to that address).
 */
object Packet {
    const val PROTO_UDP = 17

    /** A parsed IPv4/UDP datagram. Addresses are 4-byte arrays. */
    class Udp4(
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val payload: ByteArray,
    )

    /** Parse an IPv4/UDP packet; returns null for anything else (IPv6, TCP, fragments, truncated, bad lengths). */
    fun parseUdp4(buf: ByteArray, len: Int = buf.size): Udp4? {
        if (len < 28) return null
        val version = (buf[0].toInt() ushr 4) and 0xF
        if (version != 4) return null
        val ihl = (buf[0].toInt() and 0xF) * 4
        if (ihl < 20 || len < ihl + 8) return null
        val totalLen = u16(buf, 2)
        if (totalLen < ihl + 8 || totalLen > len) return null
        val flagsFrag = u16(buf, 6)
        if ((flagsFrag and 0x3FFF) != 0) return null // fragmented (MF set or offset != 0)
        if ((buf[9].toInt() and 0xFF) != PROTO_UDP) return null
        val udpLen = u16(buf, ihl + 4)
        if (udpLen < 8 || ihl + udpLen > totalLen) return null
        return Udp4(
            srcIp = buf.copyOfRange(12, 16),
            dstIp = buf.copyOfRange(16, 20),
            srcPort = u16(buf, ihl),
            dstPort = u16(buf, ihl + 2),
            payload = buf.copyOfRange(ihl + 8, ihl + udpLen),
        )
    }

    /** Build an IPv4/UDP packet with valid IP header and UDP checksums. */
    fun buildUdp4(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray, id: Int = 0): ByteArray {
        require(srcIp.size == 4 && dstIp.size == 4)
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        require(total <= 0xFFFF)
        val p = ByteArray(total)
        p[0] = 0x45
        put16(p, 2, total)
        put16(p, 4, id and 0xFFFF)
        put16(p, 6, 0x4000) // DF, no fragmentation
        p[8] = 64 // TTL
        p[9] = PROTO_UDP.toByte()
        System.arraycopy(srcIp, 0, p, 12, 4)
        System.arraycopy(dstIp, 0, p, 16, 4)
        put16(p, 10, checksum(p, 0, 20, 0))
        put16(p, 20, srcPort)
        put16(p, 22, dstPort)
        put16(p, 24, udpLen)
        System.arraycopy(payload, 0, p, 28, payload.size)
        put16(p, 26, udpChecksum(srcIp, dstIp, p, 20, udpLen))
        return p
    }

    /** Reply to [query]: swaps addresses/ports and wraps [payload]. */
    fun reply(query: Udp4, payload: ByteArray, id: Int = 0): ByteArray =
        buildUdp4(query.dstIp, query.srcIp, query.dstPort, query.srcPort, payload, id)

    /** RFC 768 checksum over pseudo header + UDP header + data; a computed 0 is sent as 0xFFFF. */
    fun udpChecksum(src: ByteArray, dst: ByteArray, buf: ByteArray, off: Int, udpLen: Int): Int {
        var sum = 0L
        sum += (u16(src, 0) + u16(src, 2) + u16(dst, 0) + u16(dst, 2)).toLong()
        sum += (PROTO_UDP + udpLen).toLong()
        val saved0 = buf[off + 6]
        val saved1 = buf[off + 7]
        buf[off + 6] = 0; buf[off + 7] = 0 // checksum field must be zero while summing
        val c = checksum(buf, off, udpLen, sum)
        buf[off + 6] = saved0; buf[off + 7] = saved1
        return if (c == 0) 0xFFFF else c
    }

    /** Internet checksum (RFC 1071) of buf[off, off+len) plus an initial partial sum. */
    fun checksum(buf: ByteArray, off: Int, len: Int, initial: Long): Int {
        var sum = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += (((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < end) sum += ((buf[i].toInt() and 0xFF) shl 8).toLong()
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** True if the IPv4 header checksum of [buf] verifies. */
    fun ipHeaderValid(buf: ByteArray): Boolean = checksum(buf, 0, (buf[0].toInt() and 0xF) * 4, 0) == 0

    /** True if the UDP checksum of an IPv4 packet verifies (or is absent). */
    fun udpChecksumValid(buf: ByteArray): Boolean {
        val ihl = (buf[0].toInt() and 0xF) * 4
        if (u16(buf, ihl + 6) == 0) return true
        val udpLen = u16(buf, ihl + 4)
        var sum = (u16(buf, 12) + u16(buf, 14) + u16(buf, 16) + u16(buf, 18) + PROTO_UDP + udpLen).toLong()
        return checksum(buf, ihl, udpLen, sum) == 0
    }

    fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte()
    }

    fun ipString(a: ByteArray) = a.joinToString(".") { (it.toInt() and 0xFF).toString() }

    /** Strict dotted-quad parser (no DNS lookups, no leading zeros). */
    fun ipBytes(s: String): ByteArray? {
        val parts = s.trim().split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' } || (p.length > 1 && p[0] == '0')) return null
            val n = p.toInt()
            if (n > 255) return null
            out[i] = n.toByte()
        }
        return out
    }
}
