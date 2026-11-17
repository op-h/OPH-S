package com.oph.sentinel.core

/** Just enough DNS (RFC 1035) to log the question and synthesise SERVFAIL. */
object Dns {
    class Question(val name: String, val qtype: Int, val end: Int)

    /** Parse the first question. Returns null for responses, malformed or empty queries. */
    fun parseQuestion(msg: ByteArray): Question? {
        if (msg.size < 12) return null
        if ((msg[2].toInt() and 0x80) != 0) return null // QR=1: a response, not a query
        if (Packet.u16(msg, 4) < 1) return null
        val (name, next) = readName(msg, 12) ?: return null
        if (next + 4 > msg.size) return null
        return Question(name, Packet.u16(msg, next), next + 4)
    }

    /**
     * Read a (possibly compressed) domain name at [start]. Returns the lower-cased dotted name
     * and the offset just after the name. Rejects pointer loops, over-long names and non-LDH labels.
     */
    fun readName(msg: ByteArray, start: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var pos = start
        var after = -1
        var jumps = 0
        while (true) {
            if (pos >= msg.size) return null
            val len = msg[pos].toInt() and 0xFF
            if (len == 0) {
                if (after < 0) after = pos + 1
                break
            } else if ((len and 0xC0) == 0xC0) {
                if (pos + 1 >= msg.size || ++jumps > 16) return null
                if (after < 0) after = pos + 2
                pos = ((len and 0x3F) shl 8) or (msg[pos + 1].toInt() and 0xFF)
            } else if ((len and 0xC0) != 0) {
                return null
            } else {
                if (pos + 1 + len > msg.size) return null
                if (sb.isNotEmpty()) sb.append('.')
                for (i in pos + 1..pos + len) {
                    val c = (msg[i].toInt() and 0xFF).toChar()
                    val ok = c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-' || c == '_'
                    if (!ok) return null
                    sb.append(c.lowercaseChar())
                }
                if (sb.length > 253) return null
                pos += 1 + len
            }
        }
        if (sb.isEmpty()) return null // root query: nothing to log
        return sb.toString() to after
    }

    /** SERVFAIL answer for [query] (same id and question, QR=1, RA=1, RCODE=2). */
    fun servfail(query: ByteArray): ByteArray {
        val q = parseQuestion(query)
        val end = q?.end ?: 12
        val out = query.copyOf(end.coerceIn(12, maxOf(12, query.size)))
        out[2] = ((query.getOrElse(2) { 0 }.toInt() and 0x79) or 0x80).toByte() // QR=1, keep opcode + RD
        out[3] = 0x82.toByte() // RA=1, RCODE=2
        Packet.put16(out, 4, if (q != null) 1 else 0)
        Packet.put16(out, 6, 0); Packet.put16(out, 8, 0); Packet.put16(out, 10, 0)
        return out
    }

    fun typeName(t: Int): String = when (t) {
        1 -> "A"; 2 -> "NS"; 5 -> "CNAME"; 6 -> "SOA"; 12 -> "PTR"; 15 -> "MX"; 16 -> "TXT"
        28 -> "AAAA"; 33 -> "SRV"; 64 -> "SVCB"; 65 -> "HTTPS"; 255 -> "ANY"
        else -> "TYPE$t"
    }

    /** Encode a standard recursive query (used by tests and the PC reachability probe). */
    fun buildQuery(id: Int, name: String, qtype: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(id ushr 8); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00) // RD
        out.write(0); out.write(1); repeat(6) { out.write(0) }
        for (label in name.trim('.').split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0)
        out.write(qtype ushr 8); out.write(qtype and 0xFF)
        out.write(0); out.write(1)
        return out.toByteArray()
    }
}
