package com.oph.sentinel.core

/** Bounded FIFO outbox: keeps the newest [capacity] events, dropping the oldest. Thread-safe. */
class EventBuffer(val capacity: Int = 2000) {
    private val q = ArrayDeque<WireEvent>()
    var dropped = 0L
        private set

    @Synchronized fun add(e: WireEvent) {
        q.addLast(e)
        trim()
    }

    /** Remove and return up to one batch from the front. */
    @Synchronized fun takeBatch(): List<WireEvent> {
        val n = Frames.takeBatch(q)
        val out = ArrayList<WireEvent>(n)
        repeat(n) { out.add(q.removeFirst()) }
        if (n == 0 && q.isNotEmpty()) q.removeFirst().also { dropped++ } // single event > 200 KB: unsendable
        return out
    }

    /** Put an unacknowledged batch back at the front (then drop oldest if over capacity). */
    @Synchronized fun requeue(events: List<WireEvent>) {
        for (i in events.indices.reversed()) q.addFirst(events[i])
        trim()
    }

    @Synchronized fun snapshot(): List<WireEvent> = q.toList()
    @Synchronized fun size() = q.size
    @Synchronized fun clear() = q.clear()

    private fun trim() {
        while (q.size > capacity) {
            q.removeFirst()
            dropped++
        }
    }
}

/** Suppress repeats of the same (app, domain) within [windowMs]. Not thread-safe; use from one thread. */
class Deduper(private val windowMs: Long = 60_000, private val maxKeys: Int = 4096) {
    private val seen = HashMap<String, Long>()

    fun shouldEmit(app: String, domain: String, now: Long = System.currentTimeMillis()): Boolean {
        val k = "$app\u0000$domain"
        val last = seen[k]
        if (last != null && now - last < windowMs) return false
        if (seen.size >= maxKeys) seen.entries.removeAll { now - it.value >= windowMs }
        if (seen.size >= maxKeys) seen.clear()
        seen[k] = now
        return true
    }
}
