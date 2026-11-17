package com.oph.sentinel

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

data class DnsEntry(val ts: Long, val app: String, val pkg: String, val domain: String, val qtype: String, val via: String)

data class Status(
    val protecting: Boolean = false,
    val connected: Boolean = false,
    val sentToday: Int = 0,
    val queries: Long = 0,
    val buffered: Int = 0,
    val lastError: String? = null,
    /** Set when the channel stopped for good (pin mismatch / key rejected) until re-enroll. */
    val fatal: Boolean = false,
)

/** Process-wide live state observed by the Compose UI and the notification. */
object AppState {
    private val _status = MutableStateFlow(Status())
    val status: StateFlow<Status> = _status
    private val _recent = MutableStateFlow<List<DnsEntry>>(emptyList())
    val recent: StateFlow<List<DnsEntry>> = _recent

    fun update(f: (Status) -> Status) = _status.update(f)

    fun addQuery(e: DnsEntry) {
        _recent.update { (listOf(e) + it).take(50) }
        _status.update { it.copy(queries = it.queries + 1) }
    }
}
