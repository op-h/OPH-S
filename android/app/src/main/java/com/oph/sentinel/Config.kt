package com.oph.sentinel

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import com.oph.sentinel.core.Enrollment
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Enrollment + settings in private SharedPreferences (MODE_PRIVATE, excluded from backup). */
class Config(ctx: Context) {
    private val p: SharedPreferences = ctx.applicationContext.getSharedPreferences("ophs", Context.MODE_PRIVATE)

    val enrollment: Enrollment?
        get() {
            val host = p.getString("host", null) ?: return null
            val token = p.getString("token", null) ?: return null
            val fp = p.getString("fp", null) ?: return null
            return Enrollment(host, p.getInt("port", 0), token, fp, deviceName)
        }

    fun enroll(e: Enrollment) {
        val ed = p.edit().putString("host", e.host).putInt("port", e.port).putString("token", e.token)
            .putString("fp", e.fingerprint).putString("last_error", null)
        if (e.name.isNotBlank()) ed.putString("name", e.name)
        ed.apply()
    }

    fun unenroll() {
        p.edit().remove("host").remove("port").remove("token").remove("fp").putBoolean("protect", false)
            .putString("last_error", null).apply()
    }

    /** Stable random agent id (16 hex), created once per install. */
    val agentId: String
        get() = p.getString("agent_id", null) ?: ByteArray(8).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }.also { p.edit().putString("agent_id", it).apply() }

    var deviceName: String
        get() = p.getString("name", null)?.takeIf { it.isNotBlank() } ?: (Build.MODEL ?: "Android")
        set(v) = p.edit().putString("name", v.trim().take(64)).apply()

    var fallbackDns: String
        get() = p.getString("fallback_dns", null) ?: "1.1.1.1"
        set(v) = p.edit().putString("fallback_dns", v.trim()).apply()

    /** User intent: protection should be on (used by BOOT_COMPLETED and always-on). */
    var protect: Boolean
        get() = p.getBoolean("protect", false)
        set(v) = p.edit().putBoolean("protect", v).apply()

    var lastError: String?
        get() = p.getString("last_error", null)
        set(v) = p.edit().putString("last_error", v).apply()

    /** Events acknowledged by the PC today (resets at local midnight). */
    val sentToday: Int
        get() = if (p.getString("sent_day", "") == today()) p.getInt("sent_count", 0) else 0

    fun addSent(n: Int) {
        val d = today()
        val cur = if (p.getString("sent_day", "") == d) p.getInt("sent_count", 0) else 0
        p.edit().putString("sent_day", d).putInt("sent_count", cur + n).apply()
    }

    private fun today() = SimpleDateFormat("yyyyMMdd", Locale.US).format(Date())
}
