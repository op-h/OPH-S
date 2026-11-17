package com.oph.sentinel

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableStateOf
import androidx.core.content.ContextCompat
import com.oph.sentinel.core.Enrollment
import com.oph.sentinel.ui.OphRoot
import com.oph.sentinel.ui.OphTheme
import com.oph.sentinel.vpn.DnsVpnService

class MainActivity : ComponentActivity() {
    /** Enrollment proposed by a deep link / QR, waiting for the user's confirmation. */
    val pendingEnroll = mutableStateOf<Enrollment?>(null)
    val deepLinkError = mutableStateOf<String?>(null)

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == RESULT_OK) DnsVpnService.start(this)
        else AppState.update { it.copy(lastError = "VPN permission was not granted") }
    }
    private val notifPerm = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(SystemBarStyle.dark(0xFF13161A.toInt()), SystemBarStyle.dark(0xFF13161A.toInt()))
        super.onCreate(savedInstanceState)
        handleIntent(intent)
        setContent { OphTheme { OphRoot(this) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(i: Intent?) {
        val data = i?.data ?: return
        if (data.scheme != "ophs") return
        val e = Enrollment.parseUri(data.toString())
        if (e == null) deepLinkError.value = "This enrollment link is invalid or incomplete."
        else pendingEnroll.value = e
    }

    fun setProtection(on: Boolean) {
        if (!on) {
            DnsVpnService.stop(this)
            return
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else DnsVpnService.start(this)
    }
}
