package com.oph.sentinel

import android.app.Application
import com.oph.sentinel.net.AgentChannel
import com.oph.sentinel.vpn.DnsVpnService

class OphApp : Application() {
    override fun onCreate() {
        super.onCreate()
        DnsVpnService.ensureChannel(this)
        AgentChannel.init(this)
    }
}
