package com.oph.sentinel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.oph.sentinel.core.WireEvent
import com.oph.sentinel.net.AgentChannel
import com.oph.sentinel.vpn.DnsVpnService

/** BOOT_COMPLETED / app update: log it and restart protection if it was on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val boot = intent.action == Intent.ACTION_BOOT_COMPLETED
        if (!boot && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val cfg = Config(ctx)
        if (boot) AgentChannel.emit(ctx, WireEvent.log("Device booted", "info"))
        if (cfg.protect) {
            if (VpnService.prepare(ctx) == null) {
                runCatching { DnsVpnService.start(ctx) }.onFailure { cfg.lastError = "Could not start protection at boot: ${it.message}" }
            } else {
                cfg.lastError = "VPN permission was withdrawn: open OPH-S to turn protection back on"
            }
        }
    }
}
