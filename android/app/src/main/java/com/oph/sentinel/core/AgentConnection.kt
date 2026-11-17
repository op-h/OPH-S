package com.oph.sentinel.core

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedTrustManager

/** Thrown when the server's leaf certificate does not match the enrolled SHA-256 pin. */
class PinMismatchException(val actual: String) : CertificateException("fingerprint mismatch")

/** Thrown when the server answers hello with welcome ok=false (bad/revoked key, busy, version). */
class WelcomeRejected(val reason: String) : Exception(reason)

/**
 * Trust exactly one certificate: the leaf whose DER SHA-256 equals [pinHex] (64 lower-case hex).
 * No CA chain and no hostname checks: the pin is the identity (same model as oph-agent).
 */
class PinnedTrustManager(private val pinHex: String) : X509ExtendedTrustManager() {
    private fun check(chain: Array<out X509Certificate>?) {
        val leaf = chain?.firstOrNull() ?: throw CertificateException("no server certificate")
        val fp = sha256Hex(leaf.encoded)
        if (!MessageDigest.isEqual(fp.toByteArray(), pinHex.toByteArray())) throw PinMismatchException(fp)
    }
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = check(chain)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = check(chain)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = check(chain)
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = throw CertificateException("client auth unsupported")
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = throw CertificateException("client auth unsupported")
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = throw CertificateException("client auth unsupported")
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

    companion object {
        fun sha256Hex(b: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    }
}

/**
 * One authenticated session on the OPH Sentinel agent channel (app/src-tauri/src/ingest.rs):
 * TLS -> hello -> welcome, then batch/ack request-response and ping keep-alives.
 * Blocking; used from one worker thread. Pure JVM so it is exercised by the interop test.
 */
class AgentConnection private constructor(private val socket: SSLSocket) : AutoCloseable {
    private val reader = BufferedReader(InputStreamReader(socket.inputStream, Charsets.UTF_8))
    private val out: OutputStream = socket.outputStream

    private fun send(line: String) {
        out.write((line + "\n").toByteArray(Charsets.UTF_8))
        out.flush()
    }

    private fun readFrame(timeoutMs: Int): Frames.Incoming {
        socket.soTimeout = timeoutMs
        val line = reader.readLine() ?: throw java.io.EOFException("server closed the connection")
        return Frames.parse(line) ?: throw java.io.IOException("bad frame from server")
    }

    /** Send one batch and wait for its ack; returns the number the server acknowledged. */
    fun sendBatch(events: List<WireEvent>): Int {
        send(Frames.batch(events))
        return when (val f = readFrame(20_000)) {
            is Frames.Incoming.Ack -> f.received
            else -> throw java.io.IOException("expected ack, got $f")
        }
    }

    /** Keep-alive; the server does not answer pings. */
    fun ping() = send(Frames.ping())

    override fun close() {
        runCatching { socket.close() }
    }

    companion object {
        const val SNI = "oph-sentinel"

        /**
         * Connect, pin, and authenticate. [protect] lets the VpnService mark the socket so it
         * bypasses the TUN (harmless here since only the DNS address is routed, but correct).
         */
        fun open(
            host: String, port: Int, pinHex: String, token: String, agentId: String, name: String, version: String,
            protect: (Socket) -> Unit = {}, connectTimeoutMs: Int = 10_000,
        ): AgentConnection {
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(PinnedTrustManager(pinHex)), null)
            val raw = Socket()
            try {
                protect(raw)
                raw.connect(InetSocketAddress(host, port), connectTimeoutMs)
                raw.tcpNoDelay = true
                raw.keepAlive = true
                val ssl = ctx.socketFactory.createSocket(raw, SNI, port, true) as SSLSocket
                val params = ssl.sslParameters
                params.serverNames = listOf(SNIHostName(SNI)) // JDK skips SNI for dot-less names unless set explicitly
                params.endpointIdentificationAlgorithm = null // identity is the pin, not the hostname
                ssl.sslParameters = params
                ssl.soTimeout = 10_000
                ssl.startHandshake()
                val c = AgentConnection(ssl)
                c.send(Frames.hello(token, agentId, name, version))
                when (val w = c.readFrame(10_000)) {
                    is Frames.Incoming.Welcome -> if (!w.ok) {
                        c.close()
                        throw WelcomeRejected(w.error ?: "rejected by server")
                    }
                    else -> {
                        c.close()
                        throw java.io.IOException("expected welcome, got $w")
                    }
                }
                return c
            } catch (e: Exception) {
                runCatching { raw.close() }
                throw e
            }
        }

        /** Walk the cause chain for a pin failure (it arrives wrapped in SSLHandshakeException). */
        fun pinFailure(e: Throwable): PinMismatchException? {
            var t: Throwable? = e
            var depth = 0
            while (t != null && depth++ < 10) {
                if (t is PinMismatchException) return t
                if (t.message?.contains("fingerprint mismatch") == true && t is CertificateException) return PinMismatchException("?")
                t = t.cause
            }
            return null
        }
    }
}
