package com.notcvnt.rknhardering.probe

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

object ProxyProber {

    fun probeNoAuthProxyType(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
    ): ProxyType? {
        return when (probeSocks5NoAuth(host, port, connectTimeoutMs, readTimeoutMs)) {
            SocksProbeResult.SOCKS5_NO_AUTH -> ProxyType.SOCKS5
            SocksProbeResult.CLOSED -> null
            SocksProbeResult.NOT_SOCKS -> ProxyType.HTTP
        }
    }

    private enum class SocksProbeResult {
        CLOSED,
        NOT_SOCKS,
        SOCKS5_NO_AUTH,
    }

    private fun probeSocks5NoAuth(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
    ): SocksProbeResult {
        return Socket().use { socket ->
            try {
                socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
            } catch (_: Exception) {
                return SocksProbeResult.CLOSED
            }

            socket.soTimeout = readTimeoutMs
            socket.tcpNoDelay = true

            try {
                socket.getOutputStream().writeSocks5NoAuthGreeting()
                val response = socket.getInputStream().readExactly(2)
                    ?: return SocksProbeResult.NOT_SOCKS
                val version = response[0].toInt() and 0xFF
                val method = response[1].toInt() and 0xFF
                if (version == 0x05 && method == 0x00) {
                    SocksProbeResult.SOCKS5_NO_AUTH
                } else {
                    SocksProbeResult.NOT_SOCKS
                }
            } catch (_: SocketTimeoutException) {
                SocksProbeResult.NOT_SOCKS
            } catch (_: Exception) {
                SocksProbeResult.NOT_SOCKS
            }
        }
    }

    private fun OutputStream.writeSocks5NoAuthGreeting() {
        write(byteArrayOf(0x05, 0x01, 0x00))
        flush()
    }

    private fun InputStream.readExactly(byteCount: Int): ByteArray? {
        val buffer = ByteArray(byteCount)
        var offset = 0
        while (offset < byteCount) {
            val read = read(buffer, offset, byteCount - offset)
            if (read <= 0) return null
            offset += read
        }
        return buffer
    }
}
