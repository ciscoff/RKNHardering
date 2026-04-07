package com.notcvnt.rknhardering.probe

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import kotlin.math.min

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
            SocksProbeResult.NOT_SOCKS -> {
                if (probeHttpConnectNoAuth(host, port, connectTimeoutMs, readTimeoutMs)) {
                    ProxyType.HTTP
                } else {
                    null
                }
            }
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

    private fun probeHttpConnectNoAuth(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
    ): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
                socket.soTimeout = readTimeoutMs
                socket.tcpNoDelay = true

                val request =
                    "CONNECT ifconfig.me:443 HTTP/1.1\r\n" +
                        "Host: ifconfig.me:443\r\n" +
                        "User-Agent: RKNHardering/1.0\r\n" +
                        "Proxy-Connection: keep-alive\r\n" +
                        "\r\n"
                socket.getOutputStream().write(request.toByteArray(Charsets.ISO_8859_1))
                socket.getOutputStream().flush()

                val statusLine = socket.getInputStream().readAsciiLine(maxBytes = 256)
                    ?: return false
                val parts = statusLine.trim().split(Regex("\\s+"), limit = 3)
                if (parts.size < 2 || !parts[0].startsWith("HTTP/")) return false
                val code = parts[1].toIntOrNull() ?: return false
                code == 200
            }
        } catch (_: Exception) {
            false
        }
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

    private fun InputStream.readAsciiLine(maxBytes: Int): String? {
        val buffer = ByteArray(min(maxBytes, 1024))
        var count = 0
        while (count < maxBytes) {
            val b = read()
            if (b == -1) return null
            if (b == '\n'.code) break
            if (b != '\r'.code) {
                if (count >= buffer.size) return null
                buffer[count] = b.toByte()
                count++
            }
        }
        return if (count == 0) null else String(buffer, 0, count, Charsets.ISO_8859_1)
    }
}
