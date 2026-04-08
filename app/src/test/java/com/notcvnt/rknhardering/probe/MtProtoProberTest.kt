package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

class MtProtoProberTest {

    @Test
    fun `returns true when socks5 connect succeeds`() {
        val result = withSocks5Server { inp, out ->
            // Read greeting (3 bytes)
            inp.readNBytes(3)
            // Reply: version 0x05, no-auth 0x00
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            // Read CONNECT request (10 bytes for IPv4)
            inp.readNBytes(10)
            // Reply: success
            out.write(
                byteArrayOf(
                    0x05, 0x00, 0x00, 0x01,       // ver, success, rsv, IPv4
                    0x00, 0x00, 0x00, 0x00,         // bind addr
                    0x00, 0x00,                      // bind port
                ),
            )
            out.flush()
        }

        assertTrue(result)
    }

    @Test
    fun `returns false when socks5 connect is rejected`() {
        val result = withSocks5Server { inp, out ->
            inp.readNBytes(3)
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            inp.readNBytes(10)
            // Reply: connection refused (0x05)
            out.write(
                byteArrayOf(
                    0x05, 0x05, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00,
                ),
            )
            out.flush()
        }

        assertFalse(result)
    }

    @Test
    fun `returns false when greeting is rejected`() {
        val result = withSocks5Server { inp, out ->
            inp.readNBytes(3)
            // Reply: no acceptable methods (0xFF)
            out.write(byteArrayOf(0x05, 0xFF.toByte()))
            out.flush()
        }

        assertFalse(result)
    }

    @Test
    fun `returns false when connection is closed`() {
        val result = withSocks5Server { _, _ ->
            // Close immediately — don't respond
        }

        assertFalse(result)
    }

    private fun withSocks5Server(
        handler: (java.io.InputStream, java.io.OutputStream) -> Unit,
    ): Boolean {
        ServerSocket(0).use { server ->
            val worker = thread(start = true) {
                try {
                    server.accept().use { client ->
                        handler(client.getInputStream(), client.getOutputStream())
                    }
                } catch (_: Exception) {
                    // Server may be closed before accept
                }
            }

            val result = MtProtoProber.trySocks5Connect(
                proxyHost = "127.0.0.1",
                proxyPort = server.localPort,
                targetHost = "149.154.167.51",
                targetPort = 443,
                connectTimeoutMs = 1000,
                readTimeoutMs = 1000,
            )

            worker.join(2000)
            return result
        }
    }
}
