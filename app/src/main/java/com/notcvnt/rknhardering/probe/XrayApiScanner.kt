package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.coroutineContext
import kotlin.math.max

data class XrayApiEndpoint(
    val host: String,
    val port: Int,
)

data class XrayScanProgress(
    val host: String,
    val scanned: Int,
    val total: Int,
    val currentPort: Int,
)

/**
 * Scans localhost for open Xray gRPC API endpoints.
 * Detects by sending an HTTP/2 connection preface and checking for a valid server response.
 * Does not require protobuf/gRPC dependencies.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class XrayApiScanner(
    private val loopbackHosts: List<String> = listOf("127.0.0.1", "::1"),
    private val scanRange: IntRange = 1024..65535,
    private val connectTimeoutMs: Int = 200,
    private val maxConcurrency: Int = 100,
    private val progressUpdateEvery: Int = 512,
) {

    suspend fun findXrayApi(
        onProgress: suspend (XrayScanProgress) -> Unit,
    ): XrayApiEndpoint? = withContext(Dispatchers.IO) {
        val portsTotal = (scanRange.last - scanRange.first + 1).coerceAtLeast(0)
        val total = portsTotal * loopbackHosts.size

        var scannedOffset = 0
        for (host in loopbackHosts) {
            val result = scanHost(
                host = host,
                scannedOffset = scannedOffset,
                total = total,
                onProgress = onProgress,
            )
            if (result != null) return@withContext result
            scannedOffset += portsTotal
        }

        null
    }

    private suspend fun scanHost(
        host: String,
        scannedOffset: Int,
        total: Int,
        onProgress: suspend (XrayScanProgress) -> Unit,
    ): XrayApiEndpoint? = coroutineScope {
        val portsTotal = (scanRange.last - scanRange.first + 1).coerceAtLeast(0)
        if (portsTotal <= 0) return@coroutineScope null

        val scanned = AtomicInteger(0)
        val found = AtomicReference<XrayApiEndpoint?>(null)

        val dispatcher = Dispatchers.IO.limitedParallelism(max(1, maxConcurrency))

        onProgress(
            XrayScanProgress(
                host = host,
                scanned = scannedOffset,
                total = total,
                currentPort = scanRange.first,
            ),
        )

        val jobs = (0 until maxConcurrency).map { workerIndex ->
            launch(dispatcher) {
                var port = scanRange.first + workerIndex
                while (port <= scanRange.last) {
                    coroutineContext.ensureActive()
                    if (found.get() != null) return@launch

                    val count = scanned.incrementAndGet()
                    if (count % progressUpdateEvery == 0) {
                        onProgress(
                            XrayScanProgress(
                                host = host,
                                scanned = scannedOffset + count,
                                total = total,
                                currentPort = port,
                            ),
                        )
                    }

                    if (isGrpcEndpoint(host, port)) {
                        found.compareAndSet(null, XrayApiEndpoint(host, port))
                        return@launch
                    }

                    port += maxConcurrency
                }
            }
        }

        jobs.joinAll()

        onProgress(
            XrayScanProgress(
                host = host,
                scanned = scannedOffset + portsTotal,
                total = total,
                currentPort = scanRange.last,
            ),
        )

        found.get()
    }

    /**
     * Detect a gRPC (HTTP/2) server by sending the HTTP/2 connection preface
     * and checking if the server responds with a valid SETTINGS frame.
     */
    private fun isGrpcEndpoint(host: String, port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
                socket.soTimeout = connectTimeoutMs
                socket.tcpNoDelay = true

                // HTTP/2 connection preface: magic + SETTINGS frame (empty)
                val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)
                // Empty SETTINGS frame: length=0, type=4, flags=0, stream=0
                val settingsFrame = byteArrayOf(
                    0x00, 0x00, 0x00, // length = 0
                    0x04,             // type = SETTINGS
                    0x00,             // flags = 0
                    0x00, 0x00, 0x00, 0x00 // stream ID = 0
                )

                val out = socket.getOutputStream()
                out.write(preface)
                out.write(settingsFrame)
                out.flush()

                // Read response frame header (9 bytes)
                val header = ByteArray(9)
                var offset = 0
                while (offset < 9) {
                    val read = socket.getInputStream().read(header, offset, 9 - offset)
                    if (read <= 0) return false
                    offset += read
                }

                // Check if it's a SETTINGS frame (type=4)
                val frameType = header[3].toInt() and 0xFF
                frameType == 0x04
            }
        } catch (_: Exception) {
            false
        }
    }
}
