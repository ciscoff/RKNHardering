package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.checker.IndirectSignsChecker.DnsClassification
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.DnsSignalStatus
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.NetworkSnapshot
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.RouteSnapshot
import com.notcvnt.rknhardering.model.EvidenceSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IndirectSignsCheckerTest {

    @Test
    fun `classifies loopback dns`() {
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("127.0.0.1"))
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("::1"))
    }

    @Test
    fun `classifies private tunnel dns including carrier grade nat`() {
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("10.0.0.2"))
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("172.16.0.10"))
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("100.64.0.10"))
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("fd00::1"))
    }

    @Test
    fun `classifies private lan and public dns separately`() {
        assertEquals(DnsClassification.PRIVATE_LAN, IndirectSignsChecker.classifyDnsAddress("192.168.1.1"))
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("8.8.8.8"))
        assertEquals(DnsClassification.OTHER_PUBLIC, IndirectSignsChecker.classifyDnsAddress("77.88.55.55"))
    }

    @Test
    fun `maps dns classes to expected statuses`() {
        assertEquals(DnsSignalStatus.DETECTED, IndirectSignsChecker.classifyDnsSignalStatus("127.0.0.1"))
        assertEquals(DnsSignalStatus.NEEDS_REVIEW, IndirectSignsChecker.classifyDnsSignalStatus("10.0.0.2"))
        assertEquals(DnsSignalStatus.CLEAR, IndirectSignsChecker.classifyDnsSignalStatus("192.168.1.1"))
        assertEquals(DnsSignalStatus.CLEAR, IndirectSignsChecker.classifyDnsSignalStatus("8.8.8.8"))
    }

    @Test
    fun `parses proc net listeners`() {
        val listeners = IndirectSignsChecker.parseProcNetListeners(
            lines = listOf(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
                "   0: 0100007F:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0",
            ),
            protocol = "tcp",
        )

        assertEquals(1, listeners.size)
        assertEquals("127.0.0.1", listeners.single().host)
        assertEquals(9090, listeners.single().port)
    }

    @Test
    fun `loopback dns on active vpn is detected`() {
        val evaluation = IndirectSignsChecker.checkDns(
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("127.0.0.1"),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("192.168.1.1"),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.DNS && it.detected })
    }

    @Test
    fun `vpn replacing public dns yields needs review`() {
        val evaluation = IndirectSignsChecker.checkDns(
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("8.8.8.8"),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("192.168.1.1"),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertTrue(evaluation.needsReview)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.DNS && it.detected })
    }

    @Test
    fun `inherited lan dns stays clear`() {
        val evaluation = IndirectSignsChecker.checkDns(
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("192.168.1.1"),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("192.168.1.1"),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.isEmpty())
    }

    @Test
    fun `default route on non standard interface is detected`() {
        val evaluation = IndirectSignsChecker.checkRoutingTable(
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = false,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.ROUTING && it.detected })
    }

    @Test
    fun `split tunneling route pattern is detected`() {
        val evaluation = IndirectSignsChecker.checkRoutingTable(
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("10.0.0.0/8", "tun0", isDefault = false)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertTrue(evaluation.evidence.any { it.description.contains("Split-tunneling") })
    }

    private fun snapshot(
        isActive: Boolean,
        isVpn: Boolean,
        interfaceName: String?,
        routes: List<RouteSnapshot>,
        dnsServers: List<String> = emptyList(),
    ): NetworkSnapshot {
        return NetworkSnapshot(
            label = interfaceName ?: "network",
            isActive = isActive,
            isVpn = isVpn,
            interfaceName = interfaceName,
            routes = routes,
            dnsServers = dnsServers,
        )
    }

    private fun route(
        destination: String,
        interfaceName: String?,
        isDefault: Boolean,
        gateway: String? = "192.0.2.1",
    ): RouteSnapshot {
        return RouteSnapshot(
            destination = destination,
            gateway = gateway,
            interfaceName = interfaceName,
            isDefault = isDefault,
        )
    }
}
