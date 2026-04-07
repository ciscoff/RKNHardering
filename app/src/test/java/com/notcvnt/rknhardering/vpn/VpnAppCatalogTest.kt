package com.notcvnt.rknhardering.vpn

import com.notcvnt.rknhardering.model.VpnAppKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnAppCatalogTest {

    @Test
    fun `finds targeted package by package name`() {
        val signature = VpnAppCatalog.findByPackageName("moe.nb4a")

        assertEquals(VpnAppCatalog.FAMILY_NEKOBOX, signature?.family)
        assertEquals(VpnAppKind.TARGETED_BYPASS, signature?.kind)
    }

    @Test
    fun `exposes family candidates for common localhost port`() {
        val families = VpnAppCatalog.familiesForPort(10808)

        assertTrue(families.contains(VpnAppCatalog.FAMILY_XRAY))
    }

    @Test
    fun `aggregates popular localhost proxy ports`() {
        assertTrue(VpnAppCatalog.localhostProxyPorts.contains(2080))
        assertTrue(VpnAppCatalog.localhostProxyPorts.contains(12334))
    }

    @Test
    fun `detects AmneziaVPN by package name`() {
        val sig = VpnAppCatalog.findByPackageName("org.amnezia.vpn")

        assertEquals(VpnAppCatalog.FAMILY_AMNEZIA, sig?.family)
        assertEquals(VpnAppKind.GENERIC_VPN, sig?.kind)
    }

    @Test
    fun `detects AmneziaWG by package name`() {
        val sig = VpnAppCatalog.findByPackageName("org.amnezia.awg")

        assertEquals(VpnAppCatalog.FAMILY_AMNEZIA, sig?.family)
        assertEquals(VpnAppKind.GENERIC_VPN, sig?.kind)
    }
}
