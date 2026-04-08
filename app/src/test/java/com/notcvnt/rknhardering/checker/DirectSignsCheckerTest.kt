package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.EvidenceSource
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DirectSignsCheckerTest {

    @Test
    fun `matches documented proxy ports`() {
        assertTrue(DirectSignsChecker.isKnownProxyPort("1080"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("3128"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("8081"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("9051"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("12345"))
    }

    @Test
    fun `matches documented proxy port ranges`() {
        assertTrue(DirectSignsChecker.isKnownProxyPort("16000"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("16042"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("16100"))
    }

    @Test
    fun `ignores unknown or invalid ports`() {
        assertFalse(DirectSignsChecker.isKnownProxyPort(null))
        assertFalse(DirectSignsChecker.isKnownProxyPort("abc"))
        assertFalse(DirectSignsChecker.isKnownProxyPort("53"))
        assertFalse(DirectSignsChecker.isKnownProxyPort("16101"))
    }

    @Test
    fun `host and port are treated as direct system proxy evidence`() {
        val result = DirectSignsChecker.evaluateProxyEndpoint("HTTP proxy", "127.0.0.1", "8080")

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.evidence.any { it.source == EvidenceSource.SYSTEM_PROXY && it.detected })
    }

    @Test
    fun `host without valid port only needs review`() {
        val result = DirectSignsChecker.evaluateProxyEndpoint("HTTP proxy", "127.0.0.1", null)

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.findings.any { it.needsReview })
        assertTrue(result.evidence.any { it.source == EvidenceSource.SYSTEM_PROXY && !it.detected })
    }

    @Test
    fun `known proxy port adds a dedicated finding`() {
        val result = DirectSignsChecker.evaluateProxyEndpoint("SOCKS proxy", "127.0.0.1", "1080")

        assertTrue(result.detected)
        assertTrue(result.findings.any { it.description.contains("1080") && it.detected })
        assertTrue(result.evidence.count { it.source == EvidenceSource.SYSTEM_PROXY && it.detected } >= 2)
    }
}
