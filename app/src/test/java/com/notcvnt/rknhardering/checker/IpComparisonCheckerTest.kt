package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IpComparisonCheckerTest {

    @Test
    fun `all checkers returning same ip produces clean result`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "1.2.3.4"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "1.2.3.4"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals("Есть ответ", result.ruGroup.statusLabel)
        assertEquals("Совпадает", result.nonRuGroup.statusLabel)
    }

    @Test
    fun `ru and non-ru mismatch with full data is detected`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "10.0.0.1"),
                response("ipify", IpCheckerScope.NON_RU, ip = "20.0.0.1"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "20.0.0.1"),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.summary.contains("10.0.0.1"))
        assertTrue(result.summary.contains("20.0.0.1"))
    }

    @Test
    fun `non-ru mismatch inside group requires attention`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "5.6.7.8"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "9.9.9.9"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.nonRuGroup.detected)
        assertEquals("Разнобой", result.nonRuGroup.statusLabel)
    }

    @Test
    fun `partial non-ru response stays in review even when ip differs`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "5.6.7.8"),
                response("ip.sb", IpCheckerScope.NON_RU, error = "timeout"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertEquals("Частично", result.nonRuGroup.statusLabel)
    }

    @Test
    fun `mixed ipv4 and ipv6 responses require review instead of detection`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("ipify", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "2a01:4f9:c013:d2ba::1"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertEquals("IPv4/IPv6", result.nonRuGroup.statusLabel)
    }

    @Test
    fun `ru group with one success and one failure is partial`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex IPv4", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("Yandex IPv6", IpCheckerScope.RU, error = "connect failed"),
                response("ifconfig.me", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("checkip.amazonaws.com", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertEquals("Частично", result.ruGroup.statusLabel)
    }

    private fun response(
        label: String,
        scope: IpCheckerScope,
        ip: String? = null,
        error: String? = null,
    ): IpCheckerResponse = IpCheckerResponse(
        label = label,
        url = "https://example.com/$label",
        scope = scope,
        ip = ip,
        error = error,
    )
}
