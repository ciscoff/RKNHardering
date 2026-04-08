package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocationSignalsCheckerTest {

    @Test
    fun `russian network mcc produces clean result`() {
        val result = LocationSignalsChecker.evaluate(snapshot())

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description.contains("MegaFon") })
        assertTrue(result.findings.any { it.description == "network_mcc_ru:true" })
    }

    @Test
    fun `foreign network mcc sets needs review`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simMcc = "244",
                simCountryIso = "fi",
            ),
        )

        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    @Test
    fun `foreign network mcc with roaming lowers confidence`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = true,
            ),
        )

        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.LOW
            },
        )
    }

    @Test
    fun `missing network mcc produces informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = null,
                networkCountryIso = null,
                networkOperatorName = null,
                simMcc = null,
                simCountryIso = null,
                isRoaming = null,
            ),
        )

        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description == "PLMN: network MCC is unavailable" })
    }

    @Test
    fun `cell lookup without location permission is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(snapshot(fineLocationPermissionGranted = false))

        assertTrue(result.findings.any { it.description.contains("ACCESS_FINE_LOCATION") })
    }

    @Test
    fun `cell lookup with no candidates is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                fineLocationPermissionGranted = true,
                cellCandidatesCount = 0,
            ),
        )

        assertTrue(result.findings.any { it.description.contains("base station identifiers are unavailable") })
    }

    @Test
    fun `ru cell lookup adds russian markers`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                fineLocationPermissionGranted = true,
                cellCandidatesCount = 1,
                cellCountryCode = "RU",
                cellLookupSummary = "OpenCellID LTE 250-01",
            ),
        )

        assertTrue(result.findings.any { it.description == "cell_country_ru:true" })
        assertTrue(result.findings.any { it.description == "location_country_ru:true" })
        assertTrue(result.findings.any { it.description.contains("OpenCellID LTE 250-01") })
    }

    @Test
    fun `wifi info without location permission is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(snapshot(fineLocationPermissionGranted = false))

        assertTrue(result.findings.any { it.description == "BSSID: permission is not granted" })
    }

    @Test
    fun `valid bssid is surfaced as informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                fineLocationPermissionGranted = true,
                bssid = "AA:BB:CC:DD:EE:FF",
            ),
        )

        assertTrue(result.findings.any { it.description.contains("AA:BB:CC:DD:EE:FF") })
    }

    @Test
    fun `placeholder bssid is treated as unavailable`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                fineLocationPermissionGranted = true,
                bssid = "02:00:00:00:00:00",
            ),
        )

        assertTrue(result.findings.any { it.description == "BSSID: unavailable" })
    }

    private fun snapshot(
        networkMcc: String? = "250",
        networkCountryIso: String? = "ru",
        networkOperatorName: String? = "MegaFon",
        simMcc: String? = "250",
        simCountryIso: String? = "ru",
        isRoaming: Boolean? = false,
        cellCountryCode: String? = null,
        cellLookupSummary: String? = null,
        cellCandidatesCount: Int = 0,
        bssid: String? = null,
        fineLocationPermissionGranted: Boolean = false,
    ): LocationSignalsChecker.LocationSnapshot {
        return LocationSignalsChecker.LocationSnapshot(
            networkMcc = networkMcc,
            networkCountryIso = networkCountryIso,
            networkOperatorName = networkOperatorName,
            simMcc = simMcc,
            simCountryIso = simCountryIso,
            isRoaming = isRoaming,
            cellCountryCode = cellCountryCode,
            cellLookupSummary = cellLookupSummary,
            cellCandidatesCount = cellCandidatesCount,
            bssid = bssid,
            fineLocationPermissionGranted = fineLocationPermissionGranted,
        )
    }
}
