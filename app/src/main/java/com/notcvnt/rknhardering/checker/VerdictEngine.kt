package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.Verdict

object VerdictEngine {

    fun evaluate(
        geoIpDetected: Boolean,
        directDetected: Boolean,
        indirectDetected: Boolean,
        bypassDetected: Boolean = false,
    ): Verdict {
        // Bypass detection (open proxy / xray API on localhost) is a strong signal
        if (bypassDetected) return Verdict.DETECTED

        return when {
            geoIpDetected && (directDetected || indirectDetected) -> Verdict.DETECTED
            geoIpDetected -> Verdict.NEEDS_REVIEW
            directDetected && indirectDetected -> Verdict.NEEDS_REVIEW
            else -> Verdict.NOT_DETECTED
        }
    }
}
