package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.model.CheckResult

object VpnCheckRunner {

    suspend fun run(
        context: Context,
        onBypassProgress: (suspend (BypassChecker.Progress) -> Unit)? = null,
    ): CheckResult {
        val geoIp = GeoIpChecker.check()
        val directSigns = DirectSignsChecker.check(context)
        val indirectSigns = IndirectSignsChecker.check(context)
        val bypassResult = BypassChecker.check(onProgress = onBypassProgress)

        val verdict = VerdictEngine.evaluate(
            geoIpDetected = geoIp.detected,
            directDetected = directSigns.detected,
            indirectDetected = indirectSigns.detected,
            bypassDetected = bypassResult.detected
        )

        return CheckResult(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            bypassResult = bypassResult,
            verdict = verdict
        )
    }
}
