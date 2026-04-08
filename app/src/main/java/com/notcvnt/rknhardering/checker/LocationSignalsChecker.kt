package com.notcvnt.rknhardering.checker

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Geocoder
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoTdscdma
import android.telephony.CellInfoWcdma
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

object LocationSignalsChecker {

    internal data class LocationSnapshot(
        val networkMcc: String?,
        val networkCountryIso: String?,
        val networkOperatorName: String?,
        val simMcc: String?,
        val simCountryIso: String?,
        val isRoaming: Boolean?,
        val cellCountryCode: String?,
        val cellLookupSummary: String?,
        val cellCandidatesCount: Int,
        val bssid: String?,
        val fineLocationPermissionGranted: Boolean,
    )

    private const val RUSSIA_MCC = "250"
    private const val PLACEHOLDER_BSSID = "02:00:00:00:00:00"

    suspend fun check(context: Context): CategoryResult = withContext(Dispatchers.IO) {
        evaluate(collectSnapshot(context))
    }

    private suspend fun collectSnapshot(context: Context): LocationSnapshot {
        val fineLocationGranted = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION,
        ) == PackageManager.PERMISSION_GRANTED

        var networkMcc: String? = null
        var networkCountryIso: String? = null
        var networkOperatorName: String? = null
        var simMcc: String? = null
        var simCountryIso: String? = null
        var isRoaming: Boolean? = null
        var cellCountryCode: String? = null
        var cellLookupSummary: String? = null
        var cellCandidatesCount = 0

        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        runCatching {
            val networkOperator = tm.networkOperator
            if (!networkOperator.isNullOrEmpty() && networkOperator.length >= 3) {
                networkMcc = networkOperator.substring(0, 3)
            }
            networkCountryIso = tm.networkCountryIso?.takeIf { it.isNotEmpty() }
            networkOperatorName = tm.networkOperatorName?.takeIf { it.isNotEmpty() }

            val simOperator = tm.simOperator
            if (!simOperator.isNullOrEmpty() && simOperator.length >= 3) {
                simMcc = simOperator.substring(0, 3)
            }
            simCountryIso = tm.simCountryIso?.takeIf { it.isNotEmpty() }
            isRoaming = tm.isNetworkRoaming
        }

        if (fineLocationGranted) {
            val candidates = collectCellCandidates(tm)
            cellCandidatesCount = candidates.size
            cellLookupSummary = if (candidates.isEmpty()) {
                "Cell lookup: base station identifiers are unavailable"
            } else {
                val lookup = OpenCellIdClient { lat, lon ->
                    reverseGeocodeCountry(context, lat, lon)
                }.lookup(candidates)
                cellCountryCode = lookup.countryCode
                buildString {
                    append(lookup.summary)
                    if (lookup.latitude != null && lookup.longitude != null) {
                        append(" (${lookup.latitude}, ${lookup.longitude})")
                    }
                }
            }
        }

        val bssid = if (fineLocationGranted) {
            runCatching { getBssid(context) }.getOrNull()
        } else {
            null
        }

        return LocationSnapshot(
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
            fineLocationPermissionGranted = fineLocationGranted,
        )
    }

    private fun collectCellCandidates(tm: TelephonyManager): List<CellLookupCandidate> {
        return runCatching {
            tm.allCellInfo
                ?.mapNotNull(::toLookupCandidate)
                ?.distinctBy { listOf(it.radio, it.mcc, it.mnc, it.areaCode, it.cellId) }
                .orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun toLookupCandidate(info: CellInfo): CellLookupCandidate? {
        return when (info) {
            is CellInfoGsm -> {
                val identity = info.cellIdentity
                val mcc = identity.mccString ?: return null
                val mnc = identity.mncString ?: return null
                CellLookupCandidate(
                    radio = "GSM",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = identity.lac.toLong(),
                    cellId = identity.cid.toLong(),
                    registered = info.isRegistered,
                )
            }

            is CellInfoLte -> {
                val identity = info.cellIdentity
                val mcc = identity.mccString ?: return null
                val mnc = identity.mncString ?: return null
                CellLookupCandidate(
                    radio = "LTE",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = identity.tac.toLong(),
                    cellId = identity.ci.toLong(),
                    registered = info.isRegistered,
                )
            }

            is CellInfoWcdma -> {
                val identity = info.cellIdentity
                val mcc = identity.mccString ?: return null
                val mnc = identity.mncString ?: return null
                CellLookupCandidate(
                    radio = "UMTS",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = identity.lac.toLong(),
                    cellId = identity.cid.toLong(),
                    registered = info.isRegistered,
                )
            }

            is CellInfoTdscdma -> {
                val identity = info.cellIdentity
                val mcc = identity.mccString ?: return null
                val mnc = identity.mncString ?: return null
                CellLookupCandidate(
                    radio = "TDSCDMA",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = identity.lac.toLong(),
                    cellId = identity.cid.toLong(),
                    registered = info.isRegistered,
                )
            }

            is CellInfoNr -> {
                val identity = info.cellIdentity
                val mcc = invokeStringGetter(identity, "getMccString") ?: return null
                val mnc = invokeStringGetter(identity, "getMncString") ?: return null
                val tac = invokeLongGetter(identity, "getTac") ?: return null
                val nci = invokeLongGetter(identity, "getNci") ?: return null
                CellLookupCandidate(
                    radio = "NR",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = tac,
                    cellId = nci,
                    registered = info.isRegistered,
                )
            }

            else -> null
        }
    }

    @Suppress("DEPRECATION")
    private fun reverseGeocodeCountry(context: Context, latitude: Double, longitude: Double): String? {
        return runCatching {
            if (!Geocoder.isPresent()) {
                null
            } else {
                Geocoder(context, Locale.US)
                    .getFromLocation(latitude, longitude, 1)
                    ?.firstOrNull()
                    ?.countryCode
                    ?.uppercase(Locale.US)
            }
        }.getOrNull()
    }

    private fun invokeStringGetter(target: Any, methodName: String): String? {
        return runCatching {
            target.javaClass.getMethod(methodName).invoke(target) as? String
        }.getOrNull()?.takeIf { it.isNotBlank() }
    }

    private fun invokeLongGetter(target: Any, methodName: String): Long? {
        return runCatching {
            when (val value = target.javaClass.getMethod(methodName).invoke(target)) {
                is Int -> value.toLong()
                is Long -> value
                else -> null
            }
        }.getOrNull()?.takeIf { it >= 0 }
    }

    @Suppress("DEPRECATION")
    private fun getBssid(context: Context): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork ?: return null
            val caps = cm.getNetworkCapabilities(network) ?: return null
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return null
            (caps.transportInfo as? WifiInfo)?.bssid
        } else {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wm.connectionInfo?.bssid
        }
    }

    internal fun evaluate(snapshot: LocationSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        if (snapshot.networkMcc == null) {
            findings += Finding("PLMN: network MCC is unavailable")
        } else {
            val networkCountry = snapshot.networkCountryIso?.uppercase(Locale.US) ?: "N/A"
            val networkIsRussia = snapshot.networkMcc == RUSSIA_MCC

            findings += Finding("Network operator: ${snapshot.networkOperatorName ?: "N/A"} ($networkCountry)")
            findings += Finding("Network MCC: ${snapshot.networkMcc}")
            if (networkIsRussia) {
                findings += Finding("network_mcc_ru:true")
            }

            snapshot.simMcc?.let { simMcc ->
                val simCountry = snapshot.simCountryIso?.uppercase(Locale.US) ?: "N/A"
                findings += Finding("SIM MCC: $simMcc ($simCountry)")
            }

            when (snapshot.isRoaming) {
                true -> findings += Finding("Roaming: yes")
                false -> findings += Finding("Roaming: no")
                null -> Unit
            }

            if (!networkIsRussia) {
                val confidence = if (snapshot.isRoaming == true) {
                    EvidenceConfidence.LOW
                } else {
                    EvidenceConfidence.MEDIUM
                }
                val description = "Network MCC ${snapshot.networkMcc} ($networkCountry) is not Russia"
                findings += Finding(
                    description = description,
                    needsReview = true,
                    source = EvidenceSource.LOCATION_SIGNALS,
                    confidence = confidence,
                )
                evidence += EvidenceItem(
                    source = EvidenceSource.LOCATION_SIGNALS,
                    detected = true,
                    confidence = confidence,
                    description = description,
                )
                needsReview = true
            }
        }

        if (!snapshot.fineLocationPermissionGranted) {
            findings += Finding("Cell lookup: ACCESS_FINE_LOCATION permission is not granted")
        } else if (snapshot.cellCandidatesCount == 0) {
            findings += Finding("Cell lookup: base station identifiers are unavailable")
        } else {
            findings += Finding("Cell lookup candidates: ${snapshot.cellCandidatesCount}")
            snapshot.cellCountryCode?.let { countryCode ->
                findings += Finding("Cell lookup country: $countryCode")
                if (countryCode == "RU") {
                    findings += Finding("cell_country_ru:true")
                    findings += Finding("location_country_ru:true")
                }
            }
            snapshot.cellLookupSummary?.let { findings += Finding(it) }
        }

        if (!snapshot.fineLocationPermissionGranted) {
            findings += Finding("BSSID: permission is not granted")
        } else if (snapshot.bssid == null || snapshot.bssid == PLACEHOLDER_BSSID) {
            findings += Finding("BSSID: unavailable")
        } else {
            findings += Finding("BSSID: ${snapshot.bssid}")
        }

        return CategoryResult(
            name = "Location signals",
            detected = false,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }
}
