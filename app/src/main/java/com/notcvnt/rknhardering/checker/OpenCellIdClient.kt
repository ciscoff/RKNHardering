package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.Locale

internal data class CellLookupCandidate(
    val radio: String,
    val mcc: String,
    val mnc: String,
    val areaCode: Long,
    val cellId: Long,
    val registered: Boolean,
)

internal data class CellLookupResult(
    val countryCode: String?,
    val latitude: Double?,
    val longitude: Double?,
    val summary: String,
)

internal class OpenCellIdClient(
    private val apiKey: String = BuildConfig.OPENCELLID_API_KEY,
    private val countryResolver: (Double, Double) -> String?,
) {

    private data class HttpResult(
        val code: Int,
        val body: String,
    )

    suspend fun lookup(candidates: List<CellLookupCandidate>): CellLookupResult = withContext(Dispatchers.IO) {
        if (apiKey.isBlank()) {
            return@withContext CellLookupResult(
                countryCode = null,
                latitude = null,
                longitude = null,
                summary = "OpenCellID API key is not configured",
            )
        }
        if (candidates.isEmpty()) {
            return@withContext CellLookupResult(
                countryCode = null,
                latitude = null,
                longitude = null,
                summary = "No cell identity data available for lookup",
            )
        }

        var lastSummary = "OpenCellID: cell not found"
        for (candidate in candidates.sortedByDescending { it.registered }.take(3)) {
            val response = try {
                fetch(buildUrl(candidate))
            } catch (error: Exception) {
                lastSummary = "OpenCellID: ${error.message ?: "request failed"}"
                continue
            }

            val coordinates = parseCoordinates(response.body)
            if (response.code in 200..299 && coordinates != null) {
                val countryCode = runCatching {
                    countryResolver(coordinates.first, coordinates.second)
                }.getOrNull()?.uppercase(Locale.US)
                return@withContext CellLookupResult(
                    countryCode = countryCode,
                    latitude = coordinates.first,
                    longitude = coordinates.second,
                    summary = "OpenCellID ${candidate.radio} ${candidate.mcc}-${candidate.mnc}",
                )
            }

            lastSummary = describeFailure(response)
        }

        CellLookupResult(
            countryCode = null,
            latitude = null,
            longitude = null,
            summary = lastSummary,
        )
    }

    private fun buildUrl(candidate: CellLookupCandidate): String {
        val query = listOf(
            "key" to apiKey,
            "mcc" to candidate.mcc,
            "mnc" to candidate.mnc,
            "lac" to candidate.areaCode.toString(),
            "cellid" to candidate.cellId.toString(),
            "radio" to candidate.radio,
            "format" to "json",
        ).joinToString("&") { (key, value) ->
            "${URLEncoder.encode(key, Charsets.UTF_8.name())}=${URLEncoder.encode(value, Charsets.UTF_8.name())}"
        }
        return "https://opencellid.org/cell/get?$query"
    }

    private fun fetch(url: String): HttpResult {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = 8_000
        connection.readTimeout = 8_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "application/json, text/xml")
        return try {
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            HttpResult(code = code, body = body)
        } finally {
            connection.disconnect()
        }
    }

    private fun parseCoordinates(body: String): Pair<Double, Double>? {
        val trimmed = body.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("<")) return null
        val json = JSONObject(trimmed)
        if (!json.has("lat") || !json.has("lon")) return null
        return json.optDouble("lat").toDouble() to json.optDouble("lon").toDouble()
    }

    private fun describeFailure(response: HttpResult): String {
        return when {
            response.code == 404 -> "OpenCellID: cell not found"
            response.code == 401 || response.code == 403 -> "OpenCellID: access denied"
            response.code in 500..599 -> "OpenCellID: server error ${response.code}"
            response.code in 400..499 -> "OpenCellID: request rejected ${response.code}"
            response.body.trim().startsWith("<") -> "OpenCellID: non-JSON response"
            else -> "OpenCellID: lookup failed ${response.code}"
        }
    }
}
