package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.probe.IfconfigClient
import com.notcvnt.rknhardering.probe.MtProtoProber
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyScanner
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.ScanMode
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayApiScanner
import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

object BypassChecker {

    data class Progress(
        val phase: String,
        val detail: String,
    )

    suspend fun check(
        onProgress: (suspend (Progress) -> Unit)? = null,
    ): BypassResult = coroutineScope {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val scanner = ProxyScanner()
        val xrayScanner = XrayApiScanner()

        val proxyDeferred = async {
            onProgress?.invoke(Progress("Сканирование портов", "Поиск открытых прокси на localhost..."))
            scanner.findOpenProxyEndpoint(
                mode = ScanMode.AUTO,
                manualPort = null,
                onProgress = { progress ->
                    val phaseText = when (progress.phase) {
                        com.notcvnt.rknhardering.probe.ScanPhase.POPULAR_PORTS -> "Популярные порты"
                        com.notcvnt.rknhardering.probe.ScanPhase.FULL_RANGE -> "Полное сканирование"
                    }
                    val percent = if (progress.total > 0) (progress.scanned * 100 / progress.total) else 0
                    onProgress?.invoke(Progress(phaseText, "Порт ${progress.currentPort} ($percent%)"))
                },
            )
        }

        val xrayDeferred = async {
            onProgress?.invoke(Progress("Xray API", "Поиск gRPC API на localhost..."))
            xrayScanner.findXrayApi { progress ->
                val percent = if (progress.total > 0) (progress.scanned * 100 / progress.total) else 0
                onProgress?.invoke(Progress("Xray API", "${progress.host}:${progress.currentPort} ($percent%)"))
            }
        }

        val proxyEndpoint = proxyDeferred.await()
        val xrayApiScanResult = xrayDeferred.await()

        reportProxyResult(proxyEndpoint, findings, evidence)
        reportXrayApiResult(xrayApiScanResult, findings, evidence)

        var directIp: String? = null
        var proxyIp: String? = null
        var confirmedBypass = false

        if (proxyEndpoint != null) {
            onProgress?.invoke(Progress("Проверка IP", "Получение прямого IP и IP через прокси..."))

            val directDeferred = async { IfconfigClient.fetchDirectIp() }
            val proxyIpDeferred = async { IfconfigClient.fetchIpViaProxy(proxyEndpoint) }

            directIp = directDeferred.await().getOrNull()
            proxyIp = proxyIpDeferred.await().getOrNull()

            findings.add(Finding("Прямой IP: ${directIp ?: "не удалось получить"}"))
            findings.add(Finding("IP через прокси: ${proxyIp ?: "не удалось получить"}"))

            if (directIp != null && proxyIp != null && directIp != proxyIp) {
                confirmedBypass = true
                findings.add(
                    Finding(
                        description = "Per-app split bypass: подтвержден (IP отличаются)",
                        detected = true,
                        source = EvidenceSource.SPLIT_TUNNEL_BYPASS,
                        confidence = EvidenceConfidence.HIGH,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.SPLIT_TUNNEL_BYPASS,
                        detected = true,
                        confidence = EvidenceConfidence.HIGH,
                        description = "Direct IP differs from proxy IP",
                    ),
                )
            } else if (directIp != null && proxyIp != null) {
                findings.add(Finding("Per-app split отключен: IP совпадают"))
            }

            // MTProto probe: if SOCKS5 proxy found but HTTP didn't work through it,
            // check if it forwards Telegram DC traffic (MTProto-only proxy like tg-ws-proxy).
            // Informational only — does not contribute to verdict scoring.
            if (proxyEndpoint.type == ProxyType.SOCKS5 && proxyIp == null) {
                onProgress?.invoke(Progress("MTProto probe", "Проверка Telegram DC через прокси..."))
                val mtResult = MtProtoProber.probe(proxyEndpoint.host, proxyEndpoint.port)
                if (mtResult.reachable) {
                    val addr = mtResult.targetAddress
                    findings.add(
                        Finding(
                            description = "MTProto-прокси: Telegram DC доступен через " +
                                "${formatHostPort(proxyEndpoint.host, proxyEndpoint.port)}" +
                                " -> ${addr?.address?.hostAddress}:${addr?.port}",
                            detected = true,
                            source = EvidenceSource.LOCAL_PROXY,
                            confidence = EvidenceConfidence.HIGH,
                            family = VpnAppCatalog.FAMILY_TG_WS_PROXY,
                        ),
                    )
                } else {
                    findings.add(Finding("MTProto probe: Telegram DC недоступен через прокси"))
                }
            }
        }

        val detected = confirmedBypass || xrayApiScanResult != null
        val needsReview = !detected && proxyEndpoint != null

        BypassResult(
            proxyEndpoint = proxyEndpoint,
            directIp = directIp,
            proxyIp = proxyIp,
            xrayApiScanResult = xrayApiScanResult,
            findings = findings,
            detected = detected,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    private fun reportProxyResult(
        proxyEndpoint: ProxyEndpoint?,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ) {
        if (proxyEndpoint == null) {
            findings.add(Finding("Открытые прокси на localhost: не обнаружены"))
            return
        }

        val candidateFamilies = VpnAppCatalog.familiesForPort(proxyEndpoint.port)
        val familySuffix = candidateFamilies.takeIf { it.isNotEmpty() }?.joinToString()
        val description = buildString {
            append("Открытый ")
            append(proxyEndpoint.type.name)
            append(" прокси: ")
            append(formatHostPort(proxyEndpoint.host, proxyEndpoint.port))
            if (!familySuffix.isNullOrBlank()) {
                append(" [")
                append(familySuffix)
                append("]")
            }
            append(" (требует подтверждения обхода)")
        }

        findings.add(
            Finding(
                description = description,
                needsReview = true,
                source = EvidenceSource.LOCAL_PROXY,
                confidence = EvidenceConfidence.MEDIUM,
                family = familySuffix,
            ),
        )
        evidence.add(
            EvidenceItem(
                source = EvidenceSource.LOCAL_PROXY,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = "Detected open ${proxyEndpoint.type.name} proxy at ${formatHostPort(proxyEndpoint.host, proxyEndpoint.port)}",
                family = familySuffix,
            ),
        )
    }

    private fun reportXrayApiResult(
        xrayApiScanResult: XrayApiScanResult?,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ) {
        if (xrayApiScanResult == null) {
            findings.add(Finding("Xray gRPC API: не обнаружен"))
            return
        }

        val ep = xrayApiScanResult.endpoint
        findings.add(
            Finding(
                description = "Xray gRPC API: ${formatHostPort(ep.host, ep.port)}",
                detected = true,
                source = EvidenceSource.XRAY_API,
                confidence = EvidenceConfidence.HIGH,
                family = VpnAppCatalog.FAMILY_XRAY,
            ),
        )
        evidence.add(
            EvidenceItem(
                source = EvidenceSource.XRAY_API,
                detected = true,
                confidence = EvidenceConfidence.HIGH,
                description = "Detected Xray gRPC API at ${formatHostPort(ep.host, ep.port)}",
                family = VpnAppCatalog.FAMILY_XRAY,
            ),
        )

        for (outbound in xrayApiScanResult.outbounds.take(10)) {
            val detail = buildString {
                append("  ")
                append(outbound.tag)
                outbound.protocolName?.let { append(" [$it]") }
                if (outbound.address != null && outbound.port != null) {
                    append(" -> ${outbound.address}:${outbound.port}")
                }
                outbound.sni?.let { append(", sni=$it") }
            }
            findings.add(
                Finding(
                    description = detail,
                    detected = true,
                    source = EvidenceSource.XRAY_API,
                    confidence = EvidenceConfidence.HIGH,
                    family = VpnAppCatalog.FAMILY_XRAY,
                ),
            )
        }
        if (xrayApiScanResult.outbounds.size > 10) {
            findings.add(
                Finding(
                    description = "  ...ещё ${xrayApiScanResult.outbounds.size - 10} аутбаундов",
                    detected = true,
                    source = EvidenceSource.XRAY_API,
                    confidence = EvidenceConfidence.HIGH,
                    family = VpnAppCatalog.FAMILY_XRAY,
                ),
            )
        }
    }

    private fun formatHostPort(host: String, port: Int): String {
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }
}
