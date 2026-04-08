package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import com.notcvnt.rknhardering.vpn.VpnClientSignal
import com.notcvnt.rknhardering.vpn.VpnDumpsysParser
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetAddress
import java.net.NetworkInterface

object IndirectSignsChecker {

    private data class SignalOutcome(
        val detected: Boolean = false,
        val needsReview: Boolean = false,
    )

    internal enum class DnsClassification {
        LOOPBACK,
        PRIVATE_LAN,
        PRIVATE_TUNNEL,
        KNOWN_PUBLIC_RESOLVER,
        LINK_LOCAL,
        OTHER_PUBLIC,
    }

    internal enum class DnsSignalStatus {
        CLEAR,
        NEEDS_REVIEW,
        DETECTED,
    }

    internal data class RouteSnapshot(
        val destination: String,
        val gateway: String?,
        val interfaceName: String?,
        val isDefault: Boolean,
    )

    internal data class NetworkSnapshot(
        val label: String,
        val isActive: Boolean,
        val isVpn: Boolean,
        val interfaceName: String?,
        val routes: List<RouteSnapshot>,
        val dnsServers: List<String>,
    )

    internal data class LocalListener(
        val protocol: String,
        val host: String,
        val port: Int,
        val state: String,
    )

    internal data class RoutingEvaluation(
        val findings: List<Finding>,
        val evidence: List<EvidenceItem>,
        val detected: Boolean,
        val needsReview: Boolean,
    )

    internal data class DnsEvaluation(
        val findings: List<Finding>,
        val evidence: List<EvidenceItem>,
        val detected: Boolean,
        val needsReview: Boolean,
    )

    internal data class ProxyTechnicalEvaluation(
        val findings: List<Finding>,
        val evidence: List<EvidenceItem>,
        val detected: Boolean,
        val needsReview: Boolean,
    )

    private val VPN_INTERFACE_PATTERNS = listOf(
        Regex("^tun\\d+"),
        Regex("^tap\\d+"),
        Regex("^wg\\d+"),
        Regex("^ppp\\d+"),
        Regex("^ipsec.*"),
    )

    private val STANDARD_INTERFACES = listOf(
        Regex("^wlan.*"),
        Regex("^rmnet.*"),
        Regex("^eth.*"),
        Regex("^lo$"),
    )

    private val KNOWN_PUBLIC_RESOLVERS = setOf(
        "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15",
        "77.88.8.8", "77.88.8.1",
        "76.76.19.19",
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2620:fe::fe", "2620:fe::9",
        "2620:119:35::35", "2620:119:53::53",
        "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
    )

    private val PROXY_TOOL_SIGNATURES = VpnAppCatalog.signatures.filter { signature ->
        VpnClientSignal.LOCAL_PROXY in signature.signals && VpnClientSignal.VPN_SERVICE !in signature.signals
    }

    private val KNOWN_LOCAL_PROXY_PORTS = (
        VpnAppCatalog.localhostProxyPorts +
            listOf(80, 443, 1080, 3127, 3128, 4080, 5555, 7000, 7044, 8000, 8080, 8081, 8082, 8888, 9000, 9050, 9051, 9150, 12345)
        ).toSet()

    fun check(context: Context): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        val activeApps = mutableListOf<ActiveVpnApp>()
        var detected = false
        var needsReview = false

        val networkSnapshots = collectNetworkSnapshots(context)

        val notVpnOutcome = checkNotVpnCapability(context, findings, evidence)
        detected = detected || notVpnOutcome.detected
        needsReview = needsReview || notVpnOutcome.needsReview

        detected = checkNetworkInterfaces(findings, evidence) || detected
        detected = checkMtu(findings, evidence) || detected

        val routingOutcome = checkRoutingTable(networkSnapshots)
        findings += routingOutcome.findings
        evidence += routingOutcome.evidence
        detected = detected || routingOutcome.detected
        needsReview = needsReview || routingOutcome.needsReview

        val dnsOutcome = checkDns(networkSnapshots)
        findings += dnsOutcome.findings
        evidence += dnsOutcome.evidence
        detected = detected || dnsOutcome.detected
        needsReview = needsReview || dnsOutcome.needsReview

        val proxyTechnicalOutcome = checkProxyTechnicalSignals(context)
        findings += proxyTechnicalOutcome.findings
        evidence += proxyTechnicalOutcome.evidence
        detected = detected || proxyTechnicalOutcome.detected
        needsReview = needsReview || proxyTechnicalOutcome.needsReview

        val dumpsysVpnOutcome = checkDumpsysVpn(findings, evidence, activeApps)
        detected = detected || dumpsysVpnOutcome.detected
        needsReview = needsReview || dumpsysVpnOutcome.needsReview

        val dumpsysServiceOutcome = checkDumpsysVpnService(findings, evidence, activeApps)
        detected = detected || dumpsysServiceOutcome.detected
        needsReview = needsReview || dumpsysServiceOutcome.needsReview

        return CategoryResult(
            name = "Косвенные признаки",
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
            activeApps = activeApps.distinctBy { Triple(it.packageName, it.serviceName, it.source) },
        )
    }

    private fun collectNetworkSnapshots(context: Context): List<NetworkSnapshot> {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = cm.activeNetwork
            cm.allNetworks.mapNotNull { network ->
                val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
                val linkProperties = cm.getLinkProperties(network) ?: return@mapNotNull null
                if (!caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    linkProperties.routes.isEmpty() &&
                    linkProperties.dnsServers.isEmpty()
                ) {
                    return@mapNotNull null
                }

                NetworkSnapshot(
                    label = network.toString(),
                    isActive = network == activeNetwork,
                    isVpn = caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN),
                    interfaceName = linkProperties.interfaceName,
                    routes = linkProperties.routes.map { route ->
                        RouteSnapshot(
                            destination = route.destination?.toString()
                                ?: if (route.isDefaultRoute) "0.0.0.0/0" else "unknown",
                            gateway = route.gateway?.hostAddress?.takeUnless { it == "0.0.0.0" || it == "::" },
                            interfaceName = route.`interface` ?: linkProperties.interfaceName,
                            isDefault = route.isDefaultRoute,
                        )
                    },
                    dnsServers = linkProperties.dnsServers.mapNotNull { it.hostAddress?.lowercase() },
                )
            }.sortedByDescending { it.isActive }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun checkNotVpnCapability(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork ?: return SignalOutcome()
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return SignalOutcome()

        val capsString = caps.toString()
        val hasNotVpn = capsString.contains("NOT_VPN")
        findings.add(
            Finding(
                description = "Capability NOT_VPN: ${if (hasNotVpn) "присутствует" else "отсутствует (подозрительно)"}",
                detected = !hasNotVpn,
                source = EvidenceSource.INDIRECT_NETWORK_CAPABILITIES,
                confidence = (!hasNotVpn).takeIf { it }?.let { EvidenceConfidence.MEDIUM },
            ),
        )
        if (!hasNotVpn) {
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.INDIRECT_NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Active network does not expose NOT_VPN capability",
                ),
            )
        }
        return SignalOutcome(detected = !hasNotVpn)
    }

    private fun checkNetworkInterfaces(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): Boolean {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            val vpnInterfaces = interfaces.filter { iface ->
                iface.isUp && VPN_INTERFACE_PATTERNS.any { pattern -> pattern.matches(iface.name) }
            }

            if (vpnInterfaces.isEmpty()) {
                findings.add(Finding("VPN-интерфейсы (tun/tap/wg/ppp/ipsec): не обнаружены"))
                return false
            }

            for (iface in vpnInterfaces) {
                findings.add(
                    Finding(
                        description = "VPN-интерфейс обнаружен: ${iface.name}",
                        detected = true,
                        source = EvidenceSource.NETWORK_INTERFACE,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.NETWORK_INTERFACE,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Active VPN-like interface ${iface.name}",
                    ),
                )
            }
            true
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке интерфейсов: ${e.message}"))
            false
        }
    }

    private fun checkMtu(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): Boolean {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            var detected = false
            for (iface in interfaces) {
                if (!iface.isUp) continue
                val isVpnLike = VPN_INTERFACE_PATTERNS.any { it.matches(iface.name) }
                if (!isVpnLike) continue

                val mtu = iface.mtu
                if (mtu !in 1..1499) continue

                findings.add(
                    Finding(
                        description = "MTU аномалия: ${iface.name} MTU=$mtu (< 1500)",
                        detected = true,
                        source = EvidenceSource.NETWORK_INTERFACE,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.NETWORK_INTERFACE,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "VPN-like interface ${iface.name} uses low MTU $mtu",
                    ),
                )
                detected = true
            }

            val activeInterfaces = interfaces.filter { it.isUp && it.mtu in 1..1499 }
            val nonVpnLowMtu = activeInterfaces.filter { iface ->
                !VPN_INTERFACE_PATTERNS.any { it.matches(iface.name) } &&
                    !STANDARD_INTERFACES.any { it.matches(iface.name) }
            }
            for (iface in nonVpnLowMtu) {
                findings.add(
                    Finding(
                        description = "MTU аномалия: нестандартный интерфейс ${iface.name} MTU=${iface.mtu}",
                        detected = true,
                        source = EvidenceSource.NETWORK_INTERFACE,
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.NETWORK_INTERFACE,
                        detected = true,
                        confidence = EvidenceConfidence.LOW,
                        description = "Non-standard interface ${iface.name} uses low MTU ${iface.mtu}",
                    ),
                )
                detected = true
            }

            if (!detected) {
                findings.add(Finding("MTU: аномалий не обнаружено"))
            }

            detected
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке MTU: ${e.message}"))
            false
        }
    }

    internal fun checkRoutingTable(networkSnapshots: List<NetworkSnapshot>): RoutingEvaluation {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false

        val snapshotsWithRoutes = networkSnapshots.filter { it.routes.isNotEmpty() }
        for (snapshot in snapshotsWithRoutes) {
            val defaultRoutes = snapshot.routes.filter { it.isDefault }
            for (route in defaultRoutes) {
                val iface = route.interfaceName
                if (iface != null && isStandardInterface(iface) && !snapshot.isVpn) {
                    findings.add(Finding("Маршрут по умолчанию: $iface (стандартный)"))
                    continue
                }

                findings.add(
                    Finding(
                        description = "Маршрут по умолчанию через нестандартный интерфейс: ${iface ?: "N/A"}",
                        detected = true,
                        source = EvidenceSource.ROUTING,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ROUTING,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Default route points to non-standard interface ${iface ?: "N/A"}",
                    ),
                )
                detected = true
            }

            val dedicatedRoutes = snapshot.routes.filter { route ->
                !route.isDefault && route.interfaceName != null && isVpnOrNonStandardInterface(route.interfaceName)
            }
            if (dedicatedRoutes.isNotEmpty()) {
                val routePreview = dedicatedRoutes.take(3).joinToString { route ->
                    "${route.destination} via ${route.interfaceName ?: "N/A"}"
                }
                findings.add(
                    Finding(
                        description = "Выделенные маршруты через VPN/нестандартный интерфейс: $routePreview",
                        detected = true,
                        source = EvidenceSource.ROUTING,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ROUTING,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Dedicated routes found on VPN/non-standard interfaces",
                    ),
                )
                detected = true
            }
        }

        val procDefaultInterfaces = collectProcDefaultRouteInterfaces()
        if (snapshotsWithRoutes.none { snapshot -> snapshot.routes.any { it.isDefault } } && procDefaultInterfaces.isNotEmpty()) {
            for (iface in procDefaultInterfaces) {
                if (isStandardInterface(iface)) {
                    findings.add(Finding("Маршрут по умолчанию (/proc/net/route): $iface (стандартный)"))
                    continue
                }

                findings.add(
                    Finding(
                        description = "Маршрут по умолчанию (/proc/net/route) через нестандартный интерфейс: $iface",
                        detected = true,
                        source = EvidenceSource.ROUTING,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ROUTING,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Default route from /proc/net/route points to non-standard interface $iface",
                    ),
                )
                detected = true
            }
        }

        val hasVpnRoutes = snapshotsWithRoutes.any { snapshot ->
            (snapshot.isVpn || isVpnOrNonStandardInterface(snapshot.interfaceName)) &&
                snapshot.routes.any { !it.isDefault }
        }
        val hasUnderlyingDefaultRoute = snapshotsWithRoutes.any { snapshot ->
            !snapshot.isVpn &&
                snapshot.routes.any { route ->
                    route.isDefault && route.interfaceName != null && isStandardInterface(route.interfaceName)
                }
        }
        if (hasVpnRoutes && hasUnderlyingDefaultRoute) {
            findings.add(
                Finding(
                    description = "Маршрутизация указывает на split tunneling: одновременно видны direct и tunnel routes",
                    detected = true,
                    source = EvidenceSource.ROUTING,
                    confidence = EvidenceConfidence.MEDIUM,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.ROUTING,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Split-tunneling route pattern detected",
                ),
            )
            detected = true
        }

        if (snapshotsWithRoutes.none { snapshot -> snapshot.routes.any { it.gateway != null } }) {
            findings.add(Finding("Маршрут до шлюза провайдера: не удалось оценить через API Android"))
        }

        if (!detected && findings.isEmpty()) {
            findings.add(Finding("Маршрутизация: аномалий не обнаружено"))
        }

        return RoutingEvaluation(
            findings = findings,
            evidence = evidence,
            detected = detected,
            needsReview = false,
        )
    }

    internal fun checkDns(networkSnapshots: List<NetworkSnapshot>): DnsEvaluation {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false
        var needsReview = false

        val activeSnapshot = networkSnapshots.firstOrNull { it.isActive }
        if (activeSnapshot == null) {
            findings.add(Finding("DNS: активная сеть не найдена"))
            return DnsEvaluation(findings, evidence, detected = false, needsReview = false)
        }

        if (activeSnapshot.dnsServers.isEmpty()) {
            findings.add(Finding("DNS серверы: не обнаружены"))
            return DnsEvaluation(findings, evidence, detected = false, needsReview = false)
        }

        val activeVpn = activeSnapshot.isVpn || isVpnOrNonStandardInterface(activeSnapshot.interfaceName)
        val activeRouteInterface = activeSnapshot.routes.firstOrNull { it.isDefault }?.interfaceName ?: activeSnapshot.interfaceName
        val routeViaVpnInterface = isVpnOrNonStandardInterface(activeRouteInterface)
        val underlyingDns = networkSnapshots
            .filter { !it.isVpn }
            .flatMapTo(linkedSetOf()) { it.dnsServers }

        for (dns in activeSnapshot.dnsServers.distinct()) {
            val changedFromUnderlying = underlyingDns.isNotEmpty() && dns !in underlyingDns
            when (classifyDnsAddress(dns)) {
                DnsClassification.LOOPBACK -> {
                    findings.add(
                        Finding(
                            description = "DNS указывает на localhost: $dns (типично для VPN/локального proxy)",
                            detected = true,
                            source = EvidenceSource.DNS,
                            confidence = EvidenceConfidence.HIGH,
                        ),
                    )
                    evidence.add(
                        EvidenceItem(
                            source = EvidenceSource.DNS,
                            detected = true,
                            confidence = EvidenceConfidence.HIGH,
                            description = "DNS resolver uses loopback address $dns",
                        ),
                    )
                    detected = true
                }

                DnsClassification.PRIVATE_TUNNEL -> {
                    val vpnAssigned = activeVpn && (changedFromUnderlying || routeViaVpnInterface)
                    findings.add(
                        Finding(
                            description = buildString {
                                append("DNS в туннельной подсети: $dns")
                                if (changedFromUnderlying) append(" (отличается от underlying сети)")
                            },
                            detected = vpnAssigned,
                            needsReview = !vpnAssigned,
                            source = EvidenceSource.DNS,
                            confidence = if (vpnAssigned) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
                        ),
                    )
                    evidence.add(
                        EvidenceItem(
                            source = EvidenceSource.DNS,
                            detected = true,
                            confidence = if (vpnAssigned) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
                            description = "DNS resolver uses private tunnel address $dns",
                        ),
                    )
                    detected = detected || vpnAssigned
                    needsReview = needsReview || !vpnAssigned
                }

                DnsClassification.PRIVATE_LAN -> {
                    if (activeVpn && changedFromUnderlying) {
                        findings.add(
                            Finding(
                                description = "DNS в LAN-подсети изменился при активном VPN: $dns",
                                needsReview = true,
                                source = EvidenceSource.DNS,
                                confidence = EvidenceConfidence.LOW,
                            ),
                        )
                        evidence.add(
                            EvidenceItem(
                                source = EvidenceSource.DNS,
                                detected = true,
                                confidence = EvidenceConfidence.LOW,
                                description = "Private LAN DNS differs from underlying network: $dns",
                            ),
                        )
                        needsReview = true
                    } else {
                        findings.add(Finding("DNS: $dns (локальный резолвер приватной сети)"))
                    }
                }

                DnsClassification.KNOWN_PUBLIC_RESOLVER,
                DnsClassification.OTHER_PUBLIC,
                -> {
                    if (activeVpn && changedFromUnderlying) {
                        findings.add(
                            Finding(
                                description = "DNS заменён при активном VPN: $dns",
                                needsReview = true,
                                source = EvidenceSource.DNS,
                                confidence = EvidenceConfidence.LOW,
                            ),
                        )
                        evidence.add(
                            EvidenceItem(
                                source = EvidenceSource.DNS,
                                detected = true,
                                confidence = EvidenceConfidence.LOW,
                                description = "DNS differs from underlying network while VPN is active: $dns",
                            ),
                        )
                        needsReview = true
                    } else if (activeVpn && underlyingDns.isEmpty()) {
                        findings.add(Finding("DNS: $dns (источник не удалось сопоставить с underlying сетью)"))
                    } else {
                        findings.add(Finding("DNS: $dns"))
                    }
                }

                DnsClassification.LINK_LOCAL -> findings.add(Finding("DNS: $dns (link-local)"))
            }
        }

        return DnsEvaluation(findings, evidence, detected, needsReview)
    }

    private fun checkProxyTechnicalSignals(context: Context): ProxyTechnicalEvaluation {
        val installedProxyTools = detectInstalledProxyTools(context)
        val listeners = collectLocalListeners()
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false
        var needsReview = false

        for (packageName in installedProxyTools) {
            val signature = PROXY_TOOL_SIGNATURES.firstOrNull { it.packageName == packageName } ?: continue
            val description = "Установлена proxy-утилита: ${signature.appName} (${signature.packageName})"
            findings.add(
                Finding(
                    description = description,
                    needsReview = true,
                    source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                    confidence = EvidenceConfidence.LOW,
                    family = signature.family,
                    packageName = signature.packageName,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                    detected = true,
                    confidence = EvidenceConfidence.LOW,
                    description = description,
                    family = signature.family,
                    packageName = signature.packageName,
                    kind = signature.kind,
                ),
            )
            needsReview = true
        }

        val loopbackListeners = listeners.filter { listener ->
            isLoopbackOrAnyAddress(listener.host) && listener.port in KNOWN_LOCAL_PROXY_PORTS
        }
        if (loopbackListeners.isNotEmpty()) {
            for (listener in loopbackListeners.distinctBy { Triple(it.protocol, it.host, it.port) }) {
                val description = "Local listener на proxy-порту: ${listener.host}:${listener.port}/${listener.protocol}"
                findings.add(
                    Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = description,
                    ),
                )
            }
            detected = true
        } else if (listeners.isNotEmpty()) {
            val localhostHighPorts = listeners.count { listener ->
                isLoopbackOrAnyAddress(listener.host) && listener.port >= 1024
            }
            if (localhostHighPorts >= 3) {
                findings.add(
                    Finding(
                        description = "Обнаружено несколько localhost listeners на высоких портах: $localhostHighPorts",
                        needsReview = true,
                        source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                        detected = true,
                        confidence = EvidenceConfidence.LOW,
                        description = "Multiple localhost listeners detected on high ports",
                    ),
                )
                needsReview = true
            }
        }

        if (installedProxyTools.isEmpty() && listeners.isEmpty()) {
            findings.add(Finding("Дополнительные proxy-технические признаки: не обнаружены"))
        }

        findings.add(
            Finding(
                description = "Проверки процессов, iptables/pf и системных сертификатов ограничены без root/privileged access",
            ),
        )

        return ProxyTechnicalEvaluation(
            findings = findings,
            evidence = evidence,
            detected = detected,
            needsReview = needsReview,
        )
    }

    internal fun parseProcNetListeners(lines: List<String>, protocol: String): List<LocalListener> {
        return lines.drop(1).mapNotNull { line ->
            val parts = line.trim().split("\\s+".toRegex())
            if (parts.size < 4) return@mapNotNull null

            val localAddress = parts[1]
            val state = parts[3]
            if (protocol.startsWith("tcp") && state != "0A") return@mapNotNull null
            if (protocol.startsWith("udp") && state !in setOf("07", "0A")) return@mapNotNull null

            val hostPort = localAddress.split(":")
            if (hostPort.size != 2) return@mapNotNull null

            val host = decodeProcAddress(hostPort[0], ipv6 = protocol.endsWith("6")) ?: return@mapNotNull null
            val port = hostPort[1].toIntOrNull(16) ?: return@mapNotNull null

            LocalListener(
                protocol = protocol,
                host = host.lowercase(),
                port = port,
                state = state,
            )
        }
    }

    private fun detectInstalledProxyTools(context: Context): Set<String> {
        val pm = context.packageManager
        return PROXY_TOOL_SIGNATURES.mapNotNullTo(linkedSetOf()) { signature ->
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(signature.packageName, android.content.pm.PackageManager.PackageInfoFlags.of(0L))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(signature.packageName, 0)
                }
                signature.packageName
            } catch (_: Exception) {
                null
            }
        }
    }

    private fun collectLocalListeners(): List<LocalListener> {
        val files = listOf(
            "tcp" to "/proc/net/tcp",
            "tcp6" to "/proc/net/tcp6",
            "udp" to "/proc/net/udp",
            "udp6" to "/proc/net/udp6",
        )
        return files.flatMap { (protocol, path) ->
            val file = File(path)
            if (!file.exists()) return@flatMap emptyList()
            runCatching {
                BufferedReader(FileReader(file)).use { reader ->
                    parseProcNetListeners(reader.readLines(), protocol)
                }
            }.getOrDefault(emptyList())
        }
    }

    private fun decodeProcAddress(hexAddress: String, ipv6: Boolean): String? {
        return try {
            val bytes = hexAddress.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val orderedBytes = if (ipv6) bytes else bytes.reversedArray()
            InetAddress.getByAddress(orderedBytes).hostAddress
        } catch (_: Exception) {
            null
        }
    }

    private fun collectProcDefaultRouteInterfaces(): List<String> {
        return try {
            val routeFile = File("/proc/net/route")
            if (!routeFile.exists()) return emptyList()
            BufferedReader(FileReader(routeFile)).use { reader ->
                reader.readLines()
                    .drop(1)
                    .mapNotNull { line ->
                        val parts = line.trim().split("\\s+".toRegex())
                        parts.takeIf { it.size >= 2 && it[1] == "00000000" }?.get(0)
                    }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun isStandardInterface(name: String?): Boolean {
        if (name.isNullOrBlank()) return false
        return STANDARD_INTERFACES.any { it.matches(name) }
    }

    private fun isVpnOrNonStandardInterface(name: String?): Boolean {
        if (name.isNullOrBlank()) return false
        return !isStandardInterface(name)
    }

    private fun isLoopbackOrAnyAddress(host: String): Boolean {
        return host == "0.0.0.0" || host == "::" || host == ":::" ||
            host == "::1" || host.startsWith("127.")
    }

    private fun isPrivate172(addr: String): Boolean {
        val parts = addr.split(".")
        if (parts.size < 2) return false
        val second = parts[1].toIntOrNull() ?: return false
        return second in 16..31
    }

    private fun isPrivateCarrierGradeNat(addr: String): Boolean {
        val parts = addr.split(".")
        if (parts.size < 2 || parts[0] != "100") return false
        val second = parts[1].toIntOrNull() ?: return false
        return second in 64..127
    }

    private fun checkDumpsysVpn(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        activeApps: MutableList<ActiveVpnApp>,
    ): SignalOutcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return SignalOutcome()
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "vpn_management"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (VpnDumpsysParser.isUnavailable(output)) {
                findings.add(Finding("dumpsys vpn_management: недоступен"))
                return SignalOutcome()
            }

            val records = VpnDumpsysParser.parseVpnManagement(output)
            if (records.isEmpty()) {
                findings.add(Finding("dumpsys vpn_management: активных VPN нет"))
                return SignalOutcome()
            }

            var detected = false
            var needsReview = false
            for (record in records) {
                val signature = record.packageName?.let { VpnAppCatalog.findByPackageName(it) }
                val confidence = when {
                    signature != null -> EvidenceConfidence.HIGH
                    record.packageName != null -> EvidenceConfidence.MEDIUM
                    else -> EvidenceConfidence.LOW
                }
                val description = buildString {
                    append("VPN management: ")
                    append(record.rawLine)
                    signature?.family?.let {
                        append(" [")
                        append(it)
                        append("]")
                    }
                }
                findings.add(
                    Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                        family = signature?.family,
                        packageName = record.packageName,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ACTIVE_VPN,
                        detected = true,
                        confidence = confidence,
                        description = record.rawLine,
                        family = signature?.family,
                        packageName = record.packageName,
                        kind = signature?.kind,
                    ),
                )
                activeApps.add(
                    ActiveVpnApp(
                        packageName = record.packageName,
                        serviceName = null,
                        family = signature?.family,
                        kind = signature?.kind,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                    ),
                )
                detected = true
                needsReview = needsReview || signature == null
            }

            SignalOutcome(detected = detected, needsReview = needsReview)
        } catch (e: Exception) {
            findings.add(Finding("dumpsys vpn_management: ${e.message}"))
            SignalOutcome()
        }
    }

    private fun checkDumpsysVpnService(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        activeApps: MutableList<ActiveVpnApp>,
    ): SignalOutcome {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "activity", "services", "android.net.VpnService"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (VpnDumpsysParser.isUnavailable(output)) {
                findings.add(Finding("dumpsys activity services VpnService: недоступен"))
                return SignalOutcome()
            }

            val records = VpnDumpsysParser.parseVpnServices(output)
            if (records.isEmpty()) {
                findings.add(Finding("Активные VpnService: не обнаружены"))
                return SignalOutcome()
            }

            var detected = false
            var needsReview = false
            for (record in records) {
                val signature = record.packageName?.let { VpnAppCatalog.findByPackageName(it) }
                val confidence = when {
                    signature != null -> EvidenceConfidence.HIGH
                    record.packageName != null -> EvidenceConfidence.MEDIUM
                    else -> EvidenceConfidence.LOW
                }
                val serviceDisplay = if (record.packageName != null && record.serviceName != null) {
                    "${record.packageName}/${record.serviceName}"
                } else {
                    record.rawLine
                }
                val description = buildString {
                    append("VpnService активен: ")
                    append(serviceDisplay)
                    signature?.family?.let {
                        append(" [")
                        append(it)
                        append("]")
                    }
                }
                findings.add(
                    Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                        family = signature?.family,
                        packageName = record.packageName,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ACTIVE_VPN,
                        detected = true,
                        confidence = confidence,
                        description = serviceDisplay,
                        family = signature?.family,
                        packageName = record.packageName,
                        kind = signature?.kind,
                    ),
                )
                activeApps.add(
                    ActiveVpnApp(
                        packageName = record.packageName,
                        serviceName = record.serviceName,
                        family = signature?.family,
                        kind = signature?.kind,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                    ),
                )
                detected = true
                needsReview = needsReview || signature == null
            }

            SignalOutcome(detected = detected, needsReview = needsReview)
        } catch (e: Exception) {
            findings.add(Finding("dumpsys activity services: ${e.message}"))
            SignalOutcome()
        }
    }

    internal fun classifyDnsAddress(addr: String): DnsClassification {
        val normalized = addr.lowercase()
        if (normalized == "::1" || normalized.startsWith("127.")) return DnsClassification.LOOPBACK
        if (normalized.startsWith("169.254.") || normalized.startsWith("fe80:")) {
            return DnsClassification.LINK_LOCAL
        }
        if (
            normalized.startsWith("10.") ||
            (normalized.startsWith("172.") && isPrivate172(normalized)) ||
            isPrivateCarrierGradeNat(normalized) ||
            normalized.startsWith("fc") ||
            normalized.startsWith("fd")
        ) {
            return DnsClassification.PRIVATE_TUNNEL
        }
        if (normalized.startsWith("192.168.")) return DnsClassification.PRIVATE_LAN
        if (normalized in KNOWN_PUBLIC_RESOLVERS) return DnsClassification.KNOWN_PUBLIC_RESOLVER
        return DnsClassification.OTHER_PUBLIC
    }

    internal fun classifyDnsSignalStatus(addr: String): DnsSignalStatus {
        return when (classifyDnsAddress(addr)) {
            DnsClassification.LOOPBACK -> DnsSignalStatus.DETECTED
            DnsClassification.PRIVATE_TUNNEL -> DnsSignalStatus.NEEDS_REVIEW
            DnsClassification.PRIVATE_LAN,
            DnsClassification.KNOWN_PUBLIC_RESOLVER,
            DnsClassification.LINK_LOCAL,
            DnsClassification.OTHER_PUBLIC,
            -> DnsSignalStatus.CLEAR
        }
    }
}
