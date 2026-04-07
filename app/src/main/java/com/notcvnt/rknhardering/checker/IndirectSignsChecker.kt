package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.NetworkInterface

object IndirectSignsChecker {

    private val VPN_INTERFACE_PATTERNS = listOf(
        Regex("^tun\\d+"),
        Regex("^tap\\d+"),
        Regex("^wg\\d+"),
        Regex("^ppp\\d+"),
        Regex("^ipsec.*")
    )

    private val STANDARD_INTERFACES = listOf(
        Regex("^wlan.*"),
        Regex("^rmnet.*"),
        Regex("^eth.*"),
        Regex("^lo$")
    )

    fun check(context: Context): CategoryResult {
        val findings = mutableListOf<Finding>()

        checkNotVpnCapability(context, findings)
        checkNetworkInterfaces(findings)
        checkMtu(findings)
        checkRoutingTable(findings)
        checkDns(context, findings)
        checkDumpsysVpn(findings)
        checkDumpsysVpnService(findings)

        val detected = findings.any { it.detected }
        return CategoryResult(
            name = "Косвенные признаки",
            detected = detected,
            findings = findings
        )
    }

    private fun checkNotVpnCapability(context: Context, findings: MutableList<Finding>) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork ?: return
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return

        val capsString = caps.toString()
        val hasNotVpn = capsString.contains("NOT_VPN")
        findings.add(
            Finding(
                "Capability NOT_VPN: ${if (hasNotVpn) "присутствует" else "отсутствует (подозрительно)"}",
                !hasNotVpn
            )
        )
    }

    private fun checkNetworkInterfaces(findings: MutableList<Finding>) {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            val vpnInterfaces = interfaces.filter { iface ->
                iface.isUp && VPN_INTERFACE_PATTERNS.any { pattern -> pattern.matches(iface.name) }
            }

            if (vpnInterfaces.isNotEmpty()) {
                for (iface in vpnInterfaces) {
                    findings.add(
                        Finding("VPN-интерфейс обнаружен: ${iface.name}", true)
                    )
                }
            } else {
                findings.add(Finding("VPN-интерфейсы (tun/tap/wg/ppp/ipsec): не обнаружены", false))
            }
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке интерфейсов: ${e.message}", false))
        }
    }

    private fun checkMtu(findings: MutableList<Finding>) {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            for (iface in interfaces) {
                if (!iface.isUp) continue
                val isVpnLike = VPN_INTERFACE_PATTERNS.any { it.matches(iface.name) }
                if (!isVpnLike) continue

                val mtu = iface.mtu
                if (mtu in 1..1499) {
                    findings.add(
                        Finding("MTU аномалия: ${iface.name} MTU=$mtu (< 1500)", true)
                    )
                }
            }

            val activeInterfaces = interfaces.filter { it.isUp && it.mtu in 1..1499 }
            val nonVpnLowMtu = activeInterfaces.filter { iface ->
                !VPN_INTERFACE_PATTERNS.any { it.matches(iface.name) } &&
                    !STANDARD_INTERFACES.any { it.matches(iface.name) }
            }
            for (iface in nonVpnLowMtu) {
                findings.add(
                    Finding("MTU аномалия: нестандартный интерфейс ${iface.name} MTU=${iface.mtu}", true)
                )
            }

            if (findings.none { it.description.startsWith("MTU") }) {
                findings.add(Finding("MTU: аномалий не обнаружено", false))
            }
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке MTU: ${e.message}", false))
        }
    }

    private fun checkRoutingTable(findings: MutableList<Finding>) {
        try {
            val routeFile = File("/proc/net/route")
            if (!routeFile.exists()) {
                findings.add(Finding("Таблица маршрутизации: /proc/net/route недоступен", false))
                return
            }

            val lines = BufferedReader(FileReader(routeFile)).use { it.readLines() }
            val defaultRoutes = lines.drop(1).filter { line ->
                val parts = line.trim().split("\\s+".toRegex())
                parts.size >= 2 && parts[1] == "00000000"
            }

            if (defaultRoutes.isEmpty()) {
                findings.add(Finding("Маршрут по умолчанию: не найден", false))
                return
            }

            for (route in defaultRoutes) {
                val parts = route.trim().split("\\s+".toRegex())
                val iface = parts[0]
                val isStandard = STANDARD_INTERFACES.any { it.matches(iface) }
                if (!isStandard) {
                    findings.add(
                        Finding(
                            "Маршрут по умолчанию через нестандартный интерфейс: $iface",
                            true
                        )
                    )
                } else {
                    findings.add(
                        Finding("Маршрут по умолчанию: $iface (стандартный)", false)
                    )
                }
            }
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке маршрутов: ${e.message}", false))
        }
    }

    private fun checkDns(context: Context, findings: MutableList<Finding>) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = cm.activeNetwork
            if (activeNetwork == null) {
                findings.add(Finding("DNS: активная сеть не найдена", false))
                return
            }

            val linkProperties = cm.getLinkProperties(activeNetwork)
            if (linkProperties == null) {
                findings.add(Finding("DNS: LinkProperties недоступны", false))
                return
            }

            val dnsServers = linkProperties.dnsServers
            if (dnsServers.isEmpty()) {
                findings.add(Finding("DNS серверы: не обнаружены", false))
                return
            }

            for (dns in dnsServers) {
                val addr = dns.hostAddress ?: continue
                val isLocalhost = addr.startsWith("127.")
                val isLinkLocal = addr.startsWith("169.254.")
                val isTunnelPrivate = addr.startsWith("10.") ||
                    (addr.startsWith("172.") && isPrivate172(addr)) ||
                    addr.startsWith("192.168.")

                when {
                    isLocalhost -> findings.add(
                        Finding("DNS указывает на localhost: $addr (типично для VPN)", true)
                    )
                    isLinkLocal -> findings.add(
                        Finding("DNS: $addr (link-local)", false)
                    )
                    isTunnelPrivate -> findings.add(
                        Finding("DNS в частной подсети: $addr (может указывать на VPN-туннель)", true)
                    )
                    else -> findings.add(
                        Finding("DNS: $addr", false)
                    )
                }
            }
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке DNS: ${e.message}", false))
        }
    }

    private fun checkDumpsysVpn(findings: MutableList<Finding>) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "vpn_management"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (output.isBlank() || output.contains("Permission Denial") || output.contains("Can't find service")) {
                findings.add(Finding("dumpsys vpn_management: недоступен", false))
                return
            }

            val vpnLines = output.lines().filter {
                it.contains("Active package name:") || it.contains("Active vpn type:")
            }

            if (vpnLines.isNotEmpty()) {
                for (line in vpnLines) {
                    findings.add(Finding("VPN management: ${line.trim()}", true))
                }
            } else if (output.contains("VPNs:")) {
                val hasActiveVpn = output.lines().any { line ->
                    val trimmed = line.trim()
                    trimmed.matches(Regex("^\\d+:.*")) && trimmed.length > 2
                }
                if (hasActiveVpn) {
                    findings.add(Finding("dumpsys vpn_management: обнаружен активный VPN", true))
                } else {
                    findings.add(Finding("dumpsys vpn_management: активных VPN нет", false))
                }
            } else {
                findings.add(Finding("dumpsys vpn_management: активных VPN нет", false))
            }
        } catch (e: Exception) {
            findings.add(Finding("dumpsys vpn_management: ${e.message}", false))
        }
    }

    private fun checkDumpsysVpnService(findings: MutableList<Finding>) {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "activity", "services", "android.net.VpnService"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (output.isBlank() || output.contains("Permission Denial")) {
                findings.add(Finding("dumpsys activity services VpnService: недоступен", false))
                return
            }

            val serviceRecords = output.lines().filter {
                it.contains("ServiceRecord") && it.contains("VpnService")
            }

            if (serviceRecords.isNotEmpty()) {
                for (line in serviceRecords) {
                    val trimmed = line.trim()
                    // Extract package name from ServiceRecord
                    val packageMatch = Regex("\\{[^}]*\\s+(\\S+/\\S+)\\}").find(trimmed)
                    val serviceName = packageMatch?.groupValues?.get(1) ?: trimmed
                    findings.add(Finding("VpnService активен: $serviceName", true))
                }
            } else if (output.contains("(nothing)") || !output.contains("ServiceRecord")) {
                findings.add(Finding("Активные VpnService: не обнаружены", false))
            }
        } catch (e: Exception) {
            findings.add(Finding("dumpsys activity services: ${e.message}", false))
        }
    }

    private fun isPrivate172(addr: String): Boolean {
        val parts = addr.split(".")
        if (parts.size < 2) return false
        val second = parts[1].toIntOrNull() ?: return false
        return second in 16..31
    }
}
