package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.probe.PublicIpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.io.IOException

object IpComparisonChecker {

    private enum class IpFamily {
        IPV4,
        IPV6,
    }

    private data class EndpointSpec(
        val label: String,
        val url: String,
        val scope: IpCheckerScope,
    )

    private val ENDPOINTS = listOf(
        EndpointSpec(
            label = "Yandex IPv4",
            url = "https://ipv4-internet.yandex.net/api/v0/ip",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "Yandex IPv6",
            url = "https://ipv6-internet.yandex.net/api/v0/ip",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "ifconfig.me",
            url = "https://ifconfig.me/ip",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "checkip.amazonaws.com",
            url = "https://checkip.amazonaws.com",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ipify",
            url = "https://api.ipify.org",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ip.sb",
            url = "https://api.ip.sb/ip",
            scope = IpCheckerScope.NON_RU,
        ),
    )

    suspend fun check(timeoutMs: Int = 7000): IpComparisonResult = withContext(Dispatchers.IO) {
        coroutineScope {
            val responses = ENDPOINTS.map { endpoint ->
                async {
                    val result = PublicIpClient.fetchIp(endpoint.url, timeoutMs)
                    IpCheckerResponse(
                        label = endpoint.label,
                        url = endpoint.url,
                        scope = endpoint.scope,
                        ip = result.getOrNull(),
                        error = result.exceptionOrNull()?.let(::formatError),
                    )
                }
            }.map { it.await() }
            evaluate(responses)
        }
    }

    internal fun evaluate(responses: List<IpCheckerResponse>): IpComparisonResult {
        val ruGroup = buildGroup(
            title = "RU-чекеры",
            responses = responses.filter { it.scope == IpCheckerScope.RU },
        )
        val nonRuGroup = buildGroup(
            title = "Не-RU чекеры",
            responses = responses.filter { it.scope == IpCheckerScope.NON_RU },
        )

        val fullConsensusAvailable = !ruGroup.needsReview &&
            !nonRuGroup.needsReview &&
            !ruGroup.detected &&
            !nonRuGroup.detected &&
            ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null

        val familyMismatch = ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null &&
            detectFamily(ruGroup.canonicalIp) != detectFamily(nonRuGroup.canonicalIp)

        val rawMismatch = ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null &&
            !familyMismatch &&
            ruGroup.canonicalIp != nonRuGroup.canonicalIp

        val detected = fullConsensusAvailable && rawMismatch
        val needsReview = !detected && (
            ruGroup.detected ||
                nonRuGroup.detected ||
                ruGroup.needsReview ||
                nonRuGroup.needsReview ||
                familyMismatch ||
                rawMismatch
            )

        val summary = when {
            detected -> "RU и не-RU чекеры вернули разные IP: ${ruGroup.canonicalIp} и ${nonRuGroup.canonicalIp}"
            familyMismatch -> "RU и не-RU чекеры вернули адреса разных семейств: ${ruGroup.canonicalIp} и ${nonRuGroup.canonicalIp}"
            rawMismatch -> "IP различаются, но данные неполные: ${ruGroup.canonicalIp} и ${nonRuGroup.canonicalIp}"
            ruGroup.canonicalIp != null && nonRuGroup.canonicalIp != null ->
                "Все чекеры вернули один IP: ${ruGroup.canonicalIp}"
            ruGroup.canonicalIp == null && nonRuGroup.canonicalIp == null ->
                "Не удалось получить ответ ни от одного IP-чекера"
            else -> "Сравнение неполное: часть чекеров не ответила"
        }

        return IpComparisonResult(
            detected = detected,
            needsReview = needsReview,
            summary = summary,
            ruGroup = ruGroup,
            nonRuGroup = nonRuGroup,
        )
    }

    private fun buildGroup(
        title: String,
        responses: List<IpCheckerResponse>,
    ): IpCheckerGroupResult {
        if (responses.size == 1) {
            val response = responses.single()
            return if (response.ip != null) {
                IpCheckerGroupResult(
                    title = title,
                    detected = false,
                    needsReview = false,
                    statusLabel = "Есть ответ",
                    summary = "IP: ${response.ip}",
                    canonicalIp = response.ip,
                    responses = responses,
                )
            } else {
                IpCheckerGroupResult(
                    title = title,
                    detected = false,
                    needsReview = true,
                    statusLabel = "Нет ответа",
                    summary = response.error?.let { "Ошибка: $it" } ?: "Сервис не ответил",
                    responses = responses,
                )
            }
        }

        val successfulIps = responses.mapNotNull { it.ip }
        val uniqueIps = successfulIps.distinct()
        val failureCount = responses.count { it.ip == null }
        val families = successfulIps.mapNotNull(::detectFamily).distinct()

        return when {
            uniqueIps.isEmpty() -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = true,
                statusLabel = "Нет ответа",
                summary = "Ни один сервис не вернул IP",
                responses = responses,
            )
            families.size > 1 -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = true,
                statusLabel = "IPv4/IPv6",
                summary = "Сервисы вернули адреса разных семейств: ${uniqueIps.joinToString()}",
                responses = responses,
            )
            uniqueIps.size > 1 -> IpCheckerGroupResult(
                title = title,
                detected = true,
                needsReview = false,
                statusLabel = "Разнобой",
                summary = "Сервисы вернули разные IP: ${uniqueIps.joinToString()}",
                responses = responses,
            )
            failureCount > 0 -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = true,
                statusLabel = "Частично",
                summary = "IP ${uniqueIps.single()}, но ${failureCount} из ${responses.size} сервисов не ответили",
                canonicalIp = uniqueIps.single(),
                responses = responses,
            )
            else -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = false,
                statusLabel = "Совпадает",
                summary = "Все сервисы группы вернули IP ${uniqueIps.single()}",
                canonicalIp = uniqueIps.single(),
                responses = responses,
            )
        }
    }

    private fun formatError(throwable: Throwable): String {
        val message = throwable.message?.trim().orEmpty()
        if (message.isNotBlank()) return message
        return when (throwable) {
            is IOException -> "Сетевая ошибка"
            else -> throwable::class.java.simpleName
        }
    }

    private fun detectFamily(ip: String?): IpFamily? {
        return when {
            ip == null -> null
            ip.contains(':') -> IpFamily.IPV6
            ip.contains('.') -> IpFamily.IPV4
            else -> null
        }
    }
}
