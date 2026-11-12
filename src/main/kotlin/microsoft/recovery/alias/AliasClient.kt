package microsoft.recovery.alias

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.client.plugins.cookies.CookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.plugins.cookies.cookies
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import io.ktor.http.parseServerSetCookieHeader
import kotlinx.coroutines.delay
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.model.GenericCanaryResponse
import microsoft.recovery.model.MakePrimaryRequest
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import org.jsoup.Jsoup
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class AliasClient(
    private val workerBaseUrl: String = "https://qh-bot.qhuyy.tech",
    private val sharedSecret: String = System.getenv("SHARED_SECRET") ?: "",
    private val domain: String = "qhuyy.tech",
    private val pollIntervalMs: Long = 3000L,
    private val timeoutMs: Long = 60000L,
    private val timeProvider: () -> Long = { System.currentTimeMillis() / 1000 },
) {

    private val logger = LoggerFactory.getLogger(AliasClient::class.java)
    private val secureRandom = SecureRandom()
    private val alphanumericChars = "abcdefghijklmnopqrstuvwxyz0123456789"

    fun extractOtcToken(rawInput: String): String {
        val trimmed = rawInput.trim()
        if (trimmed.contains("otc=", ignoreCase = true)) {
            val parsed = runCatching { Url(trimmed).parameters["otc"] }.getOrNull()
            if (!parsed.isNullOrBlank()) return parsed.trim()
            val match = Regex("""[?&]otc=([^&\s]+)""", RegexOption.IGNORE_CASE).find(trimmed)
            if (match != null) return match.groupValues[1].trim()
        }
        return trimmed
    }

    fun generateRandomAlias(length: Int = 7): String {
        val prefix = (1..length).map { alphanumericChars[secureRandom.nextInt(alphanumericChars.length)] }.joinToString("")
        return "$prefix@$domain"
    }

    fun generateAliasFromEmail(originalEmail: String): String {
        val rawPrefix = originalEmail.trim().substringBefore("@").lowercase()
        val sanitized = rawPrefix
            .filter { it in 'a'..'z' || it in '0'..'9' || it == '.' }
            .replace(Regex("""\.{2,}"""), ".")
            .trim('.')
        return if (sanitized.isNotEmpty()) "$sanitized@$domain" else generateRandomAlias()
    }

    fun computeHmacSha256(dataToSign: String, secret: String): String {
        require(secret.isNotEmpty()) { "Shared secret cannot be empty for HMAC generation" }
        val keySpec = SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(keySpec)
        val hash = mac.doFinal(dataToSign.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    suspend fun rotateAlias(
        currentCanary: String,
        oldEmail: String,
        httpClient: HttpClient,
    ): AliasRotationResult = rotateAlias(currentCanary, oldEmail, httpClient, null, null, null, null, null)

    suspend fun rotateAlias(
        currentCanary: String,
        oldEmail: String,
        httpClient: HttpClient,
        customAlias: String? = null,
        aliasOtcProvider: (suspend (String) -> String)? = null,
        cookieStorage: CookiesStorage? = null,
        sessionUaid: String? = null,
        debugListener: (suspend (String) -> Unit)? = null,
    ): AliasRotationResult {
        val candidateAlias = customAlias?.trim()?.takeIf { it.isNotEmpty() } ?: generateAliasFromEmail(oldEmail)
        val newAlias = if (candidateAlias.contains("@")) candidateAlias else "$candidateAlias@$domain"
        val aliasPrefix = newAlias.substringBefore("@")
        val aliasDomain = newAlias.substringAfter("@")
        val targetStorage = cookieStorage ?: AcceptAllCookiesStorage()
        val cookieUaid = extractLoginUaidCookie(httpClient, targetStorage)
        val makePrimaryUaid = cookieUaid
            ?: sessionUaid?.trim()?.takeIf { it.isNotEmpty() }
            ?: RecoveryParsers.generateUaid()

        val clientLoginCookies = runCatching { httpClient.cookies("https://login.live.com") }.getOrNull().orEmpty()
        for (c in clientLoginCookies) {
            targetStorage.addCookie(Url("https://login.live.com"), c)
            targetStorage.addCookie(Url("https://account.live.com"), c.copy(domain = "account.live.com", path = "/"))
        }
        val clientAccountCookies = runCatching { httpClient.cookies("https://account.live.com") }.getOrNull().orEmpty()
        for (c in clientAccountCookies) {
            targetStorage.addCookie(Url("https://account.live.com"), c.copy(domain = "account.live.com", path = "/"))
        }
        val storageLoginCookies = targetStorage.get(Url("https://login.live.com"))
        for (c in storageLoginCookies) {
            targetStorage.addCookie(Url("https://account.live.com"), c.copy(domain = "account.live.com", path = "/"))
        }

        val noRedirectClient = HttpClient(httpClient.engine) {
            followRedirects = false
            install(HttpCookies) {
                this.storage = targetStorage
            }
            install(HttpTimeout) {
                requestTimeoutMillis = 30000
                connectTimeoutMillis = 15000
                socketTimeoutMillis = 30000
            }
        }

        val (freshApiCanary, addAliasResponse) = noRedirectClient.use { stageClient ->
            val refreshedCanary = fetchFreshApiCanary(stageClient, currentCanary, targetStorage)

            val (addCookieHeader, maskedCookieDetail) = buildStage8CookieHeader(httpClient, targetStorage, "POST /AddAssocId")
            val formPairs = listOf(
                "canary" to refreshedCanary,
                "PostOption" to "NONE",
                "SingleDomain" to "outlook.com",
                "UpSell" to "",
                "AddAssocIdOptions" to "LIVE",
                "AssociatedIdLive" to aliasPrefix,
            )

            val maskedHeaders = buildString {
                appendLine("canary=${maskValue(refreshedCanary)}")
                appendLine("Referer=https://account.live.com/proofs/manage/additional")
                appendLine("Origin=https://account.live.com")
                appendLine("User-Agent=${MicrosoftHttpClientFactory.DEFAULT_USER_AGENT}")
                appendLine("Accept-Language=en-US,en;q=0.9")
                appendLine("Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                append("Cookie=$maskedCookieDetail")
            }

            val maskedParams = formPairs.joinToString("\n") { (k, v) ->
                val display = if (k == "canary") maskValue(v) else if (v.isEmpty()) "(empty)" else v
                "$k=$display"
            }

            val debugSummary = buildString {
                appendLine("**Headers:**")
                appendLine("```text")
                appendLine(maskedHeaders)
                appendLine("```")
                appendLine("**Form Parameters:**")
                appendLine("```text")
                appendLine(maskedParams)
                append("```")
            }

            logger.info(
                "Stage 8 POST /AddAssocId debug:\nHeaders:\n{}\nForm:\n{}",
                maskedHeaders,
                maskedParams,
            )
            debugListener?.invoke(debugSummary)

            val postResponse = stageClient.submitForm(
                url = "https://account.live.com/AddAssocId",
                formParameters = parameters {
                    for ((key, value) in formPairs) {
                        append(key, value)
                    }
                },
            ) {
                header("canary", refreshedCanary)
                header("Referer", "https://account.live.com/proofs/manage/additional")
                header("Origin", "https://account.live.com")
                header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
                header(
                    HttpHeaders.Accept,
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                )
                if (addCookieHeader.isNotBlank()) {
                    header(HttpHeaders.Cookie, addCookieHeader)
                }
            }
            persistAccountSetCookies(postResponse, targetStorage)
            refreshedCanary to postResponse
        }

        var activeCanary = freshApiCanary
        val addLocation = addAliasResponse.headers[HttpHeaders.Location]
        val addFinalUrl = addAliasResponse.call.request.url.toString()
        val addBody = runCatching { addAliasResponse.bodyAsText() }.getOrDefault("")
        val addBodyText = Jsoup.parse(addBody).body().text().take(300)

        logger.info(
            "Stage 8 AddAssocId response: alias={}, status={}, finalUrl={}, location={}, bodyText={}",
            newAlias,
            addAliasResponse.status.value,
            addFinalUrl,
            addLocation ?: "none",
            addBodyText,
        )

        if ((addAliasResponse.status == HttpStatusCode.Found ||
                addAliasResponse.status == HttpStatusCode.SeeOther ||
                addAliasResponse.status == HttpStatusCode.TemporaryRedirect) &&
            addLocation != null &&
            addLocation.contains("login.microsoftonline.com", ignoreCase = true)
        ) {
            logger.error(
                "Stage 8 AddAssocId {} redirect Location before SessionExpiredException: {}",
                addAliasResponse.status.value,
                addLocation,
            )
            throw SessionExpiredException(
                "Session expired during Alias Rotation. Cannot add alias.",
                redirectLocation = addLocation,
            )
        }

        if (addFinalUrl.contains("login.microsoftonline.com", ignoreCase = true) ||
            addFinalUrl.contains("login.srf", ignoreCase = true) ||
            (addLocation != null &&
                (addLocation.contains("login.srf", ignoreCase = true) ||
                    addLocation.contains("login.live.com", ignoreCase = true) ||
                    addLocation.contains("login.microsoftonline.com", ignoreCase = true))) ||
            addBody.contains("Sign in to your account") ||
            addBody.contains("name=\"PPFT\"")
        ) {
            logger.error(
                "Stage 8 AddAssocId unauthenticated response before SessionExpiredException: status={}, finalUrl={}, location={}",
                addAliasResponse.status.value,
                addFinalUrl,
                addLocation ?: "none",
            )
            throw SessionExpiredException(
                "Session expired during Alias Rotation. Cannot add alias.",
                redirectLocation = addLocation ?: addFinalUrl,
            )
        }

        if (!addAliasResponse.status.isSuccess() &&
            addAliasResponse.status != HttpStatusCode.Found &&
            addAliasResponse.status != HttpStatusCode.SeeOther
        ) {
            throw AliasVerificationFailedException("AddAssocId failed with status: ${addAliasResponse.status.value}")
        }

        if (addBody.contains("limit how frequently", ignoreCase = true) ||
            addBody.contains("Error 1213", ignoreCase = true)
        ) {
            throw AliasVerificationFailedException("AddAssocId rate-limited by Microsoft: $addBodyText")
        }

        val rawOtc = if (aliasOtcProvider != null) {
            logger.info("Stage 8 awaiting manual alias OTC input for {} (worker skipped)", newAlias)
            aliasOtcProvider(newAlias)
        } else {
            pollOtc(httpClient, newAlias)
        }
        val otc = extractOtcToken(rawOtc)
        if (otc.isBlank()) {
            throw AliasVerificationFailedException("Provided alias OTC token is blank for $newAlias")
        }

        verifyAlias(httpClient, newAlias, otc, targetStorage)
        activeCanary = makePrimary(httpClient, newAlias, activeCanary, makePrimaryUaid)
        removeOldAlias(httpClient, oldEmail, activeCanary)

        return AliasRotationResult(
            oldEmail = oldEmail,
            newEmail = newAlias,
            updatedCanary = activeCanary,
        )
    }

    private suspend fun extractLoginUaidCookie(
        httpClient: HttpClient,
        storage: CookiesStorage,
    ): String? {
        val fromStorage = storage.get(Url("https://login.live.com"))
            .firstOrNull { it.name == "uaid" }
            ?.value
            ?.takeIf { it.isNotBlank() }
        if (fromStorage != null) return fromStorage

        return runCatching {
            httpClient.cookies("https://login.live.com")
                .firstOrNull { it.name == "uaid" }
                ?.value
                ?.takeIf { it.isNotBlank() }
        }.getOrNull()
    }

    private fun maskValue(value: String): String {
        if (value.isEmpty()) return "(empty)"
        if (value.length <= 8) return "*** (len=${value.length})"
        return "${value.take(4)}...${value.takeLast(4)} (len=${value.length})"
    }

    private suspend fun buildStage8CookieHeader(
        httpClient: HttpClient,
        storage: CookiesStorage,
        operationName: String,
    ): Pair<String, String> {
        val storageLoginCookies = storage.get(Url("https://login.live.com"))
        val storageAccountCookies = storage.get(Url("https://account.live.com"))
        val clientLoginCookies = runCatching { httpClient.cookies("https://login.live.com") }.getOrNull().orEmpty()
        val clientAccountCookies = runCatching { httpClient.cookies("https://account.live.com") }.getOrNull().orEmpty()

        val merged = linkedMapOf<String, Cookie>()
        for (cookie in storageLoginCookies + clientLoginCookies) {
            merged[cookie.name] = cookie
        }
        for (cookie in storageAccountCookies + clientAccountCookies) {
            merged[cookie.name] = cookie
        }

        val isolated = merged.filter { (_, cookie) -> cookie.value.isNotBlank() }
            .map { (name, cookie) -> name to cookie.value }

        val maskedCookieSummary = if (isolated.isEmpty()) {
            "(none)"
        } else {
            isolated.joinToString("; ") { (name, value) -> "$name=${maskValue(value)}" }
        }

        logger.info(
            "Stage 8 cookie isolation for {}: {}, allStorageCookieNames={}, storLogin={}, storAcc={}, cliLogin={}, cliAcc={}",
            operationName,
            maskedCookieSummary,
            merged.keys.joinToString(","),
            storageLoginCookies.map { it.name },
            storageAccountCookies.map { it.name },
            clientLoginCookies.map { it.name },
            clientAccountCookies.map { it.name },
        )

        val rawCookieHeader = isolated.joinToString("; ") { (name, value) -> "$name=$value" }
        return rawCookieHeader to maskedCookieSummary
    }

    private suspend fun persistAccountSetCookies(
        response: HttpResponse,
        storage: CookiesStorage,
    ) {
        val accountUrl = Url("https://account.live.com")
        for (rawHeader in response.headers.getAll(HttpHeaders.SetCookie).orEmpty()) {
            val parsed = runCatching { parseServerSetCookieHeader(rawHeader) }.getOrNull()
            if (parsed != null && parsed.name.isNotBlank()) {
                storage.addCookie(
                    accountUrl,
                    parsed.copy(
                        domain = parsed.domain ?: "account.live.com",
                        path = parsed.path ?: "/",
                    ),
                )
            }
        }
    }

    private suspend fun fetchFreshApiCanary(
        client: HttpClient,
        fallbackCanary: String,
        storage: CookiesStorage,
    ): String {
        val manageResponse = client.get("https://account.live.com/proofs/manage/additional") {
            header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
            header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
            header(
                HttpHeaders.Accept,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
        }
        persistAccountSetCookies(manageResponse, storage)

        val location = manageResponse.headers[HttpHeaders.Location]
        val finalUrl = manageResponse.call.request.url.toString()
        if ((manageResponse.status == HttpStatusCode.Found ||
                manageResponse.status == HttpStatusCode.SeeOther ||
                manageResponse.status == HttpStatusCode.TemporaryRedirect) &&
            location != null &&
            (location.contains("login.microsoftonline.com", ignoreCase = true) ||
                location.contains("login.live.com", ignoreCase = true) ||
                location.contains("login.srf", ignoreCase = true))
        ) {
            logger.error(
                "Stage 8 GET /proofs/manage/additional {} redirect Location before SessionExpiredException: {}",
                manageResponse.status.value,
                location,
            )
            throw SessionExpiredException(
                "Session expired during Alias Rotation. Cannot add alias.",
                redirectLocation = location,
            )
        }
        if (finalUrl.contains("login.microsoftonline.com", ignoreCase = true) ||
            finalUrl.contains("login.srf", ignoreCase = true)
        ) {
            logger.error(
                "Stage 8 GET /proofs/manage/additional unauthenticated URL before SessionExpiredException: status={}, finalUrl={}, location={}",
                manageResponse.status.value,
                finalUrl,
                location ?: "none",
            )
            throw SessionExpiredException(
                "Session expired during Alias Rotation. Cannot add alias.",
                redirectLocation = location ?: finalUrl,
            )
        }

        val html = runCatching { manageResponse.bodyAsText() }.getOrDefault("")
        val extracted = RecoveryParsers.extractApiCanary(html, MicrosoftHttpClientFactory.json)
        if (!extracted.isNullOrBlank()) {
            logger.info("Stage 8 refreshed apiCanary from /proofs/manage/additional (length={})", extracted.length)
            return extracted
        }

        logger.warn("Stage 8 could not extract fresh apiCanary from /proofs/manage/additional (status={}); using existing canary (length={})", manageResponse.status.value, fallbackCanary.length)
        return fallbackCanary
    }

    private suspend fun pollOtc(
        httpClient: HttpClient,
        alias: String,
    ): String {
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime <= timeoutMs) {
            val timestamp = timeProvider()
            val dataToSign = "$alias:$timestamp"
            val signature = computeHmacSha256(dataToSign, sharedSecret)

            val response = httpClient.get("$workerBaseUrl/get-otc") {
                parameter("email", alias)
                parameter("timestamp", timestamp)
                parameter("signature", signature)
            }

            if (response.status == HttpStatusCode.OK) {
                val body = response.bodyAsText()
                val otc = runCatching {
                    MicrosoftHttpClientFactory.json.parseToJsonElement(body).jsonObject["otc"]?.jsonPrimitive?.content
                }.getOrNull()
                if (!otc.isNullOrBlank()) {
                    return otc
                }
            }

            delay(pollIntervalMs)
        }

        throw OtcTimeoutException("Timed out waiting for OTC token from worker for alias $alias after ${timeoutMs}ms")
    }

    private suspend fun verifyAlias(
        httpClient: HttpClient,
        alias: String,
        otc: String,
        storage: CookiesStorage,
    ) {
        val loginCookies = storage.get(Url("https://login.live.com")) +
            runCatching { httpClient.cookies("https://login.live.com") }.getOrNull().orEmpty()
        val accountCookies = storage.get(Url("https://account.live.com")) +
            runCatching { httpClient.cookies("https://account.live.com") }.getOrNull().orEmpty()
        val allCookies = (loginCookies + accountCookies).associateBy { it.name }

        val cookieValues = listOfNotNull(
            allCookies["__Host-MSAAUTH"]?.let { "__Host-MSAAUTH=${it.value}" },
            allCookies["AMRPSSecAuth"]?.let { "AMRPSSecAuth=${it.value}" },
            allCookies["amsc"]?.let { "amsc=${it.value}" },
        )

        val verifyResponse = httpClient.get("https://account.live.com/Aliases/Verify") {
            parameter("aliasname", alias)
            parameter("aliastype", "Email")
            parameter("otc", otc)
            header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
            header("Referer", "https://account.live.com/proofs/manage/additional")
            if (cookieValues.isNotEmpty()) {
                header(HttpHeaders.Cookie, cookieValues.joinToString("; "))
            }
        }

        if (!verifyResponse.status.isSuccess() &&
            verifyResponse.status != HttpStatusCode.Found &&
            verifyResponse.status != HttpStatusCode.SeeOther &&
            verifyResponse.status != HttpStatusCode.MovedPermanently
        ) {
            throw AliasVerificationFailedException("Verify API returned HTTP ${verifyResponse.status.value}")
        }

        val finalUrl = verifyResponse.call.request.url.toString()
        val location = verifyResponse.headers[HttpHeaders.Location]
        logger.info(
            "Stage 8 Aliases/Verify response: alias={}, status={}, finalUrl={}, location={}",
            alias,
            verifyResponse.status.value,
            finalUrl,
            location ?: "none",
        )

        if (finalUrl.contains("login.srf") || finalUrl.contains("login.live.com")) {
            throw AliasVerificationFailedException("Alias verification redirected to login page: $finalUrl")
        }

        if (location != null && (location.contains("login.srf") || location.contains("login.live.com"))) {
            throw AliasVerificationFailedException("Alias verification redirected to login page: $location")
        }

        val body = runCatching { verifyResponse.bodyAsText() }.getOrDefault("")
        if (body.contains("login.srf") || body.contains("Sign in to your account")) {
            throw AliasVerificationFailedException("Alias verification response indicates unauthenticated session")
        }
    }

    private suspend fun makePrimary(
        httpClient: HttpClient,
        alias: String,
        canary: String,
        uaid: String,
    ): String {
        val response = httpClient.post("https://account.live.com/API/MakePrimary") {
            contentType(ContentType.Application.Json)
            header("canary", canary)
            setBody(
                MakePrimaryRequest(
                    aliasName = alias,
                    emailChecked = true,
                    removeOldPrimary = false,
                    uiflvr = 1001,
                    uaid = uaid,
                    scid = 100115,
                    hpgid = 200650,
                )
            )
        }

        logger.info("Stage 8 MakePrimary response: alias={}, status={}", alias, response.status.value)

        if (!response.status.isSuccess()) {
            throw AliasVerificationFailedException("MakePrimary failed with status: ${response.status.value}")
        }

        val canaryResponse = runCatching { response.body<GenericCanaryResponse>() }.getOrNull()
        if (canaryResponse?.error?.code != null) {
            throw AliasVerificationFailedException("MakePrimary returned error: ${canaryResponse.error.code} - ${canaryResponse.error.message}")
        }

        return canaryResponse?.apiCanary?.takeIf { it.isNotBlank() } ?: canary
    }

    private suspend fun removeOldAlias(
        httpClient: HttpClient,
        oldEmail: String,
        canary: String,
    ) {
        val response = httpClient.submitForm(
            url = "https://account.live.com/names/manage",
            formParameters = parameters {
                append("canary", canary)
                append("action", "RemoveAlias")
                append("aliasName", oldEmail)
                append("displayName", oldEmail)
            },
        )

        if (!response.status.isSuccess() &&
            response.status != HttpStatusCode.Found &&
            response.status != HttpStatusCode.SeeOther
        ) {
            throw AliasVerificationFailedException("RemoveAlias failed with status: ${response.status.value}")
        }

        val html = response.bodyAsText()
        val confirmed = html.contains("Note_AssociatedIdRemoved")
        logger.info("Stage 8 RemoveAlias response: oldEmail={}, status={}, confirmed={}", oldEmail, response.status.value, confirmed)
        if (!confirmed) {
            throw AliasVerificationFailedException("RemoveAlias response did not contain confirmation")
        }
    }
}
