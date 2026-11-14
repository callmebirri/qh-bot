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
import io.ktor.http.content.TextContent
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import io.ktor.http.parseServerSetCookieHeader
import kotlinx.coroutines.delay
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import microsoft.recovery.model.GenericCanaryResponse
import microsoft.recovery.model.MakePrimaryRequest
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import org.jsoup.Jsoup
import org.slf4j.LoggerFactory
import java.net.URLEncoder
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

    fun decodeUnicodeCanary(raw: String): String {
        return raw.replace("\\/", "/")
            .replace("\\u002b", "+", ignoreCase = true)
            .replace("\\u002f", "/", ignoreCase = true)
            .replace("\\u003a", ":", ignoreCase = true)
            .replace("\\u003d", "=", ignoreCase = true)
            .let { RecoveryParsers.unescapeUnicode(it) }
    }

    fun buildVerifyUrl(
        newEmail: String,
        originalEmail: String,
        otc: String,
    ): String {
        val cleanOtc = extractOtcToken(otc)
        val encodedAlias = URLEncoder.encode(newEmail.trim(), "UTF-8").replace("+", "%20")
        val encodedOtc = URLEncoder.encode(cleanOtc, "UTF-8").replace("+", "%20")
        val encodedMn = URLEncoder.encode(originalEmail.trim(), "UTF-8").replace("+", "%20")
        return "https://account.live.com/Aliases/Verify?aliasname=$encodedAlias&aliastype=Email&otc=$encodedOtc&mn=$encodedMn&cxt=ALS"
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

    suspend fun addExternalAlias(
        canary: String,
        newEmail: String,
        httpClient: HttpClient,
        cookieStorage: CookiesStorage,
        debugListener: (suspend (String) -> Unit)? = null,
    ): Boolean {
        val (addCookieHeader, maskedCookieDetail) = buildStage8CookieHeader(httpClient, cookieStorage, "POST /AddAssocId")
        val formPairs = listOf(
            "canary" to canary,
            "PostOption" to "NONE",
            "SingleDomain" to "",
            "UpSell" to "",
            "AddAssocIdOptions" to "EASI",
            "AssociatedIdEasi" to newEmail,
        )

        val maskedHeaders = buildString {
            appendLine("canary=${maskValue(canary)}")
            appendLine("Referer=https://account.live.com/AddAssocId")
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

        val noRedirectClient = HttpClient(httpClient.engine) {
            followRedirects = false
            install(HttpCookies) {
                this.storage = cookieStorage
            }
            install(HttpTimeout) {
                requestTimeoutMillis = 30000
                connectTimeoutMillis = 15000
                socketTimeoutMillis = 30000
            }
        }

        val postResponse = noRedirectClient.use { stageClient ->
            stageClient.submitForm(
                url = "https://account.live.com/AddAssocId?ru=&cru=&fl=",
                formParameters = parameters {
                    for ((key, value) in formPairs) {
                        append(key, value)
                    }
                },
            ) {
                header("canary", canary)
                header("Referer", "https://account.live.com/AddAssocId")
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
        }
        persistAccountSetCookies(postResponse, cookieStorage)

        val addLocation = postResponse.headers[HttpHeaders.Location]
        val addFinalUrl = postResponse.call.request.url.toString()
        val addBody = runCatching { postResponse.bodyAsText() }.getOrDefault("")
        val addBodyText = Jsoup.parse(addBody).body().text().take(300)

        logger.info(
            "Stage 8 AddAssocId response: alias={}, status={}, finalUrl={}, location={}, bodyText={}",
            newEmail,
            postResponse.status.value,
            addFinalUrl,
            addLocation ?: "none",
            addBodyText,
        )

        if ((postResponse.status == HttpStatusCode.Found ||
                postResponse.status == HttpStatusCode.SeeOther ||
                postResponse.status == HttpStatusCode.TemporaryRedirect) &&
            addLocation != null &&
            addLocation.contains("login.microsoftonline.com", ignoreCase = true)
        ) {
            logger.error(
                "Stage 8 AddAssocId {} redirect Location before SessionExpiredException: {}",
                postResponse.status.value,
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
                postResponse.status.value,
                addFinalUrl,
                addLocation ?: "none",
            )
            throw SessionExpiredException(
                "Session expired during Alias Rotation. Cannot add alias.",
                redirectLocation = addLocation ?: addFinalUrl,
            )
        }

        if (addBody.contains("limit how frequently", ignoreCase = true) ||
            addBody.contains("Error 1213", ignoreCase = true)
        ) {
            throw AliasVerificationFailedException("AddAssocId rate-limited by Microsoft: $addBodyText")
        }

        val isConfirmed = (addLocation != null && addLocation.contains("Note_AssociatedIdAdded", ignoreCase = true)) ||
            addBody.contains("Note_AssociatedIdAdded", ignoreCase = true) ||
            (postResponse.status.isSuccess() && (addBody.contains("added", ignoreCase = true) || addBody.contains("ok", ignoreCase = true)))

        if (!isConfirmed &&
            !postResponse.status.isSuccess() &&
            postResponse.status != HttpStatusCode.Found &&
            postResponse.status != HttpStatusCode.SeeOther
        ) {
            throw AliasVerificationFailedException("AddAssocId failed with status: ${postResponse.status.value}")
        }

        if (!isConfirmed) {
            throw AliasVerificationFailedException("AddAssocId response did not contain confirmation Note_AssociatedIdAdded")
        }

        return true
    }

    private suspend fun addNativeOutlookAlias(
        canary: String,
        newAlias: String,
        httpClient: HttpClient,
        cookieStorage: CookiesStorage,
        debugListener: (suspend (String) -> Unit)? = null,
    ): Boolean {
        val aliasPrefix = newAlias.substringBefore("@")
        val (addCookieHeader, maskedCookieDetail) = buildStage8CookieHeader(httpClient, cookieStorage, "POST /AddAssocId")
        val formPairs = listOf(
            "canary" to canary,
            "PostOption" to "NONE",
            "SingleDomain" to "outlook.com",
            "UpSell" to "",
            "AddAssocIdOptions" to "LIVE",
            "AssociatedIdLive" to aliasPrefix,
        )

        val maskedHeaders = buildString {
            appendLine("canary=${maskValue(canary)}")
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

        val noRedirectClient = HttpClient(httpClient.engine) {
            followRedirects = false
            install(HttpCookies) {
                this.storage = cookieStorage
            }
            install(HttpTimeout) {
                requestTimeoutMillis = 30000
                connectTimeoutMillis = 15000
                socketTimeoutMillis = 30000
            }
        }

        val postResponse = noRedirectClient.use { stageClient ->
            stageClient.submitForm(
                url = "https://account.live.com/AddAssocId",
                formParameters = parameters {
                    for ((key, value) in formPairs) {
                        append(key, value)
                    }
                },
            ) {
                header("canary", canary)
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
        }
        persistAccountSetCookies(postResponse, cookieStorage)

        val addLocation = postResponse.headers[HttpHeaders.Location]
        val addFinalUrl = postResponse.call.request.url.toString()
        val addBody = runCatching { postResponse.bodyAsText() }.getOrDefault("")
        val addBodyText = Jsoup.parse(addBody).body().text().take(300)

        if ((postResponse.status == HttpStatusCode.Found ||
                postResponse.status == HttpStatusCode.SeeOther ||
                postResponse.status == HttpStatusCode.TemporaryRedirect) &&
            addLocation != null &&
            addLocation.contains("login.microsoftonline.com", ignoreCase = true)
        ) {
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
            throw SessionExpiredException(
                "Session expired during Alias Rotation. Cannot add alias.",
                redirectLocation = addLocation ?: addFinalUrl,
            )
        }

        if (addBody.contains("limit how frequently", ignoreCase = true) ||
            addBody.contains("Error 1213", ignoreCase = true)
        ) {
            throw AliasVerificationFailedException("AddAssocId rate-limited by Microsoft: $addBodyText")
        }

        if (!postResponse.status.isSuccess() &&
            postResponse.status != HttpStatusCode.Found &&
            postResponse.status != HttpStatusCode.SeeOther
        ) {
            throw AliasVerificationFailedException("AddAssocId failed with status: ${postResponse.status.value}")
        }

        return true
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

        val refreshedCanary = fetchFreshApiCanary(httpClient, currentCanary, targetStorage)

        val isEasi = !newAlias.endsWith("@outlook.com", ignoreCase = true) &&
            !newAlias.endsWith("@hotmail.com", ignoreCase = true)

        if (isEasi) {
            addExternalAlias(
                canary = refreshedCanary,
                newEmail = newAlias,
                httpClient = httpClient,
                cookieStorage = targetStorage,
                debugListener = debugListener,
            )
        } else {
            addNativeOutlookAlias(
                canary = refreshedCanary,
                newAlias = newAlias,
                httpClient = httpClient,
                cookieStorage = targetStorage,
                debugListener = debugListener,
            )
        }

        val rawInput = if (aliasOtcProvider != null) {
            logger.info("Stage 8 awaiting manual alias OTC input for {}", newAlias)
            aliasOtcProvider(newAlias)
        } else {
            pollOtc(httpClient, newAlias)
        }

        val trimmedInput = rawInput.trim()
        val verifyUrl = if (trimmedInput.startsWith("https://account.live.com/Aliases/Verify", ignoreCase = true) ||
            trimmedInput.startsWith("http://account.live.com/Aliases/Verify", ignoreCase = true)
        ) {
            trimmedInput
        } else {
            val otc = extractOtcToken(trimmedInput)
            if (otc.isBlank()) {
                throw AliasVerificationFailedException("Provided alias OTC token is blank for $newAlias")
            }
            buildVerifyUrl(newEmail = newAlias, originalEmail = oldEmail, otc = otc)
        }

        val verifyResult = verifyAliasViaLink(httpClient, verifyUrl, targetStorage)
        if (!verifyResult.isConfirmed) {
            throw AliasVerificationFailedException("Alias verification via link failed for $newAlias")
        }

        var activeCanary = verifyResult.newApiCanary ?: verifyResult.newCanary ?: refreshedCanary

        val primaryCanary = makePrimary(
            apiCanary = activeCanary,
            newEmail = newAlias,
            uaid = makePrimaryUaid,
            httpClient = httpClient,
            cookieStorage = targetStorage,
        )
        activeCanary = primaryCanary ?: activeCanary

        removeOldAlias(
            canary = activeCanary,
            oldEmail = oldEmail,
            httpClient = httpClient,
            cookieStorage = targetStorage,
        )

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

    @Deprecated(
        message = "Automated worker polling is deprecated in favor of manual verification link/OTC Discord input",
        level = DeprecationLevel.WARNING,
    )
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

    suspend fun verifyAliasViaLink(
        httpClient: HttpClient,
        verifyUrl: String,
        cookieStorage: CookiesStorage,
    ): VerifyAliasResult {
        val loginCookies = cookieStorage.get(Url("https://login.live.com")) +
            runCatching { httpClient.cookies("https://login.live.com") }.getOrNull().orEmpty()
        val accountCookies = cookieStorage.get(Url("https://account.live.com")) +
            runCatching { httpClient.cookies("https://account.live.com") }.getOrNull().orEmpty()
        val allCookies = (loginCookies + accountCookies).associateBy { it.name }

        val cookieValues = listOfNotNull(
            allCookies["__Host-MSAAUTH"]?.let { "__Host-MSAAUTH=${it.value}" },
            allCookies["AMRPSSecAuth"]?.let { "AMRPSSecAuth=${it.value}" },
            allCookies["amsc"]?.let { "amsc=${it.value}" },
        )

        val noRedirectClient = HttpClient(httpClient.engine) {
            followRedirects = false
            install(HttpCookies) {
                this.storage = cookieStorage
            }
            install(HttpTimeout) {
                requestTimeoutMillis = 30000
                connectTimeoutMillis = 15000
                socketTimeoutMillis = 30000
            }
        }

        val (responseStatus, location, confirmedHtml) = noRedirectClient.use { stageClient ->
            val verifyResponse = stageClient.get(verifyUrl) {
                header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                header(HttpHeaders.Accept, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                header("Referer", "https://account.live.com/proofs/manage/additional")
                if (cookieValues.isNotEmpty()) {
                    header(HttpHeaders.Cookie, cookieValues.joinToString("; "))
                }
            }
            persistAccountSetCookies(verifyResponse, cookieStorage)

            val status = verifyResponse.status
            val loc = verifyResponse.headers[HttpHeaders.Location]
            val finalUrl = verifyResponse.call.request.url.toString()

            logger.info(
                "Stage 8 verifyAliasViaLink initial response: status={}, location={}, finalUrl={}",
                status.value,
                loc ?: "none",
                finalUrl,
            )

            if (finalUrl.contains("login.srf") || finalUrl.contains("login.live.com") ||
                (loc != null && (loc.contains("login.srf") || loc.contains("login.live.com") || loc.contains("login.microsoftonline.com")))
            ) {
                throw AliasVerificationFailedException("Alias verification redirected to login page: ${loc ?: finalUrl}")
            }

            if (status == HttpStatusCode.BadRequest) {
                throw AliasVerificationFailedException("Verify API returned HTTP 400 Bad Request")
            }

            if ((status == HttpStatusCode.Found || status == HttpStatusCode.SeeOther || status == HttpStatusCode.TemporaryRedirect) &&
                loc != null && loc.contains("Note_AssociatedIdConfirmed")
            ) {
                val followResponse = stageClient.get(loc) {
                    header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                    header(HttpHeaders.Accept, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    header("Referer", verifyUrl)
                    if (cookieValues.isNotEmpty()) {
                        header(HttpHeaders.Cookie, cookieValues.joinToString("; "))
                    }
                }
                persistAccountSetCookies(followResponse, cookieStorage)
                Triple(status, loc, followResponse.bodyAsText())
            } else if (status.isSuccess()) {
                Triple(status, loc, verifyResponse.bodyAsText())
            } else {
                throw AliasVerificationFailedException("Verify API returned HTTP ${status.value} (Location: ${loc ?: "none"})")
            }
        }

        val isConfirmed = (location != null && location.contains("Note_AssociatedIdConfirmed", ignoreCase = true)) ||
            confirmedHtml.contains("Note_AssociatedIdConfirmed", ignoreCase = true) ||
            confirmedHtml.contains("verified", ignoreCase = true) ||
            confirmedHtml.contains("ok", ignoreCase = true)

        if (!isConfirmed) {
            throw AliasVerificationFailedException("Alias verification response did not contain confirmation Note_AssociatedIdConfirmed")
        }

        val doc = Jsoup.parse(confirmedHtml)
        val rawCanary = doc.selectFirst("input[name=canary]")?.attr("value")?.takeIf { it.isNotBlank() }
        val decodedCanary = rawCanary?.let { decodeUnicodeCanary(it) }

        val apiCanaryRegex = Regex(""""apiCanary"\s*:\s*"([^"]+)"""")
        val rawApiCanary = apiCanaryRegex.find(confirmedHtml)?.groupValues?.get(1)?.takeIf { it.isNotBlank() }
            ?: RecoveryParsers.extractApiCanary(confirmedHtml, MicrosoftHttpClientFactory.json)
        val decodedApiCanary = rawApiCanary?.let { decodeUnicodeCanary(it) }

        return VerifyAliasResult(
            isConfirmed = true,
            newCanary = decodedCanary,
            newApiCanary = decodedApiCanary,
        )
    }

    suspend fun makePrimary(
        apiCanary: String,
        newEmail: String,
        uaid: String,
        httpClient: HttpClient,
        tcxt: String = "",
        cookieStorage: CookiesStorage? = null,
    ): String? {
        val decodedCanary = decodeUnicodeCanary(apiCanary)
        val payloadJson = buildJsonObject {
            put("aliasName", newEmail)
            put("emailChecked", false)
            put("removeOldPrimary", false)
            put("uiflvr", 1001)
            put("uaid", uaid)
            put("scid", 100141)
            put("hpgid", 200176)
        }.toString()

        val cookieHeader = cookieStorage?.let { buildStage8CookieHeader(httpClient, it, "POST /MakePrimary").first }

        val response = httpClient.post("https://account.live.com/API/MakePrimary") {
            header(HttpHeaders.Accept, "application/json")
            header(HttpHeaders.Origin, "https://account.live.com")
            header("Referer", "https://account.live.com/names/Manage")
            header("X-Requested-With", "XMLHttpRequest")
            header("canary", decodedCanary)
            header("scid", "100141")
            header("hpgid", "200176")
            header("uaid", uaid)
            header("uiflvr", "1001")
            if (tcxt.isNotEmpty()) header("tcxt", tcxt)
            header("x-ms-apiTransport", "xhr")
            header("x-ms-apiVersion", "2")
            header(HttpHeaders.ContentType, "application/x-www-form-urlencoded; charset=UTF-8")
            if (!cookieHeader.isNullOrBlank()) {
                header(HttpHeaders.Cookie, cookieHeader)
            }
            contentType(ContentType.parse("application/x-www-form-urlencoded; charset=UTF-8"))
            setBody(TextContent(payloadJson, ContentType.parse("application/x-www-form-urlencoded; charset=UTF-8")))
        }

        logger.info("Stage 8 MakePrimary response: alias={}, status={}", newEmail, response.status.value)

        if (!response.status.isSuccess()) {
            throw AliasVerificationFailedException("MakePrimary failed with status: ${response.status.value}")
        }

        val bodyText = response.bodyAsText()
        val canaryResponse = runCatching {
            MicrosoftHttpClientFactory.json.decodeFromString<GenericCanaryResponse>(bodyText)
        }.getOrNull()

        if (canaryResponse?.error?.code != null) {
            val errorCode = canaryResponse.error.code
            val errorMsg = canaryResponse.error.message ?: errorCode
            if (errorCode == "1282" || errorMsg.contains("1282")) {
                throw AliasVerificationFailedException("MakePrimary rate limited by Microsoft (Error 1282: max 2 changes per week): $errorMsg")
            }
            throw AliasVerificationFailedException("MakePrimary returned error: $errorCode - $errorMsg")
        }

        val rawNextCanary = canaryResponse?.apiCanary
            ?: runCatching {
                MicrosoftHttpClientFactory.json.parseToJsonElement(bodyText).jsonObject["apiCanary"]?.jsonPrimitive?.content
            }.getOrNull()

        val nextCanary = rawNextCanary?.takeIf { it.isNotBlank() }?.let { decodeUnicodeCanary(it) }
        return nextCanary ?: decodedCanary
    }

    suspend fun makePrimary(
        httpClient: HttpClient,
        alias: String,
        canary: String,
        uaid: String,
    ): String = makePrimary(
        apiCanary = canary,
        newEmail = alias,
        uaid = uaid,
        httpClient = httpClient,
    ) ?: canary

    suspend fun removeOldAlias(
        canary: String,
        oldEmail: String,
        httpClient: HttpClient,
        cookieStorage: CookiesStorage? = null,
    ): Boolean {
        val decodedCanary = decodeUnicodeCanary(canary)
        val cookieHeader = cookieStorage?.let { buildStage8CookieHeader(httpClient, it, "POST /names/Manage").first }
        val response = httpClient.submitForm(
            url = "https://account.live.com/names/manage",
            formParameters = parameters {
                append("canary", decodedCanary)
                append("action", "RemoveAlias")
                append("aliasName", oldEmail)
                append("displayName", oldEmail)
            },
        ) {
            header(HttpHeaders.Accept, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            header(HttpHeaders.Origin, "https://account.live.com")
            header("Referer", "https://account.live.com/names/Manage")
            header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
            if (!cookieHeader.isNullOrBlank()) {
                header(HttpHeaders.Cookie, cookieHeader)
            }
        }

        if (!response.status.isSuccess() &&
            response.status != HttpStatusCode.Found &&
            response.status != HttpStatusCode.SeeOther
        ) {
            throw AliasVerificationFailedException("RemoveAlias failed with status: ${response.status.value}")
        }

        val location = response.headers[HttpHeaders.Location]
        val html = runCatching { response.bodyAsText() }.getOrDefault("")
        val confirmed = (location != null && location.contains("Note_AssociatedIdRemoved")) ||
            html.contains("Note_AssociatedIdRemoved")

        logger.info(
            "Stage 8 RemoveAlias response: oldEmail={}, status={}, location={}, confirmed={}",
            oldEmail,
            response.status.value,
            location ?: "none",
            confirmed,
        )
        if (!confirmed) {
            throw AliasVerificationFailedException("RemoveAlias response did not contain confirmation Note_AssociatedIdRemoved")
        }
        return true
    }
}
