package microsoft.recovery.alias

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.cookies.cookies
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.coroutines.delay
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.model.GenericCanaryResponse
import microsoft.recovery.model.MakePrimaryRequest
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
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

    private val secureRandom = SecureRandom()
    private val alphanumericChars = "abcdefghijklmnopqrstuvwxyz0123456789"

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
    ): AliasRotationResult = rotateAlias(currentCanary, oldEmail, httpClient, null)

    suspend fun rotateAlias(
        currentCanary: String,
        oldEmail: String,
        httpClient: HttpClient,
        customAlias: String? = null,
    ): AliasRotationResult {
        var activeCanary = currentCanary
        val newAlias = customAlias ?: generateAliasFromEmail(oldEmail)
        val uaid = RecoveryParsers.generateUaid()

        val addAliasResponse = httpClient.submitForm(
            url = "https://account.live.com/AddAssocId",
            formParameters = parameters {
                append("canary", activeCanary)
                append("PostOption", "NONE")
                append("SingleDomain", "")
                append("AddAssocIdOptions", "LIVE")
                append("AssociatedIdLive", newAlias)
            },
        )

        if (!addAliasResponse.status.isSuccess() &&
            addAliasResponse.status != HttpStatusCode.Found &&
            addAliasResponse.status != HttpStatusCode.SeeOther
        ) {
            throw AliasVerificationFailedException("AddAssocId failed with status: ${addAliasResponse.status.value}")
        }

        val otc = pollOtc(httpClient, newAlias)
        verifyAlias(httpClient, newAlias, otc)
        activeCanary = makePrimary(httpClient, newAlias, activeCanary, uaid)
        removeOldAlias(httpClient, oldEmail, activeCanary)

        return AliasRotationResult(
            oldEmail = oldEmail,
            newEmail = newAlias,
            updatedCanary = activeCanary,
        )
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
    ) {
        val loginCookies = runCatching { httpClient.cookies("https://login.live.com") }.getOrNull().orEmpty()
        val accountCookies = runCatching { httpClient.cookies("https://account.live.com") }.getOrNull().orEmpty()
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
            header(HttpHeaders.UserAgent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
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
        if (finalUrl.contains("login.srf") || finalUrl.contains("login.live.com")) {
            throw AliasVerificationFailedException("Alias verification redirected to login page: $finalUrl")
        }

        val location = verifyResponse.headers[HttpHeaders.Location]
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
        if (!html.contains("Note_AssociatedIdRemoved") && !response.status.isSuccess()) {
            throw AliasVerificationFailedException("RemoveAlias response did not contain confirmation")
        }
    }
}
