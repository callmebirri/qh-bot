package microsoft.recovery.stages

import database.model.RecoveredAccount
import database.repository.AccountRepository
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.request
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.RecoverUserRequest
import microsoft.recovery.model.RecoverUserResponse
import microsoft.recovery.model.RecoveryErrorData
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution
import microsoft.recovery.model.VerifyRecoveryCodeRequest
import microsoft.recovery.model.VerifyRecoveryCodeResponse
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import org.slf4j.LoggerFactory

class Stage6PasswordReset(
    private val accountRepository: AccountRepository? = null,
) : RecoveryStageHandler {

    private val logger = LoggerFactory.getLogger(Stage6PasswordReset::class.java)

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val email = context.email
        val newPassword = context.newPassword
        val newEmail = context.newEmail
        val initialRecoveryCode = context.initialRecoveryCode

        if (initialRecoveryCode.isNullOrBlank()) {
            val msg = "Missing initial recovery code from Stage 5"
            stageListener?.invoke("6", "Password Reset", false, msg)
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg))
        } else {
            val resetPageResponse = context.httpClient.get("https://account.live.com/ResetPassword.aspx") {
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

            val verifyCodeResponse = context.httpClient.post("https://account.live.com/API/Recovery/VerifyRecoveryCode") {
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
                StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg, verifyError?.first))
            } else if (verificationGrantToken == resetData.sRecoveryToken) {
                val msg = "VerifyRecoveryCode returned sRecoveryToken instead of elevated grant token"
                logger.error("Stage 6 VerifyRecoveryCode returned unchanged sRecoveryToken (len={})", verificationGrantToken.length)
                markPasswordRotationFailed(email, msg)
                stageListener?.invoke("6", "Password Reset", false, msg)
                StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg))
            } else {
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

                val recoverUserResponse = context.httpClient.post("https://account.live.com/API/Recovery/RecoverUser") {
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
                    StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg, recoverError?.first))
                } else if (finalRecoveryCode == initialRecoveryCode) {
                    val msg = "RecoverUser returned unchanged recoveryCode; password update could not be verified"
                    markPasswordRotationFailed(email, msg)
                    stageListener?.invoke("6", "Password Reset", false, msg)
                    StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg))
                } else {
                    stageListener?.invoke("6", "Password Reset", true, "Password changed & new code")
                    val canaryAfterRecover = recoverUserData.apiCanary?.takeIf { it.isNotBlank() } ?: canaryAfterVerify
                    context.finalRecoveryCode = finalRecoveryCode
                    context.activeCanary = canaryAfterRecover
                    StageExecution.Success(Unit)
                }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Password reset request failed: ${e.message}"
        markPasswordRotationFailed(context.email, msg)
        stageListener?.invoke("6", "Password Reset", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PASSWORD_ROTATION, msg, cause = e))
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

    private fun extractErrorDetails(rawJson: JsonObject?, typedError: RecoveryErrorData?): Pair<String?, String?>? {
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
}
