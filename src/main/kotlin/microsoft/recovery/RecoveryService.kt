package microsoft.recovery

import database.repository.AccountRepository
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import kotlinx.coroutines.CancellationException
import microsoft.recovery.alias.AliasClient
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.stages.RecoveryStageHandler
import microsoft.recovery.stages.Stage1Discovery
import microsoft.recovery.stages.Stage2Otp
import microsoft.recovery.stages.Stage3Polish
import microsoft.recovery.stages.Stage4Proofs
import microsoft.recovery.stages.Stage5RecoveryCode
import microsoft.recovery.stages.Stage6PasswordReset
import microsoft.recovery.stages.Stage7Suppression
import microsoft.recovery.stages.Stage8Alias
import microsoft.recovery.stages.Stage9Cleanup
import microsoft.recovery.stages.StageListener
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import org.slf4j.LoggerFactory
import java.security.SecureRandom

class RecoveryService(
    private val clientEngine: HttpClientEngine? = null,
    private val stageDelayMs: Long = 1000L,
    private val accountRepository: AccountRepository? = null,
    private val aliasClient: AliasClient? = null,
    private val stopAfterStage7: Boolean = false,
    private val stage1: RecoveryStageHandler = Stage1Discovery(),
    private val stage2: RecoveryStageHandler = Stage2Otp(),
    private val stage3: RecoveryStageHandler = Stage3Polish(clientEngine),
    private val stage4: RecoveryStageHandler = Stage4Proofs(),
    private val stage5: RecoveryStageHandler = Stage5RecoveryCode(),
    private val stage6: RecoveryStageHandler = Stage6PasswordReset(accountRepository),
    private val stage7: RecoveryStageHandler = Stage7Suppression(stageDelayMs),
    private val stage8: RecoveryStageHandler = Stage8Alias(aliasClient, stageDelayMs),
    private val stage9: RecoveryStageHandler = Stage9Cleanup(stageDelayMs),
) : AutoCloseable {

    private val logger = LoggerFactory.getLogger(RecoveryService::class.java)
    private val secureRandom = SecureRandom()

    private val workflow = RecoveryWorkflow(
        stage1 = stage1,
        stage2 = stage2,
        stage3 = stage3,
        stage4 = stage4,
        stage5 = stage5,
        stage6 = stage6,
        stage7 = stage7,
        stage8 = stage8,
        stage9 = stage9,
        accountRepository = accountRepository,
        stageDelayMs = stageDelayMs,
        stopAfterStage7 = stopAfterStage7,
    )

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

        val context = RecoveryContext(
            email = trimmedEmail,
            newPassword = targetPassword,
            newEmail = effectiveNewEmail,
            uaid = RecoveryParsers.generateUaid(),
            cookieStorage = cookieStorage,
            httpClient = client,
            otpProvider = otpProvider,
            aliasOtcProvider = aliasOtcProvider,
        )

        return try {
            workflow.execute(context, stageListener)
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
}
