package microsoft.recovery.stages

import io.ktor.client.call.body
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.GenericCanaryResponse
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.SecurityCleanupRequest
import microsoft.recovery.model.StageExecution
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.milliseconds

class Stage9Cleanup(
    private val stageDelayMs: Long = 1000L,
) : RecoveryStageHandler {

    private val logger = LoggerFactory.getLogger(Stage9Cleanup::class.java)

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val client = context.httpClient
        val uaid = context.uaid
        val passKeyIds = context.passKeyIds
        var activeCanary = context.activeCanary

        val disableTfaResponse = client.post("https://account.live.com/API/Proofs/DisableTfa") {
            contentType(ContentType.Application.Json)
            header("canary", activeCanary)
            header("X-Requested-With", "XMLHttpRequest")
            setBody(SecurityCleanupRequest(uaid = uaid))
        }
        if (!disableTfaResponse.status.isSuccess()) {
            logger.warn("DisableTfa failed with HTTP status {}", disableTfaResponse.status.value)
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
        if (!deleteDevicesResponse.status.isSuccess()) {
            logger.warn("DeleteDevices failed with HTTP status {}", deleteDevicesResponse.status.value)
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
        if (!deleteAppPasswordResponse.status.isSuccess()) {
            logger.warn("DeleteAppPassword failed with HTTP status {}", deleteAppPasswordResponse.status.value)
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
                if (!removePasskeyResponse.status.isSuccess()) {
                    logger.warn("RemovePasskey failed for passkey {}: HTTP status {}", keyId, removePasskeyResponse.status.value)
                }
                val removePasskeyData = runCatching { removePasskeyResponse.body<GenericCanaryResponse>() }.getOrNull()
                if (!removePasskeyData?.apiCanary.isNullOrBlank()) {
                    activeCanary = removePasskeyData.apiCanary
                }
                if (stageDelayMs > 0) delay(stageDelayMs)
            }
        }

        context.activeCanary = activeCanary
        stageListener?.invoke("9", "Cleanup", true, "Sessions revoked")
        StageExecution.Success(Unit)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Security cleanup failed: ${e.message}"
        stageListener?.invoke("9", "Cleanup", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SECURITY_CLEANUP, msg, cause = e))
    }
}
