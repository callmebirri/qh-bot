package microsoft.recovery.stages

import io.ktor.client.call.body
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.CancellationException
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.GenerateRecoveryCodeRequest
import microsoft.recovery.model.GenerateRecoveryCodeResponse
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution

class Stage5RecoveryCode : RecoveryStageHandler {

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val encryptedNetId = context.proofsData?.encryptedNetId
        val canary = context.activeCanary

        if (encryptedNetId.isNullOrBlank()) {
            val msg = "Missing encryptedNetId from Stage 4"
            stageListener?.invoke("5", "Recovery Code Gen", false, msg)
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.RECOVERY_CODE_GENERATION, msg))
        } else {
            val generateRecoveryResponse = context.httpClient.post("https://account.live.com/API/Proofs/GenerateRecoveryCode") {
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
                StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.RECOVERY_CODE_GENERATION, msg, genCodeData?.error?.code))
            } else {
                stageListener?.invoke("5", "Recovery Code Gen", true, "RecoveryCode generated")
                val updatedCanary = genCodeData.apiCanary?.takeIf { it.isNotBlank() } ?: canary
                context.initialRecoveryCode = initialRecoveryCode
                context.activeCanary = updatedCanary
                StageExecution.Success(Unit)
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("5", "Recovery Code Gen", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.RECOVERY_CODE_GENERATION, msg, cause = e))
    }
}
