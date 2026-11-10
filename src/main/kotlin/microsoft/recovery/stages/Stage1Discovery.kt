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
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.GetCredentialTypeRequest
import microsoft.recovery.model.GetCredentialTypeResponse
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers

class Stage1Discovery : RecoveryStageHandler {

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val loginResponse = context.httpClient.get("https://login.live.com/login.srf")
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
                val credResponse = context.httpClient.post("https://login.live.com/GetCredentialType.srf") {
                    contentType(ContentType.Application.Json)
                    header("Referer", "https://login.live.com/login.srf")
                    setBody(
                        GetCredentialTypeRequest(
                            username = context.email,
                            flowToken = initialPpft,
                            isUcuxLoginForm = true,
                            isCookieBannerShown = false,
                            checkPhones = true,
                        ),
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
                                context.initialPpft = initialPpft
                                context.proofId = primaryProof.data
                                context.proofChannel = proofChannel
                                StageExecution.Success(Unit)
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
}
