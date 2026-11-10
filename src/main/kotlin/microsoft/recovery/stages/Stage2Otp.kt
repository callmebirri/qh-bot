package microsoft.recovery.stages

import io.ktor.client.request.forms.submitForm
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
import io.ktor.http.parameters
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution
import microsoft.recovery.util.MicrosoftHttpClientFactory
import org.slf4j.LoggerFactory

class Stage2Otp : RecoveryStageHandler {

    private val logger = LoggerFactory.getLogger(Stage2Otp::class.java)

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val initialPpft = context.initialPpft
        val proofId = context.proofId
        val proofChannel = context.proofChannel

        if (initialPpft.isNullOrBlank() || proofId.isNullOrBlank() || proofChannel.isNullOrBlank()) {
            val msg = "Missing initial PPFT or proof ID from Stage 1"
            stageListener?.invoke("2", "OTP Dispatch", false, msg)
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.OTP_DISPATCH, msg))
        } else {
            val otcResponse = context.httpClient.submitForm(
                url = "https://login.live.com/GetOneTimeCode.srf",
                formParameters = parameters {
                    append("login", context.email)
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
                context.postPpft = flowToken

                val otpProvider = context.otpProvider
                if (otpProvider == null) {
                    val msg = "No OTP provider supplied"
                    stageListener?.invoke("2b", "OTP Submit", false, msg)
                    StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_ESTABLISHMENT, msg))
                } else {
                    val otp = otpProvider().trim()
                    executeStage2b(context, proofId, flowToken, otp, stageListener)
                }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("2", "OTP Dispatch", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.OTP_DISPATCH, msg, cause = e))
    }

    private suspend fun executeStage2b(
        context: RecoveryContext,
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
            val postResponse = context.httpClient.submitForm(
                url = "https://login.live.com/ppsecure/post.srf",
                formParameters = parameters {
                    append("login", context.email)
                    append("loginfmt", context.email)
                    append("type", "27")
                    append("SentProofIDE", proofId)
                    append("otc", otp)
                    append("PPFT", postPpft)
                    append("LoginOptions", "3")
                },
            )

            val loginCookies = context.cookieStorage.get(Url("https://login.live.com"))
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
                context.cookieStorage.addCookie(
                    Url("https://login.live.com"),
                    Cookie(name = "__Host-MSAAUTH", value = msaAuthCookie.value, domain = "login.live.com", path = "/", secure = true),
                )

                val storedUaid = context.cookieStorage.get(Url("https://login.live.com")).firstOrNull { it.name == "uaid" }?.value
                if (!storedUaid.isNullOrBlank()) {
                    context.uaid = storedUaid
                }

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
}
