package microsoft.recovery.stages

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.request
import io.ktor.http.HttpHeaders
import kotlinx.coroutines.CancellationException
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import org.jsoup.Jsoup
import org.slf4j.LoggerFactory

class Stage4Proofs : RecoveryStageHandler {

    private val logger = LoggerFactory.getLogger(Stage4Proofs::class.java)

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val manageProofsResponse = context.httpClient.get("https://account.live.com/proofs/manage/additional") {
            header("X-Requested-With", "XMLHttpRequest")
        }
        val finalUrl = manageProofsResponse.request.url.toString()
        val manageProofsHtml = manageProofsResponse.bodyAsText()
        val parsedDoc = Jsoup.parse(manageProofsHtml)
        val htmlTitle = parsedDoc.title()
        val hasT0 = manageProofsHtml.contains("t0")
        val hasManageProofs = manageProofsHtml.contains("manageProofs")
        val hasServerData = manageProofsHtml.contains("ServerData")
        val hasEncryptedNetId = manageProofsHtml.contains("encryptedNetId")
        val hasApiCanary = manageProofsHtml.contains("apiCanary")
        val hasPpft = manageProofsHtml.contains("PPFT")

        logger.info(
            "Stage 4 response: status={}, url={}, title={}, length={}, hasT0={}, hasManageProofs={}, hasServerData={}, hasEncryptedNetId={}, hasApiCanary={}, hasPpft={}",
            manageProofsResponse.status,
            finalUrl,
            htmlTitle,
            manageProofsHtml.length,
            hasT0,
            hasManageProofs,
            hasServerData,
            hasEncryptedNetId,
            hasApiCanary,
            hasPpft,
        )

        val proofsData = RecoveryParsers.extractManageProofsData(manageProofsHtml, MicrosoftHttpClientFactory.json)
        if (proofsData == null) {
            val htmlSnippet = manageProofsHtml.take(500).replace("\r", "").replace("\n", " ")
            val bodyText = parsedDoc.body().text().take(300)
            val debugDetail = """
Status: `${manageProofsResponse.status}` | Title: `$htmlTitle` | Length: `${manageProofsHtml.length}`
URL: `$finalUrl` | Location: `${manageProofsResponse.headers[HttpHeaders.Location] ?: "none"}`
Keys: t0=`$hasT0`, manageProofs=`$hasManageProofs`, ServerData=`$hasServerData`, encryptedNetId=`$hasEncryptedNetId`, apiCanary=`$hasApiCanary`, PPFT=`$hasPpft`
```html
$htmlSnippet
```
Text: $bodyText
            """.trimIndent()
            logger.error("Stage 4 extraction failed. {}", debugDetail)
            val msg = "Failed to extract encryptedNetId or apiCanary from additional proofs page"
            stageListener?.invoke("4", "Proofs Enumeration", false, "$msg\n$debugDetail")
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PROOFS_ENUMERATION, msg))
        } else {
            stageListener?.invoke("4", "Proofs Enumeration", true, "encryptedNetId received")
            context.proofsData = proofsData
            context.activeCanary = proofsData.apiCanary
            context.emailProofs = proofsData.emailProofs
            context.smsProofs = proofsData.smsProofs
            context.passKeyIds = proofsData.passKeyIds
            StageExecution.Success(Unit)
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("4", "Proofs Enumeration", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.PROOFS_ENUMERATION, msg, cause = e))
    }
}
