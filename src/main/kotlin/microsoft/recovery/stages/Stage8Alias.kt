package microsoft.recovery.stages

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.cookies.CookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import io.ktor.http.parseServerSetCookieHeader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import microsoft.recovery.alias.AliasClient
import microsoft.recovery.alias.SessionExpiredException
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.GenericCanaryResponse
import microsoft.recovery.model.MakePrimaryRequest
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import org.slf4j.LoggerFactory

class Stage8Alias(
    private val aliasClient: AliasClient? = null,
    private val stageDelayMs: Long = 1000L,
) : RecoveryStageHandler {

    private val logger = LoggerFactory.getLogger(Stage8Alias::class.java)

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> {
        val client = context.httpClient
        val cookieStorage = context.cookieStorage
        val email = context.email
        val newEmail = context.newEmail
        val uaid = context.uaid
        var activeCanary = context.activeCanary
        val aliasOtcProvider = context.aliasOtcProvider
        val targetAliasEmail: String

        val clientAlias = aliasClient
        if (clientAlias != null) {
            val aliasResult = runCatching {
                clientAlias.rotateAlias(
                    currentCanary = activeCanary,
                    oldEmail = email,
                    httpClient = client,
                    customAlias = if (newEmail.endsWith("@qhuyy.tech", ignoreCase = true)) newEmail else null,
                    aliasOtcProvider = aliasOtcProvider,
                    cookieStorage = cookieStorage,
                    sessionUaid = uaid,
                    debugListener = { detail ->
                        stageListener?.invoke("8-debug", "Stage 8 Request Debug", true, detail)
                    },
                )
            }.getOrElse { e ->
                if (e is CancellationException) throw e
                val msg = e.message ?: "Custom domain alias rotation failed"
                val detail = if (e is SessionExpiredException && !e.redirectLocation.isNullOrBlank()) {
                    "$msg\nLocation: ${e.redirectLocation}"
                } else {
                    msg
                }
                stageListener?.invoke("8", "Alias Rotation", false, detail)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg, cause = e))
            }
            targetAliasEmail = aliasResult.newEmail
            activeCanary = aliasResult.updatedCanary
            stageListener?.invoke("8", "Alias Rotation", true, "Alias $targetAliasEmail verified and set as primary")
        } else {
            val targetEmail = if (newEmail.contains("@")) newEmail.trim() else "${newEmail.trim()}@outlook.com"
            val newAliasPrefix = targetEmail.substringBefore("@")
            val targetDomain = targetEmail.substringAfter("@")
            targetAliasEmail = targetEmail

            val noRedirectClient = HttpClient(client.engine) {
                followRedirects = false
                install(HttpCookies) {
                    this.storage = cookieStorage
                }
            }

            val addAliasResult = runCatching {
                noRedirectClient.use { stageClient ->
                    val loginCookies = cookieStorage.get(Url("https://login.live.com"))
                    for (c in loginCookies) {
                        cookieStorage.addCookie(
                            Url("https://account.live.com"),
                            c.copy(domain = "account.live.com", path = "/"),
                        )
                    }

                    val (addCookieHeader, maskedCookies) = buildIsolatedAccountCookieHeader(cookieStorage, "POST /AddAssocId")
                    val formPairs = listOf(
                        "canary" to activeCanary,
                        "PostOption" to "NONE",
                        "SingleDomain" to "outlook.com",
                        "UpSell" to "",
                        "AddAssocIdOptions" to "LIVE",
                        "AssociatedIdLive" to newAliasPrefix,
                    )

                    val maskedHeaders = buildString {
                        appendLine("canary=${maskSecretValue(activeCanary)}")
                        appendLine("Referer=https://account.live.com/proofs/manage/additional")
                        appendLine("Origin=https://account.live.com")
                        appendLine("User-Agent=${MicrosoftHttpClientFactory.DEFAULT_USER_AGENT}")
                        appendLine("Accept-Language=en-US,en;q=0.9")
                        append("Cookie=$maskedCookies")
                    }
                    val maskedParams = formPairs.joinToString("\n") { (k, v) ->
                        val display = if (k == "canary") maskSecretValue(v) else if (v.isEmpty()) "(empty)" else v
                        "$k=$display"
                    }

                    logger.info(
                        "Stage 8 POST /AddAssocId debug:\nHeaders:\n{}\nForm:\n{}",
                        maskedHeaders,
                        maskedParams,
                    )
                    stageListener?.invoke(
                        "8-debug",
                        "Stage 8 Request Debug",
                        true,
                        "**Headers:**\n```text\n$maskedHeaders\n```\n**Form Parameters:**\n```text\n$maskedParams\n```",
                    )

                    val postResponse = stageClient.submitForm(
                        url = "https://account.live.com/AddAssocId",
                        formParameters = parameters {
                            for ((key, value) in formPairs) {
                                append(key, value)
                            }
                        },
                    ) {
                        header("canary", activeCanary)
                        header("Referer", "https://account.live.com/proofs/manage/additional")
                        header("Origin", "https://account.live.com")
                        header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                        header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
                        if (addCookieHeader.isNotBlank()) {
                            header(HttpHeaders.Cookie, addCookieHeader)
                        }
                    }

                    for (rawHeader in postResponse.headers.getAll(HttpHeaders.SetCookie).orEmpty()) {
                        val parsed = runCatching { parseServerSetCookieHeader(rawHeader) }.getOrNull()
                        if (parsed != null && parsed.name.isNotBlank()) {
                            cookieStorage.addCookie(
                                Url("https://account.live.com"),
                                parsed.copy(domain = parsed.domain ?: "account.live.com", path = parsed.path ?: "/"),
                            )
                        }
                    }

                    val addLocation = postResponse.headers[HttpHeaders.Location]
                    if ((postResponse.status == HttpStatusCode.Found ||
                            postResponse.status == HttpStatusCode.SeeOther ||
                            postResponse.status == HttpStatusCode.TemporaryRedirect) &&
                        addLocation != null &&
                        addLocation.contains("login.microsoftonline.com", ignoreCase = true)
                    ) {
                        logger.error(
                            "Stage 8 AddAssocId {} redirect Location before SessionExpiredException: {}",
                            postResponse.status.value,
                            addLocation,
                        )
                        throw SessionExpiredException(
                            "Session expired during Alias Rotation. Cannot add alias.",
                            redirectLocation = addLocation,
                        )
                    }
                    postResponse
                }
            }.getOrElse { e ->
                if (e is CancellationException) throw e
                val msg = e.message ?: "AddAssocId failed"
                val detail = if (e is SessionExpiredException && !e.redirectLocation.isNullOrBlank()) {
                    "$msg\nLocation: ${e.redirectLocation}"
                } else {
                    msg
                }
                stageListener?.invoke("8", "Alias Rotation", false, detail)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg, cause = e))
            }

            if (!addAliasResult.status.isSuccess() &&
                addAliasResult.status != HttpStatusCode.Found &&
                addAliasResult.status != HttpStatusCode.SeeOther
            ) {
                val msg = "AddAssocId failed: HTTP ${addAliasResult.status.value}"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg))
            }

            if (stageDelayMs > 0) delay(stageDelayMs)

            val makePrimaryResponse = client.post("https://account.live.com/API/MakePrimary") {
                contentType(ContentType.Application.Json)
                header("canary", activeCanary)
                setBody(
                    MakePrimaryRequest(
                        aliasName = targetAliasEmail,
                        emailChecked = true,
                        removeOldPrimary = false,
                        uaid = uaid,
                    ),
                )
            }

            if (!makePrimaryResponse.status.isSuccess()) {
                val msg = "MakePrimary request failed: HTTP ${makePrimaryResponse.status.value}"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg))
            }

            val makePrimaryData = runCatching { makePrimaryResponse.body<GenericCanaryResponse>() }.getOrNull()
            if (makePrimaryData?.error?.code != null) {
                val msg = "MakePrimary rejected: ${makePrimaryData.error.message ?: makePrimaryData.error.code}"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg, makePrimaryData.error.code))
            }
            if (!makePrimaryData?.apiCanary.isNullOrBlank()) {
                activeCanary = makePrimaryData.apiCanary
            }

            if (stageDelayMs > 0) delay(stageDelayMs)

            val removeAliasResponse = client.submitForm(
                url = "https://account.live.com/names/manage",
                formParameters = parameters {
                    append("canary", activeCanary)
                    append("action", "RemoveAlias")
                    append("aliasName", email)
                    append("displayName", email)
                },
            )
            val removeAliasHtml = runCatching { removeAliasResponse.bodyAsText() }.getOrDefault("")
            val confirmed = removeAliasHtml.contains("Note_AssociatedIdRemoved")
            if (!confirmed) {
                val msg = "RemoveAlias failed: confirmation string 'Note_AssociatedIdRemoved' not found in response (HTTP ${removeAliasResponse.status.value})"
                stageListener?.invoke("8", "Alias Rotation", false, msg)
                return StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, msg))
            }
            stageListener?.invoke("8", "Alias Rotation", true, "New alias verified and set as primary")
        }

        context.targetAliasEmail = targetAliasEmail
        context.activeCanary = activeCanary
        return StageExecution.Success(Unit)
    }

    private fun maskSecretValue(value: String): String {
        if (value.isEmpty()) return "(empty)"
        if (value.length <= 8) return "*** (len=${value.length})"
        return "${value.take(4)}...${value.takeLast(4)} (len=${value.length})"
    }

    private suspend fun buildIsolatedAccountCookieHeader(
        cookieStorage: CookiesStorage,
        operationName: String,
    ): Pair<String, String> {
        val merged = linkedMapOf<String, Cookie>()
        for (cookie in cookieStorage.get(Url("https://login.live.com"))) {
            merged[cookie.name] = cookie
        }
        for (cookie in cookieStorage.get(Url("https://account.live.com"))) {
            merged[cookie.name] = cookie
        }

        val isolated = merged.filter { (_, cookie) -> cookie.value.isNotBlank() }
            .map { (name, cookie) -> name to cookie.value }
        val maskedSummary = if (isolated.isEmpty()) {
            "(none)"
        } else {
            isolated.joinToString("; ") { (name, value) -> "$name=${maskSecretValue(value)}" }
        }
        logger.info(
            "Stage 8 cookie isolation for {}: {}, allStorageCookieNames={}",
            operationName,
            maskedSummary,
            merged.keys.joinToString(","),
        )
        return isolated.joinToString("; ") { (name, value) -> "$name=$value" } to maskedSummary
    }
}
