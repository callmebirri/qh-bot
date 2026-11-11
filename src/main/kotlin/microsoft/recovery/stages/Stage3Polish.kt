package microsoft.recovery.stages

import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpRedirect
import io.ktor.client.plugins.cookies.CookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.request
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
import io.ktor.http.parameters
import io.ktor.http.parseServerSetCookieHeader
import kotlinx.coroutines.CancellationException
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.Stage3Parser
import org.jsoup.Jsoup
import org.slf4j.LoggerFactory

class Stage3Polish(
    private val clientEngine: HttpClientEngine? = null,
) : RecoveryStageHandler {

    private val logger = LoggerFactory.getLogger(Stage3Polish::class.java)

    override suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener?,
    ): StageExecution<Unit> = try {
        val loginCookies = context.cookieStorage.get(Url("https://login.live.com"))
        val currentUaid = loginCookies.firstOrNull { it.name == "uaid" }?.value ?: context.uaid
        val msaAuthValue = loginCookies.firstOrNull { it.name == "__Host-MSAAUTH" }?.value

        if (msaAuthValue.isNullOrBlank()) {
            val msg = "Missing __Host-MSAAUTH cookie for session stabilization"
            stageListener?.invoke("3", "Session Polish", false, msg)
            StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
        } else {
            val cleanCookieHeader = "__Host-MSAAUTH=$msaAuthValue; uaid=$currentUaid"
            val stabilizationUrl = "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=21&rver=7.5.2156.0&wp=SA_20MIN&wreply=https://account.live.com/proofs/Add?apt=2&uaid=$currentUaid&lc=1033&id=38936&mkt=en-US"

            val isolatedClient = if (clientEngine != null) {
                HttpClient(clientEngine) {
                    followRedirects = true
                    install(HttpRedirect) { checkHttpMethod = false }
                    install(HttpCookies) {
                        this.storage = context.cookieStorage
                    }
                }
            } else {
                HttpClient(OkHttp.create()) {
                    followRedirects = true
                    install(HttpRedirect) { checkHttpMethod = false }
                    install(HttpCookies) {
                        this.storage = context.cookieStorage
                    }
                }
            }

            val polishResponse = isolatedClient.use { clientInstance ->
                clientInstance.get(stabilizationUrl) {
                    header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                    header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
                    header(
                        HttpHeaders.Accept,
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    )
                    header("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
                    header("Sec-Ch-Ua-Mobile", "?0")
                    header("Sec-Ch-Ua-Platform", "\"Windows\"")
                    header("Sec-Fetch-Dest", "document")
                    header("Sec-Fetch-Mode", "navigate")
                    header("Sec-Fetch-Site", "same-site")
                    header("Sec-Fetch-User", "?1")
                    header("Upgrade-Insecure-Requests", "1")
                }
            }

            for (rawHeader in polishResponse.headers.getAll(HttpHeaders.SetCookie).orEmpty()) {
                val parsed = runCatching { parseServerSetCookieHeader(rawHeader) }.getOrNull()
                if (parsed != null && parsed.name.isNotBlank()) {
                    val targetDomain = parsed.domain ?: "login.live.com"
                    val targetUrl = Url(if (targetDomain.contains("account.live.com")) "https://account.live.com" else "https://login.live.com")
                    context.cookieStorage.addCookie(
                        targetUrl,
                        parsed.copy(domain = targetDomain, path = parsed.path ?: "/"),
                    )
                }
            }

            val initialUrl = polishResponse.request.url.toString().ifBlank { stabilizationUrl }
            val responseBodyString = polishResponse.bodyAsText()
            val parsedDoc = Jsoup.parse(responseBodyString, initialUrl)
            val htmlTitle = parsedDoc.title()
            val hasPpftInitial = Stage3Parser.hasPpftInput(responseBodyString)
            val htmlSnippet = responseBodyString.take(500).replace("\r", "").replace("\n", " ")

            logger.info("=== STAGE 3 DEBUG ===")
            logger.info("HTTP Status: {}", polishResponse.status)
            logger.info("Location Header: {}", polishResponse.headers[HttpHeaders.Location] ?: "none")
            logger.info("HTML Length: {}", responseBodyString.length)
            logger.info("HTML Title: {}", htmlTitle)
            if (hasPpftInitial) {
                logger.warn("CRITICAL: Response contains PPFT. Microsoft is asking to log in again.")
            }
            logger.info("HTML Snippet: {}", htmlSnippet)

            val debugLogDetail = """
Status: `${polishResponse.status}` | Title: `$htmlTitle` | Length: `${responseBodyString.length}`
Location: `${polishResponse.headers[HttpHeaders.Location] ?: "none"}` | PPFT: `$hasPpftInitial`
```html
$htmlSnippet
```
""".trimIndent()
            stageListener?.invoke("3-debug", "Stage 3 Debug Dump", true, debugLogDetail)

            var currentHtml = responseBodyString
            var currentUrl = initialUrl
            var currentDoc = parsedDoc
            var submittedAddProofViaForm = false
            var hops = 0

            while (hops < 2) {
                val autoSubmitForm = Stage3Parser.extractAutoSubmitForm(currentHtml, currentDoc) ?: break
                val (actionUrl, hiddenFields) = autoSubmitForm

                hops++
                logger.info(
                    "Stage 3 detected DoSubmit() auto-submit form (hop={}): action={}, fieldNames={}",
                    hops,
                    actionUrl,
                    hiddenFields.joinToString(",") { it.first },
                )

                if (actionUrl.contains("/proofs/Add", ignoreCase = true)) {
                    val addProofResponse = submitStage3AddProofForm(actionUrl, hiddenFields, context.cookieStorage)
                    if (captureStage3AccountCookies(addProofResponse, context.cookieStorage)) {
                        submittedAddProofViaForm = true
                        break
                    }
                    currentHtml = addProofResponse.bodyAsText()
                    currentUrl = actionUrl
                    currentDoc = Jsoup.parse(currentHtml, currentUrl)
                } else {
                    val intermediateResponse = submitStage3IntermediateForm(actionUrl, hiddenFields, cleanCookieHeader)
                    if (captureStage3AccountCookies(intermediateResponse, context.cookieStorage)) {
                        submittedAddProofViaForm = true
                        break
                    }
                    currentHtml = intermediateResponse.bodyAsText()
                    currentUrl = intermediateResponse.request.url.toString().ifBlank { actionUrl }
                    currentDoc = Jsoup.parse(currentHtml, currentUrl)
                }
            }

            if (submittedAddProofViaForm) {
                updatePostStage3Uaid(context)
                stageListener?.invoke("3", "Session Polish", true, "AMRPSSecAuth received")
                StageExecution.Success(Unit)
            } else {
                val hasPpft = Stage3Parser.hasPpftInput(currentHtml)
                val tokenT = Stage3Parser.extractTokenT(currentHtml, currentDoc)

                if (tokenT.isNullOrBlank()) {
                    val bodyText = currentDoc.body().text()
                    logger.error("Stage 3 Failed. Microsoft Interstitial Text: {}", bodyText.take(500))

                    if (bodyText.contains("Protect", ignoreCase = true) || bodyText.contains("Verify", ignoreCase = true)) {
                        val msg = "Microsoft requested additional identity verification (Captcha/2FA). Try again later or use a different IP."
                        stageListener?.invoke("3", "Session Polish", false, "$msg\n$debugLogDetail\nText: ${bodyText.take(300)}")
                        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
                    } else if (hasPpft) {
                        val msg = "Session expired or invalid, asked to login again."
                        stageListener?.invoke("3", "Session Polish", false, "$msg\n$debugLogDetail")
                        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
                    } else {
                        val msg = "Token t not found in HTML."
                        stageListener?.invoke("3", "Session Polish", false, "$msg\n$debugLogDetail\nText: ${bodyText.take(300)}")
                        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
                    }
                } else {
                    val addProofResponse = submitStage3AddProofForm(
                        actionUrl = "https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0",
                        formFields = listOf("t" to tokenT),
                        cookieStorage = context.cookieStorage,
                    )

                    if (!captureStage3AccountCookies(addProofResponse, context.cookieStorage)) {
                        val msg = "Missing AMRPSSecAuth or amsc cookies after session stabilization"
                        stageListener?.invoke("3", "Session Polish", false, msg)
                        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg))
                    } else {
                        updatePostStage3Uaid(context)
                        stageListener?.invoke("3", "Session Polish", true, "AMRPSSecAuth received")
                        StageExecution.Success(Unit)
                    }
                }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val msg = "Network timeout or Microsoft rate limit hit: ${e.message}"
        stageListener?.invoke("3", "Session Polish", false, msg)
        StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.SESSION_POLISH, msg, cause = e))
    }

    private suspend fun updatePostStage3Uaid(context: RecoveryContext) {
        val postStage3Uaid = context.cookieStorage.get(Url("https://account.live.com")).firstOrNull { it.name == "uaid" }?.value
            ?: context.cookieStorage.get(Url("https://login.live.com")).firstOrNull { it.name == "uaid" }?.value
        if (!postStage3Uaid.isNullOrBlank()) {
            context.uaid = postStage3Uaid
        }
    }

    private suspend fun submitStage3AddProofForm(
        actionUrl: String,
        formFields: List<Pair<String, String>>,
        cookieStorage: CookiesStorage,
    ): io.ktor.client.statement.HttpResponse {
        val noRedirectPostClient = if (clientEngine != null) {
            HttpClient(clientEngine) {
                followRedirects = false
                install(HttpCookies) {
                    this.storage = cookieStorage
                }
            }
        } else {
            HttpClient(OkHttp.create()) {
                followRedirects = false
                install(HttpCookies) {
                    this.storage = cookieStorage
                }
            }
        }

        return noRedirectPostClient.use {
            val response = it.submitForm(
                url = actionUrl,
                formParameters = parameters {
                    for ((key, value) in formFields) {
                        append(key, value)
                    }
                },
            ) {
                header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
            }
            logger.info(
                "Stage 3 POST /proofs/Add status={}, location={}",
                response.status,
                response.headers[HttpHeaders.Location] ?: "none",
            )
            response
        }
    }

    private suspend fun submitStage3IntermediateForm(
        actionUrl: String,
        formFields: List<Pair<String, String>>,
        cleanCookieHeader: String,
    ): io.ktor.client.statement.HttpResponse {
        val intermediateClient = if (clientEngine != null) {
            HttpClient(clientEngine) {
                followRedirects = true
                install(HttpRedirect) { checkHttpMethod = false }
            }
        } else {
            HttpClient(OkHttp.create()) {
                followRedirects = true
                install(HttpRedirect) { checkHttpMethod = false }
            }
        }

        return intermediateClient.use {
            val response = it.submitForm(
                url = actionUrl,
                formParameters = parameters {
                    for ((key, value) in formFields) {
                        append(key, value)
                    }
                },
            ) {
                header(HttpHeaders.Cookie, cleanCookieHeader)
                header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
            }
            logger.info(
                "Stage 3 POST intermediate status={}, location={}",
                response.status,
                response.headers[HttpHeaders.Location] ?: "none",
            )
            response
        }
    }

    private suspend fun captureStage3AccountCookies(
        response: io.ktor.client.statement.HttpResponse,
        cookieStorage: CookiesStorage,
    ): Boolean {
        val existingAccountCookies = cookieStorage.get(Url("https://account.live.com"))
        val setCookieHeaders = response.headers.getAll(HttpHeaders.SetCookie).orEmpty()
        for (rawCookie in setCookieHeaders) {
            if (rawCookie.contains("AMRPSSecAuth=") && existingAccountCookies.none { it.name == "AMRPSSecAuth" }) {
                val value = rawCookie.substringAfter("AMRPSSecAuth=").substringBefore(";")
                cookieStorage.addCookie(
                    Url("https://account.live.com"),
                    Cookie(name = "AMRPSSecAuth", value = value, domain = "account.live.com", path = "/", secure = true),
                )
            }
            if (rawCookie.contains("amsc=") && existingAccountCookies.none { it.name == "amsc" }) {
                val value = rawCookie.substringAfter("amsc=").substringBefore(";")
                cookieStorage.addCookie(
                    Url("https://account.live.com"),
                    Cookie(name = "amsc", value = value, domain = "account.live.com", path = "/", secure = true),
                )
            }
        }

        val updatedCookies = cookieStorage.get(Url("https://account.live.com"))
        val hasAmrp = updatedCookies.any { it.name == "AMRPSSecAuth" }
        val hasAmsc = updatedCookies.any { it.name == "amsc" }
        return hasAmrp && hasAmsc
    }
}
