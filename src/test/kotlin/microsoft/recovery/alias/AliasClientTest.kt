package microsoft.recovery.alias

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import microsoft.recovery.util.MicrosoftHttpClientFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AliasClientTest {

    @Test
    fun testGenerateRandomAlias() {
        val client = AliasClient(domain = "qhuyy.tech")
        val alias = client.generateRandomAlias(7)
        assertTrue(alias.endsWith("@qhuyy.tech"))
        val prefix = alias.substringBefore("@")
        assertEquals(7, prefix.length)
        assertTrue(prefix.all { it.isLetterOrDigit() })
    }

    @Test
    fun testComputeHmacSha256() {
        val client = AliasClient()
        val data = "test@qhuyy.tech:1700000000"
        val secret = "super-secret-key"
        val signature = client.computeHmacSha256(data, secret)
        assertEquals(64, signature.length)
        assertTrue(signature.all { it in '0'..'9' || it in 'a'..'f' })

        val repeat = client.computeHmacSha256(data, secret)
        assertEquals(signature, repeat)
    }

    @Test
    fun testRotateAliasSuccess(): Unit = runBlocking {
        var verifyCookiesHeader: String? = null
        var makePrimaryCanary: String? = null
        var removeAliasAction: String? = null

        val mockEngine = MockEngine { request ->
            val path = request.url.encodedPath
            when {
                path == "/AddAssocId" -> {
                    respond("<html>Added</html>", HttpStatusCode.OK)
                }

                path == "/get-otc" -> {
                    val email = request.url.parameters["email"]
                    val ts = request.url.parameters["timestamp"]
                    val sig = request.url.parameters["signature"]
                    assertTrue(!email.isNullOrBlank())
                    assertTrue(!ts.isNullOrBlank())
                    assertTrue(!sig.isNullOrBlank())

                    respond(
                        content = """{"otc":"mock_otc_token_123"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

                path == "/Aliases/Verify" -> {
                    verifyCookiesHeader = request.headers[HttpHeaders.Cookie]
                    assertEquals("mock_otc_token_123", request.url.parameters["otc"])
                    assertEquals("Email", request.url.parameters["aliastype"])
                    respond("<html>Verified</html>", HttpStatusCode.OK)
                }

                path == "/API/MakePrimary" -> {
                    makePrimaryCanary = request.headers["canary"]
                    respond(
                        content = """{"apiCanary":"updated_canary_from_make_primary"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

                path == "/names/manage" -> {
                    removeAliasAction = "RemoveAlias"
                    respond(
                        content = "<html>Note_AssociatedIdRemoved</html>",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }

                else -> error("Unexpected path: $path")
            }
        }

        val cookieStorage = AcceptAllCookiesStorage()
        cookieStorage.addCookie(
            Url("https://login.live.com"),
            Cookie(name = "__Host-MSAAUTH", value = "msa_auth_val", domain = "login.live.com", path = "/", secure = true),
        )
        cookieStorage.addCookie(
            Url("https://account.live.com"),
            Cookie(name = "AMRPSSecAuth", value = "amrp_val", domain = "account.live.com", path = "/", secure = true),
        )
        cookieStorage.addCookie(
            Url("https://account.live.com"),
            Cookie(name = "amsc", value = "amsc_val", domain = "account.live.com", path = "/", secure = true),
        )

        val httpClient = HttpClient(mockEngine) {
            install(HttpCookies) {
                storage = cookieStorage
            }
            install(ContentNegotiation) {
                json(MicrosoftHttpClientFactory.json)
            }
        }

        val client = AliasClient(
            workerBaseUrl = "https://qh-bot.qhuyy.tech",
            sharedSecret = "test-secret",
            pollIntervalMs = 10L,
            timeoutMs = 1000L,
        )

        val result = client.rotateAlias(
            currentCanary = "initial_canary",
            oldEmail = "old_user@outlook.com",
            httpClient = httpClient,
            customAlias = "ab12cd@qhuyy.tech",
        )

        assertEquals("old_user@outlook.com", result.oldEmail)
        assertEquals("ab12cd@qhuyy.tech", result.newEmail)
        assertEquals("updated_canary_from_make_primary", result.updatedCanary)
        assertTrue(verifyCookiesHeader?.contains("__Host-MSAAUTH=msa_auth_val") == true)
        assertTrue(verifyCookiesHeader?.contains("AMRPSSecAuth=amrp_val") == true)
        assertTrue(verifyCookiesHeader?.contains("amsc=amsc_val") == true)
        assertEquals("initial_canary", makePrimaryCanary)
        assertEquals("RemoveAlias", removeAliasAction)
    }

    @Test
    fun testRotateAliasWorkerTimeoutThrowsOtcTimeoutException(): Unit = runBlocking {
        val mockEngine = MockEngine { request ->
            val path = request.url.encodedPath
            when (path) {
                "/AddAssocId" -> respond("<html>Added</html>", HttpStatusCode.OK)
                "/get-otc" -> respond("Not found", HttpStatusCode.NotFound)
                else -> error("Unexpected path: $path")
            }
        }

        val httpClient = HttpClient(mockEngine)

        val client = AliasClient(
            workerBaseUrl = "https://qh-bot.qhuyy.tech",
            sharedSecret = "test-secret",
            pollIntervalMs = 20L,
            timeoutMs = 50L,
        )

        assertFailsWith<OtcTimeoutException> {
            client.rotateAlias(
                currentCanary = "canary",
                oldEmail = "old@outlook.com",
                httpClient = httpClient,
            )
        }
    }

    @Test
    fun testRotateAliasVerifyRedirectToLoginThrowsException(): Unit = runBlocking {
        val mockEngine = MockEngine { request ->
            val path = request.url.encodedPath
            when (path) {
                "/AddAssocId" -> respond("<html>Added</html>", HttpStatusCode.OK)
                "/get-otc" -> respond(
                    content = """{"otc":"token"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/Aliases/Verify" -> respond(
                    content = "Redirecting",
                    status = HttpStatusCode.Found,
                    headers = headersOf(HttpHeaders.Location, "https://login.live.com/login.srf"),
                )
                "/login.srf" -> respond(
                    content = "<html><title>Sign in to your account</title></html>",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                else -> error("Unexpected path: $path")
            }
        }

        val httpClient = HttpClient(mockEngine)
        val client = AliasClient(
            sharedSecret = "test-secret",
            pollIntervalMs = 10L,
            timeoutMs = 500L,
        )

        assertFailsWith<AliasVerificationFailedException> {
            client.rotateAlias(
                currentCanary = "canary",
                oldEmail = "old@outlook.com",
                httpClient = httpClient,
            )
        }
    }

    @Test
    fun testRotateAliasVerify400ThrowsException(): Unit = runBlocking {
        val mockEngine = MockEngine { request ->
            val path = request.url.encodedPath
            when (path) {
                "/AddAssocId" -> respond("<html>Added</html>", HttpStatusCode.OK)
                "/get-otc" -> respond(
                    content = """{"otc":"token"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/Aliases/Verify" -> respond("Bad request", HttpStatusCode.BadRequest)
                else -> error("Unexpected path: $path")
            }
        }

        val httpClient = HttpClient(mockEngine)
        val client = AliasClient(
            sharedSecret = "test-secret",
            pollIntervalMs = 10L,
            timeoutMs = 500L,
        )

        assertFailsWith<AliasVerificationFailedException> {
            client.rotateAlias(
                currentCanary = "canary",
                oldEmail = "old@outlook.com",
                httpClient = httpClient,
            )
        }
    }
}
