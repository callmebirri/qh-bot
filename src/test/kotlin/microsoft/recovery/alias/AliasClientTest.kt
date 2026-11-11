package microsoft.recovery.alias

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.forms.FormDataContent
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
        var verifyUserAgent: String? = null
        var addAssocCookieHeader: String? = null
        var addAssocReferer: String? = null
        var addAssocUserAgent: String? = null
        var refreshUserAgent: String? = null
        var addAssocHeaderCanary: String? = null
        var addAssocFormCanary: String? = null
        var addAssocPostOption: String? = null
        var addAssocSingleDomain: String? = null
        var addAssocUpSell: String? = null
        var addAssocOptions: String? = null
        var addAssocLive: String? = null
        var addAssocUaid: String? = null
        var addAssocParamKeys: Set<String> = emptySet()
        var makePrimaryCanary: String? = null
        var removeAliasAction: String? = null
        val debugPayloads = mutableListOf<String>()

        val mockEngine = MockEngine { request ->
            val path = request.url.encodedPath
            when {
                path == "/proofs/manage/additional" -> {
                    refreshUserAgent = request.headers[HttpHeaders.UserAgent]
                    respond(
                        content = """<html><script>var t0={"WLXAccount":{"manageProofs":{"encryptedNetId":"net1","apiCanary":"fresh_canary_stage8"}}};</script></html>""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }

                path == "/AddAssocId" -> {
                    addAssocHeaderCanary = request.headers["canary"]
                    addAssocCookieHeader = request.headers[HttpHeaders.Cookie]
                    addAssocReferer = request.headers["Referer"]
                    addAssocUserAgent = request.headers[HttpHeaders.UserAgent]
                    val formData = (request.body as? FormDataContent)?.formData
                    addAssocParamKeys = formData?.names().orEmpty()
                    addAssocFormCanary = formData?.get("canary")
                    addAssocPostOption = formData?.get("PostOption")
                    addAssocSingleDomain = formData?.get("SingleDomain")
                    addAssocUpSell = formData?.get("UpSell")
                    addAssocOptions = formData?.get("AddAssocIdOptions")
                    addAssocLive = formData?.get("AssociatedIdLive")
                    addAssocUaid = formData?.get("uaid")
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
                    verifyUserAgent = request.headers[HttpHeaders.UserAgent]
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
            Cookie(name = "amsc", value = "amsc_val_secret_1234", domain = "account.live.com", path = "/", secure = true),
        )
        cookieStorage.addCookie(
            Url("https://login.live.com"),
            Cookie(name = "OParams", value = "stale_oparams_should_not_leak", domain = "login.live.com", path = "/"),
        )
        cookieStorage.addCookie(
            Url("https://login.live.com"),
            Cookie(name = "uaid", value = "exact_login_cookie_uaid_value", domain = "login.live.com", path = "/"),
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
            currentCanary = "stale_canary",
            oldEmail = "old_user@outlook.com",
            httpClient = httpClient,
            customAlias = "ab12cd@qhuyy.tech",
            sessionUaid = "0123456789abcdef0123456789abcdef",
            debugListener = { debugPayloads.add(it) },
        )

        assertEquals("old_user@outlook.com", result.oldEmail)
        assertEquals("ab12cd@qhuyy.tech", result.newEmail)
        assertEquals("updated_canary_from_make_primary", result.updatedCanary)
        assertEquals("fresh_canary_stage8", addAssocHeaderCanary)
        assertEquals("fresh_canary_stage8", addAssocFormCanary)
        assertEquals("NONE", addAssocPostOption)
        assertEquals("outlook.com", addAssocSingleDomain)
        assertEquals("", addAssocUpSell)
        assertEquals("LIVE", addAssocOptions)
        assertEquals("ab12cd", addAssocLive)
        assertEquals(null, addAssocUaid)
        assertEquals(
            setOf("canary", "PostOption", "SingleDomain", "UpSell", "AddAssocIdOptions", "AssociatedIdLive"),
            addAssocParamKeys,
        )
        assertEquals("https://account.live.com/proofs/manage/additional", addAssocReferer)
        assertEquals(MicrosoftHttpClientFactory.DEFAULT_USER_AGENT, refreshUserAgent)
        assertEquals(MicrosoftHttpClientFactory.DEFAULT_USER_AGENT, addAssocUserAgent)
        assertEquals(MicrosoftHttpClientFactory.DEFAULT_USER_AGENT, verifyUserAgent)
        assertTrue(addAssocCookieHeader?.contains("__Host-MSAAUTH=msa_auth_val") == true)
        assertTrue(addAssocCookieHeader?.contains("AMRPSSecAuth=amrp_val") == true)
        assertTrue(addAssocCookieHeader?.contains("amsc=amsc_val_secret_1234") == true)
        assertTrue(addAssocCookieHeader?.contains("uaid=exact_login_cookie_uaid_value") == true)
        assertEquals(1, debugPayloads.size)
        assertTrue(!debugPayloads.single().contains("fresh_canary_stage8"))
        assertTrue(!debugPayloads.single().contains("amsc_val_secret_1234"))
        assertTrue(verifyCookiesHeader?.contains("__Host-MSAAUTH=msa_auth_val") == true)
        assertTrue(verifyCookiesHeader?.contains("AMRPSSecAuth=amrp_val") == true)
        assertTrue(verifyCookiesHeader?.contains("amsc=amsc_val_secret_1234") == true)
        assertEquals("fresh_canary_stage8", makePrimaryCanary)
        assertEquals("RemoveAlias", removeAliasAction)
    }

    @Test
    fun testRotateAliasWorkerTimeoutThrowsOtcTimeoutException(): Unit = runBlocking {
        val mockEngine = MockEngine { request ->
            val path = request.url.encodedPath
            when (path) {
                "/proofs/manage/additional" -> respond(
                    content = """<html><script>var t0={"WLXAccount":{"manageProofs":{"encryptedNetId":"net1","apiCanary":"fresh_canary"}}};</script></html>""",
                    status = HttpStatusCode.OK,
                )
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
                "/proofs/manage/additional" -> respond(
                    content = """<html><script>var t0={"WLXAccount":{"manageProofs":{"encryptedNetId":"net1","apiCanary":"fresh_canary"}}};</script></html>""",
                    status = HttpStatusCode.OK,
                )
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
                "/proofs/manage/additional" -> respond(
                    content = """<html><script>var t0={"WLXAccount":{"manageProofs":{"encryptedNetId":"net1","apiCanary":"fresh_canary"}}};</script></html>""",
                    status = HttpStatusCode.OK,
                )
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

    @Test
    fun testGenerateAliasFromEmail() {
        val client = AliasClient(domain = "qhuyy.tech")
        assertEquals("john.doe@qhuyy.tech", client.generateAliasFromEmail("john.doe@gmail.com"))
        assertEquals("johnspam123@qhuyy.tech", client.generateAliasFromEmail("John+Spam_123!@hotmail.com"))
        val fallback = client.generateAliasFromEmail("+++@gmail.com")
        assertTrue(fallback.endsWith("@qhuyy.tech"))
        assertTrue(fallback.substringBefore("@").isNotEmpty())
    }

    @Test
    fun testExtractOtcToken() {
        val client = AliasClient()
        assertEquals("654321", client.extractOtcToken("  654321  "))
        assertEquals(
            "ABC_123_XYZ",
            client.extractOtcToken("https://account.live.com/Aliases/Verify?aliasname=test%40qhuyy.tech&aliastype=Email&otc=ABC_123_XYZ"),
        )
    }

    @Test
    fun testRotateAliasWithManualOtcProviderSkipsWorker(): Unit = runBlocking {
        var workerHit = false
        var verifiedOtc: String? = null
        val callOrder = mutableListOf<String>()

        val mockEngine = MockEngine { request ->
            val path = request.url.encodedPath
            when (path) {
                "/proofs/manage/additional" -> {
                    callOrder.add("RefreshCanary")
                    respond(
                        content = """<html><script>var t0={"WLXAccount":{"manageProofs":{"encryptedNetId":"net1","apiCanary":"fresh_canary"}}};</script></html>""",
                        status = HttpStatusCode.OK,
                    )
                }
                "/AddAssocId" -> {
                    callOrder.add("AddAssocId")
                    respond("<html>Added</html>", HttpStatusCode.OK)
                }
                "/get-otc" -> {
                    workerHit = true
                    error("Worker must not be requested when aliasOtcProvider is supplied")
                }
                "/Aliases/Verify" -> {
                    callOrder.add("Verify")
                    verifiedOtc = request.url.parameters["otc"]
                    respond("<html>Verified</html>", HttpStatusCode.OK)
                }
                "/API/MakePrimary" -> {
                    callOrder.add("MakePrimary")
                    respond(
                        content = """{"apiCanary":"canary_2"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
                "/names/manage" -> {
                    callOrder.add("RemoveAlias")
                    respond("<html>Note_AssociatedIdRemoved</html>", HttpStatusCode.OK)
                }
                else -> error("Unexpected path: $path")
            }
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(MicrosoftHttpClientFactory.json)
            }
        }

        val client = AliasClient(sharedSecret = "")
        val result = client.rotateAlias(
            currentCanary = "canary_1",
            oldEmail = "victim@gmail.com",
            httpClient = httpClient,
            customAlias = "victim@qhuyy.tech",
            aliasOtcProvider = { alias ->
                callOrder.add("ManualPrompt:$alias")
                "998877"
            },
        )

        assertTrue(!workerHit)
        assertEquals("998877", verifiedOtc)
        assertEquals("victim@qhuyy.tech", result.newEmail)
        assertEquals("canary_2", result.updatedCanary)
        assertEquals(
            listOf("RefreshCanary", "AddAssocId", "ManualPrompt:victim@qhuyy.tech", "Verify", "MakePrimary", "RemoveAlias"),
            callOrder,
        )
    }

    @Test
    fun testAddAssocIdRedirectToMicrosoftOnlineThrowsSessionExpiredWithoutFollowingRedirect(): Unit = runBlocking {
        var redirectFollowed = false

        val mockEngine = MockEngine { request ->
            val host = request.url.host
            val path = request.url.encodedPath
            when {
                host == "login.microsoftonline.com" -> {
                    redirectFollowed = true
                    respond("<html>Should not follow redirect</html>", HttpStatusCode.OK)
                }
                path == "/proofs/manage/additional" -> {
                    respond(
                        content = """<html><script>var t0={"WLXAccount":{"manageProofs":{"encryptedNetId":"net1","apiCanary":"fresh_canary_abc"}}};</script></html>""",
                        status = HttpStatusCode.OK,
                    )
                }
                path == "/AddAssocId" -> {
                    respond(
                        content = "",
                        status = HttpStatusCode.Found,
                        headers = headersOf(
                            HttpHeaders.Location,
                            "https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000004",
                        ),
                    )
                }
                else -> error("Unexpected request: ${request.url}")
            }
        }

        val httpClient = MicrosoftHttpClientFactory.create(engine = mockEngine)
        val client = AliasClient(sharedSecret = "")

        val thrown = assertFailsWith<SessionExpiredException> {
            client.rotateAlias(
                currentCanary = "stale_canary",
                oldEmail = "lencak480@gmail.com",
                httpClient = httpClient,
                customAlias = "lencak480@qhuyy.tech",
            )
        }

        assertTrue(!redirectFollowed)
        assertEquals("Session expired during Alias Rotation. Cannot add alias.", thrown.message)
        assertEquals(
            "https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000004",
            thrown.redirectLocation,
        )
    }

    @Test
    fun testAddAssocIdOmitsUaidWhenLoginCookieMissing(): Unit = runBlocking {
        var addAssocParamKeys: Set<String> = emptySet()
        var addAssocUaid: String? = "unexpected"
        var addAssocLive: String? = null
        val debugPayloads = mutableListOf<String>()

        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/proofs/manage/additional" -> respond(
                    content = """<html><script>var t0={"WLXAccount":{"manageProofs":{"encryptedNetId":"net1","apiCanary":"fresh_canary_no_uaid"}}};</script></html>""",
                    status = HttpStatusCode.OK,
                )
                "/AddAssocId" -> {
                    val formData = (request.body as? FormDataContent)?.formData
                    addAssocParamKeys = formData?.names().orEmpty()
                    addAssocUaid = formData?.get("uaid")
                    addAssocLive = formData?.get("AssociatedIdLive")
                    respond("<html>Added</html>", HttpStatusCode.OK)
                }
                "/Aliases/Verify" -> respond("<html>Verified</html>", HttpStatusCode.OK)
                "/API/MakePrimary" -> respond(
                    content = """{"apiCanary":"canary_primary"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/names/manage" -> respond("<html>Note_AssociatedIdRemoved</html>", HttpStatusCode.OK)
                else -> error("Unexpected path: ${request.url.encodedPath}")
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

        val client = AliasClient(sharedSecret = "")
        client.rotateAlias(
            currentCanary = "stale_canary",
            oldEmail = "lencak480@gmail.com",
            httpClient = httpClient,
            customAlias = "lencak480@qhuyy.tech",
            aliasOtcProvider = { "112233" },
            cookieStorage = cookieStorage,
            sessionUaid = "83f705bc231b49f0922e5e3609ac18fa",
            debugListener = { debugPayloads.add(it) },
        )

        assertEquals(null, addAssocUaid)
        assertEquals("lencak480", addAssocLive)
        assertEquals(
            setOf("canary", "PostOption", "SingleDomain", "UpSell", "AddAssocIdOptions", "AssociatedIdLive"),
            addAssocParamKeys,
        )
    }
}
