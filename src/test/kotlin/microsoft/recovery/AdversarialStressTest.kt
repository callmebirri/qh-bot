package microsoft.recovery

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.forms.FormDataContent
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.headersOf
import io.ktor.http.parseServerSetCookieHeader
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import microsoft.recovery.alias.AliasClient
import microsoft.recovery.alias.SessionExpiredException
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.ProofItem
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.StageExecution
import microsoft.recovery.stages.Stage2Otp
import microsoft.recovery.stages.Stage7Suppression
import microsoft.recovery.stages.Stage8Alias
import microsoft.recovery.stages.Stage9Cleanup
import microsoft.recovery.util.MicrosoftHttpClientFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AdversarialStressTest {

    @Test
    fun testNativeOutlookAliasStage8WithEmptyCookiesStorage(): Unit = runBlocking {
        val emptyStorage = AcceptAllCookiesStorage()
        var capturedAddAssocCookie: String? = null
        var capturedAddAssocCanary: String? = null

        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/AddAssocId" -> {
                    capturedAddAssocCookie = request.headers[HttpHeaders.Cookie]
                    capturedAddAssocCanary = request.headers["canary"]
                    respond(
                        content = "",
                        status = HttpStatusCode.Found,
                        headers = headersOf(HttpHeaders.Location, "https://account.live.com/proofs/manage/additional"),
                    )
                }
                "/API/MakePrimary" -> respond(
                    content = """{"apiCanary":"final_canary_999"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/names/manage" -> respond(
                    content = "<html>Note_AssociatedIdRemoved</html>",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = HttpClient(mockEngine) {
            install(HttpCookies) { this.storage = emptyStorage }
            install(ContentNegotiation) { json(MicrosoftHttpClientFactory.json) }
        }

        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "newalias",
            uaid = "uaid_val_123",
            activeCanary = "initial_canary",
            httpClient = client,
            cookieStorage = emptyStorage,
        )

        val stage8 = Stage8Alias(aliasClient = null, stageDelayMs = 0L)
        val result = stage8.execute(context, null)

        assertIs<StageExecution.Success<Unit>>(result)
        assertEquals("newalias@outlook.com", context.targetAliasEmail)
        assertEquals("final_canary_999", context.activeCanary)
        assertEquals(null, capturedAddAssocCookie)
        assertEquals("initial_canary", capturedAddAssocCanary)
    }

    @Test
    fun testNativeOutlookAliasSpecialCharactersInPrefix(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        var capturedPrefix: String? = null
        var capturedSingleDomain: String? = null
        var capturedUaidParam: String? = null

        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/AddAssocId" -> {
                    val body = request.body as FormDataContent
                    capturedPrefix = body.formData["AssociatedIdLive"]
                    capturedSingleDomain = body.formData["SingleDomain"]
                    capturedUaidParam = body.formData["uaid"]
                    respond(
                        content = "",
                        status = HttpStatusCode.Found,
                        headers = headersOf(HttpHeaders.Location, "https://account.live.com/proofs/manage/additional"),
                    )
                }
                "/API/MakePrimary" -> respond(
                    content = """{"apiCanary":"canary_456"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/names/manage" -> respond(
                    content = "<html>Note_AssociatedIdRemoved</html>",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = HttpClient(mockEngine) {
            install(HttpCookies) { this.storage = storage }
            install(ContentNegotiation) { json(MicrosoftHttpClientFactory.json) }
        }

        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "  my.weird+alias_123  ",
            uaid = "uaid_val_123",
            activeCanary = "canary_init",
            httpClient = client,
            cookieStorage = storage,
        )

        val stage8 = Stage8Alias(aliasClient = null, stageDelayMs = 0L)
        val result = stage8.execute(context, null)

        assertIs<StageExecution.Success<Unit>>(result)
        assertEquals("my.weird+alias_123@outlook.com", context.targetAliasEmail)
        assertEquals("my.weird+alias_123", capturedPrefix)
        assertEquals("outlook.com", capturedSingleDomain)
        assertEquals(null, capturedUaidParam, "uaid MUST NOT be in AddAssocId form body")
    }

    @Test
    fun testNativeOutlookAliasAlreadyContainingOutlookDomain(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        var capturedPrefix: String? = null

        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/AddAssocId" -> {
                    val body = request.body as FormDataContent
                    capturedPrefix = body.formData["AssociatedIdLive"]
                    respond(
                        content = "",
                        status = HttpStatusCode.Found,
                        headers = headersOf(HttpHeaders.Location, "https://account.live.com/proofs/manage/additional"),
                    )
                }
                "/API/MakePrimary" -> respond(
                    content = """{"apiCanary":"canary_456"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/names/manage" -> respond(
                    content = "<html>Note_AssociatedIdRemoved</html>",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = HttpClient(mockEngine) {
            install(HttpCookies) { this.storage = storage }
            install(ContentNegotiation) { json(MicrosoftHttpClientFactory.json) }
        }

        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "already_explicit@outlook.com",
            uaid = "uaid_val_123",
            activeCanary = "canary_init",
            httpClient = client,
            cookieStorage = storage,
        )

        val stage8 = Stage8Alias(aliasClient = null, stageDelayMs = 0L)
        val result = stage8.execute(context, null)

        assertIs<StageExecution.Success<Unit>>(result)
        assertEquals("already_explicit@outlook.com", context.targetAliasEmail)
        assertEquals("already_explicit", capturedPrefix)
    }

    @Test
    fun testAddAssocIdRedirectToMicrosoftOnlineThrowsSessionExpiredInStage8(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/AddAssocId" -> respond(
                    content = "",
                    status = HttpStatusCode.Found,
                    headers = headersOf(HttpHeaders.Location, "https://login.microsoftonline.com/common/oauth2/authorize"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = HttpClient(mockEngine) {
            install(HttpCookies) { this.storage = storage }
            install(ContentNegotiation) { json(MicrosoftHttpClientFactory.json) }
        }

        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "newalias",
            uaid = "uaid_val_123",
            activeCanary = "canary_init",
            httpClient = client,
            cookieStorage = storage,
        )

        val stage8 = Stage8Alias(aliasClient = null, stageDelayMs = 0L)
        val result = stage8.execute(context, null)

        assertIs<StageExecution.Failure>(result)
        assertEquals(microsoft.recovery.model.RecoveryStage.ALIAS_ROTATION, result.result.stage)
        assertTrue(result.result.message.contains("Session expired during Alias Rotation"))
    }

    @Test
    fun testAliasClientPreservesFullCookieJarAndOmitsUaidFromForm(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        storage.addCookie(
            Url("https://login.live.com"),
            Cookie(name = "__Host-MSAAUTH", value = "msa_val", domain = "login.live.com", path = "/", secure = true),
        )
        storage.addCookie(
            Url("https://login.live.com"),
            Cookie(name = "uaid", value = "session_uaid_999", domain = "login.live.com", path = "/", secure = true),
        )
        storage.addCookie(
            Url("https://login.live.com"),
            Cookie(name = "MSPOK", value = "mspok_val", domain = "login.live.com", path = "/", secure = true),
        )
        storage.addCookie(
            Url("https://account.live.com"),
            Cookie(name = "AMRPSSecAuth", value = "amrp_val", domain = "account.live.com", path = "/", secure = true),
        )
        storage.addCookie(
            Url("https://account.live.com"),
            Cookie(name = "amsc", value = "amsc_val", domain = "account.live.com", path = "/", secure = true),
        )

        var addAssocCookieHeader: String? = null
        var addAssocUaidParam: String? = null

        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/proofs/manage/additional" -> respond(
                    content = """<html><body><script>var ServerData = {"apiCanary":"fresh_canary"};</script></body></html>""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                "/AddAssocId" -> {
                    addAssocCookieHeader = request.headers[HttpHeaders.Cookie]
                    val body = request.body as FormDataContent
                    addAssocUaidParam = body.formData["uaid"]
                    respond(
                        content = "",
                        status = HttpStatusCode.Found,
                        headers = headersOf(HttpHeaders.Location, "https://account.live.com/proofs/manage/additional"),
                    )
                }
                "/Aliases/Verify" -> respond("<html>Verified</html>", HttpStatusCode.OK)
                "/API/MakePrimary" -> respond(
                    content = """{"apiCanary":"final_canary"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/names/manage" -> respond(
                    content = "<html>Note_AssociatedIdRemoved</html>",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = HttpClient(mockEngine) {
            install(HttpCookies) { this.storage = storage }
            install(ContentNegotiation) { json(MicrosoftHttpClientFactory.json) }
        }

        val aliasClient = AliasClient(domain = "qhuyy.tech")
        val result = aliasClient.rotateAlias(
            currentCanary = "initial_canary",
            oldEmail = "victim@domain.com",
            httpClient = client,
            customAlias = "testalias",
            aliasOtcProvider = { "123456" },
            cookieStorage = storage,
        )

        assertEquals("testalias@qhuyy.tech", result.newEmail)
        assertEquals("final_canary", result.updatedCanary)
        assertEquals(null, addAssocUaidParam, "uaid MUST NOT be in form body")
        assertNotNull(addAssocCookieHeader)
        assertTrue(addAssocCookieHeader!!.contains("__Host-MSAAUTH=msa_val"))
        assertTrue(addAssocCookieHeader!!.contains("AMRPSSecAuth=amrp_val"))
        assertTrue(addAssocCookieHeader!!.contains("amsc=amsc_val"))
        assertTrue(addAssocCookieHeader!!.contains("uaid=session_uaid_999"))
        assertTrue(addAssocCookieHeader!!.contains("MSPOK=mspok_val"))
    }

    @Test
    fun testAliasClientThrowsWhenSharedSecretEmptyAndOtcProviderNull(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/proofs/manage/additional" -> respond(
                    content = """<html><body><script>var ServerData = {"apiCanary":"fresh_canary"};</script></body></html>""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                "/AddAssocId" -> respond(
                    content = "",
                    status = HttpStatusCode.Found,
                    headers = headersOf(HttpHeaders.Location, "https://account.live.com/proofs/manage/additional"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = HttpClient(mockEngine) {
            install(HttpCookies) { this.storage = storage }
            install(ContentNegotiation) { json(MicrosoftHttpClientFactory.json) }
        }

        val aliasClient = AliasClient(sharedSecret = "")
        val ex = assertFailsWith<IllegalArgumentException> {
            aliasClient.rotateAlias(
                currentCanary = "canary",
                oldEmail = "victim@domain.com",
                httpClient = client,
                customAlias = "testalias",
                aliasOtcProvider = null, // triggers pollOtc
                cookieStorage = storage,
            )
        }
        assertTrue(ex.message!!.contains("Shared secret cannot be empty"))
    }

    @Test
    fun testCrossDomainCookiePartitioningInStage2AndStage8(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/GetOneTimeCode.srf" -> respond(
                    content = """{"FlowToken":"post_ppft_token","State":200}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/ppsecure/post.srf" -> respond(
                    content = "OK",
                    status = HttpStatusCode.OK,
                    headers = headersOf(
                        HttpHeaders.SetCookie,
                        listOf(
                            "__Host-MSAAUTH=secret_host_msa_auth_value; path=/; Secure; HttpOnly",
                            "uaid=server_uaid_cookie_1234; domain=login.live.com; path=/; Secure",
                        ),
                    ),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = HttpClient(mockEngine) {
            install(HttpCookies) { this.storage = storage }
        }

        val context = RecoveryContext(
            email = "test@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "new_email@outlook.com",
            uaid = "initial_synthetic_uaid",
            initialPpft = "initial_ppft_val",
            proofId = "proof_email_id",
            proofChannel = "Email",
            httpClient = client,
            cookieStorage = storage,
            otpProvider = { "123456" },
        )

        val stage2 = Stage2Otp()
        val execution = stage2.execute(context, null)

        assertIs<StageExecution.Success<Unit>>(execution)

        // Verify __Host-MSAAUTH is present in BOTH login.live.com and account.live.com
        val loginCookies = storage.get(Url("https://login.live.com"))
        val accountCookies = storage.get(Url("https://account.live.com"))

        val loginMsa = loginCookies.firstOrNull { it.name == "__Host-MSAAUTH" }
        val accountMsa = accountCookies.firstOrNull { it.name == "__Host-MSAAUTH" }

        assertNotNull(loginMsa, "__Host-MSAAUTH missing from login.live.com")
        assertNotNull(accountMsa, "__Host-MSAAUTH missing from account.live.com")
        assertEquals("secret_host_msa_auth_value", loginMsa.value)
        assertEquals("secret_host_msa_auth_value", accountMsa.value)

        // Verify uaid cookie was captured into context.uaid
        assertEquals("server_uaid_cookie_1234", context.uaid)
    }

    @Test
    fun testParseServerSetCookieHeaderWithAttributes() {
        val raw = "__Host-MSAAUTH=tok_123; path=/; Secure; HttpOnly; SameSite=None"
        val parsed = parseServerSetCookieHeader(raw)
        assertEquals("__Host-MSAAUTH", parsed.name)
        assertEquals("tok_123", parsed.value)
        assertEquals("/", parsed.path)
        assertTrue(parsed.secure)
        assertTrue(parsed.httpOnly)

        val rawWithDomain = "uaid=hex123; Domain=login.live.com; Path=/; Secure"
        val parsedDomain = parseServerSetCookieHeader(rawWithDomain)
        assertEquals("uaid", parsedDomain.name)
        assertEquals("hex123", parsedDomain.value)
        assertEquals("login.live.com", parsedDomain.domain)
        assertEquals("/", parsedDomain.path)
        assertTrue(parsedDomain.secure)
    }

    @Test
    fun testStage8RemoveAliasFailsClosedWhenConfirmationMissing(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/AddAssocId" -> respond(
                    content = "",
                    status = HttpStatusCode.Found,
                    headers = headersOf(HttpHeaders.Location, "https://account.live.com/proofs/manage/additional"),
                )
                "/API/MakePrimary" -> respond(
                    content = """{"apiCanary":"primary_canary"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/names/manage" -> respond(
                    content = "<html>Error: Could not remove alias</html>",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = MicrosoftHttpClientFactory.create(storage = storage, engine = mockEngine)
        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "newalias",
            uaid = "uaid_val_123",
            activeCanary = "initial_canary",
            httpClient = client,
            cookieStorage = storage,
        )

        val stage8 = Stage8Alias(aliasClient = null, stageDelayMs = 0L)
        val result = stage8.execute(context, null)

        assertIs<StageExecution.Failure>(result)
        assertEquals(RecoveryStage.ALIAS_ROTATION, result.result.stage)
        assertTrue(result.result.message.contains("Note_AssociatedIdRemoved"))
    }

    @Test
    fun testStage9CleanupOmitsRemovePasskeyWhenEmpty(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val requestedPaths = mutableListOf<String>()
        val mockEngine = MockEngine { request ->
            requestedPaths.add(request.url.encodedPath)
            when (request.url.encodedPath) {
                "/API/Proofs/DisableTfa",
                "/API/Proofs/DeleteDevices",
                "/API/Proofs/DeleteAppPassword",
                "/API/Proofs/RemovePasskey" -> respond(
                    content = """{"apiCanary":"cleanup_canary"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = MicrosoftHttpClientFactory.create(storage = storage, engine = mockEngine)
        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "newalias",
            uaid = "uaid_val_123",
            activeCanary = "initial_canary",
            passKeyIds = emptyList(),
            httpClient = client,
            cookieStorage = storage,
        )

        val stage9 = Stage9Cleanup(stageDelayMs = 0L)
        val result = stage9.execute(context, null)

        assertIs<StageExecution.Success<Unit>>(result)
        assertTrue(requestedPaths.contains("/API/Proofs/DisableTfa"))
        assertTrue(requestedPaths.contains("/API/Proofs/DeleteDevices"))
        assertTrue(requestedPaths.contains("/API/Proofs/DeleteAppPassword"))
        assertTrue(!requestedPaths.contains("/API/Proofs/RemovePasskey"))
    }

    @Test
    fun testStage9CleanupIteratesPasskeysAndHandlesFailuresGracefully(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val requestedPasskeys = mutableListOf<String>()
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/API/Proofs/DisableTfa" -> respond(
                    content = "Internal Server Error",
                    status = HttpStatusCode.InternalServerError,
                )
                "/API/Proofs/DeleteDevices" -> respond(
                    content = "Bad Request",
                    status = HttpStatusCode.BadRequest,
                )
                "/API/Proofs/DeleteAppPassword" -> respond(
                    content = "Not Found",
                    status = HttpStatusCode.NotFound,
                )
                "/API/Proofs/RemovePasskey" -> {
                    val bodyText = (request.body as? io.ktor.http.content.TextContent)?.text.orEmpty()
                    if (bodyText.contains("key-alpha")) requestedPasskeys.add("key-alpha")
                    if (bodyText.contains("key-beta")) requestedPasskeys.add("key-beta")
                    respond(
                        content = """{"apiCanary":"canary_passkey"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = MicrosoftHttpClientFactory.create(storage = storage, engine = mockEngine)
        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "newalias",
            uaid = "uaid_val_123",
            activeCanary = "initial_canary",
            passKeyIds = listOf("key-alpha", "key-beta"),
            httpClient = client,
            cookieStorage = storage,
        )

        val stage9 = Stage9Cleanup(stageDelayMs = 0L)
        val result = stage9.execute(context, null)

        assertIs<StageExecution.Success<Unit>>(result)
        assertEquals(listOf("key-alpha", "key-beta"), requestedPasskeys)
    }

    @Test
    fun testStage7SuppressionRedirectToLoginSrfFailsClosed(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/proofs/manage/additional" -> respond(
                    content = """
                        <html>
                        <script>
                        var t0 = {
                            "WLXAccount": {
                                "manageProofs": {
                                    "encryptedNetId": "enc_net_id_123",
                                    "apiCanary": "canary_manage_123",
                                    "emailProofs": [{"name": "victim@example.com"}]
                                }
                            }
                        };
                        </script>
                        </html>
                    """.trimIndent(),
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                "/API/Proofs/SetUserNotificationState" -> respond(
                    content = "",
                    status = HttpStatusCode.Found,
                    headers = headersOf(HttpHeaders.Location, "https://login.live.com/login.srf"),
                )
                "/login.srf" -> respond(
                    content = "<html>Login</html>",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = MicrosoftHttpClientFactory.create(storage = storage, engine = mockEngine)
        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "newalias",
            uaid = "uaid_val_123",
            activeCanary = "initial_canary",
            httpClient = client,
            cookieStorage = storage,
        )

        val stage7 = Stage7Suppression(stageDelayMs = 0L)
        val result = stage7.execute(context, null)

        assertIs<StageExecution.Failure>(result)
        assertEquals(RecoveryStage.NOTIFICATION_SUPPRESSION, result.result.stage)
        assertTrue(result.result.message.contains("redirected to unexpected path /login.srf"))
    }

    @Test
    fun testStage7SuppressionMissingCanaryFailsClosed(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/proofs/manage/additional" -> respond(
                    content = """
                        <html>
                        <script>
                        var t0 = {
                            "WLXAccount": {
                                "manageProofs": {
                                    "encryptedNetId": "enc_net_id_123",
                                    "apiCanary": "canary_manage_123",
                                    "emailProofs": [{"name": "victim@example.com"}]
                                }
                            }
                        };
                        </script>
                        </html>
                    """.trimIndent(),
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "text/html"),
                )
                "/API/Proofs/SetUserNotificationState" -> respond(
                    content = """{"error":{"code":"InvalidSession","message":"Session expired"}}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = MicrosoftHttpClientFactory.create(storage = storage, engine = mockEngine)
        val context = RecoveryContext(
            email = "victim@domain.com",
            newPassword = "NewPassword123!",
            newEmail = "newalias",
            uaid = "uaid_val_123",
            activeCanary = "initial_canary",
            httpClient = client,
            cookieStorage = storage,
        )

        val stage7 = Stage7Suppression(stageDelayMs = 0L)
        val result = stage7.execute(context, null)

        assertIs<StageExecution.Failure>(result)
        assertEquals(RecoveryStage.NOTIFICATION_SUPPRESSION, result.result.stage)
        assertTrue(result.result.message.contains("Session expired"))
    }
}
