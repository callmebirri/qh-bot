package microsoft.recovery

import database.DatabaseManager
import database.model.RecoveredAccount
import database.repository.SqliteAccountRepository
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.alias.AliasClient
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.util.MicrosoftHttpClientFactory
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RecoveryServiceTest {

    private fun createMockEngine(
        ifExistsResult: Int = 0,
        failAtNotification: Boolean = false,
        otcState: Int = 201,
        otcFlowToken: String? = "MOCK_NEW_PPFT_456",
        returnAuthCookie: Boolean = true,
        includeTokenT: Boolean = true,
        returnPpftOnPolish: Boolean = false,
        redirectPolish: Boolean = false,
        onStage3Request: ((io.ktor.client.request.HttpRequestData) -> Unit)? = null,
        extraCookies: Boolean = false,
    ): MockEngine {
        var manageAdditionalCalls = 0

        return MockEngine { request ->
            val path = request.url.encodedPath
            when {
                path == "/login.srf" && request.url.parameters.contains("wreply") -> {
                    onStage3Request?.invoke(request)
                    if (redirectPolish) {
                        respond("", HttpStatusCode.Found, headersOf(HttpHeaders.Location, "/login_redirect.srf"))
                    } else if (returnPpftOnPolish) {
                        respond("<html><form><input type=\"hidden\" name=\"PPFT\" value=\"expired\"/></form></html>", HttpStatusCode.OK)
                    } else if (!includeTokenT) {
                        respond("<html><body>No token here</body></html>", HttpStatusCode.OK)
                    } else {
                        respond(
                            content = """
                                <html>
                                <form>
                                <input type="hidden" name="t" value="SAMPLE_TOKEN_T_VALUE_1024"/>
                                </form>
                                </html>
                            """.trimIndent(),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType, "text/html"),
                        )
                    }
                }

                path == "/login_redirect.srf" -> {
                    respond(
                        content = """
                            <html>
                            <form>
                            <input type="hidden" name="t" value="SAMPLE_TOKEN_T_VALUE_1024"/>
                            </form>
                            </html>
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }

                path == "/login.srf" -> {
                    val headers = if (extraCookies) {
                        headersOf(
                            HttpHeaders.ContentType to listOf("text/html"),
                            HttpHeaders.SetCookie to listOf("uaid=server_uaid_9999; Domain=login.live.com; Path=/"),
                        )
                    } else {
                        headersOf(HttpHeaders.ContentType, "text/html")
                    }
                    respond(
                        content = """
                            <html>
                            <script>
                            var ServerData = {"sFTAg":"<input type=\"hidden\" name=\"PPFT\" id=\"i0327\" value=\"MOCK_PPFT_123\"/>","canary":""};
                            </script>
                            </html>
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headers,
                    )
                }

                path == "/GetCredentialType.srf" -> {
                    val proofsJson = if (ifExistsResult == 0) {
                        """[{"data":"proof_data_xyz","display":"user@example.com","type":1}]"""
                    } else {
                        "[]"
                    }
                    val headers = if (extraCookies) {
                        headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                            HttpHeaders.SetCookie to listOf("OParams=legacy_oparams_val; Domain=login.live.com; Path=/"),
                        )
                    } else {
                        headersOf(HttpHeaders.ContentType, "application/json")
                    }
                    respond(
                        content = """
                            {
                                "IfExistsResult": $ifExistsResult,
                                "Credentials": {
                                    "HasPassword": 1,
                                    "OtcLoginEligibleProofs": $proofsJson
                                }
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headers,
                    )
                }

                path == "/GetOneTimeCode.srf" -> {
                    val flowTokenField = if (otcFlowToken != null) """, "FlowToken": "$otcFlowToken"""" else ""
                    val headers = if (extraCookies) {
                        headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                            HttpHeaders.SetCookie to listOf("PPState=legacy_ppstate_val; Domain=login.live.com; Path=/"),
                        )
                    } else {
                        headersOf(HttpHeaders.ContentType, "application/json")
                    }
                    respond(
                        content = """{"State": $otcState$flowTokenField}""",
                        status = HttpStatusCode.OK,
                        headers = headers,
                    )
                }

                path == "/ppsecure/post.srf" -> {
                    val headers = if (returnAuthCookie) {
                        headersOf(
                            HttpHeaders.ContentType to listOf("text/html"),
                            HttpHeaders.SetCookie to listOf("__Host-MSAAUTH=msa_session_cookie_token; path=/; secure"),
                        )
                    } else {
                        headersOf(HttpHeaders.ContentType, "text/html")
                    }
                    respond(
                        content = "<html>Redirecting...</html>",
                        status = HttpStatusCode.Found,
                        headers = headers,
                    )
                }

                path == "/proofs/Add" -> {
                    respond(
                        content = "<html>Redirecting...</html>",
                        status = HttpStatusCode.Found,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("text/html"),
                            HttpHeaders.SetCookie to listOf(
                                "AMRPSSecAuth=amrp_sec_cookie_val; path=/; domain=account.live.com",
                                "amsc=amsc_cookie_val; path=/; domain=account.live.com",
                            ),
                        ),
                    )
                }

                path == "/proofs/manage/additional" -> {
                    manageAdditionalCalls++
                    respond(
                        content = """
                            <html>
                            <script>
                            var t0 = {
                                "WLXAccount": {
                                    "manageProofs": {
                                        "encryptedNetId": "enc_net_id_\\u002b123\\u003d",
                                        "apiCanary": "canary_token_manage_1",
                                        "emailProofs": [{"name": "victim_email\\u0040example.com"}],
                                        "smsProofs": [{"name": "+1234567890"}],
                                        "passKeys": [{"passKeyId": "passkey-id-1"}]
                                    }
                                }
                            };
                            </script>
                            </html>
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }

                path == "/API/Proofs/GenerateRecoveryCode" -> {
                    respond(
                        content = """
                            {
                                "recoveryCode": "INITIAL-RECOV-11111-22222-33333",
                                "apiCanary": "canary_token_after_gen"
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

                path == "/ResetPassword.aspx" -> {
                    respond(
                        content = """
                            <html>
                            <script>
                            var ServerData = {
                                "sRecoveryToken": "s_recovery_token_\\u002bdata_xyz",
                                "apiCanary": "canary_token_reset_page"
                            };
                            </script>
                            </html>
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }

                path == "/API/Recovery/VerifyRecoveryCode" -> {
                    respond(
                        content = """
                            {
                                "token": "verification_grant_token_123",
                                "apiCanary": "canary_token_after_verify"
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

                path == "/API/Recovery/RecoverUser" -> {
                    respond(
                        content = """
                            {
                                "recoveryCode": "FINAL-RECOV-44444-55555-66666",
                                "apiCanary": "canary_token_after_recover"
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

                path == "/API/Proofs/SetUserNotificationState" -> {
                    if (failAtNotification) {
                        respond("Internal server error", HttpStatusCode.InternalServerError)
                    } else {
                        respond(
                            content = """{"apiCanary": "canary_token_after_notify"}""",
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType, "application/json"),
                        )
                    }
                }

                path == "/AddAssocId" -> {
                    respond("<html>Alias added</html>", HttpStatusCode.OK)
                }

                path == "/API/MakePrimary" -> {
                    respond(
                        content = """{"apiCanary": "canary_token_after_makeprimary"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

                path == "/names/manage" -> {
                    respond("<html>Alias removed</html>", HttpStatusCode.OK)
                }

                path == "/API/Proofs/DisableTfa" ||
                path == "/API/Proofs/DeleteDevices" ||
                path == "/API/Proofs/DeleteAppPassword" ||
                path == "/API/Proofs/RemovePasskey" -> {
                    respond(
                        content = """{"apiCanary": "canary_token_after_cleanup"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

                else -> error("Unhandled request path: $path")
            }
        }
    }

    @Test
    fun testCompleteLifecycleSuccess(): Unit = runBlocking {
        val engine = createMockEngine()
        val tempDb = File.createTempFile("test_recov_", ".db")
        val dbManager = DatabaseManager(tempDb.absolutePath)
        val repository = SqliteAccountRepository(dbManager)

        val service = RecoveryService(
            clientEngine = engine,
            stageDelayMs = 0L,
            accountRepository = repository,
            stopAfterStage7 = false,
        )

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newEmail = "administrator2026@outlook.com",
        )

        if (result is RecoveryResult.Failure) {
            println("FAILURE STAGE: ${result.stage}, MESSAGE: ${result.message}")
        }
        assertIs<RecoveryResult.Success>(result)
        assertEquals("victim@example.com", result.originalEmail)
        assertEquals("administrator2026@outlook.com", result.newPrimaryEmail)
        assertEquals("INITIAL-RECOV-11111-22222-33333", result.initialRecoveryCode)
        assertEquals("FINAL-RECOV-44444-55555-66666", result.finalRecoveryCode)
        assertEquals(2, result.suppressedProofsCount)
        assertTrue(result.password.isNotEmpty())
        assertTrue(result.password.length in 12..16)

        val saved = repository.getAccountByEmail("victim@example.com")
        assertNotNull(saved)
        assertEquals(result.password, saved.password)
        assertEquals("FINAL-RECOV-44444-55555-66666", saved.recoveryCode)
        assertEquals("administrator2026@outlook.com", saved.currentPrimaryEmail)
        assertEquals(RecoveredAccount.STATUS_SUCCESS, saved.status)

        dbManager.close()
        tempDb.delete()
    }

    @Test
    fun testPendingStatusRemainsPendingOnFailureAndUpdatesOnRetry(): Unit = runBlocking {
        val tempDb = File.createTempFile("test_idempotent_", ".db")
        val dbManager = DatabaseManager(tempDb.absolutePath)
        val repository = SqliteAccountRepository(dbManager)

        repository.saveAccount(
            RecoveredAccount(
                originalEmail = "retryme@example.com",
                status = RecoveredAccount.STATUS_PENDING,
            ),
        )

        val failService = RecoveryService(
            clientEngine = createMockEngine(failAtNotification = true),
            stageDelayMs = 0L,
            accountRepository = repository,
        )
        val failResult = failService.runLifecycle(
            email = "retryme@example.com",
            otpProvider = { "123456" },
            newEmail = "alias_retry@outlook.com",
        )
        assertIs<RecoveryResult.Failure>(failResult)

        val afterFailure = repository.getAccountByOriginalEmail("retryme@example.com")
        assertNotNull(afterFailure)
        assertEquals(RecoveredAccount.STATUS_PENDING, afterFailure.status)

        val successService = RecoveryService(
            clientEngine = createMockEngine(),
            stageDelayMs = 0L,
            accountRepository = repository,
            stopAfterStage7 = false,
        )
        val successResult = successService.runLifecycle(
            email = "retryme@example.com",
            otpProvider = { "123456" },
            newEmail = "alias_retry@outlook.com",
        )
        assertIs<RecoveryResult.Success>(successResult)

        val afterSuccess = repository.getAccountByOriginalEmail("retryme@example.com")
        assertNotNull(afterSuccess)
        assertEquals(RecoveredAccount.STATUS_SUCCESS, afterSuccess.status)
        assertEquals("alias_retry@outlook.com", afterSuccess.currentPrimaryEmail)
        assertEquals(1, repository.getAllAccounts().size)

        dbManager.close()
        tempDb.delete()
    }

    @Test
    fun testAccountNotFoundInDiscovery() = runBlocking {
        val engine = createMockEngine(ifExistsResult = 1)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "nonexistent@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.CREDENTIAL_DISCOVERY, result.stage)
        assertEquals("1", result.errorCode)
    }

    @Test
    fun testAccountThrottledInDiscovery() = runBlocking {
        val engine = createMockEngine(ifExistsResult = 5)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "throttled@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.CREDENTIAL_DISCOVERY, result.stage)
        assertEquals("5", result.errorCode)
    }

    @Test
    fun testMissingAuthCookieFailsSessionEstablishment() = runBlocking {
        val engine = createMockEngine(returnAuthCookie = false)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.SESSION_ESTABLISHMENT, result.stage)
    }

    @Test
    fun testNotificationSuppressionFailClosed() = runBlocking {
        val engine = createMockEngine(failAtNotification = true)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.NOTIFICATION_SUPPRESSION, result.stage)
    }

    @Test
    fun testStageListenerEmitsEvents() = runBlocking {
        val engine = createMockEngine()
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L, stopAfterStage7 = false)
        val stagesLogged = mutableListOf<String>()

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
            stageListener = { stageKey, _, isSuccess, _ ->
                stagesLogged.add("$stageKey:$isSuccess")
            },
        )

        if (result is RecoveryResult.Failure) {
            println("FAILURE STAGE: ${result.stage}, MESSAGE: ${result.message}")
        }
        assertIs<RecoveryResult.Success>(result)
        assertTrue(stagesLogged.contains("1:true"))
        assertTrue(stagesLogged.contains("2:true"))
        assertTrue(stagesLogged.contains("2b:true"))
        assertTrue(stagesLogged.contains("3:true"))
        assertTrue(stagesLogged.contains("4:true"))
        assertTrue(stagesLogged.contains("5:true"))
        assertTrue(stagesLogged.contains("6:true"))
        assertTrue(stagesLogged.contains("7:true"))
        assertTrue(stagesLogged.contains("8:true"))
        assertTrue(stagesLogged.contains("9:true"))
    }

    @Test
    fun testStage2State206ProceedsWithFlowToken(): Unit = runBlocking {
        val engine = createMockEngine(otcState = 206)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        if (result is RecoveryResult.Failure) {
            println("FAILURE STAGE: ${result.stage}, MESSAGE: ${result.message}")
        }
        assertIs<RecoveryResult.Success>(result)
    }

    @Test
    fun testStage2MissingFlowTokenFails(): Unit = runBlocking {
        val engine = createMockEngine(otcState = 201, otcFlowToken = null)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.OTP_DISPATCH, result.stage)
        assertEquals("Fatal: Missing FlowToken in response", result.message)
    }

    @Test
    fun testStage3SessionExpiredDetectsPpft(): Unit = runBlocking {
        val engine = createMockEngine(returnPpftOnPolish = true)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.SESSION_POLISH, result.stage)
        assertEquals("Session expired or invalid, asked to login again.", result.message)
    }

    @Test
    fun testStage3MissingTokenT(): Unit = runBlocking {
        val engine = createMockEngine(includeTokenT = false)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.SESSION_POLISH, result.stage)
        assertEquals("Token t not found in HTML.", result.message)
    }

    @Test
    fun testStage3RedirectFollowed(): Unit = runBlocking {
        val engine = createMockEngine(redirectPolish = true)
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Success>(result)
    }

    @Test
    fun testStage3CookieIsolation(): Unit = runBlocking {
        var capturedStage3Cookie: String? = null
        val engine = createMockEngine(
            extraCookies = true,
            onStage3Request = { req ->
                capturedStage3Cookie = req.headers[HttpHeaders.Cookie]
            },
        )
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)
        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Success>(result)
        assertNotNull(capturedStage3Cookie)
        assertTrue(capturedStage3Cookie!!.contains("__Host-MSAAUTH=msa_session_cookie_token"))
        assertTrue(capturedStage3Cookie!!.contains("uaid=server_uaid_9999"))
        assertTrue(!capturedStage3Cookie!!.contains("OParams"))
        assertTrue(!capturedStage3Cookie!!.contains("PPState"))
    }

    @Test
    fun testStage1NetworkExceptionGracefulFailure(): Unit = runBlocking {
        val engine = MockEngine { _ ->
            throw RuntimeException("Max send count 20 exceeded. Consider increasing the property maxSendCount if more is required.")
        }
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)
        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.CREDENTIAL_DISCOVERY, result.stage)
        assertTrue(result.message.startsWith("Network timeout or Microsoft rate limit hit"))
    }

    @Test
    fun testStage3InterstitialDetection(): Unit = runBlocking {
        val engine = MockEngine { request ->
            val path = request.url.encodedPath
            when {
                path == "/login.srf" && request.url.parameters.contains("wreply") -> {
                    respond(
                        content = "<html><head><title>Verify your identity</title></head><body><h1>Protect your account</h1><p>Please verify your identity.</p></body></html>",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }
                path == "/login.srf" -> {
                    respond(
                        content = "<html><script>var ServerData = {\"sFTAg\":\"<input type=\\\"hidden\\\" name=\\\"PPFT\\\" id=\\\"i0327\\\" value=\\\"MOCK_PPFT_123\\\"/>\",\"canary\":\"\"};</script></html>",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }
                path == "/GetCredentialType.srf" -> {
                    respond(
                        content = "{\"IfExistsResult\": 0, \"Credentials\": {\"HasPassword\": 1, \"OtcLoginEligibleProofs\": [{\"data\":\"proof_data_xyz\",\"display\":\"user@example.com\",\"type\":1}]}}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
                path == "/GetOneTimeCode.srf" -> {
                    respond(
                        content = "{\"State\": 204, \"FlowToken\": \"MOCK_NEW_PPFT_456\"}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
                path == "/ppsecure/post.srf" -> {
                    respond(
                        content = "<html>Redirecting...</html>",
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("text/html"),
                            HttpHeaders.SetCookie to listOf("__Host-MSAAUTH=msa_session_cookie_token; Domain=login.live.com; Path=/; Secure"),
                        ),
                    )
                }
                else -> error("Unhandled request path: $path")
            }
        }
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)
        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.SESSION_POLISH, result.stage)
        assertEquals("Microsoft requested additional identity verification (Captcha/2FA). Try again later or use a different IP.", result.message)
    }

    @Test
    fun testStage4SendsCleanHeadersAndStage3StopsAt302(): Unit = runBlocking {
        var stage4Cookie: String? = null
        var stage4XRequestedWith: String? = null
        var redirectTargetHit = false

        val engine = MockEngine { request ->
            val path = request.url.encodedPath
            when {
                path == "/login.srf" && request.url.parameters.contains("wreply") -> {
                    respond(
                        content = "<html><form><input type=\"hidden\" name=\"t\" value=\"TOKEN_T\"/></form></html>",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }
                path == "/login.srf" -> {
                    respond(
                        content = "<html><script>var ServerData = {\"sFTAg\":\"<input type=\\\"hidden\\\" name=\\\"PPFT\\\" value=\\\"MOCK_PPFT\\\"/>\"};</script></html>",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }
                path == "/GetCredentialType.srf" -> {
                    respond(
                        content = "{\"IfExistsResult\": 0, \"Credentials\": {\"OtcLoginEligibleProofs\": [{\"data\":\"proof1\",\"type\":1}]}}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
                path == "/GetOneTimeCode.srf" -> {
                    respond(
                        content = "{\"State\": 201, \"FlowToken\": \"PPFT_2\"}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
                path == "/ppsecure/post.srf" -> {
                    respond(
                        content = "<html>OK</html>",
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("text/html"),
                            HttpHeaders.SetCookie to listOf("__Host-MSAAUTH=msa_tok; Domain=login.live.com; Path=/; Secure"),
                        ),
                    )
                }
                path == "/proofs/Add" -> {
                    respond(
                        content = "",
                        status = HttpStatusCode.Found,
                        headers = headersOf(
                            HttpHeaders.Location to listOf("https://account.live.com/should_not_follow"),
                            HttpHeaders.SetCookie to listOf(
                                "AMRPSSecAuth=amrp_tok; path=/; domain=account.live.com",
                                "amsc=amsc_tok; path=/; domain=account.live.com",
                            ),
                        ),
                    )
                }
                path == "/should_not_follow" -> {
                    redirectTargetHit = true
                    respond("<html>Should not follow 302 from POST /proofs/Add</html>", HttpStatusCode.OK)
                }
                path == "/proofs/manage/additional" -> {
                    stage4Cookie = request.headers[HttpHeaders.Cookie]
                    stage4XRequestedWith = request.headers["X-Requested-With"]
                    respond("<html><head><title>No Keys</title></head><body>Empty</body></html>", HttpStatusCode.OK)
                }
                else -> error("Unhandled request path: $path")
            }
        }

        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)
        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newPassword = "Pass",
            newEmail = "admin@outlook.com",
        )

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.PROOFS_ENUMERATION, result.stage)
        assertTrue(!redirectTargetHit)
        assertEquals(null, stage4XRequestedWith)
        assertNotNull(stage4Cookie)
        assertTrue(stage4Cookie!!.contains("AMRPSSecAuth=amrp_tok"))
        assertTrue(stage4Cookie!!.contains("amsc=amsc_tok"))
        assertTrue(!stage4Cookie!!.contains("__Host-MSAAUTH"))
    }

    @Test
    fun testStopsAtStage7ByDefaultAndMarksSuccess(): Unit = runBlocking {
        val tempDb = File.createTempFile("test_stage7_stop_", ".db")
        val dbManager = DatabaseManager(tempDb.absolutePath)
        val repository = SqliteAccountRepository(dbManager)
        var stage8Or9Hit = false
        val stagesLogged = mutableListOf<String>()

        val baseEngine = createMockEngine()
        val spyEngine = MockEngine { request ->
            val path = request.url.encodedPath
            if (path == "/AddAssocId" ||
                path == "/API/MakePrimary" ||
                path == "/names/manage" ||
                path == "/API/Proofs/DisableTfa" ||
                path == "/API/Proofs/DeleteDevices" ||
                path == "/API/Proofs/DeleteAppPassword" ||
                path == "/API/Proofs/RemovePasskey"
            ) {
                stage8Or9Hit = true
                error("Stage 8/9 endpoint should not be called when stopping at Stage 7: $path")
            }
            baseEngine.config.requestHandlers.first()(this, request)
        }

        val service = RecoveryService(
            clientEngine = spyEngine,
            stageDelayMs = 0L,
            accountRepository = repository,
        )

        val result = service.runLifecycle(
            email = "victim@example.com",
            otpProvider = { "123456" },
            newEmail = "ignored_alias@outlook.com",
            stageListener = { stageKey, _, isSuccess, _ ->
                stagesLogged.add("$stageKey:$isSuccess")
            },
        )

        assertIs<RecoveryResult.Success>(result)
        assertTrue(!stage8Or9Hit)
        assertEquals("victim@example.com", result.originalEmail)
        assertEquals("victim@example.com", result.newPrimaryEmail)
        assertEquals("FINAL-RECOV-44444-55555-66666", result.finalRecoveryCode)
        assertEquals(2, result.suppressedProofsCount)
        assertTrue(stagesLogged.contains("7:true"))
        assertTrue(stagesLogged.none { it.startsWith("8:") || it.startsWith("9:") })

        val saved = repository.getAccountByOriginalEmail("victim@example.com")
        assertNotNull(saved)
        assertEquals(RecoveredAccount.STATUS_SUCCESS, saved.status)
        assertEquals("victim@example.com", saved.currentPrimaryEmail)
        assertEquals("FINAL-RECOV-44444-55555-66666", saved.recoveryCode)

        dbManager.close()
        tempDb.delete()
    }

    @Test
    fun testRecoverUserErrorWithHttp200MarksFailedInDatabase(): Unit = runBlocking {
        val tempDb = File.createTempFile("test_recover_err_", ".db")
        val dbManager = DatabaseManager(tempDb.absolutePath)
        val repository = SqliteAccountRepository(dbManager)
        repository.saveAccount(RecoveredAccount(originalEmail = "victim@example.com", status = RecoveredAccount.STATUS_PENDING))

        val baseEngine = createMockEngine()
        val engine = MockEngine { request ->
            if (request.url.encodedPath == "/API/Recovery/RecoverUser") {
                respond(
                    content = """{"recoveryCode":"SOME-CODE","error":{"code":"1218","message":"Password matches previous"}}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
            } else {
                baseEngine.config.requestHandlers.first()(this, request)
            }
        }

        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L, accountRepository = repository)
        val result = service.runLifecycle(email = "victim@example.com", otpProvider = { "123456" })

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.PASSWORD_ROTATION, result.stage)
        assertEquals("1218", result.errorCode)

        val saved = repository.getAccountByOriginalEmail("victim@example.com")
        assertNotNull(saved)
        assertEquals(RecoveredAccount.STATUS_FAILED, saved.status)
        assertNotNull(saved.failReason)

        dbManager.close()
        tempDb.delete()
    }

    @Test
    fun testRecoverUserUnchangedRecoveryCodeMarksFailedInDatabase(): Unit = runBlocking {
        val tempDb = File.createTempFile("test_recover_same_code_", ".db")
        val dbManager = DatabaseManager(tempDb.absolutePath)
        val repository = SqliteAccountRepository(dbManager)
        repository.saveAccount(RecoveredAccount(originalEmail = "victim@example.com", status = RecoveredAccount.STATUS_PENDING))

        val baseEngine = createMockEngine()
        val engine = MockEngine { request ->
            if (request.url.encodedPath == "/API/Recovery/RecoverUser") {
                respond(
                    content = """{"recoveryCode":"INITIAL-RECOV-11111-22222-33333","enableTfa":false}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
            } else {
                baseEngine.config.requestHandlers.first()(this, request)
            }
        }

        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L, accountRepository = repository)
        val result = service.runLifecycle(email = "victim@example.com", otpProvider = { "123456" })

        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.PASSWORD_ROTATION, result.stage)

        val saved = repository.getAccountByOriginalEmail("victim@example.com")
        assertNotNull(saved)
        assertEquals(RecoveredAccount.STATUS_FAILED, saved.status)

        dbManager.close()
        tempDb.delete()
    }

    @Test
    fun testStage6PayloadAndExactPasswordSavedInDatabaseWithDerivedAlias(): Unit = runBlocking {
        val tempDb = File.createTempFile("test_stage6_payload_", ".db")
        val dbManager = DatabaseManager(tempDb.absolutePath)
        val repository = SqliteAccountRepository(dbManager)

        var capturedRecoverJson: String? = null
        var capturedAddAliasBody: String? = null
        val baseEngine = createMockEngine()
        val engine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/API/Recovery/RecoverUser" -> {
                    capturedRecoverJson = (request.body as? TextContent)?.text
                    respond(
                        content = """{"recoveryCode":"FINAL-RECOV-99999-88888-77777","enableTfa":true,"apiCanary":"can_after_recover"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
                "/AddAssocId" -> {
                    capturedAddAliasBody = (request.body as? io.ktor.client.request.forms.FormDataContent)?.formData?.get("AssociatedIdLive")
                    respond("<html>Added</html>", HttpStatusCode.OK)
                }
                "/get-otc" -> respond("""{"otc":"112233"}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
                "/Aliases/Verify" -> respond("<html>OK</html>", HttpStatusCode.OK)
                else -> baseEngine.config.requestHandlers.first()(this, request)
            }
        }

        val service = RecoveryService(
            clientEngine = engine,
            stageDelayMs = 0L,
            accountRepository = repository,
            aliasClient = AliasClient(sharedSecret = "secret", pollIntervalMs = 1L, timeoutMs = 500L),
            stopAfterStage7 = false,
        )
        val result = service.runLifecycle(email = "john.doe@gmail.com", otpProvider = { "123456" })

        assertIs<RecoveryResult.Success>(result)
        assertEquals("john.doe@qhuyy.tech", result.newPrimaryEmail)
        assertEquals("john.doe@qhuyy.tech", capturedAddAliasBody)

        assertNotNull(capturedRecoverJson)
        val recoverObj = MicrosoftHttpClientFactory.json.parseToJsonElement(capturedRecoverJson!!).jsonObject
        assertEquals("verification_grant_token_123", recoverObj["token"]?.jsonPrimitive?.content)
        assertEquals(result.password, recoverObj["password"]?.jsonPrimitive?.content)
        assertEquals("john.doe@gmail.com", recoverObj["contactEmail"]?.jsonPrimitive?.content)
        assertEquals("0", recoverObj["passwordExpiryEnabled"]?.jsonPrimitive?.content)

        val saved = repository.getAccountByOriginalEmail("john.doe@gmail.com")
        assertNotNull(saved)
        assertEquals(RecoveredAccount.STATUS_SUCCESS, saved.status)
        assertEquals(result.password, saved.password)

        dbManager.close()
        tempDb.delete()
    }
}
