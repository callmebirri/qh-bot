package microsoft.recovery

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import microsoft.recovery.RecoveryWorkflow
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.ConfirmProofVerificationRequest
import microsoft.recovery.model.DetailedProofsInventory
import microsoft.recovery.model.EnumerateProofItem
import microsoft.recovery.model.PasskeyRemovalRequest
import microsoft.recovery.model.ProofItem
import microsoft.recovery.model.ProofRemovalRequest
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.RecoveryStage
import microsoft.recovery.model.SendOttVerificationRequest
import microsoft.recovery.model.StandardProofActionRequest
import microsoft.recovery.model.StageExecution
import microsoft.recovery.stages.EnhancedStage9Cleanup
import microsoft.recovery.stages.RecoveryStageHandler
import microsoft.recovery.stages.StageListener
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.ProofExtractorExtensions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertIs

class ProofExtractorExtensionsTest {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    @Test
    fun testPasskeyRemovalRequestSerialization(): Unit {
        val request = PasskeyRemovalRequest(
            credentialId = "test-credential-guid-1234",
            uaid = "uaid-value-abc",
        )
        val serialized = json.encodeToString(request)
        val obj = json.parseToJsonElement(serialized).jsonObject

        assertTrue(serialized.contains(""""credentialId":""""))
        assertFalse(serialized.contains(""""passKeyId":""""))
        assertEquals("test-credential-guid-1234", obj["credentialId"]?.toString()?.replace("\"", ""))
        assertEquals("uaid-value-abc", obj["uaid"]?.toString()?.replace("\"", ""))
        assertEquals("1001", obj["uiflvr"]?.toString())
        assertEquals("100109", obj["scid"]?.toString())
        assertEquals("201030", obj["hpgid"]?.toString())
    }

    @Test
    fun testProofRemovalRequestSerialization(): Unit {
        val request = ProofRemovalRequest(
            proofId = "proof-guid-999",
            uaid = "uaid-value-xyz",
        )
        val serialized = json.encodeToString(request)
        val obj = json.parseToJsonElement(serialized).jsonObject

        assertTrue(serialized.contains(""""proofId":""""))
        assertEquals("proof-guid-999", obj["proofId"]?.toString()?.replace("\"", ""))
        assertEquals("uaid-value-xyz", obj["uaid"]?.toString()?.replace("\"", ""))
    }

    @Test
    fun testStandardProofActionRequestSerialization(): Unit {
        val request = StandardProofActionRequest(
            uaid = "uaid-standard-456",
        )
        val serialized = json.encodeToString(request)
        val obj = json.parseToJsonElement(serialized).jsonObject

        assertEquals("uaid-standard-456", obj["uaid"]?.toString()?.replace("\"", ""))
        assertEquals("1001", obj["uiflvr"]?.toString())
        assertEquals("100109", obj["scid"]?.toString())
        assertEquals("201030", obj["hpgid"]?.toString())
    }

    @Test
    fun testSendOttVerificationRequestSerialization(): Unit {
        val request = SendOttVerificationRequest(
            actionSpecificNetId = "net-id-123",
            destination = "user@qhuyy.tech",
            proofId = "proof-id-555",
            channel = "Email",
            uaid = "uaid-ott-789",
        )
        val serialized = json.encodeToString(request)
        val obj = json.parseToJsonElement(serialized).jsonObject

        assertEquals("net-id-123", obj["actionSpecificNetId"]?.toString()?.replace("\"", ""))
        assertEquals("user@qhuyy.tech", obj["destination"]?.toString()?.replace("\"", ""))
        assertEquals("proof-id-555", obj["proofId"]?.toString()?.replace("\"", ""))
        assertEquals("Email", obj["channel"]?.toString()?.replace("\"", ""))
        assertEquals("VerifyProof", obj["action"]?.toString()?.replace("\"", ""))
        assertEquals("uaid-ott-789", obj["uaid"]?.toString()?.replace("\"", ""))
    }

    @Test
    fun testConfirmProofVerificationRequestSerialization(): Unit {
        val request = ConfirmProofVerificationRequest(
            proofId = "proof-id-666",
            code = "849201",
            uaid = "uaid-confirm-111",
        )
        val serialized = json.encodeToString(request)
        val obj = json.parseToJsonElement(serialized).jsonObject

        assertEquals("proof-id-666", obj["proofId"]?.toString()?.replace("\"", ""))
        assertEquals("849201", obj["code"]?.toString()?.replace("\"", ""))
        assertEquals("uaid-confirm-111", obj["uaid"]?.toString()?.replace("\"", ""))
    }

    @Test
    fun testEnumerateProofItemConversion(): Unit {
        val enumItem = EnumerateProofItem(
            proofId = "guid-123",
            name = "my\\u0040email.com",
            type = "Email",
            isVerified = true,
            encryptedProofId = "enc-456",
        )
        val proofItem = enumItem.toProofItem()

        assertEquals("guid-123", proofItem.proofId)
        assertEquals("my\\u0040email.com", proofItem.name)
        assertEquals("Email", proofItem.type)
    }

    @Test
    fun testDetailedProofsInventoryCreation(): Unit {
        val inventory = DetailedProofsInventory(
            encryptedNetId = "net-123",
            apiCanary = "canary-456",
            emailProofs = listOf(ProofItem("p1", "test@domain.com", "Email")),
            smsProofs = listOf(ProofItem("p2", "+123456789", "SMS")),
            passKeyIds = listOf("key-1", "key-2"),
            hasAppPassword = false,
        )

        assertEquals("net-123", inventory.encryptedNetId)
        assertEquals("canary-456", inventory.apiCanary)
        assertEquals(1, inventory.emailProofs.size)
        assertEquals(1, inventory.smsProofs.size)
        assertEquals(2, inventory.passKeyIds.size)
        assertFalse(inventory.hasAppPassword)
    }

    @Test
    fun testExtractPasskeyCredentialIdsPrioritizesProofIdAndFallbacks(): Unit {
        val jsonPayload = """
            [
                {"proofId": "cred-from-proof-id", "passKeyId": "ignored-id"},
                {"credentialId": "cred-from-credential-id"},
                {"passKeyId": "cred-from-passkey-id"},
                {"id": "cred-from-id"},
                "direct-primitive-cred",
                {"proofId": "unicode-\u0031\u0032\u0033"},
                {"other": "missing-id"},
                ""
            ]
        """.trimIndent()

        val jsonArray = json.parseToJsonElement(jsonPayload).jsonArray
        val result = ProofExtractorExtensions.extractPasskeyCredentialIds(jsonArray)

        assertEquals(
            listOf(
                "cred-from-proof-id",
                "cred-from-credential-id",
                "cred-from-passkey-id",
                "cred-from-id",
                "direct-primitive-cred",
                "unicode-123",
            ),
            result,
        )
    }

    @Test
    fun testExtractPasskeyCredentialIdsHandlesNullAndEmpty(): Unit {
        val emptyResult = ProofExtractorExtensions.extractPasskeyCredentialIds(null)
        assertTrue(emptyResult.isEmpty())
    }

    @Test
    fun testParseDetailedProofItemsAndFallbacks(): Unit {
        val jsonPayload = """
            [
                {
                    "proofId": "p-1",
                    "displayProofName": "user\u0040test.com",
                    "isVerified": 1,
                    "encryptedProofId": "enc-1"
                },
                {
                    "id": "p-2",
                    "display": "+15551234",
                    "isVerified": 0
                },
                {
                    "name": "legacy\u0040test.com"
                },
                "direct-string-proof"
            ]
        """.trimIndent()

        val jsonArray = json.parseToJsonElement(jsonPayload).jsonArray
        val detailed = ProofExtractorExtensions.parseDetailedProofItems(jsonArray, "Email")

        assertEquals(4, detailed.size)

        assertEquals("p-1", detailed[0].proofId)
        assertEquals("user@test.com", detailed[0].name)
        assertTrue(detailed[0].isVerified)
        assertEquals("enc-1", detailed[0].encryptedProofId)

        assertEquals("p-2", detailed[1].proofId)
        assertEquals("+15551234", detailed[1].name)
        assertFalse(detailed[1].isVerified)

        assertEquals("legacy@test.com", detailed[2].proofId)
        assertEquals("legacy@test.com", detailed[2].name)
        assertTrue(detailed[2].isVerified)

        assertEquals("direct-string-proof", detailed[3].proofId)
        assertEquals("direct-string-proof", detailed[3].name)

        val proofs = ProofExtractorExtensions.parseProofItems(jsonArray, "Email")
        assertEquals(4, proofs.size)
        assertEquals("p-1", proofs[0].proofId)
        assertEquals("legacy@test.com", proofs[2].proofId)
    }

    @Test
    fun testEnhancedStage9CleanupExecutionSequenceAndProofPurging(): Unit = runBlocking {
        val requestedPaths = mutableListOf<String>()
        val requestedBodies = mutableListOf<String>()
        val storage = AcceptAllCookiesStorage()

        val mockEngine = MockEngine { request ->
            val path = request.url.encodedPath
            requestedPaths.add(path)
            val body = (request.body as? TextContent)?.text.orEmpty()
            requestedBodies.add(body)

            when (path) {
                "/API/Proofs/DisableTfa",
                "/API/Proofs/RevokeWindowsHelloProofs",
                "/API/Proofs/DeleteAppPassword",
                "/API/Proofs/RemovePasskey",
                "/API/Proofs/DeleteProof",
                "/API/Proofs/DeleteDevices" -> respond(
                    content = """{"apiCanary": "rotated_canary_${requestedPaths.size}"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val client = MicrosoftHttpClientFactory.create(storage = storage, engine = mockEngine)
        val context = RecoveryContext(
            email = "victim@example.com",
            newPassword = "NewPassword123!",
            newEmail = "admin@qhuyy.tech",
            uaid = "test-uaid-999",
            activeCanary = "initial-canary",
            passKeyIds = listOf("cred-alpha", "cred-beta"),
            emailProofs = listOf(
                ProofItem(proofId = "p-victim-email", name = "victim@gmail.com", type = "Email"),
                ProofItem(proofId = "p-safe-email", name = "admin@qhuyy.tech", type = "Email"),
            ),
            smsProofs = listOf(
                ProofItem(proofId = "p-victim-sms", name = "+1999888777", type = "SMS"),
            ),
            httpClient = client,
            cookieStorage = storage,
        )

        val stage9 = EnhancedStage9Cleanup(stageDelayMs = 0L)
        val result = stage9.execute(context, null)

        assertIs<StageExecution.Success<Unit>>(result)

        assertEquals("/API/Proofs/DisableTfa", requestedPaths[0])
        assertEquals("/API/Proofs/RevokeWindowsHelloProofs", requestedPaths[1])
        assertEquals("/API/Proofs/DeleteAppPassword", requestedPaths[2])
        assertEquals("/API/Proofs/RemovePasskey", requestedPaths[3])
        assertEquals("/API/Proofs/RemovePasskey", requestedPaths[4])
        assertEquals("/API/Proofs/DeleteProof", requestedPaths[5])
        assertEquals("/API/Proofs/DeleteProof", requestedPaths[6])
        assertEquals("/API/Proofs/DeleteDevices", requestedPaths[7])

        assertTrue(requestedBodies[3].contains(""""credentialId":"cred-alpha""""))
        assertTrue(requestedBodies[4].contains(""""credentialId":"cred-beta""""))
        assertTrue(requestedBodies[5].contains(""""proofId":"p-victim-email""""))
        assertTrue(requestedBodies[6].contains(""""proofId":"p-victim-sms""""))

        assertFalse(requestedBodies.any { it.contains("p-safe-email") })
        assertEquals("rotated_canary_8", context.activeCanary)
    }

    @Test
    fun testEnhancedStage9CleanupFailClosedOnApiError(): Unit = runBlocking {
        val storage = AcceptAllCookiesStorage()
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/API/Proofs/DisableTfa" -> respond(
                    content = """{"error": 1282, "apiCanary": "err_canary"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                else -> respond(
                    content = """{"apiCanary": "ok_canary"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
            }
        }

        val client = MicrosoftHttpClientFactory.create(storage = storage, engine = mockEngine)
        val context = RecoveryContext(
            email = "victim@example.com",
            newPassword = "NewPassword123!",
            newEmail = "admin@qhuyy.tech",
            uaid = "test-uaid-999",
            activeCanary = "initial-canary",
            httpClient = client,
            cookieStorage = storage,
        )

        val stage9 = EnhancedStage9Cleanup(stageDelayMs = 0L, maxRetries = 2)
        val result = stage9.execute(context, null)

        assertIs<StageExecution.Failure>(result)
    }

    @Test
    fun testWorkflowExecutesStage9WhenStage8Fails(): Unit = runBlocking {
        var stage9Executed = false
        val successStage = object : RecoveryStageHandler {
            override suspend fun execute(context: RecoveryContext, stageListener: StageListener?): StageExecution<Unit> =
                StageExecution.Success(Unit)
        }
        val failingStage8 = object : RecoveryStageHandler {
            override suspend fun execute(context: RecoveryContext, stageListener: StageListener?): StageExecution<Unit> =
                StageExecution.Failure(RecoveryResult.Failure(RecoveryStage.ALIAS_ROTATION, "Alias rotation failed"))
        }
        val recordingStage9 = object : RecoveryStageHandler {
            override suspend fun execute(context: RecoveryContext, stageListener: StageListener?): StageExecution<Unit> {
                stage9Executed = true
                return StageExecution.Success(Unit)
            }
        }

        val workflow = RecoveryWorkflow(
            stage1 = successStage,
            stage2 = successStage,
            stage3 = successStage,
            stage4 = successStage,
            stage5 = successStage,
            stage6 = successStage,
            stage7 = successStage,
            stage8 = failingStage8,
            stage9 = recordingStage9,
            stageDelayMs = 0L,
        )

        val storage = AcceptAllCookiesStorage()
        val client = MicrosoftHttpClientFactory.create(storage = storage, engine = MockEngine { respond("OK") })
        val context = RecoveryContext(
            email = "victim@example.com",
            newPassword = "NewPassword123!",
            newEmail = "admin@qhuyy.tech",
            uaid = "test-uaid-999",
            httpClient = client,
            cookieStorage = storage,
        )

        val result = workflow.execute(context)

        assertTrue(stage9Executed)
        assertIs<RecoveryResult.Failure>(result)
        assertEquals(RecoveryStage.ALIAS_ROTATION, result.stage)
        assertEquals("Alias rotation failed", result.message)
    }
}
