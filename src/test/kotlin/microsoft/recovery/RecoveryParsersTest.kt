package microsoft.recovery

import kotlinx.serialization.encodeToString
import microsoft.recovery.model.SecurityCleanupRequest
import microsoft.recovery.util.MicrosoftHttpClientFactory
import microsoft.recovery.util.RecoveryParsers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RecoveryParsersTest {

    @Test
    fun testGenerateUaid() {
        val uaid = RecoveryParsers.generateUaid()
        assertEquals(32, uaid.length)
        assertTrue(uaid.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun testGenerateRandomPassword() {
        val password = RecoveryParsers.generateRandomPassword(14)
        assertEquals(14, password.length)
        assertTrue(password.any { it.isUpperCase() })
        assertTrue(password.any { it.isLowerCase() })
        assertTrue(password.any { it.isDigit() })
        assertTrue(password.any { it in "!@#$%^&*" })

        for (len in 12..16) {
            val pass = RecoveryParsers.generateRandomPassword(len)
            assertEquals(len, pass.length)
            assertTrue(pass.any { it.isUpperCase() })
            assertTrue(pass.any { it.isLowerCase() })
            assertTrue(pass.any { it.isDigit() })
            assertTrue(pass.any { it in "!@#$%^&*" })
        }
    }

    @Test
    fun testUnescapeUnicode() {
        val input = "foo\\u002bbar\\u003abaz"
        val output = RecoveryParsers.unescapeUnicode(input)
        assertEquals("foo+bar:baz", output)
    }

    @Test
    fun testExtractPpftFromEmbeddedJson() {
        val html = """
            <html>
            <script>
            var ServerData = {"sFTAg":"<input type=\"hidden\" name=\"PPFT\" id=\"i0327\" value=\"DUMMY_PPFT_12345\"/>","canary":""};
            </script>
            </html>
        """.trimIndent()

        val ppft = RecoveryParsers.extractPpft(html, MicrosoftHttpClientFactory.json)
        assertEquals("DUMMY_PPFT_12345", ppft)
    }

    @Test
    fun testExtractPpftFromDirectRegex() {
        val html = """
            <html>
            <input type="hidden" name="PPFT" value="FALLBACK_PPFT_67890"/>
            </html>
        """.trimIndent()

        val ppft = RecoveryParsers.extractPpft(html, MicrosoftHttpClientFactory.json)
        assertEquals("FALLBACK_PPFT_67890", ppft)
    }

    @Test
    fun testExtractTokenT() {
        val html = """
            <html>
            <body>
            <form>
            <input type="hidden" name="t" value="TOKEN_T_SAMPLE_VALUE_1024"/>
            </form>
            </body>
            </html>
        """.trimIndent()

        val tokenT = RecoveryParsers.extractTokenT(html)
        assertEquals("TOKEN_T_SAMPLE_VALUE_1024", tokenT)
    }

    @Test
    fun testExtractManageProofsDataWithUnicodeEscapes() {
        val html = """
            <html>
            <script>
            var t0 = {
                "WLXAccount": {
                    "manageProofs": {
                        "encryptedNetId": "netId\\u002b123\\u003d",
                        "apiCanary": "canary\\u002b456\\u003d",
                        "emailProofs": [
                            {"name": "user\\u0040example.com"}
                        ],
                        "smsProofs": [
                            {"display": "+1234567890"}
                        ],
                        "passKeys": [
                            {"passKeyId": "passkey-uuid-1"}
                        ]
                    }
                }
            };
            </script>
            </html>
        """.trimIndent()

        val data = RecoveryParsers.extractManageProofsData(html, MicrosoftHttpClientFactory.json)
        assertNotNull(data)
        assertEquals("netId+123=", data.encryptedNetId)
        assertEquals("canary+456=", data.apiCanary)
        assertEquals(1, data.emailProofs.size)
        assertEquals("user@example.com", data.emailProofs[0].name)
        assertEquals("Email", data.emailProofs[0].type)
        assertEquals(1, data.smsProofs.size)
        assertEquals("+1234567890", data.smsProofs[0].name)
        assertEquals("SMS", data.smsProofs[0].type)
        assertEquals(listOf("passkey-uuid-1"), data.passKeyIds)
    }

    @Test
    fun testExtractResetPasswordData() {
        val html = """
            <html>
            <script>
            var ServerData = {
                "sRecoveryToken": "recovery_token_val\\u002babc",
                "apiCanary": "reset_canary_val\\u002bdef"
            };
            </script>
            </html>
        """.trimIndent()

        val data = RecoveryParsers.extractResetPasswordData(html, MicrosoftHttpClientFactory.json)
        assertNotNull(data)
        assertEquals("recovery_token_val+abc", data.sRecoveryToken)
        assertEquals("reset_canary_val+def", data.apiCanary)
    }

    @Test
    fun testExtractResetPasswordDataDecodesHexAndUnicodeFallbacks() {
        val html = """
            <html>
            <script>
            var ServerData = { badJs: foo(), "sRecoveryToken": "tok\x2bpart\u002f1\x3d", "apiCanary": "can\x2b2\u003d" };
            </script>
            </html>
        """.trimIndent()

        val data = RecoveryParsers.extractResetPasswordData(html, MicrosoftHttpClientFactory.json)
        assertNotNull(data)
        assertEquals("tok+part/1=", data.sRecoveryToken)
        assertEquals("can+2=", data.apiCanary)
    }

    @Test
    fun testExtractManageProofsDataFlexibleFormatsAndServerDataFallback() {
        val html = """
            <html>
            <script>
            var t0={"WLXAccount":{"manageProofs":{"encryptedNetId":"net\u002fid\u002b1\u003d","emailProofs":[{"name":"a@b.com"}],"smsProofs":[],"passKeys":[]}}},"created":new Date()};
            var ServerData = {"apiCanary": "server\u002bcanary\/ok\u003d"};
            </script>
            </html>
        """.trimIndent()

        val data = RecoveryParsers.extractManageProofsData(html, MicrosoftHttpClientFactory.json)
        assertNotNull(data)
        assertEquals("net/id+1=", data.encryptedNetId)
        assertEquals("server+canary/ok=", data.apiCanary)
        assertEquals(1, data.emailProofs.size)
        assertEquals("a@b.com", data.emailProofs[0].name)
    }

    @Test
    fun testExtractManageProofsDataWithRegexEscapedAndSpacedValues() {
        val html = """
            <html>
            <script>
            var t0 = { badJs: foo(), "encryptedNetId" : "enc\u002bval\u003d", "apiCanary" : "can\u002bval\/2\u003d", "emailProofs": [{"display": "user@test.com"}] };
            </script>
            </html>
        """.trimIndent()

        val data = RecoveryParsers.extractManageProofsData(html, MicrosoftHttpClientFactory.json)
        assertNotNull(data)
        assertEquals("enc+val=", data.encryptedNetId)
        assertEquals("can+val/2=", data.apiCanary)
        assertEquals(1, data.emailProofs.size)
        assertEquals("user@test.com", data.emailProofs[0].name)
    }

    @Test
    fun testSanitizePassword() {
        assertEquals("SafePass123!@#", RecoveryParsers.sanitizePassword("""Safe"Pass\ 123'!@#"""))
        val generated = RecoveryParsers.generateRandomPassword(14)
        assertEquals(generated, RecoveryParsers.sanitizePassword(generated))
    }

    @Test
    fun testSecurityCleanupRequestExcludesNullPassKeyId() {
        val requestWithoutPasskey = SecurityCleanupRequest(
            passKeyId = null,
            uaid = "test-uaid-1234567890abcdef12345678",
        )
        val json = MicrosoftHttpClientFactory.json.encodeToString(requestWithoutPasskey)
        assertTrue(!json.contains("passKeyId"), "JSON must not contain passKeyId when null: $json")
        assertTrue(json.contains("\"uiflvr\":1001"))
        assertTrue(json.contains("\"uaid\":\"test-uaid-1234567890abcdef12345678\""))
        assertTrue(json.contains("\"scid\":100109"))
        assertTrue(json.contains("\"hpgid\":201030"))

        val requestWithPasskey = SecurityCleanupRequest(
            passKeyId = "passkey-uuid-999",
            uaid = "test-uaid-1234567890abcdef12345678",
        )
        val jsonWithPasskey = MicrosoftHttpClientFactory.json.encodeToString(requestWithPasskey)
        assertTrue(jsonWithPasskey.contains("\"passKeyId\":\"passkey-uuid-999\""))
    }
}
