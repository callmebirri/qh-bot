package microsoft.recovery

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
}
