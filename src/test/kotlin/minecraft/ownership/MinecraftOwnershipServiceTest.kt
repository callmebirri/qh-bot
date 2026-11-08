package minecraft.ownership

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import minecraft.ownership.model.MinecraftOwnershipResult
import minecraft.ownership.util.MinecraftHttpClientFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MinecraftOwnershipServiceTest {

    private fun createMockService(
        xboxAuthResponse: Pair<HttpStatusCode, String> = HttpStatusCode.OK to """
            {"Token":"test_xbox_token","DisplayClaims":{"xui":[{"uhs":"test_uhs_123"}]}}
        """.trimIndent(),
        xstsResponse: Pair<HttpStatusCode, String> = HttpStatusCode.OK to """
            {"Token":"test_xsts_token","DisplayClaims":{"xui":[{"uhs":"test_uhs_123"}]}}
        """.trimIndent(),
        minecraftLoginResponse: Pair<HttpStatusCode, String> = HttpStatusCode.OK to """
            {"username":"test_user","roles":[],"access_token":"mock_ssid_token","token_type":"Bearer","expires_in":86400}
        """.trimIndent(),
        entitlementsResponse: Pair<HttpStatusCode, String> = HttpStatusCode.OK to """
            {"items":[{"name":"product_minecraft","source":"PURCHASE"}],"signatures":["sig_abc_123"],"keyId":"rsa_key_1"}
        """.trimIndent(),
        profileResponse: Pair<HttpStatusCode, String> = HttpStatusCode.OK to """
            {"id":"c06f89064c3e4fdcbc41947ac7dcd123","name":"TestPlayer","skins":[{"id":"s1","state":"ACTIVE","url":"https://textures.minecraft.net/texture/1","variant":"CLASSIC"}],"capes":[]}
        """.trimIndent(),
    ): MinecraftOwnershipService {
        val mockEngine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/user/authenticate" -> respond(
                    content = xboxAuthResponse.second,
                    status = xboxAuthResponse.first,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/xsts/authorize" -> respond(
                    content = xstsResponse.second,
                    status = xstsResponse.first,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/authentication/login_with_xbox" -> respond(
                    content = minecraftLoginResponse.second,
                    status = minecraftLoginResponse.first,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/entitlements/license" -> respond(
                    content = entitlementsResponse.second,
                    status = entitlementsResponse.first,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                "/minecraft/profile" -> respond(
                    content = profileResponse.second,
                    status = profileResponse.first,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                else -> error("Unexpected request to ${request.url}")
            }
        }

        val client = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(MinecraftHttpClientFactory.json)
            }
        }

        return MinecraftOwnershipService(client)
    }

    @Test
    fun `happy path returns owned with profile and purchase source`() = runBlocking {
        val service = createMockService()
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.Owned>(result)
        assertEquals("TestPlayer", result.profile?.name)
        assertEquals("c06f89064c3e4fdcbc41947ac7dcd123", result.profile?.id)
        assertEquals("PURCHASE", result.source)
        assertFalse(result.hasGamePass)
        assertEquals(listOf("sig_abc_123"), result.signatures)
    }

    @Test
    fun `no license in entitlements returns NotOwned outcome`() = runBlocking {
        val service = createMockService(
            entitlementsResponse = HttpStatusCode.OK to """
                {"items":[],"signatures":[],"keyId":"rsa_key_1"}
            """.trimIndent(),
        )
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.NotOwned>(result)
        assertEquals("Account does not own a Minecraft license", result.reason)
    }

    @Test
    fun `no minecraft items returns NotOwned outcome`() = runBlocking {
        val service = createMockService(
            entitlementsResponse = HttpStatusCode.OK to """
                {"items":[{"name":"product_dungeons","source":"PURCHASE"}],"signatures":[]}
            """.trimIndent(),
        )
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.NotOwned>(result)
        assertEquals("Account does not own a Minecraft license", result.reason)
    }

    @Test
    fun `XSTS error returns Failure outcome with mapped message for no xbox profile`() = runBlocking {
        val service = createMockService(
            xstsResponse = HttpStatusCode.Unauthorized to """
                {"Identity":"0","XErr":2148916233,"Message":"Account has no Xbox profile","Redirect":"https://xbox.com"}
            """.trimIndent(),
        )
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.Failure>(result)
        assertEquals("Account has no Xbox profile", result.reason)
    }

    @Test
    fun `XSTS error returns Failure outcome for child account`() = runBlocking {
        val service = createMockService(
            xstsResponse = HttpStatusCode.Unauthorized to """
                {"Identity":"0","XErr":2148916238,"Message":"","Redirect":""}
            """.trimIndent(),
        )
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.Failure>(result)
        assertEquals("Child account, parental consent required", result.reason)
    }

    @Test
    fun `XSTS error returns Failure outcome for region ban`() = runBlocking {
        val service = createMockService(
            xstsResponse = HttpStatusCode.Unauthorized to """
                {"Identity":"0","XErr":2148916235,"Message":""}
            """.trimIndent(),
        )
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.Failure>(result)
        assertEquals("Account banned in this region", result.reason)
    }

    @Test
    fun `XSTS unknown code includes raw code in reason`() = runBlocking {
        val service = createMockService(
            xstsResponse = HttpStatusCode.BadRequest to """
                {"Identity":"0","XErr":2148916236,"Message":"Unknown security issue"}
            """.trimIndent(),
        )
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.Failure>(result)
        assertTrue(result.reason.contains("2148916236"))
    }

    @Test
    fun `game pass source sets hasGamePass flag to true`() = runBlocking {
        val service = createMockService(
            entitlementsResponse = HttpStatusCode.OK to """
                {"items":[{"name":"game_minecraft","source":"GAMEPASS"}],"signatures":["sig_gp"]}
            """.trimIndent(),
        )
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.Owned>(result)
        assertEquals("GAMEPASS", result.source)
        assertTrue(result.hasGamePass)
    }

    @Test
    fun `profile not found 404 returns Owned with null profile`() = runBlocking {
        val service = createMockService(
            profileResponse = HttpStatusCode.NotFound to """
                {"path":"/minecraft/profile","errorType":"NOT_FOUND","errorMessage":"The server has not found anything matching the request URI"}
            """.trimIndent(),
        )
        val result = service.checkOwnership("valid_ms_token")

        assertIs<MinecraftOwnershipResult.Owned>(result)
        assertNull(result.profile)
        assertEquals("PURCHASE", result.source)
    }

    @Test
    fun `blank token returns Failure`() = runBlocking {
        val service = createMockService()
        val result = service.checkOwnership("   ")

        assertIs<MinecraftOwnershipResult.Failure>(result)
        assertEquals("Microsoft access token is blank", result.reason)
    }
}
