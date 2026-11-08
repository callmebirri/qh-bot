package minecraft.ownership

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import minecraft.ownership.model.MinecraftEntitlementsResponse
import minecraft.ownership.model.MinecraftLoginRequest
import minecraft.ownership.model.MinecraftLoginResponse
import minecraft.ownership.model.MinecraftOwnershipResult
import minecraft.ownership.model.MinecraftProfile
import minecraft.ownership.model.XboxAuthResponse
import minecraft.ownership.model.XboxUserAuthProperties
import minecraft.ownership.model.XboxUserAuthRequest
import minecraft.ownership.model.XstsAuthProperties
import minecraft.ownership.model.XstsAuthRequest
import minecraft.ownership.model.XstsErrorResponse
import minecraft.ownership.util.MinecraftHttpClientFactory
import minecraft.ownership.util.XstsErrorMapper
import org.slf4j.LoggerFactory
import java.util.UUID

class MinecraftOwnershipService(
    private val client: HttpClient = MinecraftHttpClientFactory.create(),
) : AutoCloseable {

    private val logger = LoggerFactory.getLogger(MinecraftOwnershipService::class.java)

    /**
     * Checks if the account associated with the provided Microsoft OAuth access token owns Minecraft.
     *
     * Requires a Microsoft OAuth access token with the `XboxLive.signin` scope.
     *
     * @param microsoftAccessToken Microsoft OAuth access token with XboxLive.signin scope.
     * @return [MinecraftOwnershipResult] indicating [MinecraftOwnershipResult.Owned], [MinecraftOwnershipResult.NotOwned], or [MinecraftOwnershipResult.Failure].
     */
    suspend fun checkOwnership(microsoftAccessToken: String): MinecraftOwnershipResult {
        if (microsoftAccessToken.isBlank()) {
            logger.debug("Verification rejected: Microsoft access token is blank")
            return MinecraftOwnershipResult.Failure("Microsoft access token is blank")
        }

        return try {
            performOwnershipCheck(microsoftAccessToken)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.debug("Verification failed with exception: {}", e.message)
            MinecraftOwnershipResult.Failure("Ownership verification failed: ${e.message}", cause = e)
        }
    }

    private suspend fun performOwnershipCheck(microsoftAccessToken: String): MinecraftOwnershipResult {
        logger.debug("Step 1: Authenticating with Xbox Live (RPS ticket exchange)...")
        val rpsTicket = if (microsoftAccessToken.startsWith("d=")) {
            microsoftAccessToken
        } else {
            "d=$microsoftAccessToken"
        }

        val xboxAuthResponse = client.post("https://user.auth.xboxlive.com/user/authenticate") {
            contentType(ContentType.Application.Json)
            setBody(XboxUserAuthRequest(properties = XboxUserAuthProperties(rpsTicket = rpsTicket)))
        }

        if (!xboxAuthResponse.status.isSuccess()) {
            val errorBody = xboxAuthResponse.bodyAsText()
            logger.debug("Step 1 failed (HTTP {}): {}", xboxAuthResponse.status.value, errorBody)
            return MinecraftOwnershipResult.Failure("Xbox user authentication failed (HTTP ${xboxAuthResponse.status.value}): $errorBody")
        }

        val xboxAuth = xboxAuthResponse.body<XboxAuthResponse>()
        val xboxToken = xboxAuth.token
        val uhs = xboxAuth.displayClaims?.xui?.firstOrNull()?.uhs

        if (uhs.isNullOrBlank() || xboxToken.isBlank()) {
            logger.debug("Step 1 failed: Missing user hash (uhs) or token in Xbox response")
            return MinecraftOwnershipResult.Failure("Xbox user authentication returned invalid claims or token")
        }
        logger.debug("Step 1 OK: Xbox user authenticated (uhs={})", uhs)

        logger.debug("Step 2: Authorizing with XSTS for Minecraft RelyingParty...")
        val xstsResponse = client.post("https://xsts.auth.xboxlive.com/xsts/authorize") {
            contentType(ContentType.Application.Json)
            setBody(XstsAuthRequest(properties = XstsAuthProperties(userTokens = listOf(xboxToken))))
        }

        if (!xstsResponse.status.isSuccess()) {
            val errorBody = xstsResponse.bodyAsText()
            val parsedError = runCatching { MinecraftHttpClientFactory.json.decodeFromString<XstsErrorResponse>(errorBody) }.getOrNull()
            val reason = if (parsedError?.xErr != null) {
                XstsErrorMapper.mapErrorCode(parsedError.xErr, parsedError.message)
            } else {
                "XSTS authorization failed (HTTP ${xstsResponse.status.value}): $errorBody"
            }
            logger.debug("Step 2 failed (HTTP {}): {}", xstsResponse.status.value, reason)
            return MinecraftOwnershipResult.Failure(reason)
        }

        val xstsAuth = xstsResponse.body<XboxAuthResponse>()
        val xstsToken = xstsAuth.token
        val resolvedUhs = xstsAuth.displayClaims?.xui?.firstOrNull()?.uhs ?: uhs

        if (xstsToken.isBlank()) {
            logger.debug("Step 2 failed: Empty XSTS token")
            return MinecraftOwnershipResult.Failure("XSTS authorization returned empty token")
        }
        logger.debug("Step 2 OK: XSTS token acquired")

        logger.debug("Step 3: Authenticating with Minecraft services (login_with_xbox)...")
        val loginResponse = client.post("https://api.minecraftservices.com/authentication/login_with_xbox") {
            contentType(ContentType.Application.Json)
            setBody(MinecraftLoginRequest(identityToken = "XBL3.0 x=$resolvedUhs;$xstsToken"))
        }

        if (!loginResponse.status.isSuccess()) {
            val errorBody = loginResponse.bodyAsText()
            logger.debug("Step 3 failed (HTTP {}): {}", loginResponse.status.value, errorBody)
            return MinecraftOwnershipResult.Failure("Minecraft Xbox login failed (HTTP ${loginResponse.status.value}): $errorBody")
        }

        val minecraftLogin = loginResponse.body<MinecraftLoginResponse>()
        val ssid = minecraftLogin.accessToken

        if (ssid.isBlank()) {
            logger.debug("Step 3 failed: Empty Minecraft SSID token")
            return MinecraftOwnershipResult.Failure("Minecraft login returned empty access token")
        }
        logger.debug("Step 3 OK: Minecraft SSID token acquired")

        val requestId = UUID.randomUUID().toString()
        logger.debug("Step 4: Querying license entitlements (requestId={})...", requestId)
        val entitlementsResponse = client.get("https://api.minecraftservices.com/entitlements/license?requestId=$requestId") {
            header(HttpHeaders.Authorization, "Bearer $ssid")
        }

        if (!entitlementsResponse.status.isSuccess()) {
            val errorBody = entitlementsResponse.bodyAsText()
            logger.debug("Step 4 failed (HTTP {}): {}", entitlementsResponse.status.value, errorBody)
            return MinecraftOwnershipResult.Failure("Minecraft license entitlement check failed (HTTP ${entitlementsResponse.status.value}): $errorBody")
        }

        val entitlements = entitlementsResponse.body<MinecraftEntitlementsResponse>()
        val ownedItem = entitlements.items.firstOrNull { it.name == "product_minecraft" || it.name == "game_minecraft" }
        if (ownedItem == null) {
            logger.debug("Step 4 complete: Account does NOT own Minecraft (items count={})", entitlements.items.size)
            return MinecraftOwnershipResult.NotOwned("Account does not own a Minecraft license")
        }

        val source = ownedItem.source
        val hasGamePass = entitlements.items.any { it.source.equals("GAMEPASS", ignoreCase = true) }
        val signatures = entitlements.signatures
        logger.debug("Step 4 OK: License confirmed (item={}, source={}, hasGamePass={})", ownedItem.name, source, hasGamePass)

        logger.debug("Step 5: Querying Minecraft player profile...")
        val profileResponse = client.get("https://api.minecraftservices.com/minecraft/profile") {
            header(HttpHeaders.Authorization, "Bearer $ssid")
        }

        return when (profileResponse.status) {
            HttpStatusCode.OK -> {
                val profile = profileResponse.body<MinecraftProfile>()
                logger.debug("Step 5 OK: Profile found (name={}, uuid={})", profile.name, profile.id)
                MinecraftOwnershipResult.Owned(
                    profile = profile,
                    source = source,
                    hasGamePass = hasGamePass,
                    signatures = signatures,
                )
            }
            HttpStatusCode.NotFound -> {
                logger.debug("Step 5 OK: Profile not found (HTTP 404, license owned but no username registered)")
                MinecraftOwnershipResult.Owned(
                    profile = null,
                    source = source,
                    hasGamePass = hasGamePass,
                    signatures = signatures,
                )
            }
            else -> {
                val errorBody = profileResponse.bodyAsText()
                logger.debug("Step 5 failed (HTTP {}): {}", profileResponse.status.value, errorBody)
                MinecraftOwnershipResult.Failure("Failed to fetch Minecraft profile (HTTP ${profileResponse.status.value}): $errorBody")
            }
        }
    }

    override fun close() {
        client.close()
    }
}
