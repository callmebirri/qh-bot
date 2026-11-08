package minecraft.ownership.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class XstsAuthRequest(
    @SerialName("Properties") val properties: XstsAuthProperties,
    @SerialName("RelyingParty") val relyingParty: String = "rp://api.minecraftservices.com/",
    @SerialName("TokenType") val tokenType: String = "JWT",
)

@Serializable
internal data class XstsAuthProperties(
    @SerialName("SandboxId") val sandboxId: String = "RETAIL",
    @SerialName("UserTokens") val userTokens: List<String>,
)

@Serializable
internal data class XstsErrorResponse(
    @SerialName("Identity") val identity: String? = null,
    @SerialName("XErr") val xErr: Long? = null,
    @SerialName("Message") val message: String? = null,
    @SerialName("Redirect") val redirect: String? = null,
)

