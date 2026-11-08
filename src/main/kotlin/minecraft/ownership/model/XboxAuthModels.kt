package minecraft.ownership.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class XboxUserAuthRequest(
    @SerialName("Properties") val properties: XboxUserAuthProperties,
    @SerialName("RelyingParty") val relyingParty: String = "http://auth.xboxlive.com",
    @SerialName("TokenType") val tokenType: String = "JWT",
)

@Serializable
internal data class XboxUserAuthProperties(
    @SerialName("AuthMethod") val authMethod: String = "RPS",
    @SerialName("SiteName") val siteName: String = "user.auth.xboxlive.com",
    @SerialName("RpsTicket") val rpsTicket: String,
)

@Serializable
internal data class XboxAuthResponse(
    @SerialName("IssueInstant") val issueInstant: String? = null,
    @SerialName("NotAfter") val notAfter: String? = null,
    @SerialName("Token") val token: String,
    @SerialName("DisplayClaims") val displayClaims: XboxDisplayClaims? = null,
)

@Serializable
internal data class XboxDisplayClaims(
    @SerialName("xui") val xui: List<XboxClaimXui> = emptyList(),
)

@Serializable
internal data class XboxClaimXui(
    @SerialName("uhs") val uhs: String? = null,
)

