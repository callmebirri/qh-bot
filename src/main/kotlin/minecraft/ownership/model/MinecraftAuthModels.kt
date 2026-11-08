package minecraft.ownership.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class MinecraftLoginRequest(
    @SerialName("identityToken") val identityToken: String,
)

@Serializable
internal data class MinecraftLoginResponse(
    @SerialName("username") val username: String? = null,
    @SerialName("roles") val roles: List<String> = emptyList(),
    @SerialName("access_token") val accessToken: String,
    @SerialName("token_type") val tokenType: String? = null,
    @SerialName("expires_in") val expiresIn: Long? = null,
)

