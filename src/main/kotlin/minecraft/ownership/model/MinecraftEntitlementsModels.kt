package minecraft.ownership.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class MinecraftEntitlementsResponse(
    @SerialName("items") val items: List<MinecraftEntitlementItem> = emptyList(),
    @SerialName("signatures") val signatures: List<String> = emptyList(),
    @SerialName("keyId") val keyId: String? = null,
)

@Serializable
internal data class MinecraftEntitlementItem(
    @SerialName("name") val name: String,
    @SerialName("source") val source: String,
)

