package minecraft.ownership.model

sealed interface MinecraftOwnershipResult {
    data class Owned(
        val profile: MinecraftProfile?,
        val source: String,
        val hasGamePass: Boolean,
        val signatures: List<String> = emptyList(),
    ) : MinecraftOwnershipResult

    data class NotOwned(
        val reason: String,
    ) : MinecraftOwnershipResult

    data class Failure(
        val reason: String,
        val cause: Throwable? = null,
    ) : MinecraftOwnershipResult
}

