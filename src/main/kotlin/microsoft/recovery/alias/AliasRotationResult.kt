package microsoft.recovery.alias

data class AliasRotationResult(
    val oldEmail: String,
    val newEmail: String,
    val updatedCanary: String,
)
