package microsoft.recovery.alias

data class VerifyAliasResult(
    val isConfirmed: Boolean,
    val newCanary: String? = null,
    val newApiCanary: String? = null,
)
