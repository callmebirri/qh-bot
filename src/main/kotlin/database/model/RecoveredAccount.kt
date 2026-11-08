package database.model

data class RecoveredAccount(
    val id: Long? = null,
    val originalEmail: String,
    val currentPrimaryEmail: String,
    val password: String,
    val recoveryCode: String?,
    val ownsMinecraft: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)
