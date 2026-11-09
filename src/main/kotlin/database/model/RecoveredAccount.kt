package database.model

data class RecoveredAccount(
    val id: Long? = null,
    val originalEmail: String,
    val currentPrimaryEmail: String = "",
    val password: String = "",
    val recoveryCode: String? = null,
    val ownsMinecraft: Boolean = false,
    val status: String = STATUS_PENDING,
    val failReason: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
) {
    companion object {
        const val STATUS_PENDING: String = "PENDING"
        const val STATUS_SUCCESS: String = "SUCCESS"
        const val STATUS_FAILED: String = "FAILED"
    }
}
