package microsoft.recovery.model

sealed class RecoveryResult {
    data class Success(
        val originalEmail: String,
        val newPrimaryEmail: String,
        val password: String = "",
        val initialRecoveryCode: String,
        val finalRecoveryCode: String,
        val suppressedProofsCount: Int,
        val message: String = "Account recovery and lifecycle completed successfully",
    ) : RecoveryResult()

    data class Failure(
        val stage: RecoveryStage,
        val message: String,
        val errorCode: String? = null,
        val cause: Throwable? = null,
    ) : RecoveryResult()
}

enum class RecoveryStage {
    CREDENTIAL_DISCOVERY,
    OTP_DISPATCH,
    SESSION_ESTABLISHMENT,
    SESSION_STABILIZATION,
    PROOFS_ENUMERATION,
    RECOVERY_CODE_GENERATION,
    PASSWORD_ROTATION,
    NOTIFICATION_SUPPRESSION,
    ALIAS_ROTATION,
    SECURITY_CLEANUP,
}
