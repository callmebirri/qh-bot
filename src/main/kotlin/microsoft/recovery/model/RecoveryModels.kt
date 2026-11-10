package microsoft.recovery.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class GetCredentialTypeRequest(
    val username: String,
    val flowToken: String,
    val isUcuxLoginForm: Boolean = true,
    val isCookieBannerShown: Boolean = false,
    val checkPhones: Boolean = true,
)

@Serializable
data class GetCredentialTypeResponse(
    @SerialName("IfExistsResult")
    val ifExistsResult: Int? = null,
    @SerialName("Credentials")
    val credentials: CredentialsData? = null,
)

@Serializable
data class CredentialsData(
    @SerialName("HasPassword")
    val hasPassword: Int? = null,
    @SerialName("OtcLoginEligibleProofs")
    val otcLoginEligibleProofs: List<ProofData> = emptyList(),
)

@Serializable
data class ProofData(
    val data: String? = null,
    val display: String? = null,
    val type: Int? = null,
)

@Serializable
data class GetOneTimeCodeResponse(
    @SerialName("State")
    val state: Int? = null,
    @SerialName("FlowToken")
    val flowToken: String? = null,
    @SerialName("Error")
    val error: String? = null,
)

@Serializable
data class GenerateRecoveryCodeRequest(
    val encryptedNetId: String,
)

@Serializable
data class GenerateRecoveryCodeResponse(
    val recoveryCode: String? = null,
    val apiCanary: String? = null,
    val error: RecoveryErrorData? = null,
)

@Serializable
data class VerifyRecoveryCodeRequest(
    val publicKey: String = "2CBB3761027476727BDDBC9DE02870BE01ED793A",
    val recoveryCode: String,
    val code: String,
    val scid: Int = 100103,
    val token: String,
    val uiflvr: Int = 1001,
)

@Serializable
data class VerifyRecoveryCodeResponse(
    val token: String? = null,
    val apiCanary: String? = null,
    val error: RecoveryErrorData? = null,
)

@Serializable
data class RecoverUserRequest(
    val contactEmail: String,
    val contactEpid: String = "",
    val password: String,
    val passwordExpiryEnabled: Int = 0,
    val publicKey: String = "2CBB3761027476727BDDBC9DE02870BE01ED793A",
    val token: String,
)

@Serializable
data class RecoverUserResponse(
    val recoveryCode: String? = null,
    val apiCanary: String? = null,
    val enableTfa: Boolean? = null,
    val error: RecoveryErrorData? = null,
)

@Serializable
data class RecoveryErrorData(
    val code: String? = null,
    val data: String? = null,
    val message: String? = null,
)

@Serializable
data class SetUserNotificationStateRequest(
    val proofDetails: List<NotificationProofDetail>,
    val uiflvr: Int = 1001,
    val uaid: String,
    val scid: Int = 100109,
    val hpgid: Int = 201030,
)

@Serializable
data class NotificationProofDetail(
    val name: String,
    val notificationEnabled: Boolean = false,
    val type: String,
)

@Serializable
data class MakePrimaryRequest(
    val aliasName: String,
    val emailChecked: Boolean = true,
    val removeOldPrimary: Boolean = false,
    val uiflvr: Int = 1001,
    val uaid: String,
    val scid: Int = 100115,
    val hpgid: Int = 200650,
)

@Serializable
data class SecurityCleanupRequest(
    val passKeyId: String? = null,
    val uiflvr: Int = 1001,
    val uaid: String,
    val scid: Int = 100109,
    val hpgid: Int = 201030,
)

@Serializable
data class GenericCanaryResponse(
    val apiCanary: String? = null,
    val error: RecoveryErrorData? = null,
)

data class ProofItem(
    val name: String,
    val type: String,
)

data class ManageProofsData(
    val encryptedNetId: String,
    val apiCanary: String,
    val emailProofs: List<ProofItem>,
    val smsProofs: List<ProofItem>,
    val passKeyIds: List<String>,
)

data class ResetPasswordData(
    val sRecoveryToken: String,
    val apiCanary: String,
)
