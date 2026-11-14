package microsoft.recovery.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PasskeyRemovalRequest(
    @SerialName("credentialId")
    val credentialId: String,
    val uiflvr: Int = 1001,
    val uaid: String,
    val scid: Int = 100109,
    val hpgid: Int = 201030,
)

@Serializable
data class ProofRemovalRequest(
    @SerialName("proofId")
    val proofId: String,
    val uiflvr: Int = 1001,
    val uaid: String,
    val scid: Int = 100109,
    val hpgid: Int = 201030,
)

@Serializable
data class StandardProofActionRequest(
    val uiflvr: Int = 1001,
    val uaid: String,
    val scid: Int = 100109,
    val hpgid: Int = 201030,
)

@Serializable
data class SendOttVerificationRequest(
    val actionSpecificNetId: String,
    val destination: String,
    val proofId: String,
    val channel: String,
    val proofCountry: String = "",
    val proofCountryCode: String = "",
    val action: String = "VerifyProof",
    val uiflvr: Int = 1001,
    val uaid: String,
    val scid: Int = 100109,
    val hpgid: Int = 201030,
)

@Serializable
data class ConfirmProofVerificationRequest(
    val proofId: String,
    val code: String,
    val uiflvr: Int = 1001,
    val uaid: String,
    val scid: Int = 100109,
    val hpgid: Int = 201030,
)

data class ProofItem(
    val proofId: String = "",
    val name: String,
    val type: String,
)

data class EnumerateProofItem(
    val proofId: String,
    val name: String,
    val type: String,
    val isVerified: Boolean = true,
    val encryptedProofId: String? = null,
) {
    fun toProofItem(): ProofItem = ProofItem(
        proofId = proofId,
        name = name,
        type = type,
    )
}

data class DetailedProofsInventory(
    val encryptedNetId: String,
    val apiCanary: String,
    val emailProofs: List<ProofItem>,
    val smsProofs: List<ProofItem>,
    val passKeyIds: List<String>,
    val hasAppPassword: Boolean,
)
