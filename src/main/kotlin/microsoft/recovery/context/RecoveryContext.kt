package microsoft.recovery.context

import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.CookiesStorage
import microsoft.recovery.model.ManageProofsData
import microsoft.recovery.model.ProofItem

data class RecoveryContext(
    val email: String,
    val newPassword: String,
    val newEmail: String,
    var uaid: String,
    var activeCanary: String = "",
    val cookieStorage: CookiesStorage,
    val httpClient: HttpClient,
    val otpProvider: (suspend () -> String)? = null,
    val aliasOtcProvider: (suspend (String) -> String)? = null,
    var initialPpft: String? = null,
    var proofId: String? = null,
    var proofChannel: String? = null,
    var postPpft: String? = null,
    var proofsData: ManageProofsData? = null,
    var initialRecoveryCode: String? = null,
    var finalRecoveryCode: String? = null,
    var emailProofs: List<ProofItem> = emptyList(),
    var smsProofs: List<ProofItem> = emptyList(),
    var passKeyIds: List<String> = emptyList(),
    var suppressedCount: Int = 0,
    var targetAliasEmail: String = email,
)
