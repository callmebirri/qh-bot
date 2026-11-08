package minecraft.ownership.util

object XstsErrorMapper {
    fun mapErrorCode(code: Long, message: String? = null): String = when (code) {
        2148916233L -> "Account has no Xbox profile"
        2148916238L -> "Child account, parental consent required"
        2148916235L -> "Account banned in this region"
        else -> if (!message.isNullOrBlank()) {
            "XSTS authorization failed (code: $code): $message"
        } else {
            "XSTS authorization failed (code: $code)"
        }
    }
}

