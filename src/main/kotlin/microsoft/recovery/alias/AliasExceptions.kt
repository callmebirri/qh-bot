package microsoft.recovery.alias

class OtcTimeoutException(message: String) : RuntimeException(message)

class AliasVerificationFailedException(message: String) : RuntimeException(message)

class SessionExpiredException(
    message: String,
    val redirectLocation: String? = null,
) : RuntimeException(message)

class MfaRequiredException(message: String) : RuntimeException(message)
