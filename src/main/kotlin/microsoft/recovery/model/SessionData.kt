package microsoft.recovery.model

import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.CookiesStorage

data class SessionData(
    val cookieStorage: CookiesStorage,
    val httpClient: HttpClient,
    val uaid: String,
    val activeCanary: String = "",
)
