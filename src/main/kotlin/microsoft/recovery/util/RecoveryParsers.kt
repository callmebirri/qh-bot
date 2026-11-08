package microsoft.recovery.util

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.model.ManageProofsData
import microsoft.recovery.model.ProofItem
import microsoft.recovery.model.ResetPasswordData
import org.jsoup.Jsoup
import java.security.SecureRandom

object RecoveryParsers {
    private val secureRandom = SecureRandom()
    private val unicodeRegex = Regex("""\\u([0-9a-fA-F]{4})""")
    private val ppftRegex = Regex("""name=\\?"PPFT\\?"[^>]*value=\\?"([^"\\]+)""")
    private val fallbackPpftRegex = Regex("""name="PPFT"[^>]*value="([^"]+)"""")
    private val tokenTRegex = Regex("""<input[^>]+name="t"[^>]+value="([^"]*)"""")
    private val fallbackTokenTRegex = Regex("""name="t"[^>]*value="([^"]+)"""")
    private val encryptedNetIdRegex = Regex("""\"encryptedNetId\":\"([^\"]+)\"""")
    private val apiCanaryRegex = Regex("""\"apiCanary\":\"([^\"]+)\"""")
    private val recoveryTokenRegex = Regex("""\"sRecoveryToken\":\"([^\"]+)\"""")

    fun generateUaid(): String {
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun unescapeUnicode(input: String): String = unicodeRegex.replace(input) { matchResult ->
        matchResult.groupValues[1].toInt(16).toChar().toString()
    }

    fun extractJsonObject(text: String, startPrefix: String): String? {
        val index = text.indexOf(startPrefix)
        if (index == -1) return null
        val braceStart = text.indexOf('{', index)
        if (braceStart == -1) return null
        var depth = 0
        var inString = false
        var escape = false
        for (i in braceStart until text.length) {
            val c = text[i]
            if (escape) {
                escape = false
                continue
            }
            if (c == '\\') {
                escape = true
                continue
            }
            if (c == '"') {
                inString = !inString
                continue
            }
            if (!inString) {
                if (c == '{') depth++
                else if (c == '}') {
                    depth--
                    if (depth == 0) {
                        return text.substring(braceStart, i + 1)
                    }
                }
            }
        }
        return null
    }

    fun extractPpft(html: String, json: Json): String? {
        val serverDataJson = extractJsonObject(html, "var ServerData =")
            ?: extractJsonObject(html, "ServerData =")

        if (serverDataJson != null) {
            val sFtAg = runCatching {
                json.parseToJsonElement(serverDataJson).jsonObject["sFTAg"]?.jsonPrimitive?.content
            }.getOrNull()

            if (!sFtAg.isNullOrBlank()) {
                val parsed = Jsoup.parse(sFtAg).selectFirst("input[name=PPFT]")?.attr("value")
                if (!parsed.isNullOrBlank()) return parsed
                val regexMatch = fallbackPpftRegex.find(sFtAg)?.groupValues?.get(1)
                if (!regexMatch.isNullOrBlank()) return regexMatch
            }
        }

        val directMatch = ppftRegex.find(html)?.groupValues?.get(1)
        if (!directMatch.isNullOrBlank()) return directMatch

        return fallbackPpftRegex.find(html)?.groupValues?.get(1)
    }

    fun extractTokenT(html: String): String? {
        val parsed = Jsoup.parse(html).selectFirst("input[name=t]")?.attr("value")
        if (!parsed.isNullOrBlank()) return parsed

        val match = tokenTRegex.find(html)?.groupValues?.get(1)
        if (!match.isNullOrBlank()) return match

        return fallbackTokenTRegex.find(html)?.groupValues?.get(1)
    }

    fun extractManageProofsData(html: String, json: Json): ManageProofsData? {
        val t0Json = extractJsonObject(html, "var t0 =")
            ?: extractJsonObject(html, "t0 =")

        var parsedObj: JsonObject? = null
        if (t0Json != null) {
            parsedObj = runCatching { json.parseToJsonElement(t0Json).jsonObject }.getOrNull()
        }

        val targetObj = parsedObj?.get("WLXAccount")?.let { wlx ->
            runCatching { wlx.jsonObject["manageProofs"]?.jsonObject }.getOrNull()
        } ?: parsedObj

        val netId = targetObj?.get("encryptedNetId")?.let {
            runCatching { it.jsonPrimitive.content }.getOrNull()
        } ?: encryptedNetIdRegex.find(html)?.groupValues?.get(1)?.let(::unescapeUnicode)

        val canary = targetObj?.get("apiCanary")?.let {
            runCatching { it.jsonPrimitive.content }.getOrNull()
        } ?: apiCanaryRegex.find(html)?.groupValues?.get(1)?.let(::unescapeUnicode)

        if (netId.isNullOrBlank() || canary.isNullOrBlank()) {
            return null
        }

        val emailProofs = parseProofList(targetObj?.get("emailProofs"), "Email")
        val smsProofs = parseProofList(targetObj?.get("smsProofs"), "SMS")
        val passKeyIds = parsePassKeyIds(targetObj?.get("passKeys"))

        return ManageProofsData(
            encryptedNetId = unescapeUnicode(netId),
            apiCanary = unescapeUnicode(canary),
            emailProofs = emailProofs,
            smsProofs = smsProofs,
            passKeyIds = passKeyIds,
        )
    }

    fun extractResetPasswordData(html: String, json: Json): ResetPasswordData? {
        val serverDataJson = extractJsonObject(html, "var ServerData =")
            ?: extractJsonObject(html, "ServerData =")

        var parsedObj: JsonObject? = null
        if (serverDataJson != null) {
            parsedObj = runCatching { json.parseToJsonElement(serverDataJson).jsonObject }.getOrNull()
        }

        val token = parsedObj?.get("sRecoveryToken")?.let {
            runCatching { it.jsonPrimitive.content }.getOrNull()
        } ?: recoveryTokenRegex.find(html)?.groupValues?.get(1)?.let(::unescapeUnicode)

        val canary = parsedObj?.get("apiCanary")?.let {
            runCatching { it.jsonPrimitive.content }.getOrNull()
        } ?: apiCanaryRegex.find(html)?.groupValues?.get(1)?.let(::unescapeUnicode)

        if (token.isNullOrBlank() || canary.isNullOrBlank()) {
            return null
        }

        return ResetPasswordData(
            sRecoveryToken = unescapeUnicode(token),
            apiCanary = unescapeUnicode(canary),
        )
    }

    private fun parseProofList(element: JsonElement?, type: String): List<ProofItem> {
        val array = (element as? JsonArray) ?: return emptyList()
        return array.mapNotNull { item ->
            val name = when (item) {
                is JsonObject -> item["name"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                    ?: item["display"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                    ?: item["data"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                    ?: item["email"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                else -> runCatching { item.jsonPrimitive.content }.getOrNull()
            }
            if (!name.isNullOrBlank()) ProofItem(name = unescapeUnicode(name), type = type) else null
        }
    }

    private fun parsePassKeyIds(element: JsonElement?): List<String> {
        val array = (element as? JsonArray) ?: return emptyList()
        return array.mapNotNull { item ->
            when (item) {
                is JsonObject -> item["passKeyId"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                    ?: item["id"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                else -> runCatching { item.jsonPrimitive.content }.getOrNull()
            }?.let(::unescapeUnicode)
        }
    }
}
