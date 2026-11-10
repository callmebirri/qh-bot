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
    private val encryptedNetIdRegex = Regex(""""encryptedNetId"\s*:\s*"((?:\\.|[^"\\])+)"""")
    private val encryptedNetIdAltRegex = Regex("""(?:['"]encryptedNetId['"]|\bencryptedNetId)\s*:\s*["']([^"']+)["']""")
    private val encryptedNetIdEscapedRegex = Regex("""\\"encryptedNetId\\"\s*:\s*\\"((?:[^"\\]|\\(?!"))+)\\"""")
    private val apiCanaryRegex = Regex(""""apiCanary"\s*:\s*"((?:\\.|[^"\\])+)"""")
    private val apiCanaryAltRegex = Regex("""(?:['"]apiCanary['"]|\bapiCanary)\s*:\s*["']([^"']+)["']""")
    private val apiCanaryEscapedRegex = Regex("""\\"apiCanary\\"\s*:\s*\\"((?:[^"\\]|\\(?!"))+)\\"""")
    private val recoveryTokenRegex = Regex(""""sRecoveryToken"\s*:\s*"((?:\\.|[^"\\])+)"""")
    private val t0PrefixRegex = Regex("""(?:var\s+|window\.)?\bt0\s*=\s*\{""")
    private val serverDataPrefixRegex = Regex("""(?:var\s+|window\.)?\bServerData\s*=\s*(?:\(\s*)?\{""")

    fun generateUaid(): String {
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun generateRandomPassword(length: Int = 14): String {
        val upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val lower = "abcdefghijklmnopqrstuvwxyz"
        val digits = "0123456789"
        val specials = "!@#$%^&*"
        val all = upper + lower + digits + specials

        val chars = mutableListOf(
            upper[secureRandom.nextInt(upper.length)],
            lower[secureRandom.nextInt(lower.length)],
            digits[secureRandom.nextInt(digits.length)],
            specials[secureRandom.nextInt(specials.length)],
        )

        for (i in 4 until length) {
            chars.add(all[secureRandom.nextInt(all.length)])
        }

        chars.shuffle(secureRandom)
        return chars.joinToString("")
    }

    fun sanitizePassword(password: String): String = password.filter {
        it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it in "!@#$%^&*"
    }

    fun unescapeUnicode(input: String): String = unicodeRegex.replace(input) { matchResult ->
        matchResult.groupValues[1].toInt(16).toChar().toString()
    }

    fun extractJsonObject(text: String, startPrefix: String): String? {
        val index = text.indexOf(startPrefix)
        if (index == -1) return null
        return extractBalanced(text, index, '{', '}')
    }

    private fun extractJsonObjectByRegex(text: String, prefixRegex: Regex): String? {
        val match = prefixRegex.find(text) ?: return null
        return extractBalanced(text, match.range.first, '{', '}')
    }

    private fun extractJsonArrayByKey(text: String, key: String): String? {
        val keyRegex = Regex(""""$key"\s*:\s*\[""")
        val match = keyRegex.find(text) ?: return null
        return extractBalanced(text, match.range.first, '[', ']')
    }

    private fun extractBalanced(text: String, startIndex: Int, openChar: Char, closeChar: Char): String? {
        val braceStart = text.indexOf(openChar, startIndex)
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
                if (c == openChar) {
                    depth++
                } else if (c == closeChar) {
                    depth--
                    if (depth == 0) {
                        return text.substring(braceStart, i + 1)
                    }
                }
            }
        }
        return null
    }

    private fun decodeRegexToken(raw: String, json: Json): String {
        val jsonDecoded = runCatching { json.decodeFromString<String>("\"$raw\"") }
            .getOrElse { raw.replace("\\/", "/") }
        return unescapeUnicode(jsonDecoded)
    }

    private fun JsonObject?.stringField(vararg keys: String): String? {
        if (this == null) return null
        for (key in keys) {
            val value = this[key]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
            if (!value.isNullOrBlank()) return value
        }
        return null
    }

    fun extractPpft(html: String, json: Json): String? {
        val serverDataJson = extractJsonObjectByRegex(html, serverDataPrefixRegex)
            ?: extractJsonObject(html, "var ServerData =")
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
        val t0Json = extractJsonObjectByRegex(html, t0PrefixRegex)
            ?: extractJsonObject(html, "var t0 =")
            ?: extractJsonObject(html, "t0 =")
        val t0Obj = t0Json?.let { runCatching { json.parseToJsonElement(it).jsonObject }.getOrNull() }

        val serverDataJson = extractJsonObjectByRegex(html, serverDataPrefixRegex)
        val serverDataObj = serverDataJson?.let { runCatching { json.parseToJsonElement(it).jsonObject }.getOrNull() }

        val wlxObj = t0Obj?.get("WLXAccount")?.let { runCatching { it.jsonObject }.getOrNull() }
        val manageProofsObj = wlxObj?.get("manageProofs")?.let { runCatching { it.jsonObject }.getOrNull() }
            ?: extractJsonObject(html, "\"manageProofs\"")?.let {
                runCatching { json.parseToJsonElement(it).jsonObject }.getOrNull()
            }

        val netId = manageProofsObj.stringField("encryptedNetId")
            ?: wlxObj.stringField("encryptedNetId")
            ?: t0Obj.stringField("encryptedNetId")
            ?: serverDataObj.stringField("encryptedNetId")
            ?: encryptedNetIdRegex.find(html)?.groupValues?.get(1)?.let { decodeRegexToken(it, json) }
            ?: encryptedNetIdAltRegex.find(html)?.groupValues?.get(1)?.let { decodeRegexToken(it, json) }
            ?: encryptedNetIdEscapedRegex.find(html)?.groupValues?.get(1)?.let { decodeRegexToken(it, json) }

        val canary = manageProofsObj.stringField("apiCanary")
            ?: wlxObj.stringField("apiCanary")
            ?: t0Obj.stringField("apiCanary")
            ?: serverDataObj.stringField("apiCanary")
            ?: apiCanaryRegex.find(html)?.groupValues?.get(1)?.let { decodeRegexToken(it, json) }
            ?: apiCanaryAltRegex.find(html)?.groupValues?.get(1)?.let { decodeRegexToken(it, json) }
            ?: apiCanaryEscapedRegex.find(html)?.groupValues?.get(1)?.let { decodeRegexToken(it, json) }
            ?: manageProofsObj.stringField("sCanary", "canary")
            ?: wlxObj.stringField("sCanary", "canary")
            ?: t0Obj.stringField("sCanary", "canary")
            ?: serverDataObj.stringField("sCanary", "canary")

        if (netId.isNullOrBlank() || canary.isNullOrBlank()) {
            return null
        }

        val emailProofsEl = manageProofsObj?.get("emailProofs")
            ?: t0Obj?.get("emailProofs")
            ?: extractJsonArrayByKey(html, "emailProofs")?.let {
                runCatching { json.parseToJsonElement(it) }.getOrNull()
            }
        val smsProofsEl = manageProofsObj?.get("smsProofs")
            ?: t0Obj?.get("smsProofs")
            ?: extractJsonArrayByKey(html, "smsProofs")?.let {
                runCatching { json.parseToJsonElement(it) }.getOrNull()
            }
        val passKeysEl = manageProofsObj?.get("passKeys")
            ?: t0Obj?.get("passKeys")
            ?: extractJsonArrayByKey(html, "passKeys")?.let {
                runCatching { json.parseToJsonElement(it) }.getOrNull()
            }

        return ManageProofsData(
            encryptedNetId = unescapeUnicode(netId),
            apiCanary = unescapeUnicode(canary),
            emailProofs = parseProofList(emailProofsEl, "Email"),
            smsProofs = parseProofList(smsProofsEl, "SMS"),
            passKeyIds = parsePassKeyIds(passKeysEl),
        )
    }

    fun extractResetPasswordData(html: String, json: Json): ResetPasswordData? {
        val serverDataJson = extractJsonObjectByRegex(html, serverDataPrefixRegex)
            ?: extractJsonObject(html, "var ServerData =")
            ?: extractJsonObject(html, "ServerData =")

        val parsedObj = serverDataJson?.let {
            runCatching { json.parseToJsonElement(it).jsonObject }.getOrNull()
        }

        val token = parsedObj.stringField("sRecoveryToken")
            ?: recoveryTokenRegex.find(html)?.groupValues?.get(1)?.let { decodeRegexToken(it, json) }

        val canary = parsedObj.stringField("apiCanary")
            ?: apiCanaryRegex.find(html)?.groupValues?.get(1)?.let { decodeRegexToken(it, json) }
            ?: parsedObj.stringField("sCanary", "canary")

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
