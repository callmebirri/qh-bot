package microsoft.recovery.util

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import microsoft.recovery.model.EnumerateProofItem
import microsoft.recovery.model.ProofItem

object ProofExtractorExtensions {

    fun extractPasskeyCredentialIds(passkeysElement: JsonArray?): List<String> {
        if (passkeysElement == null) return emptyList()
        return passkeysElement.mapNotNull { item ->
            val id = when (item) {
                is JsonObject -> item["proofId"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                    ?: item["credentialId"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                    ?: item["passKeyId"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                    ?: item["id"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                else -> runCatching { item.jsonPrimitive.content }.getOrNull()
            }
            id?.takeIf { it.isNotBlank() }?.let(RecoveryParsers::unescapeUnicode)
        }
    }

    fun extractPasskeyCredentialIds(element: JsonElement?): List<String> =
        extractPasskeyCredentialIds(element as? JsonArray)

    fun parseDetailedProofItems(proofsElement: JsonArray?, type: String): List<EnumerateProofItem> {
        if (proofsElement == null) return emptyList()
        return proofsElement.mapNotNull { item ->
            when (item) {
                is JsonObject -> {
                    val proofId = item["proofId"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                        ?: item["id"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                        ?: item["displayProofName"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                        ?: item["display"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                        ?: item["name"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                        ?: return@mapNotNull null
                    if (proofId.isBlank()) return@mapNotNull null

                    val displayName = item["displayProofName"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                        ?: item["display"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                        ?: item["name"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
                        ?: proofId

                    val isVerifiedInt = item["isVerified"]?.let { runCatching { it.jsonPrimitive.content.toIntOrNull() }.getOrNull() } ?: 1
                    val encryptedProofId = item["encryptedProofId"]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }

                    EnumerateProofItem(
                        proofId = RecoveryParsers.unescapeUnicode(proofId),
                        name = RecoveryParsers.unescapeUnicode(displayName),
                        type = type,
                        isVerified = isVerifiedInt == 1,
                        encryptedProofId = encryptedProofId?.takeIf { it.isNotBlank() }?.let(RecoveryParsers::unescapeUnicode),
                    )
                }
                else -> {
                    val str = runCatching { item.jsonPrimitive.content }.getOrNull()?.takeIf { it.isNotBlank() }
                        ?: return@mapNotNull null
                    val unescaped = RecoveryParsers.unescapeUnicode(str)
                    EnumerateProofItem(
                        proofId = unescaped,
                        name = unescaped,
                        type = type,
                        isVerified = true,
                        encryptedProofId = null,
                    )
                }
            }
        }
    }

    fun parseDetailedProofItems(element: JsonElement?, type: String): List<EnumerateProofItem> =
        parseDetailedProofItems(element as? JsonArray, type)

    fun parseProofItems(proofsElement: JsonArray?, type: String): List<ProofItem> =
        parseDetailedProofItems(proofsElement, type).map(EnumerateProofItem::toProofItem)

    fun parseProofItems(element: JsonElement?, type: String): List<ProofItem> =
        parseProofItems(element as? JsonArray, type)
}
