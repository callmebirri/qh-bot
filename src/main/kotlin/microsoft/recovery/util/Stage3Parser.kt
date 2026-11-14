package microsoft.recovery.util

import microsoft.recovery.alias.SessionExpiredException
import org.jsoup.Jsoup
import org.jsoup.nodes.Document

object Stage3Parser {

    private val tokenTRegexes = listOf(
        Regex("""name=["']t["']\s+value=["']([^"']+)["']"""),
        Regex("""value=["']([^"']+)["']\s+name=["']t["']"""),
        Regex("""["']t["']\s*:\s*["']([^"']+)["']"""),
    )

    private val ppftRegex = Regex("""name=\\?["']PPFT\\?["']""", RegexOption.IGNORE_CASE)

    fun hasDoSubmitForm(html: String, doc: Document): Boolean {
        return html.contains("DoSubmit()", ignoreCase = true) ||
            doc.selectFirst("body[onload*=DoSubmit]") != null
    }

    fun extractAutoSubmitForm(html: String, doc: Document): Pair<String, List<Pair<String, String>>>? {
        if (!hasDoSubmitForm(html, doc)) {
            return null
        }

        val autoSubmitForm = doc.selectFirst("form[name=fmHF], form#fmHF, form") ?: return null
        val actionUrl = autoSubmitForm.absUrl("action").ifBlank { autoSubmitForm.attr("action").trim() }
        val hiddenFields = autoSubmitForm.select("input[type=hidden]")
            .mapNotNull { input ->
                val name = input.attr("name").trim()
                if (name.isNotEmpty()) name to input.attr("value") else null
            }

        if (actionUrl.isBlank() || (!actionUrl.startsWith("https://") && !actionUrl.startsWith("http://")) || hiddenFields.isEmpty()) {
            return null
        }

        return actionUrl to hiddenFields
    }

    fun extractTokenT(html: String, doc: Document): String? {
        val formInput = doc.selectFirst("input[name=t]")?.attr("value")
        if (!formInput.isNullOrEmpty()) {
            return formInput
        }

        for (regex in tokenTRegexes) {
            val match = regex.find(html)
            if (match != null) {
                return match.groupValues[1]
            }
        }

        if (hasPpftInput(html)) {
            throw SessionExpiredException("Session rejected. Microsoft is asking to log in again. (IP may be flagged)")
        }

        return null
    }

    fun extractTokenT(html: String): String? = extractTokenT(html, Jsoup.parse(html))

    fun hasPpftInput(html: String): Boolean = ppftRegex.containsMatchIn(html)
}
