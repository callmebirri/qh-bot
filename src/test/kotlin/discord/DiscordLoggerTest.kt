package discord

import dev.kord.common.Color
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DiscordLoggerTest {

    @Test
    fun testBuildFailureEmbedContainsExpectedFields(): Unit {
        val logger = DiscordLogger()
        val embed = logger.buildFailureEmbed(
            stageName = "Stage 3 Polish",
            errorReason = "Failed to find Canary token",
            debugContext = null,
        )

        assertEquals("Account Recovery Failed", embed.title)
        assertEquals(Color(0xFF3B30), embed.color)
        assertNotNull(embed.description)
        assertTrue((embed.description?.length ?: 0) <= 4096)

        assertEquals(2, embed.fields.size)
        assertEquals("Stage", embed.fields[0].name)
        assertEquals("Stage 3 Polish", embed.fields[0].value)
        assertTrue(embed.fields[0].inline ?: false)

        assertEquals("Failure Reason", embed.fields[1].name)
        assertEquals("Failed to find Canary token", embed.fields[1].value)
    }

    @Test
    fun testBuildFailureEmbedWithDebugContext(): Unit {
        val logger = DiscordLogger()
        val debugSnippet = "Status: 200 | Title: Login\n<html><body>error</body></html>"
        val embed = logger.buildFailureEmbed(
            stageName = "Stage 3 Polish",
            errorReason = "Invalid response",
            debugContext = debugSnippet,
        )

        assertEquals(3, embed.fields.size)
        assertEquals("Debug Context", embed.fields[2].name)
        assertEquals(debugSnippet, embed.fields[2].value)
    }

    @Test
    fun testBuildFailureEmbedTruncatesLongFields(): Unit {
        val logger = DiscordLogger()
        val longStage = "S".repeat(2000)
        val longReason = "R".repeat(3000)
        val longDebug = "D".repeat(5000)

        val embed = logger.buildFailureEmbed(
            stageName = longStage,
            errorReason = longReason,
            debugContext = longDebug,
        )

        assertTrue(embed.fields[0].value.length <= 1024)
        assertTrue(embed.fields[1].value.length <= 1024)
        for (field in embed.fields) {
            assertTrue(field.name.length <= 256)
            assertTrue(field.value.length <= 1024)
        }

        val totalChars = (embed.title?.length ?: 0) +
            (embed.description?.length ?: 0) +
            embed.fields.sumOf { it.name.length + it.value.length }

        assertTrue(totalChars <= 6000)
    }

    @Test
    fun testBuildFailureEmbedHandlesBlankInputs(): Unit {
        val logger = DiscordLogger()
        val embed = logger.buildFailureEmbed(
            stageName = "",
            errorReason = "",
            debugContext = "   ",
        )

        assertEquals("Unknown Stage", embed.fields[0].value)
        assertEquals("Unknown Error", embed.fields[1].value)
        assertEquals(2, embed.fields.size)
    }

    @Test
    fun testSendDetailedFailureEarlyReturnOnZeroChannelId(): Unit = runBlocking {
        val logger = DiscordLogger()
        logger.sendDetailedFailure(
            logChannelId = 0L,
            stageName = "Stage 1",
            errorReason = "Failure",
            debugContext = "Context",
        )
    }

    @Test
    fun testSendDetailedFailureEarlyReturnOnNullKord(): Unit = runBlocking {
        val logger = DiscordLogger(null)
        logger.sendDetailedFailure(
            logChannelId = 123456789L,
            stageName = "Stage 1",
            errorReason = "Failure",
            debugContext = "Context",
        )
    }
}
