package database

import database.model.RecoveredAccount
import database.repository.SqliteAccountRepository
import kotlinx.coroutines.runBlocking
import java.io.File
import java.sql.DriverManager
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SqliteAccountRepositoryTest {

    private lateinit var dbFile: File
    private lateinit var databaseManager: DatabaseManager
    private lateinit var repository: SqliteAccountRepository

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("test_accounts_", ".db")
        databaseManager = DatabaseManager(dbPath = dbFile.absolutePath)
        repository = SqliteAccountRepository(databaseManager)
    }

    @AfterTest
    fun tearDown() {
        databaseManager.close()
        dbFile.delete()
    }

    @Test
    fun testSaveAndGetAccountByOriginalAndPrimaryEmail(): Unit = runBlocking {
        val account = RecoveredAccount(
            originalEmail = "victim@example.com",
            currentPrimaryEmail = "alias123@qhuyy.tech",
            password = "SecretPassword123!",
            recoveryCode = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
            ownsMinecraft = false,
        )

        val saved = repository.saveAccount(account)
        assertTrue(saved)

        val byOriginal = repository.getAccountByEmail("victim@example.com")
        assertNotNull(byOriginal)
        assertEquals("victim@example.com", byOriginal.originalEmail)
        assertEquals("alias123@qhuyy.tech", byOriginal.currentPrimaryEmail)
        assertEquals("SecretPassword123!", byOriginal.password)
        assertEquals("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", byOriginal.recoveryCode)
        assertFalse(byOriginal.ownsMinecraft)

        val byPrimary = repository.getAccountByEmail("alias123@qhuyy.tech")
        assertNotNull(byPrimary)
        assertEquals("victim@example.com", byPrimary.originalEmail)
    }

    @Test
    fun testUpdateMinecraftStatus(): Unit = runBlocking {
        val account = RecoveredAccount(
            originalEmail = "mcuser@example.com",
            currentPrimaryEmail = "mcalias@qhuyy.tech",
            password = "SecretPassword123!",
            recoveryCode = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
            ownsMinecraft = false,
        )
        repository.saveAccount(account)

        repository.updateMinecraftStatus("mcuser@example.com", true)
        val updated = repository.getAccountByEmail("mcuser@example.com")
        assertNotNull(updated)
        assertTrue(updated.ownsMinecraft)
    }

    @Test
    fun testGetAllAccounts(): Unit = runBlocking {
        repository.saveAccount(
            RecoveredAccount(
                originalEmail = "user1@example.com",
                currentPrimaryEmail = "alias1@qhuyy.tech",
                password = "Pass1",
                recoveryCode = "Code1",
            ),
        )
        repository.saveAccount(
            RecoveredAccount(
                originalEmail = "user2@example.com",
                currentPrimaryEmail = "alias2@qhuyy.tech",
                password = "Pass2",
                recoveryCode = "Code2",
            ),
        )

        val all = repository.getAllAccounts()
        assertEquals(2, all.size)
        assertEquals("user1@example.com", all[0].originalEmail)
        assertEquals("user2@example.com", all[1].originalEmail)
    }

    @Test
    fun testStatusTrackingAndUpsertByOriginalEmail(): Unit = runBlocking {
        repository.saveAccount(
            RecoveredAccount(
                originalEmail = "RetryUser@example.com",
                status = RecoveredAccount.STATUS_PENDING,
            ),
        )

        val pending = repository.getAccountByOriginalEmail("retryuser@example.com")
        assertNotNull(pending)
        assertEquals(RecoveredAccount.STATUS_PENDING, pending.status)

        repository.updateStatus("retryuser@example.com", RecoveredAccount.STATUS_FAILED, "Stage 2 timeout")
        val failed = repository.getAccountByOriginalEmail("retryuser@example.com")
        assertNotNull(failed)
        assertEquals(RecoveredAccount.STATUS_FAILED, failed.status)
        assertEquals("Stage 2 timeout", failed.failReason)

        repository.saveAccount(
            RecoveredAccount(
                originalEmail = "retryuser@example.com",
                currentPrimaryEmail = "newalias@outlook.com",
                password = "NewPassword99!",
                recoveryCode = "REC-CODE-999",
                status = RecoveredAccount.STATUS_SUCCESS,
                failReason = null,
            ),
        )

        val all = repository.getAllAccounts()
        assertEquals(1, all.size)
        assertEquals(RecoveredAccount.STATUS_SUCCESS, all[0].status)
        assertEquals("newalias@outlook.com", all[0].currentPrimaryEmail)
        assertEquals("NewPassword99!", all[0].password)
        assertEquals("REC-CODE-999", all[0].recoveryCode)
        assertNull(all[0].failReason)
    }

    @Test
    fun testDeleteByOriginalEmail(): Unit = runBlocking {
        repository.saveAccount(
            RecoveredAccount(
                originalEmail = "delete@example.com",
                status = RecoveredAccount.STATUS_PENDING,
            ),
        )
        assertNotNull(repository.getAccountByOriginalEmail("delete@example.com"))

        assertTrue(repository.deleteByOriginalEmail("DELETE@example.com"))
        assertNull(repository.getAccountByOriginalEmail("delete@example.com"))
    }

    @Test
    fun testSchemaMigrationAddsStatusToLegacyTable(): Unit = runBlocking {
        val legacyDb = File.createTempFile("legacy_accounts_", ".db")
        try {
            DriverManager.getConnection("jdbc:sqlite:${legacyDb.absolutePath}").use { conn ->
                conn.createStatement().use { stmt ->
                    stmt.execute(
                        """
                        CREATE TABLE recovered_accounts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            original_email TEXT NOT NULL,
                            current_primary_email TEXT NOT NULL,
                            password TEXT NOT NULL,
                            recovery_code TEXT,
                            owns_minecraft INTEGER DEFAULT 0,
                            created_at INTEGER,
                            updated_at INTEGER
                        )
                        """.trimIndent(),
                    )
                    stmt.execute(
                        """
                        INSERT INTO recovered_accounts (original_email, current_primary_email, password, recovery_code, owns_minecraft, created_at, updated_at)
                        VALUES ('legacy@example.com', 'legacyalias@outlook.com', 'LegacyPass', 'LEGACY-CODE', 1, 1000, 1000)
                        """.trimIndent(),
                    )
                }
            }

            DatabaseManager(dbPath = legacyDb.absolutePath).use { migratedDb ->
                val migratedRepo = SqliteAccountRepository(migratedDb)
                val legacyAcc = migratedRepo.getAccountByOriginalEmail("legacy@example.com")
                assertNotNull(legacyAcc)
                assertEquals(RecoveredAccount.STATUS_PENDING, legacyAcc.status)
                assertEquals("legacyalias@outlook.com", legacyAcc.currentPrimaryEmail)
            }
        } finally {
            legacyDb.delete()
        }
    }
}
