package database

import database.model.RecoveredAccount
import database.repository.SqliteAccountRepository
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
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
}
