package database.repository

import database.DatabaseManager
import database.model.RecoveredAccount
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.sql.ResultSet

class SqliteAccountRepository(
    private val databaseManager: DatabaseManager,
) : AccountRepository {

    private val logger = LoggerFactory.getLogger(SqliteAccountRepository::class.java)

    override suspend fun saveAccount(account: RecoveredAccount): Boolean = withContext(Dispatchers.IO) {
        val findSql = """
            SELECT id FROM recovered_accounts
            WHERE LOWER(original_email) = LOWER(?)
            ORDER BY id DESC
            LIMIT 1
        """.trimIndent()

        val updateSql = """
            UPDATE recovered_accounts
            SET original_email = ?,
                current_primary_email = ?,
                password = ?,
                recovery_code = ?,
                owns_minecraft = ?,
                status = ?,
                fail_reason = ?,
                updated_at = ?
            WHERE id = ?
        """.trimIndent()

        val insertSql = """
            INSERT INTO recovered_accounts (
                original_email,
                current_primary_email,
                password,
                recovery_code,
                owns_minecraft,
                status,
                fail_reason,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()

        try {
            databaseManager.getConnection().use { conn ->
                val existingId = conn.prepareStatement(findSql).use { stmt ->
                    stmt.setString(1, account.originalEmail)
                    stmt.executeQuery().use { rs ->
                        if (rs.next()) rs.getLong("id") else null
                    }
                }

                if (existingId != null) {
                    conn.prepareStatement(updateSql).use { stmt ->
                        stmt.setString(1, account.originalEmail)
                        stmt.setString(2, account.currentPrimaryEmail)
                        stmt.setString(3, account.password)
                        stmt.setString(4, account.recoveryCode)
                        stmt.setInt(5, if (account.ownsMinecraft) 1 else 0)
                        stmt.setString(6, account.status)
                        stmt.setString(7, account.failReason)
                        stmt.setLong(8, System.currentTimeMillis())
                        stmt.setLong(9, existingId)
                        stmt.executeUpdate() > 0
                    }
                } else {
                    conn.prepareStatement(insertSql).use { stmt ->
                        stmt.setString(1, account.originalEmail)
                        stmt.setString(2, account.currentPrimaryEmail)
                        stmt.setString(3, account.password)
                        stmt.setString(4, account.recoveryCode)
                        stmt.setInt(5, if (account.ownsMinecraft) 1 else 0)
                        stmt.setString(6, account.status)
                        stmt.setString(7, account.failReason)
                        stmt.setLong(8, account.createdAt)
                        stmt.setLong(9, account.updatedAt)
                        stmt.executeUpdate() > 0
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to save account for {}: {}", account.originalEmail, e.message)
            false
        }
    }

    override suspend fun getAccountByEmail(email: String): RecoveredAccount? = withContext(Dispatchers.IO) {
        val sql = """
            SELECT id, original_email, current_primary_email, password, recovery_code, owns_minecraft, status, fail_reason, created_at, updated_at
            FROM recovered_accounts
            WHERE LOWER(original_email) = LOWER(?) OR LOWER(current_primary_email) = LOWER(?)
            ORDER BY id DESC
            LIMIT 1
        """.trimIndent()

        try {
            databaseManager.getConnection().use { conn ->
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setString(1, email)
                    stmt.setString(2, email)
                    stmt.executeQuery().use { rs ->
                        if (rs.next()) rs.toRecoveredAccount() else null
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to fetch account by email {}: {}", email, e.message)
            null
        }
    }

    override suspend fun getAccountByOriginalEmail(originalEmail: String): RecoveredAccount? = withContext(Dispatchers.IO) {
        val sql = """
            SELECT id, original_email, current_primary_email, password, recovery_code, owns_minecraft, status, fail_reason, created_at, updated_at
            FROM recovered_accounts
            WHERE LOWER(original_email) = LOWER(?)
            ORDER BY id DESC
            LIMIT 1
        """.trimIndent()

        try {
            databaseManager.getConnection().use { conn ->
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setString(1, originalEmail)
                    stmt.executeQuery().use { rs ->
                        if (rs.next()) rs.toRecoveredAccount() else null
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to fetch account by original email {}: {}", originalEmail, e.message)
            null
        }
    }

    override suspend fun updateMinecraftStatus(email: String, owns: Boolean): Unit = withContext(Dispatchers.IO) {
        val sql = """
            UPDATE recovered_accounts
            SET owns_minecraft = ?, updated_at = ?
            WHERE LOWER(original_email) = LOWER(?) OR LOWER(current_primary_email) = LOWER(?)
        """.trimIndent()

        try {
            databaseManager.getConnection().use { conn ->
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setInt(1, if (owns) 1 else 0)
                    stmt.setLong(2, System.currentTimeMillis())
                    stmt.setString(3, email)
                    stmt.setString(4, email)
                    stmt.executeUpdate()
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to update Minecraft status for {}: {}", email, e.message)
        }
    }

    override suspend fun updateStatus(originalEmail: String, status: String, failReason: String?): Boolean = withContext(Dispatchers.IO) {
        val sql = """
            UPDATE recovered_accounts
            SET status = ?, fail_reason = ?, updated_at = ?
            WHERE LOWER(original_email) = LOWER(?)
        """.trimIndent()

        try {
            databaseManager.getConnection().use { conn ->
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setString(1, status)
                    stmt.setString(2, failReason)
                    stmt.setLong(3, System.currentTimeMillis())
                    stmt.setString(4, originalEmail)
                    stmt.executeUpdate() > 0
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to update status for {}: {}", originalEmail, e.message)
            false
        }
    }

    override suspend fun deleteByOriginalEmail(originalEmail: String): Boolean = withContext(Dispatchers.IO) {
        val sql = """
            DELETE FROM recovered_accounts
            WHERE LOWER(original_email) = LOWER(?)
        """.trimIndent()

        try {
            databaseManager.getConnection().use { conn ->
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setString(1, originalEmail)
                    stmt.executeUpdate() >= 0
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to delete account for {}: {}", originalEmail, e.message)
            false
        }
    }

    override suspend fun getAllAccounts(): List<RecoveredAccount> = withContext(Dispatchers.IO) {
        val sql = """
            SELECT id, original_email, current_primary_email, password, recovery_code, owns_minecraft, status, fail_reason, created_at, updated_at
            FROM recovered_accounts
            ORDER BY id ASC
        """.trimIndent()

        try {
            databaseManager.getConnection().use { conn ->
                conn.prepareStatement(sql).use { stmt ->
                    stmt.executeQuery().use { rs ->
                        val accounts = mutableListOf<RecoveredAccount>()
                        while (rs.next()) {
                            accounts.add(rs.toRecoveredAccount())
                        }
                        accounts
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to fetch all accounts: {}", e.message)
            emptyList()
        }
    }

    private fun ResultSet.toRecoveredAccount(): RecoveredAccount = RecoveredAccount(
        id = getLong("id"),
        originalEmail = getString("original_email"),
        currentPrimaryEmail = getString("current_primary_email"),
        password = getString("password"),
        recoveryCode = getString("recovery_code"),
        ownsMinecraft = getInt("owns_minecraft") == 1,
        status = getString("status") ?: RecoveredAccount.STATUS_PENDING,
        failReason = getString("fail_reason"),
        createdAt = getLong("created_at"),
        updatedAt = getLong("updated_at"),
    )
}
