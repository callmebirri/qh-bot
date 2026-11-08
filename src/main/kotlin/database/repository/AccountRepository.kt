package database.repository

import database.model.RecoveredAccount

interface AccountRepository {
    suspend fun saveAccount(account: RecoveredAccount): Boolean
    suspend fun getAccountByEmail(email: String): RecoveredAccount?
    suspend fun updateMinecraftStatus(email: String, owns: Boolean)
    suspend fun getAllAccounts(): List<RecoveredAccount>
}
