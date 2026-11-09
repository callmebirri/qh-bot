package database.repository

import database.model.RecoveredAccount

interface AccountRepository {
    suspend fun saveAccount(account: RecoveredAccount): Boolean
    suspend fun getAccountByEmail(email: String): RecoveredAccount?
    suspend fun getAccountByOriginalEmail(originalEmail: String): RecoveredAccount?
    suspend fun updateMinecraftStatus(email: String, owns: Boolean)
    suspend fun updateStatus(originalEmail: String, status: String, failReason: String? = null): Boolean
    suspend fun deleteByOriginalEmail(originalEmail: String): Boolean
    suspend fun getAllAccounts(): List<RecoveredAccount>
}
