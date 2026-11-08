package database.di

import database.DatabaseManager
import database.repository.AccountRepository
import database.repository.SqliteAccountRepository
import org.koin.core.module.Module
import org.koin.dsl.module

val databaseModule: Module = module {
    single { DatabaseManager() }
    single<AccountRepository> { SqliteAccountRepository(get()) }
}
