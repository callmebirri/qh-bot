package microsoft.recovery.di

import microsoft.recovery.RecoveryService
import org.koin.core.module.Module
import org.koin.dsl.module

val recoveryModule: Module = module {
    single { RecoveryService() }
}
