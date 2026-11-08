package minecraft.ownership.di

import minecraft.ownership.MinecraftOwnershipService
import minecraft.ownership.util.MinecraftHttpClientFactory
import org.koin.core.module.Module
import org.koin.dsl.module

val minecraftOwnershipModule: Module = module {
    single { MinecraftHttpClientFactory.create() }
    single { MinecraftOwnershipService(get()) }
}

