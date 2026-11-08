@file:JvmName("Main")
package tech.qhuyy

import command.CommandManager
import command.commands.PingCommand
import command.model.CommandInterface
import config.BotPropertiesManager
import database.di.databaseModule
import dev.kord.core.Kord
import dev.kord.gateway.ALL
import dev.kord.gateway.Intents
import dev.kord.gateway.PrivilegedIntent
import discord.DiscordLogger
import event.EventManager
import event.events.CreateMessageEvent
import event.events.RecoveryInteractionEvent
import event.model.EventInterface
import kotlinx.coroutines.coroutineScope
import microsoft.recovery.RecoveryService
import microsoft.recovery.alias.AliasClient
import org.koin.core.context.GlobalContext.startKoin
import org.koin.dsl.bind
import org.koin.dsl.module

@OptIn(PrivilegedIntent::class)
suspend fun main() {
    val token = requireNotNull(System.getenv("DBT")) { "Discord Bot Token has not been found!" }
    val kord = Kord(token)
    val koin = startKoin { modules(kordModule(kord), databaseModule) }.koin
    koin.get<EventManager>().registerAll()
    coroutineScope { koin.get<CommandManager>().registerAll() }
    kord.login { intents += Intents.ALL }
}

fun kordModule(kord: Kord) = module {
    single { kord }
    single { BotPropertiesManager() }
    single { DiscordLogger(get()) }
    single { AliasClient() }
    single { RecoveryService(accountRepository = get(), aliasClient = get()) }
    single { PingCommand() } bind CommandInterface::class
    single { CreateMessageEvent(get()) } bind EventInterface::class
    single { RecoveryInteractionEvent(get(), get()) } bind EventInterface::class
    single { CommandManager(get(), get(), getAll()) }
    single { EventManager(get(), get(), getAll()) }
}
