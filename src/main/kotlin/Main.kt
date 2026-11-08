@file:JvmName("Main")
package tech.qhuyy

import command.CommandManager
import command.commands.PingCommand
import command.model.CommandInterface
import config.BotPropertiesManager
import dev.kord.core.Kord
import dev.kord.gateway.ALL
import dev.kord.gateway.Intents
import dev.kord.gateway.PrivilegedIntent
import event.EventManager
import event.events.CreateMessageEvent
import event.model.EventInterface
import kotlinx.coroutines.coroutineScope
import org.koin.core.context.GlobalContext.startKoin
import org.koin.dsl.bind
import org.koin.dsl.module

@OptIn(PrivilegedIntent::class)
suspend fun main() {
    val token = requireNotNull(System.getenv("DBT")) { "Discord Bot Token has not been found!" }
    val kord = Kord(token)
    val koin = startKoin { modules(kordModule(kord)) }.koin
    koin.get<EventManager>().registerAll()
    coroutineScope { koin.get<CommandManager>().registerAll() }
    kord.login { intents += Intents.ALL }
}

fun kordModule(kord: Kord) = module {
    single { kord }
    single { BotPropertiesManager() }
    single { PingCommand() } bind CommandInterface::class
    single { CreateMessageEvent() } bind EventInterface::class
    single { CommandManager(get(), get(), getAll()) }
    single { EventManager(get(), get(), getAll()) }
}