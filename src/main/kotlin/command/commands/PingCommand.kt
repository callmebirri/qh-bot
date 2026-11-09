package command.commands

import command.model.CommandInterface
import config.BotPropertiesManager
import dev.kord.core.Kord
import dev.kord.core.behavior.interaction.response.respond
import dev.kord.core.event.interaction.ChatInputCommandInteractionCreateEvent
import kotlin.time.TimeSource

class PingCommand : CommandInterface {
    override val name: String = "ping"

    override suspend fun register(kord: Kord): Boolean {
        kord.createGlobalChatInputCommand(name, "Check Latency")
        return true
    }

    override suspend fun execute(
        event: ChatInputCommandInteractionCreateEvent,
        config: BotPropertiesManager
    ) {
        val interaction = event.interaction
        val response = interaction.deferPublicResponse()
        val start = TimeSource.Monotonic.markNow()
        val ltcy = start.elapsedNow()
        val ping = event.kord.gateway.averagePing?.absoluteValue
        response.respond {
            content = "Pong!\n" +
                    "API: ${ltcy.inWholeMilliseconds}ms\n" +
                    "Gateway: ${ping ?: "null"}"
        }
    }
}