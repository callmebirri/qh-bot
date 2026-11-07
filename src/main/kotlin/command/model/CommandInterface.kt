package command.model

import config.BotPropertiesManager
import dev.kord.core.Kord
import dev.kord.core.event.interaction.ChatInputCommandInteractionCreateEvent

interface CommandInterface {
    val name: String
    suspend fun register(kord: Kord): Boolean
    suspend fun execute(event: ChatInputCommandInteractionCreateEvent, config: BotPropertiesManager)
}