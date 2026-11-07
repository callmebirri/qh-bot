package command

import command.model.CommandInterface
import config.BotPropertiesManager
import dev.kord.core.Kord
import dev.kord.core.event.interaction.ChatInputCommandInteractionCreateEvent
import dev.kord.core.on

class CommandManager(
    private val kord: Kord,
    private val propertiesManager: BotPropertiesManager,
    private val listCommand: List<CommandInterface>
) {
    suspend fun registerAll() {
        listCommand.forEach { it.register(kord) }
        kord.on<ChatInputCommandInteractionCreateEvent> {
            listCommand.firstOrNull { it.name == interaction.command.rootName }
                ?.execute(this, propertiesManager)
        }
    }
}