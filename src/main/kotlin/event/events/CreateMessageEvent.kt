package event.events

import config.BotPropertiesManager
import dev.kord.common.Color
import dev.kord.common.entity.Snowflake
import dev.kord.core.Kord
import dev.kord.core.behavior.channel.MessageChannelBehavior
import dev.kord.core.behavior.channel.createEmbed
import dev.kord.core.event.gateway.ReadyEvent
import dev.kord.core.on
import discord.DiscordLogger
import event.model.EventInterface

class CreateMessageEvent(
    private val discordLogger: DiscordLogger? = null,
) : EventInterface {
    override fun register(kord: Kord, properties: BotPropertiesManager) {
        kord.on<ReadyEvent> {
            try {
                val channel = MessageChannelBehavior(Snowflake(properties.logChannelId), kord)
                channel.createEmbed {
                    title = "Birrii Auto Secure"
                    color = Color(255, 0, 255)
                    description = "Bot initialized successfully"
                }
            } catch (e: Exception) {
                val user = kord.getUser(Snowflake(properties.ownerId))?.getDmChannelOrNull()
                user?.createMessage("Notification/Log Channel ID is Invalid!")
            }

            if (properties.notiChannelId != 0L) {
                discordLogger?.sendInitialEmbed(properties.notiChannelId)
            }
        }
    }
}
