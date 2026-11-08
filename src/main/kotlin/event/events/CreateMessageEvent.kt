package event.events

import config.BotPropertiesManager
import dev.kord.common.Color
import dev.kord.common.entity.Snowflake
import dev.kord.core.Kord
import dev.kord.core.behavior.channel.createEmbed
import dev.kord.core.entity.channel.TextChannel
import dev.kord.core.event.gateway.ReadyEvent
import dev.kord.core.on
import event.model.EventInterface

class CreateMessageEvent : EventInterface {
    override fun register(kord: Kord, properties: BotPropertiesManager) {
        kord.on<ReadyEvent> {
            val channel = kord.getChannelOf<TextChannel>(Snowflake(properties.logChannelId))
            channel?.createEmbed {
                title = "Birrii Auto Secure"
                color = Color(255, 0, 255)
                description = "Bot initialized successfully"
            } ?: run {
                val user = kord.getUser(Snowflake(properties.ownerId))?.getDmChannelOrNull()
                user?.createMessage("Notification/Log Channel ID is Invalid!")
            }
        }
    }
}
