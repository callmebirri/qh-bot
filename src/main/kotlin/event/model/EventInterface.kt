package event.model

import config.BotPropertiesManager
import dev.kord.core.Kord

interface EventInterface {
    fun register(kord: Kord, properties: BotPropertiesManager)
}