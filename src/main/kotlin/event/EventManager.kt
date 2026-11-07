package event

import config.BotPropertiesManager
import dev.kord.core.Kord
import event.model.EventInterface

class EventManager(
    private val kord: Kord,
    private val properties: BotPropertiesManager,
    private val listEvent: List<EventInterface>
) {
    fun registerAll() {
        listEvent.forEach {
            it.register(kord, properties)
        }
    }
}