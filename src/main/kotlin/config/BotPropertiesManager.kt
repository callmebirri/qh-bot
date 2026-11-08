package config

import java.io.File
import java.util.*

@Suppress("UNUSED")
class BotPropertiesManager {
    private var globalConfig: BotProperties = BotProperties(
        ownerId = 1,
        guildId = 2,
        logChannelId = 3,
        notiChannelId = 4,
    )

    init {
        reload()
    }

    fun reload() {
        globalConfig = loadConfig()
    }

    private fun loadConfig(path: String = "config.properties"): BotProperties {
        val props = Properties().apply { File(path).inputStream().use { load(it) } }
        return BotProperties(
            ownerId = props.getProperty("owner.id").toLong(),
            guildId = props.getProperty("guild.id").toLong(),
            logChannelId = props.getProperty("log.channel.id").toLong(),
            notiChannelId = props.getProperty("noti.channel.id")?.toLongOrNull() ?: 0L,
        )
    }

    val ownerId: Long get() = globalConfig.ownerId
    val guildId: Long get() = globalConfig.guildId
    val logChannelId: Long get() = globalConfig.logChannelId
    val notiChannelId: Long get() = globalConfig.notiChannelId
}

data class BotProperties(
    val ownerId: Long,
    val guildId: Long,
    val logChannelId: Long,
    val notiChannelId: Long = 0L,
)