package config

import java.io.File
import java.util.Properties

@Suppress("UNUSED")
class BotPropertiesManager {
    private var globalConfig: BotProperties = BotProperties(
        ownerId = 1L,
        guildId = 2L,
        logChannelId = 3L,
        notiChannelId = 4L,
    )

    init {
        reload()
    }

    fun reload() {
        globalConfig = loadConfig()
    }

    private fun loadConfig(path: String = "config.properties"): BotProperties {
        val file = File(path)
        if (!file.exists()) {
            return globalConfig
        }
        val props = Properties().apply { file.inputStream().use { load(it) } }
        fun parseId(key: String, default: Long = 0L): Long {
            val raw = props.getProperty(key)?.trim()?.removeSurrounding("\"")?.removeSurrounding("'") ?: return default
            return raw.toULongOrNull()?.toLong() ?: raw.toLongOrNull() ?: default
        }
        return BotProperties(
            ownerId = parseId("owner.id", 1L),
            guildId = parseId("guild.id", 2L),
            logChannelId = parseId("log.channel.id", 3L),
            notiChannelId = parseId("noti.channel.id", 0L),
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