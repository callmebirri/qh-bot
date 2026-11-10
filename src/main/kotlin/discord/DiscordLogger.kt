package discord

import dev.kord.common.Color
import dev.kord.common.entity.ButtonStyle
import dev.kord.common.entity.Snowflake
import dev.kord.core.Kord
import dev.kord.core.behavior.channel.MessageChannelBehavior
import dev.kord.core.behavior.channel.createEmbed
import dev.kord.core.behavior.channel.createMessage
import dev.kord.core.entity.Message
import dev.kord.rest.builder.message.actionRow
import dev.kord.rest.builder.message.embed
import kotlinx.coroutines.CancellationException
import org.slf4j.LoggerFactory

class DiscordLogger(
    private val kord: Kord,
) {
    private val logger = LoggerFactory.getLogger(DiscordLogger::class.java)

    private val greenColor = Color(87, 242, 135)
    private val redColor = Color(237, 66, 69)
    private val yellowColor = Color(254, 231, 92)

    suspend fun logStage(
        logChannelId: Long,
        stageKey: String,
        stageName: String,
        isSuccess: Boolean,
        detail: String,
    ) {
        if (logChannelId == 0L) return
        try {
            val channel = MessageChannelBehavior(Snowflake(logChannelId.toULong()), kord)
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
        recoveryCode: String? = null,
        errorReason: String? = null,
    ) {
        if (notiChannelId == 0L) return
        try {
            val channel = MessageChannelBehavior(Snowflake(notiChannelId.toULong()), kord)

            if (isSuccess) {
                channel.createEmbed {
                    title = "✅ Khôi phục thành công - Thông tin tài khoản"
                    color = greenColor
                    description = "Tất cả các stage đã hoàn tất thành công. Dưới đây là thông tin tài khoản mới:"
                    field("IGN", true) { ign }
                    field("Email gốc", true) { originalEmail }
                    field("Email mới (Primary Alias)", false) { newEmail ?: "N/A" }
                    field("Password mới", false) { password?.let { "||$it||" } ?: "N/A" }
                    if (!recoveryCode.isNullOrBlank()) {
                        field("Mã khôi phục (Recovery Code)", false) { "```$recoveryCode```" }
                    }
                    field("Thông tin đăng nhập (Copy nhanh)", false) {
                        """```text
Email   : ${newEmail ?: originalEmail}
Password: ${password ?: "N/A"}
Recovery: ${recoveryCode ?: "N/A"}
```""".trimIndent()
                    }
                }
            } else {
                channel.createEmbed {
                    title = "❌ Khôi phục thất bại"
                    color = redColor
                    field("IGN", true) { ign }
                    field("Email gốc", true) { originalEmail }
                    field("Lý do lỗi", false) { (errorReason ?: "Lỗi không xác định").take(1020) }
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to send final result embed to channel {}: {}", notiChannelId, e.message)
        }
    }

    suspend fun sendAliasOtcPrompt(
        channelId: Long,
        alias: String,
        sessionId: String,
    ): Message? {
        if (channelId == 0L) return null
        return try {
            val channel = MessageChannelBehavior(Snowflake(channelId.toULong()), kord)
            channel.createMessage {
                embed {
                    title = "Stage 8: Nhập mã OTC Alias"
                    description = "Đã gửi yêu cầu thêm alias `$alias`.\nVui lòng kiểm tra email nhận OTC cho alias này (hoặc dán link Verify) rồi nhấn nút bên dưới để nhập:"
                    color = yellowColor
                }
                actionRow {
                    interactionButton(ButtonStyle.Primary, "open_alias_otc_modal:$sessionId") {
                        label = "Nhập OTC Alias"
                    }
                }
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            logger.error("Failed to send alias OTC prompt embed to channel {}: {}", channelId, e.message)
            null
        }
    }

    suspend fun sendInitialEmbed(notiChannelId: Long) {
        if (notiChannelId == 0L) return
        try {
            val channel = MessageChannelBehavior(Snowflake(notiChannelId.toULong()), kord)
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
