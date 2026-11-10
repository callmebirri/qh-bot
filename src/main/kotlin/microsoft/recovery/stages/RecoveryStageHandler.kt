package microsoft.recovery.stages

import microsoft.recovery.context.RecoveryContext
import microsoft.recovery.model.StageExecution

typealias StageListener = suspend (stageKey: String, stageName: String, isSuccess: Boolean, detail: String) -> Unit

interface RecoveryStageHandler {
    suspend fun execute(context: RecoveryContext, stageListener: StageListener?): StageExecution<Unit>
}
