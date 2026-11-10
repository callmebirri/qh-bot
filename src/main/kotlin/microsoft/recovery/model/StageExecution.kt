package microsoft.recovery.model

sealed class StageExecution<out T> {
    data class Success<out T>(val value: T) : StageExecution<T>()
    data class Failure(val result: RecoveryResult.Failure) : StageExecution<Nothing>()
}
