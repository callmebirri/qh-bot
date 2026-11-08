package minecraft.ownership

import kotlinx.coroutines.runBlocking
import minecraft.ownership.model.MinecraftOwnershipResult

fun main() = runBlocking {
    val token = System.getenv("MS_TOKEN")
        ?: System.getenv("MICROSOFT_ACCESS_TOKEN")
        ?: System.getenv("MS_AUTH_TOKEN")

    if (token.isNullOrBlank()) {
        println("Please set the MS_TOKEN, MICROSOFT_ACCESS_TOKEN, or MS_AUTH_TOKEN environment variable.")
        return@runBlocking
    }

    val service = MinecraftOwnershipService()
    try {
        println("Checking Minecraft ownership for provided token...")
        val result = service.checkOwnership(token)
        when (result) {
            is MinecraftOwnershipResult.Owned -> {
                println("Result: OWNED")
                println("Profile: ${result.profile?.name ?: "No profile set"} (UUID: ${result.profile?.id ?: "N/A"})")
                println("Source: ${result.source}")
                println("Has Game Pass: ${result.hasGamePass}")
                println("Signatures count: ${result.signatures.size}")
            }
            is MinecraftOwnershipResult.NotOwned -> {
                println("Result: NOT OWNED")
                println("Reason: ${result.reason}")
            }
            is MinecraftOwnershipResult.Failure -> {
                println("Result: FAILURE")
                println("Reason: ${result.reason}")
                result.cause?.let {
                    println("Cause: ${it.message}")
                }
            }
        }
    } finally {
        service.close()
    }
}
