plugins {
    kotlin("jvm") version "2.4.21"
    kotlin("plugin.serialization") version "2.4.20"
}

group = "tech.qhuyy"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven("https://snapshots.kord.dev")
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation(libs.ktor.client.mock)
    implementation(libs.kord.core)
    implementation(libs.koin.core)
    implementation(libs.kseri.core)
    implementation(libs.kcorou.core)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.okhttp)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.logback.classic)
}

kotlin {
    jvmToolchain(21)
}

tasks.register<JavaExec>("runDemo") {
    group = "application"
    description = "Runs the Minecraft ownership demo"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("minecraft.ownership.MinecraftOwnershipDemoKt")
}