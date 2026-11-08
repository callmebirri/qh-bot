plugins {
    kotlin("jvm") version "2.4.21"
    kotlin("plugin.serialization") version "2.4.20"
    application
    id("com.gradleup.shadow") version "9.6.1"
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
    implementation(libs.jsoup)
    implementation(libs.sqlite.jdbc)
    implementation(libs.hikaricp)
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("tech.qhuyy.Main")
}

tasks.jar {
    archiveClassifier.set("plain")
    manifest {
        attributes["Main-Class"] = "tech.qhuyy.Main"
    }
}

tasks.shadowJar {
    archiveClassifier.set("")
    manifest {
        attributes["Main-Class"] = "tech.qhuyy.Main"
    }
}

tasks.distZip { dependsOn(tasks.shadowJar) }
tasks.distTar { dependsOn(tasks.shadowJar) }
tasks.startScripts { dependsOn(tasks.shadowJar) }

tasks.register<JavaExec>("runDemo") {
    group = "application"
    description = "Runs the Minecraft ownership demo"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("minecraft.ownership.MinecraftOwnershipDemoKt")
}