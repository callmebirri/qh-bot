plugins {
    kotlin("jvm") version "2.4.21"
}

group = "tech.qhuyy"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven("https://snapshots.kord.dev")
}

dependencies {
    testImplementation(kotlin("test"))
    implementation(libs.kord.core)
    implementation(libs.koin.core)
}

kotlin {
    jvmToolchain(21)
}