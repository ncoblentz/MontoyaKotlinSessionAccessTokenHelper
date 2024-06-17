plugins {
    kotlin("jvm") version "1.9.23"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.nickcoblentz.montoya"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    // https://mvnrepository.com/artifact/net.portswigger.burp.extender/montoya-api
    implementation("net.portswigger.burp.extensions:montoya-api:2023.12.1")
    //implementation("com.squareup.okhttp3:okhttp:4.12.0")
    //implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.json:json:+")

}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}