plugins {
    kotlin("jvm") version "1.9.23"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("maven-publish")
    id("com.github.ben-manes.versions") version "0.51.0" //Gradle -> Help -> dependencyUpdates
    id("org.owasp.dependencycheck") version "10.0.1" // owasp dependency-check -> dependencyCheckAnalyze

}

group = "com.nickcoblentz.montoya"
version = "0.1"

repositories {
    mavenLocal()
    mavenCentral()
    maven(url="https://jitpack.io")
}

dependencies {
    testImplementation(kotlin("test"))
    // https://mvnrepository.com/artifact/net.portswigger.burp.extender/montoya-api
    implementation("net.portswigger.burp.extensions:montoya-api:2023.12.1")
    //implementation("com.squareup.okhttp3:okhttp:4.12.0")
    //implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.json:json:+")
    implementation("com.nickcoblentz.montoya:MontoyaLibrary:0.1.8")
    implementation("com.github.milchreis:uibooster:1.21.1")

}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}