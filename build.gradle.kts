plugins {
    kotlin("jvm") version "2.0.20"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("maven-publish")
    id("com.github.ben-manes.versions") version "0.51.0" //Gradle -> Help -> dependencyUpdates

}

group = "com.nickcoblentz.montoya"
version = "0.3.1"

repositories {
    mavenLocal()
    mavenCentral()
    maven(url="https://jitpack.io") {
        content {
            includeGroup("com.github.milchreis")
            includeGroup("com.github.ncoblentz")
        }
    }
}

dependencies {
    testImplementation(kotlin("test"))
    // https://mvnrepository.com/artifact/net.portswigger.burp.extender/montoya-api
    implementation("net.portswigger.burp.extensions:montoya-api:2024.7")
    //implementation("com.squareup.okhttp3:okhttp:4.12.0")
    //implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.json:json:+")
    //implementation("com.github.ncoblentz:BurpMontoyaLibrary:0.1.13")
    implementation("com.nickcoblentz.montoya:MontoyaLibrary:0.1.21")
    implementation("com.github.milchreis:uibooster:1.21.1")

}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}