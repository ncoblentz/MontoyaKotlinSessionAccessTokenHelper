plugins {
    kotlin("jvm") version "2.2.0"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("com.github.ben-manes.versions") version "0.51.0" //Gradle -> Help -> dependencyUpdates

}

group = "com.nickcoblentz.montoya"
version = "0.3.5"

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
    implementation("net.portswigger.burp.extensions:montoya-api:2025.6")
    //implementation("com.squareup.okhttp3:okhttp:4.12.0")
    //implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.json:json:+")
    implementation("com.github.ncoblentz:BurpMontoyaLibrary:0.1.27")
    //implementation("com.nickcoblentz.montoya:MontoyaLibrary:0.1.21")
    implementation("com.github.milchreis:uibooster:1.21.1")

}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}
