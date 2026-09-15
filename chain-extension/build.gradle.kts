plugins {
    java
}

repositories { mavenCentral() }

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.10")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.4")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}

java { toolchain { languageVersion = JavaLanguageVersion.of(26) } }

tasks.test { useJUnitPlatform() }

tasks.jar {
    archiveFileName = "burp-request-chain.jar"
    manifest { attributes["Main-Class"] = "com.example.burpchain.ChainExtension" }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
