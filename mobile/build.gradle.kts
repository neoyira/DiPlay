plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Optional local-only input. CI and ordinary source builds contain no accessory identity.
val localAuthenticationAssets = providers.environmentVariable("DIPLAY_AUTH_ASSETS_DIR")
    .orNull?.let { file(it).canonicalFile } ?: layout.buildDirectory.dir("generated/mfiAssets").get().asFile.apply {
        val mfiDir = resolve("offline-mfi").apply { mkdirs() }
        mfiDir.resolve("identity.pk8").writeBytes(java.util.Base64.getDecoder().decode("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAv4C+7aHy52zIUZMW2bAJVb+f2A+E88wS9ep/vXJi6hg=="))
        mfiDir.resolve("certificate.p7b").writeBytes(java.util.Base64.getDecoder().decode("MIICWwYJKoZIhvcNAQcCoIICTDCCAkgCAQExADALBgkqhkiG9w0BBwGgggIuMIICKjCCAdGgAwIBAgIQJKy7SGRvgHf3RjUjCFtg0jAKBggqhkjOPQQDAjCBiTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MT0wOwYDVQQDEzRBcHBsZSBBY2Nlc3NvcmllcyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIDAwMDAwMDAyMB4XDTE4MDYxMzA4MzI1OVoXDTQ5MTIzMTIzNTk1OVowbTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xGjAYBgNVBAsTEUFwcGxlIEFjY2Vzc29yaWVzMS0wKwYDVQQDFCRJUEFfMjRBQ0JCNDg2NDZGODA3N0Y3NDYzNTIzMDg1QjYwRDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT0mPfItJFateYmSe89Z9Bpf4HwogWewlz3ZfUgQkbuxvuvw9vGmuyMlitYkr7QNJM9/J4shFRgN1GesptbVnEpozYwNDAyBgkqhkiG92NkBiQBAf8EIgQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIwCgYIKoZIzj0EAwIDRwAwRAIgaYL03y8Xje/EKdEqhBoRJLB071JCP69YmNOQXVv+qfkCIFngsPKacTAAVavi1E47l28ltIQslTc7ABuQ5c+lt47AoQAxAA=="))
    }.canonicalFile

android {
    namespace = "com.shilapi.xcertplay"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.shihab.diplay"
        minSdk = 24
        targetSdk = 37
        versionCode = 41
        versionName = "0.2.22"

    }


    localAuthenticationAssets?.let { sourceSets.getByName("main").assets.srcDir(it) }

    signingConfigs {
        create("release") {
            storeFile = file(
                providers.environmentVariable("ANDROID_KEYSTORE_PATH")
                    .getOrElse("missing-release-keystore.jks"),
            )
            storePassword = providers.environmentVariable("ANDROID_KEYSTORE_PASSWORD").getOrElse("")
            keyAlias = providers.environmentVariable("ANDROID_KEY_ALIAS").getOrElse("")
            keyPassword = providers.environmentVariable("ANDROID_KEY_PASSWORD").getOrElse("")
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".hudtest"
            versionNameSuffix = "-hud-test"
        }
        release {
            optimization {
                enable = false
            }
            signingConfig = if (providers.environmentVariable("ANDROID_KEYSTORE_PATH").isPresent) signingConfigs.getByName("release") else signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(project(":common"))
    implementation(project(":shared"))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.app.projected)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    debugImplementation(libs.androidx.compose.ui.tooling)
}

// No implicit import. Only the two explicitly selected local runtime assets are allowed.
val credentialAssets = files(android.sourceSets.flatMap { source ->
    source.assets.directories.map { directory ->
        fileTree(directory) {
            include("**/offline-mfi/**", "**/*.pk8", "**/*.p7b", "**/*.key",
                "**/*.pem", "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.keystore")
        }
    }
})
val rejectBundledCredentials by tasks.registering {
    group = "verification"
    description = "Reject unexpected credential files in APK assets."
    val filesToCheck = credentialAssets
    val allowed = localAuthenticationAssets?.let { dir ->
        listOf("identity.pk8", "certificate.p7b").map { dir.resolve("offline-mfi/$it").canonicalFile }.toSet()
    } ?: emptySet()
    inputs.files(filesToCheck)
    doLast {
        check(allowed.all { it.isFile }) { "Explicit local authentication assets are incomplete" }
        val unexpected = filesToCheck.files.filter { it.canonicalFile !in allowed }
        check(unexpected.isEmpty()) { "Unexpected credential files in APK assets" }
    }
}
tasks.named("preBuild") { dependsOn(rejectBundledCredentials) }

// Car-test packages must be standalone. Keep ordinary source/CI builds identity-free.
val verifyStandaloneAuthentication by tasks.registering {
    group = "verification"
    description = "Require the explicit runtime authentication input for a standalone car-test APK."
    val directory = localAuthenticationAssets
    doLast {
        check(directory != null) {
            "Standalone car builds require DIPLAY_AUTH_ASSETS_DIR; assembleDebug alone is source-only."
        }
        check(listOf("identity.pk8", "certificate.p7b").all {
            directory.resolve("offline-mfi/$it").let { file -> file.isFile && file.length() > 0 }
        }) { "Standalone CarPlay authentication files are missing or empty" }
    }
}
tasks.named("preBuild") { mustRunAfter(verifyStandaloneAuthentication) }
tasks.register("assembleStandaloneDebug") {
    group = "build"
    description = "Build a standalone car-test APK with explicitly provisioned authentication."
    dependsOn(verifyStandaloneAuthentication, "assembleDebug")
}
