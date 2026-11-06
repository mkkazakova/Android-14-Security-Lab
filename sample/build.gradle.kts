plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "ru.securitylab.sample"
    compileSdk = 34
    defaultConfig {
        applicationId = "ru.securitylab.sample"
        versionCode = providers.gradleProperty("sampleVersion").orElse("1").get().toInt()
        versionName = versionCode.toString()
        minSdk = 34
        targetSdk = 34
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    buildFeatures { buildConfig = true }
    signingConfigs { create("laboratory") {
            storeFile = rootProject.file(".lab-secrets/" + providers.gradleProperty("sampleSigner").orElse("a").get() + ".p12")
            storePassword = "laboratory-only"; keyAlias = "lab"; keyPassword = "laboratory-only"
        } }
        buildTypes { getByName("debug") { signingConfig = signingConfigs.getByName("laboratory") } }
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies { implementation(project(":common")) }
