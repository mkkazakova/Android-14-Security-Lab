plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "ru.securitylab.helper"
    compileSdk = 34
    defaultConfig {
        applicationId = "ru.securitylab.helper"
        versionCode = 1
        versionName = versionCode.toString()
        minSdk = 34
        targetSdk = 34
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    buildFeatures { buildConfig = true }
    
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies { implementation(project(":common")) }
