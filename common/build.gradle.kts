plugins { id("com.android.library"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "ru.securitylab.common"
    compileSdk = 34
    defaultConfig {
        
        minSdk = 34
        
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    buildFeatures { buildConfig = true }
    
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

