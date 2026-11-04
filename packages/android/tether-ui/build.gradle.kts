plugins {
    id("com.android.library")
    id("maven-publish")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "app.fledgeling.tether.ui"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    publishing { singleVariant("release") { withSourcesJar() } }
    buildFeatures { compose = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":tether-core"))
    api("androidx.compose.ui:ui:1.10.0")
    api("androidx.compose.runtime:runtime:1.10.0")
    implementation("androidx.compose.material3:material3:1.4.0")
    implementation("androidx.compose.foundation:foundation:1.10.0")
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.3")
    testImplementation("junit:junit:4.13.2")
}


abstract class TetherUiLicenseTask : DefaultTask() {
    @get:InputFiles abstract val notices: ConfigurableFileCollection
    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty
    @TaskAction fun generate() {
        val folder = outputDirectory.get().dir("tether").asFile
        folder.mkdirs()
        notices.files.forEach { it.copyTo(folder.resolve(it.name), overwrite = true) }
    }
}
val copyTetherUiLicense = tasks.register<TetherUiLicenseTask>("copyTetherUiLicense") {
    notices.from(rootProject.projectDir.resolve("../../LICENSE"))
    outputDirectory.set(layout.buildDirectory.dir("generated/tetherLicense"))
}
androidComponents.onVariants { variant ->
    variant.sources.assets?.addGeneratedSourceDirectory(copyTetherUiLicense, TetherUiLicenseTask::outputDirectory)
}
tasks.withType<Jar>().configureEach {
    from(rootProject.projectDir.resolve("../../LICENSE")) { into("META-INF") }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                groupId = "app.fledgeling.tether"
                artifactId = "tether-ui"
                version = "0.1.0-preview.1"
                from(components["release"])
                pom {
                    name.set("Tether Android UI")
                    description.set("Optional native Compose pairing and multi-host workspace for Tether clients")
                    url.set("https://github.com/fledgeling-co/tether")
                    licenses { license { name.set("MIT License"); url.set("https://opensource.org/licenses/MIT") } }
                    scm { url.set("https://github.com/fledgeling-co/tether") }
                }
            }
        }
        repositories { maven { name = "LocalPreview"; url = uri(rootProject.layout.buildDirectory.dir("maven")) } }
    }
}
