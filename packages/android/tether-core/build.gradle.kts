plugins { id("com.android.library"); id("maven-publish") }
android {
    namespace = "app.fledgeling.tether"
    compileSdk = 36
    ndkVersion = "27.1.12297006"
    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        externalNativeBuild { cmake { arguments += "-DTETHER_RUST_DIR=${rootProject.projectDir.parentFile.parentFile}/target" } }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    testOptions { unitTests.isReturnDefaultValues = true }
    publishing { singleVariant("release") { withSourcesJar() } }
}
dependencies { api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2"); implementation("com.squareup.okhttp3:okhttp:4.12.0"); testImplementation(kotlin("test-junit", "2.2.10")); testImplementation("org.json:json:20250517"); androidTestImplementation("androidx.test:runner:1.7.0"); androidTestImplementation("androidx.test.ext:junit:1.3.0") }

abstract class TetherNoticesTask : DefaultTask() {
    @get:InputFiles abstract val notices: ConfigurableFileCollection
    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty
    @TaskAction fun generate() { val folder=outputDirectory.get().dir("tether").asFile; folder.mkdirs(); notices.files.forEach { it.copyTo(folder.resolve(it.name), overwrite=true) } }
}
val copyTetherNotices = tasks.register<TetherNoticesTask>("copyTetherNotices") {
    notices.from(rootProject.projectDir.resolve("../../LICENSE"), rootProject.projectDir.resolve("../../THIRD_PARTY_NOTICES.txt"))
    outputDirectory.set(layout.buildDirectory.dir("generated/tetherNotices"))
}
androidComponents.onVariants { variant -> variant.sources.assets?.addGeneratedSourceDirectory(copyTetherNotices, TetherNoticesTask::outputDirectory) }
tasks.withType<Jar>().configureEach { from(listOf(rootProject.projectDir.resolve("../../LICENSE"),rootProject.projectDir.resolve("../../THIRD_PARTY_NOTICES.txt"))) { into("META-INF") } }
group = "app.fledgeling.tether"
version = "0.1.0-preview.1"

afterEvaluate {
    publishing {
        publications.create<MavenPublication>("release") {
            from(components["release"])
            artifactId="tether-core"
            pom { name.set("Tether Android Core"); description.set("App-scoped encrypted companion transport using the shared Rust protocol core"); url.set("https://github.com/fledgeling-co/tether"); licenses { license { name.set("MIT License"); url.set("https://opensource.org/license/mit") } }; scm { url.set("https://github.com/fledgeling-co/tether"); connection.set("scm:git:https://github.com/fledgeling-co/tether.git") } }
        }
        repositories { maven { name="localRelease"; url=uri(rootProject.layout.buildDirectory.dir("maven")) } }
    }
}
