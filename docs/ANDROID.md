# Android integration

Android is a companion client for a Mac or Windows host. `tether-core` wraps the shared Rust protocol through a small JNI bridge. `tether-ui` adds optional native Material 3 Compose controls. The core has no Compose, camera or barcode dependency.

## Add the modules

Build the Rust Android targets before assembling the Android modules; [the build guide](INSTALLING.md) lists versions and commands. The supplied ABIs are arm64-v8a and x86_64, with minimum API 26 and Java 17 bytecode. Use source modules or download `Tether-0.1.0-preview.1-Android-maven.zip` from [Releases](https://github.com/fledgeling-co/tether/releases). The archive contains a local Maven repository with AARs, source JARs and dependency metadata; it is not a Maven Central publication.

Extract the archive into `third_party/tether`, then add its repository in your app's Gradle settings:

```kotlin
dependencyResolutionManagement {
    repositories {
        maven { url = uri("third_party/tether/maven") }
        google()
        mavenCentral()
    }
}
```

Add `implementation("app.fledgeling.tether:tether-core:0.1.0-preview.1")` for transport, or `implementation("app.fledgeling.tether:tether-ui:0.1.0-preview.1")` for UI and transport together. The Maven metadata declares transitive dependencies. Build the same local repository from source with `gradle :tether-core:publish :tether-ui:publish` after the native build; output is `packages/android/build/maven`.

In this preview, the Core AAR is 5.28 MiB with both native ABIs; the UI AAR is 147 KiB. Dependencies are unbundled, so these are archive sizes rather than installed-app sizes. Use the consuming app's ABI filters or app-bundle splits to ship its required architectures.

When importing AAR files directly, also declare their unbundled dependencies. Core requires `kotlinx-coroutines-android:1.10.2` and `okhttp:4.12.0`. UI additionally requires Compose UI/Runtime/Foundation `1.10.0`, Material 3 `1.4.0`, Activity Compose `1.11.0` and Lifecycle Runtime Compose `2.9.3`. A consuming Compose app configures the Compose compiler plugin. Source-module Gradle dependencies declare the library dependencies automatically. The sample shows the complete configuration.

Keep a stable product-specific application ID and use the application context:

```kotlin
val client = TetherClient(context.applicationContext, "com.example.companion")
val connections = TetherConnectionStore(client)

// Within your app's MaterialTheme:
TetherWorkspace(
    store = connections,
    onOpenService = { hostId, service -> /* Open your own content UI. */ }
)
```

Own the store in a ViewModel or equivalent lifecycle owner. `connections.close()` ends its monitors and streams and closes its client. The UI does not close an app-owned store merely because a composable leaves composition. A `ComposeView` can embed the same components in an existing View-based app; use a composition strategy tied to that screen's lifecycle.

## Pairing and services

The workspace supports explicit private/VPN and cloud routes, manual pairing, app-scoped invitation import, reconnect, route editing, pending-pairing recovery and separate leave/local-forget confirmations. Supply `onScanInvitation` only when your app has a scanner; permission handling and scanning remain app-owned.

Use `connections.openService(hostId, serviceId, kind)` for an authorized stream or reliable packet service. Your app provides bounded message framing and request semantics. `connections.openMedia(hostId, serviceId)` selects the private/VPN QUIC path; encoded media and packetization remain your responsibility. Respect negotiated packet limits, close returned resources and handle cancellation. Cloud WebSocket packet forwarding retains TCP ordering. No API write is replayed automatically.

The connection store admits up to six pending/open services per host, and the client admits eight across hosts. A stream supports one sender and one receiver concurrently; overlapping calls in the same direction report `busy` without closing a healthy stream. Close or cancel an unused receive to release its resources. These are connection bounds, not a measured video bitrate or UI-frame guarantee.

## Protected state

Identity and peer records live in the application's no-backup directory, encrypted with an app-scoped Android Keystore AES-GCM key. File updates are atomic and use generation checks. API 28+ requests unlocked-device use; API 26/27 cannot provide that same restriction. Losing access to a stored key or failing authentication does not authorize silently replacing an identity.

The wrapping key may be hardware protected depending on the device. The Noise identity is loaded into trusted process memory; it is not a hardware-backed X25519 key. The SDK does not promise protection from a compromised application process, complete erasure of Kotlin/JSON temporary copies or isolation between code inside the same app.

The sample uses a private profile and separates synthetic layout fixtures from actual connections. Native instrumentation, Keystore checks and host interoperability are reported separately in [validation](VALIDATION.md). Successful compilation alone is not Android-device or internet acceptance.
