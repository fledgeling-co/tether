# Changelog

## 0.1.0-preview.2

Apple packages now cover macOS 14 and iOS 17 as well as later releases; the Swift sources build at those floors and the native bridge is built for them. Nearby pairing and typed-code pairing run on one shared Rust flow in every kit, the copy on every Tether screen comes from the shared core, and a browser kit (`packages/web`) pairs through the relay.

The prebuilt Apple bridge in this release is built at those floors: macOS 14 for arm64 and x86_64, iOS 17 for device and simulator. The browser kit's source and [how Tether works](docs/how-tether-works.html) are published from this release onward.

## 0.1.0-preview.1

Initial public preview of the shared Rust transport, Swift and Kotlin clients, .NET client/host SDK, and optional SwiftUI, Compose and WinUI connection controls.

The preview includes app-scoped pairing, pinned host identities, explicit private/VPN or cloud routes, independent multi-host connections, reconnect states, local forgetting and remote revocation. Reliable byte streams and bounded media packets share the authenticated transport.

Apple packages cover macOS 15 and iOS 18. Android packages cover API 26+, arm64-v8a and x86_64. Windows native packages cover x64. Mobile SDKs are companion clients; Mac and Windows expose host controls. The optional Apple fold adapter requires the iOS 27.1 SDK.

APIs and package formats may change before a stable release. The preview supplies no managed relay endpoint, codecs, application-specific authorization or end-user signed applications. See [validation limits](docs/VALIDATION.md) and [security policy](SECURITY.md).
