# Changelog

## 0.1.0-preview.1

Initial public preview of the shared Rust transport, Swift and Kotlin clients, .NET client/host SDK, and optional SwiftUI, Compose and WinUI connection controls.

The preview includes app-scoped pairing, pinned host identities, explicit private/VPN or cloud routes, independent multi-host connections, reconnect states, local forgetting and remote revocation. Reliable byte streams and bounded media packets share the authenticated transport.

Apple packages cover macOS 15 and iOS 18. Android packages cover API 26+, arm64-v8a and x86_64. Windows native packages cover x64. Mobile SDKs are companion clients; Mac and Windows expose host controls. The optional Apple fold adapter requires the iOS 27.1 SDK.

APIs and package formats may change before a stable release. The preview supplies no managed relay endpoint, codecs, application-specific authorization or end-user signed applications. See [validation limits](docs/VALIDATION.md) and [security policy](SECURITY.md).
