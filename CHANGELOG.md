# Changelog

## 0.1.0-preview.6

`TetherHostController` on macOS now takes `allowInsecureLoopbackForTesting: Bool = false`, matching `TetherClient`, the .NET `TetherHostController` and the `tether` CLI. When enabled, `TetherHostRoute.cloud(relayURL:)` accepts `ws://` URLs targeting `127.0.0.1`, `[::1]` or `::1` and emits `--allow-loopback-dev` to the helper; when disabled (the default), only `wss://` is accepted, and non-loopback `ws://`, `localhost`, credentials, queries and fragments are refused in both modes.

Windows packages move to `0.1.0-preview.6` and the Apple prebuilt bridge is rebuilt at the same macOS 14 and iOS 17 floors.

## 0.1.0-preview.5

A .NET host's `IdentityKeyFile` must now be a drive-letter rooted path on a fixed local volume, and the path is compared against its own normalized form rather than normalized for the caller. `Path.IsPathFullyQualified` accepted `\\server\share`, `\\?\C:\…` and `\\.\C:\…`, so preview.4 would have let a profile name the host's own identity key on a network share or through the device namespace; it is the host's secret, read on every connection, and it belongs on local disk. A path holding `..` or `.` is refused rather than collapsed. A plain absolute path such as `C:\ProgramData\example\identity.key` is unaffected.

## 0.1.0-preview.4

A .NET host can now ask for the peer-identity proof. `HostServiceProfile` takes an `IdentityKeyFile` — an absolute path to the private 32-byte key file the service also holds — and `host init` emits `--identify <id>=<path>` for every service that carries one, so a Windows host proves the connecting device to its service before any application byte reaches it. The Rust CLI and the Swift SDK's `identityKeyFile` already did this; a .NET host had to run `tether.exe host init --identify` itself. TCP only, and a relative path, a URL or a UDP service is refused, as on Swift. Nothing changes for a profile without a key file.

Windows packages move to `0.1.0-preview.4`; the Apple packages and their prebuilt bridge are rebuilt at the same macOS 14 and iOS 17 floors.

## 0.1.0-preview.3

A nearby invite now carries a one-time token the invited device mints. The device answers every connection to its invite listener with a fresh 32-byte token, an invite is read only when it echoes that token, and the device repeats it in `pair.nearby`, so a host's owner sheet marks a request as invited by that token rather than by the name a peer announced. Both ends of an invite must be at this release: an older host sends no token and is refused, and an older device sends no challenge, so a newer host's invite never goes out. Browsing, typed-code pairing and the code comparison are unchanged, and the code comparison is still the only thing that decides trust.

Writing a host configuration no longer waits for ever on another writer. `update_host`, `confirm_client` and `abandon_pending` take the lock with a ten-second bound and then fail with a message naming the lock file and the process holding it, and the lock file is removed by its holder instead of accumulating beside every configuration. A lock file with no live holder never blocked anything and still does not; what changed is that a live holder is now a bounded wait and a readable error.

Windows packages are published as release assets for the first time: `Fledgeling.Tether.Windows` and `Fledgeling.Tether.WinUI` at `0.1.0-preview.3`, carrying the Windows x64 `tether_ffi.dll` and `tether.exe`, so a consumer references the SDK without a Rust toolchain. Apple packages still cover macOS 14 and iOS 17, and the prebuilt bridge in this release is built at those floors.

## 0.1.0-preview.2

Apple packages now cover macOS 14 and iOS 17 as well as later releases; the Swift sources build at those floors and the native bridge is built for them. Nearby pairing and typed-code pairing run on one shared Rust flow in every kit, the copy on every Tether screen comes from the shared core, and a browser kit (`packages/web`) pairs through the relay.

The prebuilt Apple bridge in this release is built at those floors: macOS 14 for arm64 and x86_64, iOS 17 for device and simulator. The browser kit's source and [how Tether works](docs/how-tether-works.html) are published from this release onward.

## 0.1.0-preview.1

Initial public preview of the shared Rust transport, Swift and Kotlin clients, .NET client/host SDK, and optional SwiftUI, Compose and WinUI connection controls.

The preview includes app-scoped pairing, pinned host identities, explicit private/VPN or cloud routes, independent multi-host connections, reconnect states, local forgetting and remote revocation. Reliable byte streams and bounded media packets share the authenticated transport.

Apple packages cover macOS 15 and iOS 18. Android packages cover API 26+, arm64-v8a and x86_64. Windows native packages cover x64. Mobile SDKs are companion clients; Mac and Windows expose host controls. The optional Apple fold adapter requires the iOS 27.1 SDK.

APIs and package formats may change before a stable release. The preview supplies no managed relay endpoint, codecs, application-specific authorization or end-user signed applications. See [validation limits](docs/VALIDATION.md) and [security policy](SECURITY.md).
