# Build and install

Use the components you need. Transport libraries do not require the UI libraries, and no component embeds a browser or JavaScript runtime. Release archives contain several native architectures; the consuming app packages the architectures it supports.

## Apple

Add `https://github.com/fledgeling-co/tether.git` in Xcode's package dependencies and select `TetherKit` and optionally `TetherUI`. The root package downloads the checksummed native XCFramework from the matching GitHub release. The supported deployment targets are macOS 14 and iOS 17. The prebuilt bridge covers universal macOS, arm64 iOS devices and arm64 simulators.

For a source build, install Rust 1.89 and the Apple targets, then build the bridge:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
TETHER_BUILD_JOBS=2 bash scripts/build-xcframework.sh
swift test --package-path packages/TetherKit --jobs 2
```

The root package uses the local artifact when it exists. `packages/TetherKit` is also a standalone local package. Standard UI uses Swift 6 and the ordinary platform SDK. Link the separate `TetherDuoUI` product only when building with the iOS 27.1 SDK; apply `.tetherDuoLayout()` directly to the workspace. Other apps can supply their own fold geometry through `.tetherLayoutDivisions(_:)`.

Generate the native examples with XcodeGen. `TetherWorkspaceMac` and `TetherWorkspaceIOS` use the standard UI; `TetherWorkspaceDuo` opts into the newer SDK adapter:

```sh
xcodegen generate --spec examples/AppleWorkspace/project.yml
```

Mac hosting also needs `scripts/build-apple-helper.sh`. Bundle the generated helper and sign/notarize the complete app with your own identity. Configure your app's Keychain access group; development examples are not end-user signed distributions.

## Android

Use JDK 17+, Gradle 9.4.1, SDK 36, NDK 27.1.12297006 and CMake 3.22.1. Minimum application API level is 26. Install the two Rust targets, then build the shared core and Android modules:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
bash scripts/build-android.sh
cd packages/android
gradle --no-daemon --max-workers=2 :tether-core:testDebugUnitTest :tether-ui:testDebugUnitTest :tether-core:assembleRelease :tether-ui:assembleRelease :sample:assembleDebug
```

The native build uses `ANDROID_NDK_HOME` or the NDK under `ANDROID_HOME`/`ANDROID_SDK_ROOT`. No machine-specific `local.properties` is checked in. Follow [Android integration](ANDROID.md) for source-module and AAR dependencies.

## Windows

Use the .NET 10 SDK, Rust's MSVC toolchain and Visual Studio C++ build tools. Build both SDKs and check the packaged consumer:

```powershell
./scripts/windows/build.ps1 -Configuration Release -OutputDirectory "$env:TEMP/tether-artifacts"
./scripts/windows/verify-packages.ps1 -ArtifactsDirectory "$env:TEMP/tether-artifacts"
```

The output directory must be new. Add the generated Core and WinUI NuGets as a local package source, or download them from GitHub Releases. The Core package supplies its native library and owner helper and targets .NET 8. The WinUI package and sample require .NET 10. Only x64 native artifacts are currently supplied. [Windows integration](WINDOWS.md).

## Web

Install the `wasm32-unknown-unknown` Rust target and TypeScript, then build the browser core and package:

```sh
rustup target add wasm32-unknown-unknown
bash packages/web/scripts/build.sh
```

`packages/web/dist/` holds the ES modules and `tether.wasm`; serve the `.wasm` file as `application/wasm` beside them. Browsers pair only through a `wss://` relay. [Web kit](../packages/web/README.md).

## Shared Rust and relay

```sh
cargo build --workspace --locked --jobs 2
bash scripts/gate.sh
```

The CLI binaries are `tether`, `tether-relay` and `tether-server`. For public forwarding, use the allowlisted [container deployment](../deploy/README.md). Source publication and a healthy local container do not establish public reachability.
