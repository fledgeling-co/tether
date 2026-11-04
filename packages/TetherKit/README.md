# TetherKit

Swift 6 client and Mac host SDK for macOS 15 and iOS 18, with a separate `TetherUI` library for native host/client controls. Link the optional `TetherDuoUI` product with Xcode 27.1 or newer for Duo reserved-region APIs; standard `TetherUI` does not require them. Add this directory as a local Swift package after running `scripts/build-xcframework.sh` from the repository root. The script builds the Rust C bridge for universal macOS, iOS devices and Apple Silicon simulators. Generated artifacts stay local.

```swift
let client = try TetherClient(appID: "app.example.notes")
let route = TetherRoute.cloud(relayURL: relayURL, hostID: hostID)
let peer = try await client.pair(route: route, code: typedCode)
let stream = try await client.openService("notes-api", kind: .tcp, peer: peer)
try await stream.send(requestBytes)
let reply = try await stream.receive()
try await stream.finishSending()
await stream.close()
```

`TetherConnectionStore` manages independent hosts, selection, reconnect, online observations and per-host streams. `TetherWorkspaceView(store:)` supplies native pairing, host details, route changes and removal. Mac hosts use `TetherHostController` and `TetherHostSettingsView` with a fixed bundled helper URL. See the repository's `docs/FRAMEWORKS.md` for integration examples; SDK archives include that guide under `docs/`.

Build the universal Mac helper with `scripts/build-apple-helper.sh`. SDK archives include it at `Artifacts/Helpers/tether`; embed it at `Contents/Helpers/tether` and sign and notarize your complete application. Its development signature does not establish release approval.

The app supplies the relay URL and public host ID from its host setup. For private access, choose `.privateNetwork(host: macAddress, port: port)` instead. Routes never fall back automatically. Cloud routes require WSS; the explicit loopback test option permits WS only on numeric loopback addresses.

Pairing and every service connection use the shared Rust Noise and SPAKE2 implementation. The host key is pinned before the client reveals its static key on subsequent connections. The host owns the fixed service allowlist, grants and revocation; a client never supplies a target IP or port.

For direct LAN access, the embedding iOS app supplies its local-network usage description and handles the system permission decision. The SDK does not bypass app signing or Keychain access requirements.

The default stores keep distinct application identities and peer records in this-device-only Keychain items. A pending record is saved before acknowledgement and becomes confirmed only after the host commits. `records()` includes pending entries. Use `recover(record)` after a lost completion message. If the host never received the acknowledgement, explicitly call `discardPendingPairing(record)`, obtain a fresh owner code and pair again. This operation refuses confirmed trust, another application's record and a replaced pairing generation. Connection errors never reset trust.

Await each send and receive. One operation per direction is admitted at a time, with up to eight open streams per client. Plaintext records are limited to 16 KiB; carrier frames to 64 KiB. Opening and control exchanges time out after 15 seconds; idle reads after 60 seconds. Cancellation closes the affected carrier. TCP `receive()` returns nil on authenticated half-close; `finishSending()` sends the local half-close. UDP preserves one datagram per record, including empty datagrams.

Managed connections reserve control capacity and admit six streams per host. Selecting another host leaves existing streams intact. Leave waits for durable host revocation before deleting local trust; explicit local forgetting leaves the host's grant unchanged. Route changes probe the existing host pin before an atomic generation-checked replacement. Offline or changed-identity responses never reset trust.

`openMedia(_:peer:)` provides a private/VPN QUIC datagram lease using the shared Rust backend. Its certificate pin and one-use capability arrive inside the authenticated Noise session, which remains open for lease heartbeats. Respect `maximumDatagramSize`, handle `.mediaBackpressure` by dropping or scheduling application packets, and close the session explicitly. Video/audio encoding and packetization belong to the app. `openReliablePacketStream(_:peer:)` explicitly chooses UDP packets inside the reliable TCP/WSS carrier; it is separate from the datagram fast path and never an automatic fallback.

`TetherIdentityPersistence` and `TetherPeerPersistence` allow app-owned persistence adapters. Peer adapters must provide durable saves before returning and atomically refuse `discardPending` when the pairing generation changed or became confirmed. Confirmed removal and route replacement also require atomic generation checks; older custom adapters fail closed by default. The default Keychain implementation uses an item attribute predicate for these checks.

Run `swift test --package-path packages/TetherKit --jobs 2` for native Rust/Swift crypto interoperability. After building `tether` and `tether-relay`, run `python3 packages/TetherKit/Tests/Fixtures/run_live.py` for real Rust-host TCP/UDP forwarding over both direct and loopback relay routes. The fixture uses temporary private configurations and injected stores, not the user's Keychain. Public WSS operation and physical-device behavior need their own validation.

The relay sees routing metadata and encrypted bytes; the Mac remains the application server. This protocol composition has not been audited. Owned bridge buffers are cleared, but Swift/Foundation and upstream cryptographic temporary copies are not guaranteed to be wiped. Requests, responses, pairing codes and identity material must never be logged.

The default Data Protection Keychain providers require the embedding app's application identifier and Keychain access group. On macOS, restricted Keychain entitlements require a matching provisioning profile. These providers do not silently fall back to another key store; an app can explicitly inject its own persistence adapter.

The shared native metadata test runs in `ValidationHost`, using only UUID-scoped synthetic items and exact-account cleanup. Generate its project with `xcodegen generate --spec packages/TetherKit/ValidationHost/project.yml`. Run the `TetherSDKValidationIOS` scheme on an owned iOS simulator with a contributor-supplied `TETHER_VALIDATION_TEAM`, or `TetherSDKValidation` on macOS with a matching application profile. The schemes opt in automatically and the preflight refuses authentication UI. Ordinary SwiftPM runs skip this app-host-only test. The macOS profile requirement remains separate from successful iOS simulator checks.

```sh
xcodebuild -project packages/TetherKit/ValidationHost/TetherSDKValidation.xcodeproj \
  -scheme TetherSDKValidationIOS \
  -destination "platform=iOS Simulator,id=$TETHER_SIMULATOR_UUID" \
  -parallel-testing-enabled NO -jobs 2 CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- test
```

The simulator scheme writes status, phase and cleanup counts to the validation app's Documents directory. Its evidence contains no key material. Use `scripts/validation/macos-keychain.py` to select the development profile, team and a fresh evidence directory for the macOS scheme.

Retain `LICENSE` and `THIRD_PARTY_NOTICES.txt` when distributing the bridge or embedding it in an app. GitHub release artifacts include the generated native bridge and those notices.
