# Embed Tether

Tether owns app-scoped device trust, encrypted connections and fixed service grants. Your app owns the data, codecs and API handlers on the host. The relay forwards ciphertext. This project contains Swift `TetherKit`, SwiftUI `TetherUI`, Kotlin/JNI `tether-core`, Compose `tether-ui`, and Windows .NET/WinUI components backed by the same Rust cryptographic implementation.

## Apple client

Add the root GitHub Swift package, or `packages/TetherKit` as a local package, and link `TetherKit` and optionally `TetherUI`. Build the native artifact with `scripts/build-xcframework.sh` before opening an example. The package supports macOS 15 and iOS 18; the fold observer uses iOS 27.1 APIs behind availability checks.

```swift
import TetherKit
import TetherUI

let client = try TetherClient(appID: "com.example.yourapp")
let connections = try TetherConnectionStore(client: client)
// Hold connections for the owning scene's lifetime.
TetherWorkspaceView(store: connections) { hostID, service in
    // Your app opens a granted service and presents its own content.
}
```

Use a stable identifier unique to your app. Identities and peer records use separate device-only Keychain items. Never share another product's app ID, host profile or pairing code. Embedding apps provide camera and local-network usage descriptions. Camera denial leaves manual pairing available.

`TetherWorkspaceView` provides host selection, pairing, saved identity display, reconnect, route editing and removal. `TetherPairHostView`, `TetherRouteEditor` and `TetherAdaptiveWorkspace` are independently reusable. Native system controls inherit the embedding app's accent and accessibility settings. The adaptive container observes each window's UIKit division regions; it does not infer a fold from a device name or fixed width.

A connection store preserves every paired host independently. Selecting one host does not disconnect another. Call `stopMonitoring()` when its owning scene no longer needs monitoring. A saved record initially appears offline; an authenticated host response establishes connected status. The store reserves control capacity and admits at most six managed service streams per host. Close streams explicitly when finished. The host separates eight data sessions from its 24-slot carrier/control budget. The opaque relay allows 24 carriers per host and 64 globally by default; aggregate exhaustion can still make a host unavailable, so these limits are not an availability guarantee.

```swift
let stream = try await connections.openService("api", kind: .tcp, hostID: id)
try await stream.send(requestBytes)
try await stream.finishSending()
while let bytes = try await stream.receive() {
    // Feed your bounded API response parser.
}
await stream.close()
```

TCP is a byte stream. Preserve framing in your application's protocol; transport message boundaries do not define an HTTP or application message. Tether does not replay API calls after reconnect. The application decides whether an operation is safe to retry.

## Apple host

Bundle the built `tether` executable with the Mac app and pass its fixed absolute URL to `TetherHostController`. The helper uses inherited private pipes for owner commands; it does not expose a public owner API. The app supplies its own private configuration URL and explicit fixed loopback service profiles.

Run `scripts/build-apple-helper.sh` to build the universal Mac helper. SDK archives include it at `Artifacts/Helpers/tether`; copy it to your app's `Contents/Helpers/tether`, then sign and notarize the complete app with your own identity. The SDK helper has a development signature and is not a notarized application.

```swift
let controller = try TetherHostController(
    helperURL: helper, configurationURL: privateProfile, appID: "com.example.yourapp")
let services = [try TetherHostServiceProfile(id: "api", kind: .tcp, port: 9123)]
TetherHostSettingsView(controller: controller, initialServices: services)
```

The host view creates a profile only on an explicit action, starts or stops hosting, opens a temporary pairing window, displays a real QR invitation and lists client grants. A private invitation needs the address clients can reach; a wildcard listener address is not a destination. Cloud hosting requires an authorized relay registration. Stopping the host closes connections and retains paired permissions.

A pairing invitation carries a secret temporary code. Its URL is app-scoped, expires within five minutes and must be transferred privately. Treat screenshots and clipboard copies as secrets. The relay does not receive this code. Invitations never replace an existing trusted host after an identity mismatch.

## Removal and route changes

“Leave host” asks the authenticated host to revoke this device, then deletes local trust after confirmation. An unavailable host cannot acknowledge removal. “Forget locally” explicitly deletes only this device's saved record; the host still needs to remove its old permission. A host's “Remove client” revokes that client and closes its services.

Changing private/VPN or cloud routes must authenticate the same saved host key before replacing its local route. Failure preserves the old record. Route changes close only the affected host's old streams; there is no automatic private-to-cloud fallback.

Host client presence distinguishes active sessions, recent authenticated activity and no active connection. A saved permission is not evidence that the client is online. Presence is unavailable when the host is stopped.

## Media transport

Reliable TCP/WSS streams and packet services support bounded application data. UDP packet forwarding inside these reliable carriers retains ordering and can stall behind lost TCP data. Choose that route explicitly when its reliability trade-off suits the application.

The native media fast path uses Quinn QUIC datagrams over private networks or VPNs. Its ephemeral TLS certificate pin and single-use authorization token are delivered inside the existing pinned Noise connection. The parent authenticated session owns the media lease. QUIC supplies TLS 1.3, congestion control and datagram protection; Tether does not introduce its own packet cipher. See [Quinn's transport documentation](https://docs.rs/quinn/latest/quinn/) and [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html).

Use a currently supported .NET runtime for Windows host applications; the managed compatibility target is not a reason to pin an app to an old runtime. Microsoft lists [.NET 10 LTS support through November 2028 and .NET 8/9 support ending November 10, 2026](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core). Native Windows sample and runtime verification are recorded separately in the status evidence.

The application supplies encoded audio/video packets and packetization. There is no codec, screen-capture permission broker or arbitrary remote destination in the tunnel. Keep packets within the negotiated datagram limit: an initial conservative 1,152 bytes, capped at 1,200 bytes. Late or excess real-time packets can be dropped; reliable API writes use service streams. Cloud low-latency datagrams need a suitable forwarding host and are separate from the WebSocket carrier.

## Buildable examples and evidence

`examples/AppleWorkspace/project.yml` generates Mac and iOS workspace examples with XcodeGen. The Mac example enables owner controls when `Contents/Helpers/tether` is bundled. Its example service targets port 9123; run your own handler there. `--design-fixtures` is explicitly synthetic UI data and does not establish a network connection.

Run the Rust gate, Swift SDK tests, real Swift-to-Rust fixtures and app-host Keychain checks separately. Generated layout screenshots describe their browser or native origin. Local tests and simulator captures do not establish physical iPhone internet pairing, public relay deployment, screen-reader acceptance or media performance on a lossy internet path. Current measured scope is recorded in [validation](VALIDATION.md).
