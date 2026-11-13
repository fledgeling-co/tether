# Embed native connection UI

Tether UI manages connections and trust. Your app supplies the application content, authorized-service actions and any application-specific sign-in. Pairing a device does not replace API authorization, screen-capture permission or microphone permission.

## Components

| Platform | Workspace | Smaller surfaces | Existing-app integration |
| --- | --- | --- | --- |
| iOS/macOS | `TetherWorkspaceView` | `TetherPairHostView`, `TetherHostSettingsView` on Mac | SwiftUI, `UIHostingController`, `NSHostingView` |
| Android | `TetherWorkspace` | `TetherHostList`, `TetherHostDetail`, `TetherPairHost`, `TetherRouteEditor` | Compose or an Android `ComposeView` |
| Windows | `TetherWorkspaceView` | `TetherClientView`, `TetherHostView` | WinUI `ContentControl` or an existing window |
| Web | `<tether-workspace>` | `<tether-pair>` | Any page; see `packages/web/README.md` |

Pass an app-owned store into the controls. Creating or dismissing a screen should not recreate an identity, erase trust or interrupt another host. Selecting a host changes which details are shown; streams to other hosts remain independent. Native themes, typography and controls come from SwiftUI, Material 3 and WinUI rather than a cross-platform visual shell.

## What the core decides

The pairing protocol and the words on screen live in Rust (`crates/model`), so the four kits can't drift apart. Each kit drives the same two state machines through the C ABI, or WebAssembly in the browser: `nearby.begin` and `code.begin` return a flow handle and a list of actions (`send`, `receive`, `wait`, `show_code`, `host_approved`, `store_pending`, `confirm`, `outcome`, `failed`), and the kit performs each one and reports back with `flow.receive`, `flow.tick` or `flow.stored`. The approval rules are enforced there: an approval counts only once the code has been on screen for a second and the owner's decision has read undecided since it appeared, and a decline is final even when it races the host's ready. Kits save trust only when the flow asks for `store_pending`, and confirm it only on `confirm`.

The screens render view models from the same crate. `ui.nearby` gives the device's sheet for a phase (title, message, tone, code groups and spoken form, expiry, which buttons show and whether Approve is enabled), `ui.host_request` the host owner's sheet, `ui.pair_code` the typed-code sheet with its field validation, `ui.connection_state` a saved host's state, `ui.error` the explanation for a failure code, and `ui.strings` the fixed copy for lists and sections. Each kit wraps these as typed models: `TetherCopy` in Swift, Kotlin and C#, and the Web Components call them directly. `discovery.txt`, `discovery.peer` and `discovery.invite` define the Bonjour records and invites, and `discovery.read_invitation` reads invitation links the same way everywhere. Layout, controls and theming stay native to each platform.

## Connection states

| State | What the user sees | Safe next action |
| --- | --- | --- |
| Empty | No paired hosts and a clear pairing action | Enter a host's route and current invitation |
| Connecting | Progress and cancellation | Cancel without deleting saved trust |
| Connected | Authenticated status and granted services | Open an app-provided service action |
| Offline | Saved host identity remains visible | Reconnect when the host is available |
| Pairing interrupted | Pending trust is identified | Recover or explicitly discard the pending record |
| Access removed | Host permission was revoked | Obtain a new owner-approved pairing |
| Identity changed | The new host key does not match | Keep existing trust and investigate |
| Host at capacity | A recoverable capacity error | Retry later; keep the identity |

Field labels stay visible after typing. A private address or cloud route is explicit; failure never selects another network mode. A saved route changes only after the same pinned host authenticates. Pairing invitations expire, and pairing codes are secrets: the UI should clear them after completion and avoid including them in diagnostics.

“Leave host” asks that host to revoke this device before removing the local record. “Forget locally” is available when remote revocation cannot complete and explains that the host may retain permission. Mac and Windows owner controls separately remove a client and close its services. Mobile clients do not display nonfunctional host-owner controls.

## Nearby pairing

On the local network, devices find each other instead of typing a code. A host announces `_tether._tcp` with its app ID, name, public key, port and IPv4 addresses; a device with Add a computer open announces `_tether-dev._tcp`, so a host can list it and press Connect. Choosing either side shows the same six-digit code on both screens, and each owner approves or declines. Trust is stored only after both approve, through the same ready, ack and done sequence as typed-code pairing.

The code comes from the encrypted channel after a commit-then-reveal exchange, so a device in the middle matches it with probability one in a million per attempt. Every exchange spends a host-wide attempt (12 per 10 minutes); three abandoned exchanges close nearby pairing until the owner reopens it, and the owner UI says why. Requests expire after 60 seconds, two can be open at once, and three declines pause a device for 10 minutes. Approve only counts once the code has been on screen for a second. Relay connections cannot use nearby pairing; typed codes remain for them.

| Platform | Device | Host |
| --- | --- | --- |
| iOS/iPadOS/Duo | `TetherNearbyPairView` (the workspace's Add a computer) | — |
| macOS | `TetherNearbyPairView` | `TetherNearbyDevicesSection`, `TetherNearbyRequestView` or `.tetherNearbyRequests` |
| Android | `TetherNearbyPair` (the workspace's Add a computer) | — |
| Windows | `TetherClientView` (Add a computer) | `TetherHostView` (Nearby, with the request dialog) |

Apps declare both Bonjour types in `NSBonjourServices` and a local network usage description. The design mock is `design/mocks/nearby-pairing.html`.

## Layout and lifecycle

Compact mobile windows show the host list and selected detail as separate destinations with a reachable host switcher. Wider windows can show them together. Android's optional scanner callback keeps camera/barcode choices in the embedding app; no Scan button appears when no scanner is supplied. SwiftUI's separate `TetherDuoUI` adapter supplies reserved-region geometry on the newer SDK; the base UI remains usable without it.

Keep client/store instances in the owning scene, ViewModel or window. Close streams on completion and release the store when the owner ends. Swift stores expose `stopMonitoring()` and per-host disconnect; Android stores implement `Closeable`; Windows stores and host controllers use asynchronous disposal. Follow the operating system's background execution rules. The SDK does not install a background service to keep an application alive.

## Native examples

These captures use synthetic fixture data and establish layout only. They do not demonstrate public networking or a real customer's account.

| iOS | Android | Windows |
| --- | --- | --- |
| <img src="assets/ios-native.png" alt="Native iOS offline host details with saved identity" width="260"> | <img src="assets/android-native.png" alt="Native Android synthetic host list with offline and removed-access states" width="260"> | <img src="assets/windows-native.png" alt="Native Windows permission-revoked state" width="260"> |

![Native macOS selected-host controls](assets/macos-native.png)

![Native Android wide-window dark fixture with separate host list and detail panes](assets/android-wide-native.png)

See [validation](VALIDATION.md) for the distinction between compilation, native checks and physical-device acceptance.
