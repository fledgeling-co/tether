# Validation and release limits

Tether is a pre-release integration kit. Test results describe the checked source and environment; they do not establish a hosted service or acceptance inside a consuming app. The repository CI runs source policy checks, Rust tests and platform compilation/unit checks. Native device checks remain separate.

| Area | Established locally | Remaining limits |
| --- | --- | --- |
| Shared Rust | Real private/relay host-client forwarding, peer authentication, service restrictions, revocation, cancellation and TCP half-close | No professional cryptographic audit |
| Apple | Universal Mac/device/simulator bridge, Swift SDK tests, two-host live service flows and native UI examples | Physical iPhone internet flow and broader accessibility acceptance |
| Protected Apple storage | Provisioned native Mac and iOS simulator Keychain fixtures; eight phases and exact removal of six owned accounts | Each embedding app needs its own signing and entitlement checks |
| Windows | Release x64 NuGet consumers, real service/media loops, native row-identity regressions and external UI Automation inspection | ARM64, another Windows user's storage boundary and full screen-reader operation |
| Android | 13 Core and three UI unit tests; four JNI/Keystore/direct/relay tests on an API 37 arm64 guest; four native UI workflows; fresh Maven-only app build with exact native payloads | Physical-device, older-API runtime, TalkBack, RTL, large-font and internet checks require separate runs |
| Public relay | Hardened container package and local TLS/relay checks | No managed public endpoint or physical cellular acceptance is supplied |

Standard SwiftUI and the fold adapter are separate products. The standard UI does not require the newer fold APIs. The optional adapter requires the iOS 27.1 SDK; closed portrait was previously observed, while other native fold poses remain unmeasured. Android compact/wide layouts and native rendering are recorded independently of those Apple poses.

Android's native checks include wrong-code and wrong-pin rejection, protected-storage tamper/truncation/lost-key refusal, stale-generation rejection, 128 KiB direct TCP, empty UDP packets, QUIC beyond the lease deadline, and a 512 KiB transfer through a local Rust WebSocket relay with a delayed consumer. Cancellation, queued-reader closure and remote leave were exercised. The UI workflows cover pairing errors, route forms, cancellation, trust-removal confirmation, eight status presentations and independently scrolling wide panes. The x86_64 Android library was cross-built and packaged; native execution used arm64. `scripts/verify-android-live.py --help` describes the owned emulator fixture.

Media measurements use encoded packet round trips, with separate loopback and synthetic-impairment fixtures. They are not decoded audio/video measurements, internet latency promises or cross-platform speed comparisons. QUIC is available on explicit private/VPN routes; the cloud WebSocket carrier remains ordered.

The public source is exported from a whitelist and scanned before publication. Owner status pages, local profiles, private release evidence, credentials and internal Git history are excluded. See [security policy](../SECURITY.md) for reporting a vulnerability and [testing](TESTING.md) for reproducible commands.
