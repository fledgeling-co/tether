# Security policy

Report a suspected vulnerability through [GitHub private vulnerability reporting](https://github.com/fledgeling-co/tether/security/advisories/new). Include the affected version, platform and a minimal reproduction. Keep pairing codes, private identities and customer payloads out of public issues. Pre-release APIs and the protocol may change; no stable long-term support branch is promised yet.

## Boundaries

Private mode is the smallest exposed surface. Cloud mode adds an untrusted relay and public ingress while keeping application encryption between client and host. The relay does not hold pairing codes, device private keys or application plaintext. Metadata, denial of service, host compromise and client compromise remain relevant threats.

Use separate identities and service allowlists for each app. Keep production relay registration allowlisted. Expose only the deployment's documented ingress ports; management and application-control APIs stay private. Require authenticated TLS1.3 when using the application-TLS profile. An arbitrary plaintext service is not made secure by declaring that profile.

Host identity changes require an explicit new pairing. Do not offer a trust-reset fallback after a connection failure. Revocation is host-owned. Local private-file protection assumes the OS account is trusted; it does not protect against another process already controlling that account. Swift Keychain policy protects stored records, not a compromised running app. Android stores encrypted records in its no-backup directory using an app-scoped Keystore wrapping key; the Noise identity enters trusted process memory. Android API 28+ requests unlocked-device key use; API 26/27 cannot enforce that same restriction. The CLI uses private Unix files or DPAPI CurrentUser with an owner-only Windows DACL. Profiles are bounded at 128 KiB and 256 paired clients; stores fail closed on unsupported protection or invalid access controls. DPAPI does not isolate secrets from a compromised process running as the same Windows user.

Native media uses Noise-delegated, short-lived QUIC capabilities, exact certificate pins and provider TLS signature verification. The parent Noise session owns the lease. TLS session resumption, early data and automatic cloud fallback are disabled. Streams, datagrams and protocol frames have explicit limits. WebSocket datagrams preserve boundaries but can suffer head-of-line blocking. The host must be awake and online. No cloud inbox or offline data replica exists.

The core wipes buffers it owns where supported. Rust crypto libraries, Swift Foundation and operating-system frameworks can retain temporary copies; complete memory erasure is not promised. The C ABI requires valid caller-owned pointers for the stated lengths and never treats a null or oversized input as valid.

See [validation](docs/VALIDATION.md) and the repository CI for the measured scope. Tests and model reviews do not constitute an independent cryptographic audit. Reassess Apple export-compliance declarations when linking the Noise encryption SDK into a shipping app; an existing declaration for OS-only TLS does not cover a new cryptographic library automatically.
