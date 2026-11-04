# Architecture

Tether separates the encrypted application channel from the route carrying it. The same peer identity and service authorization apply to private and cloud connections. Mode selection is explicit; a failed private connection does not silently publish the host or use a cloud relay.

## Secure-channel profile

Each app creates a separate X25519 static identity. Noise XX establishes an encrypted channel with empty handshake payloads. Existing pairings compare the host key before the client sends its final handshake message; the host checks the client's paired-device permissions before opening a service.

A new pairing uses balanced SPAKE2 through RustCrypto, with directional confirmations bound to the app ID, both device keys and the Noise handshake hash. The host opens a five-minute pairing window with a random eight-character code and three online attempts. The code is not a relay address, room name, encryption key or reusable bearer credential. Pairing records become usable only after the persistence/acknowledgement exchange; pending client records have an explicit recovery path.

The socket-free Rust core owns Noise/PAKE state. Reliable native carriers own their TCP/WSS I/O; the shared Rust media runtime owns QUIC I/O through the C ABI. The Swift SDK stores app-scoped identities and peer records in Keychain. Windows uses DPAPI CurrentUser plus owner-only ACLs; the Unix CLI uses private files. The generic Tether PAKE wire is different from MCP Router's existing RFC9382/scrypt wire and from Egress's current protocol; they are not interchangeable.

## Cloud carrier

The host opens an outbound WebSocket to the relay and proves possession of an app-scoped Ed25519 registration key against a fresh challenge. A public route ID derives from the app ID and registration public key. Production relay configuration permits only listed host IDs. Each client connection produces a single-use attachment ticket delivered over the host's authenticated control connection. The host opens an outbound data socket; the relay joins the encrypted streams.

The relay applies connection, host, stream, frame, write, idle and lifetime limits. It does not accept arbitrary TCP destinations or inspect decrypted application records. Cloud operators can still deny service and observe metadata.

## Existing TLS applications

The application-TLS profile forwards an app's own TLS1.3 bytes through the same carrier. Optional ingress routes the bounded ClientHello's public SNI to a registered host without terminating that TLS session. TLS termination for the host's outer control WebSocket is separate. The origin app must authenticate its clients and its own certificate; choosing this profile does not provide those checks automatically.

## Service boundary

Service names resolve only to owner-configured loopback addresses and ports. Device permissions name service IDs, not client-provided destinations. Revocation disconnects ongoing authorized forwarding as well as refusing new service opens. The host remains responsible for application-level permissions such as screen control, repository access or MCP authorization.

## Native media and local trust

Private/VPN media delegates a short-lived QUIC lease through the pinned Noise session. A single-use secret authorizes the exact granted UDP service. The host certificate pin arrives only inside Noise; the client also verifies the TLS handshake signature. No early data or session resumption bypasses that check. Closing the originating Noise session, expiry or revocation ends the lease. Encoded media remains the application's responsibility. The cloud reliable carrier is a separate explicit choice; it does not provide unordered datagrams.

Application IDs isolate protocol identities, records and grants. They are not an operating-system process sandbox. DPAPI CurrentUser and Unix file permissions protect stored secrets from other users; they do not isolate secrets from a compromised process running as the same user. Apple's default Keychain provider also depends on the embedding app's signing and access-group entitlements. Plaintext and delegated capabilities necessarily enter trusted endpoint memory. This kit does not claim hardware-backed key isolation, protection from a compromised endpoint, or an independent cryptographic audit.
