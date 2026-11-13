# Adopt Tether in an app

Choose one application ID and a separate host profile for each app. Register the profile's public route ID with your relay operator. The host retains its private identities and paired-device permissions. Your app continues to own its data, actions and authorization rules.

## Wrap an existing local service

The CLI's normal profile secures fixed TCP and UDP targets with Tether's pairing and Noise channel. For example:

```sh
tether host init --config "$HOME/.config/tether/example.private.json" \
  --app app.example.companion \
  --service api=tcp://127.0.0.1:8081 \
  --service media=udp://127.0.0.1:5900

tether host run --config "$HOME/.config/tether/example.private.json" \
  --direct 0.0.0.0:9797 --pair
```

The host displays a short-lived code. On a client, read that code from standard input so it does not enter the process argument list:

```sh
tether client pair --config "$HOME/.config/tether/client.private.json" \
  --app app.example.companion --direct mac-address:9797 --code-stdin

tether client forward --config "$HOME/.config/tether/client.private.json" \
  --service api --listen 127.0.0.1:8082 --kind tcp
```

Your existing client connects to its local proxy. To use a relay, pair with `--relay wss://relay.example.com/v1/relay --host-id PUBLIC_HOST_ID` instead of `--direct`; start the host with that relay URL. The route choice is explicit and persists with the pairing. Opening both a direct listener and a relay on a host is an explicit developer choice, not an automatic fallback.

For another pairing window, use `tether host pair-code --config ...` while the host runs. `host list` shows public device IDs and service permissions; `host revoke --config ... --device ...` revokes one. An interrupted pairing can be recovered with `client recover`. If the host never received the acknowledgement, use the explicit `client abandon-pending --config ... --app ...` and obtain a new code. Confirmed pairings cannot be discarded through that operation.

## Embed a native client

Build the XCFramework with `scripts/build-xcframework.sh` and add `packages/TetherKit` as a local Swift package. Its high-level client uses explicit private/cloud routes, Keychain identity and peer stores, pairing/recovery, and authorized service streams. Use [the SDK guide](../packages/TetherKit/README.md) for the current API and examples.

Rust apps can depend on `tether-core` for protocol state and `tether` for the host/client runtime. The C ABI exposes the shared crypto state and native QUIC media runtime. The CLI uses private files on Unix and DPAPI CurrentUser with owner-only ACLs on Windows. Windows apps can use `packages/windows/Tether.Core` and the native `Tether.WinUI` controls. Keep service policy at the host: a client asks for a service name, never an arbitrary IP address or port. App-specific operations still require their own permissions.

## Know which device opened a stream

A forwarded TCP service otherwise receives a bare loopback connection, so it cannot tell which paired device opened it, and any local process can reach the same port. Give the service an identity key and the host proves the device before forwarding any application byte:

```sh
tether host init --config "$HOME/.config/tether/example.private.json" \
  --app app.example.companion \
  --service api=tcp://127.0.0.1:8081 \
  --identify api="$HOME/.config/example/tether-identity.key"
```

The key file is private to your user and holds 32 random bytes or their base64; your service reads the same file. On every connection your service writes `TPIC`, the byte `1` and 32 fresh random bytes. The host answers with `TPIP`, the byte `1`, the device's 32-byte public key and `HMAC-SHA256(key, "tether-peer-identity/v1\0" || length(service) || service || challenge || device key)`. Verify the HMAC in constant time, then map the device key to your own permissions; the device key is the one `host list` shows for that client. A connection that sends anything else is not a paired device. Swift hosts set `identityKeyFile` on `TetherHostServiceProfile`. UDP services cannot be identified.

The proof says which paired device the host admitted; it is not an account. Keep your own authorisation, revocation and replay checks for the operations the device asks for.

## Keep an existing authenticated TLS protocol

Apps with their own authenticated TLS1.3, certificate pinning and pairing can use `host forward-tls --application-tls` instead of Tether's Noise profile. The TLS ingress gives the client a normal `<public-host-id>.<domain-suffix>:443` endpoint; the app's original TLS session reaches the origin unchanged. This profile does not authenticate a plaintext API automatically.

The `examples/mcp-router` adapter illustrates this separation: its phone listener uses the TLS path, while its local control API stays private. The application's existing exporter-bound PAKE protocol is distinct from Tether's Noise pairing wire. The adapter configures the route without copying router credentials into Tether.

## Job control and screen sharing

A job-control app retains its job permissions and repository policy. A loopback proxy can carry an existing authenticated protocol unchanged; a deeper integration can consume Tether's transport after mapping the peer context into the application's own permissions. Existing pairing protocols do not automatically interoperate with Tether's wire format.

A screen-sharing app may need control streams and several UDP media channels. Configure each fixed service explicitly, and test the required datagram sizes and latency. WebSocket preserves packet boundaries but adds reliable ordering and possible head-of-line delay. An outbound proxy makes connections originate locally, so a local source address cannot serve as a device identity; use an identity key (above) when the service needs to know the device. Keep capture, codecs, permissions and any third-party licensing obligations in the consuming application.

Physical-device operation, screen-sharing performance, platform entitlements and end-user permissions remain app-specific acceptance work.

See [Embed Tether](FRAMEWORKS.md) for native client/host UI, multi-host lifecycle, route changes and media APIs.
