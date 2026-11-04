# Deploy the opaque relay

The Mac serves application data. This deployment forwards encrypted connections and stores no app identity keys or pairing codes. It requires a Linux host with Docker Compose, a public domain, and inbound TCP ports 80 and 443. Hosting and certificate issuance are separate from the local verification recorded below.

## Prepare a host identity

Initialize one profile per application on the Mac. This example forwards a fixed loopback service through Tether's authenticated Noise transport:

```sh
cargo run --release -p tether -- host init \
  --config "$HOME/Library/Application Support/Tether/example-host.json" \
  --app app.example.companion \
  --service api=tcp://127.0.0.1:8081
cargo run --release -p tether -- host describe \
  --config "$HOME/Library/Application Support/Tether/example-host.json"
```

`host describe` prints a public, 52-character route ID. Put that ID in the relay allowlist. Keep the host configuration on the Mac: it contains private identity material and device permissions. A public route ID locates a host; pairing and the host's service allowlist authorize access.

## Configure DNS and deployment

Create an A record for `relay.tether.example.com` pointing at the relay host and a wildcard record for `*.tether.example.com` pointing at the same host. Replace the example suffix with a domain you control. The wildcard routes client connections; it does not require a wildcard TLS certificate.

From the repository root:

```sh
cp deploy/.env.example deploy/relay.env
# Edit relay.env: domain suffix, certificate contact, and public host IDs.
docker compose --env-file deploy/relay.env -f deploy/compose.yaml config --quiet
docker compose --env-file deploy/relay.env -f deploy/compose.yaml build
docker compose --env-file deploy/relay.env -f deploy/compose.yaml up -d
docker compose --env-file deploy/relay.env -f deploy/compose.yaml ps
```

The allowlist is mandatory. Separate multiple public IDs with commas. Adding an ID permits that signing key to register its route; it does not enroll a client or reveal an app key. Changing the allowlist requires recreating the relay container. Replacing or removing an allowed host closes its connections, so coordinate changes with active users.

The public relay URL is `wss://relay.tether.example.com/v1/relay`. Start the Mac's normal host agent with that URL, open a pairing window on the Mac, and enroll a client through the SDK or CLI. The short code stays between the endpoints. For private-only access, use the direct transport over the LAN or Tailscale/VPN and leave this deployment unused.

## Existing application TLS

An app that already implements authenticated TLS 1.3, certificate pinning and its own pairing can use raw TLS passthrough. Its client connects to `<public-host-id>.tether.example.com:443`; the Mac connects outbound through the control WebSocket. The origin's certificate reaches the client unchanged.

```sh
cargo run --release -p tether -- host forward-tls \
  --config "$HOME/Library/Application Support/Tether/example-host.json" \
  --relay wss://relay.tether.example.com/v1/relay \
  --service api --application-tls
```

Use this profile only when that fixed service authenticates its own clients and presents the identity the client expects. An ordinary plaintext API needs Tether's Noise profile. MCP Router's integration forwards its phone listener, not its local control API.

## Network and storage boundaries

| Component | Receives | Terminates |
|---|---|---|
| HAProxy, public TCP 443 | TLS ClientHello routing metadata | No TLS |
| Caddy, control hostname only | Outer HTTPS/WebSocket connections | Control transport TLS 1.3 |
| Tether, internal ports 8787/8788 | Registration metadata and encrypted frames | No application encryption |
| Mac application | Authenticated peer traffic | Noise or the application's pinned TLS |

HAProxy routes only the control hostname and one valid host-ID label under the configured suffix. Unknown routes close. The relay checks signed registration, application scope and its public host-ID allowlist. It applies bounded admission, stream counts, frame sizes and deadlines; its HTTP health endpoint returns only `ok`. Private ports are not published from Docker.

The Tether container runs as UID 65532 with a read-only filesystem and no Linux capabilities. Caddy runs under the same unprivileged UID; its named volumes retain the control hostname's certificate and ACME account. They contain no app pairing or data-encryption keys. Images are pinned by digest in the deployment files and `image-provenance.json`.

Relay operators can observe public route identifiers, app identifiers, IP addresses, timing and traffic sizes. They can disrupt availability. The deployment does not provide anonymity or a volumetric DDoS service. HAProxy's per-source limits sit before TLS routing; the relay's own admission bucket sees its immediate proxy peer and therefore also caps aggregate traffic through Caddy.

WebSocket datagram forwarding preserves packet boundaries but uses an ordered TCP carrier. It can suffer head-of-line blocking. Screen-sharing audio/video latency and throughput require separate testing; a UDP performance claim does not follow from a successful datagram echo.

## Verify and stop

A healthy container proves the local process is serving, not that an iPhone can reach it. Verify the public control hostname, then pair and read real app data on an iPhone over cellular with its VPN disabled. Check that the raw TLS profile presents the Mac's original certificate, that an unpaired device cannot use a service, and that revocation closes an existing connection. Test sleep/wake and network reconnects.

```sh
docker compose --env-file deploy/relay.env -f deploy/compose.yaml logs --tail 50
docker compose --env-file deploy/relay.env -f deploy/compose.yaml down
```

`down` stops public forwarding while retaining Caddy's certificate volumes. The Mac retains its device registry. Remove a device at the host to revoke that device; removing the relay alone does not erase a pairing.

Local checks: `cargo test -p tether-ingress` exercises adversarial ClientHello inputs and an actual TLS 1.3 origin through ingress, signed host registration and WebSocket forwarding. The client verifies the original certificate and receives its payload; invalid TLS versions and unknown routes never reach the origin. Docker build, container health/SIGTERM, Compose schema and the pinned HAProxy/Caddy configuration are separate checks. These checks do not establish public hosting or physical-device operation.

Configuration references: [HAProxy SNI passthrough](https://cdn.haproxy.com/blog/enhanced-ssl-load-balancing-with-server-name-indication-sni-tls-extension), [Caddy WebSocket proxying](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy), [Caddy listener options](https://caddyserver.com/docs/caddyfile/options).
