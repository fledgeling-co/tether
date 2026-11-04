# Deployment

The supported self-hosted deployment is documented in [deploy/README.md](../deploy/README.md). It uses the pinned images and configuration under `deploy/`, with the Mac acting as the application server.

Public operation needs an owner-approved host, domain, DNS records and certificate contact. Local container validation does not establish internet reachability. Publish only TCP80/443 as documented; keep management and relay-internal ports private. The relay allowlist contains public host IDs, not device secrets.

An app host maintains an outbound connection. Keep its identity and paired-device state on that host. Back up those private records according to the app's own recovery policy; changing the host identity requires explicit re-pairing. Do not infer that a valid configuration or green container health means a phone can connect over cellular.

## Vercel readiness

The current binaries cannot deploy unchanged to Vercel. Vercel now supports WebSockets and container functions, but [separate WebSocket connections are not guaranteed to reach one instance](https://vercel.com/docs/functions/websockets). Tether currently keeps host registrations, attachment tickets and bridges in process memory, so its separate sockets require co-location. A Vercel adaptation needs distributed ephemeral coordination and ciphertext routing, plus recovery from function-duration disconnects.

The existing MCP Router phone adapter also expects the Mac's original TLS certificate and exporter. [Vercel terminates inbound TLS before application handling](https://vercel.com/docs/how-vercel-cdn-works), so that raw TLS path cannot pass through unchanged. Generic Tether clients already encrypt inside WSS; outer TLS termination does not expose their application content. MCP Router needs a new compatible carrier that preserves endpoint authentication inside WSS, or raw TCP ingress on another host.

A persistent container host supports the current deployment architecture. Choosing that host instead of Vercel, or adding a coordination service and updating clients for Vercel, remains a scope and hosting decision. No Vercel project or deployment was created during this compatibility check on 3 November 2026.
