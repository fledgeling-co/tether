# Tether MCP

A read-only MCP gateway for data behind paired Tether services. Each HTTP request authenticates a user; each data operation checks that user's current sharing settings. Pairing grants access to a transport service, not an application account.

This is a source-built package. It includes a PageIndex adapter, a fixed-loopback Tether-forward HTTP client, a JWT verifier and an integration runner. It does not create accounts or run a hosted identity service.

```sh
npm --prefix packages/mcp ci
npm --prefix packages/mcp test
TETHER_TEST_BINARY=/absolute/path/to/tether npm --prefix packages/mcp run test:tether
```

The last command requires a real Tether runtime and fails if it is absent. It creates private temporary fixture profiles, pairs a host and client, and exercises user isolation through the encrypted forwarding path. Its synthetic service is not a production PageIndex connection.

## Connect an application

The host application supplies a `GatewayOptions` object:

- `resource`: the exact HTTPS MCP resource URL, including its path. Literal loopback HTTP is accepted for development.
- `authorizationServers`: configured issuer URLs advertised in protected-resource metadata.
- `verifyToken`: an access-token verifier returning issuer, subject, OAuth client ID, audience, scopes and expiry. `createJwtVerifier` validates asymmetric JWTs with a configured issuer, resource audience and key or JOSE key resolver. It requires an access-token type (`at+jwt` or `application/at+jwt`), `iss`, `sub`, `aud`, `exp`, `iat`, `client_id` and the `tether:read` scope. An opaque-token provider can implement the same verifier contract through introspection.
- `grants`: an authoritative callback keyed by the verified issuer, subject and client ID. Resolve account status and client consent on every call. Return `null` for disabled or unknown accounts.
- `sources`: trusted service adapters, each with a fixed service ID and dataset catalog. They receive the verified principal and current policy. No URL, credential, user ID or raw filter is accepted from MCP tool arguments.

`createTetherMcpGateway(options)` returns a web-standard `fetch` handler. `createTetherMcpNodeHandler(options)` from the `/node` entry point returns a Node HTTP handler. The compiled CLI loads your application's adapter module; it binds only to loopback:

```sh
node packages/mcp/dist/cli.js /absolute/path/to/host-adapter.mjs 7331
```

That module exports the application's real `GatewayOptions` as its default export. It is operator-owned executable configuration, not input supplied by an MCP client. Obtain existing credentials from the host's secret broker, such as Warden, through callbacks; no secret is written by this package.

`npm pack` inside the built package produces a local installable archive with the `tether-mcp` command. The package is private and is not published to npm.

## Sharing policy

```ts
const grant = {
  revision: "account-policy-17",
  datasets: [{
    serviceId: "pageindex",
    datasetId: "company-announcements",
    includeRecordIds: ["aaaaaaaaaaaaaaaaaaaaaaaa"],
    excludeRecordIds: ["bbbbbbbbbbbbbbbbbbbbbbbb"]
  }]
};
```

An omitted include list grants that dataset; an empty include list grants no records. Exclusions always win. Unknown datasets and duplicate grant entries are refused. The gateway snapshots policy and checks its fingerprint again before returning data, including changes made without a revision bump. It keeps no result cache.

Tools are `tether_list_services`, `tether_list_records`, `tether_read_record` and `tether_search_records`. A user-specific catalog resource and record URIs use the same authorization path. List and search results contain encrypted, authenticated `recordRef` values and URIs. References and pagination cursors expire after five minutes and bind to user, OAuth client, service, dataset, operation and policy. Reuse the returned reference when reading a deeply paged record. Configure one shared `cursorKey` of at least 32 random bytes for multiple replicas; the default key is process-local and lost at restart.

## PageIndex through Tether

Run an already paired `tether client forward` listener for the fixed PageIndex service. Construct `createForwardHttpClient("http://127.0.0.1:PORT")`, then give it to `createPageIndexSource` with dataset-to-`containerTag` mappings and an `accessToken(principal, datasetId, signal)` callback. That callback supplies a separately authorized PageIndex credential. The MCP bearer token is never passed to the origin.

PageIndex metadata pages establish collection membership. Searches use both an approved `documentId` and its `containerTag` before ranking, with ten metadata records examined per call. Excluded records never enter those ranker requests. Follow the returned cursor to continue; `partial: true` describes bounded coverage, not a corpus-wide absence. Diagnostics, global counts, usage and admin operations are not exposed.

A body read requires scoped metadata or an unexpired record reference, then validates the returned document ID and collection. Raw-ID lookup scans at most ten metadata pages; use a reference returned by list/search for records beyond that bound. HTTP origin responses are limited to 512 KiB and tool data to 256 KiB. Oversized records need an application-specific section or field adapter rather than a larger unrestricted tool response.

Generic list/search adapters must return at most the requested limit and resume after the last returned record; excess rows are refused rather than silently skipped. Audit events describe authorization checks, not delivery receipts. A policy change during an asynchronous audit can produce an allowed observation followed by refusal without releasing data.

Generic adapters are part of the trusted host application. They must apply the supplied policy before retrieval, AI calls or derived evidence; post-filtering a model response cannot undo an earlier disclosure. The bundled PageIndex adapter provides that constrained path.

## Deployment and client onboarding

Publish the authenticated HTTP endpoint behind HTTPS, with the exact resource audience registered at your authorization server. Configure only the required browser origins and trusted reverse-proxy Host values. Add that URL as a remote MCP connector in a client supporting this authorization flow, then sign in through the selected provider. This package advertises root and resource-path OAuth protected-resource metadata; the provider owns login, consent and token issuance.

A real issuer, user grants and service credentials are required before connecting live accounts. Installing this package does not establish Claude/ChatGPT acceptance or deploy a public endpoint. Account-selection and sharing screens in the native Tether frameworks remain the separately requested account feature.

Protocol references: [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [MCP security](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices), [official SDK HTTP examples](https://github.com/modelcontextprotocol/typescript-sdk/tree/main/examples/bearer-auth).
