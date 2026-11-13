# Tether for the web

A browser client for Tether: it pairs with a Mac or PC through a cloud relay, keeps this browser's device identity in IndexedDB, and opens the host's TCP services as encrypted streams. `<tether-pair>` and `<tether-workspace>` are drop-in Web Components for the pairing sheet and the list of paired computers. Run `npm run build` (it calls `scripts/build.sh`) to compile the Rust core to `dist/tether.wasm` and the TypeScript to `dist/`. It needs the `wasm32-unknown-unknown` Rust target and `tsc`; there is no bundler and no runtime dependency.

```html
<tether-workspace app-id="app.example.notes"></tether-workspace>
<script type="module">
  import "@fledgeling/tether-web/elements";
</script>
```

```js
import { TetherClient } from "@fledgeling/tether-web";
const client = await TetherClient.create({ appId: "app.example.notes" });
const peer = await client.pairInvitation(invitationLink);  // or client.pair(route, code)
const services = await client.status(peer);
const stream = await client.openStream("notes-api", peer);
stream.send(requestBytes);
const reply = await stream.receive();
```

The browser is a device, never a host, and it pairs only through the relay. Browsers can't open raw sockets or browse the local network, so nearby pairing and private-network routes are refused with `browser_route`. Cloud routes require `wss://`; `allowLoopbackForTesting` permits `ws://` to `127.0.0.1` or `[::1]` and nothing else. Invitation links (`tether://pair?data=…`) carry a `wss://` route and a code that expires within five minutes, and are read by the same Rust code as on iOS, Android and Windows. Media streams use QUIC and are not available in the browser.

Pairing, the Noise handshake and every encryption run in the Rust core, compiled from `crates/ffi` without its media feature. The page supplies randomness through one import backed by `crypto.getRandomValues`; the module has no other imports. The pairing flow is the same state machine every kit drives (`crates/model`), so the pending record is saved before the acknowledgement and confirmed only after the host commits, and a wrong code saves nothing.

The default `IndexedDBStore` seals the identity's private key with an AES-GCM key the browser generates as non-extractable, so the raw key never sits in IndexedDB or in an export of it. That protects it at rest. It does not protect it from script running on your origin, which can ask the browser to unseal it, so serve the app with a strict Content Security Policy. Pass a `MemoryStore` for pages that must not keep trust, or implement `TetherStore` yourself. Keys and JSON passing through JavaScript can't be wiped; the core wipes its own copies.

The components render the words the native kits render, from the core's `ui.*` commands. Theme them with `--tether-accent`, `--tether-ink`, `--tether-secondary`, `--tether-ground`, `--tether-surface`, `--tether-line`, `--tether-success`, `--tether-warning`, `--tether-danger`, `--tether-radius` and `--tether-font` on the element, or style the exposed parts. They follow the page's `color-scheme`, so they turn dark only when the page declares `color-scheme: light dark`. `<tether-pair>` fires `tether-paired` with the saved record, `tether-done` and `tether-cancel`; `<tether-workspace>` fires `tether-hosts-changed`. Give either element a client with the `client` property to share one across a page or to use a custom store; otherwise elements with the same `app-id` share one.

`python3 test/run_live.py` starts a real relay and host on loopback, then runs 8 client checks in Node and the components in Chromium through Playwright, which it loads from `~/Dev/dAIolog` (set `TETHER_PLAYWRIGHT_ROOT` to change that, or `TETHER_WEB_BROWSER=0` to skip it). The browser pass pairs through the dialog, refuses a wrong code, reconnects after a reload, forgets the host, and checks text contrast in light and dark. Set `TETHER_WEB_SHOTS` to keep its screenshots.
