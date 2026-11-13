// The web client against a real Rust host and relay, in Node (which has WebSocket and WebCrypto).
// Run through run_live.py, which starts both and passes the fixture path.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "node:net";
import { createHash } from "node:crypto";
import { loadCore, MemoryStore, TetherError } from "../dist/index.js";
import { createTestClient } from "../dist/testing.js";
import { RelayCarrier } from "../dist/session.js";

const fixture = JSON.parse(readFileSync(process.argv[2], "utf8"));
const route = { mode: "cloud", relayUrl: fixture.relayURL, hostId: fixture.hostID };
const host = (...args) => execFileSync(fixture.binary, ["host", ...args, "--config", fixture.hostConfig], { encoding: "utf8" }).trim();
const devices = () => JSON.parse(host("list")).length;
const core = await loadCore(readFileSync(new URL("../dist/tether.wasm", import.meta.url)));
const client = (store = new MemoryStore()) => createTestClient({ appId: fixture.appID, core, store });
let passed = 0;
async function check(name, work) {
  await work();
  passed++;
  console.log(`ok - ${name}`);
}
async function refused(work, codes) {
  try {
    await work();
  } catch (error) {
    if (error instanceof TetherError && codes.includes(error.code)) return error.code;
    throw new Error(`expected ${codes.join("|")}, got ${error?.code ?? error}`);
  }
  throw new Error(`expected ${codes.join("|")}, but it succeeded`);
}

const store = new MemoryStore();
const web = await client(store);
let record;

await check("pairs through the relay with the host's code, saving only after the host acknowledges", async () => {
  const steps = [];
  record = await web.pair(route, fixture.code, { onProgress: (step) => steps.push(step) });
  if (!record.confirmed || steps.join() !== "checking,storing,connected") throw new Error(`unexpected: ${steps}`);
  if ((await store.records(fixture.appID)).length !== 1) throw new Error("record not saved");
  if (devices() !== 1) throw new Error("host did not store the device");
});

await check("reads the host's granted services over a fresh pinned connection", async () => {
  const services = await web.status(record);
  if (!services.some((s) => s.id === "tcp" && s.kind === "tcp")) throw new Error(JSON.stringify(services));
});

await check("streams to a TCP service and sees the echo", async () => {
  const stream = await web.openStream("tcp", record);
  const payload = new TextEncoder().encode("browser through Rust host and relay");
  stream.send(payload);
  let echoed = "";
  while (echoed.length < payload.length) echoed += new TextDecoder().decode(await stream.receive(10_000));
  stream.close();
  if (echoed !== "browser through Rust host and relay") throw new Error(echoed);
});

await check("refuses a host that presents a different key than the saved one", async () => {
  const forged = { ...record, hostKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(9))) };
  await store.update(fixture.appID, forged.hostKey, () => forged);
  await refused(() => web.status(forged), ["identity_mismatch"]);
  await store.update(fixture.appID, forged.hostKey, () => null);
});

await check("a wrong code pairs nothing", async () => {
  const code = host("pair-code");
  const wrong = code.slice(0, 7) + (code[7] === "A" ? "B" : "A");
  const other = new MemoryStore();
  await refused(async () => (await client(other)).pair(route, wrong), ["invalid_code", "connection_closed", "timeout"]);
  if ((await other.records(fixture.appID)).length !== 0) throw new Error("a wrong code saved a record");
  if (devices() !== 1) throw new Error("a wrong code added a device");
});

await check("a second browser pairs with its own identity; loopback relays never go into invitations", async () => {
  const code = host("pair-code");
  // Invitations carry only wss:// routes, so the test relay can't be put in one.
  await refused(async () => core.call("discovery.invitation", { app: fixture.appID, route, code, expiresAtMs: Date.now() + 120_000, now: Date.now() }), ["invalid_route"]);
  const second = await client();
  const paired = await second.pair(route, code);
  if (!paired.confirmed || paired.clientKey === record.clientKey || devices() !== 2) throw new Error("second browser not paired");
});

await check("browsers refuse private routes and other apps' invitations", async () => {
  await refused(() => web.pair({ mode: "private", host: "mac.local", port: 7445 }, "K7QN4FMB"), ["browser_route"]);
  const foreign = core.call("discovery.invitation", {
    app: "other.app", route: { mode: "cloud", relayUrl: "wss://relay.example/v1/relay", hostId: fixture.hostID },
    code: "K7QN4FMB", expiresAtMs: Date.now() + 60_000, now: Date.now(),
  }).url;
  await refused(async () => web.readInvitation(foreign), ["invalid_invitation"]);
});

await check("a pairing aborted while checking saves nothing anywhere", async () => {
  const code = host("pair-code");
  const store = new MemoryStore();
  const abort = new AbortController();
  const attempt = (await client(store)).pair(route, code, { signal: abort.signal, onProgress: (s) => s === "checking" && abort.abort() });
  await refused(() => attempt, ["cancelled"]);
  if ((await store.records(fixture.appID)).length !== 0 || devices() !== 2) throw new Error("an aborted pairing saved something");
});

await check("confirmation and discard apply only to the same pending pairing", async () => {
  const stale = { ...record, confirmed: false };
  await web.discardPending(stale);
  if (!(await store.records(fixture.appID)).some((r) => r.confirmed)) throw new Error("discard removed confirmed trust");
  await refused(() => web.recover({ ...record, pairingId: crypto.randomUUID() }), ["invalid_state"]);
  if ((await store.records(fixture.appID))[0].pairingId !== record.pairingId) throw new Error("recovery replaced the record");
});

await check("two first uses of a store keep one identity", async () => {
  const shared = new MemoryStore();
  const [a, b] = await Promise.all([shared.createIdentity("x.app", "first"), shared.createIdentity("x.app", "second")]);
  if (a !== "first" || b !== "first") throw new Error(`${a} / ${b}`);
});

await check("a malformed relay URL is refused, not a crash", async () => {
  for (const relayUrl of ["wss://[", "wss://[::1", "wss://[nope]", "wss://relay:0"]) {
    await refused(async () => core.call("discovery.route", { route: { mode: "cloud", relayUrl, hostId: fixture.hostID } }), ["invalid_route"]);
  }
  core.call("ui.label", { text: "still alive" });
});

await check("a relay that floods unread frames is cut off", async () => {
  // A bare WebSocket server: accept, say ready, then send 40 frames of 60 KB nobody reads.
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("data", (head) => {
      const key = /Sec-WebSocket-Key: (.+)\r\n/i.exec(head.toString())[1];
      const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
      socket.once("data", () => {
        const ready = Buffer.from('{"type":"ready"}');
        socket.write(Buffer.concat([Buffer.from([0x81, ready.length]), ready]));
        const body = Buffer.alloc(60_000, 7);
        const header = Buffer.from([0x82, 126, body.length >> 8, body.length & 255]);
        for (let i = 0; i < 40; i++) socket.write(Buffer.concat([header, body]));
      });
    });
    socket.on("error", () => {});
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const carrier = await RelayCarrier.connect({ mode: "cloud", relayUrl: `ws://127.0.0.1:${server.address().port}/v1/relay`, hostId: fixture.hostID }, fixture.appID);
    await new Promise((resolve) => setTimeout(resolve, 500));
    await refused(() => carrier.receive(1_000), ["invalid_protocol"]);
  } finally {
    for (const socket of sockets) socket.destroy();
    server.close();
  }
});

await check("leaving removes this device at the host and here", async () => {
  await web.leave(record);
  if ((await store.records(fixture.appID)).length !== 0) throw new Error("record kept");
  if (devices() !== 1) throw new Error("host kept the device");
});

console.log(`${passed} web client checks passed`);
process.exit(0);
