// An encrypted session with a host through the cloud relay. The relay sees only Noise messages;
// the core does the handshake and every encryption.
import { TetherCore, TetherError, fromBase64, toBase64 } from "./core.js";

/** A cloud route. Browsers have no raw sockets, so the relay is the only way in. */
export interface CloudRoute {
  mode: "cloud";
  relayUrl: string;
  hostId: string;
}
export interface PrivateRoute {
  mode: "private";
  host: string;
  port: number;
}
export type Route = CloudRoute | PrivateRoute;

const WIRE_LIMIT = 65_536;
const RECORD_LIMIT = 4_096;
// Frames the page hasn't read yet. A peer that floods past this is cut off rather than buffered.
const QUEUE_FRAMES = 32;
const QUEUE_BYTES = 1_048_576;

function deadline<T>(ms: number, work: Promise<T>, onTimeout: () => void): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expiry = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      onTimeout();
      reject(new TetherError("timeout"));
    }, ms);
  });
  return Promise.race([work, expiry]).finally(() => clearTimeout(timer));
}

/** The relay's WebSocket: a hello, a `ready`, then one binary message per Noise message. Exported for tests. */
export class RelayCarrier {
  private queue: Uint8Array[] = [];
  private queued = 0;
  private waiters: { resolve: (value: Uint8Array) => void; reject: (error: Error) => void }[] = [];
  private failure: TetherError | undefined;

  private constructor(private socket: WebSocket) {}

  static async connect(route: CloudRoute, appId: string): Promise<RelayCarrier> {
    let socket: WebSocket;
    try {
      socket = new WebSocket(route.relayUrl);
    } catch {
      throw new TetherError("invalid_route");
    }
    socket.binaryType = "arraybuffer";
    const carrier = new RelayCarrier(socket);
    const ready = new Promise<void>((resolve, reject) => {
      socket.onopen = () => socket.send(JSON.stringify({ type: "client", app_id: appId, host_id: route.hostId }));
      socket.onmessage = (event) => {
        let hello: any;
        try {
          hello = typeof event.data === "string" && event.data.length <= 2048 ? JSON.parse(event.data) : undefined;
        } catch {}
        if (hello?.type !== "ready") return reject(new TetherError("relay_refused"));
        socket.onmessage = (next) => carrier.deliver(next.data);
        resolve();
      };
      socket.onerror = () => reject(new TetherError("unavailable"));
      socket.onclose = () => reject(new TetherError("unavailable"));
    });
    try {
      await deadline(15_000, ready, () => socket.close());
    } catch (error) {
      socket.close();
      throw error;
    }
    socket.onclose = () => carrier.fail(new TetherError("connection_closed"));
    socket.onerror = () => carrier.fail(new TetherError("connection_closed"));
    return carrier;
  }

  private deliver(data: unknown) {
    if (this.failure) return;
    if (!(data instanceof ArrayBuffer) || data.byteLength > WIRE_LIMIT) return this.fail(new TetherError("invalid_protocol"));
    const bytes = new Uint8Array(data);
    const waiter = this.waiters.shift();
    if (waiter) return waiter.resolve(bytes);
    if (this.queue.length >= QUEUE_FRAMES || this.queued + bytes.length > QUEUE_BYTES) return this.fail(new TetherError("invalid_protocol"));
    this.queue.push(bytes);
    this.queued += bytes.length;
  }

  private fail(error: TetherError) {
    this.failure ??= error;
    this.queue = [];
    this.queued = 0;
    for (const waiter of this.waiters.splice(0)) waiter.reject(this.failure);
    this.socket.onmessage = null;
    this.socket.close();
  }

  send(bytes: Uint8Array) {
    if (this.failure) throw this.failure;
    if (bytes.length > WIRE_LIMIT) throw new TetherError("invalid_frame");
    this.socket.send(bytes);
  }

  receive(ms: number): Promise<Uint8Array> {
    const queued = this.queue.shift();
    if (queued) {
      this.queued -= queued.length;
      return Promise.resolve(queued);
    }
    if (this.failure) return Promise.reject(this.failure);
    const next = new Promise<Uint8Array>((resolve, reject) => this.waiters.push({ resolve, reject }));
    return deadline(ms, next, () => this.fail(new TetherError("timeout")));
  }

  close() {
    this.fail(new TetherError("connection_closed"));
  }
}

/** One authenticated, encrypted connection. `peer` is the host's key; `binding` the handshake hash. */
export class Session {
  private closed = false;
  private constructor(
    private core: TetherCore,
    private carrier: RelayCarrier,
    private transport: number,
    readonly peer: string,
    readonly binding: string,
  ) {}

  /** `identity` is a core identity handle. A `pin` refuses any host key but that one. */
  static async open(core: TetherCore, route: Route, identity: number, appId: string, pin?: string, allowLoopback = false): Promise<Session> {
    if (route.mode !== "cloud") throw new TetherError("browser_route");
    const checked = core.call<{ route: CloudRoute }>("discovery.route", { route, allowLoopback }).route;
    const carrier = await RelayCarrier.connect(checked, appId);
    let handshake: number | undefined;
    try {
      handshake = core.call<{ handle: number }>("noise.new", { role: "client", identity, app: appId }).handle;
      carrier.send(fromBase64(core.call<{ data: string }>("noise.write", { handle: handshake, data: "" }).data));
      const reply = await carrier.receive(15_000);
      const read = core.call<{ remoteStatic: string | null }>("noise.read", { handle: handshake, data: toBase64(reply) });
      if (!read.remoteStatic) throw new TetherError("invalid_protocol");
      // Refuse a substituted host before message three discloses this device's key.
      if (pin && pin !== read.remoteStatic) throw new TetherError("identity_mismatch");
      carrier.send(fromBase64(core.call<{ data: string }>("noise.write", { handle: handshake, data: "" }).data));
      const finished = core.call<{ handle: number; binding: string; remoteStatic: string }>("noise.finish", { handle: handshake });
      handshake = undefined;
      return new Session(core, carrier, finished.handle, finished.remoteStatic, finished.binding);
    } catch (error) {
      if (handshake !== undefined) destroy(core, handshake);
      carrier.close();
      throw error;
    }
  }

  sendBytes(bytes: Uint8Array) {
    if (this.closed) throw new TetherError("connection_closed");
    const sealed = this.core.call<{ data: string }>("transport.encrypt", { handle: this.transport, data: toBase64(bytes) });
    this.carrier.send(fromBase64(sealed.data));
  }

  async receiveBytes(ms = 60_000): Promise<Uint8Array> {
    if (this.closed) throw new TetherError("connection_closed");
    const sealed = await this.carrier.receive(ms);
    return fromBase64(this.core.call<{ data: string }>("transport.decrypt", { handle: this.transport, data: toBase64(sealed) }).data);
  }

  /** Sends a control record. */
  send(record: Record<string, unknown>) {
    const bytes = new TextEncoder().encode(JSON.stringify({ ...record, v: 1 }));
    if (bytes.length > RECORD_LIMIT) throw new TetherError("invalid_frame");
    this.sendBytes(bytes);
  }

  /** Reads a control record. Host errors are returned as records for the flows to judge. */
  async receive(ms = 15_000): Promise<Record<string, any>> {
    const bytes = await this.receiveBytes(ms);
    if (bytes.length > RECORD_LIMIT) throw new TetherError("invalid_protocol");
    let value: any;
    try {
      value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new TetherError("invalid_protocol");
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TetherError("invalid_protocol");
    return value;
  }

  /** Reads a control record of `type`, turning a host error into a `TetherError`. */
  async expect(type: string, ms = 15_000): Promise<Record<string, any>> {
    const record = await this.receive(ms);
    if (record.v !== 1) throw new TetherError("invalid_protocol");
    if (record.type === "error") throw new TetherError(String(record.code ?? "invalid_protocol"));
    if (record.type !== type) throw new TetherError("invalid_protocol");
    return record;
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    destroy(this.core, this.transport);
    this.carrier.close();
  }
}

export function destroy(core: TetherCore, handle: number) {
  try {
    core.call("destroy", { handle });
  } catch {}
}
