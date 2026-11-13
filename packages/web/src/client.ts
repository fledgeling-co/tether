// Pairing and talking to hosts from a browser. The pairing flow itself runs in the Rust core;
// this file only moves its records and saves what it asks to save.
import { CoreSource, TetherCore, TetherError, loadCore } from "./core.js";
import { Route, Session, destroy } from "./session.js";
import { IndexedDBStore, PeerRecord, TetherStore } from "./store.js";

export interface HostService {
  id: string;
  kind: "tcp" | "udp";
}

export interface ClientOptions {
  appId: string;
  /** Defaults to IndexedDB. */
  store?: TetherStore;
  /** A loaded core, or where to load it from. */
  core?: TetherCore;
  wasm?: CoreSource;
}

/** The state of a pairing in progress, for a UI to follow. From `storing` on it can't be cancelled. */
export type PairingProgress = "checking" | "storing" | "connected";

export interface PairOptions {
  onProgress?: (state: PairingProgress) => void;
  /** Aborting closes the connection. Before `storing` nothing is saved; after it the pairing is left pending. */
  signal?: AbortSignal;
}

export interface Invitation {
  route: Route;
  code: string;
  expiresAtMs: number;
}

interface FlowStep {
  do: string;
  message?: Record<string, unknown>;
  ms?: number;
  code?: string;
  outcome?: string;
}

/** Set only by the testing entry point; production code has no way to name it. */
export const LOOPBACK = Symbol("tether.loopback");

export class TetherClient {
  private busy = false;
  private identityLoad?: Promise<string>;
  private hostWork = new Map<string, Promise<unknown>>();

  private constructor(
    readonly appId: string,
    readonly core: TetherCore,
    private store: TetherStore,
    private allowLoopback: boolean,
  ) {}

  static async create(options: ClientOptions): Promise<TetherClient> {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(options.appId)) throw new TetherError("invalid_scope");
    const core = options.core ?? (await loadCore(options.wasm));
    const loopback = (options as { [LOOPBACK]?: boolean })[LOOPBACK] === true;
    return new TetherClient(options.appId, core, options.store ?? new IndexedDBStore(), loopback);
  }

  records(): Promise<PeerRecord[]> {
    return this.store.records(this.appId);
  }

  /** The route in normal form if this client can use it, or undefined. */
  checkRoute(route: Route): Route | undefined {
    if (route.mode !== "cloud") return undefined;
    try {
      return this.core.call<{ route: Route }>("discovery.route", { route, allowLoopback: this.allowLoopback }).route;
    } catch {
      return undefined;
    }
  }

  /** Reads an invitation link meant for this app. Throws `invalid_invitation` or `invalid_route`. */
  readInvitation(url: string): Invitation {
    return this.core.call<Invitation>("discovery.read_invitation", { url, app: this.appId, now: Date.now() });
  }

  /** Pairs using an invitation link: its route and code together. */
  pairInvitation(url: string, options?: PairOptions): Promise<PeerRecord> {
    const invitation = this.readInvitation(url);
    return this.pair(invitation.route, invitation.code, options);
  }

  /** Pairs with the code the host's pairing window shows. Saved only once the host acknowledges. */
  async pair(route: Route, code: string, options: PairOptions = {}): Promise<PeerRecord> {
    if (route.mode !== "cloud") throw new TetherError("browser_route");
    if (this.busy) throw new TetherError("busy");
    this.busy = true;
    const { onProgress, signal } = options;
    let identity: { handle: number; publicKey: string } | undefined;
    let session: Session | undefined;
    let flow: number | undefined;
    const stop = () => session?.close();
    try {
      if (signal?.aborted) throw new TetherError("cancelled");
      signal?.addEventListener("abort", stop);
      identity = await this.identity();
      onProgress?.("checking");
      session = await Session.open(this.core, route, identity.handle, this.appId, undefined, this.allowLoopback);
      if (signal?.aborted) throw new TetherError("cancelled");
      const begun = this.core.call<{ handle: number; actions: FlowStep[] }>("code.begin", {
        app: this.appId, code, binding: session.binding, clientKey: identity.publicKey, hostKey: session.peer,
      });
      flow = begun.handle;
      let actions = begun.actions;
      const record: PeerRecord = {
        appId: this.appId, hostKey: session.peer, clientKey: identity.publicKey, route,
        confirmed: false, pairingId: crypto.randomUUID(),
      };
      const active = session;
      for (;;) {
        let next: FlowStep[] = [];
        for (const action of actions) {
          switch (action.do) {
            case "send":
              active.send(action.message!);
              break;
            case "receive":
              next = this.core.call<{ actions: FlowStep[] }>("flow.receive", { handle: flow, message: await active.receive(), now: 0 }).actions;
              break;
            case "store_pending": {
              // The last point a cancel can stop it: after this the ack goes out.
              if (signal?.aborted) throw new TetherError("cancelled");
              onProgress?.("storing");
              // The pending record is durable before the ack, so an interrupted pairing can recover.
              const saved = await this.serial(record.hostKey, () =>
                this.store.update(this.appId, record.hostKey, (current) => (current ? undefined : record)));
              if (saved?.pairingId !== record.pairingId) throw new TetherError("already_paired");
              next = this.core.call<{ actions: FlowStep[] }>("flow.stored", { handle: flow }).actions;
              break;
            }
            case "confirm":
              await this.confirmPending(record);
              break;
            case "outcome":
              onProgress?.("connected");
              return { ...record, confirmed: true };
            case "failed":
              throw new TetherError(action.code ?? "invalid_protocol");
          }
        }
        if (next.length === 0) throw new TetherError("invalid_protocol");
        actions = next;
      }
    } catch (error) {
      throw signal?.aborted ? new TetherError("cancelled") : error;
    } finally {
      signal?.removeEventListener("abort", stop);
      if (flow !== undefined) destroy(this.core, flow);
      session?.close();
      if (identity) destroy(this.core, identity.handle);
      this.busy = false;
    }
  }

  /** Confirms `record` only if it is still the same pending pairing; a discard in between wins. */
  private async confirmPending(record: PeerRecord): Promise<PeerRecord> {
    const saved = await this.serial(record.hostKey, () =>
      this.store.update(this.appId, record.hostKey, (current) =>
        current?.pairingId === record.pairingId && !current.confirmed ? { ...current, confirmed: true } : undefined));
    if (saved?.pairingId !== record.pairingId || !saved.confirmed) throw new TetherError("invalid_state");
    return saved;
  }

  /** Finishes a pairing whose acknowledgement never arrived. */
  async recover(record: PeerRecord): Promise<PeerRecord> {
    return this.withSession(record, false, async (session) => {
      session.send({ type: "pair.status" });
      await session.expect("pair.done");
      return this.confirmPending(record);
    });
  }

  /** The host's answer, over a fresh pinned connection. Never inferred from saved trust. */
  async status(record: PeerRecord): Promise<HostService[]> {
    return this.withSession(record, true, async (session) => {
      session.send({ type: "host.status" });
      const reply = await session.expect("host.status");
      const services = Array.isArray(reply.services) ? reply.services : [];
      return services
        .filter((s: any) => typeof s?.id === "string" && (s.kind === "tcp" || s.kind === "udp"))
        .slice(0, 64)
        .map((s: any) => ({ id: s.id, kind: s.kind }));
    });
  }

  /** Asks the host to forget this device, then forgets the host here. */
  async leave(record: PeerRecord): Promise<void> {
    await this.withSession(record, true, async (session) => {
      session.send({ type: "peer.leave" });
      await session.expect("peer.left");
    });
    await this.forget(record);
  }

  /** Forgets the host on this device only. The host keeps this device until its owner removes it. */
  async forget(record: PeerRecord): Promise<void> {
    await this.serial(record.hostKey, () =>
      this.store.update(this.appId, record.hostKey, (current) => (current?.pairingId === record.pairingId ? null : undefined)));
  }

  /** Removes a pairing that never finished. A confirmed or replaced record is left alone. */
  async discardPending(record: PeerRecord): Promise<void> {
    if (record.confirmed) throw new TetherError("invalid_state");
    await this.serial(record.hostKey, () =>
      this.store.update(this.appId, record.hostKey, (current) =>
        current?.pairingId === record.pairingId && !current.confirmed ? null : undefined));
  }

  async rename(record: PeerRecord, name: string): Promise<void> {
    const label = this.core.call<{ text: string }>("ui.label", { text: name, fallback: "" }).text;
    await this.serial(record.hostKey, () =>
      this.store.update(this.appId, record.hostKey, (current) =>
        current?.pairingId === record.pairingId ? { ...current, name: label || undefined } : undefined));
  }

  /** Opens a stream to one of the host's TCP services. Each message is one chunk of the stream. */
  async openStream(service: string, record: PeerRecord): Promise<TetherStream> {
    const session = await this.connect(record, true);
    try {
      session.send({ type: "service.open", service });
      const reply = await session.expect("service.ready");
      if (reply.kind !== "tcp") throw new TetherError("service_denied");
      return new TetherStream(session);
    } catch (error) {
      session.close();
      throw error;
    }
  }

  /** One change to a host's record at a time, in the order asked. */
  private serial<T>(hostKey: string, work: () => Promise<T>): Promise<T> {
    const previous = this.hostWork.get(hostKey) ?? Promise.resolve();
    const run = previous.then(work, work);
    const settled = run.catch(() => undefined);
    this.hostWork.set(hostKey, settled);
    void settled.then(() => {
      if (this.hostWork.get(hostKey) === settled) this.hostWork.delete(hostKey);
    });
    return run;
  }

  /** This app's identity in the core. Made once, even when several calls or tabs ask together. */
  private async identity(): Promise<{ handle: number; publicKey: string }> {
    this.identityLoad ??= (async () => {
      const saved = await this.store.identity(this.appId);
      if (saved) return saved;
      const made = this.core.call<{ handle: number; private: string }>("identity.generate");
      destroy(this.core, made.handle);
      return this.store.createIdentity(this.appId, made.private);
    })();
    let privateKey: string;
    try {
      privateKey = await this.identityLoad;
    } catch (error) {
      this.identityLoad = undefined;
      throw error;
    }
    const loaded = this.core.call<{ handle: number; public: string }>("identity.fromPrivate", { private: privateKey });
    return { handle: loaded.handle, publicKey: loaded.public };
  }

  private async connect(record: PeerRecord, confirmedOnly: boolean): Promise<Session> {
    const stored = (await this.records()).find((r) => r.hostKey === record.hostKey);
    if (!stored || stored.clientKey !== record.clientKey) throw new TetherError("identity_mismatch");
    if (confirmedOnly && !stored.confirmed) throw new TetherError("pairing_pending");
    const identity = await this.identity();
    try {
      if (identity.publicKey !== stored.clientKey) throw new TetherError("identity_mismatch");
      return await Session.open(this.core, stored.route, identity.handle, this.appId, stored.hostKey, this.allowLoopback);
    } finally {
      destroy(this.core, identity.handle);
    }
  }

  private async withSession<T>(record: PeerRecord, confirmedOnly: boolean, work: (session: Session) => Promise<T>): Promise<T> {
    const session = await this.connect(record, confirmedOnly);
    try {
      return await work(session);
    } finally {
      session.close();
    }
  }
}

/** A stream to a host service. `receive` returns null once the host has finished sending. */
export class TetherStream {
  private sentEnd = false;
  private receivedEnd = false;
  constructor(private session: Session) {}

  send(bytes: Uint8Array) {
    if (this.sentEnd) throw new TetherError("connection_closed");
    if (bytes.length > 16_384) throw new TetherError("invalid_frame");
    if (bytes.length > 0) this.session.sendBytes(bytes);
  }

  async receive(ms = 60_000): Promise<Uint8Array | null> {
    if (this.receivedEnd) return null;
    const bytes = await this.session.receiveBytes(ms);
    if (bytes.length === 0) {
      this.receivedEnd = true;
      return null;
    }
    return bytes;
  }

  /** Half-closes: the host's service sees end of input, and can still reply. */
  finish() {
    if (this.sentEnd) return;
    this.sentEnd = true;
    this.session.sendBytes(new Uint8Array());
  }

  close() {
    this.session.close();
  }
}
