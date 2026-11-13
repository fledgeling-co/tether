// Where the browser keeps this device's identity and its paired hosts.
//
// The default store is IndexedDB. The identity's private key is sealed with an AES-GCM key that
// the browser marks non-extractable, so the raw key never sits in IndexedDB or in an export of
// it. That protects the key at rest; it does not protect it from script running on your origin,
// which can still ask the browser to unseal it. Serve the app with a strict Content Security Policy.
//
// Every write resolves only once its transaction has committed, because the pairing flow sends
// its acknowledgement as soon as the pending record is saved.
import type { Route } from "./session.js";
import { TetherError } from "./core.js";

/** A paired host, the same record every kit keeps. `confirmed` is false until the host acknowledged. */
export interface PeerRecord {
  appId: string;
  hostKey: string;
  clientKey: string;
  route: Route;
  confirmed: boolean;
  pairingId: string;
  /** What this device calls the host. Chosen locally; the host never sees it. */
  name?: string;
}

/** A change to one host's record, decided against what is stored now: a record to save, null to delete, undefined to leave it. */
export type RecordChange = (current: PeerRecord | undefined) => PeerRecord | null | undefined;

export interface TetherStore {
  /** The private key for `appId`, or undefined before the first pairing. */
  identity(appId: string): Promise<string | undefined>;
  /** Saves `privateKey` unless another context saved one first, and returns whichever is stored. */
  createIdentity(appId: string, privateKey: string): Promise<string>;
  records(appId: string): Promise<PeerRecord[]>;
  /** Applies `change` atomically and returns the record as it now stands. */
  update(appId: string, hostKey: string, change: RecordChange): Promise<PeerRecord | undefined>;
}

/** Keeps everything in memory, for tests and for pages that must not persist trust. */
export class MemoryStore implements TetherStore {
  private keys = new Map<string, string>();
  private peers = new Map<string, PeerRecord>();
  async identity(appId: string) {
    return this.keys.get(appId);
  }
  async createIdentity(appId: string, privateKey: string) {
    if (!this.keys.has(appId)) this.keys.set(appId, privateKey);
    return this.keys.get(appId)!;
  }
  async records(appId: string) {
    return [...this.peers.values()].filter((r) => r.appId === appId).map((r) => ({ ...r }));
  }
  async update(appId: string, hostKey: string, change: RecordChange) {
    const key = `${appId}\n${hostKey}`;
    const current = this.peers.get(key);
    const next = change(current ? { ...current } : undefined);
    if (next === null) this.peers.delete(key);
    else if (next) this.peers.set(key, { ...next });
    const stored = this.peers.get(key);
    return stored ? { ...stored } : undefined;
  }
}

function request<T>(work: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    work.onsuccess = () => resolve(work.result);
    work.onerror = () => reject(new TetherError("storage"));
  });
}

function committed(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    let cause: string | undefined;
    tx.oncomplete = () => resolve();
    // A failed request bubbles here before the abort; remember why so the abort can say.
    tx.onerror = (event) => void (cause ??= ((event.target as IDBRequest | null)?.error ?? tx.error)?.name);
    tx.onabort = () => reject(new TetherError((cause ?? tx.error?.name) === "ConstraintError" ? "exists" : "storage"));
  });
}

export class IndexedDBStore implements TetherStore {
  private db: Promise<IDBDatabase>;

  constructor(name = "tether") {
    this.db = new Promise((resolve, reject) => {
      const open = indexedDB.open(name, 1);
      open.onupgradeneeded = () => {
        open.result.createObjectStore("seal");
        open.result.createObjectStore("identities");
        open.result.createObjectStore("peers", { keyPath: ["appId", "hostKey"] });
      };
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(new TetherError("storage"));
    });
  }

  private async read<T>(name: string, work: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    return request(work((await this.db).transaction(name, "readonly").objectStore(name)));
  }

  /** Runs `work` in one read-write transaction and resolves once it has committed. */
  private async write(name: string, work: (store: IDBObjectStore) => void): Promise<void> {
    const tx = (await this.db).transaction(name, "readwrite", { durability: "strict" });
    const done = committed(tx);
    work(tx.objectStore(name));
    await done;
  }

  /** The non-extractable sealing key. The first context to add one wins; the rest read it. */
  private async seal(): Promise<CryptoKey> {
    const existing = await this.read("seal", (s) => s.get("v1"));
    if (existing instanceof CryptoKey) return existing;
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await this.write("seal", (s) => void s.add(key, "v1")).catch((error) => {
      if (!(error instanceof TetherError && error.code === "exists")) throw error;
    });
    const stored = await this.read("seal", (s) => s.get("v1"));
    if (!(stored instanceof CryptoKey)) throw new TetherError("storage");
    return stored;
  }

  async identity(appId: string): Promise<string | undefined> {
    const sealed = await this.read("identities", (s) => s.get(appId));
    if (!sealed) return undefined;
    try {
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.iv, additionalData: new TextEncoder().encode(appId) }, await this.seal(), sealed.data);
      return new TextDecoder().decode(plain);
    } catch {
      throw new TetherError("storage");
    }
  }

  async createIdentity(appId: string, privateKey: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(appId) }, await this.seal(), new TextEncoder().encode(privateKey));
    await this.write("identities", (s) => void s.add({ iv, data }, appId)).catch((error) => {
      if (!(error instanceof TetherError && error.code === "exists")) throw error;
    });
    const stored = await this.identity(appId);
    if (!stored) throw new TetherError("storage");
    return stored;
  }

  async records(appId: string): Promise<PeerRecord[]> {
    const all: PeerRecord[] = await this.read("peers", (s) => s.getAll());
    return all.filter((r) => r.appId === appId);
  }

  async update(appId: string, hostKey: string, change: RecordChange): Promise<PeerRecord | undefined> {
    let result: PeerRecord | undefined;
    await this.write("peers", (s) => {
      const get = s.get([appId, hostKey]);
      get.onsuccess = () => {
        const current = get.result as PeerRecord | undefined;
        const next = change(current ? { ...current } : undefined);
        if (next === null) {
          s.delete([appId, hostKey]);
          result = undefined;
        } else if (next) {
          s.put(next);
          result = next;
        } else result = current;
      };
    });
    return result;
  }
}
