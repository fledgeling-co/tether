// The Rust core, compiled to WebAssembly. Every request is one JSON object in, one JSON object
// out, the same C ABI the native kits call. Responses can hold key material; the core wipes its
// own copies, but strings held by JavaScript can't be wiped, so keep them short-lived.

/** A failure from the core or the protocol, named by a stable code (`invalid_code`, `busy`, …). */
export class TetherError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "TetherError";
  }
}

export interface TetherCore {
  call<T = Record<string, any>>(command: string, request?: Record<string, unknown>): T;
}

interface Exports {
  memory: WebAssembly.Memory;
  tether_call(ptr: number, len: number): number;
  tether_free(ptr: number): void;
  tether_alloc(len: number): number;
  tether_dealloc(ptr: number, len: number): void;
}

const MAX_INPUT = 131_072;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/** Where the core comes from: a URL (default `tether.wasm` beside this module), bytes, or a compiled module. */
export type CoreSource = URL | string | ArrayBuffer | Uint8Array | WebAssembly.Module;

export async function loadCore(source?: CoreSource): Promise<TetherCore> {
  let exports: Exports | undefined;
  const imports = {
    tether: {
      // crypto.getRandomValues fills at most 65,536 bytes per call.
      random(ptr: number, len: number): number {
        try {
          const target = new Uint8Array(exports!.memory.buffer, ptr, len);
          for (let at = 0; at < len; at += 65_536) crypto.getRandomValues(target.subarray(at, Math.min(len, at + 65_536)));
          return 0;
        } catch {
          return 1;
        }
      },
    },
  };
  const resolved = source ?? new URL("./tether.wasm", import.meta.url);
  let instance: WebAssembly.Instance;
  if (resolved instanceof WebAssembly.Module) {
    instance = await WebAssembly.instantiate(resolved, imports);
  } else if (resolved instanceof ArrayBuffer || resolved instanceof Uint8Array) {
    instance = (await WebAssembly.instantiate(resolved as BufferSource, imports)).instance;
  } else {
    const response = await fetch(resolved);
    if (!response.ok) throw new TetherError("core_unavailable");
    instance = (await WebAssembly.instantiate(await response.arrayBuffer(), imports)).instance;
  }
  exports = instance.exports as unknown as Exports;
  const core = exports;
  return {
    call<T>(command: string, request: Record<string, unknown> = {}): T {
      const input = encoder.encode(JSON.stringify({ ...request, command }));
      if (input.length === 0 || input.length > MAX_INPUT) throw new TetherError("invalid_length");
      const ptr = core.tether_alloc(input.length);
      new Uint8Array(core.memory.buffer, ptr, input.length).set(input);
      input.fill(0);
      const out = core.tether_call(ptr, input.length);
      core.tether_dealloc(ptr, input.length);
      const memory = new Uint8Array(core.memory.buffer);
      let end = out;
      while (memory[end] !== 0) end++;
      const text = decoder.decode(memory.subarray(out, end));
      core.tether_free(out);
      const value = JSON.parse(text);
      if (value.ok !== true) throw new TetherError(String(value.error ?? "operation_refused"));
      delete value.ok;
      return value as T;
    },
  };
}

export function toBase64(bytes: Uint8Array): string {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text);
}

export function fromBase64(text: string): Uint8Array {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}
