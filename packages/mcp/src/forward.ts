import { AccessError, bounded } from './policy.js';

export interface JsonRequester {
  request(path: string, options: { token: string; signal: AbortSignal; body?: unknown }): Promise<unknown>;
}
/** A caller-owned `tether client forward` listener, never a model-selected remote URL. */
export function createForwardHttpClient(origin: string): JsonRequester {
  const base = new URL(origin);
  if (base.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(base.hostname)
    || !base.port || base.username || base.password || base.pathname !== '/' || base.search || base.hash) {
    throw new Error('Use the fixed literal-loopback HTTP origin of your Tether forwarder.');
  }
  return {
    async request(path, { token, signal, body }) {
      if (!path.startsWith('/') || path.startsWith('//') || /[\\\r\n#]/.test(path) || path.length > 2048
        || !token || token.length > 4096 || /[^\x21-\x7e]/.test(token)) throw new AccessError();
      const url = new URL(path, base);
      if (url.origin !== base.origin) throw new AccessError();
      const payload = body === undefined ? undefined : JSON.stringify(body);
      if (payload && Buffer.byteLength(payload) > 65536) throw new AccessError();
      const response = await bounded(fetch(url, {
        method: payload === undefined ? 'GET' : 'POST', redirect: 'error', signal,
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', ...(payload === undefined ? {} : { 'Content-Type': 'application/json' }) },
        body: payload,
      }), signal);
      if (!response.ok || !response.headers.get('content-type')?.toLowerCase().includes('application/json')) {
        await response.body?.cancel().catch(() => {}); throw new AccessError();
      }
      const reader = response.body?.getReader();
      if (!reader) throw new AccessError();
      const chunks: Uint8Array[] = []; let size = 0;
      try {
        while (true) {
          const { done, value } = await bounded(reader.read(), signal);
          if (done) break;
          size += value.byteLength;
          if (size > 524288) throw new AccessError();
          chunks.push(value);
        }
        return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
      } finally { await reader.cancel().catch(() => {}); }
    },
  };
}
