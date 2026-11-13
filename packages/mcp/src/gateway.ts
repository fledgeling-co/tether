import { createMcpHandler, McpServer, ResourceTemplate } from '@modelcontextprotocol/server';
import { z } from 'zod/v4';
import { validatePrincipal } from './auth.js';
import { DataAccess } from './access.js';
import { AccessError, bounded, boundedJSON, idSchema, principalKey } from './policy.js';
import type { GatewayOptions, Principal } from './types.js';

function secureURL(raw: string): URL {
  const url = new URL(raw);
  if (url.username || url.password || url.hash || url.search || (url.protocol !== 'https:'
    && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)))) throw new Error('Use HTTPS, or a literal loopback HTTP URL for development.');
  return url;
}
async function readBody(response: Response, signal: AbortSignal): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    while (true) {
      const { done, value } = await bounded(reader.read(), signal);
      if (done) break;
      length += value.byteLength;
      if (length > 1048576) throw new AccessError();
      chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks);
}
export function createTetherMcpGateway(options: GatewayOptions) {
  const resource = secureURL(options.resource);
  if (!options.authorizationServers.length || options.authorizationServers.length > 8) throw new Error('Configure authorization server discovery.');
  for (const issuer of options.authorizationServers) secureURL(issuer);
  const hosts = new Set([resource.host, ...(options.allowedHosts ?? [])]);
  const origins = new Set([resource.origin, ...(options.allowedOrigins ?? [])]);
  for (const origin of origins) if (secureURL(origin).origin !== origin) throw new Error('Configure exact origins.');
  const metadataPath = `/.well-known/oauth-protected-resource${resource.pathname === '/' ? '' : resource.pathname}`;
  const metadataUrl = new URL(metadataPath, resource.origin).href;
  const access = new DataAccess(options);
  const timeoutMs = options.timeoutMs ?? 30000;
  const maxRequests = options.maxConcurrentRequests ?? 32;
  const maxPerUser = options.maxRequestsPerPrincipal ?? Math.min(4, maxRequests);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 120000
    || !Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 256
    || !Number.isInteger(maxPerUser) || maxPerUser < 1 || maxPerUser > maxRequests) throw new Error('Invalid gateway limits.');
  let active = 0;
  let closed = false;
  const controllers = new Set<AbortController>();
  const users = new Map<string, number>();
  const handler = createMcpHandler(ctx => {
    const principal = ctx.authInfo?.extra?.principal as Principal | undefined;
    const signal = ctx.requestInfo?.signal;
    if (!principal || !signal) throw new AccessError();
    const server = new McpServer({ name: 'tether-data', version: '0.1.0' });
    const annotations = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
    const run = async (op: string, args = {}) => {
      try {
        const data = await access.execute(principal, signal, op, args);
        return { content: [{ type: 'text' as const, text: boundedJSON(data) }], structuredContent: data as Record<string, unknown> };
      } catch { return { isError: true, content: [{ type: 'text' as const, text: 'Access unavailable.' }] }; }
    };
    const scope = { serviceId: idSchema, datasetId: idSchema };
    const paging = { limit: z.number().int().min(1).max(50).optional(), cursor: z.string().max(8192).optional() };
    server.registerTool('tether_list_services', { description: 'List the services and datasets this signed-in account may access.', inputSchema: z.object({}).strict(), annotations }, () => run('catalog'));
    server.registerTool('tether_list_records', { description: 'List permitted records in one granted dataset; follow only its returned user-bound cursor.', inputSchema: z.object({ ...scope, ...paging }).strict(), annotations }, args => run('list', args));
    server.registerTool('tether_read_record', { description: 'Read one permitted record. Include its recordRef from a prior list/search for efficient lookup.', inputSchema: z.object({ ...scope, recordId: idSchema, recordRef: z.string().max(8192).optional() }).strict(), annotations }, args => run('read', args));
    server.registerTool('tether_search_records', { description: 'Search permitted records. partial=true means only the stated bounded portion was examined.', inputSchema: z.object({ ...scope, ...paging, query: z.string().min(1).max(2000) }).strict(), annotations }, args => run('search', args));
    server.registerResource('account-catalog', 'tether://catalog', { title: 'Your connected datasets', mimeType: 'application/json' }, async uri => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: boundedJSON(await access.execute(principal, signal, 'catalog')) }] }));
    server.registerResource('record', new ResourceTemplate('tether://records/{serviceId}/{datasetId}/{recordId}?ref={recordRef}', { list: undefined }), { title: 'Permitted service record', mimeType: 'application/json' }, async (uri, variables) => {
      const args = z.object({ ...scope, recordId: idSchema, recordRef: z.string().max(8192) }).strict().parse(variables);
      const data = await access.execute(principal, signal, 'read', args);
      return { contents: [{ uri: uri.href, mimeType: 'application/json', text: boundedJSON(data) }] };
    });
    return server;
  }, { responseMode: 'json', maxRequestBodySize: 65536, maxSubscriptions: 0, onerror: () => {} });
  return {
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const origin = request.headers.get('origin');
      const headers: Record<string, string> = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Vary': 'Origin' };
      if (origin && origins.has(origin)) Object.assign(headers, { 'Access-Control-Allow-Origin': origin, 'Access-Control-Expose-Headers': 'WWW-Authenticate' });
      const answer = (status: number, value: unknown, extra = {}) => new Response(JSON.stringify(value), { status, headers: { ...headers, 'Content-Type': 'application/json', ...extra } });
      if (closed) return answer(503, { error: 'Unavailable.' });
      if (!hosts.has(url.host) || (request.headers.has('host') && !hosts.has(request.headers.get('host')!)) || (origin && !origins.has(origin))) return answer(403, { error: 'Request refused.' });
      if (request.method === 'GET' && [metadataPath, '/.well-known/oauth-protected-resource'].includes(url.pathname)) return answer(200, { resource: options.resource, authorization_servers: [...options.authorizationServers], scopes_supported: ['tether:read'], bearer_methods_supported: ['header'] });
      if (url.pathname !== resource.pathname || url.search) return answer(404, { error: 'Not found.' });
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...headers, 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'authorization, content-type, accept, mcp-protocol-version' } });
      if (request.method !== 'POST') return answer(405, { error: 'Method not allowed.' }, { Allow: 'POST, OPTIONS' });
      if (active >= maxRequests) return answer(429, { error: 'Busy.' }, { 'Retry-After': '1' });
      active++;
      const deadline = new AbortController();
      controllers.add(deadline);
      const timer = setTimeout(() => deadline.abort(), timeoutMs);
      const signal = AbortSignal.any([deadline.signal, request.signal]);
      let user: string | undefined;
      try {
        const authorization = request.headers.get('authorization');
        const match = authorization?.match(/^Bearer ([A-Za-z0-9._~+\/-]+={0,2})$/i);
        if (!match || match[1]!.length > 8192) throw new AccessError();
        let principal: Principal;
        try {
          principal = validatePrincipal(await bounded(options.verifyToken(match[1]!, signal), signal), options.resource);
          if (!options.authorizationServers.includes(principal.issuer)) throw new AccessError();
        } catch { throw new AccessError(); }
        user = principalKey(principal);
        if ((users.get(user) ?? 0) >= maxPerUser) { user = undefined; return answer(429, { error: 'Busy.' }, { 'Retry-After': '1' }); }
        users.set(user, (users.get(user) ?? 0) + 1);
        const response = await bounded(handler.fetch(new Request(request, { signal }), { authInfo: { token: match[1]!, clientId: principal.clientId, resource, scopes: [...principal.scopes], expiresAt: principal.expiresAt, extra: { principal } } }), signal);
        const body = await readBody(response, signal);
        validatePrincipal(principal, options.resource);
        const outgoing = new Headers(response.headers);
        for (const [key, value] of Object.entries(headers)) outgoing.set(key, value);
        return new Response(body.byteLength ? new TextDecoder().decode(body) : null, { status: response.status, headers: outgoing });
      } catch {
        if (signal.aborted) return answer(504, { error: 'Request timed out or was cancelled.' });
        return answer(401, { error: 'Unauthorized.' }, { 'WWW-Authenticate': `Bearer resource_metadata="${metadataUrl}", scope="tether:read"` });
      } finally {
        clearTimeout(timer); controllers.delete(deadline); active--;
        if (user) { const left = (users.get(user) ?? 1) - 1; if (left) users.set(user, left); else users.delete(user); }
      }
    },
    close: async () => { closed = true; for (const c of controllers) c.abort(); await handler.close(); },
  };
}
