import { createServer } from 'node:http';
import { once } from 'node:events';
import { generateKeyPair, SignJWT } from 'jose';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createJwtVerifier, createForwardHttpClient, createPageIndexSource } from '../dist/index.js';
import { createTetherMcpNodeHandler } from '../dist/node.js';

export const ISSUER = 'https://identity.example.test';
export const ISSUER2 = 'https://second-identity.example.test';
export const A = 'aaaaaaaaaaaaaaaaaaaaaaaa';
export const C = 'cccccccccccccccccccccccc';
export const B = 'bbbbbbbbbbbbbbbbbbbbbbbb';
export const EXTRA = Array.from({ length: 25 }, (_, n) => (n + 1).toString(16).padStart(24, '0'));
export async function listen(server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}
export async function closeServer(server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
export async function originFixture() {
  const docs = [A, C, ...EXTRA].map(id => ({ id, containerTag: 'alpha', title: id === C ? 'BOB-ONLY-CONTENT' : 'ALICE-CONTENT', structure: [{ text: id === C ? 'BOB-ONLY-CONTENT' : 'ALICE-CONTENT' }], internalApiKey: 'INTERNAL-DO-NOT-EXPOSE' }));
  docs.push({ id: B, containerTag: 'beta', title: 'BOB-ONLY-CONTENT', structure: [{ text: 'BOB-ONLY-CONTENT' }] });
  const state = { calls: [], poisoned: false, delay: undefined, redirect: false, oversize: false };
  const server = createServer(async (req, res) => {
    let data = ''; for await (const chunk of req) data += chunk;
    const url = new URL(req.url, 'http://fixture');
    const body = data ? JSON.parse(data) : undefined;
    state.calls.push({ path: url.pathname, query: Object.fromEntries(url.searchParams), body, authorization: req.headers.authorization });
    res.setHeader('Content-Type', 'application/json');
    if (!['Bearer synthetic-upstream-alice', 'Bearer synthetic-upstream-bob', 'Bearer synthetic-upstream-other'].includes(req.headers.authorization)) { res.writeHead(401); res.end('{}'); return; }
    if (state.redirect) { res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data' }); res.end('{}'); return; }
    if (state.oversize) { res.end(JSON.stringify({ data: 'x'.repeat(600000) })); return; }
    if (url.pathname === '/v3/documents') {
      const scope = docs.filter(d => d.containerTag === url.searchParams.get('containerTag'));
      const offset = Number(url.searchParams.get('cursor') ?? 0);
      const page = scope.slice(offset, offset + 100);
      res.end(JSON.stringify({ documents: page.map(({ id, containerTag, title }) => ({ id, containerTag, title })), nextCursor: offset + page.length < scope.length ? String(offset + page.length) : null })); return;
    }
    if (url.pathname.startsWith('/v3/documents/')) {
      if (state.delay) await state.delay();
      const doc = state.poisoned ? docs.find(d => d.id === B) : docs.find(d => d.id === url.pathname.split('/').at(-1));
      if (!doc) res.writeHead(404);
      res.end(JSON.stringify(doc ?? {})); return;
    }
    if (url.pathname === '/v4/documents/search') {
      const selected = docs.filter(d => d.id === body.documentId && d.containerTag === body.containerTag);
      res.end(JSON.stringify({ matches: selected.map(d => ({ documentId: d.id, nodeId: '1', title: d.title, text: d.structure[0].text, score: 0.9 })), globalSecret: 'INTERNAL-DO-NOT-EXPOSE', coverage: { eligibleDocuments: 999999 } })); return;
    }
    res.writeHead(404); res.end('{}');
  });
  return { state, docs, server, origin: await listen(server), close: () => closeServer(server) };
}
export async function gatewayFixture({ sourceOrigin, timeoutMs = 3000, maxConcurrentRequests = 32 } = {}) {
  const origin = sourceOrigin ? undefined : await originFixture();
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  let node;
  const http = createServer((req, res) => void node.handler(req, res));
  const resource = `${await listen(http)}/mcp`;
  const policies = new Map([
    [`${ISSUER}|alice`, { revision: 'one', datasets: [{ serviceId: 'pageindex', datasetId: 'alpha', includeRecordIds: [A, C, ...EXTRA], excludeRecordIds: [C] }] }],
    [`${ISSUER}|bob`, { revision: 'one', datasets: [{ serviceId: 'pageindex', datasetId: 'alpha', includeRecordIds: [C] }, { serviceId: 'pageindex', datasetId: 'beta' }] }],
    [`${ISSUER2}|alice`, { revision: 'one', datasets: [{ serviceId: 'pageindex', datasetId: 'beta' }] }],
  ]);
  const state = { credentialCalls: 0, grantsHook: undefined, audit: [], signals: [] };
  const one = createJwtVerifier({ issuer: ISSUER, resource, key: publicKey });
  const two = createJwtVerifier({ issuer: ISSUER2, resource, key: publicKey });
  const source = createPageIndexSource({ id: 'pageindex', datasets: [{ id: 'alpha', title: 'Alpha', containerTag: 'alpha' }, { id: 'beta', title: 'Beta', containerTag: 'beta' }], http: { request: (path, options) => { state.signals.push(options.signal); return createForwardHttpClient(sourceOrigin ?? origin.origin).request(path, options); } }, accessToken: async p => { state.credentialCalls++; return `synthetic-upstream-${p.issuer === ISSUER2 ? 'other' : p.subject}`; } });
  node = createTetherMcpNodeHandler({ resource, authorizationServers: [ISSUER, ISSUER2], timeoutMs, maxConcurrentRequests, maxRequestsPerPrincipal: Math.min(4, maxConcurrentRequests), verifyToken: async (token, signal) => { try { return await one(token, signal); } catch { return two(token, signal); } }, grants: async (p, signal) => { if (state.grantsHook) await state.grantsHook(p, signal); return p.clientId === 'synthetic-client' ? policies.get(`${p.issuer}|${p.subject}`) ?? null : null; }, sources: [source], audit: event => { state.audit.push(event); } });
  const token = async (subject, overrides = {}) => new SignJWT({ scope: 'tether:read', client_id: 'synthetic-client', ...overrides.payload }).setProtectedHeader({ alg: 'RS256', typ: overrides.typ ?? 'at+jwt' }).setIssuer(overrides.issuer ?? ISSUER).setSubject(subject).setAudience(overrides.audience ?? resource).setIssuedAt().setExpirationTime(overrides.exp ?? '5m').sign(overrides.key ?? privateKey);
  const clients = [];
  const client = async (subject = 'alice', mode = 'auto', overrides = {}) => {
    const bearer = await token(subject, overrides);
    const c = new Client({ name: 'fixture', version: '1' }, { versionNegotiation: { mode } });
    await c.connect(new StreamableHTTPClientTransport(new URL(resource), { authProvider: { token: async () => bearer } }));
    clients.push(c); return c;
  };
  return { origin, state, policies, resource, token, client, publicKey, source, async close() { for (const c of clients) await c.close(); await node.close(); await closeServer(http); await origin?.close(); } };
}
export const call = async (client, name, args = {}) => client.callTool({ name, arguments: args });
export const data = result => result.structuredContent ?? JSON.parse(result.content[0].text);
