import test from 'node:test';
import { request as httpRequest } from 'node:http';
import assert from 'node:assert/strict';
import { generateKeyPair } from 'jose';
import { DataAccess } from '../dist/access.js';
import { gatewayFixture, ISSUER, ISSUER2, A, B, C, EXTRA, call, data } from './fixture.mjs';

test('authenticated MCP and account isolation', async t => {
  const f = await gatewayFixture();
  t.after(() => f.close());
  const alice = await f.client('alice'); const bob = await f.client('bob');
  const scope = { serviceId: 'pageindex', datasetId: 'alpha' };
  await t.test('official clients discover tools and legacy clients can call', async () => {
    const tools = await alice.listTools(); assert.equal(tools.tools.length, 4); assert.ok(tools.tools.every(t => t.annotations.readOnlyHint));
    const legacy = await f.client('alice', 'legacy');
    assert.deepEqual(data(await call(legacy, 'tether_list_services')).services[0].datasets.map(d => d.id), ['alpha']);
    assert.deepEqual(data(await call(bob, 'tether_list_services')).services[0].datasets.map(d => d.id), ['alpha', 'beta']);
  });
  await t.test('public resource metadata and bearer challenges are discoverable', async () => {
    for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const response = await fetch(new URL(path, f.resource)); assert.equal(response.status, 200);
      const body = await response.json(); assert.equal(body.resource, f.resource); assert.deepEqual(body.scopes_supported, ['tether:read']);
    }
    const r = await fetch(f.resource, { method: 'POST', body: '{}' }); assert.equal(r.status, 401); assert.match(r.headers.get('www-authenticate'), /resource_metadata=.*mcp/); assert.equal(r.headers.get('cache-control'), 'no-store');
  });
  await t.test('forged, expired, wrong audience/issuer/type/scope tokens never touch the source', async () => {
    const { privateKey } = await generateKeyPair('RS256');
    const bad = [await f.token('alice', { key: privateKey }), await f.token('alice', { exp: 1 }), await f.token('alice', { audience: 'https://elsewhere.test/mcp' }), await f.token('alice', { issuer: 'https://evil.test' }), await f.token('alice', { typ: 'JWT' }), await f.token('alice', { payload: { scope: 'admin' } })];
    const before = f.state.credentialCalls;
    for (const token of bad) { const r = await fetch(f.resource, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: '{}' }); assert.equal(r.status, 401); }
    assert.equal(f.state.credentialCalls, before);
  });
  await t.test('issuer plus subject and OAuth client identify the account', async () => {
    const other = await f.client('alice', 'auto', { issuer: ISSUER2 });
    assert.deepEqual(data(await call(other, 'tether_list_services')).services[0].datasets.map(d => d.id), ['beta']);
    const unapproved = await f.client('alice', 'auto', { payload: { client_id: 'unapproved-client' } });
    assert.equal((await call(unapproved, 'tether_list_services')).isError, true);
  });
  let aliceRef;
  await t.test('include/exclude and pagination do not drop approved metadata', async () => {
    const seen = []; let cursor;
    for (let page = 0; page < 20; page++) {
      const result = data(await call(alice, 'tether_list_records', { ...scope, limit: 3, ...(cursor ? { cursor } : {}) }));
      for (const record of result.records) { seen.push(record.id); if (record.id === A) aliceRef = record; }
      cursor = result.nextCursor; if (!cursor) break;
    }
    assert.deepEqual(seen.sort(), [A, ...EXTRA].sort()); assert.ok(!seen.includes(C)); assert.ok(aliceRef.recordRef);
  });
  await t.test('direct IDs, signed references and resources enforce the same policy', async () => {
    const a = data(await call(alice, 'tether_read_record', { ...scope, recordId: A, recordRef: aliceRef.recordRef }));
    assert.equal(a.id, A); assert.match(JSON.stringify(a), /ALICE-CONTENT/); assert.ok(!JSON.stringify(a).includes('INTERNAL-DO-NOT-EXPOSE'));
    const resource = await alice.readResource({ uri: aliceRef.uri }); assert.match(resource.contents[0].text, /ALICE-CONTENT/);
    const before = f.state.credentialCalls;
    for (const [client, id, ref] of [[alice, C, undefined], [bob, A, aliceRef.recordRef]]) assert.equal((await call(client, 'tether_read_record', { ...scope, recordId: id, ...(ref ? { recordRef: ref } : {}) })).isError, true);
    assert.equal(f.state.credentialCalls, before);
    await assert.rejects(bob.readResource({ uri: aliceRef.uri }));
    assert.equal(f.state.credentialCalls, before);
  });
  await t.test('signed cursors reject another user, tampering and another query', async () => {
    const page = data(await call(alice, 'tether_list_records', { ...scope, limit: 1 })); assert.ok(page.nextCursor);
    const before = f.state.credentialCalls;
    for (const [client, cursor] of [[bob, page.nextCursor], [alice, `${page.nextCursor}x`]]) assert.equal((await call(client, 'tether_list_records', { ...scope, cursor })).isError, true);
    const search = data(await call(alice, 'tether_search_records', { ...scope, query: 'alpha' })); assert.ok(search.nextCursor);
    const afterSearch = f.state.credentialCalls;
    assert.equal((await call(alice, 'tether_search_records', { ...scope, query: 'different', cursor: search.nextCursor })).isError, true);
    assert.equal(f.state.credentialCalls, afterSearch); assert.ok(afterSearch > before);
  });
  await t.test('search never passes an excluded ID into ranking and drops global diagnostics', async () => {
    f.origin.state.calls.length = 0;
    const result = data(await call(alice, 'tether_search_records', { ...scope, query: 'evidence' }));
    assert.equal(result.partial, true); assert.ok(result.records.length > 0);
    const searches = f.origin.state.calls.filter(c => c.path === '/v4/documents/search');
    assert.ok(searches.length > 0); assert.ok(searches.every(c => c.body.documentId && c.body.documentId !== C && c.body.containerTag === 'alpha'));
    assert.ok(!JSON.stringify(result).includes('BOB-ONLY-CONTENT')); assert.ok(!JSON.stringify(result).includes('999999')); assert.ok(!JSON.stringify(result).includes('INTERNAL-DO-NOT-EXPOSE'));
    assert.ok(f.origin.state.calls.every(c => c.authorization === 'Bearer synthetic-upstream-alice'));
  });
  await t.test('model arguments cannot override identity, destination, filters or credentials', async () => {
    const before = f.state.credentialCalls;
    for (const extra of [{ userId: 'bob' }, { url: 'http://169.254.169.254/' }, { filter: {} }, { token: 'synthetic-upstream-bob' }]) {
      const result = await call(alice, 'tether_list_records', { ...scope, ...extra }).catch(() => ({ isError: true })); assert.equal(result.isError, true);
    }
    assert.equal((await call(alice, 'tether_list_records', { serviceId: 'unknown', datasetId: 'alpha' })).isError, true);
    assert.equal((await call(alice, 'tether_read_record', { ...scope, recordId: '../beta' }).catch(() => ({ isError: true }))).isError, true);
    assert.equal(f.state.credentialCalls, before);
  });
  await t.test('host/origin checks, query tokens and oversized bodies fail closed', async () => {
    const token = await f.token('alice');
    const hostileOrigin = await fetch(f.resource, { method: 'POST', headers: { Origin: 'https://evil.test', Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: '{}' }); assert.equal(hostileOrigin.status, 403);
    // Fetch forbids/normalises Host overrides; use an actual raw HTTP request for this negative control.
    const hostileHost = await new Promise((resolve, reject) => { const req = httpRequest(f.resource, { method: 'POST', headers: { Host: 'evil.test', Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }, res => { res.resume(); resolve(res.statusCode); }); req.on('error', reject); req.end('{}'); });
    assert.equal(hostileHost, 403);
    assert.equal((await fetch(`${f.resource}?access_token=${token}`, { method: 'POST', body: '{}' })).status, 404);
    const r = await fetch(f.resource, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ x: 'x'.repeat(70000) }) }); assert.equal(r.status, 413);
  });
  await t.test('poisoned upstream document tuples and redirects release no data', async () => {
    f.origin.state.poisoned = true;
    const result = await call(alice, 'tether_read_record', { ...scope, recordId: A, recordRef: aliceRef.recordRef }); assert.equal(result.isError, true); assert.ok(!JSON.stringify(result).includes('BOB-ONLY-CONTENT'));
    f.origin.state.poisoned = false; f.origin.state.redirect = true;
    assert.equal((await call(alice, 'tether_list_records', scope)).isError, true); f.origin.state.redirect = false;
    f.origin.state.oversize = true; assert.equal((await call(alice, 'tether_list_records', scope)).isError, true); f.origin.state.oversize = false;
  });
  await t.test('revocation and changes without a revision bump invalidate in-flight results', async () => {
    for (const remove of [false, true]) {
      const prior = structuredClone(f.policies.get(`${ISSUER}|alice`));
      let release; let reached;
      const pending = new Promise(r => { reached = r; });
      f.origin.state.delay = () => { reached(); return new Promise(r => { release = r; }); };
      const work = call(alice, 'tether_read_record', { ...scope, recordId: A }); await pending;
      if (remove) f.policies.delete(`${ISSUER}|alice`); else f.policies.get(`${ISSUER}|alice`).datasets[0].excludeRecordIds.push(A);
      release(); const result = await work; assert.equal(result.isError, true); assert.ok(!JSON.stringify(result).includes('ALICE-CONTENT'));
      f.origin.state.delay = undefined; f.policies.set(`${ISSUER}|alice`, prior);
    }
  });
  await t.test('empty includes call no source and stale record references are refused', async () => {
    const prior = structuredClone(f.policies.get(`${ISSUER}|alice`)); const before = f.state.credentialCalls;
    f.policies.set(`${ISSUER}|alice`, { revision: 'two', datasets: [{ ...scope, includeRecordIds: [] }] });
    assert.deepEqual(data(await call(alice, 'tether_list_records', scope)).records, []); assert.equal(f.state.credentialCalls, before);
    f.policies.set(`${ISSUER}|alice`, { ...prior, revision: 'three' });
    assert.equal((await call(alice, 'tether_read_record', { ...scope, recordId: A, recordRef: aliceRef.recordRef })).isError, true); assert.equal(f.state.credentialCalls, before);
    f.policies.set(`${ISSUER}|alice`, prior);
  });
  assert.ok(f.state.audit.length > 0); assert.ok(f.state.audit.every(e => !JSON.stringify(e).includes('Bearer') && !JSON.stringify(e).includes('ALICE-CONTENT')));
});

test('a non-cooperative grant provider is bounded by the request deadline', async t => {
  const f = await gatewayFixture({ timeoutMs: 100 }); t.after(() => f.close());
  const client = await f.client('alice'); f.state.grantsHook = () => new Promise(() => {});
  const started = Date.now(); await assert.rejects(call(client, 'tether_list_services')); assert.ok(Date.now() - started < 1500);
});

test('disconnect cancels the upstream request signal', async t => {
  const f = await gatewayFixture(); t.after(() => f.close());
  let reached, release;
  const arrived = new Promise(resolve => { reached = resolve; });
  f.origin.state.delay = () => { reached(); return new Promise(resolve => { release = resolve; }); };
  const token = await f.token('alice');
  const request = httpRequest(f.resource, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' } });
  request.on('error', () => {});
  request.end(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'tether_read_record', arguments: { serviceId: 'pageindex', datasetId: 'alpha', recordId: A } } }));
  await arrived; const signal = f.state.signals.at(-1); assert.equal(signal.aborted, false);
  const cancelled = new Promise(resolve => signal.addEventListener('abort', resolve, { once: true }));
  request.destroy();
  await Promise.race([cancelled, new Promise((_, reject) => setTimeout(() => reject(new Error('Upstream was not cancelled.')), 500))]);
  assert.equal(signal.aborted, true); release();
});

test('capacity rejects another HTTP request while the first is active', async t => {
  const f = await gatewayFixture({ maxConcurrentRequests: 1 }); t.after(() => f.close());
  const client = await f.client('alice');
  let reached, release;
  const arrived = new Promise(resolve => { reached = resolve; });
  const wait = new Promise(resolve => { release = resolve; });
  f.state.grantsHook = async () => { reached(); await wait; };
  const active = call(client, 'tether_list_services'); await arrived;
  const response = await fetch(f.resource, { method: 'POST', headers: { Authorization: `Bearer ${await f.token('bob')}`, 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(response.status, 429); release();
  assert.equal(data(await active).services[0].id, 'pageindex');
});


test('generic adapters cannot silently skip excess rows or audit revoked reads as allowed', async () => {
  const principal = { issuer: ISSUER, subject: 'alice', clientId: 'test', audience: 'test', scopes: ['tether:read'], expiresAt: Date.now()/1000+60 };
  let grant = { revision: 'one', datasets: [{serviceId:'generic',datasetId:'records'}] };
  const events = [];
  const records = [A,B].map(id=>({id,datasetId:'records',data:{text:'allowed'}}));
  const source = { id:'generic',title:'Generic',datasets:[{id:'records',title:'Records'}],
    list: async()=>({records,next:'next-page'}), search:async()=>({records,partial:true}),
    read:async()=>{grant=null;return records[0];} };
  const access = new DataAccess({sources:[source],grants:async()=>grant,audit:event=>events.push(event)});
  for (const operation of ['list','search']) await assert.rejects(access.execute(principal,new AbortController().signal,operation,{serviceId:'generic',datasetId:'records',limit:1,query:'q'}));
  await assert.rejects(access.execute(principal,new AbortController().signal,'read',{serviceId:'generic',datasetId:'records',recordId:A}));
  assert.deepEqual(events.map(event=>event.outcome),['refused','refused','refused']);
});
