import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, connect } from 'node:net';
import { once } from 'node:events';
import { originFixture, gatewayFixture, A, C, call, data } from './fixture.mjs';

async function freePort() {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
async function ready(port) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await new Promise(resolve => { const socket = connect(port, '127.0.0.1'); socket.once('connect', () => { socket.destroy(); resolve(true); }); socket.once('error', () => resolve(false)); })) return;
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  throw new Error('Fixture listener did not become ready.');
}
test('official MCP client -> user policy -> real paired Tether -> private service', { timeout: 30000 }, async t => {
  const binary = process.env.TETHER_TEST_BINARY;
  assert.ok(binary, 'Set TETHER_TEST_BINARY to a real built Tether runtime; this integration never silently skips.');
  await stat(binary);
  const directory = await mkdtemp(join(tmpdir(), 'tether-mcp-'));
  const children = [];
  t.after(async () => {
    for (const child of children.reverse()) {
      if (child.exitCode === null) { child.kill('SIGINT'); await Promise.race([once(child, 'exit'), new Promise(r => setTimeout(r, 1500))]); if (child.exitCode === null) child.kill('SIGKILL'); }
    }
    await rm(directory, { recursive: true, force: true });
  });
  const origin = await originFixture(); t.after(() => origin.close());
  const hostConfig = join(directory, 'host.json'); const clientConfig = join(directory, 'client.json');
  const originPort = new URL(origin.origin).port;
  const init = spawnSync(binary, ['host', 'init', '--config', hostConfig, '--app', 'app.fledgeling.mcp-fixture', '--service', `pageindex=tcp://127.0.0.1:${originPort}`], { encoding: 'utf8', timeout: 10000 });
  assert.equal(init.status, 0, 'Tether host fixture initialization must succeed.');
  const hostPort = await freePort();
  const host = spawn(binary, ['host', 'run', '--config', hostConfig, '--direct', `127.0.0.1:${hostPort}`, '--pair'], { stdio: ['ignore', 'pipe', 'pipe'] }); children.push(host);
  const code = await Promise.race([once(host.stdout, 'data').then(([bytes]) => bytes.toString().trim()), new Promise((_, reject) => setTimeout(() => reject(new Error('No fixture pairing window.')), 4000))]);
  await ready(hostPort);
  const pair = spawnSync(binary, ['client', 'pair', '--config', clientConfig, '--app', 'app.fledgeling.mcp-fixture', '--direct', `127.0.0.1:${hostPort}`, '--code-stdin'], { input: `${code}\n`, encoding: 'utf8', timeout: 10000 });
  assert.equal(pair.status, 0, 'The synthetic device must complete real encrypted pairing.');
  const forwardPort = await freePort();
  const forward = spawn(binary, ['client', 'forward', '--config', clientConfig, '--service', 'pageindex', '--listen', `127.0.0.1:${forwardPort}`], { stdio: 'ignore' }); children.push(forward);
  await ready(forwardPort);
  const gateway = await gatewayFixture({ sourceOrigin: `http://127.0.0.1:${forwardPort}` }); t.after(() => gateway.close());
  const alice = await gateway.client('alice'); const bob = await gateway.client('bob');
  const scope = { serviceId: 'pageindex', datasetId: 'alpha' };
  const page = data(await call(alice, 'tether_list_records', scope));
  const record = page.records.find(d => d.id === A); assert.ok(record);
  const read = data(await call(alice, 'tether_read_record', { ...scope, recordId: A, recordRef: record.recordRef }));
  assert.match(JSON.stringify(read), /ALICE-CONTENT/);
  const before = origin.state.calls.length;
  assert.equal((await call(alice, 'tether_read_record', { ...scope, recordId: C })).isError, true);
  assert.equal((await call(bob, 'tether_read_record', { ...scope, recordId: A, recordRef: record.recordRef })).isError, true);
  assert.equal(origin.state.calls.length, before, 'Denied identities/records must not reach the paired service.');
  origin.state.calls.length = 0;
  const search = data(await call(alice, 'tether_search_records', { ...scope, query: 'report' })); assert.ok(search.records.length > 0);
  const rankerCalls = origin.state.calls.filter(c => c.path === '/v4/documents/search');
  assert.ok(rankerCalls.length > 0); assert.ok(rankerCalls.every(c => c.body.documentId && c.body.documentId !== C && c.body.containerTag === 'alpha'));
});
