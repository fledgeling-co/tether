import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

// Configure public routing metadata only. Selecting Internet in the Mac app starts the tunnel later.
const [relayURL, domainSuffix, ...extra] = process.argv.slice(2);
if (!relayURL || !domainSuffix || extra.length) {
  console.error('Usage: node examples/mcp-router/configure.mjs wss://relay.example.com/v1/relay tunnel.example.com');
  process.exit(2);
}
try {
  const relay = new URL(relayURL);
  if (relay.protocol !== 'wss:' || relay.username || relay.password || relay.search || relay.hash || relay.pathname !== '/v1/relay') throw new Error();
  const token = (await readFile(join(homedir(), '.claude', 'mcp-router', 'control.token'), 'utf8')).trim();
  const response = await fetch('http://127.0.0.1:8879/pairing/access/tether', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-mcpr-token': token },
    body: JSON.stringify({ relayURL, domainSuffix }), signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error();
  const configured = await response.json();
  if (!configured.configured || !/^[a-z2-7]{52}$/.test(configured.hostID)) throw new Error();
  console.log(JSON.stringify({ configured: true, relayURL: configured.relayURL, domainSuffix: configured.domainSuffix, hostID: configured.hostID }));
  console.log('Allow this public host ID on the relay, then select Internet in the MCP Router Mac app.');
} catch {
  console.error('Tether configuration failed. Check the running MCP Router, private control token and installed Tether helper.');
  process.exitCode = 1;
}
