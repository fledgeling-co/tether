#!/usr/bin/env node
import { createServer } from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createTetherMcpNodeHandler } from './node.js';
import type { GatewayOptions } from './types.js';

const modulePath = process.argv[2];
const port = Number(process.argv[3] ?? 7331);
if (!modulePath || !Number.isInteger(port) || port < 1 || port > 65535) {
  console.error('Usage: tether-mcp /absolute/path/to/host-adapter.mjs [port]');
  process.exitCode = 64;
} else {
  try {
    const options: GatewayOptions = (await import(pathToFileURL(resolve(modulePath)).href)).default;
    const gateway = createTetherMcpNodeHandler(options);
    const server = createServer({ requestTimeout: 30000, headersTimeout: 10000, maxHeaderSize: 16384 }, gateway.handler);
    server.maxHeadersCount = 64;
    let closing = false;
    const close = async () => {
      if (closing) return;
      closing = true;
      server.close();
      server.closeAllConnections();
      await gateway.close();
    };
    server.on('error', () => {
      console.error('Tether MCP could not start. Check the configured listener and host adapter.');
      process.exitCode = 1;
      void close();
    });
    process.once('SIGINT', () => { void close(); });
    process.once('SIGTERM', () => { void close(); });
    server.listen(port, '127.0.0.1', () => console.error(`Tether MCP listening on loopback port ${port}.`));
  } catch {
    console.error('Tether MCP could not start. Check the host adapter configuration.');
    process.exitCode = 1;
  }
}
