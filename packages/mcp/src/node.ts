import { toNodeHandler } from '@modelcontextprotocol/node';
import { createTetherMcpGateway } from './gateway.js';
import type { GatewayOptions } from './types.js';
import type { IncomingMessage, ServerResponse } from 'node:http';

export function createTetherMcpNodeHandler(options: GatewayOptions) {
  const gateway = createTetherMcpGateway(options);
  const resource = new URL(options.resource);
  const hosts = new Set([resource.host, ...(options.allowedHosts ?? [])]);
  const origins = new Set([resource.origin, ...(options.allowedOrigins ?? [])]);
  let active = 0;
  let closed = false;
  const controllers = new Set<AbortController>();
  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const refuse = (status: number) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end('{"error":"Request refused."}'); };
    if (closed) { refuse(503); return; }
    if (!req.headers.host || !hosts.has(req.headers.host) || (req.headers.origin !== undefined && !origins.has(req.headers.origin))) { refuse(403); return; }
    if (active >= (options.maxConcurrentRequests ?? 32)) { refuse(429); return; }
    active++;
    const controller = new AbortController(); controllers.add(controller);
    let finished = false;
    const timer = setTimeout(() => { controller.abort(); if (!res.headersSent) refuse(408); req.destroy(); }, options.timeoutMs ?? 30000);
    const done = () => { if (!finished) { finished = true; controller.abort(); controllers.delete(controller); clearTimeout(timer); active--; } };
    res.once('finish', done); res.once('close', done);
    const serve = toNodeHandler({ fetch: request => gateway.fetch(new Request(request, { signal: AbortSignal.any([request.signal, controller.signal]) })) }, { maxRequestBodySize: 65536 });
    try { await serve(req, res); }
    catch { if (!res.headersSent) refuse(400); else res.destroy(); }
  };
  return { handler, close: async () => { closed = true; for (const c of controllers) c.abort(); await gateway.close(); } };
}
