import { z } from 'zod/v4';
import { AccessError, bounded, emptyGrant, recordAllowed } from './policy.js';
import type { JsonRequester } from './forward.js';
import type { DataRecord, DataSource, Principal, SourceContext } from './types.js';

const documentId = z.string().regex(/^[a-f0-9]{24}$/i);
const metadata = z.object({ id: documentId, containerTag: z.string().max(100), title: z.string().max(2000).optional(), docName: z.string().max(2000).optional() });
const listing = z.object({ documents: z.array(metadata).max(100), nextCursor: z.string().max(4096).nullable().optional() });
const matchSchema = z.object({ documentId, nodeId: z.string().max(200), title: z.string().max(2000), text: z.string().max(100000).optional(), leafText: z.string().max(100000).optional(), score: z.number().finite() });
const matches = z.object({ matches: z.array(matchSchema).max(50) });
export interface PageIndexOptions {
  id: string;
  title?: string;
  datasets: readonly { id: string; title: string; containerTag: string }[];
  http: JsonRequester;
  /** Resolve a separately authorized PageIndex credential, never the MCP bearer token. */
  accessToken(principal: Principal, datasetId: string, signal: AbortSignal): Promise<string>;
}
export function createPageIndexSource(options: PageIndexOptions): DataSource {
  const datasets = new Map(options.datasets.map(d => [d.id, { ...d }]));
  if (datasets.size !== options.datasets.length || options.datasets.some(d => !/^[A-Za-z0-9._-]{1,100}$/.test(d.containerTag))) throw new Error('Invalid PageIndex datasets.');
  const connection = async (context: SourceContext) => {
    const dataset = datasets.get(context.grant.datasetId);
    if (!dataset || emptyGrant(context.grant)) throw new AccessError();
    const token = await bounded(options.accessToken(context.principal, dataset.id, context.signal), context.signal);
    return { dataset, call: (path: string, body?: unknown) => bounded(options.http.request(path, { token, signal: context.signal, body }), context.signal) };
  };
  const positionSchema = z.object({ upstream: z.string().max(4096).optional(), offset: z.number().int().min(0).max(100) }).strict();
  const decodePosition = (value?: string) => value ? positionSchema.parse(JSON.parse(value)) : { offset: 0, upstream: undefined };
  const summaries = async (context: SourceContext, cursor?: string) => {
    const { dataset, call } = await connection(context);
    const query = new URLSearchParams({ containerTag: dataset.containerTag, limit: '100', ...(cursor ? { cursor } : {}) });
    const page = listing.parse(await call(`/v3/documents?${query}`));
    if (page.documents.some(d => d.containerTag !== dataset.containerTag)) throw new AccessError();
    return { dataset, call, page };
  };
  const projectMatch = (context: SourceContext, match: z.infer<typeof matchSchema>): DataRecord => ({
    id: match.documentId, datasetId: context.grant.datasetId, title: match.title,
    data: { nodeId: match.nodeId, ...(match.text !== undefined ? { text: match.text } : {}), ...(match.leafText !== undefined ? { leafText: match.leafText } : {}), score: match.score },
  });
  return {
    id: options.id, title: options.title ?? 'PageIndex', datasets: options.datasets.map(d => ({ id: d.id, title: d.title })),
    async list(context, input) {
      const position = decodePosition(input.cursor);
      const { page } = await summaries(context, position.upstream);
      let offset = position.offset;
      if (offset > page.documents.length) throw new AccessError();
      const records = [];
      while (offset < page.documents.length && records.length < input.limit) {
        const doc = page.documents[offset++]!;
        if (recordAllowed(context.grant, doc.id)) records.push({ id: doc.id, datasetId: context.grant.datasetId, title: doc.title ?? doc.docName });
      }
      const next = offset < page.documents.length ? JSON.stringify({ upstream: position.upstream, offset })
        : page.nextCursor ? JSON.stringify({ upstream: page.nextCursor, offset: 0 }) : undefined;
      return { records, ...(next ? { next } : {}), partial: Boolean(next) };
    },
    async read(context, id) {
      documentId.parse(id);
      if (!recordAllowed(context.grant, id)) throw new AccessError();
      // GET /documents/:id is collection-blind, including its cache. Establish membership first.
      // A scoped documentId search would spend AI tokens; metadata scanning is bounded and read-only.
      let cursor: string | undefined; let permitted = context.verifiedRecordId === id;
      let selected: Awaited<ReturnType<typeof connection>> | undefined;
      const seen = new Set<string>();
      if (permitted) selected = await connection(context);
      for (let page = 0; !permitted && page < 10; page++) {
        const scoped = await summaries(context, cursor);
        if (scoped.page.documents.some(d => d.id === id)) { permitted = true; selected = scoped; break; }
        if (!scoped.page.nextCursor || seen.has(scoped.page.nextCursor)) break;
        cursor = scoped.page.nextCursor; seen.add(cursor);
      }
      if (!permitted || !selected) throw new AccessError();
      const raw = await selected.call(`/v3/documents/${encodeURIComponent(id)}`);
      const doc = metadata.extend({ structure: z.array(z.unknown()).max(10000), docDescription: z.string().max(100000).optional() }).parse(raw);
      if (doc.id !== id || doc.containerTag !== selected.dataset.containerTag) throw new AccessError();
      return { id, datasetId: context.grant.datasetId, title: doc.title ?? doc.docName,
        data: { description: doc.docDescription, structure: doc.structure } };
    },
    async search(context, input) {
      const position = decodePosition(input.cursor);
      const { dataset, call, page } = await summaries(context, position.upstream);
      if (position.offset > page.documents.length) throw new AccessError();
      // All searches use positive IDs with a collection scope before ranking, even for broad grants.
      const window = page.documents.slice(position.offset, position.offset + 10);
      const selected = window.filter(d => recordAllowed(context.grant, d.id));
      const offset = position.offset + window.length;
      const next = offset < page.documents.length ? JSON.stringify({ upstream: position.upstream, offset })
        : page.nextCursor ? JSON.stringify({ upstream: page.nextCursor, offset: 0 }) : undefined;
      const records: DataRecord[] = [];
      for (const doc of selected) {
        const result = matches.parse(await call('/v4/documents/search', { q: input.query, containerTag: dataset.containerTag,
          documentId: doc.id, topK: Math.min(5, input.limit), includeText: true }));
        if (result.matches.some(m => m.documentId !== doc.id || !recordAllowed(context.grant, m.documentId))) throw new AccessError();
        records.push(...result.matches.map(m => projectMatch(context, m)));
      }
      records.sort((a, b) => (b.data as { score: number }).score - (a.data as { score: number }).score);
      return { records: records.slice(0, input.limit), ...(next ? { next } : {}), partial: true };
    },
  };
}
