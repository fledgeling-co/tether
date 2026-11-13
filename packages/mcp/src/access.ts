import { z } from 'zod/v4';
import { AccessError, bounded, boundedJSON, Cursors, emptyGrant, fingerprint, idSchema, principalKey, queryKey, recordAllowed, snapshotGrant } from './policy.js';
import type { AccountGrant, DataRecord, DataSource, DatasetGrant, GatewayOptions, Principal, RecordSummary, SourceContext } from './types.js';

const summarySchema = z.object({ id: idSchema, datasetId: idSchema, title: z.string().max(2000).optional() });
const recordSchema = summarySchema.extend({ data: z.unknown() });
const pageSchema = z.object({ records: z.array(summarySchema).max(100), next: z.string().max(4096).optional(), partial: z.boolean().optional() });
const searchSchema = z.object({ records: z.array(recordSchema).max(100), next: z.string().max(4096).optional(), partial: z.boolean() });

export class DataAccess {
  readonly sources = new Map<string, DataSource>();
  private readonly cursors: Cursors;
  constructor(private readonly options: GatewayOptions) {
    this.cursors = new Cursors(options.cursorKey);
    for (const source of options.sources) {
      idSchema.parse(source.id);
      if (this.sources.has(source.id) || !source.title || source.title.length > 200) throw new Error('Invalid source registration.');
      const seen = new Set<string>();
      for (const dataset of source.datasets) {
        idSchema.parse(dataset.id);
        if (seen.has(dataset.id) || !dataset.title || dataset.title.length > 200) throw new Error('Invalid dataset registration.');
        seen.add(dataset.id);
      }
      this.sources.set(source.id, { ...source, datasets: source.datasets.map(d => Object.freeze({ ...d })) });
    }
  }
  private async current(principal: Principal, signal: AbortSignal): Promise<AccountGrant> {
    if (principal.expiresAt <= Date.now() / 1000 || signal.aborted) throw new AccessError();
    return snapshotGrant(await bounded(this.options.grants(principal, signal), signal));
  }
  async execute(principal: Principal, signal: AbortSignal, operation: string, args: { serviceId?: string; datasetId?: string; recordId?: string; recordRef?: string; limit?: number; cursor?: string; query?: string } = {}): Promise<unknown> {
    const key = principalKey(principal);
    const audit = async (outcome: 'allowed' | 'refused') => {
      if (this.options.audit) await bounded(Promise.resolve(this.options.audit({ principalKey: key, operation, serviceId: args.serviceId, datasetId: args.datasetId, outcome })), signal);
    };
    try {
      const account = await this.current(principal, signal);
      const version = fingerprint(account);
      let result: unknown;
      if (operation === 'catalog') {
        result = { services: [...this.sources.values()].flatMap(source => {
          const datasets = source.datasets.filter(d => account.datasets.some(g => g.serviceId === source.id && g.datasetId === d.id && !emptyGrant(g)));
          return datasets.length ? [{ id: source.id, title: source.title, datasets }] : [];
        }) };
      } else {
        const source = this.sources.get(args.serviceId ?? '');
        const grant = account.datasets.find(g => g.serviceId === args.serviceId && g.datasetId === args.datasetId);
        if (!source || !grant || !source.datasets.some(d => d.id === grant.datasetId)) throw new AccessError();
        if (emptyGrant(grant)) {
          if (operation === 'read') throw new AccessError();
          result = { records: [], partial: false };
        } else {
          const context: SourceContext = { principal, grant, signal };
          const decorate = (record: RecordSummary | DataRecord) => {
            const ref = this.cursors.issue({ principal: key, policy: version, service: source.id, dataset: grant.datasetId, operation: 'read', query: queryKey(record.id) }, record.id);
            return { ...record, recordRef: ref, uri: `tether://records/${source.id}/${grant.datasetId}/${record.id}?ref=${encodeURIComponent(ref)}` };
          };
          if (operation === 'read') {
            if (!args.recordId || !recordAllowed(grant, args.recordId)) throw new AccessError();
            if (args.recordRef) {
              const id = this.cursors.read(args.recordRef, { principal: key, policy: version, service: source.id, dataset: grant.datasetId, operation: 'read', query: queryKey(args.recordId) });
              if (id !== args.recordId) throw new AccessError();
              context.verifiedRecordId = id;
            }
            const record = recordSchema.parse(await bounded(source.read(context, args.recordId), signal));
            this.checkRecord(record, grant);
            if (record.id !== args.recordId) throw new AccessError();
            result = decorate(record);
          } else {
            const binding = { principal: key, policy: version, service: source.id, dataset: grant.datasetId,
              operation: operation as 'list' | 'search', query: queryKey(args.query) };
            const cursor = args.cursor ? this.cursors.read(args.cursor, binding) : undefined;
            const limit = Math.max(1, Math.min(50, args.limit ?? 20));
            if (operation === 'list') {
              const page = pageSchema.parse(await bounded(source.list(context, { limit, cursor }), signal));
              if (page.records.length > limit) throw new AccessError();
              // A source may return an unfiltered metadata page. Forbidden metadata never leaves this process.
              for (const record of page.records) if (record.datasetId !== grant.datasetId) throw new AccessError();
              result = { records: page.records.filter(r => recordAllowed(grant, r.id)).slice(0, limit).map(decorate),
                ...(page.next ? { nextCursor: this.cursors.issue(binding, page.next) } : {}), partial: page.partial ?? Boolean(page.next) };
            } else if (operation === 'search') {
              const page = searchSchema.parse(await bounded(source.search(context, { query: args.query ?? '', limit, cursor }), signal));
              if (page.records.length > limit) throw new AccessError();
              // Search sources must enforce the policy before retrieval/AI, not merely filter output.
              for (const record of page.records) this.checkRecord(record, grant);
              result = { records: page.records.slice(0, limit).map(decorate),
                ...(page.next ? { nextCursor: this.cursors.issue(binding, page.next) } : {}), partial: page.partial };
            } else throw new AccessError();
          }
        }
      }
      boundedJSON(result);
      const beforeAudit = await this.current(principal, signal);
      if (fingerprint(beforeAudit) !== version) throw new AccessError();
      await audit('allowed');
      const current = await this.current(principal, signal);
      if (fingerprint(current) !== version || signal.aborted) throw new AccessError();
      return result;
    } catch {
      try { await audit('refused'); } catch { /* Audit/timeout failures never release data. */ }
      throw new AccessError();
    }
  }
  private checkRecord(record: RecordSummary, grant: DatasetGrant): void {
    if (record.datasetId !== grant.datasetId || !recordAllowed(grant, record.id)) throw new AccessError();
  }
}
