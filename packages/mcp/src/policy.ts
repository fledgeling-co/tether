import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { z } from 'zod/v4';
import type { AccountGrant, DatasetGrant, Principal } from './types.js';

export const idSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
const datasetSchema = z.object({
  serviceId: idSchema, datasetId: idSchema,
  includeRecordIds: z.array(idSchema).max(10000).optional(),
  excludeRecordIds: z.array(idSchema).max(10000).optional(),
}).strict();
const grantSchema = z.object({ revision: idSchema, datasets: z.array(datasetSchema).max(256) }).strict();
export class AccessError extends Error { constructor() { super('Access unavailable.'); } }
export function principalKey(p: Principal): string {
  return createHash('sha256').update(JSON.stringify([p.issuer, p.subject, p.clientId])).digest('hex');
}
export function snapshotGrant(value: AccountGrant | null): AccountGrant {
  if (value === null) throw new AccessError();
  const result = grantSchema.parse(value);
  const seen = new Set<string>();
  for (const d of result.datasets) {
    const key = JSON.stringify([d.serviceId, d.datasetId]);
    if (seen.has(key)) throw new AccessError();
    seen.add(key);
    if (d.includeRecordIds) d.includeRecordIds = [...new Set(d.includeRecordIds)].sort();
    if (d.excludeRecordIds) d.excludeRecordIds = [...new Set(d.excludeRecordIds)].sort();
    if (d.includeRecordIds) Object.freeze(d.includeRecordIds);
    if (d.excludeRecordIds) Object.freeze(d.excludeRecordIds);
    Object.freeze(d);
  }
  result.datasets.sort((a, b) => JSON.stringify([a.serviceId, a.datasetId]).localeCompare(JSON.stringify([b.serviceId, b.datasetId])));
  Object.freeze(result.datasets);
  Object.freeze(result);
  return result;
}
export function fingerprint(grant: AccountGrant): string {
  return createHash('sha256').update(JSON.stringify(grant)).digest('hex');
}
export function recordAllowed(grant: DatasetGrant, id: string): boolean {
  return idSchema.safeParse(id).success && !grant.excludeRecordIds?.includes(id)
    && (grant.includeRecordIds === undefined || grant.includeRecordIds.includes(id));
}
export function emptyGrant(grant: DatasetGrant): boolean { return grant.includeRecordIds?.length === 0; }
const cursorSchema = z.object({
  v: z.literal(1), principal: z.string().length(64), policy: z.string().length(64),
  service: idSchema, dataset: idSchema, operation: z.enum(['list', 'search', 'read']),
  query: z.string().length(64), position: z.string().max(4096), expires: z.number().int(),
}).strict();
export class Cursors {
  private readonly key: Buffer;
  constructor(key: Uint8Array = randomBytes(32)) {
    if (key.byteLength < 32) throw new Error('Cursor key must contain at least 32 bytes.');
    this.key = createHash('sha256').update(key).digest();
  }
  issue(binding: Omit<z.infer<typeof cursorSchema>, 'v' | 'expires' | 'position'>, position: string): string {
    const body = Buffer.from(JSON.stringify(cursorSchema.parse({ ...binding, v: 1, position, expires: Date.now() + 300000 })));
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce);
    cipher.setAAD(Buffer.from('tether-mcp-cursor-v1'));
    const encrypted = Buffer.concat([cipher.update(body), cipher.final()]);
    return `v1.${nonce.toString('base64url')}.${encrypted.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}`;
  }
  read(value: string, binding: Omit<z.infer<typeof cursorSchema>, 'v' | 'expires' | 'position'>): string {
    if (value.length > 8192) throw new AccessError();
    const parts = value.split('.');
    if (parts.length !== 4 || parts[0] !== 'v1') throw new AccessError();
    const nonce = Buffer.from(parts[1]!, 'base64url'), ciphertext = Buffer.from(parts[2]!, 'base64url'), tag = Buffer.from(parts[3]!, 'base64url');
    if (nonce.length !== 12 || tag.length !== 16) throw new AccessError();
    const decipher = createDecipheriv('aes-256-gcm', this.key, nonce);
    decipher.setAAD(Buffer.from('tether-mcp-cursor-v1')); decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const parsed = cursorSchema.parse(JSON.parse(plaintext.toString('utf8')));
    if (parsed.expires < Date.now() || Object.entries(binding).some(([key, value]) => parsed[key as keyof typeof parsed] !== value)) throw new AccessError();
    return parsed.position;
  }
}
export function queryKey(value = ''): string { return createHash('sha256').update(value).digest('hex'); }
export function bounded<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new AccessError());
  return new Promise((resolve, reject) => {
    const stop = () => reject(new AccessError());
    signal.addEventListener('abort', stop, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', stop));
  });
}
export function boundedJSON(value: unknown, max = 262144): string {
  const text = JSON.stringify(value);
  if (text === undefined || Buffer.byteLength(text) > max) throw new AccessError();
  return text;
}
