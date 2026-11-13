export interface Principal {
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly audience: string;
  readonly scopes: readonly string[];
  readonly expiresAt: number;
}
export type TokenVerifier = (token: string, signal: AbortSignal) => Promise<Principal>;
export interface DatasetGrant {
  serviceId: string;
  datasetId: string;
  /** Absent permits the dataset; [] permits no records. */
  includeRecordIds?: string[];
  excludeRecordIds?: string[];
}
export interface AccountGrant {
  revision: string;
  datasets: DatasetGrant[];
}
/** Return null for a disabled, unlinked or unknown account. Resolve afresh, including consent. */
export type GrantProvider = (principal: Principal, signal: AbortSignal) => Promise<AccountGrant | null>;
export interface SourceContext {
  principal: Principal;
  grant: Readonly<DatasetGrant>;
  signal: AbortSignal;
  /** A gateway-signed, user/policy-bound reference issued from authorized metadata. */
  verifiedRecordId?: string;
}
export interface RecordSummary { id: string; datasetId: string; title?: string }
export interface DataRecord extends RecordSummary { data: unknown }
export interface RecordPage { records: RecordSummary[]; next?: string; partial?: boolean }
export interface SearchPage { records: DataRecord[]; next?: string; partial: boolean }
export interface DataSource {
  id: string;
  title: string;
  datasets: readonly { id: string; title: string }[];
  /** Return at most limit records; next resumes after the last returned record. */
  list(context: SourceContext, input: { limit: number; cursor?: string }): Promise<RecordPage>;
  read(context: SourceContext, id: string): Promise<DataRecord>;
  /** Apply policy before retrieval/AI and return at most limit records. */
  search(context: SourceContext, input: { query: string; limit: number; cursor?: string }): Promise<SearchPage>;
}
export interface AuditEvent {
  principalKey: string;
  operation: string;
  serviceId?: string;
  datasetId?: string;
  /** Authorization observation, not a client-delivery receipt; a later refusal may follow. */
  outcome: 'allowed' | 'refused';
}
export interface GatewayOptions {
  resource: string;
  authorizationServers: readonly string[];
  verifyToken: TokenVerifier;
  grants: GrantProvider;
  sources: readonly DataSource[];
  allowedOrigins?: readonly string[];
  /** Optional extra Host values for an explicitly configured reverse proxy. */
  allowedHosts?: readonly string[];
  timeoutMs?: number;
  maxConcurrentRequests?: number;
  maxRequestsPerPrincipal?: number;
  /** Supply the same >=32-byte secret to replicas; default is process-local and ephemeral. */
  cursorKey?: Uint8Array;
  audit?: (event: AuditEvent) => void | Promise<void>;
}
