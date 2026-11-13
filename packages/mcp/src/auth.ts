import { jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { Principal, TokenVerifier } from './types.js';
import { AccessError } from './policy.js';

export interface JwtVerifierOptions {
  issuer: string;
  resource: string;
  key: CryptoKey | Uint8Array | JWTVerifyGetKey;
  algorithms?: string[];
}
export function createJwtVerifier(options: JwtVerifierOptions): TokenVerifier {
  const algorithms = options.algorithms ?? ['RS256'];
  if (!algorithms.length || algorithms.some(a => !['RS256', 'PS256', 'ES256', 'EdDSA'].includes(a))) throw new Error('Use a supported asymmetric JWT algorithm.');
  return async (token, signal) => {
    if (signal.aborted) throw new AccessError();
    const { payload, protectedHeader } = await jwtVerify(token, options.key as JWTVerifyGetKey, {
      issuer: options.issuer, audience: options.resource, algorithms,
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'client_id'],
      clockTolerance: 0,
    });
    if (!['at+jwt', 'application/at+jwt'].includes(protectedHeader.typ ?? '')) throw new AccessError();
    const scopes = typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : [];
    return validatePrincipal({ issuer: payload.iss, subject: payload.sub, clientId: payload.client_id,
      audience: options.resource, scopes, expiresAt: payload.exp }, options.resource);
  };
}
export function validatePrincipal(value: unknown, resource: string): Principal {
  const p = value as Partial<Principal> | undefined;
  if (!p || ![p.issuer, p.subject, p.clientId].every(x => typeof x === 'string' && x.length > 0 && x.length <= 2048)
    || p.audience !== resource || !Number.isFinite(p.expiresAt) || p.expiresAt! <= Date.now() / 1000
    || !Array.isArray(p.scopes) || p.scopes.length > 64 || !p.scopes.every(x => typeof x === 'string' && x.length < 128)
    || !p.scopes.includes('tether:read')) throw new AccessError();
  return Object.freeze({ issuer: p.issuer!, subject: p.subject!, clientId: p.clientId!, audience: resource,
    scopes: Object.freeze([...p.scopes]), expiresAt: p.expiresAt! });
}
