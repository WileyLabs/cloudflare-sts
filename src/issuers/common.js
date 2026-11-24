// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';
import { HttpError, ensure } from '../http.js';

export const DEFAULT_ALGS = ['RS256', 'ES256'];

const isStr = (s, max = 256) => typeof s === 'string' && s.length > 0 && s.length <= max;

/** Infer issuer type from the iss string when policy only pins a JWKS URL. */
export function inferType(iss) {
  if (iss === 'https://token.actions.githubusercontent.com') return 'github';
  if (iss === 'https://accounts.google.com' || iss === 'accounts.google.com') return 'gcp';
  if (/oidc-discovery|spiffe|spire/i.test(iss)) return 'spiffe';
  if (/oidc\.eks\.|cognito-idp\.|\.amazonaws\.com/i.test(iss)) return 'aws';
  return 'oidc';
}

/**
 * Policy `issuers` entry: either a JWKS URL string (legacy) or
 * `{ jwks, type?, algorithms? }`.
 */
export function normalizeIssuerEntry(iss, value) {
  if (typeof value === 'string') {
    return { iss, jwks: value, type: inferType(iss), algorithms: DEFAULT_ALGS };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`policy: bad issuer entry for ${iss}`);
  }
  const jwks = value.jwks;
  const type = value.type ?? inferType(iss);
  const algorithms = value.algorithms ?? DEFAULT_ALGS;
  if (typeof jwks !== 'string' || !jwks) throw new Error(`policy: bad JWKS for ${iss}`);
  if (typeof type !== 'string' || !type) throw new Error(`policy: bad type for ${iss}`);
  if (!Array.isArray(algorithms) || !algorithms.length || !algorithms.every((a) => isStr(a, 16))) {
    throw new Error(`policy: bad algorithms for ${iss}`);
  }
  return { iss, jwks, type, algorithms };
}

export function jwksUrl(entry) {
  return entry.jwks;
}

/**
 * Verify signature / aud / exp; `requiredClaims` always includes `sub`.
 * `requireIss: false` skips JWT `iss` (SPIFFE JWT-SVIDs may omit it).
 */
export async function verifyOidcJwt(
  token,
  entry,
  audience,
  jwksCache,
  { requiredClaims = ['sub', 'exp'], requireIss = true } = {}
) {
  ensure(token.length > 0 && token.length <= 8192, 401, 'token_invalid');
  let decoded;
  try {
    decoded = decodeJwt(token);
  } catch {
    throw new HttpError(401, 'token_invalid');
  }
  if (requireIss) {
    ensure(typeof decoded.iss === 'string' && decoded.iss === entry.iss, 401, 'token_invalid');
  }

  if (!jwksCache.has(entry.iss)) jwksCache.set(entry.iss, createRemoteJWKSet(new URL(entry.jwks)));
  try {
    const opts = {
      audience,
      algorithms: entry.algorithms,
      requiredClaims
    };
    if (requireIss) opts.issuer = entry.iss;
    const { payload } = await jwtVerify(token, jwksCache.get(entry.iss), opts);
    if (typeof payload.sub !== 'string' || !payload.sub) throw new Error('sub');
    return payload;
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(401, 'token_invalid');
  }
}

/**
 * Replay key: prefer jti; else sha256(header.payload) — not the signature.
 * ES256 (r,s) and (r,n−s) verify the same content; hashing the full JWT would
 * let a signature variant bypass replay protection.
 */
export async function replayKey(iss, claims, token) {
  if (typeof claims.jti === 'string' && claims.jti) return `${iss}:${claims.jti}`;
  const parts = String(token).split('.');
  const signingInput = parts.length >= 2 ? `${parts[0]}.${parts[1]}` : String(token);
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(signingInput));
  const hex = [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${iss}:sha256:${hex}`;
}

export function claimExpiry(claims) {
  ensure(typeof claims.exp === 'number' && Number.isFinite(claims.exp), 401, 'token_invalid');
  return claims.exp;
}
