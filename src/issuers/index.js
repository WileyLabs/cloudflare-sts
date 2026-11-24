// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import { decodeJwt } from 'jose';
import { HttpError, ensure as ensureHttp } from '../http.js';
import { normalizeIssuerEntry, verifyOidcJwt, replayKey, claimExpiry } from './common.js';
import { github } from './github.js';
import { gcp } from './gcp.js';
import { spiffe } from './spiffe.js';
import { aws } from './aws.js';
import { oidc } from './oidc.js';

const HANDLERS = Object.fromEntries([github, gcp, spiffe, aws, oidc].map((h) => [h.type, h]));

export function handlerFor(type) {
  return HANDLERS[type] ?? oidc;
}

/** Build iss -> normalized entry map from policy.issuers. */
export function buildIssuerMap(issuers) {
  const map = new Map();
  for (const [iss, value] of Object.entries(issuers)) {
    const entry = normalizeIssuerEntry(iss, value);
    if (!HANDLERS[entry.type] && entry.type !== 'oidc') {
      throw new Error(`policy: unknown issuer type ${entry.type} for ${iss}`);
    }
    map.set(iss, entry);
  }
  return map;
}

export function validateIssuerRule(type, rule, at, ensure) {
  handlerFor(type).validateRule(rule, at, ensure);
}

/** JWT claim that carries the caller identity for this issuer type. */
export function identityClaimName(type) {
  return handlerFor(type).identityClaim ?? 'sub';
}

/** Pick SPIFFE issuer entry from JWT `sub` trust domain when `iss` is absent. */
function resolveSpiffeEntry(issuerMap, sub) {
  ensureHttp(typeof sub === 'string' && sub.startsWith('spiffe://'), 401, 'token_invalid');
  const td = sub.slice('spiffe://'.length).split('/')[0];
  ensureHttp(td, 401, 'token_invalid');
  const candidates = [...issuerMap.entries()].filter(([, e]) => e.type === 'spiffe');
  ensureHttp(candidates.length > 0, 401, 'unknown_issuer');
  const prefer = candidates.find(([iss, e]) => iss.includes(td) || e.jwks.includes(td));
  return prefer ?? candidates[0];
}

/**
 * Verify Bearer JWT against the pinned issuer map.
 * Returns { iss, claims, entry, token, replay, exp }.
 * SPIFFE JWT-SVIDs may omit `iss`; other types require it.
 */
export async function verifyCaller(token, issuerMap, audience, jwksCache) {
  ensureHttp(token.length > 0 && token.length <= 8192, 401, 'token_invalid');
  let decoded;
  try {
    decoded = decodeJwt(token);
  } catch {
    throw new HttpError(401, 'token_invalid');
  }

  let iss = decoded.iss;
  let entry;
  let requireIss = true;

  if (typeof iss === 'string' && iss) {
    entry = issuerMap.get(iss);
    ensureHttp(entry, 401, 'unknown_issuer');
  } else {
    // Issuerless token: only SPIFFE — bind via trust domain in sub.
    const resolved = resolveSpiffeEntry(issuerMap, decoded.sub);
    iss = resolved[0];
    entry = resolved[1];
    requireIss = false;
  }

  const handler = handlerFor(entry.type);
  if (!requireIss) ensureHttp(handler.type === 'spiffe', 401, 'token_invalid');
  const requiredClaims = handler.requireJti ? ['sub', 'exp', 'jti'] : ['sub', 'exp'];
  let claims = await verifyOidcJwt(token, entry, audience, jwksCache, { requiredClaims, requireIss });
  claims = await handler.afterVerify(claims, ensureHttp);
  const exp = claimExpiry(claims);
  const replay = await replayKey(iss, claims, token);
  return { iss, claims, entry, token, replay, exp };
}

export { HANDLERS, replayKey };
