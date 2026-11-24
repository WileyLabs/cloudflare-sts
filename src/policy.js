// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import { buildIssuerMap, identityClaimName, validateIssuerRule } from './issuers/index.js';

export const MIN_TTL = 60;
export const MAX_TTL = 86400;
export const DEFAULT_TTL = 900;

// '*' = any run of characters; anchored, case-sensitive; everything else literal.
export const glob = (pattern, v) => {
  if (typeof pattern !== 'string' || typeof v !== 'string') return false;
  return new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$').test(v);
};

function optionalClaimsMatch(ruleClaims, jwtClaims) {
  if (!ruleClaims || !Object.keys(ruleClaims).length) return true;
  return Object.entries(ruleClaims).every(
    ([k, p]) => typeof jwtClaims[k] === 'string' && [].concat(p).some((x) => glob(x, jwtClaims[k]))
  );
}

/**
 * Match by principal (identity claim for the issuer type), then optional extra claims.
 * @param {string} type issuer type (github|gcp|spiffe|aws|oidc)
 */
export function findRule(rules, iss, claims, type) {
  const claimName = identityClaimName(type);
  const identity = claims[claimName];
  if (typeof identity !== 'string' || !identity) return undefined;
  return rules.find(
    (r) =>
      r.issuer === iss &&
      [].concat(r.principal).some((p) => glob(p, identity)) &&
      optionalClaimsMatch(r.claims, claims)
  );
}

const isInt = (n) => Number.isInteger(n);

export function ttlFor(rule, requested) {
  if (!validTtl(rule.max_ttl_seconds)) throw new Error('invalid max_ttl_seconds');
  if (requested !== undefined && !validTtl(requested)) throw new Error('invalid ttl');
  return Math.min(requested ?? DEFAULT_TTL, rule.max_ttl_seconds);
}

const ipv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split('.').every((o) => +o <= 255);
const ipv6 = (s) => s.includes(':') && /^[0-9a-f:.]+$/i.test(s) && !/:::/.test(s) && (s.match(/::/g) ?? []).length <= 1;
export function validIpOrCidr(v) {
  if (typeof v !== 'string') return false;
  const [ip, bits, extra] = v.split('/');
  if (extra !== undefined) return false;
  const v4 = ipv4(ip);
  if (!v4 && !ipv6(ip)) return false;
  return bits === undefined || (/^\d{1,3}$/.test(bits) && +bits <= (v4 ? 32 : 128));
}

const isObj = (o) => o && typeof o === 'object' && !Array.isArray(o);
const isStr = (s, max = 256) => typeof s === 'string' && s.length > 0 && s.length <= max;
const nonEmpty = (o) => isObj(o) && Object.keys(o).length > 0;
const nonEmptyArray = (a) => Array.isArray(a) && a.length > 0;
const validTtl = (n) => isInt(n) && n >= MIN_TTL && n <= MAX_TTL;

function ensure(cond, msg) {
  if (!cond) throw new Error(`policy: ${msg}`);
}

function validateIssuers(issuers) {
  ensure(nonEmpty(issuers), 'issuers required');
  const map = buildIssuerMap(issuers);
  for (const [iss, entry] of map) {
    const url = URL.canParse(entry.jwks) ? new URL(entry.jwks) : null;
    ensure(url, `bad JWKS url for ${iss}`);
    ensure(url.protocol === 'https:', `JWKS url must be https for ${iss}`);
  }
  return map;
}

function validateOptionalClaims(claims, at) {
  if (claims === undefined) return;
  ensure(isObj(claims), `${at}: claims must be an object`);
  for (const [name, value] of Object.entries(claims)) {
    const patterns = [].concat(value);
    ensure(isStr(name, 64) && patterns.every((x) => isStr(x)), `${at}: bad claim ${name}`);
  }
}

function validateCfPolicy(x, at) {
  ensure(['allow', 'deny'].includes(x.effect ?? 'allow'), `${at}: effect must be allow|deny`);
  ensure(nonEmptyArray(x.permission_groups) && x.permission_groups.every((g) => isStr(g, 128)), `${at}: permission_groups invalid`);
  ensure(nonEmpty(x.resources) && Object.values(x.resources).every((v) => isStr(v) || isObj(v)), `${at}: resources invalid`);
}

const ZONE_NAME = /^(\*|[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?)$/i;
const PROFILE_NAME = /^[A-Za-z0-9._-]{1,64}$/;

function validateProfiles(profiles) {
  if (profiles === undefined) return;
  ensure(isObj(profiles), 'profiles must be an object');
  for (const [name, p] of Object.entries(profiles)) {
    ensure(PROFILE_NAME.test(name), `bad profile name ${name}`);
    ensure(isObj(p) && nonEmptyArray(p.permissions) && p.permissions.every((x) => isStr(x, 128)), `profile ${name}: permissions invalid`);
  }
}

function validateGrants(grants, profiles, at) {
  ensure(nonEmptyArray(grants), `${at}: grants must be a non-empty array`);
  for (const g of grants) {
    ensure(isObj(g), `${at}: grant must be an object`);
    ensure(Object.keys(g).every((k) => ['permissions', 'profile', 'zones'].includes(k)), `${at}: unknown grant key`);
    ensure((g.permissions === undefined) !== (g.profile === undefined), `${at}: grant needs exactly one of permissions or profile`);
    if (g.profile !== undefined) ensure(typeof g.profile === 'string' && Object.hasOwn(profiles ?? {}, g.profile), `${at}: unknown profile ${g.profile}`);
    else ensure(nonEmptyArray(g.permissions) && g.permissions.every((x) => isStr(x, 128)), `${at}: grant permissions invalid`);
    if (g.zones !== undefined) {
      ensure(nonEmptyArray(g.zones) && g.zones.every((z) => typeof z === 'string' && ZONE_NAME.test(z)), `${at}: grant zones invalid`);
      ensure(!g.zones.includes('*') || g.zones.length === 1, `${at}: "*" cannot be combined with zone names`);
    }
  }
}

export function expandGrants(rule, profiles = {}) {
  return (rule.grants ?? []).map((g) => ({
    permissions: [...new Set(g.permissions ?? profiles[g.profile].permissions)],
    ...(g.zones && { zones: g.zones })
  }));
}

function validateRule(r, issuerMap, profiles, seenIds) {
  ensure(isObj(r), 'rule must be an object');
  ensure(/^[A-Za-z0-9._-]{1,64}$/.test(r.id ?? ''), 'rule id invalid');
  ensure(!seenIds.has(r.id), `duplicate rule id ${r.id}`);
  seenIds.add(r.id);

  const at = `rule ${r.id}`;
  ensure(issuerMap.has(r.issuer), `${at}: unknown issuer`);
  ensure(r.description === undefined || isStr(r.description, 200), `${at}: description invalid`);
  ensure(r.principal !== undefined, `${at}: principal required`);
  const principals = [].concat(r.principal);
  ensure(principals.length > 0 && principals.every((p) => isStr(p, 512)), `${at}: principal invalid`);
  validateOptionalClaims(r.claims, at);
  validateIssuerRule(issuerMap.get(r.issuer).type, r, at, ensure);
  ensure(validTtl(r.max_ttl_seconds), `${at}: max_ttl_seconds must be ${MIN_TTL}-${MAX_TTL}`);
  ensure(r.policies !== undefined || r.grants !== undefined, `${at}: grants or policies required`);
  if (r.grants !== undefined) validateGrants(r.grants, profiles, at);
  if (r.policies !== undefined) {
    ensure(nonEmptyArray(r.policies), `${at}: policies required`);
    ensure(r.grants !== undefined || r.policies.some((x) => (x.effect ?? 'allow') === 'allow'), `${at}: needs an allow policy`);
    r.policies.forEach((x) => validateCfPolicy(x, at));
  }
  if (r.client_ips !== undefined) ensure(nonEmptyArray(r.client_ips) && r.client_ips.every(validIpOrCidr), `${at}: client_ips invalid`);
}

export function validatePolicy(p) {
  ensure(isObj(p), 'must be an object');
  ensure(isStr(p.audience), 'audience required');
  const issuerMap = validateIssuers(p.issuers);
  validateProfiles(p.profiles);
  ensure(nonEmptyArray(p.rules), 'rules required');
  const seenIds = new Set();
  p.rules.forEach((r) => validateRule(r, issuerMap, p.profiles, seenIds));
  return p;
}
