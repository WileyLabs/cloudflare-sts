// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import { createRemoteJWKSet, jwtVerify } from 'jose';
import policyBundle from '../policy.bundle.json' with { type: 'json' };

/** Worker runtime policy (hierarchy metadata kept on rules as `_source`). */
const policyJson = {
  audience: policyBundle.audience,
  issuers: policyBundle.issuers,
  profiles: policyBundle.profiles,
  rules: policyBundle.rules
};
import { PAGE } from './ui.js';
import { MAX_TTL, MIN_TTL, expandGrants, findRule, glob, ttlFor, validatePolicy } from './policy.js';
import { HttpError, ensure } from './http.js';
import { buildIssuerMap, verifyCaller } from './issuers/index.js';

export { glob, findRule, ttlFor, HttpError };

const API = 'https://api.cloudflare.com/client/v4';
const MAX_BODY = 1024;
const RETENTION_DAYS = 90;
const PAGE_SIZE = 200;
const DENIAL_PAGE_SIZE = 100;
const ACCOUNT_SCOPE = 'com.cloudflare.api.account';
const ZONE_SCOPE = 'com.cloudflare.api.account.zone';
const JTI_GRACE_SECONDS = 60;
const CLEANUP_PER_PAGE = 50;
const CLEANUP_MAX_PAGES = 20;
const CLEANUP_GRACE_SECONDS = 3600;
// Next run of the "17 * * * *" cron, as epoch ms.
const nextRunMs = (nowMs) => {
  const d = new Date(nowMs);
  d.setUTCMinutes(17, 0, 0);
  if (d.getTime() <= nowMs) d.setUTCHours(d.getUTCHours() + 1);
  return d.getTime();
};
const CLEANUP_CRON_LABEL = 'hourly at :17 UTC';
const STS_NAME = /^sts\/[^/]{1,80}\/[0-9a-f]{12}\/\d{10,16}$/;
const CLEANUP_MAX_DELETES = 200;
const HEX32 = /^[0-9a-f]{32}$/i;
const ACCESS_DOMAIN = /^[a-z0-9-]+\.cloudflareaccess\.com$/i;

const PAGE_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer'
};
const API_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

const log = (o) => console.log(JSON.stringify(o));

async function sha(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].slice(0, 6).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function createWorker(rawPolicy) {
  const policy = validatePolicy(rawPolicy);
  const issuerMap = buildIssuerMap(policy.issuers);
  const jwks = new Map();
  const accessJwks = new Map();
  const profiles = policy.profiles ?? {};
  const zones = new Map();
  let groups; // { any, account, zone }: permission group name -> id, per scope

  // `allow404`: a missing object resolves to null instead of a 502 (used by revoke).
  async function cf(env, path, init, { allow404 = false } = {}) {
    let res, body;
    try {
      res = await fetch(API + path, {
        ...init,
        headers: { Authorization: `Bearer ${await env.CF_PARENT_TOKEN.get()}`, 'Content-Type': 'application/json' }
      });
      body = await res.json();
    } catch (e) {
      console.error(JSON.stringify({ evt: 'cf_error', path, reason: 'transport', msg: e?.message }));
      throw new HttpError(502, 'cloudflare_error');
    }
    if (allow404 && res.status === 404) return null;
    const succeeded = res.ok && body?.success === true && body.result != null;
    if (!succeeded) {
      const errors = Array.isArray(body?.errors) ? body.errors.map((e) => ({ code: e?.code, message: e?.message })) : undefined;
      console.error(JSON.stringify({ evt: 'cf_error', path, status: res.status, errors }));
    }
    ensure(succeeded, 502, 'cloudflare_error');
    return body.result;
  }

  // Permission group name -> id. `scope` ('account' | 'zone') picks the right group when a name exists in both scopes.
  async function groupId(env, name, scope = 'any') {
    if (HEX32.test(name)) return name;
    if (!groups) {
      const list = await cf(env, `/accounts/${env.CF_ACCOUNT_ID}/tokens/permission_groups`);
      ensure(Array.isArray(list), 502, 'cloudflare_error');
      const byScope = (scopeName) => new Map(list.filter((g) => (g.scopes ?? []).includes(scopeName)).map((g) => [g.name, g.id]));
      groups = { any: new Map(list.map((g) => [g.name, g.id])), account: byScope(ACCOUNT_SCOPE), zone: byScope(ZONE_SCOPE) };
    }
    ensure(groups[scope].has(name), 500, 'unknown_permission_group');
    return groups[scope].get(name);
  }

  async function zoneId(env, name) {
    if (!zones.has(name)) {
      const found = await cf(env, `/zones?name=${encodeURIComponent(name)}&account.id=${env.CF_ACCOUNT_ID}`);
      ensure(Array.isArray(found) && found.length === 1 && HEX32.test(found[0].id ?? ''), 500, 'unknown_zone');
      zones.set(name, found[0].id);
    }
    return zones.get(name);
  }

  // A grant (names) becomes one Cloudflare policy. No zones = whole account; "*" = every zone, nested under the account
  // (account-owned tokens cannot use a bare zone wildcard).
  async function grantPolicy(env, grant) {
    const scope = grant.zones ? 'zone' : 'account';
    const account = `${ACCOUNT_SCOPE}.${env.CF_ACCOUNT_ID}`;
    let resources;
    if (!grant.zones) resources = { [account]: '*' };
    else if (grant.zones[0] === '*') resources = { [account]: { [`${ZONE_SCOPE}.*`]: '*' } };
    else resources = Object.fromEntries(await Promise.all(grant.zones.map(async (z) => [`${ZONE_SCOPE}.${await zoneId(env, z)}`, '*'])));
    return {
      effect: 'allow',
      resources,
      permission_groups: await Promise.all(grant.permissions.map(async (p) => ({ id: await groupId(env, p, scope) })))
    };
  }

  // Rule -> Cloudflare policies. `requested` (permission names from the caller) can only narrow what the rule's grants allow.
  async function buildPolicies(env, rule, requested) {
    const grants = expandGrants(rule, profiles);
    let selected = grants;
    if (requested) {
      ensure(grants.length > 0, 400, 'narrowing_unsupported');
      const allowed = new Set(grants.flatMap((g) => g.permissions));
      ensure(requested.every((p) => allowed.has(p)), 403, 'permission_not_allowed');
      selected = grants.map((g) => ({ ...g, permissions: g.permissions.filter((p) => requested.includes(p)) })).filter((g) => g.permissions.length);
    }
    const policies = await Promise.all(selected.map((g) => grantPolicy(env, g)));
    const granted = [...selected];
    if (!requested) {
      for (const p of rule.policies ?? []) {
        policies.push({
          effect: p.effect ?? 'allow',
          resources: p.resources,
          permission_groups: await Promise.all(p.permission_groups.map(async (g) => ({ id: await groupId(env, g) })))
        });
        granted.push(p);
      }
    }
    return { policies, granted };
  }

  /**
   * Owner fingerprint: sha(iss:sub). Legacy sha(sub)-only names are accepted only for
   * GitHub Actions (the pre-multi-issuer format) so other issuers cannot revoke them.
   */
  async function ownerFingerprints(iss, sub) {
    const next = await sha(`${iss}:${sub}`);
    const allowed = new Set([next]);
    if (iss === 'https://token.actions.githubusercontent.com') allowed.add(await sha(sub));
    return { next, allowed };
  }

  async function mint(env, rule, iss, sub, ttl, requested) {
    const { policies, granted } = await buildPolicies(env, rule, requested);
    const iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');
    const now = Date.now();
    const { next: owner } = await ownerFingerprints(iss, sub);
    const t = await cf(env, `/accounts/${env.CF_ACCOUNT_ID}/tokens`, {
      method: 'POST',
      body: JSON.stringify({
        name: `sts/${rule.id}/${owner}/${now}`.slice(0, 120),
        policies,
        not_before: iso(now - 30000),
        expires_on: iso(now + ttl * 1000),
        ...(rule.client_ips && { condition: { request_ip: { in: rule.client_ips } } })
      })
    });
    const wellFormed = typeof t?.id === 'string' && typeof t.value === 'string' && t.value && typeof t.expires_on === 'string';
    if (!wellFormed) console.error(JSON.stringify({ evt: 'cf_error', reason: 'bad_token_response', cf_token_id: t?.id }));
    ensure(wellFormed, 502, 'cloudflare_error');
    return { t, granted };
  }

  // Each OIDC JWT may be exchanged once. Key is jti when present, else sha256(header.payload).
  // Fails closed: without D1 there is no replay protection, so no token is issued.
  async function consumeReplay(env, replay, exp) {
    ensure(env.DB, 500, 'internal_error');
    const now = Math.floor(Date.now() / 1000);
    try {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM used_jti WHERE expires_at < ?').bind(now),
        env.DB.prepare('INSERT INTO used_jti (jti, expires_at) VALUES (?, ?)').bind(replay, exp + JTI_GRACE_SECONDS)
      ]);
    } catch (e) {
      if (/UNIQUE|constraint/i.test(e?.message ?? '')) throw new HttpError(401, 'token_replayed');
      console.error(JSON.stringify({ evt: 'jti_write_failed', msg: e?.message }));
      throw new HttpError(500, 'internal_error');
    }
  }

  // Reads a small request body without buffering more than MAX_BODY bytes (also when there is no content-length).
  async function readBody(request) {
    ensure(Number(request.headers.get('content-length') ?? 0) <= MAX_BODY, 413, 'body_too_large');
    if (!request.body) return '';
    const reader = request.body.getReader();
    const decoder = new TextDecoder();
    let size = 0;
    let text = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY) {
        await reader.cancel();
        throw new HttpError(413, 'body_too_large');
      }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  }

  // Empty body = {}. Only the listed keys are accepted.
  async function readJson(request, allowedKeys) {
    const text = await readBody(request);
    if (!text.trim()) return {};
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new HttpError(400, 'invalid_json');
    }
    const ok = body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).every((k) => allowedKeys.includes(k));
    ensure(ok, 400, 'invalid_request');
    return body;
  }

  // Body of POST /token: optional ttl_seconds and optional permissions (names) to narrow the rule's grants.
  async function readTokenRequest(request) {
    const { ttl_seconds: ttl, permissions } = await readJson(request, ['ttl_seconds', 'permissions']);
    ensure(ttl === undefined || (Number.isInteger(ttl) && ttl >= MIN_TTL && ttl <= MAX_TTL), 400, 'invalid_ttl');
    const validNames = Array.isArray(permissions) && permissions.length > 0 && permissions.length <= 32 && permissions.every((p) => typeof p === 'string' && p.length > 0 && p.length <= 128);
    ensure(permissions === undefined || validNames, 400, 'invalid_permissions');
    return { ttl, permissions };
  }

  async function limit(env, key, binding = 'RATE_LIMIT') {
    const limiter = env[binding] ?? env.RATE_LIMIT;
    ensure(limiter, 500, 'internal_error');
    const { success } = await limiter.limit({ key });
    ensure(success, 429, 'rate_limited');
  }

  // Optional second layer for the dashboard: when ACCESS_TEAM_DOMAIN + ACCESS_AUD are set, a valid Cloudflare Access JWT is required.
  async function requireAccess(request, env) {
    if (!env.ACCESS_TEAM_DOMAIN && !env.ACCESS_AUD) return;
    ensure(ACCESS_DOMAIN.test(env.ACCESS_TEAM_DOMAIN ?? '') && env.ACCESS_AUD, 500, 'internal_error');
    const token = request.headers.get('Cf-Access-Jwt-Assertion');
    ensure(token, 401, 'access_required');
    if (!accessJwks.has(env.ACCESS_TEAM_DOMAIN)) {
      accessJwks.set(env.ACCESS_TEAM_DOMAIN, createRemoteJWKSet(new URL(`https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`)));
    }
    try {
      await jwtVerify(token, accessJwks.get(env.ACCESS_TEAM_DOMAIN), {
        issuer: `https://${env.ACCESS_TEAM_DOMAIN}`,
        audience: env.ACCESS_AUD,
        algorithms: ['RS256']
      });
    } catch {
      throw new HttpError(401, 'access_required');
    }
  }

  // Best effort: the token is already minted, so a DB failure is logged (cf_token_id is in the logs) instead of failing the exchange.
  async function record(env, request, rule, iss, claims, ttl, t, granted) {
    const issued = Math.floor(Date.now() / 1000);
    try {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO mints (id, rule_id, description, sub, repository, actor, issuer, policies, ttl, issued_at, expires_at, ray, ip) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
          t.id, rule.id, rule.description ?? null, claims.sub, claims.repository ?? claims.email ?? null, claims.actor ?? null, iss, JSON.stringify(granted), ttl, issued,
          Math.floor(Date.parse(t.expires_on) / 1000), request.headers.get('cf-ray'), request.headers.get('cf-connecting-ip')
        ),
        env.DB.prepare('DELETE FROM mints WHERE issued_at < ?').bind(issued - RETENTION_DAYS * 86400)
      ]);
    } catch (e) {
      console.error(JSON.stringify({ evt: 'audit_write_failed', cf_token_id: t.id, msg: e?.message }));
    }
  }

  async function markRevoked(env, id) {
    try {
      await env.DB.prepare('UPDATE mints SET revoked_at = ? WHERE id = ?').bind(Math.floor(Date.now() / 1000), id).run();
    } catch (e) {
      console.error(JSON.stringify({ evt: 'audit_write_failed', cf_token_id: id, msg: e?.message }));
    }
  }

  async function listMints(env) {
    ensure(env.DB, 500, 'internal_error');
    const { results } = await env.DB.prepare('SELECT * FROM mints ORDER BY issued_at DESC LIMIT ?').bind(PAGE_SIZE).all();
    const mints = results.map((m) => ({ ...m, policies: JSON.parse(m.policies) }));
    return Response.json({ mints }, { headers: API_HEADERS });
  }

  async function listDenials(env) {
    ensure(env.DB, 500, 'internal_error');
    const { results } = await env.DB.prepare('SELECT * FROM denials ORDER BY ts DESC LIMIT ?').bind(DENIAL_PAGE_SIZE).all();
    return Response.json({ denials: results }, { headers: API_HEADERS });
  }

  // Headline numbers and a 24h hourly histogram for the dashboard, in one D1 round trip.
  async function stats(env) {
    ensure(env.DB, 500, 'internal_error');
    const now = Math.floor(Date.now() / 1000);
    const since = now - 86400;
    const q = (sql, ...args) => env.DB.prepare(sql).bind(...args);
    const [minted, active, revoked, denied, hourly] = await env.DB.batch([
      q('SELECT COUNT(*) AS n FROM mints WHERE issued_at > ?', since),
      q('SELECT COUNT(*) AS n FROM mints WHERE expires_at > ? AND revoked_at IS NULL', now),
      q('SELECT COUNT(*) AS n FROM mints WHERE revoked_at > ?', since),
      q('SELECT COUNT(*) AS n FROM denials WHERE ts > ?', since),
      q('SELECT (issued_at / 3600) AS hour, COUNT(*) AS n FROM mints WHERE issued_at > ? GROUP BY hour ORDER BY hour', since)
    ]);
    const n = (r) => r.results?.[0]?.n ?? 0;
    return Response.json(
      { now, minted_24h: n(minted), active: n(active), revoked_24h: n(revoked), denied_24h: n(denied), hourly: (hourly.results ?? []).map((h) => ({ hour: h.hour * 3600, n: h.n })) },
      { headers: API_HEADERS }
    );
  }

  // Read-only view of the loaded policy (no secrets in it; same access gate as the rest of the dashboard).
  function policyView(env) {
    const rules = policy.rules.map((r) => ({
      id: r.id,
      description: r.description ?? null,
      issuer: r.issuer,
      principal: r.principal,
      claims: r.claims ?? null,
      max_ttl_seconds: r.max_ttl_seconds,
      client_ips: r.client_ips ?? null,
      grants: expandGrants(r, profiles),
      raw_policies: (r.policies ?? []).length,
      source: r._source ?? null
    }));
    const issuers = Object.fromEntries([...issuerMap].map(([iss, e]) => [iss, { type: e.type, jwks: e.jwks }]));
    return Response.json({ audience: policy.audience, profiles, issuers, rules, account: env.CF_ACCOUNT_ID }, { headers: API_HEADERS });
  }

  // Authenticated denials only (JWT verified): unauthenticated noise would let anyone fill the table.
  async function recordDenial(env, request, ctx, e) {
    try {
      const ts = Math.floor(Date.now() / 1000);
      await env.DB.batch([
        env.DB.prepare('INSERT INTO denials (ts, reason, status, sub, repository, ray, ip) VALUES (?,?,?,?,?,?,?)').bind(
          ts, e.code, e.status, ctx.claims.sub, ctx.claims.repository ?? ctx.claims.email ?? null, request.headers.get('cf-ray'), request.headers.get('cf-connecting-ip')
        ),
        env.DB.prepare('DELETE FROM denials WHERE ts < ?').bind(ts - RETENTION_DAYS * 86400)
      ]);
    } catch (err) {
      console.error(JSON.stringify({ evt: 'audit_write_failed', reason: e.code, msg: err?.message }));
    }
  }

  // Shared by /token and /revoke: header -> per-IP limit -> JWT -> per-subject limit -> rule.
  async function authenticate(request, env, ctx) {
    const auth = request.headers.get('Authorization') ?? '';
    ensure(auth.startsWith('Bearer '), 401, 'auth_header_missing');
    await limit(env, `ip:${request.headers.get('cf-connecting-ip') ?? 'unknown'}`);
    const verified = await verifyCaller(auth.slice(7).trim(), issuerMap, policy.audience, jwks);
    ctx.claims = verified.claims;
    await limit(env, `sub:${verified.iss}:${verified.claims.sub}`);
    const type = verified.entry.type;
    const rule = findRule(policy.rules, verified.iss, verified.claims, type);
    ensure(rule, 403, 'no_matching_rule');
    return { ...verified, rule };
  }

  async function handleToken(request, env, ctx) {
    const { iss, claims, rule, replay, exp, entry } = await authenticate(request, env, ctx);
    const { ttl: requestedTtl, permissions } = await readTokenRequest(request);
    let ttl;
    try {
      ttl = ttlFor(rule, requestedTtl);
    } catch {
      throw new HttpError(500, 'internal_error');
    }
    // SPIRE caches JWT-SVIDs (stable jti until exp). Single-use jti breaks CI re-runs and
    // mint+revoke in one job; per-subject rate limit still applies via authenticate().
    if (entry.type !== 'spiffe') await consumeReplay(env, replay, exp);
    const { t, granted } = await mint(env, rule, iss, claims.sub, ttl, permissions);
    await record(env, request, rule, iss, claims, ttl, t, granted);
    log({ evt: 'mint', sub: claims.sub, repository: claims.repository ?? claims.email, rule: rule.id, ttl, cf_token_id: t.id, ray: request.headers.get('cf-ray') });
    return Response.json({ id: t.id, token: t.value, expires_on: t.expires_on, rule: rule.id }, { headers: API_HEADERS });
  }

  // Revoke only tokens minted for this issuer+subject (name embeds sha(iss:sub); legacy sha(sub) still accepted).
  // Do not consumeReplay here: mint already burned the jti, and issuers like SPIRE cache JWT-SVIDs
  // so mint+revoke cannot obtain two distinct tokens in one job.
  async function handleRevoke(request, env, ctx) {
    const { iss, claims, rule } = await authenticate(request, env, ctx);
    const { token_id: id } = await readJson(request, ['token_id']);
    ensure(typeof id === 'string' && HEX32.test(id), 400, 'invalid_request');

    const path = `/accounts/${env.CF_ACCOUNT_ID}/tokens/${id}`;
    const info = await cf(env, path, undefined, { allow404: true });
    ensure(info, 404, 'token_not_found');
    const [prefix, , owner] = String(info.name ?? '').split('/');
    const { allowed } = await ownerFingerprints(iss, claims.sub);
    ensure(prefix === 'sts' && allowed.has(owner), 403, 'forbidden');

    await cf(env, path, { method: 'DELETE' }, { allow404: true });
    if (env.DB) await markRevoked(env, id);
    log({ evt: 'revoke', sub: claims.sub, repository: claims.repository ?? claims.email, rule: rule.id, cf_token_id: id, ray: request.headers.get('cf-ray') });
    return Response.json({ revoked: true, id }, { headers: API_HEADERS });
  }

  // Dashboard data endpoints: same access gate and per-IP limit.
  const DASHBOARD_API = { '/api/mints': listMints, '/api/denials': listDenials, '/api/stats': stats, '/api/policy': policyView, '/api/cleanup': cleanupPreview, '/api/cleanup/trend': cleanupTrend };

  async function handle(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/') {
      await requireAccess(request, env);
      return new Response(PAGE, { headers: PAGE_HEADERS });
    }
    if (request.method === 'GET' && Object.hasOwn(DASHBOARD_API, url.pathname)) {
      await requireAccess(request, env);
      // Own bucket (DASH_LIMIT): viewing the dashboard must not eat the per-IP budget of /token and /revoke.
      await limit(env, `dash:${request.headers.get('cf-connecting-ip') ?? 'unknown'}`, 'DASH_LIMIT');
      return DASHBOARD_API[url.pathname](env, url);
    }
    if (request.method === 'POST' && url.pathname === '/api/cleanup') {
      await requireAccess(request, env);
      await limit(env, `dash:${request.headers.get('cf-connecting-ip') ?? 'unknown'}`, 'DASH_LIMIT');
      return Response.json(await cleanupExpired(env), { headers: API_HEADERS });
    }
    if (request.method === 'POST' && url.pathname === '/token') return handleToken(request, env, ctx);
    if (request.method === 'POST' && url.pathname === '/revoke') return handleRevoke(request, env, ctx);
    throw new HttpError(404, 'not_found');
  }

  // Cloudflare keeps expired tokens in the account forever, so a daily cron deletes the expired sts/* ones.
  // Guardrails: a token is deletable only if ALL hold: name starts with "sts/" AND matches mint() format
  // (sts/<rule>/<12 hex owner>/<ms>), Cloudflare reports status "expired", expires_on is a valid date more
  // than CLEANUP_GRACE_SECONDS in the past, id is 32 hex.
  // Anything else (active, unknown, malformed, foreign tokens, the parent token) is never touched.
  // `projected`: also accept still-active tokens, to preview what the NEXT run will find (never used to delete).
  const deletable = (t, nowMs, projected = false) => {
    const name = String(t?.name ?? '');
    const exp = Date.parse(t?.expires_on ?? '');
    return (
      HEX32.test(t?.id ?? '') &&
      name.startsWith('sts/') &&
      STS_NAME.test(name) &&
      (t.status === 'expired' || (projected && t.status === 'active')) &&
      Number.isFinite(exp) &&
      exp < nowMs - CLEANUP_GRACE_SECONDS * 1000
    );
  };

  const ignoreReason = (t, nowMs) => {
    const exp = Date.parse(t?.expires_on ?? '');
    if (!HEX32.test(t?.id ?? '')) return 'bad id';
    if (!String(t.name).startsWith('sts/')) return 'name does not start with sts/';
    if (!STS_NAME.test(t.name)) return 'name not in mint format';
    if (!Number.isFinite(exp)) return 'no valid expires_on';
    if (t.status !== 'expired' && t.status !== 'active') return 'status ' + t.status;
    if (t.status === 'active') return 'still active';
    return exp >= nowMs - CLEANUP_GRACE_SECONDS * 1000 ? 'inside grace period' : 'not eligible';
  };

  // Read-only scan shared by the cron and the dashboard preview.
  async function findExpired(env) {
    const base = `/accounts/${env.CF_ACCOUNT_ID}/tokens`;
    const now = Date.now();
    const next = nextRunMs(now);
    const candidates = [];
    const upcoming = [];
    const statuses = {};
    const ignored = [];
    let scanned = 0;
    for (let page = 1; page <= CLEANUP_MAX_PAGES; page++) {
      // Without include_expired=true the API hides expired tokens, so cleanup would always find 0.
      const list = await cf(env, `${base}?page=${page}&per_page=${CLEANUP_PER_PAGE}&include_expired=true`);
      ensure(Array.isArray(list), 502, 'cloudflare_error');
      scanned += list.length;
      for (const t of list) {
        if (deletable(t, now)) candidates.push({ id: t.id, name: t.name, status: t.status, expires_on: t.expires_on });
        else if (t.status === 'expired' && deletable({ ...t, status: 'expired' }, Date.parse(t.expires_on) + CLEANUP_GRACE_SECONDS * 1000 + 1)) {
          // Expired but still inside the grace period: deleted by the first cron run after the grace ends.
          upcoming.push({ id: t.id, name: t.name, status: t.status, expires_on: t.expires_on, delete_at: Math.floor(nextRunMs(Date.parse(t.expires_on) + CLEANUP_GRACE_SECONDS * 1000) / 1000) });
        } else if (deletable(t, next, true)) upcoming.push({ id: t.id, name: t.name, status: t.status, expires_on: t.expires_on, delete_at: Math.floor(next / 1000) });
        else {
          // Why a token is left alone (shown on the Cleanup tab). Only sts-looking names are listed, never other teams' tokens.
          statuses[t.status] = (statuses[t.status] ?? 0) + 1;
          const name = String(t?.name ?? '');
          if (/^sts/i.test(name) && ignored.length < 50) ignored.push({ id: t.id, name, status: t.status, expires_on: t.expires_on, reason: ignoreReason(t, now) });
        }
      }
      if (list.length < CLEANUP_PER_PAGE) break;
    }
    return { scanned, candidates, upcoming, next, statuses, ignored };
  }

  // One counter row per hour (upsert), never per token: the trend chart needs only totals, and the table stays tiny.
  async function recordCleanup(env, deleted) {
    const ts = Math.floor(Date.now() / 1000);
    const hour = ts - (ts % 3600);
    try {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO cleanup_stats (hour, deleted, runs) VALUES (?, ?, 1) ON CONFLICT(hour) DO UPDATE SET deleted = deleted + excluded.deleted, runs = runs + 1').bind(hour, deleted),
        env.DB.prepare('DELETE FROM cleanup_stats WHERE hour < ?').bind(ts - RETENTION_DAYS * 86400)
      ]);
    } catch (e) {
      console.error(JSON.stringify({ evt: 'audit_write_failed', reason: 'cleanup_stats', msg: e?.message }));
    }
  }

  async function cleanupExpired(env) {
    const { scanned, candidates } = await findExpired(env);
    const batch = candidates.slice(0, CLEANUP_MAX_DELETES);
    const dryRun = env.CLEANUP_DRY_RUN === 'true';
    let deleted = 0;
    let skipped = 0;
    if (!dryRun) {
      for (const c of batch) {
        try {
          // Re-read right before deleting: the token must still match every guardrail.
          const fresh = await cf(env, `/accounts/${env.CF_ACCOUNT_ID}/tokens/${c.id}`, undefined, { allow404: true });
          if (!fresh || !deletable(fresh, Date.now())) {
            skipped++;
            continue;
          }
          await cf(env, `/accounts/${env.CF_ACCOUNT_ID}/tokens/${c.id}`, { method: 'DELETE' }, { allow404: true });
          deleted++;
        } catch {
          // cf() already logged it; keep going with the rest.
        }
      }
    }
    if (deleted > 0 && env.DB) await recordCleanup(env, deleted);
    log({ evt: 'cleanup', dry_run: dryRun, scanned, found: candidates.length, deleted, skipped });
    return { scanned, found: candidates.length, deleted, skipped, dry_run: dryRun };
  }

  // Dashboard preview: what the next run deletes. `tokens` are deletable right now; `upcoming` are active tokens that will be
  // past the grace period by the next run. Read-only: nothing is deleted from here.
  async function cleanupPreview(env) {
    const { scanned, candidates, upcoming, next, statuses, ignored } = await findExpired(env);
    return Response.json(
      {
        schedule: CLEANUP_CRON_LABEL, now: Math.floor(Date.now() / 1000), next_run: Math.floor(next / 1000),
        grace_seconds: CLEANUP_GRACE_SECONDS, max_per_run: CLEANUP_MAX_DELETES, dry_run: env.CLEANUP_DRY_RUN === 'true',
        scanned, total: candidates.length, tokens: candidates.slice(0, CLEANUP_MAX_DELETES),
        upcoming_total: upcoming.length, upcoming: upcoming.slice(0, CLEANUP_MAX_DELETES), statuses, ignored
      },
      { headers: API_HEADERS }
    );
  }

  // Counters only: minted (from mints) vs deleted by the cron (from cleanup_stats), per hour (1 day) or per day (7 / 30 days).
  async function cleanupTrend(env, url) {
    ensure(env.DB, 500, 'internal_error');
    const days = [1, 7, 30].includes(Number(url.searchParams.get('days'))) ? Number(url.searchParams.get('days')) : 1;
    const bucket = days === 1 ? 3600 : 86400;
    const now = Math.floor(Date.now() / 1000);
    const since = now - days * 86400;
    const [minted, deleted] = await env.DB.batch([
      // `bucket` is a fixed constant (3600 or 86400), inlined: a bound number would make SQLite divide as REAL.
      env.DB.prepare(`SELECT CAST(issued_at / ${bucket} AS INTEGER) AS b, COUNT(*) AS n FROM mints WHERE issued_at > ? GROUP BY b ORDER BY b`).bind(since),
      env.DB.prepare(`SELECT CAST(hour / ${bucket} AS INTEGER) AS b, SUM(deleted) AS n FROM cleanup_stats WHERE hour > ? GROUP BY b ORDER BY b`).bind(since)
    ]);
    const series = (r) => (r.results ?? []).map((x) => ({ t: x.b * bucket, n: x.n }));
    const m = series(minted);
    const d = series(deleted);
    const sum = (a) => a.reduce((t, x) => t + x.n, 0);
    return Response.json({ days, bucket, now, minted: m, deleted: d, minted_total: sum(m), deleted_total: sum(d) }, { headers: API_HEADERS });
  }

  return {
    scheduled(event, env, ctx) {
      ctx.waitUntil(cleanupExpired(env));
    },
    cleanupExpired,
    async fetch(request, env) {
      const ctx = {};
      try {
        return await handle(request, env, ctx);
      } catch (e) {
        const known = e instanceof HttpError;
        if (!known) console.error('unhandled', e?.message);
        log({ evt: 'deny', reason: known ? e.code : 'internal_error', ray: request.headers.get('cf-ray') });
        if (known && ctx.claims && env.DB) await recordDenial(env, request, ctx, e);
        return Response.json({ error: known ? e.code : 'internal_error' }, { status: known ? e.status : 500, headers: API_HEADERS });
      }
    }
  };
}

export default createWorker(policyJson);
