// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createWorker } from '../src/index.js';
import policy from './fixture-policy.json' with { type: 'json' };
import realBundle from '../policy.bundle.json' with { type: 'json' };
const realPolicy = {
  audience: realBundle.audience,
  issuers: realBundle.issuers,
  profiles: realBundle.profiles,
  rules: realBundle.rules.map(({ _source, ...r }) => r)
};

const iss = 'https://token.actions.githubusercontent.com';
const jwksUrl = policy.issuers[iss];
const aud = policy.audience;
const { publicKey, privateKey } = await generateKeyPair('RS256');
const other = await generateKeyPair('RS256');
const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };

const claims = {
  repository: 'example/terraform-cf',
  ref: 'refs/heads/main',
  job_workflow_ref: 'example/terraform-cf/.github/workflows/apply.yml@refs/heads/main'
};
const SUB = 'repo:example/terraform-cf:ref:refs/heads/main';

const jwt = ({ key = privateKey, issuer = iss, audience = aud, sub = SUB, exp = '5m', nbf, jti = crypto.randomUUID(), extra = claims } = {}) => {
  let j = new SignJWT({ ...extra }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuedAt().setIssuer(issuer).setAudience(audience).setExpirationTime(exp);
  if (sub !== null) j = j.setSubject(sub);
  if (jti !== null) j = j.setJti(jti);
  if (nbf) j = j.setNotBefore(nbf);
  return j.sign(key);
};

const good = { id: 'a'.repeat(32), value: 'secret-value', expires_on: '2030-01-01T00:00:00Z' };
const ACCOUNT = 'com.cloudflare.api.account';
const ZONE = 'com.cloudflare.api.account.zone';
const zoneMap = { 'example.com': 'e'.repeat(32) };
let cfCalls, cfMode, groupsResult, tokenInfo;
const json = (o, status = 200) => new Response(JSON.stringify(o), { status });
globalThis.fetch = async (url, init) => {
  url = String(url);
  if (url === jwksUrl) return json({ keys: [jwk] });
  cfCalls.push({ url, init });
  if (url.includes('/zones?name=')) {
    const found = zoneMap[new URL(url).searchParams.get('name')];
    return json({ success: true, result: found ? [{ id: found }] : [] });
  }
  if (url.endsWith('/permission_groups')) return cfMode === 'groups_fail' ? json({ success: false, errors: [] }, 500) : json({ success: true, result: groupsResult });
  if (url.endsWith(`/tokens/${good.id}`)) {
    if (init?.method === 'DELETE') return cfMode === 'delete_fail' ? json({ success: false, errors: [] }, 500) : json({ success: true, result: { id: good.id } });
    return tokenInfo ? json({ success: true, result: tokenInfo }) : json({ success: false, errors: [{ code: 7003 }] }, 404);
  }
  if (cfMode === 'http_500') return json({ success: true, result: good }, 500);
  if (cfMode === 'success_false') return json({ success: false, errors: [{ code: 1, message: 'nope' }] }, 400);
  if (cfMode === 'not_json') return new Response('<html>', { status: 200 });
  if (cfMode === 'bad_token') return json({ success: true, result: { id: 'x' } });
  if (cfMode === 'throw') throw new Error('network');
  return json({ success: true, result: good });
};

// Fake D1: records statements, enforces the used_jti primary key like SQLite would.
const fakeDb = (rows = []) => {
  const db = {
    rows,
    jti: new Set(),
    mintInserts: [],
    denialInserts: [],
    updates: [],
    prepare: (sql) => ({ sql, args: [], bind(...a) { this.args = a; return this; }, all: async () => ({ results: rows }), run: async function () { db.updates.push([this.sql, this.args]); } }),
    batch: async (stmts) => {
      for (const s of stmts) {
        if (/INSERT INTO used_jti/.test(s.sql)) {
          if (db.jti.has(s.args[0])) throw new Error('D1_ERROR: UNIQUE constraint failed: used_jti.jti');
          db.jti.add(s.args[0]);
        } else if (/INSERT INTO mints/.test(s.sql)) db.mintInserts.push([s.sql, s.args]);
        else if (/INSERT INTO denials/.test(s.sql)) db.denialInserts.push(s.args);
      }
    }
  };
  return db;
};
const env = (over = {}) => ({
  CF_ACCOUNT_ID: 'acc',
  CF_PARENT_TOKEN: { get: async () => 'PARENT-SECRET' },
  RATE_LIMIT: { limit: async () => ({ success: true }) },
  DB: fakeDb(),
  ...over
});
const call = (w, token, { body, e = env(), method = 'POST', path = '/token', headers = {} } = {}) =>
  w.fetch(new Request('https://x' + path, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers }, body }), e);

const setup = (p = policy) => {
  cfCalls = [];
  cfMode = 'ok';
  tokenInfo = null;
  groupsResult = [
    { id: 'a'.repeat(32), name: 'DNS Write', scopes: [ZONE] },
    { id: 'b'.repeat(32), name: 'DNS Read', scopes: [ZONE] },
    { id: 'c'.repeat(32), name: 'Account Settings Read', scopes: [ACCOUNT] },
    { id: 'd'.repeat(32), name: 'Workers Routes Write', scopes: [ZONE] },
    { id: '1'.repeat(32), name: 'Shared Perm', scopes: [ACCOUNT] },
    { id: '2'.repeat(32), name: 'Shared Perm', scopes: [ZONE] }
  ];
  return createWorker(p);
};
const status = async (p, code, err) => {
  const r = await p;
  assert.equal(r.status, code);
  if (err) assert.equal((await r.json()).error, err);
  return r;
};
const sha12 = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].slice(0, 6).map((b) => b.toString(16).padStart(2, '0')).join('');

test('valid JWT mints token; response shape and no-store', async () => {
  const w = setup();
  const r = await status(call(w, await jwt(), { body: JSON.stringify({ ttl_seconds: 120 }) }), 200);
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await r.json(), { id: good.id, token: 'secret-value', expires_on: good.expires_on, rule: 'terraform-cf-main-dns' });
  const req = JSON.parse(cfCalls.at(-1).init.body);
  assert.match(req.name, /^sts\/terraform-cf-main-dns\/[0-9a-f]{12}\/\d+$/);
  assert.ok(!req.name.includes('terraform-cf:ref'));
  assert.equal(cfCalls.at(-1).init.headers.Authorization, 'Bearer PARENT-SECRET');
  assert.equal(Date.parse(req.expires_on) - Date.parse(req.not_before) <= 150000, true);
  assert.equal(req.condition, undefined);
});

test('JWT rejections', async () => {
  const w = setup();
  await status(call(w, await jwt({ key: other.privateKey })), 401, 'token_invalid');
  await status(call(w, await jwt({ issuer: 'https://evil.example' })), 401, 'unknown_issuer');
  await status(call(w, await jwt({ issuer: 'constructor' })), 401, 'unknown_issuer');
  await status(call(w, await jwt({ audience: 'other' })), 401, 'token_invalid');
  await status(call(w, await jwt({ exp: Math.floor(Date.now() / 1000) - 3600 })), 401, 'token_invalid');
  await status(call(w, await jwt({ nbf: Math.floor(Date.now() / 1000) + 3600 })), 401, 'token_invalid');
  await status(call(w, await jwt({ sub: null })), 401, 'token_invalid');
  await status(call(w, await jwt({ sub: '' })), 401, 'token_invalid');
  await status(call(w, await jwt({ jti: null })), 401, 'token_invalid');
  await status(call(w, 'garbage'), 401, 'token_invalid');
  await status(call(w, null), 401, 'auth_header_missing');
  assert.equal(cfCalls.length, 0);
});

test('alg none and HS256 (key confusion) are rejected', async () => {
  const w = setup();
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss, aud, sub: SUB, jti: 'x', iat: now, exp: now + 300, ...claims };
  await status(call(w, `${b64({ alg: 'none', typ: 'JWT' })}.${b64(payload)}.`), 401, 'token_invalid');
  const hs = await new SignJWT(payload).setProtectedHeader({ alg: 'HS256', kid: 'k1' }).sign(new TextEncoder().encode(JSON.stringify(jwk)));
  await status(call(w, hs), 401, 'token_invalid');
  assert.equal(cfCalls.length, 0);
});

test('no matching rule -> 403, nothing minted, jti not consumed', async () => {
  const w = setup();
  const e = env();
  await status(call(w, await jwt({ sub: 'repo:example/terraform-cf:ref:refs/heads/dev', extra: { ...claims, ref: 'refs/heads/dev' } }), { e }), 403, 'no_matching_rule');
  assert.equal(cfCalls.length, 0);
  assert.equal(e.DB.jti.size, 0);
});

test('request validation', async () => {
  const w = setup();
  const t = await jwt();
  await status(call(w, t, { body: '{bad' }), 400, 'invalid_json');
  await status(call(w, t, { body: '[]' }), 400, 'invalid_request');
  await status(call(w, t, { body: '{"x":1}' }), 400, 'invalid_request');
  for (const v of [0, -1, 59, 86401, 1.5, '900', null]) await status(call(w, t, { body: JSON.stringify({ ttl_seconds: v }) }), 400, 'invalid_ttl');
  await status(call(w, t, { body: JSON.stringify({ pad: 'x'.repeat(2000) }) }), 413, 'body_too_large');
  await status(call(w, t, { method: 'GET' }), 404);
  await status(call(w, t, { path: '/other' }), 404);
  assert.equal(cfCalls.length, 0);
});

test('chunked body without content-length is capped', async () => {
  const w = setup();
  const big = new ReadableStream({ start(c) { for (let i = 0; i < 8; i++) c.enqueue(new TextEncoder().encode('x'.repeat(512))); c.close(); } });
  const req = new Request('https://x/token', { method: 'POST', headers: { Authorization: `Bearer ${await jwt()}` }, body: big, duplex: 'half' });
  await status(w.fetch(req, env()), 413, 'body_too_large');
});

test('ttl is capped by rule max', async () => {
  const w = setup();
  await status(call(w, await jwt(), { body: JSON.stringify({ ttl_seconds: 86400 }) }), 200);
  const req = JSON.parse(cfCalls.at(-1).init.body);
  assert.ok(Date.parse(req.expires_on) - Date.parse(req.not_before) <= 900000 + 31000);
});

test('second rule applies client_ips to the minted token', async () => {
  const w = setup();
  const extra = { repository: 'example/ip-pinned', ref: 'refs/heads/release' };
  const r = await status(call(w, await jwt({ extra, sub: 'repo:example/ip-pinned:ref:refs/heads/release' })), 200);
  assert.equal((await r.json()).rule, 'pinned-ip-read');
  assert.deepEqual(JSON.parse(cfCalls.at(-1).init.body).condition, { request_ip: { in: ['203.0.113.0/24'] } });
});

test('JWT is single use (replay rejected) and D1 is required', async () => {
  const w = setup();
  const e = env();
  const t = await jwt();
  await status(call(w, t, { e }), 200);
  const before = cfCalls.length;
  await status(call(w, t, { e }), 401, 'token_replayed');
  assert.equal(cfCalls.length, before);
  await status(call(w, await jwt(), { e: env({ DB: undefined }) }), 500, 'internal_error');
  const broken = fakeDb();
  broken.batch = async () => { throw new Error('d1 down'); };
  await status(call(w, await jwt(), { e: env({ DB: broken }) }), 500, 'internal_error');
  assert.equal(cfCalls.length, before);
});

test('Cloudflare failures return generic 502 without leaking details', async () => {
  const w = setup();
  for (const mode of ['http_500', 'success_false', 'not_json', 'bad_token', 'throw']) {
    cfMode = mode;
    const r = await status(call(w, await jwt()), 502);
    assert.deepEqual(await r.json(), { error: 'cloudflare_error' });
  }
});

test('permission group lookup (names) and failures', async () => {
  const named = structuredClone(policy);
  named.rules[0].policies[0].permission_groups = ['DNS Write'];
  let w = setup(named);
  await status(call(w, await jwt()), 200);
  assert.equal(JSON.parse(cfCalls.at(-1).init.body).policies[0].permission_groups[0].id, 'a'.repeat(32));
  const before = cfCalls.length;
  await status(call(w, await jwt()), 200);
  assert.equal(cfCalls.length - before, 1);

  cfCalls = [];
  w = createWorker(named);
  cfMode = 'groups_fail';
  await status(call(w, await jwt()), 502, 'cloudflare_error');
  cfMode = 'ok';
  groupsResult = [];
  w = createWorker(named);
  await status(call(w, await jwt()), 500, 'unknown_permission_group');
});

test('rate limiting: per-IP, per-subject, fail closed without binding', async () => {
  const w = setup();
  const keys = [];
  const rl = (deny) => ({ limit: async ({ key }) => (keys.push(key), { success: !key.startsWith(deny) }) });
  await status(call(w, await jwt(), { e: env({ RATE_LIMIT: rl('ip:') }) }), 429, 'rate_limited');
  assert.equal(cfCalls.length, 0);
  await status(call(w, await jwt(), { e: env({ RATE_LIMIT: rl('sub:') }) }), 429, 'rate_limited');
  assert.equal(cfCalls.length, 0);
  assert.ok(keys.some((k) => k.startsWith('sub:')));
  await status(call(w, await jwt(), { e: env({ RATE_LIMIT: undefined }) }), 500, 'internal_error');
});

test('malformed policy fails at startup', () => {
  const p = structuredClone(policy);
  p.rules[0].principal = 'not-a-github-sub';
  assert.throws(() => createWorker(p), /policy:/);
  assert.doesNotThrow(() => createWorker(realPolicy));
});

test('mint is recorded in D1 without the token value', async () => {
  const w = setup();
  const e = env();
  await status(call(w, await jwt(), { e }), 200);
  const [sql, args] = e.DB.mintInserts[0];
  assert.match(sql, /INSERT INTO mints/);
  assert.equal(args[0], good.id);
  assert.equal(args[1], 'terraform-cf-main-dns');
  assert.equal(args[4], 'example/terraform-cf');
  assert.ok(!JSON.stringify(args).includes('secret-value'));
  assert.equal(args[10], Math.floor(Date.parse(good.expires_on) / 1000));
});

test('audit write failure does not fail the exchange', async () => {
  const w = setup();
  const db = fakeDb();
  const batch = db.batch;
  db.batch = async (stmts) => {
    if (stmts.some((s) => /INSERT INTO mints/.test(s.sql))) throw new Error('d1 down');
    return batch(stmts);
  };
  await status(call(w, await jwt(), { e: env({ DB: db }) }), 200);
});

const GITHUB_ISS = 'https://token.actions.githubusercontent.com';

test('revoke: owner can revoke its own token, which is marked in D1', async () => {
  const w = setup();
  tokenInfo = { id: good.id, name: `sts/terraform-cf-main-dns/${await sha12(`${GITHUB_ISS}:${SUB}`)}/123` };
  const e = env();
  const r = await status(call(w, await jwt(), { e, path: '/revoke', body: JSON.stringify({ token_id: good.id }) }), 200);
  assert.deepEqual(await r.json(), { revoked: true, id: good.id });
  assert.equal(cfCalls.at(-1).init.method, 'DELETE');
  assert.match(e.DB.updates[0][0], /UPDATE mints SET revoked_at/);
  assert.equal(e.DB.updates[0][1][1], good.id);
});

test('revoke: GitHub legacy sha(sub) name still works; other subject forbidden', async () => {
  const w = setup();
  const body = JSON.stringify({ token_id: good.id });
  tokenInfo = { id: good.id, name: `sts/terraform-cf-main-dns/${await sha12(SUB)}/123` };
  await status(call(w, await jwt(), { path: '/revoke', body }), 200);
});

test('revoke: other subject, unknown token, bad input; same JWT ok twice', async () => {
  const w = setup();
  const body = JSON.stringify({ token_id: good.id });
  tokenInfo = { id: good.id, name: `sts/terraform-cf-main-dns/${await sha12(`${GITHUB_ISS}:someone-else`)}/123` };
  await status(call(w, await jwt(), { path: '/revoke', body }), 403, 'forbidden');
  tokenInfo = { id: good.id, name: 'manually-created-token' };
  await status(call(w, await jwt(), { path: '/revoke', body }), 403, 'forbidden');
  assert.ok(!cfCalls.some((c) => c.init?.method === 'DELETE'));
  tokenInfo = null;
  await status(call(w, await jwt(), { path: '/revoke', body }), 404, 'token_not_found');
  for (const b of ['{}', '{"token_id":"short"}', '{"token_id":5}', '{"token_id":"' + good.id + '","x":1}', '[]']) {
    await status(call(w, await jwt(), { path: '/revoke', body: b }), 400);
  }
  tokenInfo = { id: good.id, name: `sts/terraform-cf-main-dns/${await sha12(`${GITHUB_ISS}:${SUB}`)}/123` };
  const t = await jwt();
  const shared = env();
  // Revoke does not burn jti (SPIRE caches SVIDs; mint+revoke share one JWT).
  await status(call(w, t, { path: '/revoke', body, e: shared }), 200);
  await status(call(w, t, { path: '/revoke', body, e: shared }), 200);
  cfMode = 'delete_fail';
  await status(call(w, await jwt(), { path: '/revoke', body }), 502, 'cloudflare_error');
  await status(call(w, null, { path: '/revoke', body }), 401, 'auth_header_missing');
  await status(call(w, await jwt({ sub: 'repo:example/terraform-cf:ref:refs/heads/dev', extra: { ...claims, ref: 'refs/heads/dev' } }), { path: '/revoke', body }), 403, 'no_matching_rule');
});

test('GET /api/mints lists records; GET / serves the page with hardened headers', async () => {
  const w = setup();
  const row = { id: 'x', rule_id: 'r', sub: 's', policies: '[{"permission_groups":["g"]}]', issued_at: 1, expires_at: 2 };
  const r = await status(call(w, null, { method: 'GET', path: '/api/mints', e: env({ DB: fakeDb([row]) }) }), 200);
  assert.deepEqual((await r.json()).mints[0].policies, [{ permission_groups: ['g'] }]);
  const page = await status(call(w, null, { method: 'GET', path: '/' }), 200);
  assert.match(page.headers.get('content-type'), /text\/html/);
  const csp = page.headers.get('content-security-policy');
  for (const d of ["default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"]) assert.ok(csp.includes(d), d);
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
  await status(call(w, null, { method: 'GET', path: '/api/mints', e: env({ DB: undefined }) }), 500);
  await status(call(w, null, { method: 'GET', path: '/api/mints', e: env({ DB: fakeDb(), RATE_LIMIT: { limit: async () => ({ success: false }) } }) }), 429);
});

test('dashboard requires a valid Cloudflare Access JWT when configured', async () => {
  const w = setup();
  const access = { ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com', ACCESS_AUD: 'aud-tag' };
  await status(call(w, null, { method: 'GET', path: '/', e: env(access) }), 401, 'access_required');
  for (const path of ['/api/mints', '/api/stats', '/api/policy', '/api/denials']) await status(call(w, null, { method: 'GET', path, e: env(access) }), 401, 'access_required');
  await status(call(w, null, { method: 'GET', path: '/', e: env(access), headers: { 'Cf-Access-Jwt-Assertion': 'garbage' } }), 401, 'access_required');
  await status(call(w, null, { method: 'GET', path: '/', e: env({ ACCESS_TEAM_DOMAIN: 'evil.example.com', ACCESS_AUD: 'a' }) }), 500);
  await status(call(w, null, { method: 'GET', path: '/', e: env() }), 200);
});

const demo = { repository: 'example/grants-demo', ref: 'refs/heads/main' };
const demoJwt = (over = {}) => jwt({ extra: demo, sub: 'repo:example/grants-demo:ref:refs/heads/main', ...over });
const sentPolicies = () => JSON.parse(cfCalls.at(-1).init.body).policies;

test('grants: names and zone names resolve to ids, split by scope, "*" nests under the account', async () => {
  const w = setup();
  const e = env();
  await status(call(w, await demoJwt(), { e }), 200);
  const [zone, account, allZones] = sentPolicies();
  assert.deepEqual(zone, { effect: 'allow', resources: { [`${ZONE}.${'e'.repeat(32)}`]: '*' }, permission_groups: [{ id: 'b'.repeat(32) }, { id: 'a'.repeat(32) }] });
  assert.deepEqual(account, { effect: 'allow', resources: { [`${ACCOUNT}.acc`]: '*' }, permission_groups: [{ id: 'c'.repeat(32) }] });
  assert.deepEqual(allZones, { effect: 'allow', resources: { [`${ACCOUNT}.acc`]: { [`${ZONE}.*`]: '*' } }, permission_groups: [{ id: 'd'.repeat(32) }] });
  // The audit log keeps the readable grants, not ids.
  const granted = JSON.parse(e.DB.mintInserts[0][1][7]);
  assert.deepEqual(granted[0], { permissions: ['DNS Read', 'DNS Write'], zones: ['example.com'] });
});

test('grants: a name that exists in both scopes resolves per grant scope; lookups are cached', async () => {
  const p = structuredClone(policy);
  p.rules.find((r) => r.id === 'grants-demo').grants = [{ permissions: ['Shared Perm'] }, { permissions: ['Shared Perm'], zones: ['example.com'] }];
  const w = setup(p);
  await status(call(w, await demoJwt()), 200);
  const [account, zone] = sentPolicies();
  assert.equal(account.permission_groups[0].id, '1'.repeat(32));
  assert.equal(zone.permission_groups[0].id, '2'.repeat(32));
  cfCalls.length = 0;
  await status(call(w, await demoJwt()), 200);
  assert.equal(cfCalls.filter((c) => c.url.includes('/zones?') || c.url.endsWith('/permission_groups')).length, 0);
});

test('grants: unknown zone or permission fails closed with a generic error', async () => {
  const p = structuredClone(policy);
  const r = p.rules.find((x) => x.id === 'grants-demo');
  r.grants = [{ permissions: ['DNS Read'], zones: ['nope.example'] }];
  await status(call(setup(p), await demoJwt()), 500, 'unknown_zone');
  r.grants = [{ permissions: ['No Such Permission'] }];
  await status(call(setup(p), await demoJwt()), 500, 'unknown_permission_group');
  // A zone-only permission asked for at account scope is not found either.
  r.grants = [{ permissions: ['DNS Read'] }];
  await status(call(setup(p), await demoJwt()), 500, 'unknown_permission_group');
});

test('narrowing: a caller can ask for fewer permissions, never more', async () => {
  const w = setup();
  const e = env();
  await status(call(w, await demoJwt(), { e, body: JSON.stringify({ permissions: ['DNS Read'] }) }), 200);
  assert.deepEqual(sentPolicies(), [{ effect: 'allow', resources: { [`${ZONE}.${'e'.repeat(32)}`]: '*' }, permission_groups: [{ id: 'b'.repeat(32) }] }]);
  assert.deepEqual(JSON.parse(e.DB.mintInserts[0][1][7]), [{ permissions: ['DNS Read'], zones: ['example.com'] }]);

  cfCalls.length = 0;
  const denyDb = fakeDb();
  await status(call(w, await demoJwt(), { e: env({ DB: denyDb }), body: JSON.stringify({ permissions: ['DNS Read', 'Zone Write'] }) }), 403, 'permission_not_allowed');
  assert.equal(cfCalls.filter((c) => c.init?.method === 'POST').length, 0);
  assert.equal(denyDb.denialInserts[0][1], 'permission_not_allowed');

  // Raw-policy rules cannot be narrowed; malformed requests are rejected before anything is minted.
  await status(call(w, await jwt(), { body: JSON.stringify({ permissions: ['DNS Write'] }) }), 400, 'narrowing_unsupported');
  for (const bad of [[], [1], 'DNS Read', [''], Array(33).fill('x')]) {
    await status(call(w, await demoJwt(), { body: JSON.stringify({ permissions: bad }) }), 400, 'invalid_permissions');
  }
});

test('denials: recorded only after the JWT is verified', async () => {
  const w = setup();
  const db = fakeDb();
  const e = env({ DB: db });
  const badSub = 'repo:example/terraform-cf:ref:refs/heads/dev';
  await status(call(w, await jwt({ sub: badSub, extra: { ...claims, ref: 'refs/heads/dev' } }), { e }), 403, 'no_matching_rule');
  assert.equal(db.denialInserts.length, 1);
  const [ts, reason, code, sub, repository] = db.denialInserts[0];
  assert.ok(Math.abs(ts - Date.now() / 1000) < 5);
  assert.deepEqual([reason, code, sub, repository], ['no_matching_rule', 403, badSub, 'example/terraform-cf']);
  await status(call(w, null, { e }), 401, 'auth_header_missing');
  await status(call(w, 'garbage', { e }), 401, 'token_invalid');
  await status(call(w, await jwt({ key: other.privateKey }), { e }), 401, 'token_invalid');
  assert.equal(db.denialInserts.length, 1);
  // A failing denial write never changes the response.
  const broken = fakeDb();
  broken.batch = async () => { throw new Error('d1 down'); };
  await status(call(w, await jwt({ sub: badSub, extra: { ...claims, ref: 'refs/heads/dev' } }), { e: env({ DB: broken }) }), 403, 'no_matching_rule');
});

test('dashboard api: stats, denials and policy', async () => {
  const w = setup();
  const results = (r) => ({ results: r });
  const statsDb = {
    prepare: () => ({ bind() { return this; } }),
    batch: async () => [results([{ n: 7 }]), results([{ n: 2 }]), results([{ n: 1 }]), results([{ n: 3 }]), results([{ hour: 10, n: 4 }])]
  };
  const s = await (await status(call(w, null, { method: 'GET', path: '/api/stats', e: env({ DB: statsDb }) }), 200)).json();
  assert.deepEqual([s.minted_24h, s.active, s.revoked_24h, s.denied_24h], [7, 2, 1, 3]);
  assert.deepEqual(s.hourly, [{ hour: 36000, n: 4 }]);

  const d = await (await status(call(w, null, { method: 'GET', path: '/api/denials', e: env({ DB: fakeDb([{ id: 1, reason: 'no_matching_rule' }]) }) }), 200)).json();
  assert.equal(d.denials[0].reason, 'no_matching_rule');

  const pol = await (await status(call(w, null, { method: 'GET', path: '/api/policy' }), 200)).json();
  assert.deepEqual(pol.rules.map((r) => r.id), policy.rules.map((r) => r.id));
  const demoRule = pol.rules.find((r) => r.id === 'grants-demo');
  assert.deepEqual(demoRule.grants[0], { permissions: ['DNS Read', 'DNS Write'], zones: ['example.com'] });
  assert.equal(pol.rules.find((r) => r.id === 'terraform-cf-main-dns').raw_policies, 1);
  await status(call(w, null, { method: 'GET', path: '/api/stats', e: env({ DB: undefined }) }), 500);
});

test('cleanup: deletes only expired, well-formed sts/* tokens', async () => {
  const w = createWorker(policy);
  const hex = (c) => c.repeat(32);
  const name = 'sts/rule/abcdef012345/1700000000000';
  const tokens = [
    { id: hex('b'), name, status: 'expired', expires_on: '2020-01-01T00:00:00Z' }, // deletable
    { id: hex('c'), name, status: 'active', expires_on: '2099-01-01T00:00:00Z' },
    { id: hex('d'), name: 'other-token', status: 'expired', expires_on: '2020-01-01T00:00:00Z' },
    { id: hex('e'), name: 'sts/rule/abcdef012345/1700000000000/x', status: 'expired', expires_on: '2020-01-01T00:00:00Z' },
    { id: hex('f'), name, status: 'expired', expires_on: new Date(Date.now() - 60000).toISOString() }, // inside grace
    { id: hex('1'), name, status: 'expired', expires_on: 'garbage' },
    { id: hex('2'), name, status: 'disabled', expires_on: '2020-01-01T00:00:00Z' },
    // Hard prefix check: must start with lowercase "sts/" (not Sts/, not embedded)
    { id: hex('3'), name: 'Sts/rule/abcdef012345/1700000000000', status: 'expired', expires_on: '2020-01-01T00:00:00Z' },
    { id: hex('4'), name: 'prefix-sts/rule/abcdef012345/1700000000000', status: 'expired', expires_on: '2020-01-01T00:00:00Z' }
  ];
  const saved = globalThis.fetch;
  const deleted = [];
  globalThis.fetch = async (url, init) => {
    url = String(url);
    if (init?.method === 'DELETE') { deleted.push(url.split('/').pop()); return json({ success: true, result: { id: 'x' } }); }
    if (url.includes('include_expired=true') && url.includes('page=')) return json({ success: true, result: tokens });
    if (url.includes('?page=')) return json({ success: true, result: [] }); // expired omitted without include_expired
    return json({ success: true, result: tokens.find((t) => url.endsWith(t.id)) });
  };
  const env = { CF_ACCOUNT_ID: 'a'.repeat(32), CF_PARENT_TOKEN: { get: async () => 'p' } };
  try {
    assert.deepEqual(await w.cleanupExpired(env), { scanned: 9, found: 1, deleted: 1, skipped: 0, dry_run: false });
    assert.deepEqual(deleted, [hex('b')]);
    deleted.length = 0;
    assert.equal((await w.cleanupExpired({ ...env, CLEANUP_DRY_RUN: 'true' })).deleted, 0);
    assert.deepEqual(deleted, []);
    const r = await status(call(w, null, { method: 'GET', path: '/api/cleanup' }), 200);
    assert.equal((await r.json()).total, 1);
    const run = await status(call(w, null, { method: 'POST', path: '/api/cleanup' }), 200);
    assert.deepEqual(await run.json(), { scanned: 9, found: 1, deleted: 1, skipped: 0, dry_run: false });
    assert.deepEqual(deleted, [hex('b')]);
  } finally { globalThis.fetch = saved; }
});

test('cleanup trend: counters only; run records one hourly upsert', async () => {
  const w = createWorker(policy);
  const seen = [];
  const db = {
    prepare: (sql) => ({ sql, args: [], bind(...a) { this.args = a; return this; } }),
    batch: async (stmts) => {
      seen.push(...stmts.map((s) => s.sql));
      return /FROM mints/.test(stmts[0].sql) ? [{ results: [{ b: 10, n: 4 }] }, { results: [{ b: 10, n: 3 }] }] : [];
    }
  };
  const r = await (await status(call(w, null, { method: 'GET', path: '/api/cleanup/trend?days=1', e: env({ DB: db }) }), 200)).json();
  assert.deepEqual([r.minted_total, r.deleted_total, r.bucket], [4, 3, 3600]);
  assert.deepEqual(r.deleted, [{ t: 36000, n: 3 }]);
  assert.equal((await (await status(call(w, null, { method: 'GET', path: '/api/cleanup/trend?days=999', e: env({ DB: db }) }), 200)).json()).days, 1);

  seen.length = 0;
  const hex = 'b'.repeat(32), name = 'sts/rule/abcdef012345/1700000000000';
  const saved = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    url = String(url);
    if (init?.method === 'DELETE') return json({ success: true, result: { id: 'x' } });
    if (url.includes('?page=')) return json({ success: true, result: [{ id: hex, name, status: 'expired', expires_on: '2020-01-01T00:00:00Z' }] });
    return json({ success: true, result: { id: hex, name, status: 'expired', expires_on: '2020-01-01T00:00:00Z' } });
  };
  try {
    await w.cleanupExpired({ CF_ACCOUNT_ID: 'a'.repeat(32), CF_PARENT_TOKEN: { get: async () => 'p' }, DB: db });
  } finally { globalThis.fetch = saved; }
  assert.equal(seen.filter((q) => /INSERT INTO cleanup_stats/.test(q)).length, 1);
});
