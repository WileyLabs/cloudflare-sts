// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createWorker } from '../src/index.js';
import { validatePolicy } from '../src/policy.js';
import { buildIssuerMap, handlerFor } from '../src/issuers/index.js';
import { inferType, normalizeIssuerEntry, replayKey } from '../src/issuers/common.js';
import fixture from './fixture-policy.json' with { type: 'json' };

const aud = fixture.audience;
const { publicKey, privateKey } = await generateKeyPair('RS256');
const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };

const GCP_ISS = 'https://accounts.google.com';
const GCP_JWKS = 'https://www.googleapis.com/oauth2/v3/certs';
const SPIFFE_ISS = 'https://oidc-discovery.example.com';
const SPIFFE_JWKS = 'https://oidc-discovery.example.com/keys';
const AWS_ISS = 'https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE';
const AWS_JWKS = 'https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE/keys';

const multiPolicy = () => {
  const p = structuredClone(fixture);
  p.issuers = {
    ...p.issuers,
    [GCP_ISS]: { type: 'gcp', jwks: GCP_JWKS },
    'accounts.google.com': { type: 'gcp', jwks: GCP_JWKS },
    [SPIFFE_ISS]: { type: 'spiffe', jwks: SPIFFE_JWKS },
    [AWS_ISS]: { type: 'aws', jwks: AWS_JWKS }
  };
  p.rules.push(
    {
      id: 'gcp-sa-dns',
      issuer: GCP_ISS,
      principal: 'cf-lists-manager@example-infra.iam.gserviceaccount.com',
      max_ttl_seconds: 600,
      grants: [{ permissions: ['DNS Read'], zones: ['example.com'] }]
    },
    {
      id: 'spiffe-helper-dns',
      issuer: SPIFFE_ISS,
      principal: 'spiffe://example.com/x509pop-agent/*/spiffe-helper',
      max_ttl_seconds: 600,
      grants: [{ permissions: ['DNS Read'], zones: ['example.com'] }]
    },
    {
      id: 'aws-eks-dns',
      issuer: AWS_ISS,
      principal: 'system:serviceaccount:default:cf-sts-client',
      max_ttl_seconds: 600,
      grants: [{ permissions: ['DNS Read'], zones: ['example.com'] }]
    }
  );
  return p;
};

const jwksByUrl = {
  [fixture.issuers['https://token.actions.githubusercontent.com']]: jwk,
  [GCP_JWKS]: jwk,
  [SPIFFE_JWKS]: jwk,
  [AWS_JWKS]: jwk
};

const ACCOUNT = 'com.cloudflare.api.account';
const ZONE = 'com.cloudflare.api.account.zone';
const good = { id: 'a'.repeat(32), value: 'secret-value', expires_on: '2030-01-01T00:00:00Z' };
let cfCalls;
globalThis.fetch = async (url) => {
  url = String(url);
  if (jwksByUrl[url]) return new Response(JSON.stringify({ keys: [jwksByUrl[url]] }));
  cfCalls.push(url);
  if (url.includes('/zones?name=')) return new Response(JSON.stringify({ success: true, result: [{ id: 'e'.repeat(32) }] }));
  if (url.endsWith('/permission_groups')) {
    return new Response(
      JSON.stringify({
        success: true,
        result: [
          { id: 'b'.repeat(32), name: 'DNS Read', scopes: [ZONE] },
          { id: 'c'.repeat(32), name: 'Account Settings Read', scopes: [ACCOUNT] }
        ]
      })
    );
  }
  return new Response(JSON.stringify({ success: true, result: good }));
};

const fakeDb = () => {
  const db = {
    jti: new Set(),
    prepare: (sql) => ({ sql, args: [], bind(...a) { this.args = a; return this; }, all: async () => ({ results: [] }), run: async () => {} }),
    batch: async (stmts) => {
      for (const s of stmts) {
        if (/INSERT INTO used_jti/.test(s.sql)) {
          if (db.jti.has(s.args[0])) throw new Error('D1_ERROR: UNIQUE constraint failed: used_jti.jti');
          db.jti.add(s.args[0]);
        }
      }
    }
  };
  return db;
};
const env = () => ({
  CF_ACCOUNT_ID: 'acc',
  CF_PARENT_TOKEN: { get: async () => 'PARENT' },
  RATE_LIMIT: { limit: async () => ({ success: true }) },
  DB: fakeDb()
});

const sign = async ({ issuer, sub, extra = {}, jti, alg = 'RS256', omitIss = false } = {}) => {
  let j = new SignJWT({ ...extra })
    .setProtectedHeader({ alg, kid: 'k1' })
    .setIssuedAt()
    .setAudience(aud)
    .setExpirationTime('5m')
    .setSubject(sub);
  if (!omitIss) j = j.setIssuer(issuer);
  if (jti !== null && jti !== undefined) j = j.setJti(jti);
  else if (jti === undefined) j = j.setJti(crypto.randomUUID());
  return j.sign(privateKey);
};

const call = (w, token, e = env()) =>
  w.fetch(new Request('https://x/token', { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: '{}' }), e);

test('inferType and normalizeIssuerEntry', () => {
  assert.equal(inferType('https://token.actions.githubusercontent.com'), 'github');
  assert.equal(inferType('https://accounts.google.com'), 'gcp');
  assert.equal(inferType('https://oidc-discovery.example.com'), 'spiffe');
  assert.equal(inferType(AWS_ISS), 'aws');
  const e = normalizeIssuerEntry(GCP_ISS, { type: 'gcp', jwks: GCP_JWKS, algorithms: ['RS256'] });
  assert.equal(e.type, 'gcp');
  assert.deepEqual(e.algorithms, ['RS256']);
});

test('handler principal validators', () => {
  const ensure = (c, m) => {
    if (!c) throw new Error(m);
  };
  assert.doesNotThrow(() => handlerFor('gcp').validateRule({ principal: 'a@p.iam.gserviceaccount.com' }, 'r', ensure));
  assert.throws(() => handlerFor('gcp').validateRule({ principal: 'a@*' }, 'r', ensure));
  assert.throws(() => handlerFor('gcp').validateRule({ principal: 'user@gmail.com' }, 'r', ensure));
  assert.doesNotThrow(() =>
    handlerFor('spiffe').validateRule({ principal: 'spiffe://example.com/x509pop-agent/*/spiffe-helper' }, 'r', ensure)
  );
  assert.throws(() => handlerFor('spiffe').validateRule({ principal: '*' }, 'r', ensure));
  assert.throws(() => handlerFor('aws').validateRule({ principal: 'system:*' }, 'r', ensure));
  assert.doesNotThrow(() => handlerFor('aws').validateRule({ principal: 'system:serviceaccount:ns:sa' }, 'r', ensure));
});

test('multi-issuer policy validates', () => {
  assert.doesNotThrow(() => validatePolicy(multiPolicy()));
  assert.equal(buildIssuerMap(multiPolicy().issuers).get(GCP_ISS).type, 'gcp');
});

test('GCP SA JWT mints; missing email_verified rejected; no jti uses sha256 replay', async () => {
  cfCalls = [];
  const w = createWorker(multiPolicy());
  const e = env();
  const email = 'cf-lists-manager@example-infra.iam.gserviceaccount.com';
  const bad = await sign({ issuer: GCP_ISS, sub: '123', extra: { email, email_verified: false }, jti: null });
  assert.equal((await call(w, bad, e)).status, 401);

  const token = await sign({ issuer: GCP_ISS, sub: '123', extra: { email, email_verified: true }, jti: null });
  const r = await call(w, token, e);
  assert.equal(r.status, 200);
  assert.equal((await r.json()).rule, 'gcp-sa-dns');

  // Replay via sha256(header.payload) — same JWT without jti, same D1
  assert.equal((await call(w, token, e)).status, 401);
  const key = await replayKey(GCP_ISS, { exp: 1 }, token);
  assert.match(key, /^https:\/\/accounts\.google\.com:sha256:[0-9a-f]{64}$/);

  // Equivalent ES256 signature variant (different sig, same header.payload) shares replay key
  const [h, p] = token.split('.');
  const twin = `${h}.${p}.ZmFrZS1zaWctdmFyaWFudA`;
  assert.equal(await replayKey(GCP_ISS, { exp: 1 }, twin), key);
});

test('SPIFFE JWT-SVID mints on sub glob; non-spiffe sub rejected', async () => {
  cfCalls = [];
  const w = createWorker(multiPolicy());
  const bad = await sign({ issuer: SPIFFE_ISS, sub: 'not-a-spiffe-id', jti: null });
  assert.equal((await call(w, bad)).status, 401);

  const sub = 'spiffe://example.com/x509pop-agent/tools-5/spiffe-helper';
  const token = await sign({ issuer: SPIFFE_ISS, sub, jti: null });
  const r = await call(w, token);
  assert.equal(r.status, 200);
  assert.equal((await r.json()).rule, 'spiffe-helper-dns');

  // JWT-SVIDs may omit iss — bind via trust domain in sub
  const noIss = await sign({ issuer: SPIFFE_ISS, sub, jti: null, omitIss: true });
  assert.equal((await call(w, noIss)).status, 200);
});

test('AWS EKS OIDC mints on exact sub', async () => {
  cfCalls = [];
  const w = createWorker(multiPolicy());
  const sub = 'system:serviceaccount:default:cf-sts-client';
  const token = await sign({ issuer: AWS_ISS, sub, jti: null });
  const r = await call(w, token);
  assert.equal(r.status, 200);
  assert.equal((await r.json()).rule, 'aws-eks-dns');

  const other = await sign({ issuer: AWS_ISS, sub: 'system:serviceaccount:default:other', jti: null });
  assert.equal((await call(w, other)).status, 403);
});

test('GCP WIF principal:// email is accepted by policy validator', () => {
  const p = multiPolicy();
  p.rules.push({
    id: 'wif',
    issuer: GCP_ISS,
    principal:
      'principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/spiffe-oidc-pool/subject/spiffe://example.com/x509pop-agent/h/spiffe-helper',
    max_ttl_seconds: 600,
    grants: [{ permissions: ['DNS Read'], zones: ['example.com'] }]
  });
  assert.doesNotThrow(() => validatePolicy(p));
});

test('GCP default compute/appspot SA emails are valid principals', () => {
  const p = multiPolicy();
  for (const [id, principal] of [
    ['compute', '123456789012-compute@developer.gserviceaccount.com'],
    ['appspot', 'my-project@appspot.gserviceaccount.com']
  ]) {
    p.rules.push({
      id,
      issuer: GCP_ISS,
      principal,
      max_ttl_seconds: 600,
      grants: [{ permissions: ['DNS Read'], zones: ['example.com'] }]
    });
  }
  assert.doesNotThrow(() => validatePolicy(p));
});
