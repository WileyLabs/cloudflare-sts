// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import test from 'node:test';
import assert from 'node:assert/strict';
import { expandGrants, findRule, glob, ttlFor, validatePolicy, validIpOrCidr } from '../src/policy.js';
import policy from './fixture-policy.json' with { type: 'json' };
import realBundle from '../policy.bundle.json' with { type: 'json' };
const realPolicy = {
  audience: realBundle.audience,
  issuers: realBundle.issuers,
  profiles: realBundle.profiles,
  rules: realBundle.rules.map(({ _source, ...r }) => r)
};

const iss = 'https://token.actions.githubusercontent.com';
const type = 'github';

const jwtClaims = (over = {}) => ({
  sub: 'repo:example/terraform-cf:ref:refs/heads/main',
  repository: 'example/terraform-cf',
  ref: 'refs/heads/main',
  job_workflow_ref: 'example/terraform-cf/.github/workflows/apply.yml@refs/heads/main',
  ...over
});

test('glob: exact, wildcard, multiple wildcards, anchoring, case', () => {
  assert.ok(glob('refs/heads/main', 'refs/heads/main'));
  assert.ok(!glob('refs/heads/main', 'refs/heads/main-evil'));
  assert.ok(!glob('refs/heads/main', 'x/refs/heads/main'));
  assert.ok(glob('a/*.yml', 'a/x.yml'));
  assert.ok(glob('a/*/b/*', 'a/x/b/y'));
  assert.ok(glob('*', 'anything'));
  assert.ok(!glob('Main', 'main'));
});

test('glob: regex specials are literal; empty and invalid inputs', () => {
  assert.ok(!glob('a.b', 'axb'));
  assert.ok(glob('a+b(c)[d]{e}^$|?', 'a+b(c)[d]{e}^$|?'));
  assert.ok(!glob('a|b', 'a'));
  assert.ok(glob('', ''));
  assert.ok(!glob('', 'x'));
  assert.ok(!glob(undefined, 'x'));
  assert.ok(!glob('x', undefined));
  assert.ok(!glob(1, '1'));
});

test('findRule: principal (sub) match + optional claims', () => {
  assert.ok(findRule(policy.rules, iss, jwtClaims(), type));
  assert.ok(!findRule(policy.rules, iss, jwtClaims({ sub: 'repo:example/other:ref:refs/heads/main' }), type));
  assert.ok(!findRule(policy.rules, 'https://evil.example', jwtClaims(), type));
  assert.ok(!findRule(policy.rules, iss, jwtClaims({ job_workflow_ref: 'example/terraform-cf/.github/workflows/apply.yml@refs/heads/dev' }), type));
  assert.ok(!findRule([{ issuer: iss, principal: 'repo:x:ref:refs/heads/main' }], iss, { sub: '' }, type));
});

test('ttlFor: bounds and invalid values', () => {
  const r = { max_ttl_seconds: 900 };
  assert.equal(ttlFor(r, 86400), 900);
  assert.equal(ttlFor(r, undefined), 900);
  assert.equal(ttlFor(r, 60), 60);
  assert.equal(ttlFor({ max_ttl_seconds: 60 }, undefined), 60);
  assert.equal(ttlFor({ max_ttl_seconds: 86400 }, 86400), 86400);
  for (const bad of [0, -5, 59, 86401, 1.5, '900', NaN, null]) assert.throws(() => ttlFor(r, bad), `requested ${bad}`);
  for (const bad of [undefined, 0, 59, 86401, '900', -1, 1.5]) assert.throws(() => ttlFor({ max_ttl_seconds: bad }, 60), `max ${bad}`);
});

test('validIpOrCidr', () => {
  for (const g of ['1.2.3.4', '10.0.0.0/8', '2001:db8::/32', '::1']) assert.ok(validIpOrCidr(g), g);
  for (const b of ['256.1.1.1', '1.2.3.4/33', '1.2.3', 'x', '1.2.3.4/8/8', '2001:db8::/129', '', 5]) assert.ok(!validIpOrCidr(b), String(b));
});

const clone = () => structuredClone(policy);
const bad = (fn) => {
  const p = clone();
  fn(p);
  assert.throws(() => validatePolicy(p), /policy:/);
};

test('real and fixture policies are valid', () => {
  assert.doesNotThrow(() => validatePolicy(policy));
  assert.doesNotThrow(() => validatePolicy(realPolicy));
});

test('malformed policies are rejected', () => {
  bad((p) => delete p.audience);
  bad((p) => (p.issuers = {}));
  bad((p) => (p.issuers[iss] = 'http://insecure.example/jwks'));
  bad((p) => (p.issuers[iss] = 'not a url'));
  bad((p) => (p.rules[0].issuer = 'https://unknown.example'));
  bad((p) => delete p.rules[0].principal);
  bad((p) => (p.rules[0].principal = 'not-a-repo-sub'));
  bad((p) => (p.rules[0].principal = 'repo:example/*:ref:refs/heads/main'));
  for (const t of [0, 59, 86401, 1.5, '900']) bad((p) => (p.rules[0].max_ttl_seconds = t));
  bad((p) => delete p.rules[0].max_ttl_seconds);
  bad((p) => (p.rules[0].policies = []));
  bad((p) => (p.rules[0].policies[0].effect = 'permit'));
  bad((p) => (p.rules[0].policies[0].effect = 'deny'));
  bad((p) => (p.rules[0].policies[0].permission_groups = []));
  bad((p) => (p.rules[0].policies[0].resources = {}));
  bad((p) => (p.rules[0].policies[0].resources = 'zone'));
  bad((p) => (p.rules[0].client_ips = ['999.1.1.1']));
  bad((p) => (p.rules[0].client_ips = []));
  bad((p) => p.rules.push(structuredClone(p.rules[0])));
  assert.throws(() => validatePolicy(null));
});

test('github principals must be exact repo: subjects', () => {
  bad((p) => (p.rules[0].principal = 'spiffe://x'));
  bad((p) => (p.rules[0].claims = { job_workflow_ref: '*' }));
});

test('findRule: principal list (OR) for second rule', () => {
  const other = {
    sub: 'repo:example/ip-pinned:ref:refs/heads/release',
    repository: 'example/ip-pinned',
    ref: 'refs/heads/release'
  };
  assert.equal(findRule(policy.rules, iss, other, type).id, 'pinned-ip-read');
  assert.ok(!findRule(policy.rules, iss, { ...other, sub: 'repo:example/ip-pinned:ref:refs/heads/dev' }, type));
});

test('production policy: deploy rule pins environment principal + workflow', () => {
  const r = realPolicy.rules.find((x) => x.id === 'cloudflare-sts-deploy');
  assert.ok(r);
  const principals = [].concat(r.principal);
  assert.ok(principals.includes('repo:example/cloudflare-sts:environment:production'));
  assert.ok(principals.includes('repo:example@00000000/cloudflare-sts@1111111111:environment:production'));
  assert.equal(r.claims.ref, 'refs/heads/main');
  assert.equal(r.claims.job_workflow_ref, 'example/cloudflare-sts/.github/workflows/cd.yml@refs/heads/main');
  assert.equal(r.claims.environment, 'production');
  assert.ok(r.max_ttl_seconds <= 900);
  const ok = {
    sub: 'repo:example/cloudflare-sts:environment:production',
    ...r.claims
  };
  assert.ok(findRule(realPolicy.rules, iss, ok, type));
  assert.ok(
    findRule(realPolicy.rules, iss, { ...ok, sub: 'repo:example@00000000/cloudflare-sts@1111111111:environment:production' }, type)
  );
  for (const badClaim of [{ ref: 'refs/pull/1/merge' }, { environment: 'staging' }, { job_workflow_ref: 'example/cloudflare-sts/.github/workflows/ci.yml@refs/heads/main' }]) {
    assert.ok(!findRule(realPolicy.rules, iss, { ...ok, ...badClaim }, type), JSON.stringify(badClaim));
  }
  // Deploy rule must not match a plain ref principal; CI usecase may.
  const refHit = findRule(realPolicy.rules, iss, { sub: 'repo:example/cloudflare-sts:ref:refs/heads/main', ...r.claims }, type);
  assert.notEqual(refHit?.id, 'cloudflare-sts-deploy');
  assert.equal(refHit?.id, 'cloudflare-sts-ci-usecase-github');
});

test('production policy: CI usecase rules for github / gcp / spiffe', () => {
  const gh = realPolicy.rules.find((x) => x.id === 'cloudflare-sts-ci-usecase-github');
  assert.ok(gh);
  assert.ok(findRule(realPolicy.rules, iss, { sub: 'repo:example/cloudflare-sts:pull_request' }, type));
  assert.ok(
    findRule(realPolicy.rules, iss, { sub: 'repo:example@00000000/cloudflare-sts@1111111111:pull_request' }, type)
  );
  const gcpIss = Object.keys(realPolicy.issuers).find((k) => realPolicy.issuers[k].type === 'gcp');
  const spiffeIss = Object.keys(realPolicy.issuers).find((k) => realPolicy.issuers[k].type === 'spiffe');
  assert.ok(
    findRule(realPolicy.rules, gcpIss, { email: 'sa-ci@example-project.iam.gserviceaccount.com' }, 'gcp')
  );
  assert.ok(
    findRule(realPolicy.rules, spiffeIss, { sub: 'spiffe://example.com/ns/arc-runners/sa/arc-runners' }, 'spiffe')
  );
});

test('grants and profiles: valid shapes and expansion', () => {
  const rule = policy.rules.find((r) => r.id === 'grants-demo');
  assert.deepEqual(expandGrants(rule, policy.profiles), [
    { permissions: ['DNS Read', 'DNS Write'], zones: ['example.com'] },
    { permissions: ['Account Settings Read'] },
    { permissions: ['Workers Routes Write'], zones: ['*'] }
  ]);
  assert.deepEqual(expandGrants({ grants: [{ permissions: ['A', 'A', 'B'] }] }), [{ permissions: ['A', 'B'] }]);
  assert.deepEqual(expandGrants({ policies: [] }), []);
});

test('grants and profiles: malformed definitions are rejected', () => {
  const g = (p) => p.rules.find((r) => r.id === 'grants-demo');
  bad((p) => (g(p).grants = []));
  bad((p) => (g(p).grants = 'x'));
  bad((p) => (g(p).grants[0] = { zones: ['example.com'] }));
  bad((p) => (g(p).grants[0] = { profile: 'dns', permissions: ['DNS Read'] }));
  bad((p) => (g(p).grants[0] = { profile: 'missing' }));
  bad((p) => (g(p).grants[0] = { permissions: [] }));
  bad((p) => (g(p).grants[0] = { permissions: ['DNS Read'], zones: [] }));
  bad((p) => (g(p).grants[0] = { permissions: ['DNS Read'], zones: ['bad zone!'] }));
  bad((p) => (g(p).grants[0] = { permissions: ['DNS Read'], zones: ['*', 'example.com'] }));
  bad((p) => (g(p).grants[0] = { permissions: ['DNS Read'], effect: 'deny' }));
  bad((p) => delete g(p).grants);
  bad((p) => (p.profiles = { 'bad name!': { permissions: ['x'] } }));
  bad((p) => (p.profiles = { dns: { permissions: [] } }));
  bad((p) => (p.profiles = 'x'));
});

test('a rule may combine grants with a raw deny policy', () => {
  const p = structuredClone(policy);
  const r = p.rules.find((x) => x.id === 'grants-demo');
  r.policies = [{ effect: 'deny', permission_groups: ['4755a26eedb94da69e1066d98aa820be'], resources: { 'com.cloudflare.api.account.zone.x': '*' } }];
  assert.doesNotThrow(() => validatePolicy(p));
});
