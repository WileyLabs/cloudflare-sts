// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { parsePolicyPath, POLICY_ROOT, buildPolicyBundle } from '../scripts/lib/policy-tree.mjs';

test('parsePolicyPath: resource and resource/principal shapes', () => {
  const res = parsePolicyPath(join(POLICY_ROOT, 'github/example/example-app/policy.yaml'));
  assert.deepEqual(
    { provider: res.provider, account: res.account, resource: res.resource, principal: res.principal },
    { provider: 'github', account: 'example', resource: 'example-app', principal: null }
  );
  const prin = parsePolicyPath(
    join(POLICY_ROOT, 'github/example/cloudflare-sts/environment-production/policy.yaml')
  );
  assert.equal(prin.resource, 'cloudflare-sts');
  assert.equal(prin.principal, 'environment-production');
});

test('parsePolicyPath: rejects team-style 3-segment leaves and deep trees', () => {
  assert.throws(() => parsePolicyPath(join(POLICY_ROOT, 'github/example/policy.yaml')), /must be policy/);
  assert.throws(
    () => parsePolicyPath(join(POLICY_ROOT, 'github/a/b/c/d/policy.yaml')),
    /must be policy/
  );
});

test('buildPolicyBundle sources use resource[/principal]', () => {
  const { _meta } = buildPolicyBundle();
  assert.ok(_meta.sources.length >= 2);
  assert.ok(_meta.sources.every((s) => s.resource && !('team' in s)));
  const paths = new Set(_meta.sources.map((s) => s.path));
  assert.ok(paths.has('github/example/cloudflare-sts/environment-production/policy.yaml'));
  assert.ok(paths.has('github/example/example-app/policy.yaml'));
});
