#!/usr/bin/env node

// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// Checks that every permission and zone name in the bundled policy exists in the Cloudflare account.
// Usage: CLOUDFLARE_API_TOKEN=<token able to list permission groups> npm run check:policy
import { readFileSync } from 'node:fs';
import { expandGrants } from '../src/policy.js';
import { BUNDLE_PATH } from './lib/policy-tree.mjs';

const policy = JSON.parse(readFileSync(BUNDLE_PATH, 'utf8'));
const account = (readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8').match(/CF_ACCOUNT_ID\s*=\s*"([0-9a-f]{32})"/) ?? [])[1];
const token = process.env.CLOUDFLARE_API_TOKEN;
if (!account || !token) {
  console.error('Need CF_ACCOUNT_ID in wrangler.toml and CLOUDFLARE_API_TOKEN in the environment');
  process.exit(2);
}

const api = async (path) => {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, { headers: { Authorization: `Bearer ${token}` } });
  const body = await res.json();
  if (!body.success) throw new Error(`${path}: ${JSON.stringify(body.errors)}`);
  return body.result;
};

const groups = await api(`/accounts/${account}/tokens/permission_groups`);
const names = (scope) => new Set(groups.filter((g) => g.scopes.includes(scope)).map((g) => g.name));
const known = { account: names('com.cloudflare.api.account'), zone: names('com.cloudflare.api.account.zone') };

const problems = [];
const zonesChecked = new Map();
for (const rule of policy.rules) {
  for (const grant of expandGrants(rule, policy.profiles)) {
    const scope = grant.zones ? 'zone' : 'account';
    for (const p of grant.permissions) if (!known[scope].has(p)) problems.push(`${rule.id}: "${p}" is not a ${scope}-scope permission group`);
    for (const z of (grant.zones ?? []).filter((x) => x !== '*')) {
      if (!zonesChecked.has(z)) zonesChecked.set(z, (await api(`/zones?name=${encodeURIComponent(z)}&account.id=${account}`)).length === 1);
      if (!zonesChecked.get(z)) problems.push(`${rule.id}: zone "${z}" not found in the account`);
    }
  }
}
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`policy OK: ${policy.rules.length} rules, all permission and zone names resolve`);
