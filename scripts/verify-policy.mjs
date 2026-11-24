#!/usr/bin/env node

// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// Syntax (YAML) + JSON Schema + Worker semantic validation for the policy/ tree.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parseDocument } from 'yaml';
import { buildPolicyBundle, POLICY_ROOT, parsePolicyPath, readYaml } from './lib/policy-tree.mjs';
import { validatePolicy } from '../src/policy.js';

let failed = 0;
const ok = (msg) => console.log(`OK  ${msg}`);
const fail = (msg) => {
  console.error(`FAIL ${msg}`);
  failed++;
};

// 1) Every YAML file under policy/ must parse (no duplicate keys).
function walkYaml(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'schema') continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walkYaml(p, out);
    else if (/\.ya?ml$/i.test(name)) out.push(p);
  }
  return out;
}

for (const file of walkYaml(POLICY_ROOT)) {
  const rel = file.slice(POLICY_ROOT.length);
  try {
    const doc = parseDocument(readFileSync(file, 'utf8'), { uniqueKeys: true });
    if (doc.errors?.length) throw new Error(doc.errors.map((e) => e.message).join('; '));
    ok(`yaml ${rel}`);
  } catch (e) {
    fail(`yaml ${rel}: ${e.message}`);
  }
}

// 2) Path shape for resource[/principal] policies
try {
  const { readdirSync: rd, statSync: st } = await import('node:fs');
  const walk = (d, acc = []) => {
    for (const n of rd(d)) {
      if (n === 'schema') continue;
      const p = join(d, n);
      if (st(p).isDirectory()) walk(p, acc);
      else if (n === 'policy.yaml') acc.push(p);
    }
    return acc;
  };
  for (const f of walk(POLICY_ROOT)) {
    const { rel, provider, account, resource, principal } = parsePolicyPath(f);
    const leaf = principal ? `${provider}/${account}/${resource}/${principal}` : `${provider}/${account}/${resource}`;
    ok(`path ${rel} → ${leaf}`);
  }
} catch (e) {
  fail(`path: ${e.message}`);
}

// 3) Schema + semantic bundle
try {
  const bundle = buildPolicyBundle();
  const forWorker = {
    audience: bundle.audience,
    issuers: bundle.issuers,
    profiles: bundle.profiles,
    rules: bundle.rules.map(({ _source, ...r }) => r)
  };
  validatePolicy(forWorker);
  ok(`bundle ${forWorker.rules.length} rules, ${Object.keys(forWorker.issuers).length} issuers, ${Object.keys(forWorker.profiles).length} profiles`);
  for (const s of bundle._meta.sources) ok(`source ${s.path} [${s.rule_ids.join(', ')}]`);
} catch (e) {
  fail(`bundle: ${e.message}`);
}

// 4) Root files present
for (const f of ['config.yaml', 'issuers.yaml', 'profiles.yaml']) {
  try {
    readYaml(join(POLICY_ROOT, f));
    ok(`root ${f}`);
  } catch (e) {
    fail(`root ${f}: ${e.message}`);
  }
}

if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log('\npolicy verification passed');
