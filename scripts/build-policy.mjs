#!/usr/bin/env node

// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// Walk policy/<provider>/<account>/<resource>[/<principal>]/policy.yaml → policy.bundle.json
import { writeFileSync } from 'node:fs';
import { buildPolicyBundle, BUNDLE_PATH } from './lib/policy-tree.mjs';
import { validatePolicy } from '../src/policy.js';

const check = process.argv.includes('--check');

try {
  const bundle = buildPolicyBundle();
  // Strip _source / _meta before Worker semantic validation (runtime fields).
  const forWorker = {
    audience: bundle.audience,
    issuers: bundle.issuers,
    profiles: bundle.profiles,
    rules: bundle.rules.map(({ _source, ...r }) => r)
  };
  validatePolicy(forWorker);

  const json = JSON.stringify(bundle, null, 2) + '\n';
  if (check) {
    const { readFileSync } = await import('node:fs');
    let existing = '';
    try {
      existing = readFileSync(BUNDLE_PATH, 'utf8');
    } catch {
      console.error('policy.bundle.json missing — run npm run build:policy');
      process.exit(1);
    }
    if (existing !== json) {
      console.error('policy.bundle.json is stale — run npm run build:policy');
      process.exit(1);
    }
    console.log(`policy.bundle.json up to date (${forWorker.rules.length} rules)`);
    process.exit(0);
  }

  writeFileSync(BUNDLE_PATH, json);
  console.log(
    `wrote policy.bundle.json (${forWorker.rules.length} rules from ${bundle._meta.sources.length} policy files)`
  );
} catch (e) {
  console.error(e.message || e);
  process.exit(1);
}
