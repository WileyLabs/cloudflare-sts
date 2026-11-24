// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import Ajv2020 from 'ajv/dist/2020.js';

export const POLICY_ROOT = fileURLToPath(new URL('../../policy/', import.meta.url));
export const BUNDLE_PATH = fileURLToPath(new URL('../../policy.bundle.json', import.meta.url));

const ajv = new Ajv2020({ allErrors: true, strict: false });
const loadSchema = (name) => JSON.parse(readFileSync(join(POLICY_ROOT, 'schema', name), 'utf8'));
const validateConfig = ajv.compile(loadSchema('config.schema.json'));
const validateIssuers = ajv.compile(loadSchema('issuers.schema.json'));
const validateProfiles = ajv.compile(loadSchema('profiles.schema.json'));
const validateResourcePolicy = ajv.compile(loadSchema('resource-policy.schema.json'));

function formatAjv(validate, label) {
  const errs = (validate.errors ?? []).map((e) => `${e.instancePath || '/'} ${e.message}`).join('; ');
  return `${label}: ${errs || 'invalid'}`;
}

export function readYaml(path) {
  return parseYaml(readFileSync(path, 'utf8'));
}

function walkPolicyYamls(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'schema') continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walkPolicyYamls(p, out);
    else if (name === 'policy.yaml') out.push(p);
  }
  return out;
}

/**
 * Path shapes (under policy/):
 *   <provider>/<account>/<resource>/policy.yaml
 *   <provider>/<account>/<resource>/<principal>/policy.yaml
 *
 * principal segment is a filesystem-safe slug (not necessarily the JWT principal string).
 */
export function parsePolicyPath(filePath) {
  const rel = relative(POLICY_ROOT, filePath);
  const parts = rel.split(sep);
  const leaf = parts[parts.length - 1];
  if (leaf !== 'policy.yaml' || (parts.length !== 4 && parts.length !== 5)) {
    throw new Error(
      `policy file must be policy/<provider>/<account>/<resource>[/<principal>]/policy.yaml (got ${rel})`
    );
  }
  const [provider, account, resource, maybePrincipal] = parts;
  const principal = parts.length === 5 ? maybePrincipal : null;
  for (const [label, v] of [
    ['provider', provider],
    ['account', account],
    ['resource', resource],
    ...(principal ? [['principal', principal]] : [])
  ]) {
    if (!/^[A-Za-z0-9._@-]{1,128}$/.test(v)) throw new Error(`bad ${label} segment "${v}" in ${rel}`);
  }
  return { provider, account, resource, principal, rel };
}

/** @deprecated use parsePolicyPath */
export const parseTeamPath = parsePolicyPath;

function expandIssuers(raw) {
  const flat = {};
  const byProvider = {};
  for (const [name, entry] of Object.entries(raw)) {
    if (entry.enabled === false) {
      byProvider[name] = { ...entry, disabled: true };
      continue;
    }
    const issList = [].concat(entry.iss);
    const normalized = {
      type: entry.type,
      jwks: entry.jwks,
      algorithms: entry.algorithms ?? ['RS256', 'ES256']
    };
    byProvider[name] = { ...normalized, iss: issList[0], aliases: issList };
    for (const iss of issList) {
      if (flat[iss]) throw new Error(`duplicate iss "${iss}" (from ${name} and earlier)`);
      flat[iss] = { type: normalized.type, jwks: normalized.jwks, algorithms: normalized.algorithms };
    }
  }
  return { flat, byProvider };
}

/** Resolve to every iss alias so findRule matches whichever form the JWT uses. */
function resolveIssuerList(ruleIssuer, provider, byProvider, flat) {
  const raw = ruleIssuer ?? provider;
  if (byProvider[raw]) {
    if (byProvider[raw].disabled) throw new Error(`issuer provider "${raw}" is disabled in issuers.yaml`);
    return byProvider[raw].aliases;
  }
  if (flat[raw]) return [raw];
  throw new Error(`unknown issuer "${raw}" (not a provider key or registered iss)`);
}

function aliasRuleId(baseId, iss, aliases) {
  if (aliases.length === 1) return baseId;
  const digest = createHash('sha256').update(`${baseId}\0${iss}`).digest('hex');
  const id = `${baseId}--${digest.slice(0, 8)}`;
  return id.length <= 64 ? id : `r-${digest.slice(0, 16)}`;
}

/**
 * Load + schema-validate the policy tree and return the Worker bundle
 * { audience, issuers, profiles, rules, _meta }.
 */
export function buildPolicyBundle() {
  const config = readYaml(join(POLICY_ROOT, 'config.yaml'));
  if (!validateConfig(config)) throw new Error(formatAjv(validateConfig, 'config.yaml'));

  const issuersRaw = readYaml(join(POLICY_ROOT, 'issuers.yaml'));
  if (!validateIssuers(issuersRaw)) throw new Error(formatAjv(validateIssuers, 'issuers.yaml'));

  const profiles = readYaml(join(POLICY_ROOT, 'profiles.yaml')) ?? {};
  if (!validateProfiles(profiles)) throw new Error(formatAjv(validateProfiles, 'profiles.yaml'));

  const { flat: issuers, byProvider } = expandIssuers(issuersRaw);
  if (!Object.keys(issuers).length) throw new Error('no enabled issuers in issuers.yaml');

  const files = walkPolicyYamls(POLICY_ROOT).sort();
  if (!files.length) {
    throw new Error('no policy/<provider>/<account>/<resource>[/<principal>]/policy.yaml files found');
  }

  const collected = [];
  const seenIds = new Set();
  const sources = [];

  for (const file of files) {
    const { provider, account, resource, principal: pathPrincipal, rel } = parsePolicyPath(file);
    if (!byProvider[provider]) throw new Error(`${rel}: provider "${provider}" not defined in issuers.yaml`);
    if (byProvider[provider].disabled) throw new Error(`${rel}: provider "${provider}" is disabled`);

    const doc = readYaml(file);
    if (!validateResourcePolicy(doc)) throw new Error(formatAjv(validateResourcePolicy, rel));

    sources.push({
      path: rel,
      provider,
      account,
      resource,
      principal: pathPrincipal,
      rule_ids: doc.rules.map((r) => r.id)
    });

    for (const rule of doc.rules) {
      const aliases = resolveIssuerList(rule.issuer, provider, byProvider, issuers);
      for (const issuer of aliases) {
        const id = aliasRuleId(rule.id, issuer, aliases);
        if (seenIds.has(id)) throw new Error(`duplicate rule id "${id}" (${rel})`);
        seenIds.add(id);
        collected.push({
          ...rule,
          id,
          issuer,
          _source: {
            provider,
            account,
            resource,
            principal: pathPrincipal,
            path: rel,
            base_id: rule.id,
            issuer_aliases: aliases
          }
        });
      }
    }
  }

  // One rule per identity path — no cross-file merge / overlap detection.
  const rules = collected.sort((a, b) => a.issuer.localeCompare(b.issuer) || a.id.localeCompare(b.id));

  return {
    audience: config.audience,
    issuers,
    profiles,
    rules,
    _meta: {
      generated_from: 'policy/',
      sources
    }
  };
}
