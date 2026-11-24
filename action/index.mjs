// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// Runs twice (see action.yaml): the main step mints a token, the post step (end of job, always) revokes it.
import { appendFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const env = process.env;
const input = (name) => (env[`INPUT_${name.toUpperCase()}`] ?? '').trim();
const url = input('url').replace(/\/+$/, '');
const audience = input('audience');
const write = (file, name, value) => appendFileSync(file, `${name}=${value}\n`);

/**
 * Fresh OIDC JWT for each cf-sts call (mint and revoke are single-use).
 * - jwt-command set: run it (GCP gcloud print-identity-token, spire-agent, …)
 * - else: GitHub Actions OIDC for this job
 */
async function getJwt() {
  const cmd = input('jwt-command');
  if (cmd) {
    const out = execSync(cmd, {
      encoding: 'utf8',
      shell: '/bin/bash',
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe']
    }).trim();
    const jwt = out.split(/\s+/).find((t) => /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(t)) ?? out;
    if (!jwt || !jwt.includes('.')) throw new Error('jwt-command did not print a JWT');
    return jwt;
  }
  if (!env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    throw new Error("missing OIDC (add 'permissions: id-token: write', or set jwt-command)");
  }
  const oidc = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  oidc.searchParams.set('audience', audience);
  const { value: jwt } = await (
    await fetch(oidc, { headers: { Authorization: `bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } })
  ).json();
  if (!jwt) throw new Error('GitHub OIDC returned empty JWT');
  return jwt;
}

async function callStsApi(path, body) {
  const jwt = await getJwt();
  console.log(`::add-mask::${jwt}`);
  const res = await fetch(url + path, {
    method: 'POST',
    headers: { Authorization: `Bearer ${jwt}` },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30000)
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

if (!env.STATE_post) {
  // Main step. Mark the state first so the post step runs even if minting fails halfway.
  write(env.GITHUB_STATE, 'post', '1');
  try {
    const permissions = input('permissions').split(/[,\n]/).map((p) => p.trim()).filter(Boolean);
    const { status, body } = await callStsApi('/token', {
      ttl_seconds: Number(input('ttl-seconds')),
      ...(permissions.length && { permissions })
    });
    if (status !== 200) throw new Error(`mint failed: HTTP ${status} ${body.error ?? ''}`);
    console.log(`::add-mask::${body.token}`);
    write(env.GITHUB_STATE, 'token_id', body.id);
    for (const [name, value] of [
      ['token', body.token],
      ['token-id', body.id],
      ['expires-on', body.expires_on],
      ['rule', body.rule]
    ])
      write(env.GITHUB_OUTPUT, name, value);
    write(env.GITHUB_ENV, 'CLOUDFLARE_API_TOKEN', body.token);
    console.log(`cf-sts: minted rule=${body.rule} id=${body.id}`);
  } catch (e) {
    console.log(`::error::cf-sts: ${e.message}`);
    process.exitCode = 1;
  }
} else if (env.STATE_token_id) {
  // Post step. Never fails the job: the token expires on its own anyway.
  try {
    const { status, body } = await callStsApi('/revoke', { token_id: env.STATE_token_id });
    if (status !== 200 && status !== 404) throw new Error(`HTTP ${status} ${body.error ?? ''}`);
    console.log(`cf-sts: revoked token ${env.STATE_token_id}`);
  } catch (e) {
    console.log(`::warning::cf-sts: revoke failed: ${e.message} (the token will still expire on its own)`);
  }
}
