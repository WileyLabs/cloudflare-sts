// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// Run with: node --test action/test/cloudflare-sts.test.mjs
// Runs index.mjs as the runner would (main step, then post step with the saved state) against a fake OIDC + cf-sts server.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const script = join(import.meta.dirname, '..', 'index.mjs');
const ID = 'a'.repeat(32);
const calls = [];
let mintStatus = 200;
let revokeStatus = 200;

const server = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    const url = new URL(req.url, 'http://x');
    const send = (code, o) => (res.writeHead(code, { 'Content-Type': 'application/json' }), res.end(JSON.stringify(o)));
    if (url.pathname === '/oidc') return send(200, { value: `jwt.${url.searchParams.get('audience')}` });
    calls.push({ path: url.pathname, auth: req.headers.authorization, body: JSON.parse(raw || '{}') });
    if (url.pathname === '/token') return mintStatus === 200 ? send(200, { id: ID, token: 'SECRETTOKEN', expires_on: '2030-01-01T00:00:00Z', rule: 'r' }) : send(mintStatus, { error: 'no_matching_rule' });
    send(url.pathname === '/revoke' ? revokeStatus : 404, { error: 'x' });
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

// Async spawn: the fake server lives in this process, so the event loop must stay free.
function run(env = {}) {
  const d = mkdtempSync(join(tmpdir(), 'cfsts-'));
  const files = { GITHUB_OUTPUT: join(d, 'out'), GITHUB_ENV: join(d, 'env'), GITHUB_STATE: join(d, 'state') };
  for (const f of Object.values(files)) writeFileSync(f, '');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script], {
      env: { PATH: process.env.PATH, ...files, ACTIONS_ID_TOKEN_REQUEST_URL: `${base}/oidc?x=1`, ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'req', INPUT_URL: base, INPUT_AUDIENCE: 'cf-sts.test', 'INPUT_TTL-SECONDS': '300', ...env }
    });
    let stdout = '';
    child.stdout.on('data', (c) => (stdout += c));
    child.on('close', (status) => {
      const read = (f) => readFileSync(files[f], 'utf8');
      // The runner hands the saved state to the post step as STATE_<name>.
      const state = Object.fromEntries(read('GITHUB_STATE').split('\n').filter(Boolean).map((l) => [`STATE_${l.split('=')[0]}`, l.split('=')[1]]));
      resolve({ status, stdout, out: read('GITHUB_OUTPUT'), envFile: read('GITHUB_ENV'), state });
    });
  });
}
const reset = () => ((calls.length = 0), (mintStatus = 200), (revokeStatus = 200));

test('main mints, masks, sets outputs, exports the token and saves state', async () => {
  reset();
  const r = await run();
  assert.equal(r.status, 0, r.stdout);
  assert.ok(r.stdout.includes('::add-mask::SECRETTOKEN'));
  assert.ok(!r.stdout.replace('::add-mask::SECRETTOKEN', '').includes('SECRETTOKEN'));
  assert.match(r.out, /^token=SECRETTOKEN$/m);
  assert.match(r.out, new RegExp(`^token-id=${ID}$`, 'm'));
  assert.match(r.out, /^rule=r$/m);
  assert.equal(r.envFile, 'CLOUDFLARE_API_TOKEN=SECRETTOKEN\n');
  assert.deepEqual(r.state, { STATE_post: '1', STATE_token_id: ID });
  assert.deepEqual(calls, [{ path: '/token', auth: 'Bearer jwt.cf-sts.test', body: { ttl_seconds: 300 } }]);
});

test('permissions input is sent as a list (comma or newline separated); empty sends none', async () => {
  reset();
  await run({ INPUT_PERMISSIONS: 'DNS Read, DNS Write\nZone Read\n' });
  assert.deepEqual(calls[0].body, { ttl_seconds: 300, permissions: ['DNS Read', 'DNS Write', 'Zone Read'] });
  calls.length = 0;
  await run({ INPUT_PERMISSIONS: ' ' });
  assert.deepEqual(calls[0].body, { ttl_seconds: 300 });
});

test('post revokes the token saved by main', async () => {
  reset();
  const { state } = await run();
  calls.length = 0;
  const r = await run(state);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /revoked token/);
  assert.deepEqual(calls, [{ path: '/revoke', auth: 'Bearer jwt.cf-sts.test', body: { token_id: ID } }]);
});

test('failed mint reports the cf-sts error, and the post step then does nothing', async () => {
  reset();
  mintStatus = 403;
  const r = await run();
  assert.equal(r.status, 1);
  assert.match(r.stdout, /::error::cf-sts: mint failed: HTTP 403 no_matching_rule/);
  assert.equal(r.out, '');
  calls.length = 0;
  assert.equal((await run(r.state)).status, 0);
  assert.equal(calls.length, 0);
});

test('missing OIDC permission is explained', async () => {
  reset();
  const r = await run({ ACTIONS_ID_TOKEN_REQUEST_URL: '' });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /id-token: write|jwt-command/);
});

test('jwt-command supplies the JWT for mint and post revoke', async () => {
  reset();
  const cmd = `printf '%s' 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0In0.sig'`;
  const r = await run({
    ACTIONS_ID_TOKEN_REQUEST_URL: '',
    'INPUT_JWT-COMMAND': cmd
  });
  assert.equal(r.status, 0, r.stdout);
  assert.equal(calls[0].auth, 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0In0.sig');
  calls.length = 0;
  const post = await run({ ...r.state, ACTIONS_ID_TOKEN_REQUEST_URL: '', 'INPUT_JWT-COMMAND': cmd });
  assert.equal(post.status, 0, post.stdout);
  assert.equal(calls[0].path, '/revoke');
  assert.equal(calls[0].auth, 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0In0.sig');
});

test('post never fails the job', async () => {
  reset();
  const { state } = await run();
  revokeStatus = 404;
  assert.equal((await run(state)).status, 0);
  revokeStatus = 502;
  let r = await run(state);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /::warning::.*HTTP 502/);
  r = await run({ ...state, INPUT_URL: 'http://127.0.0.1:1' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /::warning::/);
});
