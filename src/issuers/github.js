// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

const anyOf = (v) => [].concat(v);

/** GitHub Actions OIDC — identity is JWT `sub` (e.g. repo:org/repo:ref:…). */
export const github = {
  type: 'github',
  requireJti: true,
  identityClaim: 'sub',

  validateRule(rule, at, ensure) {
    const principals = anyOf(rule.principal);
    ensure(principals.length > 0, `${at}: principal required`);
    for (const p of principals) {
      ensure(typeof p === 'string' && p.startsWith('repo:'), `${at}: github principal must be a repo:… subject`);
      ensure(!p.includes('*'), `${at}: github principal must be exact (no *)`);
    }
    const claims = rule.claims ?? {};
    ensure(claims.email_verified === undefined, `${at}: unknown claim email_verified`);
    // Optional extras: prefer pinning workflow when granting write
    for (const [name, value] of Object.entries(claims)) {
      ensure(anyOf(value).every((x) => typeof x === 'string' && x.length > 0 && x !== '*'), `${at}: bare * claim ${name}`);
    }
  },

  async afterVerify(claims, ensureHttp) {
    ensureHttp(typeof claims.jti === 'string' && claims.jti, 401, 'token_invalid');
    return claims;
  }
};
