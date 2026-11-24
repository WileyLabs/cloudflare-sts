// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

const anyOf = (v) => [].concat(v);
const SPIFFE_ID = /^spiffe:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$/;

/** SPIRE JWT-SVID — identity is JWT `sub` (spiffe://…). Path globs allowed. */
export const spiffe = {
  type: 'spiffe',
  requireJti: false,
  identityClaim: 'sub',

  validateRule(rule, at, ensure) {
    const principals = anyOf(rule.principal);
    ensure(principals.length > 0, `${at}: principal required`);
    for (const p of principals) {
      ensure(typeof p === 'string' && p.startsWith('spiffe://'), `${at}: spiffe principal must start with spiffe://`);
      ensure(p !== '*' && p !== 'spiffe://*', `${at}: bare spiffe wildcard`);
      if (!p.includes('*')) ensure(SPIFFE_ID.test(p), `${at}: invalid spiffe id`);
    }
  },

  async afterVerify(claims, ensureHttp) {
    ensureHttp(typeof claims.sub === 'string' && SPIFFE_ID.test(claims.sub), 401, 'token_invalid');
    return claims;
  }
};
