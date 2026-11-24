// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

const anyOf = (v) => [].concat(v);
const SPIFFE_ID = /^spiffe:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$/;
// User-managed SA + Google-managed defaults (compute / appspot).
const SA_EMAIL =
  /^[a-z0-9._-]+@(?:[a-z0-9-]+\.iam\.gserviceaccount\.com|developer\.gserviceaccount\.com|appspot\.gserviceaccount\.com)$/i;
const PRINCIPAL = /^principal:\/\//;

/**
 * Google ID tokens — identity is JWT `email` (SA or principal:// WIF).
 */
export const gcp = {
  type: 'gcp',
  requireJti: false,
  identityClaim: 'email',

  validateRule(rule, at, ensure) {
    const principals = anyOf(rule.principal);
    ensure(principals.length > 0, `${at}: principal required`);
    ensure(
      principals.every((x) => typeof x === 'string' && !x.includes('*') && (SA_EMAIL.test(x) || PRINCIPAL.test(x))),
      `${at}: gcp principal must be an exact SA email or principal:// URI`
    );
    ensure(rule.claims?.email_verified === undefined, `${at}: email_verified is enforced by the verifier, do not put it in claims`);
  },

  async afterVerify(claims, ensureHttp) {
    ensureHttp(claims.email_verified === true, 401, 'token_invalid');
    ensureHttp(typeof claims.email === 'string' && claims.email, 401, 'token_invalid');
    if (PRINCIPAL.test(claims.email) && claims.email.includes('/subject/')) {
      const spiffeId = claims.email.split('/subject/')[1];
      if (spiffeId && SPIFFE_ID.test(spiffeId)) claims = { ...claims, spiffe_id: spiffeId };
    }
    return claims;
  }
};
