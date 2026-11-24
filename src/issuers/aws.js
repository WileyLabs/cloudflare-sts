// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

const anyOf = (v) => [].concat(v);

/**
 * AWS OIDC — identity is JWT `sub` (EKS SA subject, Cognito sub, etc.).
 * Use the ARN-like or SA subject string your IdP puts in `sub`.
 */
export const aws = {
  type: 'aws',
  requireJti: false,
  identityClaim: 'sub',

  validateRule(rule, at, ensure) {
    const principals = anyOf(rule.principal);
    ensure(principals.length > 0, `${at}: principal required`);
    ensure(
      principals.every((x) => typeof x === 'string' && x.length > 0 && !x.includes('*')),
      `${at}: aws principal must be exact (no *)`
    );
  },

  async afterVerify(claims, ensureHttp) {
    ensureHttp(typeof claims.sub === 'string' && claims.sub, 401, 'token_invalid');
    return claims;
  }
};
