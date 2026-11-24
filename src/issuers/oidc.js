// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

const anyOf = (v) => [].concat(v);

/** Generic OIDC — identity is JWT `sub`. */
export const oidc = {
  type: 'oidc',
  requireJti: false,
  identityClaim: 'sub',

  validateRule(rule, at, ensure) {
    const principals = anyOf(rule.principal);
    ensure(principals.length > 0, `${at}: principal required`);
    ensure(principals.every((x) => typeof x === 'string' && x !== '*'), `${at}: bare * principal`);
  },

  async afterVerify(claims) {
    return claims;
  }
};
