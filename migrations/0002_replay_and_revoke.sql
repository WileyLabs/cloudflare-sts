-- Single-use OIDC JWTs: one row per exchanged JWT (issuer:jti), pruned once the JWT has expired.
CREATE TABLE IF NOT EXISTS used_jti (
  jti        TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL      -- unix seconds
);
CREATE INDEX IF NOT EXISTS used_jti_expires_at ON used_jti (expires_at);

-- Set when the minted token is revoked through POST /revoke.
ALTER TABLE mints ADD COLUMN revoked_at INTEGER;
