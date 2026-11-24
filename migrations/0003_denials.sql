-- Authenticated denials (JWT verified, then refused): no matching rule, replay, narrowing refused, rate limited...
-- Unauthenticated noise is not stored, so this table cannot be filled by anyone without a valid OIDC token.
CREATE TABLE IF NOT EXISTS denials (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,     -- unix seconds
  reason     TEXT NOT NULL,        -- error code returned to the caller
  status     INTEGER NOT NULL,
  sub        TEXT,
  repository TEXT,
  ray        TEXT,
  ip         TEXT
);
CREATE INDEX IF NOT EXISTS denials_ts ON denials (ts DESC);
