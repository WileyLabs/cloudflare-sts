CREATE TABLE IF NOT EXISTS mints (
  id          TEXT PRIMARY KEY,   -- Cloudflare token id (never the token value)
  rule_id     TEXT NOT NULL,
  description TEXT,
  sub         TEXT NOT NULL,
  repository  TEXT,
  actor       TEXT,
  issuer      TEXT NOT NULL,
  policies    TEXT NOT NULL,      -- JSON: permission groups + resources granted
  ttl         INTEGER NOT NULL,
  issued_at   INTEGER NOT NULL,   -- unix seconds
  expires_at  INTEGER NOT NULL,   -- unix seconds
  ray         TEXT,
  ip          TEXT
);
CREATE INDEX IF NOT EXISTS mints_issued_at ON mints (issued_at DESC);
