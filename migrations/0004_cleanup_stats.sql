-- Hourly counters for the cleanup cron (one row per hour in which something was deleted; never per token).
CREATE TABLE IF NOT EXISTS cleanup_stats (
  hour    INTEGER PRIMARY KEY,   -- unix seconds, start of the hour
  deleted INTEGER NOT NULL DEFAULT 0,
  runs    INTEGER NOT NULL DEFAULT 0
);
