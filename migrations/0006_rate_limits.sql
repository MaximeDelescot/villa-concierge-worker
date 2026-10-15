-- Small fixed-window counters used for abuse/flood protection on the
-- public guest chat endpoint (see bumpRateLimit()/checkRateLimit() in
-- src/worker.js). Rows are short-lived and pruned opportunistically by
-- the worker itself — this table should always stay small.
CREATE TABLE rate_limits (
  bucket_key TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_rate_limits_expires ON rate_limits(expires_at);
