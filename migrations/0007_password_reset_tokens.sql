-- Password-reset tokens for managers. A row is created when "forgot
-- password" is requested and consumed (or left to expire) shortly after —
-- see requestPasswordReset()/resetPassword() in src/worker.js. This table
-- should always stay small.
CREATE TABLE password_reset_tokens (
  token TEXT PRIMARY KEY,
  manager_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE INDEX idx_password_reset_tokens_manager ON password_reset_tokens(manager_id);
