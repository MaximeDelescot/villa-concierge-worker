-- Manager accounts (multi-tenant auth) — replaces the single shared
-- MANAGER_PASSWORD with real per-manager logins. Each manager owns a set
-- of villas; the first manager ever created is an admin and can see every
-- manager's villas.

CREATE TABLE managers (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE sessions (
  token TEXT PRIMARY KEY,
  manager_id TEXT NOT NULL REFERENCES managers(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_sessions_manager ON sessions(manager_id);

ALTER TABLE villas ADD COLUMN manager_id TEXT REFERENCES managers(id);

CREATE INDEX idx_villas_manager ON villas(manager_id);
