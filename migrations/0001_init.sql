-- Villa Concierge — initial schema (Cloudflare D1 / SQLite)

CREATE TABLE villas (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE knowledge_items (
  id TEXT PRIMARY KEY,
  villa_id TEXT NOT NULL REFERENCES villas(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  fields_json TEXT NOT NULL DEFAULT '{}',
  photo TEXT,
  item_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE conversations (
  id TEXT PRIMARY KEY,
  villa_id TEXT NOT NULL REFERENCES villas(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL,
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  messages_json TEXT NOT NULL DEFAULT '[]',
  needs_human INTEGER NOT NULL DEFAULT 0,
  handled INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_knowledge_villa ON knowledge_items(villa_id);
CREATE INDEX idx_conversations_villa ON conversations(villa_id);
CREATE UNIQUE INDEX idx_conversations_session ON conversations(villa_id, session_id);
