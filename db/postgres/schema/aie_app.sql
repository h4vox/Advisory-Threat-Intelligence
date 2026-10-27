-- aie_app: this instance and its users: accounts, sign-in sessions, settings, crawler
-- configuration and locks, AI chat sessions, marketplace integrations (API keys), and any
-- document not recognised yet (unclassified_documents), kept until it is classified.
-- Same phase 1 layout as aie_intel. Idempotent. See docs/db-migration.md.

-- One row per migration run (backup, migrate, verify), with its counts and outcome.
CREATE TABLE IF NOT EXISTS migration_runs (
  run_id      text        PRIMARY KEY,
  phase       text        NOT NULL,
  started_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  status      text        NOT NULL DEFAULT 'running',
  source      text,
  summary     jsonb       NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS users (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  username          text GENERATED ALWAYS AS (lower(doc->>'username')) STORED,
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS users_id_idx ON users (id);
CREATE INDEX IF NOT EXISTS users_username_idx ON users (username);

CREATE TABLE IF NOT EXISTS auth_sessions (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS auth_sessions_id_idx ON auth_sessions (id);

CREATE TABLE IF NOT EXISTS app_state (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS app_state_id_idx ON app_state (id);
CREATE INDEX IF NOT EXISTS app_state_type_idx ON app_state (doc_type);

CREATE TABLE IF NOT EXISTS agent_chat_sessions (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS agent_chat_sessions_id_idx ON agent_chat_sessions (id);

CREATE TABLE IF NOT EXISTS agent_chat_messages (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  session_id        text GENERATED ALWAYS AS (doc->>'sessionId') STORED,
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS agent_chat_messages_id_idx ON agent_chat_messages (id);
CREATE INDEX IF NOT EXISTS agent_chat_messages_session_idx ON agent_chat_messages (session_id);

CREATE TABLE IF NOT EXISTS integrations (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS integrations_id_idx ON integrations (id);

CREATE TABLE IF NOT EXISTS unclassified_documents (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS unclassified_documents_id_idx ON unclassified_documents (id);
CREATE INDEX IF NOT EXISTS unclassified_documents_type_idx ON unclassified_documents (source_collection, doc_type);
