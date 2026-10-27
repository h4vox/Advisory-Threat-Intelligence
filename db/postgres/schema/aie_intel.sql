-- aie_intel: shared threat intelligence, the same for every account and instance.
-- Phase 1 (lossless copy from MongoDB): every row keeps the original document in `doc`
-- (MongoDB Extended JSON, relaxed), its source collection and _id, and a SHA-256 of the
-- document for verification. Generated columns expose the fields the app filters on.
-- Idempotent: safe to run again. See docs/db-migration.md.

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

CREATE TABLE IF NOT EXISTS reports (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(), 
  -- Columns the app filters and sorts on, kept in step with doc.
  title             text GENERATED ALWAYS AS (doc->>'title') STORED,
  canonical_url     text GENERATED ALWAYS AS (doc->>'canonicalUrl') STORED,
  status            text GENERATED ALWAYS AS (doc->>'status') STORED,
  published_at      text GENERATED ALWAYS AS (doc->>'publishedAt') STORED,
  ingested_at       text GENERATED ALWAYS AS (COALESCE(doc->'ingestedAt'->>'$date', doc->>'ingestedAt')) STORED,
  source_id         text GENERATED ALWAYS AS (doc->>'sourceId') STORED,
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS reports_id_idx ON reports (id);
CREATE INDEX IF NOT EXISTS reports_published_idx ON reports (published_at DESC NULLS LAST, ingested_at DESC);
CREATE INDEX IF NOT EXISTS reports_status_idx ON reports (status);
CREATE INDEX IF NOT EXISTS reports_canonical_url_idx ON reports USING hash (canonical_url);
CREATE INDEX IF NOT EXISTS reports_source_idx ON reports (source_id);

CREATE TABLE IF NOT EXISTS sources (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  name              text GENERATED ALWAYS AS (doc->>'name') STORED,
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS sources_id_idx ON sources (id);

CREATE TABLE IF NOT EXISTS discovered_sources (
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
CREATE INDEX IF NOT EXISTS discovered_sources_id_idx ON discovered_sources (id);

CREATE TABLE IF NOT EXISTS discovered_resources (
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
CREATE INDEX IF NOT EXISTS discovered_resources_id_idx ON discovered_resources (id);

CREATE TABLE IF NOT EXISTS graph_edges (
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
CREATE INDEX IF NOT EXISTS graph_edges_id_idx ON graph_edges (id);

CREATE TABLE IF NOT EXISTS knowledge_objects (
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
CREATE INDEX IF NOT EXISTS knowledge_objects_id_idx ON knowledge_objects (id);
CREATE INDEX IF NOT EXISTS knowledge_objects_type_idx ON knowledge_objects (doc_type);

CREATE TABLE IF NOT EXISTS crawl_jobs (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  started_at        text GENERATED ALWAYS AS (COALESCE(doc->'startedAt'->>'$date', doc->>'startedAt')) STORED,
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS crawl_jobs_id_idx ON crawl_jobs (id);
CREATE INDEX IF NOT EXISTS crawl_jobs_started_idx ON crawl_jobs (started_at DESC);

CREATE TABLE IF NOT EXISTS crawl_job_items (
  source_collection text        NOT NULL,
  mongo_id          text        NOT NULL,
  id                text        NOT NULL,
  doc_type          text,
  doc               jsonb       NOT NULL,
  doc_sha256        text        NOT NULL,
  nul_removed       integer     NOT NULL DEFAULT 0,
  migrated_at       timestamptz NOT NULL DEFAULT now(),
  job_id            text GENERATED ALWAYS AS (doc->>'jobId') STORED,
  PRIMARY KEY (source_collection, mongo_id)
);
CREATE INDEX IF NOT EXISTS crawl_job_items_id_idx ON crawl_job_items (id);
CREATE INDEX IF NOT EXISTS crawl_job_items_job_idx ON crawl_job_items (job_id);

CREATE TABLE IF NOT EXISTS ingest_events (
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
CREATE INDEX IF NOT EXISTS ingest_events_id_idx ON ingest_events (id);

CREATE TABLE IF NOT EXISTS collector_state (
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
CREATE INDEX IF NOT EXISTS collector_state_id_idx ON collector_state (id);
CREATE INDEX IF NOT EXISTS collector_state_type_idx ON collector_state (doc_type);

CREATE TABLE IF NOT EXISTS advisories (
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
CREATE INDEX IF NOT EXISTS advisories_id_idx ON advisories (id);

CREATE TABLE IF NOT EXISTS simulation_runs (
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
CREATE INDEX IF NOT EXISTS simulation_runs_id_idx ON simulation_runs (id);
