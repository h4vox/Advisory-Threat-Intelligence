-- AIE Phase 1: source registry + retrieved reports (unowned shared knowledge)

create table if not exists sources (
  id text primary key,
  name text not null,
  slug text not null unique,
  category text not null,
  priority integer not null default 2,
  homepage_url text not null,
  enabled boolean not null default true,
  trust_level text not null default 'high',
  notes text not null default '',
  last_ingest_at timestamptz
);

create table if not exists reports (
  id text primary key,
  source_id text not null references sources(id),
  title text not null,
  url text not null,
  canonical_url text not null,
  published_at text,
  content_type text not null,
  status text not null,
  raw_hash text not null,
  text_hash text not null,
  quality_score double precision not null,
  quality_reasons text not null,
  word_count integer not null,
  extracted_text text not null,
  iocs_json text not null default '[]',
  ingest_origin text not null default 'live',
  ingested_at timestamptz not null default now()
);

create unique index if not exists reports_canonical_url_idx on reports (canonical_url);
create index if not exists reports_source_id_idx on reports (source_id);
create index if not exists reports_ingested_at_idx on reports (ingested_at desc);

create table if not exists ingest_events (
  id text primary key,
  report_id text,
  url text not null,
  outcome text not null,
  detail text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists ingest_events_created_at_idx on ingest_events (created_at desc);
