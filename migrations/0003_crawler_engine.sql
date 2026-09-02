-- Migration 0003: Autonomous Threat Intelligence Crawler & Ingestion Engine

-- 1. Extend reports table with provenance, classification, and analysis
alter table reports add column if not exists publisher text not null default '';
alter table reports add column if not exists author text not null default '';
alter table reports add column if not exists classification text not null default 'THREAT_REPORT';
alter table reports add column if not exists discovery_method text not null default 'manual';
alter table reports add column if not exists discovery_query text not null default '';
alter table reports add column if not exists parent_source text not null default '';
alter table reports add column if not exists source_domain text not null default '';
alter table reports add column if not exists version integer not null default 1;
alter table reports add column if not exists analysis_json text not null default '{}';

-- 2. Crawl configuration table
create table if not exists crawl_config (
  id text primary key,
  enabled boolean not null default true,
  paused boolean not null default false,
  frequency_minutes integer not null default 360,
  start_hour text not null default '09:00',
  max_resources_per_run integer not null default 25,
  max_depth integer not null default 2,
  auto_ingest boolean not null default true,
  auto_analyze boolean not null default true,
  search_discovery boolean not null default true,
  recursive_discovery boolean not null default true,
  keywords text not null default 'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation", "threat actor", "incident response"',
  date_range_days integer,
  last_run_at timestamptz,
  next_run_at timestamptz,
  updated_at timestamptz not null default now()
);

-- 3. Crawl jobs table
create table if not exists crawl_jobs (
  id text primary key,
  status text not null default 'queued',
  trigger_type text not null default 'MANUAL',
  started_at timestamptz,
  completed_at timestamptz,
  source_count integer not null default 0,
  discovered_count integer not null default 0,
  qualified_count integer not null default 0,
  ingested_count integer not null default 0,
  duplicate_count integer not null default 0,
  failed_count integer not null default 0,
  rejected_count integer not null default 0,
  updated_count integer not null default 0,
  skipped_count integer not null default 0,
  error_summary text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists crawl_jobs_created_at_idx on crawl_jobs (created_at desc);
create index if not exists crawl_jobs_status_idx on crawl_jobs (status);

-- 4. Crawl job items audit log
create table if not exists crawl_job_items (
  id text primary key,
  job_id text not null references crawl_jobs(id) on delete cascade,
  source_id text,
  url text not null,
  canonical_url text not null,
  title text not null default '',
  classification text not null default 'OTHER',
  decision text not null,
  reason text not null default '',
  discovery_method text not null default 'crawl_source',
  discovery_query text not null default '',
  parent_url text,
  depth integer not null default 1,
  publisher text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists crawl_job_items_job_id_idx on crawl_job_items (job_id);
create index if not exists crawl_job_items_created_at_idx on crawl_job_items (created_at desc);

-- 5. Discovered resources pool (for qualification queue, deduplication and discovery review)
create table if not exists discovered_resources (
  id text primary key,
  canonical_url text not null unique,
  url text not null,
  source_id text,
  title text not null default '',
  publisher text not null default '',
  author text not null default '',
  publication_date text,
  classification text not null default 'THREAT_REPORT',
  discovery_method text not null default 'crawl_source',
  discovery_query text not null default '',
  parent_source text not null default '',
  source_domain text not null default '',
  content_type text not null default 'text/html',
  status text not null default 'discovered',
  reject_reason text not null default '',
  quality_score double precision,
  report_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists discovered_resources_status_idx on discovered_resources (status);
create index if not exists discovered_resources_source_id_idx on discovered_resources (source_id);
create index if not exists discovered_resources_created_at_idx on discovered_resources (created_at desc);
