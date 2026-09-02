-- Autonomous CTI crawler: jobs, queue, discovered resources, schedule, provenance

alter table reports add column if not exists discovery_method text not null default '';
alter table reports add column if not exists discovery_query text not null default '';
alter table reports add column if not exists parent_source text not null default '';
alter table reports add column if not exists publisher text not null default '';
alter table reports add column if not exists author text not null default '';
alter table reports add column if not exists classification text not null default '';
alter table reports add column if not exists source_domain text not null default '';
alter table reports add column if not exists analysis_json text not null default '';
alter table reports add column if not exists version integer not null default 1;

create table if not exists crawl_config (
  id text primary key,
  enabled boolean not null default false,
  paused boolean not null default false,
  frequency_minutes integer not null default 360,
  start_hour text not null default '09:00',
  max_resources_per_run integer not null default 24,
  max_depth integer not null default 2,
  auto_ingest boolean not null default true,
  auto_analyze boolean not null default false,
  search_discovery boolean not null default true,
  recursive_discovery boolean not null default true,
  keywords text not null default '',
  date_range_days integer,
  last_run_at timestamptz,
  next_run_at timestamptz,
  updated_at timestamptz not null default now()
);

insert into crawl_config (id) values ('default')
  on conflict (id) do nothing;

create table if not exists crawl_jobs (
  id text primary key,
  status text not null,
  trigger_type text not null,
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
  config_snapshot text not null default '{}'
);

create index if not exists crawl_jobs_started_idx on crawl_jobs (started_at desc);

create table if not exists crawl_queue (
  id text primary key,
  job_id text not null references crawl_jobs(id),
  kind text not null,
  url text not null default '',
  query text not null default '',
  source_id text,
  parent_url text,
  discovery_method text not null,
  discovery_query text not null default '',
  depth integer not null default 0,
  status text not null default 'pending',
  created_at timestamptz not null default now()
);

create index if not exists crawl_queue_job_status_idx on crawl_queue (job_id, status);

create table if not exists crawl_job_items (
  id text primary key,
  job_id text not null references crawl_jobs(id),
  source_id text,
  url text not null,
  canonical_url text not null default '',
  title text not null default '',
  classification text not null default '',
  decision text not null,
  reason text not null default '',
  discovery_method text not null default '',
  discovery_query text not null default '',
  parent_url text,
  depth integer not null default 0,
  publisher text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists crawl_job_items_job_idx on crawl_job_items (job_id, created_at desc);

create table if not exists crawl_source_state (
  source_id text primary key references sources(id),
  last_crawled_at timestamptz,
  last_successful_crawl timestamptz,
  last_seen_resource text,
  etag text,
  last_modified text,
  content_hash text,
  crawl_status text not null default 'idle',
  last_error text not null default ''
);

create table if not exists discovered_resources (
  id text primary key,
  canonical_url text not null unique,
  url text not null,
  source_id text,
  title text not null default '',
  publisher text not null default '',
  author text not null default '',
  publication_date text,
  classification text not null default '',
  discovery_method text not null,
  discovery_query text not null default '',
  parent_source text not null default '',
  source_domain text not null default '',
  content_type text not null default '',
  original_content_type text not null default '',
  document_hash text not null default '',
  collection_date timestamptz,
  status text not null,
  reject_reason text not null default '',
  quality_score double precision,
  report_id text,
  created_at timestamptz not null default now()
);

create index if not exists discovered_resources_status_idx on discovered_resources (status, created_at desc);
