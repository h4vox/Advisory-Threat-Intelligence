-- Migration 0005: Resiliency fix for sources, crawl jobs, items, and discovered resources

alter table sources add column if not exists feed_url text not null default '';
alter table reports add column if not exists pdf_url text not null default '';
alter table reports add column if not exists raw_html text not null default '';

alter table crawl_jobs add column if not exists created_at timestamptz not null default now();
alter table crawl_jobs add column if not exists error_summary text not null default '';
alter table crawl_jobs add column if not exists source_count integer not null default 0;

alter table crawl_job_items add column if not exists created_at timestamptz not null default now();
alter table crawl_job_items add column if not exists publisher text not null default '';
alter table crawl_job_items add column if not exists depth integer not null default 0;

alter table discovered_resources add column if not exists created_at timestamptz not null default now();
alter table discovered_resources add column if not exists quality_score double precision;
alter table discovered_resources add column if not exists report_id text;
