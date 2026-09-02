import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analyzeThreatIntelligence } from "./attack-chain";
import { REPORT_CATALOG, SOURCE_SEED } from "./catalog";
import {
  cancelJob,
  createAndRunCrawlJob,
  getOrCreateCrawlConfig,
} from "./crawler";
import {
  canonicalizeUrl,
  excerptOf,
  harvestIocs,
  htmlToText,
  MAX_BYTES,
  scoreQuality,
  sha256Hex,
  toIsoString,
} from "./extract";
import { qualifyContent } from "./qualification";
import { SEED_REPORTS } from "./seed-reports";
import type {
  CatalogItem,
  CrawlerState,
  CrawlJob,
  CrawlJobItem,
  DashboardStats,
  DiscoveredResource,
  IngestEvent,
  IntelAnalysis,
  IocHit,
  QualityReason,
  ReportListItem,
  ReportRecord,
  SourceRecord,
  TrustLevel,
} from "./types";
import { getSql } from "@/lib/db";

type SourceRow = {
  id: string;
  name: string;
  slug: string;
  category: string;
  priority: number;
  homepage_url: string;
  enabled: boolean;
  trust_level: string;
  notes: string;
  last_ingest_at: string | null;
};

type ReportRow = {
  id: string;
  source_id: string;
  source_name: string;
  title: string;
  url: string;
  canonical_url: string;
  published_at: string | null;
  content_type: string;
  status: string;
  raw_hash: string;
  text_hash: string;
  quality_score: number;
  quality_reasons: string;
  word_count: number;
  extracted_text: string;
  iocs_json: string;
  ingest_origin: string;
  ingested_at: string;
  publisher?: string;
  author?: string;
  classification?: string;
  discovery_method?: string;
  discovery_query?: string;
  parent_source?: string;
  source_domain?: string;
  version?: number;
  analysis_json?: string;
};

function newId(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

function mapSource(r: SourceRow): SourceRecord {
  return {
    id: r.id,
    name: r.name,
    slug: r.slug,
    category: r.category,
    priority: Number(r.priority),
    homepageUrl: r.homepage_url,
    enabled: Boolean(r.enabled),
    trustLevel: r.trust_level as TrustLevel,
    notes: r.notes,
    lastIngestAt: r.last_ingest_at,
  };
}

function parseJson<T>(raw: string | undefined | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function toListItem(r: ReportRow): ReportListItem {
  return {
    id: r.id,
    sourceId: r.source_id,
    sourceName: r.source_name,
    title: r.title,
    url: r.url,
    canonicalUrl: r.canonical_url,
    publishedAt: r.published_at,
    contentType: r.content_type,
    status: r.status as ReportListItem["status"],
    rawHash: r.raw_hash,
    textHash: r.text_hash,
    qualityScore: Number(r.quality_score),
    wordCount: Number(r.word_count),
    iocs: parseJson<IocHit[]>(r.iocs_json, []),
    ingestOrigin: r.ingest_origin as ReportListItem["ingestOrigin"],
    ingestedAt: r.ingested_at,
    excerpt: excerptOf(r.extracted_text),
    iocCount: parseJson<IocHit[]>(r.iocs_json, []).length,
    publisher: r.publisher ?? r.source_name,
    author: r.author ?? r.source_name,
    classification: r.classification ?? "THREAT_REPORT",
    discoveryMethod: r.discovery_method ?? "manual",
    discoveryQuery: r.discovery_query ?? "",
    parentSource: r.parent_source ?? "",
    sourceDomain: r.source_domain ?? "",
    version: Number(r.version ?? 1),
  };
}

async function ensureSeeded() {
  const sql = await getSql();
  const existing = await sql<{ c: number }>`select count(*)::int as c from sources`;
  if (Number(existing[0]?.c ?? 0) === 0) {
    for (const s of SOURCE_SEED) {
      await sql`
        insert into sources (id, name, slug, category, priority, homepage_url, enabled, trust_level, notes)
        values (${s.id}, ${s.name}, ${s.slug}, ${s.category}, ${s.priority}, ${s.homepageUrl}, ${s.enabled}, ${s.trustLevel}, ${s.notes})
        on conflict (id) do nothing
      `;
    }
  }

  const rc = await sql<{ c: number }>`select count(*)::int as c from reports`;
  if (Number(rc[0]?.c ?? 0) === 0) {
    for (const r of SEED_REPORTS) {
      const { score, reasons, wordCount } = scoreQuality(r.text, r.title);
      const qual = qualifyContent(r.text, r.title, r.url);
      const iocs = harvestIocs(r.text);
      const rawHash = sha256Hex(r.text);
      const canonical = canonicalizeUrl(r.url);
      const intel = analyzeThreatIntelligence(r.text, r.title, qual.classification);

      await sql`
        insert into reports (
          id, source_id, title, url, canonical_url, published_at, content_type, status,
          raw_hash, text_hash, quality_score, quality_reasons, word_count, extracted_text,
          iocs_json, ingest_origin, publisher, author, classification, discovery_method,
          source_domain, version, analysis_json
        ) values (
          ${r.id}, ${r.sourceId}, ${r.title}, ${r.url}, ${canonical}, ${r.publishedAt},
          ${"text/plain"}, ${"acquired"}, ${rawHash}, ${rawHash}, ${score},
          ${JSON.stringify(reasons)}, ${wordCount}, ${r.text}, ${JSON.stringify(iocs)}, ${"seed"},
          ${"Seed Intelligence"}, ${"Curated CTI"}, ${qual.classification}, ${"seed"},
          ${"thedfirreport.com"}, 1, ${JSON.stringify(intel)}
        )
        on conflict (id) do nothing
      `;
      await sql`
        insert into ingest_events (id, report_id, url, outcome, detail)
        values (${newId("evt")}, ${r.id}, ${r.url}, ${"seeded"}, ${"Gold-set seed for Phase 1 retrieval"})
      `;
    }
  }

  // Ensure default crawl configuration exists
  await getOrCreateCrawlConfig();
}

const REPORT_SELECT = `
  r.id, r.source_id, s.name as source_name, r.title, r.url, r.canonical_url,
  r.published_at, r.content_type, r.status, r.raw_hash, r.text_hash,
  r.quality_score, r.quality_reasons, r.word_count, r.extracted_text,
  r.iocs_json, r.ingest_origin, r.ingested_at::text as ingested_at,
  r.publisher, r.author, r.classification, r.discovery_method,
  r.discovery_query, r.parent_source, r.source_domain, r.version,
  r.analysis_json
`;

export const getDashboard = createServerFn({ method: "GET" }).handler(async (): Promise<DashboardStats> => {
  await ensureSeeded();
  const sql = await getSql();
  const src = await sql<{ c: number; e: number }>`
    select count(*)::int as c, count(*) filter (where enabled)::int as e from sources
  `;
  const rep = await sql<{ c: number; a: number; q: number }>`
    select count(*)::int as c,
           count(*) filter (where status = 'acquired')::int as a,
           coalesce(avg(quality_score), 0)::float as q
    from reports
  `;
  const iocRows = await sql<{ iocs_json: string }>`select iocs_json from reports where status = 'acquired'`;
  const iocCount = iocRows.reduce((n, row) => n + parseJson<IocHit[]>(row.iocs_json, []).length, 0);

  const recentRows = await sql.query<ReportRow>(
    `select ${REPORT_SELECT} from reports r join sources s on s.id = r.source_id order by r.ingested_at desc limit 6`,
  );
  const eventRows = await sql<{
    id: string;
    report_id: string | null;
    url: string;
    outcome: string;
    detail: string;
    created_at: string;
  }>`select id, report_id, url, outcome, detail, created_at::text as created_at from ingest_events order by created_at desc limit 8`;

  const config = await getOrCreateCrawlConfig();
  const runningJobs = await sql<{ id: string }>`select id from crawl_jobs where status = 'running' limit 1`;
  const crawlerStatus = runningJobs.length > 0 ? "running" : config.paused ? "paused" : config.enabled ? "scheduled" : "disabled";

  return {
    sourceCount: Number(src[0]?.c ?? 0),
    enabledSources: Number(src[0]?.e ?? 0),
    reportCount: Number(rep[0]?.c ?? 0),
    acquiredCount: Number(rep[0]?.a ?? 0),
    avgQuality: Math.round(Number(rep[0]?.q ?? 0) * 100) / 100,
    iocCount,
    recent: recentRows.map(toListItem),
    events: eventRows.map(
      (e): IngestEvent => ({
        id: e.id,
        reportId: e.report_id,
        url: e.url,
        outcome: e.outcome,
        detail: e.detail,
        createdAt: e.created_at,
      }),
    ),
    crawlerStatus,
    lastCrawlAt: config.lastRunAt,
    nextCrawlAt: config.nextRunAt,
  };
});

export const listSources = createServerFn({ method: "GET" }).handler(async (): Promise<SourceRecord[]> => {
  await ensureSeeded();
  const sql = await getSql();
  const rows = await sql<SourceRow>`
    select id, name, slug, category, priority, homepage_url, enabled, trust_level, notes,
           last_ingest_at::text as last_ingest_at
    from sources
    order by priority asc, name asc
  `;
  return rows.map(mapSource);
});

export const toggleSource = createServerFn({ method: "POST" })
  .validator(z.object({ id: z.string(), enabled: z.boolean() }))
  .handler(async ({ data }) => {
    const sql = await getSql();
    await sql`update sources set enabled = ${data.enabled} where id = ${data.id}`;
    return { ok: true as const };
  });

export const listReports = createServerFn({ method: "GET" })
  .validator(z.object({ q: z.string().optional(), classification: z.string().optional() }).optional())
  .handler(async ({ data }): Promise<ReportListItem[]> => {
    await ensureSeeded();
    const sql = await getSql();
    const q = data?.q?.trim().toLowerCase() ?? "";
    const classification = data?.classification?.trim();

    const rows = await sql.query<ReportRow>(
      `select ${REPORT_SELECT} from reports r join sources s on s.id = r.source_id order by r.ingested_at desc`,
    );
    let items = rows.map(toListItem);

    if (classification && classification !== "ALL") {
      items = items.filter((r) => r.classification === classification);
    }

    if (!q) return items;
    return items.filter((r) =>
      `${r.title} ${r.sourceName} ${r.url} ${r.excerpt} ${r.classification}`.toLowerCase().includes(q),
    );
  });

export const getReport = createServerFn({ method: "GET" })
  .validator(z.object({ id: z.string() }))
  .handler(async ({ data }): Promise<ReportRecord | null> => {
    await ensureSeeded();
    const sql = await getSql();
    const rows = await sql.query<ReportRow>(
      `select ${REPORT_SELECT} from reports r join sources s on s.id = r.source_id where r.id = $1`,
      [data.id],
    );
    const r = rows[0];
    if (!r) return null;

    let analysis = parseJson<IntelAnalysis | null>(r.analysis_json, null);
    if (!analysis || !analysis.attackChain || analysis.attackChain.length === 0) {
      analysis = analyzeThreatIntelligence(r.extracted_text, r.title, r.classification ?? "THREAT_REPORT");
    }

    return {
      ...toListItem(r),
      extractedText: r.extracted_text,
      qualityReasons: parseJson<QualityReason[]>(r.quality_reasons, []),
      analysis,
    };
  });

export const listCatalog = createServerFn({ method: "GET" }).handler(async (): Promise<
  (CatalogItem & { alreadyIngested: boolean; sourceName: string })[]
> => {
  await ensureSeeded();
  const sql = await getSql();
  const urls = await sql<{ canonical_url: string }>`select canonical_url from reports`;
  const have = new Set(urls.map((u) => u.canonical_url));
  const sources = await sql<{ slug: string; name: string }>`select slug, name from sources`;
  const names = Object.fromEntries(sources.map((s) => [s.slug, s.name]));
  return REPORT_CATALOG.map((c) => {
    let canonical = c.url;
    try {
      canonical = canonicalizeUrl(c.url);
    } catch {
      /* keep */
    }
    return {
      ...c,
      alreadyIngested: have.has(canonical),
      sourceName: names[c.sourceSlug] ?? c.sourceSlug,
    };
  });
});

type IngestResult =
  | { ok: true; reportId: string; duplicate: boolean; qualityScore: number; title: string }
  | { ok: false; error: string };

async function matchSource(url: string): Promise<string> {
  const sql = await getSql();
  const host = new URL(url).hostname.replace(/^www\./, "");
  const rows = await sql<SourceRow>`select * from sources`;
  const hit = rows.find((s) => {
    try {
      return (
        new URL(s.homepage_url).hostname.replace(/^www\./, "").includes(host.split(".").slice(-2).join(".")) ||
        host.includes(new URL(s.homepage_url).hostname.replace(/^www\./, ""))
      );
    } catch {
      return false;
    }
  });
  return hit?.id ?? rows.find((s) => s.slug === "dfir")?.id ?? SOURCE_SEED[0].id;
}

async function persistReport(input: {
  sourceId: string;
  title: string;
  url: string;
  canonical: string;
  publishedAt: string | null;
  contentType: string;
  raw: string | Uint8Array;
  text: string;
  origin: "live" | "paste" | "seed" | "crawl";
  publisher?: string;
  author?: string;
  classification?: string;
  discoveryMethod?: string;
  discoveryQuery?: string;
}): Promise<IngestResult> {
  const sql = await getSql();
  const dup = await sql<{ id: string }>`select id from reports where canonical_url = ${input.canonical}`;
  if (dup[0]) {
    await sql`
      insert into ingest_events (id, report_id, url, outcome, detail)
      values (${newId("evt")}, ${dup[0].id}, ${input.url}, 'duplicate', 'Canonical URL already stored in knowledge base')
    `;
    const existing = await sql<{ quality_score: number; title: string }>`
      select quality_score, title from reports where id = ${dup[0].id}
    `;
    return {
      ok: true,
      reportId: dup[0].id,
      duplicate: true,
      qualityScore: Number(existing[0]?.quality_score ?? 0),
      title: existing[0]?.title ?? input.title,
    };
  }

  const { score, reasons, wordCount } = scoreQuality(input.text, input.title);
  const qual = qualifyContent(input.text, input.title, input.url);
  const status = wordCount < 80 ? "rejected" : "acquired";
  const iocs = harvestIocs(input.text);
  const rawHash = sha256Hex(input.raw);
  const textHash = sha256Hex(input.text);
  const id = newId("rpt");
  const domain = new URL(input.canonical).hostname.replace(/^www\./, "");
  const classification = input.classification ?? qual.classification;

  // Run TTP and attack-chain extraction
  const analysis = analyzeThreatIntelligence(input.text, input.title, classification);

  await sql`
    insert into reports (
      id, source_id, title, url, canonical_url, published_at, content_type, status,
      raw_hash, text_hash, quality_score, quality_reasons, word_count, extracted_text,
      iocs_json, ingest_origin, publisher, author, classification, discovery_method,
      discovery_query, parent_source, source_domain, version, analysis_json
    ) values (
      ${id}, ${input.sourceId}, ${input.title}, ${input.url}, ${input.canonical},
      ${input.publishedAt}, ${input.contentType}, ${status}, ${rawHash}, ${textHash},
      ${score}, ${JSON.stringify(reasons)}, ${wordCount}, ${input.text},
      ${JSON.stringify(iocs)}, ${input.origin}, ${input.publisher ?? domain},
      ${input.author ?? domain}, ${classification}, ${input.discoveryMethod ?? 'manual'},
      ${input.discoveryQuery ?? ''}, ${input.publisher ?? domain}, ${domain}, 1,
      ${JSON.stringify(analysis)}
    )
  `;
  await sql`update sources set last_ingest_at = now() where id = ${input.sourceId}`;
  await sql`
    insert into ingest_events (id, report_id, url, outcome, detail)
    values (
      ${newId("evt")}, ${id}, ${input.url}, ${status},
      ${status === "rejected" ? "Below quality threshold" : `[${classification}] quality ${score} · ${wordCount} words · ${iocs.length} IOCs`}
    )
  `;
  return { ok: true, reportId: id, duplicate: false, qualityScore: score, title: input.title };
}

async function fetchResource(url: string): Promise<{
  contentType: string;
  body: string;
  bytes: Uint8Array;
}> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 18000);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "user-agent":
          "AIE-Retrieval/0.1 (+research; public-cti ingest; contact: security-research)",
        accept: "text/html,application/xhtml+xml,application/pdf,text/plain;q=0.9,*/*;q=0.5",
      },
    });
    if (!res.ok) {
      throw new Error(`Source returned HTTP ${res.status}`);
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > MAX_BYTES) {
      throw new Error("Document exceeds 1.5 MB ingest limit");
    }
    const contentType = (res.headers.get("content-type") ?? "text/html").split(";")[0].trim();
    const body = new TextDecoder("utf-8", { fatal: false }).decode(buf);
    return { contentType, body, bytes: buf };
  } finally {
    clearTimeout(t);
  }
}

export const ingestUrl = createServerFn({ method: "POST" })
  .validator(
    z.object({
      url: z.string().min(8),
      pasted: z.string().optional(),
    }),
  )
  .handler(async ({ data }): Promise<IngestResult> => {
    await ensureSeeded();
    let canonical: string;
    try {
      canonical = canonicalizeUrl(data.url);
    } catch {
      return { ok: false, error: "URL is not valid." };
    }

    const sourceId = await matchSource(canonical);

    if (data.pasted && data.pasted.trim().length > 40) {
      const looksHtml = /<html|<body|<article/i.test(data.pasted);
      const extracted = looksHtml ? htmlToText(data.pasted) : { title: "", text: data.pasted.trim() };
      const title = extracted.title && extracted.title !== "Untitled report" ? extracted.title : "Pasted report";
      return persistReport({
        sourceId,
        title,
        url: canonical,
        canonical,
        publishedAt: null,
        contentType: looksHtml ? "text/html" : "text/plain",
        raw: data.pasted,
        text: extracted.text,
        origin: "paste",
        discoveryMethod: "manual_paste",
      });
    }

    try {
      const fetched = await fetchResource(canonical);
      if (fetched.contentType.includes("pdf")) {
        return persistReport({
          sourceId,
          title: canonical.split("/").pop() || "PDF document",
          url: canonical,
          canonical,
          publishedAt: null,
          contentType: "application/pdf",
          raw: fetched.bytes,
          text: `PDF stored by cryptographic hash. Format preserved. Size ${fetched.bytes.byteLength} bytes.`,
          origin: "live",
          discoveryMethod: "manual_url",
        });
      }
      const extracted = htmlToText(fetched.body);
      return persistReport({
        sourceId,
        title: extracted.title,
        url: canonical,
        canonical,
        publishedAt: null,
        contentType: fetched.contentType || "text/html",
        raw: fetched.body,
        text: extracted.text,
        origin: "live",
        discoveryMethod: "manual_url",
      });
    } catch (err) {
      const sql = await getSql();
      const message = err instanceof Error ? err.message : "Fetch failed";
      await sql`
        insert into ingest_events (id, report_id, url, outcome, detail)
        values (${newId("evt")}, ${null}, ${canonical}, 'failed', ${message})
      `;
      return {
        ok: false,
        error: `${message}. If the publisher blocks automated fetch, paste the article text instead.`,
      };
    }
  });

// Crawler Server Functions
export const getCrawlerState = createServerFn({ method: "GET" }).handler(async (): Promise<CrawlerState> => {
  await ensureSeeded();
  const sql = await getSql();
  const config = await getOrCreateCrawlConfig();

  const jobs = await sql<{
    id: string;
    status: CrawlJob["status"];
    trigger_type: CrawlJob["triggerType"];
    started_at: string | null;
    completed_at: string | null;
    source_count: number;
    discovered_count: number;
    qualified_count: number;
    ingested_count: number;
    duplicate_count: number;
    failed_count: number;
    rejected_count: number;
    updated_count: number;
    skipped_count: number;
    error_summary: string;
  }>`select * from crawl_jobs order by created_at desc limit 10`;

  const activeJob = jobs.find((j) => j.status === "running") ?? null;

  const items = await sql<{
    id: string;
    job_id: string;
    source_id: string | null;
    url: string;
    canonical_url: string;
    title: string;
    classification: string;
    decision: string;
    reason: string;
    discovery_method: string;
    discovery_query: string;
    parent_url: string | null;
    depth: number;
    publisher: string;
    created_at: string;
  }>`select * from crawl_job_items order by created_at desc limit 25`;

  const discovered = await sql<{
    id: string;
    canonical_url: string;
    url: string;
    source_id: string | null;
    title: string;
    publisher: string;
    author: string;
    publication_date: string | null;
    classification: string;
    discovery_method: string;
    discovery_query: string;
    parent_source: string;
    source_domain: string;
    content_type: string;
    status: string;
    reject_reason: string;
    quality_score: number | null;
    report_id: string | null;
    created_at: string;
  }>`select * from discovered_resources order by created_at desc limit 40`;

  const sourceStatsRows = await sql<{
    name: string;
    found: number;
    ingested: number;
    failed: number;
  }>`
    select s.name,
           count(i.id)::int as found,
           count(i.id) filter (where i.decision = 'INGESTED')::int as ingested,
           count(i.id) filter (where i.decision = 'FAILED')::int as failed
    from sources s
    left join crawl_job_items i on i.source_id = s.id
    group by s.id, s.name
    order by ingested desc, found desc
    limit 8
  `;

  return {
    config,
    activeJob: activeJob
      ? {
          id: activeJob.id,
          status: activeJob.status,
          triggerType: activeJob.trigger_type,
          startedAt: toIsoString(activeJob.started_at),
          completedAt: toIsoString(activeJob.completed_at),
          sourceCount: Number(activeJob.source_count),
          discoveredCount: Number(activeJob.discovered_count),
          qualifiedCount: Number(activeJob.qualified_count),
          ingestedCount: Number(activeJob.ingested_count),
          duplicateCount: Number(activeJob.duplicate_count),
          failedCount: Number(activeJob.failed_count),
          rejectedCount: Number(activeJob.rejected_count),
          updatedCount: Number(activeJob.updated_count),
          skippedCount: Number(activeJob.skipped_count),
          errorSummary: activeJob.error_summary,
        }
      : null,
    jobs: jobs.map((j) => ({
      id: j.id,
      status: j.status,
      triggerType: j.trigger_type,
      startedAt: toIsoString(j.started_at),
      completedAt: toIsoString(j.completed_at),
      sourceCount: Number(j.source_count),
      discoveredCount: Number(j.discovered_count),
      qualifiedCount: Number(j.qualified_count),
      ingestedCount: Number(j.ingested_count),
      duplicateCount: Number(j.duplicate_count),
      failedCount: Number(j.failed_count),
      rejectedCount: Number(j.rejected_count),
      updatedCount: Number(j.updated_count),
      skippedCount: Number(j.skipped_count),
      errorSummary: j.error_summary,
    })),
    items: items.map((itm) => ({
      id: itm.id,
      jobId: itm.job_id,
      sourceId: itm.source_id,
      url: itm.url,
      canonicalUrl: itm.canonical_url,
      title: itm.title,
      classification: itm.classification,
      decision: itm.decision,
      reason: itm.reason,
      discoveryMethod: itm.discovery_method,
      discoveryQuery: itm.discovery_query,
      parentUrl: itm.parent_url,
      depth: Number(itm.depth),
      publisher: itm.publisher,
      createdAt: toIsoString(itm.created_at) ?? "",
    })),
    discovered: discovered.map((d) => ({
      id: d.id,
      canonicalUrl: d.canonical_url,
      url: d.url,
      sourceId: d.source_id,
      title: d.title,
      publisher: d.publisher,
      author: d.author,
      publicationDate: d.publication_date,
      classification: d.classification,
      discoveryMethod: d.discovery_method,
      discoveryQuery: d.discovery_query,
      parentSource: d.parent_source,
      sourceDomain: d.source_domain,
      contentType: d.content_type,
      status: d.status,
      rejectReason: d.reject_reason,
      qualityScore: d.quality_score ? Number(d.quality_score) : null,
      reportId: d.report_id,
      createdAt: toIsoString(d.created_at) ?? "",
    })),
    sourceStats: sourceStatsRows.map((s) => ({
      sourceName: s.name,
      found: Number(s.found),
      ingested: Number(s.ingested),
      failed: Number(s.failed),
    })),
  };
});

export const updateCrawlerConfig = createServerFn({ method: "POST" })
  .validator(
    z.object({
      enabled: z.boolean().optional(),
      paused: z.boolean().optional(),
      frequencyMinutes: z.number().optional(),
      startHour: z.string().optional(),
      maxResourcesPerRun: z.number().optional(),
      maxDepth: z.number().optional(),
      autoIngest: z.boolean().optional(),
      autoAnalyze: z.boolean().optional(),
      searchDiscovery: z.boolean().optional(),
      recursiveDiscovery: z.boolean().optional(),
      keywords: z.string().optional(),
    }),
  )
  .handler(async ({ data }) => {
    const sql = await getSql();
    const current = await getOrCreateCrawlConfig();

    const updated = {
      enabled: data.enabled ?? current.enabled,
      paused: data.paused ?? current.paused,
      frequencyMinutes: data.frequencyMinutes ?? current.frequencyMinutes,
      startHour: data.startHour ?? current.startHour,
      maxResourcesPerRun: data.maxResourcesPerRun ?? current.maxResourcesPerRun,
      maxDepth: data.maxDepth ?? current.maxDepth,
      autoIngest: data.autoIngest ?? current.autoIngest,
      autoAnalyze: data.autoAnalyze ?? current.autoAnalyze,
      searchDiscovery: data.searchDiscovery ?? current.searchDiscovery,
      recursiveDiscovery: data.recursiveDiscovery ?? current.recursiveDiscovery,
      keywords: data.keywords ?? current.keywords,
    };

    await sql`
      update crawl_config
      set enabled = ${updated.enabled},
          paused = ${updated.paused},
          frequency_minutes = ${updated.frequencyMinutes},
          start_hour = ${updated.startHour},
          max_resources_per_run = ${updated.maxResourcesPerRun},
          max_depth = ${updated.maxDepth},
          auto_ingest = ${updated.autoIngest},
          auto_analyze = ${updated.autoAnalyze},
          search_discovery = ${updated.searchDiscovery},
          recursive_discovery = ${updated.recursiveDiscovery},
          keywords = ${updated.keywords},
          updated_at = now()
      where id = ${current.id}
    `;

    return { ok: true as const, config: updated };
  });

export const triggerCrawlJob = createServerFn({ method: "POST" })
  .validator(
    z
      .object({
        triggerType: z.enum(["MANUAL", "SCHEDULED", "SEARCH", "API", "AGENT"]).optional(),
      })
      .optional(),
  )
  .handler(async ({ data }) => {
    await ensureSeeded();
    const job = await createAndRunCrawlJob(data?.triggerType ?? "MANUAL");
    return { ok: true as const, job };
  });

export const cancelCrawlJob = createServerFn({ method: "POST" })
  .validator(z.object({ jobId: z.string() }))
  .handler(async ({ data }) => {
    const success = await cancelJob(data.jobId);
    return { ok: success };
  });

export const ingestDiscoveredUrl = createServerFn({ method: "POST" })
  .validator(z.object({ discoveredId: z.string() }))
  .handler(async ({ data }): Promise<IngestResult> => {
    await ensureSeeded();
    const sql = await getSql();
    const rows = await sql<{
      id: string;
      url: string;
      canonical_url: string;
      title: string;
      source_id: string | null;
      publisher: string;
      classification: string;
      discovery_method: string;
    }>`select * from discovered_resources where id = ${data.discoveredId}`;

    const item = rows[0];
    if (!item) return { ok: false, error: "Discovered item not found" };

    const sourceId = item.source_id || (await matchSource(item.canonical_url));
    const result = await ingestUrl({ data: { url: item.canonical_url } });

    if (result.ok) {
      await sql`
        update discovered_resources
        set status = 'ingested', report_id = ${result.reportId}, quality_score = ${result.qualityScore}, updated_at = now()
        where id = ${data.discoveredId}
      `;
    }

    return result;
  });
