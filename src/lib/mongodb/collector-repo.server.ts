/**
 * Collector persistence (phase 9): per-URL fetch state, per-source health and yield, per-job
 * funnels, the multi-hash dedup index, mirrors ("also seen at") and content versions.
 *
 * MongoDB (production): documents in the threat-intel collection (docType collector_fetch_state /
 * collector_source_health), the funnel on the crawl_job document and collector fields on the
 * report document. Local fallback (no MONGODB_URI): small JSON tables created on first use in the
 * app's SQL database (PGLite in this workspace, which is in-memory and resets on restart — the
 * state is honest about that through `collectorPersistence()`).
 */
import { getSql, type Sql } from "@/lib/db";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import type { FetchState } from "../aie/collector/fetch-state";
import type { SourceHealth } from "../aie/collector/health";
import type { DedupIndexEntry } from "../aie/collector/dedup";
import { mergeMirrors } from "../aie/collector/dedup";
import type {
  AttackEntityRef,
  CrawlFunnel,
  ReportAttachment,
  ReportFingerprints,
  ReportMirror,
  ReportVersionEntry,
} from "../aie/types";

export type CollectorPersistence = "mongodb" | "local";

export function collectorPersistence(): CollectorPersistence {
  return isMongoConfigured() ? "mongodb" : "local";
}

/** Collector fields kept per report (on the Mongo report doc; in collector_report_meta locally). */
export type ReportCollectorMeta = {
  fingerprints?: ReportFingerprints;
  attackRefs?: AttackEntityRef[];
  attachments?: ReportAttachment[];
  mirrors?: ReportMirror[];
  versionHistory?: ReportVersionEntry[];
  relevance?: { score: number; reason: string };
  canonicalReportId?: string;
};

// ---------------------------------------------------------------------------
// Local tables
// ---------------------------------------------------------------------------

const g = globalThis as typeof globalThis & { __collectorTables__?: Promise<Sql> };

async function localSql(): Promise<Sql> {
  g.__collectorTables__ ??= (async () => {
    const sql = await getSql();
    await sql`create table if not exists collector_fetch_state (url text primary key, source_id text, data text not null, updated_at timestamptz not null default now())`;
    await sql`create table if not exists collector_source_health (source_id text primary key, data text not null, updated_at timestamptz not null default now())`;
    await sql`create table if not exists collector_job_funnel (job_id text primary key, data text not null, created_at timestamptz not null default now())`;
    await sql`create table if not exists collector_report_meta (report_id text primary key, data text not null, updated_at timestamptz not null default now())`;
    return sql;
  })().catch((err) => {
    g.__collectorTables__ = undefined;
    throw err;
  });
  return g.__collectorTables__;
}

function parse<T>(raw: string | null | undefined): T | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

let mongoIndexesReady = false;
async function mongoCol() {
  const col = await getThreatIntelCollection();
  if (!mongoIndexesReady) {
    mongoIndexesReady = true;
    try {
      await col.createIndex({ docType: 1, url: 1 }, { name: "collector_fetch_state_url", partialFilterExpression: { docType: "collector_fetch_state" } });
      await col.createIndex({ docType: 1, sourceId: 1 }, { name: "collector_source_health_id", partialFilterExpression: { docType: "collector_source_health" } });
    } catch (err) {
      console.warn("[collector] index creation skipped:", (err as Error).message);
    }
  }
  return col;
}

// ---------------------------------------------------------------------------
// Fetch state
// ---------------------------------------------------------------------------

export async function getFetchStates(urls: string[]): Promise<Map<string, FetchState>> {
  const out = new Map<string, FetchState>();
  const unique = [...new Set(urls.filter(Boolean))];
  if (unique.length === 0) return out;
  if (isMongoConfigured()) {
    const col = await mongoCol();
    const docs = await col.find({ docType: "collector_fetch_state", url: { $in: unique } }).project({ _id: 0, docType: 0, id: 0 }).toArray();
    for (const d of docs as unknown as FetchState[]) out.set(d.url, d);
    return out;
  }
  const sql = await localSql();
  for (let i = 0; i < unique.length; i += 200) {
    const chunk = unique.slice(i, i + 200);
    const rows = await sql<{ url: string; data: string }>`select url, data from collector_fetch_state where url = any(${chunk})`;
    for (const r of rows) {
      const s = parse<FetchState>(r.data);
      if (s) out.set(r.url, s);
    }
  }
  return out;
}

export async function putFetchStates(states: FetchState[]): Promise<void> {
  if (states.length === 0) return;
  if (isMongoConfigured()) {
    const col = await mongoCol();
    await col.bulkWrite(
      states.map((s) => ({
        updateOne: {
          filter: { docType: "collector_fetch_state", url: s.url },
          // `id` is required: the collection's unique (docType, id) index lets only one document of a
          // type go without one, so without it every fetch state after the first failed to save.
          update: { $set: { ...s, docType: "collector_fetch_state", id: `fetch:${s.url}`, updatedAt: new Date().toISOString() } },
          upsert: true,
        },
      })),
      { ordered: false },
    );
    return;
  }
  const sql = await localSql();
  for (const s of states) {
    await sql`
      insert into collector_fetch_state (url, source_id, data, updated_at) values (${s.url}, ${s.sourceId ?? null}, ${JSON.stringify(s)}, now())
      on conflict (url) do update set data = excluded.data, source_id = excluded.source_id, updated_at = now()
    `;
  }
}

export async function countFetchStates(): Promise<number> {
  if (isMongoConfigured()) {
    const col = await mongoCol();
    return col.countDocuments({ docType: "collector_fetch_state" });
  }
  const sql = await localSql();
  const r = await sql<{ c: number }>`select count(*)::int as c from collector_fetch_state`;
  return Number(r[0]?.c ?? 0);
}

// ---------------------------------------------------------------------------
// Source health
// ---------------------------------------------------------------------------

export async function getSourceHealthMap(): Promise<Map<string, SourceHealth>> {
  const out = new Map<string, SourceHealth>();
  if (isMongoConfigured()) {
    const col = await mongoCol();
    const docs = await col.find({ docType: "collector_source_health" }).project({ _id: 0, docType: 0, id: 0 }).toArray();
    for (const d of docs as unknown as SourceHealth[]) out.set(d.sourceId, d);
    return out;
  }
  const sql = await localSql();
  const rows = await sql<{ source_id: string; data: string }>`select source_id, data from collector_source_health`;
  for (const r of rows) {
    const h = parse<SourceHealth>(r.data);
    if (h) out.set(r.source_id, h);
  }
  return out;
}

export async function putSourceHealth(list: SourceHealth[]): Promise<void> {
  if (list.length === 0) return;
  if (isMongoConfigured()) {
    const col = await mongoCol();
    await col.bulkWrite(
      list.map((h) => ({
        updateOne: {
          filter: { docType: "collector_source_health", sourceId: h.sourceId },
          update: { $set: { ...h, docType: "collector_source_health", id: `health:${h.sourceId}` } },
          upsert: true,
        },
      })),
      { ordered: false },
    );
    return;
  }
  const sql = await localSql();
  for (const h of list) {
    await sql`
      insert into collector_source_health (source_id, data, updated_at) values (${h.sourceId}, ${JSON.stringify(h)}, now())
      on conflict (source_id) do update set data = excluded.data, updated_at = now()
    `;
  }
}

// ---------------------------------------------------------------------------
// Job funnels
// ---------------------------------------------------------------------------

export async function putJobFunnel(jobId: string, funnel: CrawlFunnel): Promise<void> {
  if (isMongoConfigured()) {
    const col = await mongoCol();
    await col.updateOne({ docType: "crawl_job", id: jobId }, { $set: { funnel } });
    return;
  }
  const sql = await localSql();
  await sql`
    insert into collector_job_funnel (job_id, data) values (${jobId}, ${JSON.stringify(funnel)})
    on conflict (job_id) do update set data = excluded.data
  `;
}

export async function getJobFunnels(jobIds: string[]): Promise<Record<string, CrawlFunnel>> {
  const out: Record<string, CrawlFunnel> = {};
  const ids = [...new Set(jobIds.filter(Boolean))].slice(0, 200);
  if (ids.length === 0) return out;
  if (isMongoConfigured()) {
    const col = await mongoCol();
    const docs = await col.find({ docType: "crawl_job", id: { $in: ids }, funnel: { $exists: true } }).project({ _id: 0, id: 1, funnel: 1 }).toArray();
    for (const d of docs as Array<{ id: string; funnel: CrawlFunnel }>) out[d.id] = d.funnel;
    return out;
  }
  const sql = await localSql();
  const rows = await sql<{ job_id: string; data: string }>`select job_id, data from collector_job_funnel where job_id = any(${ids})`;
  for (const r of rows) {
    const f = parse<CrawlFunnel>(r.data);
    if (f) out[r.job_id] = f;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Dedup index, mirrors, versions, report meta
// ---------------------------------------------------------------------------

export async function loadDedupIndexEntries(): Promise<DedupIndexEntry[]> {
  if (isMongoConfigured()) {
    const col = await getThreatIntelCollection();
    const docs = await col
      .find({ docType: "report", status: { $ne: "duplicate" }, discoveryMethod: { $ne: "structured_sync" } })
      .project({ _id: 0, id: 1, canonicalUrl: 1, title: 1, publisher: 1, sourceDomain: 1, sourceTier: 1, publishedAt: 1, ingestedAt: 1, textHash: 1, fingerprints: 1 })
      .toArray();
    return docs as unknown as DedupIndexEntry[];
  }
  const sql = await localSql();
  const rows = await sql<{
    id: string;
    canonical_url: string;
    title: string;
    publisher: string;
    source_domain: string;
    published_at: string | null;
    text_hash: string;
    meta: string | null;
  }>`
    select r.id, r.canonical_url, r.title, coalesce(r.publisher, '') as publisher, coalesce(r.source_domain, '') as source_domain,
           r.published_at::text as published_at, r.text_hash, m.data as meta
    from reports r left join collector_report_meta m on m.report_id = r.id
    where coalesce(r.status, '') <> 'duplicate'
  `;
  return rows.map((r) => ({
    id: r.id,
    canonicalUrl: r.canonical_url,
    title: r.title,
    publisher: r.publisher,
    sourceDomain: r.source_domain,
    publishedAt: r.published_at,
    textHash: r.text_hash,
    fingerprints: parse<ReportCollectorMeta>(r.meta)?.fingerprints ?? null,
  }));
}

export async function getReportCollectorMeta(reportId: string): Promise<ReportCollectorMeta | null> {
  if (isMongoConfigured()) {
    const col = await getThreatIntelCollection();
    const doc = await col.findOne(
      { docType: "report", id: reportId },
      { projection: { _id: 0, fingerprints: 1, attachments: 1, mirrors: 1, versionHistory: 1, relevance: 1, canonicalReportId: 1, "extractedEntities.attackRefs": 1 } },
    );
    if (!doc) return null;
    const d = doc as Record<string, any>;
    return {
      fingerprints: d.fingerprints,
      attachments: d.attachments,
      mirrors: d.mirrors,
      versionHistory: d.versionHistory,
      relevance: d.relevance,
      canonicalReportId: d.canonicalReportId,
      attackRefs: d.extractedEntities?.attackRefs,
    };
  }
  const sql = await localSql();
  const rows = await sql<{ data: string }>`select data from collector_report_meta where report_id = ${reportId}`;
  return parse<ReportCollectorMeta>(rows[0]?.data);
}

/** Local only: merge collector fields for a report (Mongo stores them on the report document). */
export async function mergeLocalReportMeta(reportId: string, patch: ReportCollectorMeta): Promise<void> {
  const sql = await localSql();
  const rows = await sql<{ data: string }>`select data from collector_report_meta where report_id = ${reportId}`;
  const prev = parse<ReportCollectorMeta>(rows[0]?.data) ?? {};
  const next: ReportCollectorMeta = { ...prev, ...patch };
  if (patch.mirrors) next.mirrors = mergeMirrors(prev.mirrors, patch.mirrors);
  if (patch.versionHistory) next.versionHistory = [...patch.versionHistory, ...(prev.versionHistory ?? [])].slice(0, 20);
  await sql`
    insert into collector_report_meta (report_id, data, updated_at) values (${reportId}, ${JSON.stringify(next)}, now())
    on conflict (report_id) do update set data = excluded.data, updated_at = now()
  `;
}

/** Records that a document was also seen at another URL. */
export async function recordMirror(reportId: string, mirror: ReportMirror): Promise<void> {
  if (isMongoConfigured()) {
    const col = await getThreatIntelCollection();
    const doc = await col.findOne({ docType: "report", id: reportId }, { projection: { _id: 0, mirrors: 1 } });
    if (!doc) return;
    await col.updateOne({ docType: "report", id: reportId }, { $set: { mirrors: mergeMirrors((doc as { mirrors?: ReportMirror[] }).mirrors, [mirror]) } });
    return;
  }
  await mergeLocalReportMeta(reportId, { mirrors: [mirror] });
}

/**
 * The new copy became canonical: mark the older record as a duplicate that points at it, and
 * move its mirrors (plus its own URL) onto the canonical record.
 */
export async function supersedeWithCanonical(oldId: string, newId: string, oldAsMirror: ReportMirror): Promise<void> {
  if (isMongoConfigured()) {
    const col = await getThreatIntelCollection();
    const old = await col.findOne({ docType: "report", id: oldId }, { projection: { _id: 0, mirrors: 1 } });
    const cur = await col.findOne({ docType: "report", id: newId }, { projection: { _id: 0, mirrors: 1 } });
    const mirrors = mergeMirrors((cur as { mirrors?: ReportMirror[] } | null)?.mirrors, [oldAsMirror, ...(((old as { mirrors?: ReportMirror[] } | null)?.mirrors) ?? [])]);
    await col.updateOne({ docType: "report", id: oldId }, { $set: { status: "duplicate", canonicalReportId: newId, updatedAt: new Date().toISOString() } });
    await col.updateOne({ docType: "report", id: newId }, { $set: { mirrors } });
    return;
  }
  const sql = await localSql();
  await sql`update reports set status = 'duplicate' where id = ${oldId}`;
  const oldMeta = await getReportCollectorMeta(oldId);
  await mergeLocalReportMeta(oldId, { canonicalReportId: newId });
  await mergeLocalReportMeta(newId, { mirrors: [oldAsMirror, ...(oldMeta?.mirrors ?? [])] });
}

export type VersionUpdate = {
  reportId: string;
  version: number;
  previous: ReportVersionEntry;
  fields: {
    title: string;
    extractedText: string;
    textHash: string;
    rawHash: string;
    wordCount: number;
    qualityScore: number;
    iocs: unknown[];
    analysis?: unknown;
    extractedEntities?: unknown;
    fingerprints: ReportFingerprints;
    contentType: string;
  };
};

/** Stores a changed document as a new version (the previous hash is kept, nothing is duplicated). */
export async function applyReportVersion(u: VersionUpdate): Promise<void> {
  const now = new Date().toISOString();
  if (isMongoConfigured()) {
    const col = await getThreatIntelCollection();
    const doc = await col.findOne({ docType: "report", id: u.reportId }, { projection: { _id: 0, versionHistory: 1 } });
    const history = [u.previous, ...(((doc as { versionHistory?: ReportVersionEntry[] } | null)?.versionHistory) ?? [])].slice(0, 20);
    const $set: Record<string, unknown> = {
      ...u.fields,
      version: u.version,
      versionHistory: history,
      updatedAt: now,
      contentUpdatedAt: now,
    };
    if (u.fields.analysis === undefined) delete $set.analysis;
    if (u.fields.extractedEntities === undefined) delete $set.extractedEntities;
    await col.updateOne({ docType: "report", id: u.reportId }, { $set });
    return;
  }
  const sql = await localSql();
  await sql`
    update reports set
      title = ${u.fields.title}, extracted_text = ${u.fields.extractedText}, text_hash = ${u.fields.textHash},
      raw_hash = ${u.fields.rawHash}, word_count = ${u.fields.wordCount}, quality_score = ${u.fields.qualityScore},
      iocs_json = ${JSON.stringify(u.fields.iocs)}, content_type = ${u.fields.contentType}, version = ${u.version}
    where id = ${u.reportId}
  `;
  if (u.fields.analysis !== undefined) {
    await sql`update reports set analysis_json = ${JSON.stringify(u.fields.analysis)} where id = ${u.reportId}`;
  }
  await mergeLocalReportMeta(u.reportId, { fingerprints: u.fields.fingerprints, versionHistory: [u.previous] });
}

/** Report id + current hashes for a stored canonical URL (used when revalidating known URLs). */
export async function findStoredReportByCanonical(
  canonicalUrl: string,
): Promise<{ id: string; textHash: string; rawHash: string; version: number; wordCount: number; title: string; ingestedAt: string | null; extractedText: string; normalizedTextHash: string | null } | null> {
  if (isMongoConfigured()) {
    const col = await getThreatIntelCollection();
    const d = await col.findOne(
      { docType: "report", canonicalUrl },
      { projection: { _id: 0, id: 1, textHash: 1, rawHash: 1, version: 1, wordCount: 1, title: 1, ingestedAt: 1, extractedText: 1, "fingerprints.normalizedTextHash": 1 } },
    );
    return d
      ? { id: d.id, textHash: d.textHash, rawHash: d.rawHash, version: Number(d.version ?? 1), wordCount: Number(d.wordCount ?? 0), title: d.title, ingestedAt: d.ingestedAt ?? null, extractedText: d.extractedText ?? "", normalizedTextHash: d.fingerprints?.normalizedTextHash ?? null }
      : null;
  }
  const sql = await localSql();
  const rows = await sql<{ id: string; text_hash: string; raw_hash: string; version: number; word_count: number; title: string; ingested_at: string | null; extracted_text: string; meta: string | null }>`
    select r.id, r.text_hash, r.raw_hash, coalesce(r.version, 1) as version, r.word_count, r.title, r.ingested_at::text as ingested_at,
           r.extracted_text, m.data as meta
    from reports r left join collector_report_meta m on m.report_id = r.id where r.canonical_url = ${canonicalUrl} limit 1
  `;
  const r = rows[0];
  return r
    ? { id: r.id, textHash: r.text_hash, rawHash: r.raw_hash, version: Number(r.version), wordCount: Number(r.word_count), title: r.title, ingestedAt: r.ingested_at, extractedText: r.extracted_text ?? "", normalizedTextHash: parse<ReportCollectorMeta>(r.meta)?.fingerprints?.normalizedTextHash ?? null }
    : null;
}
