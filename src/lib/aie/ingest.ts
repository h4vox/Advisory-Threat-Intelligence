import { getSql } from "@/lib/db";
import { SOURCE_SEED } from "./catalog";
import {
  canonicalizeUrl,
  excerptOf,
  harvestIocs,
  htmlToText,
  MAX_BYTES,
  scoreQuality,
  sha256Hex,
} from "./extract";
import { newId } from "./ids";
import { SEED_REPORTS } from "./seed-reports";
import type {
  IngestEvent,
  IngestOrigin,
  IntelAnalysis,
  IocHit,
  QualityReason,
  ReportListItem,
  ReportRecord,
  SourceRecord,
  TrustLevel,
} from "./types";

export type SourceRow = {
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

export type ReportRow = {
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
  discovery_method: string;
  discovery_query: string;
  parent_source: string;
  publisher: string;
  author: string;
  classification: string;
  source_domain: string;
  analysis_json: string;
  version: number;
};

export type IngestResult =
  | {
      ok: true;
      reportId: string;
      duplicate: boolean;
      updated: boolean;
      qualityScore: number;
      title: string;
      classification: string;
      status: string;
    }
  | { ok: false; error: string };

export const REPORT_SELECT = `
  r.id, r.source_id, s.name as source_name, r.title, r.url, r.canonical_url,
  r.published_at, r.content_type, r.status, r.raw_hash, r.text_hash,
  r.quality_score, r.quality_reasons, r.word_count, r.extracted_text,
  r.iocs_json, r.ingest_origin, r.ingested_at::text as ingested_at,
  coalesce(r.discovery_method, '') as discovery_method,
  coalesce(r.discovery_query, '') as discovery_query,
  coalesce(r.parent_source, '') as parent_source,
  coalesce(r.publisher, '') as publisher,
  coalesce(r.author, '') as author,
  coalesce(r.classification, '') as classification,
  coalesce(r.source_domain, '') as source_domain,
  coalesce(r.analysis_json, '') as analysis_json,
  coalesce(r.version, 1) as version
`;

export function parseJson<T>(raw: string, fallback: T): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function mapSource(r: SourceRow): SourceRecord {
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

function parseAnalysis(raw: string): IntelAnalysis | null {
  if (!raw || raw === "null") return null;
  const parsed = parseJson<IntelAnalysis | null>(raw, null);
  return parsed && typeof parsed === "object" && "method" in parsed ? parsed : null;
}

export function toListItem(r: ReportRow): ReportListItem {
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
    ingestOrigin: r.ingest_origin as IngestOrigin,
    ingestedAt: r.ingested_at,
    excerpt: excerptOf(r.extracted_text),
    iocCount: parseJson<IocHit[]>(r.iocs_json, []).length,
    discoveryMethod: r.discovery_method ?? "",
    discoveryQuery: r.discovery_query ?? "",
    parentSource: r.parent_source ?? "",
    publisher: r.publisher ?? "",
    author: r.author ?? "",
    classification: r.classification ?? "",
    sourceDomain: r.source_domain ?? "",
    version: Number(r.version ?? 1),
  };
}

export function toReport(r: ReportRow): ReportRecord {
  return {
    ...toListItem(r),
    extractedText: r.extracted_text,
    qualityReasons: parseJson<QualityReason[]>(r.quality_reasons, []),
    analysis: parseAnalysis(r.analysis_json),
  };
}

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

export async function ensureSeeded() {
  const sql = await getSql();
  for (const s of SOURCE_SEED) {
    await sql`
      insert into sources (id, name, slug, category, priority, homepage_url, enabled, trust_level, notes)
      values (${s.id}, ${s.name}, ${s.slug}, ${s.category}, ${s.priority}, ${s.homepageUrl}, ${s.enabled}, ${s.trustLevel}, ${s.notes})
      on conflict (id) do nothing
    `;
  }
  const rc = await sql<{ c: number }>`select count(*)::int as c from reports`;
  if (Number(rc[0]?.c ?? 0) === 0) {
    for (const r of SEED_REPORTS) {
      const { score, reasons, wordCount } = scoreQuality(r.text, r.title);
      const iocs = harvestIocs(r.text);
      const rawHash = sha256Hex(r.text);
      const canonical = canonicalizeUrl(r.url);
      await sql`
        insert into reports (
          id, source_id, title, url, canonical_url, published_at, content_type, status,
          raw_hash, text_hash, quality_score, quality_reasons, word_count, extracted_text,
          iocs_json, ingest_origin, source_domain, publisher
        ) values (
          ${r.id}, ${r.sourceId}, ${r.title}, ${r.url}, ${canonical}, ${r.publishedAt},
          ${"text/plain"}, ${"acquired"}, ${rawHash}, ${rawHash}, ${score},
          ${JSON.stringify(reasons)}, ${wordCount}, ${r.text}, ${JSON.stringify(iocs)}, ${"seed"},
          ${hostOf(r.url)}, ${""}
        )
      `;
      await sql`
        insert into ingest_events (id, report_id, url, outcome, detail)
        values (${newId("evt")}, ${r.id}, ${r.url}, ${"seeded"}, ${"Gold-set seed for Phase 1 retrieval"})
      `;
    }
  }
  await sql`insert into crawl_config (id) values (${"default"}) on conflict (id) do nothing`;
}

export async function matchSource(url: string): Promise<string> {
  const sql = await getSql();
  const host = hostOf(url);
  const rows = await sql<SourceRow>`select * from sources`;
  const hit = rows.find((s) => {
    try {
      const srcHost = hostOf(s.homepage_url);
      if (!srcHost || !host) return false;
      return host === srcHost || host.endsWith(`.${srcHost}`) || srcHost.endsWith(`.${host}`);
    } catch {
      return false;
    }
  });
  return hit?.id ?? rows.find((s) => s.slug === "dfir")?.id ?? SOURCE_SEED[0].id;
}

export async function matchOrCreateSource(url: string, publisherHint?: string): Promise<{
  id: string;
  created: boolean;
  name: string;
}> {
  const sql = await getSql();
  const existingId = await matchSource(url);
  const rows = await sql<SourceRow>`select * from sources where id = ${existingId}`;
  const existing = rows[0];
  const host = hostOf(url);
  if (existing && host && hostOf(existing.homepage_url) && (host === hostOf(existing.homepage_url) || host.endsWith(`.${hostOf(existing.homepage_url)}`))) {
    return { id: existing.id, created: false, name: existing.name };
  }
  const slug = host.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || newId("src");
  const dup = await sql<SourceRow>`select * from sources where slug = ${slug}`;
  if (dup[0]) return { id: dup[0].id, created: false, name: dup[0].name };
  const id = newId("src");
  const name = publisherHint?.trim() || host;
  const origin = `https://${host}/`;
  await sql`
    insert into sources (id, name, slug, category, priority, homepage_url, enabled, trust_level, notes)
    values (
      ${id}, ${name}, ${slug}, ${"discovered"}, ${5}, ${origin}, ${false}, ${"community"},
      ${"Auto-discovered publisher. Enable to include in future crawls."}
    )
    on conflict (slug) do nothing
  `;
  const again = await sql<SourceRow>`select * from sources where slug = ${slug}`;
  return { id: again[0]?.id ?? id, created: !dup[0], name: again[0]?.name ?? name };
}

export async function fetchResource(
  url: string,
  opts?: { timeoutMs?: number; userAgent?: string },
): Promise<{
  contentType: string;
  body: string;
  bytes: Uint8Array;
  etag: string | null;
  lastModified: string | null;
  finalUrl: string;
}> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), opts?.timeoutMs ?? 18000);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "user-agent":
          opts?.userAgent ??
          "AIE-Crawler/0.2 (+research; public-cti ingest; respectful; contact: security-research)",
        accept: "text/html,application/xhtml+xml,application/pdf,application/rss+xml,text/xml,text/plain;q=0.9,*/*;q=0.5",
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
    return {
      contentType,
      body,
      bytes: buf,
      etag: res.headers.get("etag"),
      lastModified: res.headers.get("last-modified"),
      finalUrl: res.url || url,
    };
  } finally {
    clearTimeout(t);
  }
}

export type PersistInput = {
  sourceId: string;
  title: string;
  url: string;
  canonical: string;
  publishedAt: string | null;
  contentType: string;
  raw: string | Uint8Array;
  text: string;
  origin: IngestOrigin;
  discoveryMethod?: string;
  discoveryQuery?: string;
  parentSource?: string;
  publisher?: string;
  author?: string;
  classification?: string;
  sourceDomain?: string;
  analysis?: IntelAnalysis | null;
};

export async function persistReport(input: PersistInput): Promise<IngestResult> {
  const sql = await getSql();
  const dup = await sql<{ id: string; text_hash: string; quality_score: number; title: string; version: number }>`
    select id, text_hash, quality_score, title, coalesce(version, 1) as version
    from reports where canonical_url = ${input.canonical}
  `;
  const { score, reasons, wordCount } = scoreQuality(input.text, input.title);
  const status = wordCount < 80 ? "rejected" : "acquired";
  const iocs = harvestIocs(input.text);
  const rawHash = sha256Hex(input.raw);
  const textHash = sha256Hex(input.text);
  const domain = input.sourceDomain || hostOf(input.canonical);
  const analysisJson = input.analysis ? JSON.stringify(input.analysis) : "";

  if (dup[0]) {
    if (dup[0].text_hash === textHash) {
      await sql`
        insert into ingest_events (id, report_id, url, outcome, detail)
        values (${newId("evt")}, ${dup[0].id}, ${input.url}, ${"duplicate"}, ${"Canonical URL already stored"})
      `;
      return {
        ok: true,
        reportId: dup[0].id,
        duplicate: true,
        updated: false,
        qualityScore: Number(dup[0].quality_score),
        title: dup[0].title,
        classification: input.classification ?? "",
        status: "acquired",
      };
    }
    const nextVersion = Number(dup[0].version ?? 1) + 1;
    await sql`
      update reports set
        title = ${input.title},
        url = ${input.url},
        published_at = ${input.publishedAt},
        content_type = ${input.contentType},
        status = ${status},
        raw_hash = ${rawHash},
        text_hash = ${textHash},
        quality_score = ${score},
        quality_reasons = ${JSON.stringify(reasons)},
        word_count = ${wordCount},
        extracted_text = ${input.text},
        iocs_json = ${JSON.stringify(iocs)},
        publisher = ${input.publisher ?? ""},
        author = ${input.author ?? ""},
        classification = ${input.classification ?? ""},
        source_domain = ${domain},
        analysis_json = ${analysisJson || undefined as unknown as string},
        version = ${nextVersion},
        ingested_at = now()
      where id = ${dup[0].id}
    `;
    if (analysisJson) {
      await sql`update reports set analysis_json = ${analysisJson} where id = ${dup[0].id}`;
    }
    await sql`
      insert into ingest_events (id, report_id, url, outcome, detail)
      values (${newId("evt")}, ${dup[0].id}, ${input.url}, ${"updated"}, ${`Content changed · v${nextVersion}`})
    `;
    return {
      ok: true,
      reportId: dup[0].id,
      duplicate: false,
      updated: true,
      qualityScore: score,
      title: input.title,
      classification: input.classification ?? "",
      status,
    };
  }

  const id = newId("rpt");
  await sql`
    insert into reports (
      id, source_id, title, url, canonical_url, published_at, content_type, status,
      raw_hash, text_hash, quality_score, quality_reasons, word_count, extracted_text,
      iocs_json, ingest_origin, discovery_method, discovery_query, parent_source,
      publisher, author, classification, source_domain, analysis_json, version
    ) values (
      ${id}, ${input.sourceId}, ${input.title}, ${input.url}, ${input.canonical},
      ${input.publishedAt}, ${input.contentType}, ${status}, ${rawHash}, ${textHash},
      ${score}, ${JSON.stringify(reasons)}, ${wordCount}, ${input.text},
      ${JSON.stringify(iocs)}, ${input.origin}, ${input.discoveryMethod ?? ""},
      ${input.discoveryQuery ?? ""}, ${input.parentSource ?? ""}, ${input.publisher ?? ""},
      ${input.author ?? ""}, ${input.classification ?? ""}, ${domain}, ${analysisJson}, ${1}
    )
  `;
  await sql`update sources set last_ingest_at = now() where id = ${input.sourceId}`;
  await sql`
    insert into ingest_events (id, report_id, url, outcome, detail)
    values (
      ${newId("evt")}, ${id}, ${input.url}, ${status},
      ${status === "rejected" ? "Below quality threshold" : `quality ${score} · ${wordCount} words`}
    )
  `;
  return {
    ok: true,
    reportId: id,
    duplicate: false,
    updated: false,
    qualityScore: score,
    title: input.title,
    classification: input.classification ?? "",
    status,
  };
}

export async function recordIngestFailure(url: string, message: string) {
  const sql = await getSql();
  await sql`
    insert into ingest_events (id, report_id, url, outcome, detail)
    values (${newId("evt")}, ${null}, ${url}, ${"failed"}, ${message})
  `;
}

export function mapEvent(e: {
  id: string;
  report_id: string | null;
  url: string;
  outcome: string;
  detail: string;
  created_at: string;
}): IngestEvent {
  return {
    id: e.id,
    reportId: e.report_id,
    url: e.url,
    outcome: e.outcome,
    detail: e.detail,
    createdAt: e.created_at,
  };
}

export { htmlToText, canonicalizeUrl, scoreQuality, harvestIocs, sha256Hex };
