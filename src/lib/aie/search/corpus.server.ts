/**
 * Library corpus for intelligence search and chat grounding, in both storage
 * modes:
 *   - MongoDB: candidate retrieval ($text over the alias-expanded query,
 *     entity-field regexes per alias, exact CVE / ATT&CK ids), then re-ranking.
 *   - Local SQL fallback: every stored report, scored in memory.
 *
 * Server-only.
 */
import { getSql } from "@/lib/db";
import { isMongoConfigured } from "../../mongodb/client.server";
import { mongoSearchIntelCandidates } from "../../mongodb/repository.server";
import { excerptOf } from "../extract";
import { selectPassages, type Passage } from "../retrieval";
import type { IntelAnalysis, IocHit, ReportListItem } from "../types";
import { runSearch } from "./engine";
import { expansionText, understandQuery } from "./query";
import type { ScoredDoc } from "./rank";
import { prepareReport, type ReportLike } from "./report-docs";
import type { InterpretedQuery, ResultWhy } from "./types";

type LocalRow = {
  id: string;
  source_id: string;
  source_name: string | null;
  title: string;
  url: string;
  canonical_url: string;
  published_at: string | null;
  content_type: string;
  status: string;
  raw_hash: string;
  text_hash: string;
  quality_score: number;
  word_count: number;
  extracted_text: string;
  iocs_json: string;
  ingest_origin: string;
  ingested_at: string;
  publisher: string | null;
  author: string | null;
  classification: string | null;
  discovery_method: string | null;
  source_domain: string | null;
  version: number | null;
  analysis_json: string | null;
};

function parseJson<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

/** A stored report with the fields search ranks on plus the list-item fields the library renders. */
export type CorpusReport = ReportLike & { listItem: ReportListItem };

function localToReport(r: LocalRow): CorpusReport {
  const iocs = parseJson<IocHit[]>(r.iocs_json, []);
  const analysis = parseJson<IntelAnalysis | null>(r.analysis_json, null);
  const publisher = r.publisher ?? r.source_name ?? "";
  const listItem: ReportListItem = {
    id: r.id,
    sourceId: r.source_id,
    sourceName: r.source_name ?? publisher,
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
    iocs,
    ingestOrigin: r.ingest_origin as ReportListItem["ingestOrigin"],
    ingestedAt: r.ingested_at,
    excerpt: excerptOf(r.extracted_text ?? ""),
    iocCount: iocs.length,
    publisher,
    author: r.author ?? publisher,
    classification: r.classification ?? "THREAT_REPORT",
    discoveryMethod: r.discovery_method ?? "manual",
    discoveryQuery: "",
    parentSource: "",
    sourceDomain: r.source_domain ?? "",
    version: Number(r.version ?? 1),
    rawHtml: "",
    pdfUrl: "",
    analysis,
  };
  return {
    id: r.id,
    title: r.title,
    extractedText: r.extracted_text ?? "",
    url: r.url,
    canonicalUrl: r.canonical_url,
    publisher,
    sourceName: r.source_name ?? undefined,
    sourceId: r.source_id,
    publishedAt: r.published_at,
    qualityScore: Number(r.quality_score),
    analysis,
    iocs,
    classification: r.classification ?? undefined,
    textHash: r.text_hash,
    status: r.status,
    version: Number(r.version ?? 1),
    listItem,
  };
}

function mongoToReport(d: Record<string, any>): CorpusReport {
  const text = String(d.extractedText ?? "");
  const iocs = Array.isArray(d.iocs) ? (d.iocs as IocHit[]) : [];
  const publisher = String(d.publisher || d.sourceName || "");
  const listItem = {
    ...d,
    id: String(d.id),
    sourceName: d.sourceName || publisher,
    publisher,
    excerpt: d.excerpt || excerptOf(text),
    iocs,
    iocCount: iocs.length,
    qualityScore: Number(d.qualityScore ?? 0),
    wordCount: Number(d.wordCount ?? 0),
    classification: d.classification || "THREAT_REPORT",
    rawHtml: "",
    pdfBase64: "",
    extractedText: undefined,
    qualityReasons: undefined,
    analysis: (d.analysis as IntelAnalysis) ?? null,
  } as unknown as ReportListItem;
  return {
    id: String(d.id),
    title: String(d.title ?? "Untitled report"),
    extractedText: text,
    excerpt: d.excerpt,
    url: d.url,
    canonicalUrl: d.canonicalUrl,
    publisher,
    sourceName: d.sourceName,
    sourceId: d.sourceId,
    publishedAt: d.publishedAt ?? null,
    qualityScore: Number(d.qualityScore ?? 0),
    analysis: d.analysis ?? null,
    extractedEntities: d.extractedEntities,
    iocs,
    docTypes: Array.isArray(d.docTypes) ? d.docTypes : undefined,
    sourceTier: d.sourceTier,
    sourceConfidence: d.sourceConfidence,
    structured: d.structured,
    classification: d.classification,
    resourceKind: d.resourceKind,
    textHash: d.textHash,
    status: d.status,
    version: Number(d.version ?? 1),
    listItem,
  };
}

let localCache: { at: number; rows: CorpusReport[] } | null = null;
const LOCAL_TTL_MS = 15_000;

async function loadLocalReports(): Promise<CorpusReport[]> {
  if (localCache && Date.now() - localCache.at < LOCAL_TTL_MS) return localCache.rows;
  const sql = await getSql();
  const rows = await sql.query<LocalRow>(
    `select r.id, r.source_id, s.name as source_name, r.title, r.url, r.canonical_url, r.published_at, r.content_type,
            r.status, r.raw_hash, r.text_hash, r.quality_score, r.word_count, r.extracted_text, r.iocs_json,
            r.ingest_origin, r.ingested_at::text as ingested_at, r.publisher, r.author, r.classification,
            r.discovery_method, r.source_domain, r.version, r.analysis_json
       from reports r left join sources s on s.id = r.source_id
      where r.status not in ('rejected', 'duplicate')
      order by r.ingested_at desc
      limit 2000`,
  );
  const mapped = rows.map(localToReport);
  localCache = { at: Date.now(), rows: mapped };
  return mapped;
}

export function invalidateLocalSearchCache() {
  localCache = null;
}

export type Corpus = {
  persistence: "mongodb" | "local";
  reports: CorpusReport[];
};

/** Loads the reports to rank for a query (all local reports, or Mongo candidates). */
export async function loadCorpus(iq: InterpretedQuery, opts: { ensureLocal?: () => Promise<void>; limit?: number } = {}): Promise<Corpus> {
  if (isMongoConfigured()) {
    const docs = await mongoSearchIntelCandidates({
      text: expansionText(iq),
      aliases: iq.entities.filter((e) => !e.negated).flatMap((e) => e.aliases),
      cves: iq.cves,
      techniques: iq.techniques.filter((t) => !t.negated).flatMap((t) => [t.id, ...t.related]),
      filterOnly: iq.filterOnly,
      limit: opts.limit,
    });
    return { persistence: "mongodb", reports: docs.map((d) => mongoToReport(d as Record<string, any>)) };
  }
  if (opts.ensureLocal) await opts.ensureLocal();
  return { persistence: "local", reports: await loadLocalReports() };
}

// ---------------------------------------------------------------------------
// Chat grounding
// ---------------------------------------------------------------------------

export type ChatCandidate = {
  id: string;
  title: string;
  publisher: string;
  sourceName: string;
  url: string;
  canonicalUrl: string;
  publishedAt: string | null;
  extractedText: string;
  score: number;
  matchedBy: "text" | "exact_id" | "regex";
};

export type PassageWhy = {
  sid: string;
  reportId: string;
  docRank: number;
  docScore: number;
  passageScore: number;
  matchedTerms: string[];
  matchedEntities: Array<{ name: string; id: string; via: string }>;
  matchedTechniques: string[];
  reason: string;
};

export type ChatRetrieval = {
  interpreted: { summary: string; chips: string[]; expansion: string };
  candidates: ChatCandidate[];
  passages: Passage[];
  why: PassageWhy[];
  persistence: "mongodb" | "local";
};

/**
 * Hybrid retrieval for the AI agent chat: interpret the question (aliases,
 * technique names), rank library reports with the hybrid ranker, then select
 * BM25 passages from the top reports using the alias-expanded query. Each
 * passage carries why it was chosen.
 */
export async function retrieveForChat(question: string, opts: { ensureLocal?: () => Promise<void>; k?: number; perDoc?: number } = {}): Promise<ChatRetrieval> {
  const iq = understandQuery(question.slice(0, 500));
  const corpus = await loadCorpus(iq, { ensureLocal: opts.ensureLocal, limit: 60 });
  const byId = new Map(corpus.reports.map((r) => [r.id, r]));
  const out = runSearch(corpus.reports.map(prepareReport), iq, { group: "reports", limit: 1, includeKnowledge: false });
  const top: ScoredDoc[] = out.rankedReports.slice(0, 12);
  const expansion = expansionText(iq);
  // Passage query: the question, the aliases of recognised entities, and technique names.
  const passageQuery = `${question}\n${expansion}`.slice(0, 2000);
  const passages = selectPassages(
    top.map((s) => {
      const r = byId.get(s.prepared.doc.id)!;
      return {
        id: r.id,
        title: r.title,
        text: String(r.extractedText ?? ""),
        meta: { publisher: r.publisher || r.sourceName || "", publishedAt: r.publishedAt ?? "" },
      };
    }),
    passageQuery,
    { k: opts.k ?? 8, perDoc: opts.perDoc ?? 2 },
  );
  const rankOf = new Map(top.map((s, i) => [s.prepared.doc.id, { rank: i + 1, s }]));
  const why: PassageWhy[] = passages.map((p, i) => {
    const info = rankOf.get(p.docId);
    const w: ResultWhy | undefined = info?.s.why;
    const ents = (w?.matchedEntities ?? []).map((e) => ({ name: e.name, id: e.id, via: e.via }));
    const lowerText = p.text.toLowerCase();
    const inPassage = ents.filter((e) => lowerText.includes(e.via.toLowerCase()) || lowerText.includes(e.name.toLowerCase()));
    const techs = (w?.matchedTechniques ?? [])
      .filter((t) => lowerText.includes(t.id.toLowerCase()) || lowerText.includes((t.name.split(": ").pop() ?? t.name).toLowerCase()))
      .map((t) => t.id);
    const reasonParts = [
      `report ranked #${info?.rank ?? "?"} (score ${info?.s.adjusted ?? info?.s.score ?? 0})`,
      inPassage.length ? `passage names ${inPassage.map((e) => (e.via !== e.name ? `${e.via} (= ${e.name} ${e.id})` : `${e.name} ${e.id}`)).join(", ")}` : "",
      techs.length ? `passage covers ${techs.join(", ")}` : "",
      p.matched.length ? `matched terms ${p.matched.slice(0, 8).join(", ")}` : "",
    ].filter(Boolean);
    return {
      sid: `S${i + 1}`,
      reportId: p.docId,
      docRank: info?.rank ?? 0,
      docScore: info?.s.adjusted ?? info?.s.score ?? 0,
      passageScore: p.score,
      matchedTerms: p.matched,
      matchedEntities: inPassage,
      matchedTechniques: techs,
      reason: reasonParts.join("; "),
    };
  });
  const candidates: ChatCandidate[] = top.map((s) => {
    const r = byId.get(s.prepared.doc.id)!;
    return {
      id: r.id,
      title: r.title,
      publisher: r.publisher || "",
      sourceName: r.sourceName || r.publisher || "",
      url: r.url || "",
      canonicalUrl: r.canonicalUrl || r.url || "",
      publishedAt: r.publishedAt ?? null,
      extractedText: String(r.extractedText ?? ""),
      score: s.adjusted ?? s.score,
      matchedBy: s.why.matchedIds.length ? "exact_id" : "text",
    };
  });
  return {
    interpreted: { summary: iq.summary, chips: iq.chips.map((c) => `${c.label}${c.detail ? ` (${c.detail})` : ""}`), expansion },
    candidates,
    passages,
    why,
    persistence: corpus.persistence,
  };
}

