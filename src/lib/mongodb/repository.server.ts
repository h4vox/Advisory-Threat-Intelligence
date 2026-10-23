import type { Filter, Document } from "mongodb";
import { decryptConfigSecrets, encryptConfigSecrets } from "../aie/secret-box.server";
import { getCollectionName, getDatabaseName, getThreatIntelCollection, isMongoConfigured } from "./client.server";
import type {
  AppSettings,
  EmulationOption,
  CrawlConfig,
  CrawlJob,
  CrawlJobItem,
  CrawlerState,
  DashboardStats,
  DiscoveredResource,
  ExtractedEntities,
  IngestEvent,
  IntelAnalysis,
  IocHit,
  QualityReason,
  ReportListItem,
  ReportRecord,
  ResourceKind,
  SourceRecord,
  StorageStats,
  TrustLevel,
  DiscoveredSourceRecord,
  DiscoveryGraphEdge,
  ThreatRegionStats,
  TacticDistributionStats,
} from "../aie/types";
import { DEFAULT_APP_SETTINGS } from "../aie/types";
import { computeDashboardAnalytics } from "../aie/dashboard-analytics";
import { computeReportSimHash, excerptOf } from "../aie/extract";
import { logger } from "../aie/logger";
import { SOURCE_SEED } from "../aie/catalog";
import type { IntegrationItem, MarketplaceState } from "../aie/marketplace-types";
import {
  DEFAULT_INTEGRATIONS,
  DEFAULT_CURATED_RESOURCES,
  DEFAULT_POWERUPS,
  DEFAULT_PLAYBOOKS,
} from "../aie/marketplace-registry";
import { runUnifiedResourceEvaluation } from "../aie/ai-manager";
import { isCandidateResourceUrl } from "../aie/qualification";
import { sanitizeAgyModel, DEFAULT_AGY_MODEL } from "../aie/agent-framework/types";
import { resolveActiveModel } from "../aie/active-model";
import { excerptAround, extractExactIds, queryTerms, selectPassages } from "../aie/retrieval";

let indexesEnsured = false;
let indexesPromise: Promise<void> | null = null;

// High-speed in-memory caches (invalidated on write)
let cachedReportsList: { timestamp: number; data: ReportListItem[] } | null = null;
const CACHE_TTL_MS = 60_000;

let cachedDashboardStats: { timestamp: number; data: DashboardStats } | null = null;
const DASHBOARD_CACHE_TTL_MS = 25_000;

let cachedStorageStats: { timestamp: number; data: StorageStats } | null = null;
const STORAGE_STATS_CACHE_TTL_MS = 15_000;

let cachedCrawlConfig: { timestamp: number; data: CrawlConfig } | null = null;
const CONFIG_CACHE_TTL_MS = 60_000;

let cachedAppSettings: { timestamp: number; data: AppSettings } | null = null;
const SETTINGS_CACHE_TTL_MS = 60_000;

// Local fallback for app settings when MONGODB_URI is not set (mirrors memoryIntegrations). Holds
// the active AI provider and model so the marketplace and model selection work without MongoDB;
// resets on restart, like the rest of the no-Mongo path.
let memoryAppSettings: AppSettings = { ...DEFAULT_APP_SETTINGS };

// Checker registries, registered by the crawler to avoid a circular import. Kept on globalThis so a
// dev reload of either module (Vite re-evaluates it after an edit or pull) keeps one shared view of
// which jobs this process is running; a reset registry made the watchdog finalize live jobs.
const registries = globalThis as typeof globalThis & {
  __aieJobActiveCheck?: (jobId: string) => boolean;
  __aieScheduleCheck?: () => Promise<any>;
};

export function registerJobActiveChecker(fn: (jobId: string) => boolean) {
  registries.__aieJobActiveCheck = fn;
}

export function isJobActive(jobId: string): boolean {
  return registries.__aieJobActiveCheck ? registries.__aieJobActiveCheck(jobId) : false;
}

/**
 * Why a crawl-job record still marked "running" can be finalized by a watchdog, or null to leave it.
 * A job this process is running is never touched: it finalizes itself (with its real counts) and the
 * crawler releases it if it hangs. Finalizing a live job also made it cancel itself and lose its counts.
 */
export function staleRunningJobReason(job: { id: string; startedAt?: string | null }, nowMs: number, maxRunMs: number): "expired" | "orphaned" | null {
  if (isJobActive(job.id)) return null;
  const elapsedMs = nowMs - (job.startedAt ? new Date(job.startedAt).getTime() : 0);
  if (elapsedMs > maxRunMs + 30 * 1000) return "expired";
  if (elapsedMs > 60 * 1000) return "orphaned";
  return null;
}

export function registerScheduleChecker(fn: () => Promise<any>) {
  registries.__aieScheduleCheck = fn;
}

let lastScheduleCheckTimestamp = 0;
export function triggerScheduleCheck() {
  const now = Date.now();
  if (now - lastScheduleCheckTimestamp < 30_000) return;
  lastScheduleCheckTimestamp = now;
  const scheduleCheckFn = registries.__aieScheduleCheck;
  if (scheduleCheckFn) {
    void scheduleCheckFn().catch((err) => {
      console.warn("[scheduler-hook] triggerScheduleCheck error:", err);
    });
  }
}

let cachedCrawlerState: { timestamp: number; data: CrawlerState } | null = null;
const CRAWLER_STATE_IDLE_TTL_MS = 20_000; // 20s TTL when idle: 0ms responses without hammering DB
const CRAWLER_STATE_ACTIVE_TTL_MS = 3_000; // 3s TTL when active job is running

let cachedTelemetrySummary: {
  timestamp: number;
  data: {
    sourceStats: { sourceName: string; found: number; ingested: number; failed: number }[];
    totalDiscovered: number;
    totalSources: number;
    totalJobs: number;
    totalGraphEdges: number;
  };
} | null = null;
const TELEMETRY_SUMMARY_TTL_MS = 25_000; // 25s TTL for heavy counts and aggregations

let cachedDiscoveredSources: { timestamp: number; data: DiscoveredSourceRecord[] } | null = null;
const DISCOVERED_SOURCES_CACHE_TTL_MS = 30_000; // 30s TTL: avoid running 3 heavy aggregations every poll

export function invalidateReportsCache() {
  cachedReportsList = null;
  logger.cache("INVALIDATE", "reports-list", "Cleared in-memory reports cache");
}

export function invalidateDashboardCache() {
  cachedDashboardStats = null;
  cachedStorageStats = null;
  logger.cache("INVALIDATE", "dashboard-stats", "Cleared in-memory dashboard cache");
}

export function invalidateConfigCache() {
  cachedCrawlConfig = null;
  logger.cache("INVALIDATE", "crawl-config", "Cleared in-memory crawl config cache");
}

export function invalidateSettingsCache() {
  cachedAppSettings = null;
  cachedStorageStats = null;
  logger.cache("INVALIDATE", "app-settings", "Cleared in-memory app settings cache");
}

let lastKnownGoodCrawlerState: CrawlerState | null = null;

let lastCrawlerInvalidateTime = 0;
let crawlerInvalidateDebounceTimer: NodeJS.Timeout | null = null;

export function invalidateCrawlerStateCache(force = false) {
  const now = Date.now();
  if (force || now - lastCrawlerInvalidateTime > 1200) {
    lastCrawlerInvalidateTime = now;
    if (crawlerInvalidateDebounceTimer) {
      clearTimeout(crawlerInvalidateDebounceTimer);
      crawlerInvalidateDebounceTimer = null;
    }
    if (cachedCrawlerState) {
      cachedCrawlerState.timestamp = 0;
    }
    cachedDiscoveredSources = null;
    cachedTelemetrySummary = null;
    cachedStorageStats = null;
    logger.cache("INVALIDATE", "crawler-state", "Marked in-memory crawler state cache as stale");
  } else if (!crawlerInvalidateDebounceTimer) {
    crawlerInvalidateDebounceTimer = setTimeout(() => {
      crawlerInvalidateDebounceTimer = null;
      lastCrawlerInvalidateTime = Date.now();
      if (cachedCrawlerState) {
        cachedCrawlerState.timestamp = 0;
      }
      cachedDiscoveredSources = null;
      cachedTelemetrySummary = null;
      cachedStorageStats = null;
      logger.cache("INVALIDATE", "crawler-state", "Marked in-memory crawler state cache as stale (coalesced)");
    }, 1200);
  }
}

export function purgeAllServerCaches() {
  cachedReportsList = null;
  cachedDashboardStats = null;
  cachedStorageStats = null;
  cachedCrawlConfig = null;
  cachedAppSettings = null;
  cachedCrawlerState = null;
  cachedDiscoveredSources = null;
  cachedTelemetrySummary = null;
  logger.cache("INVALIDATE", "all", "Flushed all in-memory server caches");
  return {
    reportsCleared: true,
    dashboardCleared: true,
    configCleared: true,
    settingsCleared: true,
    crawlerStateCleared: true,
    timestamp: new Date().toISOString(),
  };
}

export async function ensureMongoIndexes() {
  if (indexesEnsured || !isMongoConfigured()) return;
  if (indexesPromise) return indexesPromise;

  indexesPromise = (async () => {
    try {
      const col = await getThreatIntelCollection();
      await col.createIndexes([
        { key: { docType: 1, id: 1 }, unique: true, background: true },
        {
          key: { docType: 1, canonicalUrl: 1 },
          unique: true,
          partialFilterExpression: { docType: "report", canonicalUrl: { $type: "string" } },
          background: true,
        },
        { key: { docType: 1, ingestedAt: -1 }, background: true },
        { key: { docType: 1, classification: 1 }, background: true },
        { key: { docType: 1, resourceKind: 1 }, background: true },
        { key: { docType: 1, status: 1 }, background: true },
        { key: { docType: 1, status: 1, ingestedAt: -1 }, background: true },
        { key: { docType: 1, status: 1, qualityScore: -1 }, background: true },
        { key: { docType: 1, classification: 1, ingestedAt: -1 }, background: true },
        { key: { docType: 1, resourceKind: 1, ingestedAt: -1 }, background: true },
        { key: { docType: 1, priority: 1 }, background: true },
        { key: { docType: 1, createdAt: -1 }, background: true },
        { key: { docType: 1, domain: 1 }, background: true },
        { key: { docType: 1, publisher: 1, decision: 1 }, background: true },
        { key: { docType: 1, from: 1, to: 1, relationship: 1 }, background: true },
        { key: { docType: 1, status: 1, createdAt: -1 }, background: true },
      ]);

      // Ensure Full-Text Search index across content, titles, attack chains, and TTPs
      try {
        await col.createIndex(
          {
            title: "text",
            extractedText: "text",
            "analysis.threatActors": "text",
            "analysis.malware": "text",
            "extractedEntities.cves": "text",
            "extractedEntities.techniques": "text",
            "analysis.attackChain.summary": "text",
          },
          {
            weights: {
              title: 10,
              "analysis.threatActors": 8,
              "analysis.malware": 8,
              "extractedEntities.cves": 8,
              "extractedEntities.techniques": 7,
              "analysis.attackChain.summary": 6,
              extractedText: 2,
            },
            name: "threat_intel_fulltext_search_index",
            background: true,
          }
        );
      } catch (textIdxErr) {
        // May already exist with compatible or existing schema (an older
        // definition keeps working; search queries do not depend on its name).
        console.debug("[mongodb] Full-text index check:", (textIdxErr as Error).message);
      }

      // Per-user chat history lookups (sessions are scoped by userId).
      try {
        await col.createIndex(
          { docType: 1, userId: 1, sessionId: 1, createdAt: -1 },
          { name: "agent_chat_user_session", background: true, partialFilterExpression: { docType: "agent_chat_message" } },
        );
      } catch (chatIdxErr) {
        console.debug("[mongodb] Chat index check:", (chatIdxErr as Error).message);
      }

      indexesEnsured = true;
    } catch (err) {
      console.warn("[mongodb] failed ensuring indexes:", err);
    } finally {
      indexesPromise = null;
    }
  })();

  return indexesPromise;
}

// ---------------------------------------------------------------------------
// Report CRUD
// ---------------------------------------------------------------------------

export async function mongoGetReportById(id: string): Promise<ReportRecord | null> {
  const startTime = Date.now();
  const col = await getThreatIntelCollection();
  let doc = await col.findOne({ docType: "report", id: id.trim() });

  if (!doc) {
    // Normalised exact match first (case / "report-" prefix variants), then a
    // strictly anchored prefix match. Never an unanchored regex: that let a
    // short or crafted id resolve to an arbitrary report via a collection scan.
    const cleanId = id.trim().toLowerCase();
    const hexPart = cleanId.replace(/^(rpt[-_]|report[-_])/i, "").replace(/[^a-f0-9]/g, "");
    if (hexPart.length > 0) {
      doc = await col.findOne({
        docType: "report",
        id: { $in: [cleanId, `rpt_${hexPart}`] },
      });
    }
    if (!doc && hexPart.length >= 8) {
      // hexPart only contains [a-f0-9], so it is regex-safe; escape anyway.
      const escaped = hexPart.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const candidates = await col
        .find({ docType: "report", id: { $regex: `^rpt_${escaped}` } })
        .limit(2)
        .toArray();
      doc = candidates.length === 1 ? candidates[0] : null;
    }
  }

  logger.mongo(
    "findOne",
    "threat-intel",
    Date.now() - startTime,
    doc ? `found report "${doc.title}" (${id})` : `report ${id} not found`,
  );
  if (!doc) return null;

  return {
    id: doc.id,
    sourceId: doc.sourceId,
    sourceName: doc.sourceName || doc.publisher || "Verified Source",
    title: doc.title,
    url: doc.url,
    canonicalUrl: doc.canonicalUrl,
    publishedAt: doc.publishedAt ?? null,
    contentType: doc.contentType || "text/html",
    status: doc.status || "acquired",
    rawHash: doc.rawHash,
    textHash: doc.textHash,
    qualityScore: Number(doc.qualityScore ?? 0),
    qualityReasons: (doc.qualityReasons as QualityReason[]) || [],
    wordCount: Number(doc.wordCount ?? 0),
    extractedText: doc.extractedText || "",
    iocs: (doc.iocs as IocHit[]) || [],
    ingestOrigin: doc.ingestOrigin || "crawl",
    ingestedAt: doc.ingestedAt,
    publisher: doc.publisher || doc.sourceName,
    author: doc.author || doc.publisher,
    classification: doc.classification || "THREAT_REPORT",
    resourceKind: (doc.resourceKind as ResourceKind) || "CAMPAIGN_INTEL",
    extractedEntities: (doc.extractedEntities as ExtractedEntities) || undefined,
    discoveryMethod: doc.discoveryMethod || "manual",
    discoveryQuery: doc.discoveryQuery || "",
    parentSource: doc.parentSource || "",
    sourceDomain: doc.sourceDomain || "",
    version: Number(doc.version ?? 1),
    rawHtml: doc.rawHtml || "",
    pdfUrl: doc.pdfUrl || "",
    pdfBase64: doc.pdfBase64 || "",
    analysis: (doc.analysis as IntelAnalysis) || null,
    scoreBreakdown: doc.scoreBreakdown,
    simulationScore: typeof doc.simulationScore === "number" ? doc.simulationScore : undefined,
    isEmergingTechnique: Boolean(doc.isEmergingTechnique),
    noveltyRationale: (doc.noveltyRationale as string) || undefined,
    tags: Array.isArray(doc.tags) && doc.tags.length > 0 ? doc.tags : deriveReportTags(doc as any),
    aiVerified: doc.aiVerified === true,
    aiQualityScore: typeof doc.aiQualityScore === "number" ? doc.aiQualityScore : undefined,
    aiAuditReason: (doc.aiAuditReason as string) || undefined,
  };
}

export async function mongoFindReportByCanonical(canonicalUrl: string): Promise<ReportRecord | null> {
  const col = await getThreatIntelCollection();
  const doc = await col.findOne({ docType: "report", canonicalUrl });
  if (!doc) return null;
  return mongoGetReportById(doc.id);
}

export function deriveReportTags(report: any): string[] {
  const tagsSet = new Set<string>();
  if (report.publisher && report.publisher !== "Unknown Publisher") tagsSet.add(report.publisher);
  if (report.sourceName && report.sourceName !== "Verified Source" && report.sourceName !== report.publisher) {
    tagsSet.add(report.sourceName);
  }
  if (report.classification) {
    tagsSet.add(String(report.classification).toUpperCase().replace(/\s+/g, "_"));
  }
  if (report.resourceKind) {
    tagsSet.add(String(report.resourceKind));
  }
  const actors = report.analysis?.threatActors || report.extractedEntities?.threatActors;
  if (Array.isArray(actors)) {
    for (const a of actors) {
      if (a && a !== "None Identified") tagsSet.add(String(a).trim());
    }
  }
  const malware = report.analysis?.malware || report.extractedEntities?.malwareFamilies;
  if (Array.isArray(malware)) {
    for (const m of malware) {
      if (m && m !== "None Identified") tagsSet.add(String(m).trim());
    }
  }
  const cves = report.extractedEntities?.cves;
  if (Array.isArray(cves)) {
    for (const c of cves) {
      if (c) tagsSet.add(String(c).toUpperCase().trim());
    }
  }
  const techniques = report.extractedEntities?.techniques;
  if (Array.isArray(techniques)) {
    for (const t of techniques.slice(0, 5)) {
      if (t?.id) tagsSet.add(String(t.id).toUpperCase().trim());
    }
  }
  const attackChain = report.analysis?.attackChain;
  if (Array.isArray(attackChain)) {
    for (const step of attackChain) {
      if (Array.isArray(step.techniques)) {
        for (const tech of step.techniques.slice(0, 3)) {
          if (tech) tagsSet.add(String(tech).toUpperCase().trim());
        }
      }
    }
  }
  return Array.from(tagsSet).slice(0, 15);
}

// ---------------------------------------------------------------------------
// Search helpers (weighted $text index + exact identifier matches)
// ---------------------------------------------------------------------------

/**
 * Build a `$text: { $search }` string from free text. Quotes and leading
 * hyphens are stripped so user input cannot form phrase or negation operators.
 */
function toMongoTextSearch(query: string): string {
  const terms = queryTerms(query)
    .map((t) => t.replace(/["\\]/g, "").replace(/^-+/, ""))
    .filter(Boolean)
    .slice(0, 24);
  return terms.length > 0 ? terms.join(" ") : query.replace(/["\\]/g, " ").replace(/(^|\s)-+/g, "$1").slice(0, 200);
}

function exactIdClauses(query: string): Filter<Document>[] {
  const { cves, techniques } = extractExactIds(query);
  const clauses: Filter<Document>[] = [];
  if (cves.length > 0) {
    clauses.push({ "extractedEntities.cves": { $in: cves } }, { "analysis.vulnerabilities": { $in: cves } });
  }
  if (techniques.length > 0) {
    clauses.push(
      { "extractedEntities.techniques.id": { $in: techniques } },
      { "extractedEntities.techniques": { $in: techniques } },
      { "analysis.ttps": { $in: techniques } },
    );
  }
  return clauses;
}

async function findReportsByExactIds(
  col: Awaited<ReturnType<typeof getThreatIntelCollection>>,
  baseFilter: Filter<Document>,
  query: string,
  projection: Record<string, unknown>,
  limit: number,
): Promise<Document[]> {
  const clauses = exactIdClauses(query);
  if (clauses.length === 0) return [];
  const filter: Filter<Document> = {
    ...baseFilter,
    $and: [...((baseFilter.$and as Filter<Document>[]) ?? []), { $or: clauses }],
  };
  return col.find(filter).project(projection).sort({ ingestedAt: -1 }).limit(limit).toArray();
}

function dedupeDocs(docs: Document[]): Document[] {
  const seen = new Set<string>();
  const out: Document[] = [];
  for (const d of docs) {
    const key = String(d.id ?? d._id);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(d);
  }
  return out;
}

export async function mongoListReports(params?: {
  q?: string;
  classification?: string;
  resourceKind?: string;
  sourceId?: string;
  actor?: string;
  malware?: string;
  tactic?: string;
  publisher?: string;
  minScore?: number;
  hasIocs?: boolean;
  limit?: number;
  offset?: number;
}): Promise<ReportListItem[]> {
  // Paging params do not change which documents match; the default (unfiltered)
  // list is cached in full and sliced per request.
  const isDefaultQuery =
    !params ||
    Object.entries(params).every(
      ([k, v]) => k === "limit" || k === "offset" || v === undefined || v === "" || v === "ALL" || v === false,
    );
  const pageLimit = typeof params?.limit === "number" && params.limit > 0 ? Math.floor(params.limit) : undefined;
  const pageOffset = typeof params?.offset === "number" && params.offset > 0 ? Math.floor(params.offset) : 0;
  const slicePage = (rows: ReportListItem[]) =>
    pageLimit !== undefined ? rows.slice(pageOffset, pageOffset + pageLimit) : rows.slice(pageOffset);

  if (isDefaultQuery && cachedReportsList && Date.now() - cachedReportsList.timestamp < CACHE_TTL_MS) {
    logger.mongo(
      "listReports",
      "threat-intel",
      0,
      `Returned ${cachedReportsList.data.length} cached intelligence reports`,
      true,
    );
    return slicePage(cachedReportsList.data);
  }

  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();

  // Superseded copies (status "duplicate") are linked to their canonical report and stay out of listings.
  const filter: Filter<Document> = { docType: "report", status: { $ne: "duplicate" } };
  const andConditions: Filter<Document>[] = [];

  if (params?.classification && params.classification !== "ALL") {
    andConditions.push({ classification: params.classification });
  }

  if (params?.resourceKind && params.resourceKind !== "ALL") {
    const rk = params.resourceKind;
    if (rk === "FULL_ATTACK_CHAIN") {
      andConditions.push({
        $or: [
          { resourceKind: "FULL_ATTACK_CHAIN" },
          { classification: { $in: ["FULL_ATTACK_CHAIN", "ATTACK_CHAIN_REPORT", "INTRUSION_REPORT"] } },
          { "analysis.attackChain.0": { $exists: true } },
        ],
      });
    } else if (rk === "CAMPAIGN_INTEL") {
      andConditions.push({
        $or: [
          { resourceKind: "CAMPAIGN_INTEL" },
          { classification: { $in: ["CAMPAIGN_INTEL", "THREAT_REPORT", "CAMPAIGN_REPORT", "GENERIC_NEWS"] } },
        ],
      });
    } else if (rk === "PROCEDURE_DEEPDIVE") {
      andConditions.push({
        $or: [
          { resourceKind: "PROCEDURE_DEEPDIVE" },
          { classification: { $in: ["PROCEDURE_DEEPDIVE", "ADVERSARY_EMULATION", "PURPLE_TEAM", "TTP_DEEPDIVE"] } },
          { "analysis.emulation.0": { $exists: true } },
        ],
      });
    } else if (rk === "MALWARE_ANALYSIS") {
      andConditions.push({
        $or: [
          { resourceKind: "MALWARE_ANALYSIS" },
          { classification: "MALWARE_ANALYSIS" },
          { "analysis.malware.0": { $exists: true } },
        ],
      });
    } else if (rk === "DETECTION_GUIDANCE") {
      andConditions.push({
        $or: [
          { resourceKind: "DETECTION_GUIDANCE" },
          { classification: { $in: ["DETECTION_GUIDANCE", "DETECTION_RESEARCH", "SIGMA_RULES"] } },
          { "analysis.detections.0": { $exists: true } },
        ],
      });
    } else if (rk === "VULNERABILITY_ADVISORY") {
      andConditions.push({
        $or: [
          { resourceKind: "VULNERABILITY_ADVISORY" },
          { classification: { $in: ["VULNERABILITY_ADVISORY", "VULNERABILITY_REPORT", "CVE_EXPLOIT"] } },
          { "extractedEntities.cves.0": { $exists: true } },
        ],
      });
    } else if (rk === "THREAT_ACTOR_DOSSIER") {
      andConditions.push({
        $or: [
          { resourceKind: "THREAT_ACTOR_DOSSIER" },
          { classification: "THREAT_ACTOR_REPORT" },
          { "analysis.threatActors.0": { $exists: true } },
        ],
      });
    } else {
      andConditions.push({ resourceKind: rk });
    }
  }

  if (params?.sourceId && params.sourceId !== "ALL") {
    andConditions.push({ sourceId: params.sourceId });
  }

  if (params?.actor) {
    const actorRegex = new RegExp(params.actor.trim().slice(0, 120).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    andConditions.push({
      $or: [
        { "analysis.threatActors": { $regex: actorRegex } },
        { "extractedEntities.threatActors": { $regex: actorRegex } },
      ],
    });
  }

  if (params?.malware) {
    const malwareRegex = new RegExp(params.malware.trim().slice(0, 120).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    andConditions.push({
      $or: [
        { "analysis.malware": { $regex: malwareRegex } },
        { "extractedEntities.malwareFamilies": { $regex: malwareRegex } },
      ],
    });
  }

  if (params?.tactic) {
    const tacticRegex = new RegExp(params.tactic.trim().slice(0, 120).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    andConditions.push({
      $or: [
        { "analysis.attackChain.tactic": { $regex: tacticRegex } },
        { "extractedEntities.tactics": { $regex: tacticRegex } },
      ],
    });
  }

  if (params?.publisher && params.publisher !== "ALL") {
    const pubRegex = new RegExp(params.publisher.trim().slice(0, 120).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    andConditions.push({
      $or: [
        { publisher: { $regex: pubRegex } },
        { sourceName: { $regex: pubRegex } },
        { sourceDomain: { $regex: pubRegex } },
      ],
    });
  }

  if (typeof params?.minScore === "number" && params.minScore > 0) {
    andConditions.push({ qualityScore: { $gte: params.minScore } });
  }

  if (params?.hasIocs) {
    andConditions.push({ "iocs.0": { $exists: true } });
  }

  const hasQuery = Boolean(params?.q?.trim());
  const rawQuery = hasQuery ? params!.q!.trim().slice(0, 300) : "";
  let searchTokens: string[] = [];
  // Regex condition used only when the weighted $text index is unavailable or
  // finds nothing (e.g. partial words, which $text does not match).
  let regexQueryCondition: Filter<Document> | null = null;

  if (hasQuery) {
    const cleanEscaped = rawQuery.slice(0, 150).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(cleanEscaped, "i");
    searchTokens = rawQuery.split(/\s+/).filter((w) => w.length >= 2).slice(0, 6);
    const tokenRegexes = searchTokens.map((w) => new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));

    const orConditions: Filter<Document>[] = [
      { title: { $regex: regex } },
      { extractedText: { $regex: regex } },
      { publisher: { $regex: regex } },
      { sourceName: { $regex: regex } },
      { url: { $regex: regex } },
      { canonicalUrl: { $regex: regex } },
      { classification: { $regex: regex } },
      { resourceKind: { $regex: regex } },
      { "analysis.threatActors": { $regex: regex } },
      { "analysis.malware": { $regex: regex } },
      { "extractedEntities.cves": { $regex: regex } },
      { "extractedEntities.techniques.id": { $regex: regex } },
      { "extractedEntities.techniques.name": { $regex: regex } },
      { "extractedEntities.tactics": { $regex: regex } },
      { "analysis.attackChain.summary": { $regex: regex } },
      { "iocs.value": { $regex: regex } },
    ];

    // If multiple words entered (e.g. "powershell encoded" or "lazarus sideload"),
    // also match documents that contain all terms anywhere in text/title/actors
    if (searchTokens.length > 1) {
      orConditions.push({
        $and: tokenRegexes.map((tr) => ({
          $or: [
            { title: { $regex: tr } },
            { extractedText: { $regex: tr } },
            { "analysis.threatActors": { $regex: tr } },
            { "analysis.malware": { $regex: tr } },
            { "analysis.attackChain.summary": { $regex: tr } },
          ],
        })),
      });
    }

    regexQueryCondition = { $or: orConditions };
  }

  if (andConditions.length > 0) {
    filter.$and = andConditions;
  }

  const startTime = Date.now();
  const projection: Record<string, number> = {
    id: 1,
    sourceId: 1,
    sourceName: 1,
    title: 1,
    url: 1,
    canonicalUrl: 1,
    publishedAt: 1,
    contentType: 1,
    status: 1,
    rawHash: 1,
    textHash: 1,
    qualityScore: 1,
    wordCount: 1,
    iocs: 1,
    ingestOrigin: 1,
    ingestedAt: 1,
    publisher: 1,
    author: 1,
    classification: 1,
    resourceKind: 1,
    extractedEntities: 1,
    discoveryMethod: 1,
    discoveryQuery: 1,
    parentSource: 1,
    sourceDomain: 1,
    version: 1,
    analysis: 1,
    simulationScore: 1,
    isEmergingTechnique: 1,
    noveltyRationale: 1,
    tags: 1,
    aiVerified: 1,
    aiQualityScore: 1,
    aiAuditReason: 1,
    excerpt: 1,
    scoreBreakdown: 1,
  };

  // When searching, also load extractedText to compute exact matched snippets
  if (hasQuery) {
    projection.extractedText = 1;
  }

  let docs: Document[] = [];
  let searchMode: "list" | "text" | "regex" = "list";
  if (hasQuery) {
    // Relevance path: weighted $text index ranked by textScore, plus exact
    // CVE / ATT&CK id matches pinned to the top of the first page.
    try {
      const textDocs = await col
        .find({ ...filter, $text: { $search: toMongoTextSearch(rawQuery) } })
        .project({ ...projection, _textScore: { $meta: "textScore" } })
        .sort({ _textScore: { $meta: "textScore" } })
        .skip(pageOffset)
        .limit(pageLimit ?? 500)
        .toArray();
      const idDocs =
        pageOffset === 0 ? await findReportsByExactIds(col, filter, rawQuery, projection, pageLimit ?? 500) : [];
      const merged = dedupeDocs([...idDocs, ...textDocs]);
      if (merged.length > 0 || pageOffset > 0) {
        docs = pageLimit !== undefined ? merged.slice(0, pageLimit) : merged;
        searchMode = "text";
      }
    } catch (err) {
      logger.warn("MONGO", `$text search unavailable, using regex fallback: ${(err as Error).message}`);
    }
  }

  if (searchMode !== "text") {
    const regexFilter: Filter<Document> = regexQueryCondition
      ? { ...filter, $and: [...((filter.$and as Filter<Document>[]) ?? []), regexQueryCondition] }
      : filter;
    const cursor = col.find(regexFilter).sort({ ingestedAt: -1 }).project(projection);
    // The unfiltered list is cached in full; anything else is paged in Mongo.
    if (!isDefaultQuery) {
      if (pageOffset > 0) cursor.skip(pageOffset);
      if (pageLimit !== undefined) cursor.limit(pageLimit);
    }
    docs = await cursor.toArray();
    searchMode = hasQuery ? "regex" : "list";
  }
  logger.mongo(
    "listReports",
    "threat-intel",
    Date.now() - startTime,
    `Fetched ${docs.length} documents from cluster (${searchMode})`,
  );

  const mapped = docs.map((doc) => {
    const rawExcerpt = (doc.excerpt as string) || "";
    const text = rawExcerpt || (doc.extractedText as string) || (doc.title as string) || "";
    const excerpt = rawExcerpt.length > 0 ? rawExcerpt : excerptOf(text);
    const iocsList = (doc.iocs as IocHit[]) || [];

    let calculatedKind = (doc.resourceKind as ResourceKind) || null;
    if (!calculatedKind) {
      const cls = (doc.classification || "").toUpperCase();
      const analysisObj = doc.analysis as IntelAnalysis | undefined;
      const entitiesObj = doc.extractedEntities as ExtractedEntities | undefined;
      if (cls.includes("INTRUSION") || cls.includes("ATTACK_CHAIN") || (analysisObj?.attackChain && analysisObj.attackChain.length > 0)) {
        calculatedKind = "FULL_ATTACK_CHAIN";
      } else if (cls.includes("MALWARE") || (analysisObj?.malware && analysisObj.malware.length > 0)) {
        calculatedKind = "MALWARE_ANALYSIS";
      } else if (cls.includes("EMULATION") || cls.includes("PROCEDURE") || cls.includes("PURPLE") || (analysisObj?.emulation && analysisObj.emulation.length > 0)) {
        calculatedKind = "PROCEDURE_DEEPDIVE";
      } else if (cls.includes("DETECTION") || cls.includes("SIGMA") || (analysisObj?.detections && analysisObj.detections.length > 0)) {
        calculatedKind = "DETECTION_GUIDANCE";
      } else if (cls.includes("VULNERABILITY") || (entitiesObj?.cves && entitiesObj.cves.length > 0)) {
        calculatedKind = "VULNERABILITY_ADVISORY";
      } else if (cls.includes("THREAT_ACTOR") || (analysisObj?.threatActors && analysisObj.threatActors.length > 0)) {
        calculatedKind = "THREAT_ACTOR_DOSSIER";
      } else {
        calculatedKind = "CAMPAIGN_INTEL";
      }
    }

    let matchedSnippet: string | undefined = undefined;
    if (hasQuery && doc.extractedText) {
      // Snippet from the best-scoring passage of this report (BM25 over its chunks).
      const fullText = String(doc.extractedText || "");
      const [best] = selectPassages(
        [{ id: String(doc.id), title: String(doc.title || ""), text: fullText }],
        rawQuery,
        { k: 1, perDoc: 1, minScore: 0, maxDocChars: 300_000 },
      );
      if (best) {
        matchedSnippet = excerptAround(best.text, rawQuery, 240);
      } else {
        const lower = fullText.toLowerCase();
        const token = [rawQuery, ...searchTokens].find((t) => lower.includes(t.toLowerCase()));
        if (token) matchedSnippet = excerptAround(fullText.slice(0, 300_000), token, 240);
      }
    }

    return {
      id: doc.id,
      sourceId: doc.sourceId,
      sourceName: doc.sourceName || doc.publisher || "Verified Source",
      title: doc.title,
      url: doc.url,
      canonicalUrl: doc.canonicalUrl,
      publishedAt: doc.publishedAt ?? null,
      contentType: doc.contentType || "text/html",
      status: doc.status || "acquired",
      rawHash: doc.rawHash,
      textHash: doc.textHash,
      qualityScore: Number(doc.qualityScore ?? 0),
      wordCount: Number(doc.wordCount ?? 0),
      iocs: iocsList,
      ingestOrigin: doc.ingestOrigin || "crawl",
      ingestedAt: doc.ingestedAt,
      excerpt,
      iocCount: iocsList.length,
      publisher: doc.publisher || doc.sourceName,
      author: doc.author || doc.publisher,
      classification: doc.classification || "THREAT_REPORT",
      resourceKind: calculatedKind,
      extractedEntities: (doc.extractedEntities as ExtractedEntities) || undefined,
      discoveryMethod: doc.discoveryMethod || "manual",
      discoveryQuery: doc.discoveryQuery || "",
      parentSource: doc.parentSource || "",
      sourceDomain: doc.sourceDomain || "",
      version: Number(doc.version ?? 1),
      rawHtml: "",
      pdfUrl: doc.pdfUrl || "",
      pdfBase64: "",
      analysis: (doc.analysis as IntelAnalysis) || null,
      simulationScore: typeof doc.simulationScore === "number" ? doc.simulationScore : undefined,
      isEmergingTechnique: Boolean(doc.isEmergingTechnique),
      noveltyRationale: (doc.noveltyRationale as string) || undefined,
      tags: Array.isArray(doc.tags) && doc.tags.length > 0 ? doc.tags : deriveReportTags(doc as any),
      aiVerified: doc.aiVerified === true,
      aiQualityScore: typeof doc.aiQualityScore === "number" ? doc.aiQualityScore : undefined,
      aiAuditReason: (doc.aiAuditReason as string) || undefined,
      scoreBreakdown: doc.scoreBreakdown,
      matchedSnippet,
    };
  });

  if (isDefaultQuery) {
    cachedReportsList = { timestamp: Date.now(), data: mapped };
    return slicePage(mapped);
  }

  return mapped;
}

export interface ReportSearchCandidate {
  id: string;
  title: string;
  publisher: string;
  sourceName: string;
  url: string;
  canonicalUrl: string;
  publishedAt: string | null;
  extractedText: string;
  /** Mongo textScore, 1000 for an exact-id match, or fallback token-hit count. */
  score: number;
  matchedBy: "text" | "exact_id" | "regex";
}

const CANDIDATE_TEXT_MAX_CHARS = 300_000;
const CANDIDATE_PROJECTION = {
  id: 1,
  title: 1,
  publisher: 1,
  sourceName: 1,
  url: 1,
  canonicalUrl: 1,
  publishedAt: 1,
  extractedText: 1,
  "analysis.threatActors": 1,
  "analysis.malware": 1,
  "extractedEntities.cves": 1,
  "extractedEntities.techniques": 1,
} as const;

function toCandidate(doc: Document, score: number, matchedBy: ReportSearchCandidate["matchedBy"]): ReportSearchCandidate {
  return {
    id: String(doc.id),
    title: String(doc.title || "Untitled report"),
    publisher: String(doc.publisher || doc.sourceName || ""),
    sourceName: String(doc.sourceName || doc.publisher || ""),
    url: String(doc.url || ""),
    canonicalUrl: String(doc.canonicalUrl || doc.url || ""),
    publishedAt: doc.publishedAt ? String(doc.publishedAt) : null,
    extractedText: String(doc.extractedText || "").slice(0, CANDIDATE_TEXT_MAX_CHARS),
    score,
    matchedBy,
  };
}

/**
 * Candidate reports for grounded retrieval. Primary: weighted `$text` index
 * ranked by textScore. Exact CVE / ATT&CK ids in the query are also matched on
 * their entity fields and merged in first. If `$text` is unavailable (index
 * missing) a bounded regex search is ranked by token hits in title/entities.
 */
export async function mongoSearchReportCandidates(
  query: string,
  opts: { limit?: number } = {},
): Promise<ReportSearchCandidate[]> {
  if (!isMongoConfigured()) return [];
  const limit = Math.max(1, Math.min(100, opts.limit ?? 25));
  const q = String(query ?? "").trim().slice(0, 500);
  if (!q) return [];
  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();
  const base: Filter<Document> = { docType: "report" };
  const startTime = Date.now();

  const idDocs = (await findReportsByExactIds(col, base, q, CANDIDATE_PROJECTION, limit).catch(() => [])).map((d) =>
    toCandidate(d, 1000, "exact_id"),
  );

  let ranked: ReportSearchCandidate[] = [];
  let mode: "text" | "regex" = "text";
  try {
    const docs = await col
      .find({ ...base, $text: { $search: toMongoTextSearch(q) } })
      .project({ ...CANDIDATE_PROJECTION, _textScore: { $meta: "textScore" } })
      .sort({ _textScore: { $meta: "textScore" } })
      .limit(limit)
      .toArray();
    ranked = docs.map((d) => toCandidate(d, Number(d._textScore ?? 0), "text"));
  } catch (err) {
    mode = "regex";
    logger.warn("MONGO", `$text candidate search failed, using regex fallback: ${(err as Error).message}`);
    const tokens = queryTerms(q).filter((t) => t.length >= 3).slice(0, 8);
    if (tokens.length > 0) {
      const regexes = tokens.map((t) => new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
      const docs = await col
        .find({
          ...base,
          $or: regexes.flatMap((r) => [
            { title: { $regex: r } },
            { "analysis.threatActors": { $regex: r } },
            { "analysis.malware": { $regex: r } },
            { "extractedEntities.cves": { $regex: r } },
            { "extractedEntities.techniques.id": { $regex: r } },
            { extractedText: { $regex: r } },
          ]),
        })
        .project(CANDIDATE_PROJECTION)
        .limit(limit * 3)
        .toArray();
      ranked = docs
        .map((d) => {
          const head = [
            d.title,
            ...((d.analysis?.threatActors as string[]) ?? []),
            ...((d.analysis?.malware as string[]) ?? []),
            ...((d.extractedEntities?.cves as string[]) ?? []),
            ...(((d.extractedEntities?.techniques as Array<{ id?: string } | string>) ?? []).map((t) =>
              typeof t === "string" ? t : t?.id ?? "",
            )),
          ]
            .join(" ")
            .toLowerCase();
          const hits = tokens.reduce((n, t) => n + (head.includes(t) ? 1 : 0), 0);
          return toCandidate(d, hits, "regex");
        })
        .sort((a, b) => b.score - a.score)
        .slice(0, limit);
    }
  }

  const seen = new Set<string>();
  const merged: ReportSearchCandidate[] = [];
  for (const c of [...idDocs, ...ranked]) {
    if (seen.has(c.id)) continue;
    seen.add(c.id);
    merged.push(c);
  }
  logger.mongo(
    "searchReportCandidates",
    "threat-intel",
    Date.now() - startTime,
    `${merged.length} candidates (${idDocs.length} exact-id, ${ranked.length} ${mode})`,
  );
  return merged.slice(0, Math.max(limit, idDocs.length));
}

export async function mongoInsertReport(report: ReportRecord): Promise<void> {
  const startTime = Date.now();
  invalidateReportsCache();
  invalidateDashboardCache();
  const col = await getThreatIntelCollection();
  const excerpt = (report as any).excerpt || excerptOf(report.extractedText || report.title || "");

  // "AI verified" is set only by a real model evaluation (crawler agent pass
  // or the AI library audit). Heuristic quality scores are stored as such.
  const tags = Array.isArray(report.tags) && report.tags.length > 0 ? report.tags : deriveReportTags(report as any);
  const aiAuditReason = report.aiAuditReason || "Not yet evaluated by an AI model.";

  await col.updateOne(
    { docType: "report", id: report.id },
    {
      $set: {
        docType: "report",
        ...report,
        tags,
        aiVerified: report.aiVerified ?? false,
        aiQualityScore: report.aiQualityScore,
        aiAuditReason,
        excerpt,
        // Near-duplicate fingerprint over the same extractedText window the crawler compares against.
        ...(report.extractedText ? { simhash: computeReportSimHash(report.extractedText) } : {}),
        updatedAt: new Date().toISOString(),
      },
    },
    { upsert: true },
  );
  logger.mongo(
    "updateOne:upsert",
    "threat-intel",
    Date.now() - startTime,
    `Saved report "${report.title}" (${report.id})`,
  );
}

export async function mongoDeleteReport(id: string): Promise<boolean> {
  const startTime = Date.now();
  invalidateReportsCache();
  invalidateDashboardCache();
  const col = await getThreatIntelCollection();
  const res = await col.deleteOne({ docType: "report", id });
  const ok = res.deletedCount > 0;
  logger.mongo(
    "deleteOne",
    "threat-intel",
    Date.now() - startTime,
    `Deleted report ${id} (success: ${ok})`,
  );
  return ok;
}

// ---------------------------------------------------------------------------
// Source Records
// ---------------------------------------------------------------------------

let cachedSourcesList: { timestamp: number; data: SourceRecord[] } | null = null;

export async function mongoListSources(): Promise<SourceRecord[]> {
  const now = Date.now();
  if (cachedSourcesList && now - cachedSourcesList.timestamp < 60_000) {
    return cachedSourcesList.data;
  }
  try {
    await ensureMongoIndexes();
    const col = await getThreatIntelCollection();
    const docs = await col
      .find({ docType: "source" })
      .sort({ priority: 1, name: 1 })
      .toArray();

    // Aggregate report counts by sourceId and sourceDomain
    const reportCountBySourceId = new Map<string, number>();
    const reportCountByDomain = new Map<string, number>();
    try {
      const reportAgg = await col
        .aggregate<{ _id: { sourceId?: string; sourceDomain?: string }; count: number }>([
          { $match: { docType: "report" } },
          {
            $group: {
              _id: { sourceId: "$sourceId", sourceDomain: "$sourceDomain" },
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();

      for (const item of reportAgg) {
        if (item._id.sourceId) {
          reportCountBySourceId.set(
            item._id.sourceId,
            (reportCountBySourceId.get(item._id.sourceId) || 0) + item.count,
          );
        }
        if (item._id.sourceDomain) {
          const dom = item._id.sourceDomain.toLowerCase().replace(/^www\./, "");
          reportCountByDomain.set(dom, (reportCountByDomain.get(dom) || 0) + item.count);
        }
      }
    } catch (aggErr) {
      logger.warn("mongodb", "Failed to aggregate report counts for sources:", aggErr);
    }

    const result: SourceRecord[] = docs.map((doc) => {
      const seedDef = SOURCE_SEED.find((s) => s.id === doc.id || s.slug === doc.slug);
      let domain = "";
      try {
        domain = new URL(doc.homepageUrl).hostname.toLowerCase().replace(/^www\./, "");
      } catch {
        // Invalid homepage URL: source shown without a domain.
      }
      const count =
        reportCountBySourceId.get(doc.id) ||
        (doc.slug ? reportCountBySourceId.get(doc.slug) : 0) ||
        (domain ? reportCountByDomain.get(domain) : 0) ||
        0;

      return {
        id: doc.id,
        name: doc.name,
        slug: doc.slug,
        category: doc.category,
        priority: Number(doc.priority),
        homepageUrl: doc.homepageUrl,
        crawlPattern: doc.crawlPattern || seedDef?.crawlPattern || `${doc.homepageUrl.replace(/\/+$/, "")}/*`,
        feedUrl: doc.feedUrl || "",
        enabled: Boolean(doc.enabled),
        trustLevel: (doc.trustLevel as TrustLevel) || "reputable",
        notes: doc.notes || "",
        lastIngestAt: doc.lastIngestAt || null,
        resourceCount: count,
        // Registry fields (tier / connector / yields) and structured-sync status.
        tier: doc.tier ?? seedDef?.tier,
        connector: doc.connector ?? seedDef?.connector,
        yields: Array.isArray(doc.yields) ? doc.yields : seedDef?.yields,
        connectorConfig: doc.connectorConfig ?? seedDef?.connectorConfig,
        lastSyncAt: doc.lastSyncAt ?? null,
        lastSyncCount: typeof doc.lastSyncCount === "number" ? doc.lastSyncCount : undefined,
        lastSyncError: doc.lastSyncError ?? null,
      };
    });
    cachedSourcesList = { timestamp: Date.now(), data: result };
    return result;
  } catch (err) {
    if (cachedSourcesList?.data) {
      logger.warn(
        "mongodb",
        "mongoListSources encountered transient error; serving cached sources:",
        err instanceof Error ? err.message : err,
      );
      return cachedSourcesList.data;
    }
    throw err;
  }
}

export async function mongoToggleSource(id: string, enabled: boolean): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne({ docType: "source", id }, { $set: { enabled, updatedAt: new Date().toISOString() } });
  cachedSourcesList = null;
  invalidateCrawlerStateCache();
}

export async function mongoUpdateSourceLastIngest(id: string): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "source", id },
    { $set: { lastIngestAt: new Date().toISOString(), updatedAt: new Date().toISOString() } },
  );
  cachedSourcesList = null;
  invalidateCrawlerStateCache();
}

export async function mongoSeedSources(sources: Array<Omit<SourceRecord, "lastIngestAt"> & { lastIngestAt?: string | null }>): Promise<void> {
  const col = await getThreatIntelCollection();
  const count = await col.countDocuments({ docType: "source" });
  if (count === 0) {
    for (const s of sources) {
      await col.updateOne(
        { docType: "source", id: s.id },
        { $set: { docType: "source", lastIngestAt: null, ...s, createdAt: new Date().toISOString() } },
        { upsert: true },
      );
    }
  } else {
    // Synchronize latest crawlPattern definitions into existing MongoDB source documents
    for (const s of sources) {
      if (s.crawlPattern) {
        await col.updateOne(
          { docType: "source", id: s.id },
          { $set: { crawlPattern: s.crawlPattern } },
        );
      }
    }
  }

  // Registry sync: upsert every seeded source's registry fields (tier, connector,
  // yields, feeds, notes…) onto existing docs and insert sources added since the
  // first seed. User state — `enabled`, ingest/sync history — is only set on insert.
  const now = new Date().toISOString();
  const ops = SOURCE_SEED.map((seed) => {
    const { id, enabled, ...registry } = seed;
    const $set: Record<string, unknown> = { updatedAt: now };
    for (const [k, v] of Object.entries(registry)) if (v !== undefined) $set[k] = v;
    return {
      updateOne: {
        filter: { docType: "source", id },
        update: {
          $set,
          $setOnInsert: { docType: "source", id, enabled, lastIngestAt: null, createdAt: now },
        },
        upsert: true,
      },
    };
  });
  if (ops.length) await col.bulkWrite(ops, { ordered: false });
  cachedSourcesList = null;
}

// ---------------------------------------------------------------------------
// Crawler Config & Granular Controls
// ---------------------------------------------------------------------------

export const DEFAULT_CRAWL_CONFIG: CrawlConfig = {
  id: "cfg_default",
  enabled: true,
  paused: false,
  frequencyMinutes: 360,
  startHour: "09:00",
  maxResourcesPerRun: 60,
  maxResourcesPerJob: 60,
  maxRunTimeMinutes: 5,
  maxResourcesPerDomain: 8,
  maxDepth: 3,
  discoveryBreadth: "balanced",
  allowExternalDomains: true,
  domainAllowlist: [],
  domainBlocklist: [],
  rateLimitMs: 150,
  concurrency: 2,
  maxPdfDownloads: 10,
  autoIngest: true,
  autoAnalyze: true,
  generatePdf: true,
  rssDiscovery: true,
  htmlDiscovery: true,
  searchDiscovery: true,
  recursiveDiscovery: true,
  keywords: 'ransomware, "attack chain", "infection chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"',
  noiseKeywords: "webinar, discount, pricing, subscribe, careers, terms of service, privacy policy, podcast, videointerview",
  minQualityScore: 0.40,
  minWordCount: 200,
  strictnessMode: "balanced",
  requireIocs: false,
  requireAttck: false,
  rejectMarketingNoise: true,
  dedupMethod: "smart_hybrid",
  activeSources: [],
  targetResourceTypes: [
    "FULL_ATTACK_CHAIN",
    "CAMPAIGN_INTEL",
    "PROCEDURE_DEEPDIVE",
    "MALWARE_ANALYSIS",
    "DETECTION_GUIDANCE",
    "VULNERABILITY_ADVISORY",
    "THREAT_ACTOR_DOSSIER",
  ],
  dateRangeDays: null,
  lastRunAt: null,
  nextRunAt: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(),
  // AI Agent Enhancement Layer Settings
  agentDiscoveryEnabled: true,
  agentTaggingEnabled: true,
  agentApprovalEnabled: true,
  agentAutoIngestEnabled: false,
  agentCrawlSourcesEnabled: true,
  agentLibraryAuditEnabled: true,
  agentAutoPruneJunkEnabled: false,
  agentModel: DEFAULT_AGY_MODEL,
  agentTimeoutSeconds: 45,
};

export async function mongoGetCrawlConfig(): Promise<CrawlConfig> {
  if (cachedCrawlConfig && Date.now() - cachedCrawlConfig.timestamp < CONFIG_CACHE_TTL_MS) {
    logger.mongo("getCrawlConfig", "threat-intel", 0, "Returned cached crawl configuration", true);
    return cachedCrawlConfig.data;
  }

  const startTime = Date.now();
  const col = await getThreatIntelCollection();
  const doc = await col.findOne({ docType: "crawl_config" });

  let config: CrawlConfig;
  if (doc) {
    const { _id, ...cleanDoc } = doc as any;
    config = {
      ...DEFAULT_CRAWL_CONFIG,
      ...cleanDoc,
      id: doc.id || DEFAULT_CRAWL_CONFIG.id,
      enabled: Boolean(doc.enabled ?? true),
      paused: Boolean(doc.paused ?? false),
      frequencyMinutes: Number(doc.frequencyMinutes ?? 360),
      startHour: doc.startHour || "09:00",
      maxResourcesPerRun: Number(doc.maxResourcesPerRun ?? doc.maxResourcesPerJob ?? 60),
      maxResourcesPerJob: Number(doc.maxResourcesPerJob ?? doc.maxResourcesPerRun ?? 60),
      maxRunTimeMinutes: Number(doc.maxRunTimeMinutes ?? 5),
      maxResourcesPerDomain: Number(doc.maxResourcesPerDomain ?? 8),
      maxDepth: Number(doc.maxDepth ?? 3),
      discoveryBreadth: doc.discoveryBreadth || "balanced",
      allowExternalDomains: doc.allowExternalDomains !== false,
      domainAllowlist: doc.domainAllowlist || [],
      domainBlocklist: doc.domainBlocklist || [],
      rateLimitMs: Number(doc.rateLimitMs ?? 150),
      concurrency: Number(doc.concurrency ?? 2),
      maxPdfDownloads: Number(doc.maxPdfDownloads ?? 10),
      autoIngest: Boolean(doc.autoIngest ?? true),
      autoAnalyze: Boolean(doc.autoAnalyze ?? true),
      generatePdf: Boolean(doc.generatePdf ?? true),
      rssDiscovery: Boolean(doc.rssDiscovery ?? true),
      htmlDiscovery: Boolean(doc.htmlDiscovery ?? true),
      searchDiscovery: Boolean(doc.searchDiscovery ?? true),
      recursiveDiscovery: Boolean(doc.recursiveDiscovery ?? true),
      keywords: doc.keywords || DEFAULT_CRAWL_CONFIG.keywords,
      noiseKeywords: doc.noiseKeywords || DEFAULT_CRAWL_CONFIG.noiseKeywords,
      minQualityScore: Number(doc.minQualityScore ?? 0.35),
      minWordCount: Number(doc.minWordCount ?? 100),
      strictnessMode: doc.strictnessMode || "balanced",
      requireIocs: Boolean(doc.requireIocs ?? false),
      requireAttck: Boolean(doc.requireAttck ?? false),
      rejectMarketingNoise: Boolean(doc.rejectMarketingNoise ?? true),
      dedupMethod: doc.dedupMethod || "smart_hybrid",
      activeSources: (doc.activeSources as string[]) || [],
      targetResourceTypes: (doc.targetResourceTypes as ResourceKind[]) || DEFAULT_CRAWL_CONFIG.targetResourceTypes,
      dateRangeDays: doc.dateRangeDays ? Number(doc.dateRangeDays) : null,
      lastRunAt: doc.lastRunAt || null,
      nextRunAt: doc.nextRunAt || null,
      agentDiscoveryEnabled: Boolean(doc.agentDiscoveryEnabled ?? true),
      agentTaggingEnabled: Boolean(doc.agentTaggingEnabled ?? true),
      agentApprovalEnabled: Boolean(doc.agentApprovalEnabled ?? true),
      agentAutoIngestEnabled: Boolean(doc.agentAutoIngestEnabled ?? false),
      agentCrawlSourcesEnabled: Boolean(doc.agentCrawlSourcesEnabled ?? true),
      agentLibraryAuditEnabled: Boolean(doc.agentLibraryAuditEnabled ?? true),
      agentAutoPruneJunkEnabled: Boolean(doc.agentAutoPruneJunkEnabled ?? false),
      agentModel: sanitizeAgyModel(doc.agentModel),
      agentTimeoutSeconds: Number(doc.agentTimeoutSeconds ?? 45),
    };
  } else {
    config = DEFAULT_CRAWL_CONFIG;
    await col.updateOne(
      { docType: "crawl_config", id: DEFAULT_CRAWL_CONFIG.id },
      { $set: { docType: "crawl_config", ...DEFAULT_CRAWL_CONFIG } },
      { upsert: true },
    );
  }

  cachedCrawlConfig = { timestamp: Date.now(), data: config };
  logger.mongo(
    "getCrawlConfig",
    "threat-intel",
    Date.now() - startTime,
    `Loaded config (id=${config.id}, mode=${config.strictnessMode})`,
  );
  return config;
}

export async function mongoUpdateCrawlConfig(updates: Partial<CrawlConfig>): Promise<CrawlConfig> {
  const startTime = Date.now();
  invalidateConfigCache();
  invalidateDashboardCache();
  const col = await getThreatIntelCollection();
  const current = await mongoGetCrawlConfig();

  // If scheduler is enabled and interval changed or enabled, intelligently update nextRunAt
  const willBeEnabled = updates.enabled !== undefined ? updates.enabled : current.enabled;
  const newFreq = updates.frequencyMinutes !== undefined ? updates.frequencyMinutes : (current.frequencyMinutes || 60);

  if (willBeEnabled && updates.paused !== true) {
    const now = Date.now();
    const lastRunMs = current.lastRunAt ? new Date(current.lastRunAt).getTime() : 0;
    
    // Recalculate nextRunAt if not explicitly provided and interval or enabled state changed
    if (updates.nextRunAt === undefined) {
      if (updates.frequencyMinutes !== undefined) {
        // User changed interval: schedule next run newFreq minutes from now
        updates.nextRunAt = new Date(now + newFreq * 60 * 1000).toISOString();
      } else if (updates.enabled === true && !current.enabled) {
        if (!lastRunMs) {
          updates.nextRunAt = new Date(now + 30_000).toISOString();
        } else {
          const targetNextMs = lastRunMs + newFreq * 60 * 1000;
          updates.nextRunAt = new Date(Math.max(now + 30_000, targetNextMs)).toISOString();
        }
      }
    }
  }

  const merged: CrawlConfig = { ...current, ...updates };
  const { _id, ...cleanMerged } = merged as any;
  await col.updateOne({ docType: "crawl_config", id: current.id }, { $set: cleanMerged }, { upsert: true });
  cachedCrawlConfig = { timestamp: Date.now(), data: cleanMerged };
  logger.mongo(
    "updateOne:crawl_config",
    "threat-intel",
    Date.now() - startTime,
    `Updated crawl config (${Object.keys(updates).join(", ")})`,
  );

  // Trigger schedule check in background so due scans run immediately
  triggerScheduleCheck();

  return cleanMerged;
}

// ---------------------------------------------------------------------------
// General App Settings & Storage Telemetry
// ---------------------------------------------------------------------------

export async function mongoGetAppSettings(): Promise<AppSettings> {
  if (cachedAppSettings && Date.now() - cachedAppSettings.timestamp < SETTINGS_CACHE_TTL_MS) {
    logger.mongo("getAppSettings", "threat-intel", 0, "Returned cached application settings", true);
    return cachedAppSettings.data;
  }

  // No MongoDB: serve the in-memory settings (seeded from defaults) so marketplace and model selection work.
  if (!isMongoConfigured()) {
    cachedAppSettings = { timestamp: Date.now(), data: memoryAppSettings };
    return memoryAppSettings;
  }

  const startTime = Date.now();
  const col = await getThreatIntelCollection();
  const doc = await col.findOne({ docType: "app_settings" });

  let settings: AppSettings;
  if (doc) {
    const { _id, ...cleanDoc } = doc as any;
    settings = {
      ...DEFAULT_APP_SETTINGS,
      ...cleanDoc,
      id: doc.id || DEFAULT_APP_SETTINGS.id,
      organizationName: doc.organizationName || DEFAULT_APP_SETTINGS.organizationName,
      nodeId: doc.nodeId || DEFAULT_APP_SETTINGS.nodeId,
      defaultClassification: doc.defaultClassification || DEFAULT_APP_SETTINGS.defaultClassification,
      iocConfidenceThreshold: Number(doc.iocConfidenceThreshold ?? DEFAULT_APP_SETTINGS.iocConfidenceThreshold),
      evidenceRetentionDays: Number(doc.evidenceRetentionDays ?? DEFAULT_APP_SETTINGS.evidenceRetentionDays),
      defaultExportFormat: doc.defaultExportFormat || DEFAULT_APP_SETTINGS.defaultExportFormat,
      cacheTtlSeconds: Number(doc.cacheTtlSeconds ?? DEFAULT_APP_SETTINGS.cacheTtlSeconds),
      dashboardCacheTtlSeconds: Number(doc.dashboardCacheTtlSeconds ?? DEFAULT_APP_SETTINGS.dashboardCacheTtlSeconds),
      autoPurgeStaleEventsDays: Number(doc.autoPurgeStaleEventsDays ?? DEFAULT_APP_SETTINGS.autoPurgeStaleEventsDays),
      defaultMatrixLayout: doc.defaultMatrixLayout || DEFAULT_APP_SETTINGS.defaultMatrixLayout,
      matrixSubtechniqueAutoExpand: Boolean(doc.matrixSubtechniqueAutoExpand ?? DEFAULT_APP_SETTINGS.matrixSubtechniqueAutoExpand),
      pollingIntervalSeconds: Number(doc.pollingIntervalSeconds ?? DEFAULT_APP_SETTINGS.pollingIntervalSeconds),
      enableSoundAlerts: Boolean(doc.enableSoundAlerts ?? false),
      enableLiveTelemetryStream: Boolean(doc.enableLiveTelemetryStream ?? true),
      updatedAt: doc.updatedAt || new Date().toISOString(),
    };
  } else {
    settings = DEFAULT_APP_SETTINGS;
    await col.updateOne(
      { docType: "app_settings", id: DEFAULT_APP_SETTINGS.id },
      { $set: { docType: "app_settings", ...DEFAULT_APP_SETTINGS } },
      { upsert: true },
    );
  }

  cachedAppSettings = { timestamp: Date.now(), data: settings };
  logger.mongo(
    "getAppSettings",
    "threat-intel",
    Date.now() - startTime,
    `Loaded app settings (org=${settings.organizationName}, node=${settings.nodeId})`,
  );
  return settings;
}

export async function mongoUpdateAppSettings(updates: Partial<AppSettings>): Promise<AppSettings> {
  const startTime = Date.now();
  invalidateSettingsCache();
  // No MongoDB: update the in-memory settings (resets on restart).
  if (!isMongoConfigured()) {
    memoryAppSettings = { ...memoryAppSettings, ...updates, updatedAt: new Date().toISOString() };
    cachedAppSettings = { timestamp: Date.now(), data: memoryAppSettings };
    return memoryAppSettings;
  }
  const col = await getThreatIntelCollection();
  const current = await mongoGetAppSettings();
  const merged = { ...current, ...updates, updatedAt: new Date().toISOString() };
  const { _id, ...cleanMerged } = merged as any;
  await col.updateOne({ docType: "app_settings", id: current.id }, { $set: cleanMerged }, { upsert: true });
  cachedAppSettings = { timestamp: Date.now(), data: cleanMerged };
  logger.mongo(
    "updateOne:app_settings",
    "threat-intel",
    Date.now() - startTime,
    `Updated app settings (${Object.keys(updates).join(", ")})`,
  );
  return cleanMerged;
}

export async function mongoGetStorageStats(): Promise<StorageStats> {
  const now = Date.now();
  if (cachedStorageStats && now - cachedStorageStats.timestamp < STORAGE_STATS_CACHE_TTL_MS) {
    return cachedStorageStats.data;
  }

  const col = await getThreatIntelCollection();
  const [
    totalReports,
    visibleReports,
    totalSources,
    totalDiscovered,
    totalJobs,
    totalEvents,
  ] = await Promise.all([
    col.countDocuments({ docType: "report" }),
    col.countDocuments({ docType: "report", status: { $nin: ["rejected", "duplicate"] } }),
    col.countDocuments({ docType: "source" }),
    col.countDocuments({ docType: "discovered_resource" }),
    col.countDocuments({ docType: "crawl_job" }),
    col.countDocuments({ docType: "ingest_event" }),
  ]);

  const result: StorageStats = {
    configured: isMongoConfigured(),
    engine: "mongodb",
    databaseName: getDatabaseName(),
    collectionName: getCollectionName(),
    totalReports,
    visibleReports,
    totalSources,
    totalDiscovered,
    totalJobs,
    totalEvents,
    cacheStatus: {
      reportsCached: cachedReportsList !== null,
      dashboardCached: cachedDashboardStats !== null,
      configCached: cachedCrawlConfig !== null,
      settingsCached: cachedAppSettings !== null,
    },
    serverUptimeSeconds: Math.floor(process.uptime()),
  };
  cachedStorageStats = { timestamp: now, data: result };
  return result;
}

// ---------------------------------------------------------------------------
// Jobs & Items
// ---------------------------------------------------------------------------

export async function mongoInsertCrawlJob(job: CrawlJob): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "crawl_job", id: job.id },
    { $set: { docType: "crawl_job", ...job, createdAt: new Date().toISOString() } },
    { upsert: true },
  );
  invalidateCrawlerStateCache();
}

export async function mongoUpdateCrawlJob(id: string, updates: Partial<CrawlJob>): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "crawl_job", id },
    { $set: { ...updates, updatedAt: new Date().toISOString() } },
  );
  invalidateCrawlerStateCache();
}

export async function mongoListRecentCrawlJobs(limit = 100): Promise<CrawlJob[]> {
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "crawl_job" })
    .sort({ startedAt: -1, createdAt: -1 })
    .limit(limit)
    .toArray();

  return docs.map((d) => ({
    id: d.id,
    status: d.status,
    triggerType: d.triggerType,
    startedAt: d.startedAt || null,
    completedAt: d.completedAt || null,
    sourceCount: Number(d.sourceCount ?? 0),
    discoveredCount: Number(d.discoveredCount ?? 0),
    evaluatedCount: Number(d.evaluatedCount ?? 0),
    qualifiedCount: Number(d.qualifiedCount ?? 0),
    ingestedCount: Number(d.ingestedCount ?? 0),
    duplicateCount: Number(d.duplicateCount ?? 0),
    failedCount: Number(d.failedCount ?? 0),
    rejectedCount: Number(d.rejectedCount ?? 0),
    updatedCount: Number(d.updatedCount ?? 0),
    skippedCount: Number(d.skippedCount ?? 0),
    newSourcesCount: Number(d.newSourcesCount ?? 0),
    pdfGeneratedCount: Number(d.pdfGeneratedCount ?? 0),
    errorSummary: d.errorSummary || "",
    currentStage: d.currentStage || undefined,
    currentUrl: d.currentUrl || undefined,
    activeWorkers: d.activeWorkers !== undefined ? Number(d.activeWorkers) : undefined,
    activeDomains: Array.isArray(d.activeDomains) ? d.activeDomains : undefined,
    throughputDocsPerSec: d.throughputDocsPerSec !== undefined ? Number(d.throughputDocsPerSec) : undefined,
    stageCounts: d.stageCounts || undefined,
  }));
}

export async function mongoInsertCrawlJobItem(item: CrawlJobItem): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.insertOne({
    docType: "crawl_job_item",
    ...item,
    createdAt: item.createdAt || new Date().toISOString(),
  });
}

export async function mongoListRecentCrawlJobItems(limit = 25): Promise<CrawlJobItem[]> {
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "crawl_job_item" })
    .project({
      id: 1,
      jobId: 1,
      sourceId: 1,
      url: 1,
      canonicalUrl: 1,
      title: 1,
      classification: 1,
      decision: 1,
      reason: 1,
      discoveryMethod: 1,
      discoveryQuery: 1,
      parentUrl: 1,
      depth: 1,
      publisher: 1,
      createdAt: 1,
    })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();

  return docs.map((d) => ({
    id: d.id,
    jobId: d.jobId,
    sourceId: d.sourceId || null,
    url: d.url,
    canonicalUrl: d.canonicalUrl,
    title: d.title,
    classification: d.classification,
    decision: d.decision,
    reason: d.reason,
    discoveryMethod: d.discoveryMethod,
    discoveryQuery: d.discoveryQuery || "",
    parentUrl: d.parentUrl || null,
    depth: Number(d.depth ?? 1),
    publisher: d.publisher || "",
    createdAt: d.createdAt,
  }));
}

// ---------------------------------------------------------------------------
// Discovered Resources Queue
// ---------------------------------------------------------------------------

export async function mongoUpsertDiscoveredResource(resource: Partial<DiscoveredResource> & { canonicalUrl: string }): Promise<void> {
  if (!isMongoConfigured()) return;
  const targetUrl = resource.canonicalUrl || resource.url || "";
  if (!isCandidateResourceUrl(targetUrl).isResource) {
    return; // Drop non-CTI URLs, marketing, commercial trials, and search filters before saving
  }
  const title = (resource.title || "").toLowerCase();
  if (
    title.includes("free trial") ||
    title.includes("free 30-day") ||
    title.includes("raport roczny") ||
    title.includes("accessibility statement") ||
    title.includes("site map") ||
    title.includes("truRisk platform")
  ) {
    return; // Drop marketing trials, accessibility statements, and non-CTI documentation
  }
  try {
    const col = await getThreatIntelCollection();
    const assignedId = resource.id || `dsc_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const { id: _ignoredId, createdAt: _ignoredCreated, ...setFields } = resource;
    await col.updateOne(
      { docType: "discovered_resource", canonicalUrl: resource.canonicalUrl },
      {
        $set: {
          docType: "discovered_resource",
          ...setFields,
          updatedAt: new Date().toISOString(),
        },
        $setOnInsert: {
          id: assignedId,
          createdAt: resource.createdAt || new Date().toISOString(),
        },
      },
      { upsert: true },
    );
  } catch (err) {
    console.warn("[mongodb] mongoUpsertDiscoveredResource error:", err);
  }
}

export async function mongoListDiscoveredResources(limit = 40): Promise<DiscoveredResource[]> {
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "discovered_resource" })
    .project({
      id: 1,
      canonicalUrl: 1,
      url: 1,
      sourceId: 1,
      title: 1,
      publisher: 1,
      author: 1,
      publicationDate: 1,
      classification: 1,
      resourceKind: 1,
      discoveryMethod: 1,
      discoveryQuery: 1,
      parentSource: 1,
      parentUrl: 1,
      sourceDomain: 1,
      contentType: 1,
      status: 1,
      qualityScore: 1,
      rejectReason: 1,
      reportId: 1,
      discoveryPath: 1,
      createdAt: 1,
      updatedAt: 1,
    })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();

  return docs.map((d) => ({
    id: d.id || `dsc_${d._id}`,
    canonicalUrl: d.canonicalUrl,
    url: d.url,
    sourceId: d.sourceId || null,
    title: d.title,
    publisher: d.publisher || "",
    author: d.author || "",
    publicationDate: d.publicationDate || null,
    classification: d.classification,
    resourceKind: d.resourceKind,
    discoveryMethod: d.discoveryMethod,
    discoveryQuery: d.discoveryQuery,
    parentSource: d.parentSource,
    parentUrl: d.parentUrl,
    sourceDomain: d.sourceDomain,
    contentType: d.contentType,
    status: d.status,
    qualityScore: d.qualityScore ? Number(d.qualityScore) : null,
    rejectReason: d.rejectReason,
    reportId: d.reportId,
    discoveryPath: (d.discoveryPath as string[]) || [],
    createdAt: d.createdAt,
    updatedAt: d.updatedAt,
  }));
}

// ---------------------------------------------------------------------------
// Ingest Events
// ---------------------------------------------------------------------------

export async function mongoInsertIngestEvent(event: IngestEvent): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.insertOne({
    docType: "ingest_event",
    ...event,
    createdAt: event.createdAt || new Date().toISOString(),
  });
}

export async function mongoListRecentIngestEvents(limit = 8): Promise<IngestEvent[]> {
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "ingest_event" })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();

  return docs.map((d) => ({
    id: d.id || `evt_${d._id}`,
    reportId: d.reportId || null,
    url: d.url,
    outcome: d.outcome,
    detail: d.detail || "",
    createdAt: d.createdAt,
  }));
}

// ---------------------------------------------------------------------------
// Unified Crawler State from MongoDB
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Discovered Sources & Graph Edges
// ---------------------------------------------------------------------------

const NON_CTI_DOMAINS = new Set([
  "uscis.gov",
  "ice.gov",
  "e-verify.gov",
  "edit.dhs.gov",
  "webbook.nist.gov",
  "arxiv.org",
  "justice.gov",
  "myaccount.uscis.gov",
]);

export async function mongoInsertDiscoveredSource(source: DiscoveredSourceRecord) {
  if (!isMongoConfigured()) return;
  const dom = (source.domain || "").toLowerCase().replace(/^www\./, "");
  if (NON_CTI_DOMAINS.has(dom) || (dom.endsWith(".gov") && !dom.includes("cisa") && !dom.includes("ncsc") && !dom.includes("cyber"))) {
    return;
  }
  try {
    const col = await getThreatIntelCollection();
    const assignedId = source.id || `src_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    // Exclude firstDiscoveredAt from setFields to prevent MongoServerError code 40 conflict
    const { id: _ignoredId, resourceCount: _ignoredCount, firstDiscoveredAt: _ignoredFirst, ...setFields } = source;
    await col.updateOne(
      { docType: "discovered_source", domain: source.domain },
      {
        $set: {
          docType: "discovered_source",
          ...setFields,
          lastSeenAt: new Date().toISOString(),
        },
        $inc: { resourceCount: 1 },
        $setOnInsert: {
          id: assignedId,
          firstDiscoveredAt: source.firstDiscoveredAt || new Date().toISOString(),
        },
      },
      { upsert: true },
    );
  } catch (err) {
    console.warn("[mongodb] mongoInsertDiscoveredSource error:", err);
  }
}

const PRIMARY_SEED_DOMAINS = new Set([
  "thedfirreport.com",
  "unit42.paloaltonetworks.com",
  "paloaltonetworks.com",
  "redcanary.com",
  "mandiant.com",
  "cisa.gov",
  "bleepingcomputer.com",
  "sentinelone.com",
  "microsoft.com",
  "techcommunity.microsoft.com",
  "welivesecurity.com",
  "crowdstrike.com",
  "cloud.google.com",
]);

function getCuratedDomainsSet(): Set<string> {
  const set = new Set<string>();
  for (const s of SOURCE_SEED) {
    try {
      const u = new URL(s.homepageUrl);
      set.add(u.hostname.toLowerCase().replace(/^www\./, ""));
    } catch {
      // Seed with an invalid homepage URL contributes no domain.
    }
  }
  for (const d of PRIMARY_SEED_DOMAINS) {
    set.add(d.toLowerCase().replace(/^www\./, ""));
  }
  [
    "paloaltonetworks.com",
    "unit42.paloaltonetworks.com",
    "talosintelligence.com",
    "blog.talosintelligence.com",
    "ahnlab.com",
    "asec.ahnlab.com",
    "jp.ahnlab.com",
    "checkpoint.com",
    "research.checkpoint.com",
    "sophos.com",
    "news.sophos.com",
    "sekoia.io",
    "blog.sekoia.io",
    "welivesecurity.com",
    "eset.com",
    "redcanary.com",
    "sentinelone.com",
    "huntress.com",
    "cisa.gov",
    "bleepingcomputer.com",
    "trendmicro.com",
    "microsoft.com",
    "techcommunity.microsoft.com",
    "cloud.google.com",
    "mandiant.com",
    "sans.edu",
    "isc.sans.edu",
    "rapid7.com",
    "specterops.io",
    "posts.specterops.io",
    "attackiq.com",
    "center-for-threat-informed-defense.github.io",
    "elastic.co",
  ].forEach((d) => set.add(d.toLowerCase()));
  return set;
}

function formatDiscoveredDomainName(domain: string): string {
  const d = domain.toLowerCase().replace(/^www\./, "");
  const KNOWN_NAMES: Record<string, string> = {
    "attack.mitre.org": "MITRE ATT&CK Framework",
    "github.com": "GitHub Threat Intelligence & PoC Repositories",
    "nvd.nist.gov": "NIST National Vulnerability Database",
    "dhs.gov": "Department of Homeland Security (DHS)",
    "krebsonsecurity.com": "Krebs on Security",
    "ncsc.gov.uk": "UK National Cyber Security Centre (NCSC)",
    "ic3.gov": "FBI Internet Crime Complaint Center (IC3)",
    "justice.gov": "US Department of Justice Cyber Operations",
    "isc.sans.edu": "SANS Internet Storm Center",
    "arxiv.org": "Cornell arXiv Cyber Research Papers",
    "media.defense.gov": "NSA / CISA Defense Publications",
    "cert.pl": "CERT Polska Technical Analysis",
    "securelist.com": "Securelist (Kaspersky GReAT)",
    "zerotracelab.com": "ZeroTrace Lab",
    "arstechnica.com": "Ars Technica Information Security",
    "trendmicro.com": "Trend Micro Threat Research",
    "darkreading.com": "Dark Reading Threat Intelligence",
    "securityweek.com": "SecurityWeek",
    "vx-underground.org": "VX-Underground Samples",
  };
  if (KNOWN_NAMES[d]) return KNOWN_NAMES[d];
  const parts = d.split(".");
  const root = parts.length > 2 && (parts[1] === "gov" || parts[1] === "co" || parts[1] === "ac") ? parts[0] : (parts.length > 1 ? parts[parts.length - 2] : parts[0]);
  return root
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function calculateDiscoveredDomainTrust(domain: string, avgScore?: number): number {
  const d = domain.toLowerCase();
  if (d.endsWith(".gov") || d.endsWith(".mil") || d.includes("mitre.org") || d.includes("nist.gov") || d.includes("media.defense.gov")) {
    return 0.98;
  }
  if (d.endsWith(".edu") || d.includes("arxiv.org") || d.includes("sans.edu")) {
    return 0.94;
  }
  if (d.includes("github.com") || d.includes("ncsc.gov.uk") || d.includes("cert.pl")) {
    return 0.92;
  }
  if (d.includes("krebsonsecurity.com") || d.includes("securelist.com") || d.includes("zerotracelab.com")) {
    return 0.95;
  }
  if (avgScore && avgScore > 0) {
    return Math.min(0.95, Math.max(0.60, Number(avgScore.toFixed(2))));
  }
  return 0.88;
}

export async function mongoListDiscoveredSources(): Promise<DiscoveredSourceRecord[]> {
  if (!isMongoConfigured()) return [];
  const now = Date.now();
  if (cachedDiscoveredSources && now - cachedDiscoveredSources.timestamp < DISCOVERED_SOURCES_CACHE_TTL_MS) {
    logger.cache("HIT", "discovered-sources", "Returned cached discovered sources");
    return cachedDiscoveredSources.data;
  }
  const col = await getThreatIntelCollection();
  const curatedDomains = getCuratedDomainsSet();
  const sourceMap = new Map<string, DiscoveredSourceRecord>();

  // Real report counts from Library (docType: "report") for non-curated external domains
  const reportCountByDomain = new Map<string, number>();
  try {
    const reportAgg = await col
      .aggregate<{ _id: string; count: number }>([
        { $match: { docType: "report" } },
        { $group: { _id: "$sourceDomain", count: { $sum: 1 } } },
      ])
      .toArray();
    for (const r of reportAgg) {
      if (r._id) {
        reportCountByDomain.set(r._id.toLowerCase().replace(/^www\./, ""), r.count);
      }
    }
  } catch (rErr) {
    console.warn("[mongodb] aggregate report counts for discovered sources:", rErr);
  }

  // 1. Any explicitly recorded discovered_source docs
  try {
    const docs = await col
      .find({ docType: "discovered_source" })
      .sort({ resourceCount: -1, trustScore: -1 })
      .limit(100)
      .toArray();

    for (const d of docs) {
      const rawDomain = (d.domain || "").toLowerCase().trim().replace(/^www\./, "");
      if (!rawDomain || curatedDomains.has(rawDomain)) continue;
      const liveReportCount = reportCountByDomain.get(rawDomain) || 0;
      const count = Math.max(Number(d.resourceCount ?? 0), liveReportCount);
      const isVerifiedReportSource = liveReportCount > 0;

      sourceMap.set(rawDomain, {
        id: d.id || `src_disc_${rawDomain.replace(/[^a-z0-9]/gi, "_")}`,
        domain: rawDomain,
        name: d.name || formatDiscoveredDomainName(rawDomain),
        homepageUrl: d.homepageUrl || `https://${rawDomain}`,
        crawlPattern: d.crawlPattern || (d.base_url ? `${d.base_url}/*` : `https://${rawDomain}/*`),
        parentSource: d.parentSource || (isVerifiedReportSource ? "Library Report" : "Citation Discovery"),
        parentUrl: d.parentUrl,
        discoveryPath: (d.discoveryPath as string[]) || [rawDomain],
        trustScore: Number(d.trustScore ?? calculateDiscoveredDomainTrust(rawDomain)),
        resourceCount: Math.max(count, 1),
        status: isVerifiedReportSource ? "verified" : (d.status || "discovered"),
        origin: d.origin || (d.crawlPattern || d.whyCrawl ? "agent_discovery" : "crawler_outlink"),
        enabled: d.enabled !== false,
        notes: d.notes || d.whyCrawl || "",
        whyCrawl: d.whyCrawl || d.notes || "",
        firstDiscoveredAt: d.firstDiscoveredAt || new Date().toISOString(),
        lastSeenAt: d.lastSeenAt || new Date().toISOString(),
      });
    }
  } catch (err) {
    console.warn("[mongodb] explicit discovered_source query error:", err);
  }

  // 2. Ensure every external domain that has reports in Library is tracked in Discovered Sources
  for (const [dom, count] of reportCountByDomain.entries()) {
    if (!curatedDomains.has(dom) && dom.includes(".") && !sourceMap.has(dom)) {
      sourceMap.set(dom, {
        id: `src_disc_${dom.replace(/[^a-z0-9]/gi, "_")}`,
        domain: dom,
        name: formatDiscoveredDomainName(dom),
        homepageUrl: `https://${dom}`,
        crawlPattern: `https://${dom}/*`,
        parentSource: "Library Report Ingestion",
        discoveryPath: ["Library", dom],
        trustScore: calculateDiscoveredDomainTrust(dom),
        resourceCount: count,
        status: "verified",
        origin: "agent_discovery",
        enabled: true,
        firstDiscoveredAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
      });
    }
  }

  // 3. Aggregate unique external domains from discovered_resource
  try {
    const resourceAgg = await col
      .aggregate<{
        _id: string;
        resourceCount: number;
        parentSource: string;
        parentUrl?: string;
        minDate?: string;
        maxDate?: string;
        avgScore?: number;
      }>([
        { $match: { docType: "discovered_resource" } },
        {
          $group: {
            _id: "$sourceDomain",
            resourceCount: { $sum: 1 },
            parentSource: { $first: "$parentSource" },
            parentUrl: { $first: "$parentUrl" },
            minDate: { $min: "$createdAt" },
            maxDate: { $max: "$createdAt" },
            avgScore: { $avg: "$qualityScore" },
          },
        },
        { $sort: { resourceCount: -1 } },
        { $limit: 100 },
      ])
      .toArray();

    for (const r of resourceAgg) {
      const domain = (r._id || "").toLowerCase().trim().replace(/^www\./, "");
      if (!domain || curatedDomains.has(domain) || !domain.includes(".")) continue;

      const trustScore = calculateDiscoveredDomainTrust(domain, r.avgScore);
      const resCount = r.resourceCount || 1;
      const existing = sourceMap.get(domain);

      if (!existing) {
        sourceMap.set(domain, {
          id: `src_disc_${domain.replace(/[^a-z0-9]/gi, "_")}`,
          domain,
          name: formatDiscoveredDomainName(domain),
          homepageUrl: `https://${domain}`,
          crawlPattern: `https://${domain}/*`,
          parentSource: r.parentSource || "Autonomous Crawler Outlink",
          parentUrl: r.parentUrl || `https://${domain}`,
          discoveryPath: [r.parentSource || "Primary Seed", domain],
          trustScore,
          resourceCount: resCount,
          status: resCount >= 3 || trustScore >= 0.90 ? "approved" : "discovered",
          firstDiscoveredAt: r.minDate || new Date().toISOString(),
          lastSeenAt: r.maxDate || new Date().toISOString(),
        });
      } else {
        existing.resourceCount = Math.max(existing.resourceCount, resCount);
      }
    }
  } catch (aggErr) {
    console.warn("[mongodb] aggregate discovered_resource domains:", aggErr);
  }

  // 4. Aggregate unique external domains from crawl_job_item where depth > 0
  try {
    const itemAgg = await col
      .aggregate<{
        _id: string;
        resourceCount: number;
        publisher?: string;
        parentUrl?: string;
        minDate?: string;
        maxDate?: string;
      }>([
        { $match: { docType: "crawl_job_item", depth: { $gt: 0 } } },
        {
          $group: {
            _id: "$domain",
            resourceCount: { $sum: 1 },
            publisher: { $first: "$publisher" },
            parentUrl: { $first: "$parentUrl" },
            minDate: { $min: "$createdAt" },
            maxDate: { $max: "$createdAt" },
          },
        },
        { $sort: { resourceCount: -1 } },
        { $limit: 100 },
      ])
      .toArray();

    for (const item of itemAgg) {
      const domain = (item._id || "").toLowerCase().trim().replace(/^www\./, "");
      if (!domain || curatedDomains.has(domain) || !domain.includes(".")) continue;

      const existing = sourceMap.get(domain);
      const trustScore = calculateDiscoveredDomainTrust(domain);
      const count = item.resourceCount || 1;

      if (!existing) {
        sourceMap.set(domain, {
          id: `src_disc_${domain.replace(/[^a-z0-9]/gi, "_")}`,
          domain,
          name: formatDiscoveredDomainName(domain),
          homepageUrl: `https://${domain}`,
          crawlPattern: `https://${domain}/*`,
          parentSource: item.publisher || "Citation Discovery",
          parentUrl: item.parentUrl || `https://${domain}`,
          discoveryPath: [item.publisher || "Seed Outlink", domain],
          trustScore,
          resourceCount: count,
          status: count >= 3 || trustScore >= 0.90 ? "approved" : "discovered",
          firstDiscoveredAt: item.minDate || new Date().toISOString(),
          lastSeenAt: item.maxDate || new Date().toISOString(),
        });
      } else {
        existing.resourceCount = Math.max(existing.resourceCount, count);
      }
    }
  } catch (aggErr2) {
    console.warn("[mongodb] aggregate crawl_job_item domains:", aggErr2);
  }

  const results = Array.from(sourceMap.values()).sort((a, b) => {
    // Verified sources with library reports first
    const aVerified = a.status === "verified" ? 1 : 0;
    const bVerified = b.status === "verified" ? 1 : 0;
    if (bVerified !== aVerified) return bVerified - aVerified;
    if (b.resourceCount !== a.resourceCount) return b.resourceCount - a.resourceCount;
    return b.trustScore - a.trustScore;
  });
  cachedDiscoveredSources = { timestamp: Date.now(), data: results };
  return results;
}

export async function mongoCreateDiscoveredSource(
  source: Partial<DiscoveredSourceRecord>,
): Promise<DiscoveredSourceRecord> {
  const col = await getThreatIntelCollection();
  const domain = (source.domain || "").toLowerCase().trim().replace(/^www\./, "");
  const id = source.id || `src_disc_${domain.replace(/[^a-z0-9]/gi, "_")}_${Date.now().toString(36)}`;
  const record: DiscoveredSourceRecord = {
    id,
    domain,
    name: source.name || formatDiscoveredDomainName(domain),
    homepageUrl: source.homepageUrl || `https://${domain}`,
    crawlPattern: source.crawlPattern || `https://${domain}/*`,
    parentSource: source.parentSource || "Manual Discovered Source",
    discoveryPath: source.discoveryPath || [domain],
    trustScore: Number(source.trustScore ?? 0.85),
    resourceCount: Number(source.resourceCount ?? 1),
    status: source.status || "discovered",
    origin: source.origin || "manual",
    enabled: source.enabled !== false,
    notes: source.notes || "",
    whyCrawl: source.whyCrawl || "",
    firstDiscoveredAt: source.firstDiscoveredAt || new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
  };

  await col.updateOne(
    { docType: "discovered_source", domain },
    { $set: { docType: "discovered_source", ...record } },
    { upsert: true },
  );
  cachedDiscoveredSources = null;
  invalidateCrawlerStateCache();
  return record;
}

export async function mongoUpdateDiscoveredSource(
  id: string,
  updates: Partial<DiscoveredSourceRecord>,
): Promise<void> {
  const col = await getThreatIntelCollection();
  const { id: _id, domain: _domain, firstDiscoveredAt: _first, ...safeUpdates } = updates;
  await col.updateOne(
    { docType: "discovered_source", id },
    { $set: { ...safeUpdates, lastSeenAt: new Date().toISOString() } },
  );
  cachedDiscoveredSources = null;
  invalidateCrawlerStateCache();
}

export async function mongoRevokeDiscoveredSource(id: string): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "discovered_source", id },
    { $set: { status: "rejected", enabled: false, lastSeenAt: new Date().toISOString() } },
  );
  cachedDiscoveredSources = null;
  invalidateCrawlerStateCache();
}

export async function mongoDeleteDiscoveredSource(id: string): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.deleteOne({ docType: "discovered_source", id });
  cachedDiscoveredSources = null;
  invalidateCrawlerStateCache();
}

export async function mongoToggleDiscoveredSource(id: string, enabled: boolean): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "discovered_source", id },
    { $set: { enabled, lastSeenAt: new Date().toISOString() } },
  );
  cachedDiscoveredSources = null;
  invalidateCrawlerStateCache();
}

export async function mongoValidateDiscoveredSource(
  id: string,
  status: "discovered" | "evaluated" | "approved" | "ignored" | "verified" | "rejected",
): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "discovered_source", id },
    { $set: { status, lastSeenAt: new Date().toISOString() } },
  );
  cachedDiscoveredSources = null;
  invalidateCrawlerStateCache();
}

export async function mongoInsertGraphEdge(edge: Omit<DiscoveryGraphEdge, "id" | "createdAt">) {
  if (!isMongoConfigured()) return;
  try {
    const col = await getThreatIntelCollection();
    const id = `edge_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    await col.updateOne(
      { docType: "graph_edge", from: edge.from, to: edge.to, relationship: edge.relationship },
      {
        $set: {
          docType: "graph_edge",
          id,
          ...edge,
          createdAt: new Date().toISOString(),
        },
      },
      { upsert: true },
    );
  } catch (err) {
    console.warn("[mongodb] mongoInsertGraphEdge error:", err);
  }
}

export async function mongoInsertGraphEdgesBatch(edges: Omit<DiscoveryGraphEdge, "id" | "createdAt">[]) {
  if (!isMongoConfigured() || edges.length === 0) return;
  try {
    const col = await getThreatIntelCollection();
    const ops = edges.map((edge) => ({
      updateOne: {
        filter: { docType: "graph_edge", from: edge.from, to: edge.to, relationship: edge.relationship },
        update: {
          $set: {
            docType: "graph_edge",
            id: `edge_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`,
            ...edge,
            createdAt: new Date().toISOString(),
          },
        },
        upsert: true,
      },
    }));
    await col.bulkWrite(ops, { ordered: false });
  } catch (err) {
    console.warn("[mongodb] mongoInsertGraphEdgesBatch error:", err);
  }
}

export async function mongoListGraphEdges(limit = 60): Promise<DiscoveryGraphEdge[]> {
  if (!isMongoConfigured()) return [];
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "graph_edge" })
    .project({
      id: 1,
      from: 1,
      to: 1,
      relationship: 1,
      label: 1,
      jobId: 1,
      createdAt: 1,
    })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();
  return docs.map((d) => ({
    id: d.id || `edge_${d._id}`,
    from: d.from,
    to: d.to,
    relationship: d.relationship,
    label: d.label,
    jobId: d.jobId,
    createdAt: d.createdAt,
  }));
}

async function getOrComputeTelemetrySummary(col: any) {
  const now = Date.now();
  if (cachedTelemetrySummary && now - cachedTelemetrySummary.timestamp < TELEMETRY_SUMMARY_TTL_MS) {
    return cachedTelemetrySummary.data;
  }

  const [sourceStatsDocs, totalDiscovered, totalSources, totalJobs, totalGraphEdges] = await Promise.all([
    col
      .aggregate([
        { $match: { docType: "crawl_job_item" } },
        {
          $group: {
            _id: "$publisher",
            found: { $sum: 1 },
            ingested: {
              $sum: { $cond: [{ $eq: ["$decision", "INGESTED"] }, 1, 0] },
            },
            failed: {
              $sum: { $cond: [{ $eq: ["$decision", "FAILED"] }, 1, 0] },
            },
          },
        },
        { $sort: { ingested: -1, found: -1 } },
        { $limit: 8 },
      ])
      .toArray(),
    col.countDocuments({ docType: "discovered_resource" }),
    col.countDocuments({ docType: "source" }),
    col.countDocuments({ docType: "crawl_job" }),
    col.countDocuments({ docType: "graph_edge" }),
  ]);

  const sourceStats = sourceStatsDocs.map((s: any) => ({
    sourceName: s._id || "Unknown Source",
    found: Number(s.found),
    ingested: Number(s.ingested),
    failed: Number(s.failed),
  }));

  const data = {
    sourceStats,
    totalDiscovered,
    totalSources,
    totalJobs,
    totalGraphEdges,
  };

  cachedTelemetrySummary = { timestamp: now, data };
  return data;
}

export async function mongoGetCrawlerState(): Promise<CrawlerState> {
  // Non-blocking trigger of autonomous schedule check
  triggerScheduleCheck();

  const now = Date.now();
  const hasActiveJob = Boolean(cachedCrawlerState?.data?.activeJob);
  const ttl = hasActiveJob ? CRAWLER_STATE_ACTIVE_TTL_MS : CRAWLER_STATE_IDLE_TTL_MS;
  if (cachedCrawlerState && now - cachedCrawlerState.timestamp < ttl) {
    logger.cache("HIT", "crawler-state", "Returned cached crawler telemetry");
    return cachedCrawlerState.data;
  }

  const startTime = Date.now();
  let attempts = 0;
  while (attempts < 2) {
    attempts++;
    try {
      const col = await getThreatIntelCollection();

      const [
        config,
        jobs,
        items,
        discovered,
        discoveredSources,
        graphEdges,
        summaryData,
      ] = await Promise.all([
        mongoGetCrawlConfig(),
        mongoListRecentCrawlJobs(100),
        mongoListRecentCrawlJobItems(250),
        mongoListDiscoveredResources(350),
        mongoListDiscoveredSources(),
        mongoListGraphEdges(150),
        getOrComputeTelemetrySummary(col),
      ]);

      // Watchdog & Zombie Job Reconciliation:
      // Auto-detect and reconcile jobs stuck in "running" status across process restarts or exceeding runtime limits
      const nowTime = Date.now();
      const maxJobDurationMs = (config.maxRunTimeMinutes || 5) * 60 * 1000;

      for (const j of jobs) {
        if (j.status === "running") {
          const startedMs = j.startedAt ? new Date(j.startedAt).getTime() : 0;
          const elapsedMs = nowTime - startedMs;
          // Never a job this process is running; otherwise expired past its limit, or orphaned after 60s.
          const staleReason = staleRunningJobReason(j, nowTime, maxJobDurationMs);
          const isExpired = staleReason === "expired";
          const isOrphaned = staleReason === "orphaned";

          if (staleReason) {
            logger.warn(
              "crawler-watchdog",
              `Auto-reconciling stuck crawl job ${j.id} (elapsed: ${Math.round(elapsedMs / 1000)}s, limit: ${Math.round(maxJobDurationMs / 60000)}m, expired: ${isExpired}, orphaned: ${isOrphaned})`,
            );
            j.status = "completed";
            j.completedAt = j.completedAt || new Date().toISOString();
            j.errorSummary = isExpired
              ? `Job auto-finalized: exceeded configured time limit (${config.maxRunTimeMinutes || 5} min)`
              : "Job finalized: process restart or execution state reconciled";
            j.currentStage = "indexed";

            // Persist update to MongoDB Atlas document so it is healed for all future sessions
            void col.updateOne(
              { docType: "crawl_job", id: j.id },
              {
                $set: {
                  status: "completed",
                  completedAt: j.completedAt,
                  errorSummary: j.errorSummary,
                  currentStage: "indexed",
                  updatedAt: new Date().toISOString(),
                },
              },
            ).catch(() => {});
          }
        }
      }

      const activeJob = jobs.find((j) => j.status === "running") ?? null;

      const state: CrawlerState = {
        config,
        activeJob,
        jobs,
        items,
        discovered,
        discoveredSources,
        graphEdges,
        sourceStats: summaryData.sourceStats,
        totalCounts: {
          discovered: summaryData.totalDiscovered,
          sources: summaryData.totalSources,
          jobs: summaryData.totalJobs,
          graphEdges: summaryData.totalGraphEdges,
        },
      };

      const cleanState = JSON.parse(JSON.stringify(state));
      cachedCrawlerState = { timestamp: Date.now(), data: cleanState };
      lastKnownGoodCrawlerState = cleanState;
      logger.mongo("crawlerState", "threat-intel", Date.now() - startTime, "Fetched crawler state telemetry");
      return cleanState;
    } catch (err) {
      if (lastKnownGoodCrawlerState) {
        logger.warn(
          "mongodb",
          "mongoGetCrawlerState encountered transient error; serving last known good Atlas state:",
          err instanceof Error ? err.message : err,
        );
        return lastKnownGoodCrawlerState;
      }
      if (cachedCrawlerState?.data) {
        return cachedCrawlerState.data;
      }
      if (attempts < 2) {
        logger.warn(
          "mongodb",
          `mongoGetCrawlerState fetch attempt ${attempts} failed, retrying in 1s...`,
          err instanceof Error ? err.message : err,
        );
        await new Promise((r) => setTimeout(r, 1000));
        continue;
      }
      throw err;
    }
  }

  // Fallback if loop finishes unexpectedly
  if (lastKnownGoodCrawlerState) {
    return lastKnownGoodCrawlerState;
  }
  if (cachedCrawlerState?.data) {
    return cachedCrawlerState.data;
  }
  throw new Error("Unable to fetch crawler state from database");
}

// ---------------------------------------------------------------------------
// Dashboard Aggregates
// ---------------------------------------------------------------------------

export async function mongoListRecentReports(limit = 6): Promise<ReportListItem[]> {
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "report" })
    .sort({ ingestedAt: -1 })
    .limit(limit)
    .project({
      id: 1,
      sourceId: 1,
      sourceName: 1,
      title: 1,
      url: 1,
      canonicalUrl: 1,
      publishedAt: 1,
      contentType: 1,
      status: 1,
      rawHash: 1,
      textHash: 1,
      qualityScore: 1,
      wordCount: 1,
      iocs: 1,
      ingestOrigin: 1,
      ingestedAt: 1,
      publisher: 1,
      author: 1,
      classification: 1,
      resourceKind: 1,
      simulationScore: 1,
      isEmergingTechnique: 1,
      noveltyRationale: 1,
      excerpt: 1,
    })
    .toArray();

  return docs.map((doc) => {
    const rawExcerpt = (doc.excerpt as string) || "";
    const text = rawExcerpt || (doc.extractedText as string) || (doc.title as string) || "";
    const excerpt = rawExcerpt.length > 0 ? rawExcerpt : excerptOf(text);
    const iocsList = (doc.iocs as IocHit[]) || [];

    return {
      id: doc.id,
      sourceId: doc.sourceId,
      sourceName: doc.sourceName || doc.publisher || "Verified Source",
      title: doc.title,
      url: doc.url,
      canonicalUrl: doc.canonicalUrl,
      publishedAt: doc.publishedAt ?? null,
      contentType: doc.contentType || "text/html",
      status: doc.status || "acquired",
      rawHash: doc.rawHash,
      textHash: doc.textHash,
      qualityScore: Number(doc.qualityScore ?? 0),
      wordCount: Number(doc.wordCount ?? 0),
      iocs: iocsList,
      ingestOrigin: doc.ingestOrigin || "crawl",
      ingestedAt: doc.ingestedAt,
      excerpt,
      iocCount: iocsList.length,
      publisher: doc.publisher || doc.sourceName,
      author: doc.author || doc.publisher,
      classification: doc.classification || "THREAT_REPORT",
      resourceKind: (doc.resourceKind as ResourceKind) || "CAMPAIGN_INTEL",
      simulationScore: typeof doc.simulationScore === "number" ? doc.simulationScore : undefined,
      isEmergingTechnique: Boolean(doc.isEmergingTechnique),
      noveltyRationale: (doc.noveltyRationale as string) || undefined,
      version: Number(doc.version ?? 1),
      discoveryMethod: doc.discoveryMethod || "",
      discoveryQuery: doc.discoveryQuery || "",
      parentSource: doc.parentSource || "",
      sourceDomain: doc.sourceDomain || "",
    };
  });
}

export async function mongoGetDashboardStats(): Promise<DashboardStats> {
  // Non-blocking trigger of autonomous schedule check
  triggerScheduleCheck();

  if (cachedDashboardStats && Date.now() - cachedDashboardStats.timestamp < DASHBOARD_CACHE_TTL_MS) {
    logger.mongo(
      "getDashboardStats",
      "threat-intel",
      0,
      `Returned cached metrics (${cachedDashboardStats.data.reportCount} reports, ${cachedDashboardStats.data.sourceCount} sources)`,
      true,
    );
    return cachedDashboardStats.data;
  }

  const startTime = Date.now();
  const col = await getThreatIntelCollection();

  const [
    sourceTotal,
    enabledSources,
    reportTotal,
    acquiredTotal,
    discoveredSourcesCount,
    metricsAgg,
    recent,
    events,
    config,
    activeJob,
    analyticsReports,
  ] = await Promise.all([
    col.countDocuments({ docType: "source" }),
    col.countDocuments({ docType: "source", enabled: true }),
    col.countDocuments({ docType: "report" }),
    col.countDocuments({ docType: "report", status: "acquired" }),
    col.countDocuments({ docType: "discovered_source" }),
    col.aggregate<{ _id: null; avgQ: number; totalIocs: number }>([
      { $match: { docType: "report", status: "acquired" } },
      {
        $group: {
          _id: null,
          avgQ: { $avg: "$qualityScore" },
          totalIocs: { $sum: { $size: { $ifNull: ["$iocs", []] } } },
        },
      },
    ]).toArray(),
    mongoListRecentReports(6),
    mongoListRecentIngestEvents(8),
    mongoGetCrawlConfig(),
    col.findOne({ docType: "crawl_job", status: "running" }),
    col
      .find({ docType: "report", status: { $ne: "rejected" } })
      .project({
        id: 1,
        title: 1,
        url: 1,
        ingestedAt: 1,
        tags: 1,
        "analysis.threatActors": 1,
        "analysis.malware": 1,
        "analysis.attackChain": 1,
        "analysis.ttps": 1,
        "analysis.vulnerabilities": 1,
        "extractedEntities.threatActors": 1,
        "extractedEntities.malwareFamilies": 1,
        "extractedEntities.cves": 1,
        "extractedEntities.tactics": 1,
        "extractedEntities.techniques": 1,
      })
      .toArray(),
  ]);

  const avgQuality = metricsAgg[0]?.avgQ ? Math.round(Number(metricsAgg[0].avgQ) * 100) / 100 : 0;
  const iocCount = Number(metricsAgg[0]?.totalIocs ?? 0);

  logger.mongo(
    "getDashboardStats",
    "threat-intel",
    Date.now() - startTime,
    `Aggregated 11 queries in ${Date.now() - startTime}ms: ${reportTotal} reports, ${sourceTotal} sources, ${iocCount} IOCs`,
  );

  let effectiveActiveJob = activeJob;
  if (effectiveActiveJob) {
    const maxJobDurationMs = (config.maxRunTimeMinutes || 5) * 60 * 1000;
    const watched = { id: String(effectiveActiveJob.id), startedAt: effectiveActiveJob.startedAt as string | null | undefined };
    if (staleRunningJobReason(watched, Date.now(), maxJobDurationMs)) {
      const orphanJobId = effectiveActiveJob.id;
      effectiveActiveJob = null;
      void col.updateOne(
        { docType: "crawl_job", id: orphanJobId },
        {
          $set: {
            status: "completed",
            completedAt: new Date().toISOString(),
            errorSummary: "Job auto-finalized by dashboard watchdog",
            currentStage: "indexed",
            updatedAt: new Date().toISOString(),
          },
        },
      ).catch(() => {});
    }
  }

  const crawlerStatus = effectiveActiveJob
    ? "running"
    : config.paused
      ? "paused"
      : config.enabled
        ? "scheduled"
        : "disabled";

  // Dynamically compute threat actors, CVEs, flows, matrix heatmap, regions and tactics from real reports
  const analytics = computeDashboardAnalytics(analyticsReports || []);

  const stats: DashboardStats = {
    sourceCount: sourceTotal,
    enabledSources,
    reportCount: reportTotal,
    acquiredCount: acquiredTotal,
    avgQuality,
    iocCount,
    recent,
    events,
    crawlerStatus,
    lastCrawlAt: config.lastRunAt,
    nextCrawlAt: config.nextRunAt,
    discoveredSourcesCount,
    threatRegions: analytics.threatRegions,
    tacticDistribution: analytics.tacticDistribution,
    topThreatActors: analytics.topThreatActors,
    cveVelocity: analytics.cveVelocity,
    threatFlows: analytics.threatFlows,
    attackHeatmap: analytics.attackHeatmap,
  };

  cachedDashboardStats = { timestamp: Date.now(), data: stats };
  return stats;
}

export async function mongoGetIngestedCanonicalUrls(): Promise<Set<string>> {
  if (!isMongoConfigured()) return new Set();
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "report" })
    .project({ canonicalUrl: 1, _id: 0 })
    .toArray();
  const set = new Set<string>();
  for (const d of docs) {
    if (d.canonicalUrl) set.add(d.canonicalUrl);
  }
  return set;
}

export async function mongoGetExistingReportsDedupIndex(): Promise<
  Array<{
    id: string;
    canonicalUrl: string;
    textHash: string;
    title: string;
    excerpt: string;
    wordCount?: number;
    /** computeReportSimHash(extractedText), stored at insert; absent on older records. */
    simhash?: string;
  }>
> {
  if (!isMongoConfigured()) return [];
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "report" })
    .project({ id: 1, canonicalUrl: 1, textHash: 1, title: 1, excerpt: 1, wordCount: 1, simhash: 1, _id: 0 })
    .toArray();
  return docs as any[];
}

// ---------------------------------------------------------------------------
// Original fetched content (as received, before any extraction/regeneration).
// Stored once per report as gzip+base64; rawHtml stays the display rendition.
// ---------------------------------------------------------------------------

/** Originals above this size are not stored (rawHash still identifies them). */
export const MAX_ORIGINAL_CONTENT_BYTES = 1_500_000;

type ReportOriginalFields = {
  originalContent: string; // gzip, base64
  originalContentType: string;
  originalBytes: number; // uncompressed length
  originalStoredAt: string;
};

/**
 * Save the original fetched bytes for a report. Write-once: an existing
 * original is never overwritten. Returns false when skipped (too large,
 * empty, already stored, or Mongo not configured).
 */
export async function mongoSaveReportOriginal(
  id: string,
  content: string | Uint8Array,
  contentType: string,
): Promise<boolean> {
  if (!isMongoConfigured() || !id) return false;
  const bytes = typeof content === "string" ? Buffer.from(content, "utf8") : Buffer.from(content);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_ORIGINAL_CONTENT_BYTES) return false;
  const { gzipSync } = await import("node:zlib");
  const fields: ReportOriginalFields = {
    originalContent: gzipSync(bytes).toString("base64"),
    originalContentType: contentType || "application/octet-stream",
    originalBytes: bytes.byteLength,
    originalStoredAt: new Date().toISOString(),
  };
  const col = await getThreatIntelCollection();
  const res = await col.updateOne(
    { docType: "report", id, originalContent: { $exists: false } },
    { $set: fields },
  );
  return res.modifiedCount > 0;
}

/** Original content of a report: `bytes` is base64 of the gzip stream; `length` is the uncompressed size. */
export async function mongoGetReportOriginal(
  id: string,
): Promise<{ contentType: string; bytes: string; length: number } | null> {
  if (!isMongoConfigured()) return null;
  const col = await getThreatIntelCollection();
  const doc = await col.findOne(
    { docType: "report", id },
    { projection: { originalContent: 1, originalContentType: 1, originalBytes: 1, _id: 0 } },
  );
  if (!doc || typeof doc.originalContent !== "string" || !doc.originalContent) return null;
  return {
    contentType: String(doc.originalContentType || "application/octet-stream"),
    bytes: doc.originalContent,
    length: Number(doc.originalBytes ?? 0),
  };
}

/**
 * AI-powered Library Quality Audit & Verification Engine
 * Analyzes full content, extracts MITRE ATT&CK techniques, actors, malware, and CVEs,
 * tags resources accurately, assigns canonical ResourceKinds, verifies authentic threat intel,
 * and safely prunes confirmed non-threat content (generic index queries, webinars, podcasts, error pages)
 * if autoPruneJunk is enabled.
 */
export async function mongoAuditLibraryWithAi(options?: {
  autoPruneJunk?: boolean;
  limit?: number;
  unverifiedOnly?: boolean;
  forceAll?: boolean;
}): Promise<{
  success: boolean;
  totalAudited: number;
  verifiedCount: number;
  prunedCount: number;
  aiEvaluatedCount: number;
  prunedTitles: string[];
  message: string;
}> {
  const startTime = Date.now();
  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();

  // If autoPruneJunk is not explicitly specified, check CrawlConfig
  let shouldPrune = options?.autoPruneJunk;
  if (shouldPrune === undefined) {
    const cfg = await mongoGetCrawlConfig();
    shouldPrune = Boolean(cfg.agentAutoPruneJunkEnabled);
  }

  const reports = await col.find({ docType: "report" }, { projection: { originalContent: 0 } }).toArray();
  let verifiedCount = 0;
  let prunedCount = 0;
  let aiEvaluatedCount = 0;
  const prunedTitles: string[] = [];
  const maxAiEvaluations = options?.limit ?? 10;

  for (const doc of reports) {
    const iocCount = Array.isArray(doc.iocs) ? doc.iocs.length : 0;
    const entities = doc.extractedEntities as ExtractedEntities | undefined;
    const analysis = doc.analysis as IntelAnalysis | undefined;
    const qualityScore = Number(doc.qualityScore ?? 0);
    const wordCount = Number(doc.wordCount ?? 0);
    const title = (doc.title as string) || "";
    const url = (doc.url as string) || "";
    const text = (doc.extractedText as string) || "";

    // STRICT SAFETY GUARDRAILS: High-value technical assets must NEVER be pruned
    const hasProtectedSignals =
      iocCount >= 2 ||
      (entities?.cves && entities.cves.length > 0) ||
      (entities?.techniques && entities.techniques.length > 0) ||
      (analysis?.attackChain && analysis.attackChain.length > 0) ||
      qualityScore >= 0.70;

    // Check for junk patterns (structural quality pre-screening)
    let isJunk = false;
    let junkReason = "";

    try {
      const u = new URL(url);
      const host = u.hostname.replace(/^www\./, "").toLowerCase();
      const path = u.pathname.replace(/\/+$/, "") || "/";
      if (
        host === "uscis.gov" ||
        host === "ice.gov" ||
        host === "e-verify.gov" ||
        host === "edit.dhs.gov" ||
        (host.endsWith(".dhs.gov") && !host.includes("cisa"))
      ) {
        isJunk = true;
        junkReason = `Non-CTI administrative host: ${host}`;
      } else if (
        path === "" ||
        path === "/" ||
        path === "/en" ||
        path === "/en-us" ||
        path === "/en_us" ||
        /sitemap/i.test(path)
      ) {
        isJunk = true;
        junkReason = `Homepage or root sitemap: ${path || "/"}`;
      } else if (
        path.endsWith("/podcasts") ||
        path.includes("/podcasts/") ||
        path.endsWith("/webinars") ||
        path.endsWith("/white-papers") ||
        path.endsWith("/tips-advice") ||
        path.endsWith("/business-security") ||
        path.endsWith("/disclosure-policy") ||
        path.endsWith("/privacy-policy") ||
        path.endsWith("/privacy") ||
        path.endsWith("/terms") ||
        path.endsWith("/contact") ||
        path.endsWith("/about") ||
        path.endsWith("/sitemap1.aspx") ||
        path.endsWith("/latest-publications") ||
        path.endsWith("/resources") ||
        path.endsWith("/projects") ||
        path.endsWith("/nice")
      ) {
        isJunk = true;
        junkReason = `Index / Resource aggregator path: ${path}`;
      }
    } catch {
      // Invalid URL
    }

    if (!isJunk && !hasProtectedSignals) {
      const lowerUrl = url.toLowerCase();
      const lowerTitle = title.toLowerCase();

      // 1. Generic portal search/filter query pages (e.g. CISA facet filters)
      if (
        (lowerUrl.includes("?f%5b") || lowerUrl.includes("?f[")) &&
        (lowerTitle.includes("alerts & advisories") || lowerTitle.includes("cybersecurity alerts")) &&
        iocCount === 0
      ) {
        isJunk = true;
        junkReason = "Generic portal search/filter index page with zero IOCs";
      }
      // 2. Podcast audio landing pages
      else if ((lowerUrl.includes("/podcasts/") || lowerTitle.includes("podcast") || lowerUrl.includes("talos_takes")) && iocCount === 0) {
        isJunk = true;
        junkReason = "Podcast episode / audio landing page without technical indicators";
      }
      // 3. Webinar sign-up marketing pages
      else if (
        (lowerTitle.startsWith("[webinar]") || lowerTitle.includes("exclusive briefing on q2 incidents")) &&
        iocCount === 0
      ) {
        isJunk = true;
        junkReason = "Commercial webinar marketing registration page";
      }
      // 4. Utility pages (contact, privacy, 404)
      else if (
        lowerTitle === "podcasts" ||
        lowerTitle === "white papers" ||
        lowerTitle === "tips & advice" ||
        lowerTitle === "privacy policy" ||
        lowerTitle.includes("contact us") ||
        lowerTitle.includes("page not found") ||
        lowerTitle.includes("404 not found")
      ) {
        isJunk = true;
        junkReason = "Corporate utility / 404 / contact page";
      }
      // 5. Bare shell (<120 words with 0 IOCs and 0 techniques)
      else if (wordCount < 120 && iocCount === 0 && (!entities?.tactics || entities.tactics.length === 0) && (!entities?.techniques || entities.techniques.length === 0)) {
        isJunk = true;
        junkReason = "Sub-threshold stub content with no technical evidence";
      }
    }

    if (isJunk) {
      if (shouldPrune) {
        await col.deleteOne({ id: doc.id, docType: "report" });
        prunedCount++;
        prunedTitles.push(title || url);
        continue;
      } else {
        await col.updateOne(
          { id: doc.id, docType: "report" },
          {
            $set: {
              status: "rejected",
              aiVerified: false,
              aiQualityScore: 0,
              aiAuditReason: `Rejected by Quality Gate: ${junkReason}`,
              updatedAt: new Date().toISOString(),
            },
          }
        );
        prunedCount++;
        prunedTitles.push(title || url);
        continue;
      }
    }

    let calculatedKind = (doc.resourceKind as ResourceKind) || null;
    const cls = (doc.classification || "").toUpperCase();
    const fullTextUpper = (text + " " + title).toUpperCase();
    const tags = Array.isArray(doc.tags) && doc.tags.length > 0 ? doc.tags : deriveReportTags(doc as any);

    if (
      cls.includes("INTRUSION") ||
      cls.includes("ATTACK_CHAIN") ||
      (analysis?.attackChain && analysis.attackChain.length > 0) ||
      fullTextUpper.includes("INITIAL ACCESS") ||
      fullTextUpper.includes("LATERAL MOVEMENT")
    ) {
      calculatedKind = "FULL_ATTACK_CHAIN";
    } else if (
      cls.includes("MALWARE") ||
      (analysis?.malware && analysis.malware.length > 0) ||
      fullTextUpper.includes("REVERSE ENGINEERING") ||
      fullTextUpper.includes("C2 BEACON") ||
      fullTextUpper.includes("LOADER")
    ) {
      calculatedKind = "MALWARE_ANALYSIS";
    } else if (
      cls.includes("EMULATION") ||
      cls.includes("PROCEDURE") ||
      cls.includes("PURPLE") ||
      (analysis?.emulation && analysis.emulation.length > 0) ||
      fullTextUpper.includes("ADVERSARY EMULATION") ||
      fullTextUpper.includes("ATOMIC RED TEAM")
    ) {
      calculatedKind = "PROCEDURE_DEEPDIVE";
    } else if (
      cls.includes("DETECTION") ||
      cls.includes("SIGMA") ||
      (analysis?.detections && analysis.detections.length > 0) ||
      fullTextUpper.includes("SIGMA RULE") ||
      fullTextUpper.includes("HUNTING QUERY")
    ) {
      calculatedKind = "DETECTION_GUIDANCE";
    } else if (
      cls.includes("VULNERABILITY") ||
      (entities?.cves && entities.cves.length > 0) ||
      fullTextUpper.includes("EXPLOITATION") ||
      fullTextUpper.includes("ZERO-DAY")
    ) {
      calculatedKind = "VULNERABILITY_ADVISORY";
    } else if (
      cls.includes("THREAT_ACTOR") ||
      (analysis?.threatActors && analysis.threatActors.length > 0) ||
      fullTextUpper.includes("THREAT ACTOR") ||
      fullTextUpper.includes("STATE-SPONSORED")
    ) {
      calculatedKind = "THREAT_ACTOR_DOSSIER";
    } else {
      calculatedKind = "CAMPAIGN_INTEL";
    }

    // Cognitive AI Agent Evaluation:
    // Dispatches unverified or low-confidence reports to the containerized AGY agent
    // for authentic 5-dimensional adversary tradecraft rubric evaluation
    const needsAiEvaluation =
      (Boolean(options?.forceAll) || (!doc.aiVerified && doc.status !== "rejected") || doc.status === "pending") &&
      aiEvaluatedCount < maxAiEvaluations &&
      text.length > 80;

    if (needsAiEvaluation) {
      aiEvaluatedCount++;
      try {
        let evalDomain = (doc.sourceDomain as string) || "";
        if (!evalDomain && url) {
          try {
            evalDomain = new URL(url).hostname.replace(/^www\./, "");
          } catch {
            // Invalid URL: evaluate without a domain.
          }
        }
        const evalRes = await runUnifiedResourceEvaluation({
          title,
          url,
          text,
          domain: evalDomain || "unknown",
          timeoutSeconds: 35,
        });

        if (evalRes.success && !evalRes.fallback) {
          const isApproved =
            evalRes.recommendApproval &&
            evalRes.passScore >= 50 &&
            evalRes.classification !== "OTHER" &&
            evalRes.classification !== "GENERIC_NEWS";

          if (isApproved) {
            calculatedKind = evalRes.resourceKind || calculatedKind;
            const updatedAnalysis: any = { ...(doc.analysis || {}) };
            if (evalRes.threatActors && evalRes.threatActors.length > 0) {
              const existingActors = new Set(updatedAnalysis.threatActors || []);
              for (const act of evalRes.threatActors) existingActors.add(act);
              updatedAnalysis.threatActors = Array.from(existingActors);
            }
            if (evalRes.mitreTechniques && evalRes.mitreTechniques.length > 0) {
              const existingTechs = new Set(updatedAnalysis.techniques || []);
              for (const t of evalRes.mitreTechniques) existingTechs.add(t);
              updatedAnalysis.techniques = Array.from(existingTechs);
            }

            await col.updateOne(
              { id: doc.id, docType: "report" },
              {
                $set: {
                  status: "acquired",
                  classification: evalRes.classification || doc.classification,
                  resourceKind: calculatedKind,
                  tags,
                  aiVerified: true,
                  aiQualityScore: evalRes.passScore,
                  aiAuditReason: `AI Agent Approval (${evalRes.passScore}/100): ${evalRes.rationale}`,
                  analysis: updatedAnalysis,
                  updatedAt: new Date().toISOString(),
                },
              }
            );
            verifiedCount++;
            continue;
          } else {
            // AI Agent strictly rejected this report
            if (shouldPrune) {
              await col.deleteOne({ id: doc.id, docType: "report" });
              prunedCount++;
              prunedTitles.push(title || url);
              continue;
            } else {
              await col.updateOne(
                { id: doc.id, docType: "report" },
                {
                  $set: {
                    status: "rejected",
                    classification: evalRes.classification || "OTHER",
                    resourceKind: evalRes.resourceKind || calculatedKind,
                    tags,
                    aiVerified: false,
                    aiQualityScore: evalRes.passScore || 0,
                    aiAuditReason: `Rejected by AI Agent (${evalRes.passScore}/100): ${evalRes.rationale}`,
                    updatedAt: new Date().toISOString(),
                  },
                }
              );
              prunedCount++;
              prunedTitles.push(title || url);
              continue;
            }
          }
        }
      } catch (err) {
        console.debug("[audit] Live AI evaluation error for doc:", doc.id, (err as Error).message);
      }
    }

    // Retain verified status if already verified by AI agent previously
    if (doc.aiVerified) {
      verifiedCount++;
      continue;
    }

    // Structural CTI Signal Qualified (Pending deep AI cognitive turn in a future batch)
    // NEVER fake aiVerified: true without cognitive model evaluation
    const scoreVal = Math.min(
      Math.max(
        Math.round(
          ((qualityScore || 0.5) * 0.45 +
            (Number(doc.simulationScore ?? 0.3) || 0.3) * 0.35 +
            (iocCount > 0 ? 0.2 : 0.05)) *
            100,
        ),
        40,
      ),
      95,
    );

    await col.updateOne(
      { id: doc.id, docType: "report" },
      {
        $set: {
          status: "acquired",
          resourceKind: calculatedKind,
          tags,
          aiVerified: false,
          aiQualityScore: scoreVal,
          aiAuditReason: "Structural CTI Signal Qualified (Pending Cognitive AI Audit Batch)",
          updatedAt: new Date().toISOString(),
        },
      }
    );
    verifiedCount++;
  }

  invalidateReportsCache();
  invalidateDashboardCache();
  invalidateCrawlerStateCache();

  logger.mongo(
    "auditLibraryWithAi",
    "threat-intel",
    Date.now() - startTime,
    `Audited ${reports.length} reports: ${verifiedCount} verified (${aiEvaluatedCount} deep AI agent evaluations), ${prunedCount} pruned`,
  );

  return {
    success: true,
    totalAudited: reports.length,
    verifiedCount,
    prunedCount,
    aiEvaluatedCount,
    prunedTitles: prunedTitles.slice(0, 10),
    message: `Audited ${reports.length} reports: verified ${verifiedCount} technical intelligence records (${aiEvaluatedCount} evaluated by Antigravity Agent)${
      prunedCount > 0 ? ` and pruned ${prunedCount} non-threat pages` : ""
    }.`,
  };
}

// ---------------------------------------------------------------------------
// Marketplace & Response Integration Repository Methods
// ---------------------------------------------------------------------------

let memoryIntegrations: IntegrationItem[] = JSON.parse(JSON.stringify(DEFAULT_INTEGRATIONS));
let cachedMarketplaceIntegrations: { timestamp: number; data: IntegrationItem[] } | null = null;
const MARKETPLACE_CACHE_TTL_MS = 15_000;

export function invalidateMarketplaceCache() {
  cachedMarketplaceIntegrations = null;
}

export async function mongoGetMarketplaceIntegrations(): Promise<IntegrationItem[]> {
  if (cachedMarketplaceIntegrations && Date.now() - cachedMarketplaceIntegrations.timestamp < MARKETPLACE_CACHE_TTL_MS) {
    return cachedMarketplaceIntegrations.data;
  }

  if (!isMongoConfigured()) {
    cachedMarketplaceIntegrations = { timestamp: Date.now(), data: memoryIntegrations };
    return memoryIntegrations;
  }

  try {
    const col = await getThreatIntelCollection();
    const docs = await col.find({ docType: "marketplace_integration" }).toArray();

    const dbMap = new Map<string, any>();
    for (const d of docs) {
      if (d.id) dbMap.set(d.id, d);
    }

    // Merge defaults with DB records
    const result: IntegrationItem[] = DEFAULT_INTEGRATIONS.map((def) => {
      const saved = dbMap.get(def.id);
      if (!saved) return def;
      return {
        ...def,
        status: saved.status ?? def.status,
        version: saved.version ?? def.version,
        config: {
          ...def.config,
          ...(decryptConfigSecrets(saved.config) as IntegrationItem["config"]),
        },
      };
    });

    memoryIntegrations = result;
    cachedMarketplaceIntegrations = { timestamp: Date.now(), data: result };
    return result;
  } catch (err) {
    logger.error("MARKETPLACE", "Failed to load marketplace integrations from DB, falling back to memory", err);
    return memoryIntegrations;
  }
}

export async function mongoSaveMarketplaceIntegration(item: IntegrationItem): Promise<IntegrationItem> {
  invalidateMarketplaceCache();

  // Update in-memory
  const idx = memoryIntegrations.findIndex((x) => x.id === item.id);
  if (idx >= 0) {
    memoryIntegrations[idx] = { ...memoryIntegrations[idx], ...item };
  } else {
    memoryIntegrations.push(item);
  }

  if (!isMongoConfigured()) {
    return item;
  }

  try {
    const col = await getThreatIntelCollection();
    await col.updateOne(
      { docType: "marketplace_integration", id: item.id },
      {
        $set: {
          docType: "marketplace_integration",
          id: item.id,
          name: item.name,
          category: item.category,
          type: item.type,
          provider: item.provider,
          version: item.version,
          status: item.status,
          config: encryptConfigSecrets(item.config),
          updatedAt: new Date().toISOString(),
        },
      },
      { upsert: true }
    );
  } catch (err) {
    logger.error("MARKETPLACE", `Failed to persist integration ${item.id} to DB`, err);
    throw new Error(`Failed to save integration ${item.id}.`);
  }

  return item;
}

export async function mongoUninstallMarketplaceIntegration(id: string): Promise<{ success: boolean; id: string }> {
  invalidateMarketplaceCache();

  // Reset to default uninstalled state
  const def = DEFAULT_INTEGRATIONS.find((x) => x.id === id);
  const resetItem: IntegrationItem = def
    ? {
        ...def,
        status: "not_installed",
        config: undefined,
      }
    : {
        id,
        name: id,
        category: "Intelligence",
        type: "cli_agent",
        provider: "Unknown",
        version: "v1.0.0",
        releaseDate: new Date().toISOString(),
        status: "not_installed",
        description: "",
        overview: "",
        actions: [],
        connectors: [],
        tags: [],
        supportedModels: [],
      };

  const idx = memoryIntegrations.findIndex((x) => x.id === id);
  if (idx >= 0) {
    memoryIntegrations[idx] = resetItem;
  }

  if (isMongoConfigured()) {
    try {
      const col = await getThreatIntelCollection();
      await col.updateOne(
        { docType: "marketplace_integration", id },
        {
          $set: {
            status: "not_installed",
            config: {},
            updatedAt: new Date().toISOString(),
          },
        }
      );
    } catch (err) {
      logger.error("MARKETPLACE", `Failed to mark integration ${id} uninstalled in DB`, err);
    }
  }

  // Check if active agent in AppSettings needs reset
  try {
    const settings = await mongoGetAppSettings();
    if (settings.activeAgentProvider === id) {
      await mongoUpdateAppSettings({
        activeAgentProvider: "agy_agent",
        agentModel: DEFAULT_AGY_MODEL,
      });
    }
  } catch (err) {
    console.warn("[marketplace] failed to reset active provider on uninstall:", err);
  }

  return { success: true, id };
}

export async function mongoGetMarketplaceState(): Promise<MarketplaceState> {
  const integrations = await mongoGetMarketplaceIntegrations();
  const settings = await mongoGetAppSettings();

  const activeProviderId = settings.activeAgentProvider || "agy_agent";
  const activeIntegration = integrations.find((x) => x.id === activeProviderId);

  return {
    activeProviderId,
    // REST/API providers keep their own model; the AGY agent path is normalised. See active-model.ts.
    activeModel: resolveActiveModel({
      providerId: activeProviderId,
      agentModel: settings.agentModel,
      selectedModel: activeIntegration?.config?.selectedModel,
    }),
    debuggerMode: Boolean(settings.debuggerMode),
    integrations,
    curatedResources: DEFAULT_CURATED_RESOURCES,
    powerups: DEFAULT_POWERUPS,
    playbooks: DEFAULT_PLAYBOOKS,
  };
}

/** Retrieval trace persisted on agent chat messages (no prompt text, no secrets). */
export interface ChatRetrievalTrace {
  query: string;
  tokens: string[];
  conversational: boolean;
  candidates: Array<{ reportId: string; score: number; matchedBy: "text" | "exact_id" | "regex" }>;
  passages: Array<{ sid: string; reportId: string; start: number; end: number; score: number }>;
  cited: string[];
  unknownCitations: string[];
  evidenceGap: boolean;
  promptSha256: string | null;
  model: string;
  at: string;
}

export interface AgentChatMessageRecord {
  id: string;
  sessionId: string;
  /** Owner (verified analyst user id). Reads, lists and clears filter on it. */
  userId: string;
  sender: "user" | "agent";
  text: string;
  model?: string;
  latencyMs?: number;
  sources?: any[];
  /** Reply contains factual sentences without an [S#] citation. */
  uncitedClaims?: boolean;
  /** Reply is the evidence-gap message (no passage met the threshold). */
  evidenceGap?: boolean;
  retrievedCount?: number;
  /** Retrieval trace for reproducing the answer (no prompt text, no secrets). */
  retrieval?: ChatRetrievalTrace;
  timestamp: string;
}

export async function mongoSaveChatMessage(message: AgentChatMessageRecord): Promise<void> {
  if (!isMongoConfigured()) return;
  try {
    const col = await getThreatIntelCollection();
    await col.insertOne({
      docType: "agent_chat_message",
      ...message,
      createdAt: new Date(),
    });
  } catch (err) {
    console.warn("[chat-repo] Failed to persist chat message:", err);
  }
}

/** Most recent `limit` messages of a user's session, oldest first. */
export async function mongoGetChatSessionMessages(
  sessionId: string,
  userId: string,
  opts: { limit?: number } = {},
): Promise<AgentChatMessageRecord[]> {
  if (!isMongoConfigured()) return [];
  try {
    const col = await getThreatIntelCollection();
    const docs = await col
      .find({ docType: "agent_chat_message", userId, sessionId })
      .project({ retrieval: 0 })
      .sort({ createdAt: -1 })
      .limit(Math.max(1, Math.min(200, opts.limit ?? 100)))
      .toArray();

    return docs.reverse().map((d: any) => ({
      id: d.id || String(d._id),
      sessionId: d.sessionId,
      userId: d.userId,
      sender: d.sender,
      text: d.text,
      model: d.model,
      latencyMs: d.latencyMs,
      sources: d.sources,
      uncitedClaims: d.uncitedClaims,
      evidenceGap: d.evidenceGap,
      retrievedCount: d.retrievedCount,
      timestamp: d.timestamp || d.createdAt?.toISOString?.() || new Date().toISOString(),
    }));
  } catch (err) {
    console.warn("[chat-repo] Failed to get session messages:", err);
    return [];
  }
}

export async function mongoClearChatSession(sessionId: string, userId: string): Promise<void> {
  if (!isMongoConfigured()) return;
  try {
    const col = await getThreatIntelCollection();
    await col.deleteMany({ docType: "agent_chat_message", userId, sessionId });
  } catch (err) {
    console.warn("[chat-repo] Failed to clear session:", err);
  }
}

export async function mongoListChatSessions(userId: string): Promise<
  Array<{ sessionId: string; lastMessage: string; messageCount: number; updatedAt: string }>
> {
  if (!isMongoConfigured()) return [];
  try {
    const col = await getThreatIntelCollection();
    const pipeline = [
      { $match: { docType: "agent_chat_message", userId } },
      { $sort: { createdAt: -1 } },
      {
        $group: {
          _id: "$sessionId",
          lastMessage: { $first: "$text" },
          messageCount: { $sum: 1 },
          updatedAt: { $first: "$createdAt" },
        },
      },
      { $sort: { updatedAt: -1 } },
      { $limit: 15 },
    ];
    const results = await col.aggregate(pipeline).toArray();
    return results.map((r: any) => ({
      sessionId: r._id,
      lastMessage: (r.lastMessage || "").slice(0, 80),
      messageCount: r.messageCount || 0,
      updatedAt: r.updatedAt ? new Date(r.updatedAt).toISOString() : new Date().toISOString(),
    }));
  } catch (err) {
    console.warn("[chat-repo] Failed to list sessions:", err);
    return [];
  }
}


// ---------------------------------------------------------------------------
// Structured intelligence (ATT&CK, emulation, attack flows, KEV)
//
// Structured-source documents are stored as ordinary `report` docs (stable
// ids: att_G0016, art_T1059.001, ctid_fin6, af_<slug>…) so the library,
// search and facets see them. Lookup indexes live beside them:
//   docType "emulation_index"  one row per (source, kind, technique) with EmulationOption[]
//   docType "kev"              one row per CISA KEV CVE
//   docType "attack_technique" ATT&CK technique reference (name, tactics, platforms, data sources)
// ---------------------------------------------------------------------------

export type StructuredUpsertResult = { upserted: number; modified: number; unchanged: number; skipped: number; pruned: number; errors: string[] };

const STRUCTURED_BATCH = 400;

let structuredIndexesEnsured = false;
async function ensureStructuredIndexes(col: Awaited<ReturnType<typeof getThreatIntelCollection>>) {
  if (structuredIndexesEnsured) return;
  structuredIndexesEnsured = true;
  try {
    await col.createIndexes([
      { key: { docType: 1, techniqueId: 1 }, name: "structured_technique_lookup", background: true },
      { key: { docType: 1, cveId: 1 }, name: "structured_kev_lookup", background: true },
      { key: { docType: 1, sourceId: 1, discoveryMethod: 1 }, name: "structured_source_docs", background: true },
      { key: { docType: 1, docTypes: 1 }, name: "report_doc_types", background: true },
    ]);
  } catch (err) {
    console.debug("[mongodb] structured index check:", (err as Error).message);
  }
}

async function bulkUpsertInBatches(
  col: Awaited<ReturnType<typeof getThreatIntelCollection>>,
  ops: any[],
): Promise<{ upserted: number; modified: number; matched: number; errors: string[] }> {
  let upserted = 0;
  let modified = 0;
  let matched = 0;
  const errors: string[] = [];
  for (let i = 0; i < ops.length; i += STRUCTURED_BATCH) {
    const chunk = ops.slice(i, i + STRUCTURED_BATCH);
    try {
      const r = await col.bulkWrite(chunk, { ordered: false });
      upserted += r.upsertedCount;
      modified += r.modifiedCount;
      matched += r.matchedCount;
    } catch (err: any) {
      // Unordered bulk writes apply every op that can be applied; duplicate
      // canonical URLs (a crawled copy of the same page) are reported, not fatal.
      const r = err?.result;
      if (r) {
        upserted += r.upsertedCount ?? 0;
        modified += r.modifiedCount ?? 0;
        matched += r.matchedCount ?? 0;
      }
      const writeErrors: any[] = err?.writeErrors ?? err?.result?.getWriteErrors?.() ?? [];
      if (Array.isArray(writeErrors) && writeErrors.length) {
        for (const we of writeErrors.slice(0, 5)) errors.push(String(we?.errmsg ?? we?.err?.errmsg ?? we?.message ?? we));
        if (writeErrors.length > 5) errors.push(`…and ${writeErrors.length - 5} more write errors`);
      } else {
        errors.push(err instanceof Error ? err.message : String(err));
      }
    }
  }
  return { upserted, modified, matched, errors };
}

/**
 * Upserts structured-source reports by stable id. `ingestedAt` is kept from the
 * first sync; content fields are replaced. With `prune`, reports previously
 * synced from this source that are no longer produced are removed.
 */
export async function mongoUpsertStructuredReports(
  sourceId: string,
  docs: ReportRecord[],
  opts?: { prune?: boolean },
): Promise<StructuredUpsertResult> {
  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();
  const now = new Date().toISOString();
  const ops = docs.map((d) => {
    const { ingestedAt, ...rest } = d;
    return {
      updateOne: {
        filter: { docType: "report", id: d.id },
        update: {
          $set: {
            ...rest,
            docType: "report",
            excerpt: excerptOf(d.extractedText || d.title || ""),
            tags: Array.isArray(d.tags) && d.tags.length ? d.tags : deriveReportTags(d as any),
            structuredSyncAt: now,
            updatedAt: now,
          },
          $setOnInsert: { ingestedAt: ingestedAt || now },
        },
        upsert: true,
      },
    };
  });
  await ensureStructuredIndexes(col);
  const r = await bulkUpsertInBatches(col, ops);
  let pruned = 0;
  if (opts?.prune && docs.length > 0) {
    const keep = docs.map((d) => d.id);
    const del = await col.deleteMany({ docType: "report", sourceId, discoveryMethod: "structured_sync", id: { $nin: keep } });
    pruned = del.deletedCount ?? 0;
  }
  invalidateReportsCache();
  invalidateDashboardCache();
  return {
    upserted: r.upserted,
    modified: r.modified,
    unchanged: Math.max(0, r.matched - r.modified),
    skipped: Math.max(0, docs.length - r.upserted - r.matched),
    pruned,
    errors: r.errors,
  };
}

export type EmulationIndexRow = {
  techniqueId: string;
  kind: EmulationOption["kind"];
  sourceId: string;
  options: EmulationOption[];
};

/** Upserts a source's emulation-index rows (same technique+kind merged); prunes stale rows unless `prune: false`. */
export async function mongoReplaceEmulationIndex(sourceId: string, rows: EmulationIndexRow[], opts?: { prune?: boolean }): Promise<number> {
  const col = await getThreatIntelCollection();
  await ensureStructuredIndexes(col);
  const merged = new Map<string, EmulationIndexRow>();
  for (const r of rows) {
    const key = `${r.kind}|${r.techniqueId}`;
    const cur = merged.get(key);
    if (!cur) merged.set(key, { ...r, options: [...r.options] });
    else {
      const seen = new Set(cur.options.map((o) => `${o.ref}|${o.name}`));
      for (const o of r.options) if (!seen.has(`${o.ref}|${o.name}`)) cur.options.push(o);
    }
  }
  const now = new Date().toISOString();
  const ids: string[] = [];
  const ops = [...merged.values()].map((r) => {
    const id = `emu_${sourceId}_${r.kind}_${r.techniqueId}`;
    ids.push(id);
    return {
      updateOne: {
        filter: { docType: "emulation_index", id },
        update: { $set: { docType: "emulation_index", id, ...r, options: r.options.slice(0, 200), updatedAt: now } },
        upsert: true,
      },
    };
  });
  await bulkUpsertInBatches(col, ops);
  // Stale rows are dropped only after a complete sync (a partial sync keeps them).
  if (opts?.prune !== false) await col.deleteMany({ docType: "emulation_index", sourceId, id: { $nin: ids } });
  return merged.size;
}

/**
 * Emulation options grouped by technique. A parent id (T1059) also returns its
 * sub-techniques' options (T1059.001…), keyed by their own ids.
 */
export async function mongoGetEmulationOptions(techniqueIds: string[]): Promise<Record<string, EmulationOption[]>> {
  const ids = Array.from(new Set(techniqueIds.map((t) => t.trim().toUpperCase()).filter((t) => /^T\d{4}(\.\d{3})?$/.test(t)))).slice(0, 200);
  if (ids.length === 0) return {};
  const col = await getThreatIntelCollection();
  const parents = ids.filter((t) => !t.includes("."));
  const or: Filter<Document>[] = [{ techniqueId: { $in: ids } }];
  if (parents.length) or.push({ techniqueId: { $regex: `^(${parents.join("|")})\\.\\d{3}$` } });
  const rows = await col
    .find({ docType: "emulation_index", $or: or })
    .project({ _id: 0, techniqueId: 1, kind: 1, options: 1 })
    .limit(2000)
    .toArray();
  const KIND_ORDER: Record<string, number> = { atomic_test: 0, caldera_ability: 1, ctid_procedure: 2, attack_flow: 3, custom: 4 };
  const out: Record<string, EmulationOption[]> = {};
  for (const r of rows as any[]) {
    const list = (out[r.techniqueId] ??= []);
    for (const o of (r.options ?? []) as EmulationOption[]) list.push(o);
  }
  for (const k of Object.keys(out)) {
    out[k].sort((a, b) => (KIND_ORDER[a.kind] ?? 9) - (KIND_ORDER[b.kind] ?? 9) || a.name.localeCompare(b.name));
    out[k] = out[k].slice(0, 120);
  }
  return out;
}

export type KevIndexRow = {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  dueDate?: string;
  ransomwareUse?: string;
  requiredAction?: string;
  shortDescription?: string;
  notes?: string;
  cwes?: string[];
};

export async function mongoReplaceKevIndex(sourceId: string, rows: KevIndexRow[]): Promise<number> {
  const col = await getThreatIntelCollection();
  await ensureStructuredIndexes(col);
  const now = new Date().toISOString();
  const ids = rows.map((r) => `kev_${r.cveId}`);
  const ops = rows.map((r, i) => ({
    updateOne: {
      filter: { docType: "kev", id: ids[i] },
      update: { $set: { docType: "kev", id: ids[i], sourceId, ...r, updatedAt: now } },
      upsert: true,
    },
  }));
  await bulkUpsertInBatches(col, ops);
  if (rows.length > 0) await col.deleteMany({ docType: "kev", sourceId, id: { $nin: ids } });
  return rows.length;
}

/** KEV rows for the given CVE ids (case-insensitive). */
export async function mongoGetKevEntries(cveIds: string[]): Promise<KevIndexRow[]> {
  const ids = Array.from(new Set(cveIds.map((c) => c.trim().toUpperCase()).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)))).slice(0, 500);
  if (ids.length === 0) return [];
  const col = await getThreatIntelCollection();
  const rows = await col
    .find({ docType: "kev", cveId: { $in: ids } })
    .project({ _id: 0, docType: 0, id: 0, sourceId: 0, updatedAt: 0 })
    .toArray();
  return rows as unknown as KevIndexRow[];
}

export type AttackTechniqueRow = {
  id: string;
  name: string;
  tactics: string[];
  platforms: string[];
  dataSources: string[];
  isSubtechnique: boolean;
  url: string;
  description?: string;
};

export async function mongoReplaceAttackTechniqueIndex(rows: AttackTechniqueRow[]): Promise<number> {
  const col = await getThreatIntelCollection();
  const now = new Date().toISOString();
  const ops = rows.map((t) => ({
    updateOne: {
      filter: { docType: "attack_technique", id: `tech_${t.id}` },
      update: { $set: { ...t, docType: "attack_technique", id: `tech_${t.id}`, techniqueId: t.id, updatedAt: now } },
      upsert: true,
    },
  }));
  await bulkUpsertInBatches(col, ops);
  if (rows.length > 0) {
    await col.deleteMany({ docType: "attack_technique", id: { $nin: rows.map((t) => `tech_${t.id}`) } });
  }
  return rows.length;
}

/** Stored ATT&CK technique reference rows (all, or the given ids). */
export async function mongoGetAttackTechniques(ids?: string[]): Promise<AttackTechniqueRow[]> {
  const col = await getThreatIntelCollection();
  const filter: Filter<Document> = { docType: "attack_technique" };
  if (ids?.length) filter.techniqueId = { $in: ids.map((i) => i.toUpperCase()) };
  const rows = await col
    .find(filter)
    .project({ _id: 0, docType: 0, updatedAt: 0 })
    .toArray();
  return (rows as any[]).map(({ techniqueId, ...r }) => ({ ...r, id: techniqueId })) as AttackTechniqueRow[];
}

/** Records the outcome of a structured sync on the source document. */
export async function mongoRecordSourceSync(
  id: string,
  outcome: { ok: boolean; count?: number; error?: string | null; stats?: Record<string, number>; warnings?: string[] },
): Promise<void> {
  const col = await getThreatIntelCollection();
  const now = new Date().toISOString();
  const $set: Record<string, unknown> = { lastSyncAttemptAt: now, updatedAt: now, lastSyncError: outcome.error ?? null };
  if (outcome.ok) {
    $set.lastSyncAt = now;
    $set.lastSyncCount = outcome.count ?? 0;
    $set.lastSyncStats = outcome.stats ?? {};
    $set.lastSyncWarnings = (outcome.warnings ?? []).slice(0, 20);
    $set.lastIngestAt = now;
  }
  await col.updateOne({ docType: "source", id }, { $set });
  cachedSourcesList = null;
  invalidateCrawlerStateCache();
}

export type IntelCoverageCounts = {
  byDocType: Record<string, number>;
  byTier: Record<string, number>;
  total: number;
  structured: number;
  atomicTechniques: number;
  emulationTechniques: number;
  emulationByKind: Record<string, number>;
  kevEntries: number;
  attackTechniques: number;
};

/** Counts by DocType and source tier plus index sizes (dashboards / library facets). */
export async function mongoGetIntelCoverage(): Promise<IntelCoverageCounts> {
  const col = await getThreatIntelCollection();
  const [byType, byTier, total, structured, emuKinds, emuTechs, atomicTechs, kev, techniques] = await Promise.all([
    col
      .aggregate<{ _id: string; n: number }>([
        { $match: { docType: "report", status: { $nin: ["rejected", "duplicate"] }, "docTypes.0": { $exists: true } } },
        { $unwind: "$docTypes" },
        { $group: { _id: "$docTypes", n: { $sum: 1 } } },
      ])
      .toArray(),
    col
      .aggregate<{ _id: number | null; n: number }>([
        { $match: { docType: "report", status: { $nin: ["rejected", "duplicate"] } } },
        { $group: { _id: "$sourceTier", n: { $sum: 1 } } },
      ])
      .toArray(),
    col.countDocuments({ docType: "report", status: { $nin: ["rejected", "duplicate"] } }),
    col.countDocuments({ docType: "report", discoveryMethod: "structured_sync" }),
    col
      .aggregate<{ _id: string; n: number }>([{ $match: { docType: "emulation_index" } }, { $group: { _id: "$kind", n: { $sum: 1 } } }])
      .toArray(),
    col.distinct("techniqueId", { docType: "emulation_index" }),
    col.distinct("techniqueId", { docType: "emulation_index", kind: "atomic_test" }),
    col.countDocuments({ docType: "kev" }),
    col.countDocuments({ docType: "attack_technique" }),
  ]);
  const byDocType: Record<string, number> = {};
  for (const r of byType) if (r._id) byDocType[r._id] = r.n;
  const byTierOut: Record<string, number> = {};
  for (const r of byTier) byTierOut[String(r._id ?? "unknown")] = r.n;
  if (kev > 0) byDocType.KEV_ENTRY = (byDocType.KEV_ENTRY ?? 0) + kev;
  const emulationByKind: Record<string, number> = {};
  for (const r of emuKinds) emulationByKind[r._id] = r.n;
  return {
    byDocType,
    byTier: byTierOut,
    total,
    structured,
    atomicTechniques: atomicTechs.length,
    emulationTechniques: emuTechs.length,
    emulationByKind,
    kevEntries: kev,
    attackTechniques: techniques,
  };
}

// ---------------------------------------------------------------------------
// Intelligence search candidates (phase 9 hybrid ranker; re-ranked in src/lib/aie/search)
// ---------------------------------------------------------------------------

/** Fields the hybrid ranker and the library hit list need (no raw HTML / PDF bytes). */
const INTEL_CANDIDATE_PROJECTION = {
  _id: 0,
  rawHtml: 0,
  pdfBase64: 0,
  originalContent: 0,
  scoreBreakdown: 0,
} as const;

/**
 * Candidate reports for intelligence search: weighted `$text` over the
 * alias-expanded query, entity-field regexes for every alias, and exact CVE /
 * ATT&CK id matches, merged (exact ids first). With no text to search
 * (filter-only queries) the newest reports are returned. Bounded; the caller
 * re-ranks.
 */
export async function mongoSearchIntelCandidates(opts: {
  text: string;
  aliases: string[];
  cves: string[];
  techniques: string[];
  filterOnly: boolean;
  limit?: number;
}): Promise<Document[]> {
  if (!isMongoConfigured()) return [];
  const limit = Math.max(10, Math.min(400, opts.limit ?? 150));
  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();
  const base: Filter<Document> = { docType: "report", status: { $nin: ["rejected", "duplicate"] } };
  const startTime = Date.now();
  if (opts.filterOnly) {
    const docs = await col.find(base).project(INTEL_CANDIDATE_PROJECTION).sort({ publishedAt: -1, ingestedAt: -1 }).limit(limit * 2).toArray();
    logger.mongo("searchIntelCandidates", "threat-intel", Date.now() - startTime, `${docs.length} (filter-only)`);
    return docs;
  }
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const lists: Document[][] = [];
  const idOr: Filter<Document>[] = [];
  const cves = opts.cves.map((c) => c.toUpperCase()).slice(0, 20);
  const techs = opts.techniques.map((t) => t.toUpperCase()).slice(0, 60);
  if (cves.length) {
    idOr.push({ "extractedEntities.cves": { $in: cves } }, { "analysis.vulnerabilities": { $in: cves } }, { "iocs.value": { $in: cves.map((c) => c.toLowerCase()) } }, { "structured.cveId": { $in: cves } });
  }
  if (techs.length) {
    idOr.push(
      { "extractedEntities.techniques.id": { $in: techs } },
      { "analysis.ttps": { $in: techs } },
      { "structured.techniques": { $in: techs } },
      { "structured.techniqueId": { $in: techs } },
    );
  }
  if (idOr.length) lists.push(await col.find({ ...base, $or: idOr }).project(INTEL_CANDIDATE_PROJECTION).limit(limit).toArray().catch(() => []));
  const aliases = Array.from(new Set(opts.aliases.map((a) => a.trim()).filter((a) => a.length >= 3))).slice(0, 40);
  if (aliases.length) {
    const re = new RegExp(`(^|[^\\w])(${aliases.map(esc).join("|")})([^\\w]|$)`, "i");
    lists.push(
      await col
        .find({
          ...base,
          $or: [
            { title: { $regex: re } },
            { "analysis.threatActors": { $regex: re } },
            { "analysis.malware": { $regex: re } },
            { "extractedEntities.threatActors": { $regex: re } },
            { "extractedEntities.malwareFamilies": { $regex: re } },
            { "extractedEntities.campaign": { $regex: re } },
            { "structured.aliases": { $regex: re } },
          ],
        })
        .project(INTEL_CANDIDATE_PROJECTION)
        .limit(limit)
        .toArray()
        .catch(() => []),
    );
  }
  const q = opts.text.trim();
  if (q) {
    try {
      lists.push(
        await col
          .find({ ...base, $text: { $search: toMongoTextSearch(q) } })
          .project({ ...INTEL_CANDIDATE_PROJECTION, _textScore: { $meta: "textScore" } })
          .sort({ _textScore: { $meta: "textScore" } })
          .limit(limit)
          .toArray(),
      );
    } catch (err) {
      logger.warn("MONGO", `$text intel search failed, using regex fallback: ${(err as Error).message}`);
      const tokens = queryTerms(q).filter((t) => t.length >= 3).slice(0, 8);
      if (tokens.length) {
        const re = new RegExp(tokens.map(esc).join("|"), "i");
        lists.push(
          await col
            .find({ ...base, $or: [{ title: { $regex: re } }, { extractedText: { $regex: re } }] })
            .project(INTEL_CANDIDATE_PROJECTION)
            .limit(limit)
            .toArray()
            .catch(() => []),
        );
      }
    }
  }
  const merged = dedupeDocs(lists.flat());
  logger.mongo("searchIntelCandidates", "threat-intel", Date.now() - startTime, `${merged.length} candidates from ${lists.length} strategies`);
  return merged.slice(0, limit * 2);
}
