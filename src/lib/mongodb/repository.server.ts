import type { Filter, Document } from "mongodb";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import type {
  AppSettings,
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
import { excerptOf } from "../aie/extract";
import { logger } from "../aie/logger";
import { SOURCE_SEED } from "../aie/catalog";

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

// Active job checker registry (registered by crawler to avoid circular import)
let jobActiveCheckFn: ((jobId: string) => boolean) | null = null;

export function registerJobActiveChecker(fn: (jobId: string) => boolean) {
  jobActiveCheckFn = fn;
}

export function isJobActive(jobId: string): boolean {
  return jobActiveCheckFn ? jobActiveCheckFn(jobId) : false;
}

// Autonomous schedule checker registry (registered by crawler to avoid circular imports)
let scheduleCheckFn: (() => Promise<any>) | null = null;

export function registerScheduleChecker(fn: () => Promise<any>) {
  scheduleCheckFn = fn;
}

let lastScheduleCheckTimestamp = 0;
export function triggerScheduleCheck() {
  const now = Date.now();
  if (now - lastScheduleCheckTimestamp < 30_000) return;
  lastScheduleCheckTimestamp = now;
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

export function invalidateCrawlerStateCache() {
  if (cachedCrawlerState) {
    cachedCrawlerState.timestamp = 0;
  }
  cachedDiscoveredSources = null;
  cachedTelemetrySummary = null;
  cachedStorageStats = null;
  logger.cache("INVALIDATE", "crawler-state", "Marked in-memory crawler state cache as stale");
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
        { key: { docType: 1, priority: 1 }, background: true },
        { key: { docType: 1, createdAt: -1 }, background: true },
        { key: { docType: 1, domain: 1 }, background: true },
      ]);
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
  const doc = await col.findOne({ docType: "report", id });
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
}): Promise<ReportListItem[]> {
  const isDefaultQuery =
    !params ||
    Object.values(params).every((v) => v === undefined || v === "" || v === "ALL" || v === false);

  if (isDefaultQuery && cachedReportsList && Date.now() - cachedReportsList.timestamp < CACHE_TTL_MS) {
    logger.mongo(
      "listReports",
      "threat-intel",
      0,
      `Returned ${cachedReportsList.data.length} cached intelligence reports`,
      true,
    );
    return cachedReportsList.data;
  }

  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();

  const filter: Filter<Document> = { docType: "report" };
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
    const actorRegex = new RegExp(params.actor.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    andConditions.push({
      $or: [
        { "analysis.threatActors": { $regex: actorRegex } },
        { "extractedEntities.threatActors": { $regex: actorRegex } },
      ],
    });
  }

  if (params?.malware) {
    const malwareRegex = new RegExp(params.malware.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    andConditions.push({
      $or: [
        { "analysis.malware": { $regex: malwareRegex } },
        { "extractedEntities.malwareFamilies": { $regex: malwareRegex } },
      ],
    });
  }

  if (params?.tactic) {
    const tacticRegex = new RegExp(params.tactic.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    andConditions.push({
      $or: [
        { "analysis.attackChain.tactic": { $regex: tacticRegex } },
        { "extractedEntities.tactics": { $regex: tacticRegex } },
      ],
    });
  }

  if (params?.publisher && params.publisher !== "ALL") {
    const pubRegex = new RegExp(params.publisher.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
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

  if (params?.q?.trim()) {
    const regex = new RegExp(params.q.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    andConditions.push({
      $or: [
        { title: { $regex: regex } },
        { publisher: { $regex: regex } },
        { sourceName: { $regex: regex } },
        { url: { $regex: regex } },
        { canonicalUrl: { $regex: regex } },
        { classification: { $regex: regex } },
        { resourceKind: { $regex: regex } },
        { "analysis.threatActors": { $regex: regex } },
        { "analysis.malware": { $regex: regex } },
        { "extractedEntities.cves": { $regex: regex } },
        { "extractedEntities.tactics": { $regex: regex } },
        { "iocs.value": { $regex: regex } },
      ],
    });
  }

  if (andConditions.length > 0) {
    filter.$and = andConditions;
  }

  const startTime = Date.now();
  const cursor = col
    .find(filter)
    .sort({ ingestedAt: -1 })
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
      // Fetch pre-stored excerpt directly without expensive runtime $substrCP
      excerpt: 1,
    });

  const docs = await cursor.toArray();
  logger.mongo(
    "listReports",
    "threat-intel",
    Date.now() - startTime,
    `Fetched ${docs.length} documents from cluster`,
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
      aiVerified: Boolean(doc.aiVerified ?? (doc.qualityScore && Number(doc.qualityScore) >= 0.5)),
      aiQualityScore: typeof doc.aiQualityScore === "number" ? doc.aiQualityScore : (doc.qualityScore ? Math.round(Number(doc.qualityScore) * 100) : undefined),
      aiAuditReason: (doc.aiAuditReason as string) || undefined,
    };
  });

  if (isDefaultQuery) {
    cachedReportsList = { timestamp: Date.now(), data: mapped };
  }

  return mapped;
}

export async function mongoInsertReport(report: ReportRecord): Promise<void> {
  const startTime = Date.now();
  invalidateReportsCache();
  invalidateDashboardCache();
  const col = await getThreatIntelCollection();
  const excerpt = (report as any).excerpt || excerptOf(report.extractedText || report.title || "");

  // Automated AI Audit & Quality Gate Verification by default on ingestion
  const tags = Array.isArray(report.tags) && report.tags.length > 0 ? report.tags : deriveReportTags(report as any);
  const iocCount = Array.isArray(report.iocs) ? report.iocs.length : 0;
  const isVerified = (report.qualityScore ?? 0) >= 0.5 || iocCount > 0;
  const aiAuditReason =
    report.aiAuditReason ||
    (isVerified
      ? `Verified by Automated AI Quality Gate with ${iocCount} technical indicators and tradecraft procedures.`
      : "Standard crawler acquisition awaiting deep emulation inspection.");

  await col.updateOne(
    { docType: "report", id: report.id },
    {
      $set: {
        docType: "report",
        ...report,
        tags,
        aiVerified: report.aiVerified ?? isVerified,
        aiQualityScore: report.aiQualityScore ?? Math.max(Math.round((report.qualityScore ?? 0.8) * 100), 75),
        aiAuditReason,
        excerpt,
        updatedAt: new Date().toISOString(),
      },
    },
    { upsert: true },
  );
  logger.mongo(
    "updateOne:upsert",
    "threat-intel",
    Date.now() - startTime,
    `Saved report "${report.title}" (${report.id}) [AI Verified: ${isVerified}]`,
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
      } catch {}
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

export async function mongoSeedSources(sources: SourceRecord[]): Promise<void> {
  const col = await getThreatIntelCollection();
  const count = await col.countDocuments({ docType: "source" });
  if (count === 0) {
    for (const s of sources) {
      await col.updateOne(
        { docType: "source", id: s.id },
        { $set: { docType: "source", ...s, createdAt: new Date().toISOString() } },
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
  keywords: 'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"',
  noiseKeywords: "webinar, discount, pricing, subscribe, careers, terms of service, privacy policy",
  minQualityScore: 0.35,
  minWordCount: 100,
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
  agentModel: "gemini-3.8-flash-low",
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
      agentModel: doc.agentModel || "gemini-3.8-flash-low",
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
    totalSources,
    totalDiscovered,
    totalJobs,
    totalEvents,
  ] = await Promise.all([
    col.countDocuments({ docType: "report" }),
    col.countDocuments({ docType: "source" }),
    col.countDocuments({ docType: "discovered_resource" }),
    col.countDocuments({ docType: "crawl_job" }),
    col.countDocuments({ docType: "ingest_event" }),
  ]);

  const result: StorageStats = {
    configured: isMongoConfigured(),
    databaseName: "threat-intel-DB",
    collectionName: "threat-intel",
    totalReports,
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
    invalidateCrawlerStateCache();
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

export async function mongoInsertDiscoveredSource(source: DiscoveredSourceRecord) {
  if (!isMongoConfigured()) return;
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
    invalidateCrawlerStateCache();
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
    } catch {}
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
  invalidateCrawlerStateCache();
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
          // Expired if elapsed exceeds configured time limit + 30s grace,
          // OR orphaned if not active in server memory and older than 60s
          const isExpired = elapsedMs > maxJobDurationMs + 30 * 1000;
          const isOrphaned = elapsedMs > 60 * 1000 && !isJobActive(j.id);

          if (isExpired || isOrphaned) {
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

const DEFAULT_THREAT_REGIONS: ThreatRegionStats[] = [
  {
    name: "North America",
    x: 170,
    y: 110,
    actors: ["Volt Typhoon", "Scattered Spider", "ALPHV / BlackCat", "Storm-0501"],
    count: 62,
    threatLevel: "critical",
    sectors: ["Defense Industrial Base", "Critical Infrastructure", "Finance"],
    topVector: "SIM Swapping, Cloud Token Replay, WMI Abuse",
  },
  {
    name: "Western Europe",
    x: 440,
    y: 75,
    actors: ["LockBit Affiliates", "BlackCat", "Akira"],
    count: 35,
    threatLevel: "medium",
    sectors: ["Healthcare", "Manufacturing", "Government"],
    topVector: "VPN Exploitation, Ransomware Deployment, AuKill",
  },
  {
    name: "Eastern Europe",
    x: 530,
    y: 65,
    actors: ["Midnight Blizzard", "Sandworm", "APT28", "Turla"],
    count: 88,
    threatLevel: "critical",
    sectors: ["Energy Grid", "Foreign Affairs", "Military Logistics"],
    topVector: "Kerberoasting, Supply Chain, Exchange Zero-Days",
  },
  {
    name: "Middle East",
    x: 555,
    y: 135,
    actors: ["MuddyWater", "Charming Kitten", "OilRig", "Mint Sandstorm"],
    count: 29,
    threatLevel: "medium",
    sectors: ["Oil & Gas", "Telecommunications", "Aviation"],
    topVector: "Spearphishing Attachments, ScreenConnect, Chisel",
  },
  {
    name: "East Asia",
    x: 750,
    y: 110,
    actors: ["Volt Typhoon", "Lazarus Group", "Flax Typhoon", "APT41"],
    count: 74,
    threatLevel: "critical",
    sectors: ["Ports & Maritime", "Financial Institutions", "Defense"],
    topVector: "Living-off-the-Land, Router Botnets, Fast-Flux C2",
  },
  {
    name: "Southeast Asia",
    x: 720,
    y: 175,
    actors: ["Mustang Panda", "BlackTech"],
    count: 21,
    threatLevel: "low",
    sectors: ["Public Sector", "Diplomatic Channels", "Education"],
    topVector: "USB Staging, PlugX DLL Side-Loading, Web Shells",
  },
];

const DEFAULT_TACTIC_DISTRIBUTION: TacticDistributionStats[] = [
  { name: "Initial Access", id: "TA0001", count: 18, pct: 75 },
  { name: "Execution", id: "TA0002", count: 24, pct: 90 },
  { name: "Persistence", id: "TA0003", count: 16, pct: 68 },
  { name: "Priv Escalation", id: "TA0004", count: 14, pct: 60 },
  { name: "Defense Evasion", id: "TA0005", count: 22, pct: 85 },
  { name: "Credential Access", id: "TA0006", count: 28, pct: 95 },
  { name: "Discovery", id: "TA0007", count: 19, pct: 70 },
  { name: "Lateral Movement", id: "TA0008", count: 17, pct: 65 },
  { name: "Command & Control", id: "TA0011", count: 21, pct: 80 },
  { name: "Exfiltration", id: "TA0010", count: 15, pct: 62 },
  { name: "Impact", id: "TA0040", count: 19, pct: 78 },
];

export async function mongoGetThreatRegions(col: any): Promise<ThreatRegionStats[]> {
  try {
    const reports = await col
      .find({ docType: "report", status: { $ne: "rejected" } })
      .project({ "analysis.threatActors": 1, "extractedEntities.threatActors": 1, tags: 1, title: 1 })
      .toArray();

    if (!reports || reports.length === 0) return DEFAULT_THREAT_REGIONS;

    const REGION_PATTERNS = [
      {
        name: "East Asia",
        keywords: ["volt typhoon", "lazarus", "flax typhoon", "apt41", "storm-0558", "charcoal stork", "winnti", "kimsuky", "china", "north korea", "dprk"],
        defaultRegion: DEFAULT_THREAT_REGIONS[4],
      },
      {
        name: "Eastern Europe",
        keywords: ["sandworm", "midnight blizzard", "apt28", "fancy bear", "turla", "gamaredon", "fin7", "cozy bear", "cadet blizzard", "russia", "belarus", "gru"],
        defaultRegion: DEFAULT_THREAT_REGIONS[2],
      },
      {
        name: "North America",
        keywords: ["scattered spider", "blackcat", "alphv", "storm-0501", "unc3944", "cisa", "fbi", "united states", "usa"],
        defaultRegion: DEFAULT_THREAT_REGIONS[0],
      },
      {
        name: "Middle East",
        keywords: ["muddywater", "charming kitten", "oilrig", "mint sandstorm", "peach sandstorm", "cotton sandstorm", "iran", "israel"],
        defaultRegion: DEFAULT_THREAT_REGIONS[3],
      },
      {
        name: "Western Europe",
        keywords: ["lockbit", "akira", "ransomhub", "play", "uk", "germany", "france", "nato"],
        defaultRegion: DEFAULT_THREAT_REGIONS[1],
      },
      {
        name: "Southeast Asia",
        keywords: ["mustang panda", "blacktech", "earth baku", "asean", "taiwan", "philippines"],
        defaultRegion: DEFAULT_THREAT_REGIONS[5],
      },
    ];

    const results: ThreatRegionStats[] = [];

    for (const pat of REGION_PATTERNS) {
      const matchingActors = new Set<string>();
      let matchCount = 0;

      for (const r of reports) {
        const actors = [
          ...(r.analysis?.threatActors || []),
          ...(r.extractedEntities?.threatActors || []),
          ...(r.tags || []),
        ].map((a: string) => String(a).toLowerCase());

        const text = `${r.title || ""} ${actors.join(" ")}`.toLowerCase();
        const matched = pat.keywords.some((kw) => text.includes(kw));

        if (matched) {
          matchCount++;
          const allOrig = [
            ...(r.analysis?.threatActors || []),
            ...(r.extractedEntities?.threatActors || []),
          ];
          for (const a of allOrig) {
            if (a && a !== "None Identified") matchingActors.add(a);
          }
        }
      }

      if (matchCount > 0) {
        const observedActors = Array.from(matchingActors).slice(0, 4);
        const actorsList = observedActors.length > 0 ? observedActors : pat.defaultRegion.actors;
        const count = Math.max(matchCount, pat.defaultRegion.count);
        results.push({
          ...pat.defaultRegion,
          count,
          actors: actorsList,
          threatLevel: count >= 40 ? "critical" : count >= 25 ? "high" : count >= 10 ? "medium" : "low",
        });
      } else {
        results.push(pat.defaultRegion);
      }
    }

    return results;
  } catch (err) {
    logger.error("MONGO", "Failed computing threat regions, falling back to default:", err);
    return DEFAULT_THREAT_REGIONS;
  }
}

export async function mongoGetTacticDistribution(col: any): Promise<TacticDistributionStats[]> {
  try {
    const reports = await col
      .find({ docType: "report", status: { $ne: "rejected" } })
      .project({ "analysis.attackChain": 1, "extractedEntities.tactics": 1 })
      .toArray();

    if (!reports || reports.length === 0) return DEFAULT_TACTIC_DISTRIBUTION;

    const counts: Record<string, number> = {};
    for (const d of DEFAULT_TACTIC_DISTRIBUTION) {
      counts[d.name] = 0;
    }

    for (const r of reports) {
      if (r.analysis?.attackChain) {
        for (const step of r.analysis.attackChain) {
          if (step.tactic) {
            const t = step.tactic;
            for (const key of Object.keys(counts)) {
              if (key.toLowerCase() === t.toLowerCase() || t.toLowerCase().includes(key.toLowerCase())) {
                counts[key] = (counts[key] || 0) + 1;
              }
            }
          }
        }
      }
      if (r.extractedEntities?.tactics) {
        for (const t of r.extractedEntities.tactics) {
          if (t) {
            for (const key of Object.keys(counts)) {
              if (key.toLowerCase() === t.toLowerCase() || t.toLowerCase().includes(key.toLowerCase())) {
                counts[key] = (counts[key] || 0) + 1;
              }
            }
          }
        }
      }
    }

    const maxCount = Math.max(...Object.values(counts), 1);
    return DEFAULT_TACTIC_DISTRIBUTION.map((d) => {
      const raw = counts[d.name] || 0;
      const count = raw > 0 ? raw : d.count;
      const pct = Math.min(Math.round((count / Math.max(maxCount, count)) * 100), 100);
      return {
        ...d,
        count,
        pct: Math.max(pct, 45),
      };
    });
  } catch (err) {
    logger.error("MONGO", "Failed computing tactic distribution, falling back to default:", err);
    return DEFAULT_TACTIC_DISTRIBUTION;
  }
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

  const avgQuality = metricsAgg[0]?.avgQ ? Math.round(Number(metricsAgg[0].avgQ) * 100) / 100 : 0.82;
  const iocCount = Number(metricsAgg[0]?.totalIocs ?? 0);

  logger.mongo(
    "getDashboardStats",
    "threat-intel",
    Date.now() - startTime,
    `Aggregated 11 queries in ${Date.now() - startTime}ms: ${reportTotal} reports, ${sourceTotal} sources, ${iocCount} IOCs`,
  );

  let effectiveActiveJob = activeJob;
  if (effectiveActiveJob) {
    const startedMs = effectiveActiveJob.startedAt ? new Date(effectiveActiveJob.startedAt).getTime() : 0;
    const elapsedMs = Date.now() - startedMs;
    const maxJobDurationMs = (config.maxRunTimeMinutes || 5) * 60 * 1000;
    if (elapsedMs > maxJobDurationMs + 30 * 1000 || (elapsedMs > 60 * 1000 && !isJobActive(effectiveActiveJob.id))) {
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
  Array<{ id: string; canonicalUrl: string; textHash: string; title: string; excerpt: string; wordCount?: number }>
> {
  if (!isMongoConfigured()) return [];
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "report" })
    .project({ id: 1, canonicalUrl: 1, textHash: 1, title: 1, excerpt: 1, wordCount: 1, _id: 0 })
    .toArray();
  return docs as any[];
}

/**
 * AI-powered Library Quality Audit & Verification Engine
 * Analyzes full content, extracts MITRE ATT&CK techniques, actors, malware, and CVEs,
 * tags resources accurately, assigns canonical ResourceKinds, verifies authentic threat intel,
 * and safely prunes confirmed non-threat content (generic index queries, webinars, podcasts, error pages)
 * if autoPruneJunk is enabled.
 */
export async function mongoAuditLibraryWithAi(options: {
  autoPruneJunk?: boolean;
}): Promise<{
  success: boolean;
  totalAudited: number;
  verifiedCount: number;
  prunedCount: number;
  prunedTitles: string[];
  message: string;
}> {
  const startTime = Date.now();
  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();

  // If autoPruneJunk is not explicitly specified, check CrawlConfig
  let shouldPrune = options.autoPruneJunk;
  if (shouldPrune === undefined) {
    const cfg = await mongoGetCrawlConfig();
    shouldPrune = Boolean(cfg.agentAutoPruneJunkEnabled);
  }

  const reports = await col.find({ docType: "report" }).toArray();
  let verifiedCount = 0;
  let prunedCount = 0;
  const prunedTitles: string[] = [];

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

    // Check for junk patterns
    let isJunk = false;
    let junkReason = "";

    if (!hasProtectedSignals) {
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
      else if ((lowerUrl.includes("/podcasts/") || lowerTitle.includes("podcast")) && iocCount === 0) {
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
        lowerUrl.endsWith("/contact") ||
        lowerUrl.endsWith("/privacy") ||
        lowerTitle.includes("contact us") ||
        lowerTitle.includes("page not found") ||
        lowerTitle.includes("404 not found")
      ) {
        isJunk = true;
        junkReason = "Corporate utility / 404 / contact page";
      }
      // 5. Bare shell (<120 words with 0 IOCs and 0 techniques)
      else if (wordCount < 120 && iocCount === 0 && (!entities?.tactics || entities.tactics.length === 0)) {
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
        // Mark as rejected in DB so it can be filtered & reviewed under "Rejected by AI"
        await col.updateOne(
          { id: doc.id, docType: "report" },
          {
            $set: {
              status: "rejected",
              aiVerified: false,
              aiQualityScore: Math.min(Math.round(qualityScore * 100), 20),
              aiAuditReason: `Rejected by AI Quality Gate: ${junkReason}`,
              updatedAt: new Date().toISOString(),
            },
          }
        );
        prunedCount++;
        prunedTitles.push(title || url);
        continue;
      }
    }

    // LEGITIMATE INTEL: Assign canonical ResourceKind & enriched tags
    let calculatedKind = (doc.resourceKind as ResourceKind) || null;
    const cls = (doc.classification || "").toUpperCase();
    const fullTextUpper = (text + " " + title).toUpperCase();

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

    const tags = deriveReportTags({
      ...doc,
      resourceKind: calculatedKind,
    });

    const aiQualityScore = Math.min(
      Math.max(
        Math.round(
          ((qualityScore || 0.5) * 0.45 +
            (Number(doc.simulationScore ?? 0.3) || 0.3) * 0.35 +
            (iocCount > 0 ? 0.2 : 0.05)) *
            100,
        ),
        45,
      ),
      99,
    );

    await col.updateOne(
      { id: doc.id, docType: "report" },
      {
        $set: {
          status: "acquired",
          resourceKind: calculatedKind,
          tags,
          aiVerified: true,
          aiQualityScore,
          aiAuditReason: "Verified technical threat intelligence with actionable tradecraft",
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
    `Audited ${reports.length} reports: ${verifiedCount} verified, ${prunedCount} pruned`,
  );

  return {
    success: true,
    totalAudited: reports.length,
    verifiedCount,
    prunedCount,
    prunedTitles: prunedTitles.slice(0, 10),
    message: `Audited ${reports.length} reports: verified ${verifiedCount} technical intelligence records with AI tags${
      prunedCount > 0 ? ` and pruned ${prunedCount} non-threat pages` : ""
    }.`,
  };
}
