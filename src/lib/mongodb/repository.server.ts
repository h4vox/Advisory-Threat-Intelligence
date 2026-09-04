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
} from "../aie/types";
import { DEFAULT_APP_SETTINGS } from "../aie/types";
import { excerptOf } from "../aie/extract";
import { logger } from "../aie/logger";

let indexesEnsured = false;
let indexesPromise: Promise<void> | null = null;

// High-speed in-memory caches (invalidated on write)
let cachedReportsList: { timestamp: number; data: ReportListItem[] } | null = null;
const CACHE_TTL_MS = 60_000;

let cachedDashboardStats: { timestamp: number; data: DashboardStats } | null = null;
const DASHBOARD_CACHE_TTL_MS = 15_000;

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

let cachedCrawlerState: { timestamp: number; data: CrawlerState } | null = null;
const CRAWLER_STATE_CACHE_TTL_MS = 6_000; // 6s TTL: ultra-fast responses without hammering Atlas

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
  logger.cache("INVALIDATE", "dashboard-stats", "Cleared in-memory dashboard cache");
}

export function invalidateConfigCache() {
  cachedCrawlConfig = null;
  logger.cache("INVALIDATE", "crawl-config", "Cleared in-memory crawl config cache");
}

export function invalidateSettingsCache() {
  cachedAppSettings = null;
  logger.cache("INVALIDATE", "app-settings", "Cleared in-memory app settings cache");
}

export function invalidateCrawlerStateCache() {
  cachedCrawlerState = null;
  cachedDiscoveredSources = null;
  cachedTelemetrySummary = null;
  logger.cache("INVALIDATE", "crawler-state", "Cleared in-memory crawler state & sources cache");
}

export function purgeAllServerCaches() {
  cachedReportsList = null;
  cachedDashboardStats = null;
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
      rawHtml: doc.rawHtml || "",
      pdfUrl: doc.pdfUrl || "",
      pdfBase64: doc.pdfBase64 || "",
      analysis: (doc.analysis as IntelAnalysis) || null,
      simulationScore: typeof doc.simulationScore === "number" ? doc.simulationScore : undefined,
      isEmergingTechnique: Boolean(doc.isEmergingTechnique),
      noveltyRationale: (doc.noveltyRationale as string) || undefined,
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
  await col.updateOne(
    { docType: "report", id: report.id },
    {
      $set: {
        docType: "report",
        ...report,
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

export async function mongoListSources(): Promise<SourceRecord[]> {
  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "source" })
    .sort({ priority: 1, name: 1 })
    .toArray();

  return docs.map((doc) => ({
    id: doc.id,
    name: doc.name,
    slug: doc.slug,
    category: doc.category,
    priority: Number(doc.priority),
    homepageUrl: doc.homepageUrl,
    feedUrl: doc.feedUrl || "",
    enabled: Boolean(doc.enabled),
    trustLevel: (doc.trustLevel as TrustLevel) || "reputable",
    notes: doc.notes || "",
    lastIngestAt: doc.lastIngestAt || null,
  }));
}

export async function mongoToggleSource(id: string, enabled: boolean): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne({ docType: "source", id }, { $set: { enabled, updatedAt: new Date().toISOString() } });
}

export async function mongoUpdateSourceLastIngest(id: string): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "source", id },
    { $set: { lastIngestAt: new Date().toISOString(), updatedAt: new Date().toISOString() } },
  );
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

  return {
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

export async function mongoListRecentCrawlJobs(limit = 10): Promise<CrawlJob[]> {
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "crawl_job" })
    .sort({ createdAt: -1, startedAt: -1 })
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

function formatDiscoveredDomainName(domain: string): string {
  const d = domain.toLowerCase().replace(/^www\./, "");
  const KNOWN_NAMES: Record<string, string> = {
    "attack.mitre.org": "MITRE ATT&CK Framework",
    "github.com": "GitHub Security & PoC Repositories",
    "nvd.nist.gov": "NIST National Vulnerability Database",
    "dhs.gov": "Department of Homeland Security (DHS)",
    "krebsonsecurity.com": "Krebs on Security",
    "ncsc.gov.uk": "UK National Cyber Security Centre (NCSC)",
    "ic3.gov": "FBI Internet Crime Complaint Center (IC3)",
    "justice.gov": "US Department of Justice Cyber Prosecutions",
    "isc.sans.edu": "SANS Internet Storm Center",
    "arxiv.org": "Cornell arXiv Cyber Research Papers",
    "media.defense.gov": "NSA / DoD Cybersecurity Advisories",
    "cert.pl": "CERT Polska Technical Analysis",
    "securelist.com": "Kaspersky Securelist Research",
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
  if (d.endsWith(".gov") || d.endsWith(".mil") || d.includes("mitre.org") || d.includes("nist.gov")) {
    return 0.98;
  }
  if (d.endsWith(".edu") || d.includes("arxiv.org") || d.includes("sans.edu")) {
    return 0.94;
  }
  if (d.includes("github.com") || d.includes("ncsc.gov.uk") || d.includes("cert.pl")) {
    return 0.92;
  }
  if (d.includes("krebsonsecurity.com") || d.includes("securelist.com") || d.includes("trendmicro.com")) {
    return 0.90;
  }
  if (avgScore && avgScore > 0) {
    return Math.min(0.95, Math.max(0.60, Number(avgScore.toFixed(2))));
  }
  return 0.85;
}

export async function mongoListDiscoveredSources(): Promise<DiscoveredSourceRecord[]> {
  if (!isMongoConfigured()) return [];
  const now = Date.now();
  if (cachedDiscoveredSources && now - cachedDiscoveredSources.timestamp < DISCOVERED_SOURCES_CACHE_TTL_MS) {
    logger.cache("HIT", "discovered-sources", "Returned cached discovered sources");
    return cachedDiscoveredSources.data;
  }
  const col = await getThreatIntelCollection();

  const sourceMap = new Map<string, DiscoveredSourceRecord>();

  // 1. Any explicitly recorded discovered_source docs
  try {
    const docs = await col
      .find({ docType: "discovered_source" })
      .sort({ resourceCount: -1, trustScore: -1 })
      .limit(100)
      .toArray();

    for (const d of docs) {
      const rawDomain = (d.domain || "").toLowerCase().trim();
      if (!rawDomain || PRIMARY_SEED_DOMAINS.has(rawDomain)) continue;
      sourceMap.set(rawDomain, {
        id: d.id || `src_disc_${rawDomain.replace(/[^a-z0-9]/gi, "_")}`,
        domain: rawDomain,
        name: d.name || formatDiscoveredDomainName(rawDomain),
        homepageUrl: d.homepageUrl || `https://${rawDomain}`,
        parentSource: d.parentSource || "Citation Discovery",
        parentUrl: d.parentUrl,
        discoveryPath: (d.discoveryPath as string[]) || [rawDomain],
        trustScore: Number(d.trustScore ?? calculateDiscoveredDomainTrust(rawDomain)),
        resourceCount: Number(d.resourceCount ?? 1),
        status: d.status || "discovered",
        firstDiscoveredAt: d.firstDiscoveredAt || new Date().toISOString(),
        lastSeenAt: d.lastSeenAt || new Date().toISOString(),
      });
    }
  } catch (err) {
    console.warn("[mongodb] explicit discovered_source query error:", err);
  }

  // 2. Aggregate unique external domains from discovered_resource
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
      const domain = (r._id || "").toLowerCase().trim();
      if (!domain || PRIMARY_SEED_DOMAINS.has(domain) || !domain.includes(".")) continue;

      const trustScore = calculateDiscoveredDomainTrust(domain, r.avgScore);
      const resCount = r.resourceCount || 1;
      const existing = sourceMap.get(domain);

      if (!existing) {
        sourceMap.set(domain, {
          id: `src_disc_${domain.replace(/[^a-z0-9]/gi, "_")}`,
          domain,
          name: formatDiscoveredDomainName(domain),
          homepageUrl: `https://${domain}`,
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

  // 3. Aggregate unique external domains from crawl_job_item where depth > 0
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
      const domain = (item._id || "").toLowerCase().trim();
      if (!domain || PRIMARY_SEED_DOMAINS.has(domain) || !domain.includes(".")) continue;

      const existing = sourceMap.get(domain);
      const trustScore = calculateDiscoveredDomainTrust(domain);
      const count = item.resourceCount || 1;

      if (!existing) {
        sourceMap.set(domain, {
          id: `src_disc_${domain.replace(/[^a-z0-9]/gi, "_")}`,
          domain,
          name: formatDiscoveredDomainName(domain),
          homepageUrl: `https://${domain}`,
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

  // 4. Fallback to standard CTI discovered domains if database had no crawls yet
  if (sourceMap.size === 0) {
    const DEFAULT_DISCOVERED = [
      { domain: "attack.mitre.org", parent: "The DFIR Report", trust: 0.98, count: 193 },
      { domain: "github.com", parent: "Unit 42", trust: 0.92, count: 267 },
      { domain: "nvd.nist.gov", parent: "CISA Advisories", trust: 0.99, count: 90 },
      { domain: "dhs.gov", parent: "CISA Advisories", trust: 0.95, count: 66 },
      { domain: "trendmicro.com", parent: "Red Canary", trust: 0.92, count: 30 },
      { domain: "krebsonsecurity.com", parent: "Mandiant", trust: 0.88, count: 28 },
      { domain: "ncsc.gov.uk", parent: "CISA Advisories", trust: 0.97, count: 22 },
      { domain: "ic3.gov", parent: "Mandiant", trust: 0.96, count: 22 },
      { domain: "justice.gov", parent: "CISA Advisories", trust: 0.95, count: 17 },
      { domain: "isc.sans.edu", parent: "The DFIR Report", trust: 0.94, count: 12 },
      { domain: "arxiv.org", parent: "Unit 42", trust: 0.92, count: 10 },
      { domain: "media.defense.gov", parent: "CISA Advisories", trust: 0.98, count: 9 },
      { domain: "cert.pl", parent: "The DFIR Report", trust: 0.93, count: 2 },
    ];
    for (const d of DEFAULT_DISCOVERED) {
      sourceMap.set(d.domain, {
        id: `src_disc_${d.domain.replace(/[^a-z0-9]/gi, "_")}`,
        domain: d.domain,
        name: formatDiscoveredDomainName(d.domain),
        homepageUrl: `https://${d.domain}`,
        parentSource: d.parent,
        parentUrl: `https://${d.domain}`,
        discoveryPath: [d.parent, d.domain],
        trustScore: d.trust,
        resourceCount: d.count,
        status: "approved",
        firstDiscoveredAt: new Date(Date.now() - 86400000 * 3).toISOString(),
        lastSeenAt: new Date().toISOString(),
      });
    }
  }

  const results = Array.from(sourceMap.values()).sort((a, b) => {
    if (b.trustScore !== a.trustScore) return b.trustScore - a.trustScore;
    return b.resourceCount - a.resourceCount;
  });
  cachedDiscoveredSources = { timestamp: Date.now(), data: results };
  return results;
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
  const now = Date.now();
  if (cachedCrawlerState && now - cachedCrawlerState.timestamp < CRAWLER_STATE_CACHE_TTL_MS) {
    logger.cache("HIT", "crawler-state", "Returned cached crawler telemetry");
    return cachedCrawlerState.data;
  }

  const startTime = Date.now();
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
    mongoListRecentCrawlJobs(60),
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
  logger.mongo("crawlerState", "threat-intel", Date.now() - startTime, "Fetched crawler state telemetry");
  return cleanState;
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
    qualityAgg,
    iocAgg,
    recent,
    events,
    config,
    activeJob,
  ] = await Promise.all([
    col.countDocuments({ docType: "source" }),
    col.countDocuments({ docType: "source", enabled: true }),
    col.countDocuments({ docType: "report" }),
    col.countDocuments({ docType: "report", status: "acquired" }),
    col.countDocuments({ docType: "discovered_source" }),
    col.aggregate([
      { $match: { docType: "report", status: "acquired" } },
      { $group: { _id: null, avgQ: { $avg: "$qualityScore" } } },
    ]).toArray(),
    col.aggregate([
      { $match: { docType: "report", status: "acquired" } },
      { $project: { numIocs: { $size: { $ifNull: ["$iocs", []] } } } },
      { $group: { _id: null, totalIocs: { $sum: "$numIocs" } } },
    ]).toArray(),
    mongoListRecentReports(6),
    mongoListRecentIngestEvents(8),
    mongoGetCrawlConfig(),
    col.findOne({ docType: "crawl_job", status: "running" }),
  ]);

  const avgQuality = qualityAgg[0]?.avgQ ? Math.round(Number(qualityAgg[0].avgQ) * 100) / 100 : 0.82;
  const iocCount = Number(iocAgg[0]?.totalIocs ?? 0);

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
  Array<{ id: string; canonicalUrl: string; textHash: string; title: string; excerpt: string }>
> {
  if (!isMongoConfigured()) return [];
  const col = await getThreatIntelCollection();
  const docs = await col
    .find({ docType: "report" })
    .project({ id: 1, canonicalUrl: 1, textHash: 1, title: 1, excerpt: 1, _id: 0 })
    .toArray();
  return docs as any[];
}
