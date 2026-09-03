import type { Filter, Document } from "mongodb";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import type {
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
  TrustLevel,
  DiscoveredSourceRecord,
  DiscoveryGraphEdge,
} from "../aie/types";
import { excerptOf } from "../aie/extract";

let indexesEnsured = false;

export async function ensureMongoIndexes() {
  if (indexesEnsured || !isMongoConfigured()) return;
  try {
    const col = await getThreatIntelCollection();
    // Purge any documents with id: null to prevent E11000 duplicate key conflicts
    await col.deleteMany({ id: null });
    await col.createIndex({ docType: 1, id: 1 }, { unique: true, background: true });
    await col.createIndex(
      { docType: 1, canonicalUrl: 1 },
      {
        unique: true,
        partialFilterExpression: { docType: "report", canonicalUrl: { $type: "string" } },
        background: true,
      },
    );
    await col.createIndex({ docType: 1, ingestedAt: -1 }, { background: true });
    await col.createIndex({ docType: 1, classification: 1 }, { background: true });
    await col.createIndex({ docType: 1, resourceKind: 1 }, { background: true });
    await col.createIndex({ docType: 1, status: 1 }, { background: true });
    await col.createIndex({ docType: 1, priority: 1 }, { background: true });
    await col.createIndex({ docType: 1, createdAt: -1 }, { background: true });
    indexesEnsured = true;
  } catch (err) {
    console.warn("[mongodb] failed ensuring indexes:", err);
  }
}

// ---------------------------------------------------------------------------
// Report CRUD
// ---------------------------------------------------------------------------

export async function mongoGetReportById(id: string): Promise<ReportRecord | null> {
  const col = await getThreatIntelCollection();
  const doc = await col.findOne({ docType: "report", id });
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
      // Avoid transferring multi-megabyte HTML/PDF strings over network for list cards
      excerpt: { $substrCP: [{ $ifNull: ["$extractedText", ""] }, 0, 320] },
    });

  const docs = await cursor.toArray();
  console.log(`[mongo] listReports: fetched ${docs.length} reports in ${Date.now() - startTime}ms`);

  return docs.map((doc) => {
    const text = (doc.excerpt as string) || (doc.extractedText as string) || "";
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
      excerpt: excerptOf(text),
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
    };
  });
}

export async function mongoInsertReport(report: ReportRecord): Promise<void> {
  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "report", id: report.id },
    {
      $set: {
        docType: "report",
        ...report,
        updatedAt: new Date().toISOString(),
      },
    },
    { upsert: true },
  );
}

export async function mongoDeleteReport(id: string): Promise<boolean> {
  const col = await getThreatIntelCollection();
  const res = await col.deleteOne({ docType: "report", id });
  return res.deletedCount > 0;
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

const DEFAULT_CRAWL_CONFIG: CrawlConfig = {
  id: "cfg_default",
  enabled: true,
  paused: false,
  frequencyMinutes: 360,
  startHour: "09:00",
  maxResourcesPerRun: 30,
  maxDepth: 2,
  autoIngest: true,
  autoAnalyze: true,
  generatePdf: true,
  rssDiscovery: true,
  htmlDiscovery: true,
  searchDiscovery: true,
  recursiveDiscovery: true,
  keywords: 'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"',
  noiseKeywords: "webinar, discount, pricing, subscribe, careers, terms of service, privacy policy",
  minQualityScore: 0.40,
  minWordCount: 120,
  strictnessMode: "balanced",
  requireIocs: false,
  requireAttck: false,
  rejectMarketingNoise: true,
  dedupMethod: "both",
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
  const col = await getThreatIntelCollection();
  const doc = await col.findOne({ docType: "crawl_config" });

  if (doc) {
    return {
      id: doc.id,
      enabled: Boolean(doc.enabled ?? true),
      paused: Boolean(doc.paused ?? false),
      frequencyMinutes: Number(doc.frequencyMinutes ?? 360),
      startHour: doc.startHour || "09:00",
      maxResourcesPerRun: Number(doc.maxResourcesPerRun ?? 30),
      maxDepth: Number(doc.maxDepth ?? 2),
      autoIngest: Boolean(doc.autoIngest ?? true),
      autoAnalyze: Boolean(doc.autoAnalyze ?? true),
      generatePdf: Boolean(doc.generatePdf ?? true),
      rssDiscovery: Boolean(doc.rssDiscovery ?? true),
      htmlDiscovery: Boolean(doc.htmlDiscovery ?? true),
      searchDiscovery: Boolean(doc.searchDiscovery ?? true),
      recursiveDiscovery: Boolean(doc.recursiveDiscovery ?? true),
      keywords: doc.keywords || DEFAULT_CRAWL_CONFIG.keywords,
      noiseKeywords: doc.noiseKeywords || DEFAULT_CRAWL_CONFIG.noiseKeywords,
      minQualityScore: Number(doc.minQualityScore ?? 0.40),
      minWordCount: Number(doc.minWordCount ?? 120),
      strictnessMode: doc.strictnessMode || "balanced",
      requireIocs: Boolean(doc.requireIocs ?? false),
      requireAttck: Boolean(doc.requireAttck ?? false),
      rejectMarketingNoise: Boolean(doc.rejectMarketingNoise ?? true),
      dedupMethod: doc.dedupMethod || "both",
      activeSources: (doc.activeSources as string[]) || [],
      targetResourceTypes: (doc.targetResourceTypes as ResourceKind[]) || DEFAULT_CRAWL_CONFIG.targetResourceTypes,
      dateRangeDays: doc.dateRangeDays ? Number(doc.dateRangeDays) : null,
      lastRunAt: doc.lastRunAt || null,
      nextRunAt: doc.nextRunAt || null,
    };
  }

  await col.updateOne(
    { docType: "crawl_config", id: DEFAULT_CRAWL_CONFIG.id },
    { $set: { docType: "crawl_config", ...DEFAULT_CRAWL_CONFIG } },
    { upsert: true },
  );

  return DEFAULT_CRAWL_CONFIG;
}

export async function mongoUpdateCrawlConfig(updates: Partial<CrawlConfig>): Promise<CrawlConfig> {
  const col = await getThreatIntelCollection();
  const current = await mongoGetCrawlConfig();
  const merged = { ...current, ...updates, updatedAt: new Date().toISOString() };
  await col.updateOne({ docType: "crawl_config", id: current.id }, { $set: merged }, { upsert: true });
  return merged;
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
}

export async function mongoUpdateCrawlJob(id: string, updates: Partial<CrawlJob>): Promise<void> {
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "crawl_job", id },
    { $set: { ...updates, updatedAt: new Date().toISOString() } },
  );
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
    qualifiedCount: Number(d.qualifiedCount ?? 0),
    ingestedCount: Number(d.ingestedCount ?? 0),
    duplicateCount: Number(d.duplicateCount ?? 0),
    failedCount: Number(d.failedCount ?? 0),
    rejectedCount: Number(d.rejectedCount ?? 0),
    updatedCount: Number(d.updatedCount ?? 0),
    skippedCount: Number(d.skippedCount ?? 0),
    errorSummary: d.errorSummary || "",
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
    const { id: _ignoredId, ...setFields } = resource;
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
          createdAt: new Date().toISOString(),
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
    .sort({ createdAt: -1, updatedAt: -1 })
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
    const { id: _ignoredId, ...setFields } = source;
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
          firstDiscoveredAt: new Date().toISOString(),
        },
      },
      { upsert: true },
    );
  } catch (err) {
    console.warn("[mongodb] mongoInsertDiscoveredSource error:", err);
  }
}

export async function mongoListDiscoveredSources(): Promise<DiscoveredSourceRecord[]> {
  if (!isMongoConfigured()) return [];
  const col = await getThreatIntelCollection();
  const docs = await col.find({ docType: "discovered_source" }).sort({ trustScore: -1, resourceCount: -1 }).limit(50).toArray();
  return docs.map((d) => ({
    id: d.id,
    domain: d.domain,
    name: d.name,
    homepageUrl: d.homepageUrl,
    parentSource: d.parentSource || "",
    parentUrl: d.parentUrl,
    discoveryPath: (d.discoveryPath as string[]) || [],
    trustScore: Number(d.trustScore ?? 0.5),
    resourceCount: Number(d.resourceCount ?? 1),
    status: d.status || "discovered",
    firstDiscoveredAt: d.firstDiscoveredAt || new Date().toISOString(),
    lastSeenAt: d.lastSeenAt || new Date().toISOString(),
  }));
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
}

export async function mongoListGraphEdges(limit = 60): Promise<DiscoveryGraphEdge[]> {
  if (!isMongoConfigured()) return [];
  const col = await getThreatIntelCollection();
  const docs = await col.find({ docType: "graph_edge" }).sort({ createdAt: -1 }).limit(limit).toArray();
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

export async function mongoGetCrawlerState(): Promise<CrawlerState> {
  const col = await getThreatIntelCollection();

  const [config, jobs, items, discovered, discoveredSources, graphEdges, sourceStatsDocs] = await Promise.all([
    mongoGetCrawlConfig(),
    mongoListRecentCrawlJobs(10),
    mongoListRecentCrawlJobItems(35),
    mongoListDiscoveredResources(50),
    mongoListDiscoveredSources(),
    mongoListGraphEdges(60),
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
  ]);

  const activeJob = jobs.find((j) => j.status === "running") ?? null;

  const sourceStats = sourceStatsDocs.map((s) => ({
    sourceName: s._id || "Unknown Source",
    found: Number(s.found),
    ingested: Number(s.ingested),
    failed: Number(s.failed),
  }));

  return {
    config,
    activeJob,
    jobs,
    items,
    discovered,
    discoveredSources,
    graphEdges,
    sourceStats,
  };
}

// ---------------------------------------------------------------------------
// Dashboard Aggregates
// ---------------------------------------------------------------------------

export async function mongoGetDashboardStats(): Promise<DashboardStats> {
  const col = await getThreatIntelCollection();

  const [sourceTotal, enabledSources, reportTotal, acquiredTotal, discoveredSourcesCount, qualityAgg, iocDocs] = await Promise.all([
    col.countDocuments({ docType: "source" }),
    col.countDocuments({ docType: "source", enabled: true }),
    col.countDocuments({ docType: "report" }),
    col.countDocuments({ docType: "report", status: "acquired" }),
    col.countDocuments({ docType: "discovered_source" }),
    col.aggregate([
      { $match: { docType: "report", status: "acquired" } },
      { $group: { _id: null, avgQ: { $avg: "$qualityScore" } } },
    ]).toArray(),
    col.find({ docType: "report", status: "acquired" }).project({ iocs: 1 }).toArray(),
  ]);

  const avgQuality = qualityAgg[0]?.avgQ ? Math.round(Number(qualityAgg[0].avgQ) * 100) / 100 : 0.82;
  const iocCount = iocDocs.reduce((acc, d) => acc + ((d.iocs as unknown[])?.length || 0), 0);

  const recent = (await mongoListReports()).slice(0, 6);
  const events = await mongoListRecentIngestEvents(8);
  const config = await mongoGetCrawlConfig();
  const activeJob = await col.findOne({ docType: "crawl_job", status: "running" });

  const crawlerStatus = activeJob
    ? "running"
    : config.paused
      ? "paused"
      : config.enabled
        ? "scheduled"
        : "disabled";

  return {
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
}
