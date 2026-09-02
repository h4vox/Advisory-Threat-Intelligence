import type { Collection, Filter, Document } from "mongodb";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import type {
  CrawlConfig,
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
} from "../aie/types";
import { excerptOf } from "../aie/extract";

let indexesEnsured = false;

export async function ensureMongoIndexes() {
  if (indexesEnsured || !isMongoConfigured()) return;
  try {
    const col = await getThreatIntelCollection();
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
    discoveryMethod: doc.discoveryMethod || "manual",
    discoveryQuery: doc.discoveryQuery || "",
    parentSource: doc.parentSource || "",
    sourceDomain: doc.sourceDomain || "",
    version: Number(doc.version ?? 1),
    rawHtml: doc.rawHtml || "",
    pdfUrl: doc.pdfUrl || "",
    analysis: (doc.analysis as IntelAnalysis) || null,
  };
}

export async function mongoListReports(params?: {
  q?: string;
  classification?: string;
}): Promise<ReportListItem[]> {
  await ensureMongoIndexes();
  const col = await getThreatIntelCollection();

  const filter: Filter<Document> = { docType: "report" };

  if (params?.classification && params.classification !== "ALL") {
    filter.classification = params.classification;
  }

  if (params?.q?.trim()) {
    const regex = new RegExp(params.q.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    filter.$or = [
      { title: { $regex: regex } },
      { publisher: { $regex: regex } },
      { sourceName: { $regex: regex } },
      { url: { $regex: regex } },
      { canonicalUrl: { $regex: regex } },
      { classification: { $regex: regex } },
      { "analysis.threatActors": { $regex: regex } },
      { "analysis.malware": { $regex: regex } },
    ];
  }

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
      extractedText: 1,
      publisher: 1,
      author: 1,
      classification: 1,
      discoveryMethod: 1,
      discoveryQuery: 1,
      parentSource: 1,
      sourceDomain: 1,
      version: 1,
      rawHtml: 1,
      pdfUrl: 1,
    });

  const docs = await cursor.toArray();

  return docs.map((doc) => {
    const text = doc.extractedText || "";
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
      excerpt: excerptOf(text),
      iocCount: iocsList.length,
      publisher: doc.publisher || doc.sourceName,
      author: doc.author || doc.publisher,
      classification: doc.classification || "THREAT_REPORT",
      discoveryMethod: doc.discoveryMethod || "manual",
      discoveryQuery: doc.discoveryQuery || "",
      parentSource: doc.parentSource || "",
      sourceDomain: doc.sourceDomain || "",
      version: Number(doc.version ?? 1),
      rawHtml: doc.rawHtml || "",
      pdfUrl: doc.pdfUrl || "",
    };
  });
}

export async function mongoFindReportByCanonical(canonicalUrl: string): Promise<{ id: string; qualityScore: number; title: string } | null> {
  const col = await getThreatIntelCollection();
  const doc = await col.findOne(
    { docType: "report", canonicalUrl },
    { projection: { id: 1, qualityScore: 1, title: 1 } },
  );
  if (!doc) return null;
  return { id: doc.id, qualityScore: Number(doc.qualityScore ?? 0), title: doc.title };
}

export async function mongoInsertReport(report: ReportRecord & { sourceName?: string }): Promise<void> {
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
// Crawler Config & Jobs
// ---------------------------------------------------------------------------

export async function mongoGetCrawlConfig(): Promise<CrawlConfig> {
  const col = await getThreatIntelCollection();
  const doc = await col.findOne({ docType: "crawl_config" });

  if (doc) {
    return {
      id: doc.id,
      enabled: Boolean(doc.enabled),
      paused: Boolean(doc.paused),
      frequencyMinutes: Number(doc.frequencyMinutes ?? 360),
      startHour: doc.startHour || "09:00",
      maxResourcesPerRun: Number(doc.maxResourcesPerRun ?? 25),
      maxDepth: Number(doc.maxDepth ?? 2),
      autoIngest: Boolean(doc.autoIngest ?? true),
      autoAnalyze: Boolean(doc.autoAnalyze ?? true),
      searchDiscovery: Boolean(doc.searchDiscovery ?? true),
      recursiveDiscovery: Boolean(doc.recursiveDiscovery ?? true),
      keywords: doc.keywords || 'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK"',
      dateRangeDays: doc.dateRangeDays ? Number(doc.dateRangeDays) : null,
      lastRunAt: doc.lastRunAt || null,
      nextRunAt: doc.nextRunAt || null,
    };
  }

  const nextRun = new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString();
  const defaultConfig: CrawlConfig = {
    id: "cfg_default",
    enabled: true,
    paused: false,
    frequencyMinutes: 360,
    startHour: "09:00",
    maxResourcesPerRun: 25,
    maxDepth: 2,
    autoIngest: true,
    autoAnalyze: true,
    searchDiscovery: true,
    recursiveDiscovery: true,
    keywords: 'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"',
    dateRangeDays: null,
    lastRunAt: null,
    nextRunAt: nextRun,
  };

  await col.updateOne(
    { docType: "crawl_config", id: defaultConfig.id },
    { $set: { docType: "crawl_config", ...defaultConfig } },
    { upsert: true },
  );

  return defaultConfig;
}

export async function mongoUpdateCrawlConfig(updates: Partial<CrawlConfig>): Promise<CrawlConfig> {
  const col = await getThreatIntelCollection();
  const current = await mongoGetCrawlConfig();
  const merged = { ...current, ...updates, updatedAt: new Date().toISOString() };
  await col.updateOne({ docType: "crawl_config", id: current.id }, { $set: merged }, { upsert: true });
  return merged;
}

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
  const col = await getThreatIntelCollection();
  await col.updateOne(
    { docType: "discovered_resource", canonicalUrl: resource.canonicalUrl },
    {
      $set: {
        docType: "discovered_resource",
        ...resource,
        updatedAt: new Date().toISOString(),
      },
      $setOnInsert: {
        createdAt: new Date().toISOString(),
      },
    },
    { upsert: true },
  );
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
    classification: d.classification || "THREAT_REPORT",
    discoveryMethod: d.discoveryMethod || "crawl_source",
    discoveryQuery: d.discoveryQuery || "",
    parentSource: d.parentSource || "",
    sourceDomain: d.sourceDomain || "",
    contentType: d.contentType || "text/html",
    status: d.status || "discovered",
    rejectReason: d.rejectReason || "",
    qualityScore: d.qualityScore ? Number(d.qualityScore) : null,
    reportId: d.reportId || null,
    createdAt: d.createdAt || new Date().toISOString(),
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
// Dashboard Aggregates
// ---------------------------------------------------------------------------

export async function mongoGetDashboardStats(): Promise<DashboardStats> {
  const col = await getThreatIntelCollection();

  const [sourceTotal, enabledSources, reportTotal, acquiredTotal, qualityAgg, iocDocs] = await Promise.all([
    col.countDocuments({ docType: "source" }),
    col.countDocuments({ docType: "source", enabled: true }),
    col.countDocuments({ docType: "report" }),
    col.countDocuments({ docType: "report", status: "acquired" }),
    col.aggregate([
      { $match: { docType: "report", status: "acquired" } },
      { $group: { _id: null, avgQ: { $avg: "$qualityScore" } } },
    ]).toArray(),
    col.find({ docType: "report", status: "acquired" }).project({ iocs: 1 }).toArray(),
  ]);

  const avgQuality = qualityAgg[0]?.avgQ ? Math.round(Number(qualityAgg[0].avgQ) * 100) / 100 : 0.82;
  const iocCount = iocDocs.reduce((acc, d) => acc + ((d.iocs as any[])?.length || 0), 0);

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
  };
}
