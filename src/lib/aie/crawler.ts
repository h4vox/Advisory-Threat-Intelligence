import { analyzeThreatIntelligence, extractStructuredEntities } from "./attack-chain";
import { lookupAttackTechnique } from "./mitre-matrix";
import {
  DISCOVERY_KNOWLEDGE_POOL,
  evaluateDomainTrust,
  extractOutlinksAndCitations,
  generateSearchQueries,
} from "./discovery";
import {
  canonicalizeUrl,
  computeHammingDistance,
  computeReportSimHash,
  excerptOf,
  harvestIocs,
  htmlToText,
  extractHtmlMetadata,
  MAX_BYTES,
  scoreQuality,
  sectionsOf,
  sha256Hex,
  toIsoString,
} from "./extract";
import { parseRssOrAtomXml } from "./feeds";
import {
  CRAWL_LOCK_HEARTBEAT_MS,
  acquireCrawlLock as acquireLockDoc,
  describeHeldLock,
  releaseCrawlLock as releaseLockDoc,
  renewCrawlLock,
  type CrawlLockCollection,
  type CrawlLockDoc,
  type HolderJobStatus,
} from "./crawl-lock";
import { buildPristineDocumentHtml, extractTextFromPdfBuffer } from "./pdf";
import { isSafeCrawlPatternString, isSafePublicUrlString, safeFetchResource, safeFetchText, validateSafePublicUrl } from "./security";
import { discoverAgentSources, evaluateResourceWithAgent, type AgentEvaluationResult } from "./agy-agent";
import {
  resolveCrawlerAiAvailability,
  runUnifiedSourceDiscovery,
  runUnifiedResourceEvaluation,
  runUnifiedDomainResourceDiscovery,
  runUnifiedReportDiscovery,
  runUnifiedTranslation,
  type CrawlerAiAvailability,
} from "./ai-manager";
import { articleProse, detectLanguage } from "./technical-depth";
import {
  ORIGINAL_TEXT_CAP,
  TRANSLATIONS_PER_JOB,
  TRANSLATION_ITEM_SHARE,
  TRANSLATION_JOB_BUDGET_MS,
  declaredHtmlLang,
  findEnglishAlternate,
  guessEnglishUrls,
  languageName,
} from "./translation";
import { WORKER_DRAIN_GRACE_MS, hungJobReason, itemTimeoutMs, settleWithin } from "./crawl-guards";
import { isCandidateResourceUrl, matchesCrawlPattern, qualifyContent } from "./qualification";
import type {
  CrawlConfig,
  CrawlJob,
  CrawlJobItem,
  CrawlPipelineStage,
  CrawlTrigger,
  DiscoveredResource,
  ReportRecord,
  ReportTranslation,
  SourceRecord,
} from "./types";
import { getSql, type Sql } from "@/lib/db";
import { logger } from "./logger";
import { sanitizeAgyModel, DEFAULT_AGY_MODEL } from "./agent-framework/types";
import { getThreatIntelCollection, isMongoConfigured } from "../mongodb/client.server";
import {
  mongoFindReportByCanonical,
  mongoGetCrawlConfig,
  mongoInsertCrawlJob,
  mongoInsertCrawlJobItem,
  mongoInsertDiscoveredSource,
  mongoInsertGraphEdge,
  mongoInsertGraphEdgesBatch,
  mongoInsertIngestEvent,
  mongoInsertReport,
  mongoSaveReportOriginal,
  mongoListReports,
  mongoGetExistingReportsDedupIndex,
  mongoListSources,
  mongoListDiscoveredSources,
  mongoCreateDiscoveredSource,
  mongoSeedSources,
  mongoUpdateCrawlConfig,
  mongoUpdateCrawlJob,
  mongoUpdateSourceLastIngest,
  mongoUpsertDiscoveredResource,
  ensureMongoIndexes,
  invalidateCrawlerStateCache,
  registerJobActiveChecker,
  registerScheduleChecker,
} from "../mongodb/repository.server";
import { SOURCE_SEED, isStructuredSource, registryEntry } from "./catalog";
import { annotateReportProvenance } from "./doc-classifier";
import { classifyResearch, normalizeResearchDiscovery, type ResearchCategoryId } from "./research-taxonomy";
import { extractTelemetryRefs } from "./telemetry-refs";
import { buildSearchPlan, isSearchChallenge, parseBraveJson, parseDuckDuckGoHtml, parseSearxngJson, searchProviders, type SearchProvider, type SearchResult } from "./web-search";
import { mongoResearchCoverage } from "../mongodb/research-repo.server";
import { CollectorRun, COLLECTOR_USER_AGENT, type CrawlRunOptions } from "./collector/run";
import { computeFingerprints, hammingDistance64, normalizeForFingerprint, simhash64 } from "./collector/fingerprint";
import { DUPLICATE_KIND_LABEL, preferCanonical } from "./collector/dedup";
import {
  discoverFeedLinks,
  filterSitemapEntries,
  findNextPageUrl,
  paginationUrls,
  parseSitemapXml,
  planBackfill,
  rankChildSitemaps,
  titleFromSlug,
} from "./collector/discovery-depth";
import { appendPdfText, enrichAttackEntities, findFullReportPdfLinks, withAttackRefs } from "./collector/enrich";
import type { RelevanceResult } from "./collector/relevance";
import { computeDue } from "./collector/health";
import {
  applyReportVersion,
  findStoredReportByCanonical,
  getSourceHealthMap,
  mergeLocalReportMeta,
  recordMirror,
  supersedeWithCanonical,
} from "../mongodb/collector-repo.server";
import type { TextSection } from "./extract";
import { EMULATION_GRADE_META, assessEmulationValue, summarizeEmulation } from "./emulation-value";
import { isAdvisoryPublisher } from "./technical-depth";
import { resolvePublicationDate, type PublishedDate } from "./published-date";
import { mongoAnalyseNewlyIngested } from "../mongodb/library-review-repo.server";
import type { ReportAttachment, ReportMirror } from "./types";

/** Re-fetched pages this close (SimHash bits) to the stored copy are cosmetic edits, not new versions. */
const COSMETIC_CHANGE_DISTANCE = 2;

function newId(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

type JobControl = {
  cancel: boolean;
  pause: boolean;
  /** When the job was reserved (ms). */
  startedAt: number;
  /** The job's time limit (ms). Still registered well past it means the job is hung. */
  maxRunMs: number;
  /** When an operator cancel was requested (ms), so a job that never drains can be released. */
  cancelledAt?: number;
  /** Renews this job's crawl-lock lease while it runs (Mongo only). */
  leaseTimer?: ReturnType<typeof setInterval>;
};

const DEFAULT_JOB_MAX_RUN_MS = 20 * 60_000;

// Crawler state is process-wide, on globalThis. In dev, Vite re-evaluates this module after an edit or
// `git pull`; module-level state then split in two: the running job lived in the old copy, the new copy
// (and the watchdog) could not see it, the dashboard finalized it as "orphaned" while it still held the
// crawl lock ("A crawl is already running"), and a second scheduler daemon started. One map, one lock
// owner and one daemon per process.
type CrawlerGlobals = typeof globalThis & {
  __aieActiveJobs?: Map<string, JobControl>;
  __aieDrainingJobs?: Map<string, JobControl>;
  __aieCrawlLockOwner?: string;
  __aieSchedulerDaemon?: ReturnType<typeof setInterval>;
  __aieSchedulerTick?: () => Promise<unknown>;
};
const crawlerGlobals = globalThis as CrawlerGlobals;

// Jobs that hold the crawl slot in this process.
const activeJobs: Map<string, JobControl> = (crawlerGlobals.__aieActiveJobs ??= new Map());
// Cancelled jobs still winding down their in-flight requests. They no longer hold the slot: an operator
// cancel frees it at once, so the next crawl can start while these finish.
const drainingJobs: Map<string, JobControl> = (crawlerGlobals.__aieDrainingJobs ??= new Map());

// Register memory state tracker with repository watchdog
registerJobActiveChecker((jobId: string) => activeJobs.has(jobId) || drainingJobs.has(jobId));

export function isJobActiveInMemory(jobId: string): boolean {
  return activeJobs.has(jobId);
}

// ---------------------------------------------------------------------------
// Cross-process crawl lock (Mongo only): a short lease renewed by a heartbeat while the job runs, taken
// over at once when its job is no longer running (see ./crawl-lock). Without Mongo, the in-memory
// activeJobs map is the only guard (single process).
// ---------------------------------------------------------------------------

const CRAWL_LOCK_OWNER = (crawlerGlobals.__aieCrawlLockOwner ??= `${process.pid}:${crypto.randomUUID().slice(0, 8)}`);
export const CRAWL_ALREADY_RUNNING_MESSAGE = "A crawl is already running";

export class CrawlAlreadyRunningError extends Error {
  constructor(detail?: string) {
    super(detail ? `${CRAWL_ALREADY_RUNNING_MESSAGE} (${detail})` : CRAWL_ALREADY_RUNNING_MESSAGE);
    this.name = "CrawlAlreadyRunningError";
  }
}

async function lockCollection(): Promise<CrawlLockCollection> {
  return (await getThreatIntelCollection<CrawlLockDoc>()) as unknown as CrawlLockCollection;
}

async function crawlJobStatus(jobId: string): Promise<HolderJobStatus> {
  const jobsCol = await getThreatIntelCollection();
  const job = await jobsCol.findOne({ docType: "crawl_job", id: jobId }, { projection: { status: 1 } });
  if (!job) return "missing";
  return job.status === "running" ? "running" : "finished";
}

/**
 * Takes the crawl lock for `jobId`, or throws CrawlAlreadyRunningError naming the job that holds it.
 * `staleAfterMs`: other jobs still marked "running" after this long belong to a stopped server.
 */
async function acquireCrawlLock(jobId: string, staleAfterMs: number): Promise<void> {
  const res = await acquireLockDoc(await lockCollection(), {
    jobId,
    owner: CRAWL_LOCK_OWNER,
    isLocalActive: (id) => activeJobs.has(id),
    holderStatus: crawlJobStatus,
  });
  if (!res.ok) throw new CrawlAlreadyRunningError(describeHeldLock(res.heldBy, res.expiresInMs));

  const now = new Date();
  if (res.takenOverFrom) {
    console.warn(`[crawler] crawl lock taken over from ${res.takenOverFrom.jobId} (${res.takenOverFrom.reason})`);
    // A holder that is not running anywhere but still says "running" never finished: record that.
    if (res.takenOverFrom.reason !== "holder_finished") {
      try {
        await updateJobIfRunning(res.takenOverFrom.jobId, {
          status: "interrupted",
          completedAt: now.toISOString(),
          errorSummary: "Crawl job interrupted (its server stopped or reloaded before completion)",
        });
      } catch {
        /* the dashboard watchdog reconciles the record */
      }
    }
  }

  // We own the lock, so any other job still marked "running" past the stale window belongs to a stopped server.
  try {
    const cutoffIso = new Date(now.getTime() - staleAfterMs).toISOString();
    const jobsCol = await getThreatIntelCollection();
    const stale = await jobsCol.updateMany(
      { docType: "crawl_job", status: "running", id: { $ne: jobId }, startedAt: { $lt: cutoffIso } },
      {
        $set: {
          status: "interrupted",
          completedAt: now.toISOString(),
          errorSummary: "Crawl job interrupted (instance stopped before completion)",
          updatedAt: now.toISOString(),
        },
      },
    );
    if (stale.modifiedCount > 0) {
      console.warn(`[crawler] marked ${stale.modifiedCount} stale running job(s) as interrupted`);
      invalidateCrawlerStateCache();
    }
  } catch (err) {
    console.warn("[crawler] failed to mark stale running jobs as interrupted:", err);
  }
}

/** Renews the job's lease every 30 s. If the lock was taken over (its job was cancelled elsewhere), the job stops. */
function startLockHeartbeat(jobId: string, control: JobControl): void {
  stopLockHeartbeat(control);
  control.leaseTimer = setInterval(() => {
    void (async () => {
      try {
        const kept = await renewCrawlLock(await lockCollection(), { jobId, owner: CRAWL_LOCK_OWNER });
        if (!kept && !control.cancel) {
          console.warn(`[crawler] job ${jobId} lost the crawl lock (cancelled or taken over); stopping`);
          control.cancel = true;
          control.cancelledAt ??= Date.now();
        }
      } catch {
        /* transient database error: the next beat retries; the lease outlasts several beats */
      }
    })();
  }, CRAWL_LOCK_HEARTBEAT_MS);
  control.leaseTimer.unref?.();
}

function stopLockHeartbeat(control: JobControl | undefined): void {
  if (control?.leaseTimer) clearInterval(control.leaseTimer);
  if (control) control.leaseTimer = undefined;
}

/** Frees the lock if `jobId` holds it. `anyOwner`: an operator cancel, which ends the job wherever it runs. */
async function releaseCrawlLock(jobId: string, anyOwner = false): Promise<void> {
  try {
    await releaseLockDoc(await lockCollection(), anyOwner ? { jobId } : { jobId, owner: CRAWL_LOCK_OWNER });
  } catch (err) {
    console.warn(`[crawler] failed to release crawl lock for ${jobId} (its lease expires on its own):`, err);
  }
}

/** Conditionally updates a job only while it is still "running"; returns whether it matched. */
async function updateJobIfRunning(jobId: string, updates: Partial<CrawlJob>): Promise<boolean> {
  const col = await getThreatIntelCollection();
  const res = await col.updateOne(
    { docType: "crawl_job", id: jobId, status: "running" },
    { $set: { ...updates, updatedAt: new Date().toISOString() } },
  );
  invalidateCrawlerStateCache();
  return res.matchedCount > 0;
}

/**
 * Release in-memory jobs that can no longer be running normally: still registered well past their time
 * limit, or cancelled long ago without stopping (an awaited request that never answered). Without this
 * one hung job blocked every scheduled and manual crawl until the server restarted.
 */
async function releaseHungJobs(now = Date.now()): Promise<string[]> {
  const released: string[] = [];
  for (const [id, ctl] of activeJobs) {
    const reason = hungJobReason(ctl, now);
    if (!reason) continue;
    ctl.cancel = true;
    stopLockHeartbeat(ctl);
    activeJobs.delete(id);
    released.push(id);
    const summary =
      reason === "over_time"
        ? `Crawl job stopped: still running ${Math.round((now - ctl.startedAt) / 60_000)} min after it started (limit ${Math.round(ctl.maxRunMs / 60_000)} min) because a request never answered; released automatically`
        : "Crawl job cancelled; it did not stop in time and was released automatically";
    console.warn(`[crawler] releasing hung job ${id}: ${summary}`);
    if (isMongoConfigured()) {
      try {
        await updateJobIfRunning(id, { status: "interrupted", completedAt: new Date(now).toISOString(), errorSummary: summary });
      } catch {
        /* the dashboard watchdog reconciles the record */
      }
      await releaseCrawlLock(id);
    }
  }
  // Cancelled jobs that never finished winding down hold nothing; just forget them.
  for (const [id, ctl] of drainingJobs) {
    if (hungJobReason(ctl, now)) drainingJobs.delete(id);
  }
  if (released.length) invalidateCrawlerStateCache();
  return released;
}

interface FrontierItem {
  url: string;
  canonicalUrl: string;
  depth: number;
  priorityScore: number;
  parentUrl: string | null;
  parentSource: string | null;
  discoveryPath: string[];
  discoveryMethod: "seed_source" | "rss_feed" | "outlink_citation" | "pdf_reference" | "repo_reference" | "search_expansion" | "agent_discovery" | "sitemap";
  sourceId?: string;
  sourceSlug?: string;
  publisher?: string;
  author?: string;
  domain: string;
  preloadedText?: string;
  title?: string;
  /** Publication date reported by the source (feed or page metadata); null when unknown. */
  publishedAt?: string | null;
  /** How the publication date was established (./published-date), once the content is in hand. */
  publishedDate?: PublishedDate;
  /** Creation date from the PDF's document information, for PDF resources. */
  pdfDate?: string;
  /** Feed summary (used by the relevance pre-score when the full text is not preloaded). */
  summary?: string;
  /** Sitemap lastmod / feed updated date: a listing-reported change after our last fetch triggers revalidation. */
  lastmodHint?: string | null;
  /** Relevance pre-score computed at enqueue (title, summary, URL, source history). */
  relevance?: RelevanceResult;
  /** The web search that found it (search discovery). */
  discoveryQuery?: string;
  /** The research category that search was looking for (./research-taxonomy). */
  researchCategory?: ResearchCategoryId;
}

export async function getOrCreateCrawlConfig(): Promise<CrawlConfig> {
  if (isMongoConfigured()) {
    try {
      return await mongoGetCrawlConfig();
    } catch (err) {
      console.warn("[mongodb] getOrCreateCrawlConfig fallback:", err);
    }
  }

  const sql = await getSql();
  const rows = await sql<Record<string, unknown>>`select * from crawl_config limit 1`;

  const defaultConfig: CrawlConfig = {
    id: "cfg_default",
    enabled: true,
    paused: false,
    frequencyMinutes: 360,
    startHour: "09:00",
    maxResourcesPerRun: 60,
    maxResourcesPerJob: 60,
    maxResourcesPerDomain: 8,
    maxDepth: 3,
    discoveryBreadth: "balanced",
    allowExternalDomains: true,
    domainAllowlist: [],
    domainBlocklist: [],
    rateLimitMs: 150,
    concurrency: 4,
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
    minEmulationGrade: "context",
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

  if (rows.length > 0) {
    // The local table stores a subset of the config in snake_case columns: map it over the defaults
    // (returning the raw row left autoIngest / autoAnalyze / dedupMethod undefined, i.e. silently off).
    const r = rows[0];
    const pick = <T,>(v: unknown, fallback: T): T => (v === null || v === undefined ? fallback : (v as T));
    const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : typeof v === "string" ? v : null);
    return {
      ...defaultConfig,
      id: String(r.id ?? defaultConfig.id),
      enabled: pick(r.enabled, defaultConfig.enabled),
      paused: pick(r.paused, defaultConfig.paused),
      frequencyMinutes: Number(pick(r.frequency_minutes, defaultConfig.frequencyMinutes)),
      startHour: pick(r.start_hour, defaultConfig.startHour),
      maxResourcesPerRun: Number(pick(r.max_resources_per_run, defaultConfig.maxResourcesPerRun)),
      maxDepth: Number(pick(r.max_depth, defaultConfig.maxDepth)),
      autoIngest: pick(r.auto_ingest, defaultConfig.autoIngest),
      autoAnalyze: pick(r.auto_analyze, defaultConfig.autoAnalyze),
      searchDiscovery: pick(r.search_discovery, defaultConfig.searchDiscovery),
      recursiveDiscovery: pick(r.recursive_discovery, defaultConfig.recursiveDiscovery),
      keywords: pick(r.keywords, defaultConfig.keywords),
      dateRangeDays: r.date_range_days === null || r.date_range_days === undefined ? null : Number(r.date_range_days),
      lastRunAt: iso(r.last_run_at),
      nextRunAt: iso(r.next_run_at),
    };
  }

  await sql`
    insert into crawl_config (
      id, enabled, paused, frequency_minutes, start_hour, max_resources_per_run,
      max_depth, auto_ingest, auto_analyze, search_discovery, recursive_discovery,
      keywords, date_range_days, last_run_at, next_run_at
    ) values (
      ${defaultConfig.id}, ${defaultConfig.enabled}, ${defaultConfig.paused},
      ${defaultConfig.frequencyMinutes}, ${defaultConfig.startHour}, ${defaultConfig.maxResourcesPerRun},
      ${defaultConfig.maxDepth}, ${defaultConfig.autoIngest}, ${defaultConfig.autoAnalyze},
      ${defaultConfig.searchDiscovery}, ${defaultConfig.recursiveDiscovery}, ${defaultConfig.keywords},
      ${defaultConfig.dateRangeDays}, ${defaultConfig.lastRunAt}, ${defaultConfig.nextRunAt}
    )
  `;

  return defaultConfig;
}

export async function executeCrawlJob(
  jobId: string,
  triggerType: CrawlTrigger = "MANUAL",
  targetedQuery?: string,
  runOptions: CrawlRunOptions = {},
): Promise<CrawlJob> {
  // The time limit covers the whole job, discovery included (the watchdog measures from the start too).
  const jobStartTime = Date.now();
  const isMongo = isMongoConfigured();
  const config = isMongo ? await mongoGetCrawlConfig() : await getOrCreateCrawlConfig();

  // Reuse the entry reserved by createAndRunCrawlJob so an early cancel is not lost.
  const jobControl: JobControl = activeJobs.get(jobId) ?? { cancel: false, pause: false, startedAt: jobStartTime, maxRunMs: DEFAULT_JOB_MAX_RUN_MS };
  activeJobs.set(jobId, jobControl);

  const breadth = config.discoveryBreadth || "balanced";
  let maxDepth = config.maxDepth || 3;
  if (breadth === "focused") maxDepth = 1;
  else if (breadth === "wide") maxDepth = Math.max(maxDepth, 4);

  let configuredMax = config.maxResourcesPerJob || config.maxResourcesPerRun || 60;
  const maxTotalResources = targetedQuery
    ? Math.min(Math.max(configuredMax, 15), 100)
    : breadth === "wide"
      ? Math.min(Math.max(configuredMax, 30), 300)
      : Math.min(Math.max(configuredMax, 20), 150);
  let maxPerDomain = breadth === "wide" ? Math.max(config.maxResourcesPerDomain || 8, 8) : config.maxResourcesPerDomain || 6;
  const maxPdfDownloads = config.maxPdfDownloads || 10;

  // Collector context: schedules, backoff, fetch state, robots, relevance, multi-hash dedup, funnel.
  const collector = await CollectorRun.start(jobId, triggerType, runOptions);
  const backfillPlan = collector.backfillPlan;

  // The run's time limit covers discovery and processing (it counts from the start of the job).
  // Discovery gets a third of it, between 45 s and 5 min: unbounded, slow AI link harvesting could use
  // a whole run and leave nothing to evaluate ("81 found, 0 ingested") or never end ("0 found").
  const maxRunTimeMinutes = backfillPlan
    ? backfillPlan.maxRunMinutes
    : config.maxRunTimeMinutes && config.maxRunTimeMinutes > 0
      ? config.maxRunTimeMinutes
      : 5;
  const MAX_JOB_EXECUTION_TIME_MS = maxRunTimeMinutes * 60 * 1000;
  jobControl.maxRunMs = MAX_JOB_EXECUTION_TIME_MS;
  const discoveryDeadline = jobStartTime + Math.min(Math.max(MAX_JOB_EXECUTION_TIME_MS / 3, 45_000), 5 * 60_000);
  const discoveryTimeLeft = () => discoveryDeadline - Date.now();
  // Asking the AI for an article list when a homepage yields no links costs a model call per source.
  const AI_HARVESTS_PER_JOB = 3;
  let aiHarvestsThisJob = 0;
  // AI scoring pauses for the rest of the run after this many failures in a row (no answer, errors).
  const AI_FAILURES_BEFORE_PAUSE = 3;
  let aiEvalFailuresInARow = 0;
  let aiEvalPaused = false;
  if (backfillPlan) {
    // A backfill walks one source's history: bounded by the plan, not the per-run caps.
    configuredMax = backfillPlan.maxArticles;
    maxPerDomain = backfillPlan.maxArticles;
  }
  const isTargeted = Boolean(targetedQuery);
  let pdfAttachments = 0;

  const initialJob: CrawlJob = {
    id: jobId,
    status: "running",
    triggerType,
    startedAt: new Date().toISOString(),
    completedAt: null,
    sourceCount: 0,
    discoveredCount: 0,
    evaluatedCount: 0,
    qualifiedCount: 0,
    ingestedCount: 0,
    duplicateCount: 0,
    failedCount: 0,
    rejectedCount: 0,
    updatedCount: 0,
    skippedCount: 0,
    newSourcesCount: 0,
    pdfGeneratedCount: 0,
    errorSummary: "",
    currentStage: "discovered",
  };

  if (isMongo) {
    try {
      await mongoInsertCrawlJob(initialJob);
    } catch (err) {
      console.warn("[mongodb] insert crawl job:", err);
    }
  } else {
    try {
      const sql = await getSql();
      await sql`
        update crawl_jobs
        set status = 'running', started_at = now()
        where id = ${jobId}
      `;
    } catch {
      /* ignore sql fallback error */
    }
  }

  console.log(`[crawler] STARTING job ${jobId} (trigger=${triggerType}, query="${targetedQuery || ""}")`);

  let discoveredCount = 0;
  let evaluatedCount = 0;
  let qualifiedCount = 0;
  let ingestedCount = 0;
  /** Reports stored by this run, for the AI analysis that follows it. */
  const ingestedReportIds: string[] = [];
  let duplicateCount = 0;
  let failedCount = 0;
  let rejectedCount = 0;
  let skippedCount = 0;
  let newSourcesCount = 0;
  let pdfGeneratedCount = 0;
  let translationsThisJob = 0;
  let translationMsThisJob = 0;
  let sources: SourceRecord[] = [];
  let jobFailed = false;
  let jobErrorSummary = "";
  let sql: Sql | null = null;

  try {
    try {
      sql = await getSql();
    } catch {
      /* ignore sql init fallback */
    }

    // Discovery can take minutes (feeds, sitemaps, homepages, search, the AI agent). Report what it is doing
    // and how much it has found as it goes, instead of showing "0 found" until it ends. Fire-and-forget,
    // throttled; a record that is no longer "running" (cancelled elsewhere) stops the job.
    let discoveryActivity = "Preparing discovery";
    let lastDiscoveryReportAt = 0;
    // Set once articles are being processed: links found then are reported with the processing progress.
    let discoveryPhaseOver = false;
    const reportDiscovery = (activity?: string, force = false) => {
      if (activity) discoveryActivity = activity;
      if (discoveryPhaseOver || !isMongoConfigured()) return;
      const now = Date.now();
      if (!force && now - lastDiscoveryReportAt < 2000) return;
      lastDiscoveryReportAt = now;
      void updateJobIfRunning(jobId, { discoveredCount, currentStage: "discovered", currentUrl: discoveryActivity }).then(
        (stillRunning) => {
          if (!stillRunning) jobControl.cancel = true;
        },
        () => {
          /* non-critical telemetry */
        },
      );
    };

    // Decide once whether AI can answer this run. A dead AI path (no provider key, no working sandbox)
    // is skipped up front: articles are qualified by the heuristic engine instead of each one waiting
    // out an agent timeout, which with the default AGY provider used up whole runs ("0 found").
    const aiWanted = config.agentDiscoveryEnabled !== false || Boolean(config.agentTaggingEnabled || config.agentApprovalEnabled);
    const ai: CrawlerAiAvailability = aiWanted
      ? await resolveCrawlerAiAvailability().catch((err: unknown) => ({
          usable: false,
          sandbox: false,
          detail: `AI availability check failed (${err instanceof Error ? err.message : String(err)})`,
        }))
      : { usable: false, sandbox: false, detail: "AI features are turned off in settings" };
    console.log(`[crawler] job ${jobId}: AI ${ai.usable ? "on" : "skipped"} (${ai.detail})`);
    // Translation is its own setting: it needs AI even when AI scoring and discovery are off, so it
    // checks for a provider on the first non-English report only.
    let translationAiCheck: Promise<CrawlerAiAvailability> | null = null;
    const translationAi = (): Promise<CrawlerAiAvailability> =>
      aiWanted
        ? Promise.resolve(ai)
        : (translationAiCheck ??= resolveCrawlerAiAvailability().catch((err: unknown) => ({
            usable: false,
            sandbox: false,
            detail: `AI availability check failed (${err instanceof Error ? err.message : String(err)})`,
          })));
    if (aiWanted && !ai.usable) {
      logger.agent(
        "UNAVAILABLE",
        `AI scoring skipped for this crawl: ${ai.detail}. Articles are qualified by the heuristic engine; add an AI provider API key in the Marketplace to enable AI scoring.`,
      );
    }
    if (isMongoConfigured()) {
      try {
        await ensureMongoIndexes();
      } catch {
        /* ignore index errors */
      }
    }

    // 1. Get enabled sources and merge updated SOURCE_SEED definitions
    const seedMap = new Map<string, SourceRecord>();
    for (const s of SOURCE_SEED) {
      seedMap.set(s.id, {
        ...s,
        feedUrl: s.feedUrl || `${s.homepageUrl.replace(/\/+$/, "")}/feed/`,
        lastIngestAt: null,
      });
    }

    if (isMongoConfigured()) {
      try {
        const allSources = await mongoListSources();
        for (const s of allSources) {
          const seed = seedMap.get(s.id);
          seedMap.set(s.id, {
            ...s,
            crawlPattern: s.crawlPattern || seed?.crawlPattern,
            feedUrl: seed?.feedUrl || s.feedUrl || `${s.homepageUrl.replace(/\/+$/, "")}/feed/`,
          });
        }
      } catch (err) {
        console.warn("[mongodb] list sources fallback:", err);
      }
    }

    // Structured connectors (STIX / GitHub / JSON) are synced by syncStructuredSource, not crawled.
    sources = Array.from(seedMap.values()).filter((s) => s.enabled !== false && !isStructuredSource(s));
    if (isMongoConfigured()) {
      try {
        await mongoSeedSources(sources);
      } catch {
        /* ignore seed errors */
      }
    }

    // Buffer for items discovered during initial source discovery before queue initialization
    const preHarvestedItems: FrontierItem[] = [];

    // Autonomous AI source discovery runs alongside the core discovery below (feeds, sitemaps,
    // homepages) within its own share of the discovery budget. It used to run first and, with a slow
    // model, used the whole budget before a single feed was read. New sources are saved for later runs;
    // report links it finds in time are crawled in this one.
    const aiDiscoveryDeadline = jobStartTime + Math.min(60_000, (discoveryDeadline - jobStartTime) / 2);
    let aiSourceDiscovery: Promise<void> = Promise.resolve();
    if (!jobControl.cancel && ai.usable && isMongoConfigured() && config.agentDiscoveryEnabled !== false && !runOptions.backfill && !runOptions.sourceIds?.length) {
      reportDiscovery("Asking the AI agent for new research sources", true);
      aiSourceDiscovery = (async () => {
        try {
          logger.agent(
            "DISCOVERY",
            "Launching autonomous CTI source discovery (Adversary Emulation Intelligence Skill)...",
            { model: sanitizeAgyModel(config.agentModel), timeout: `${config.agentTimeoutSeconds || 45}s` }
          );
          console.log(`[crawler] [AI AGENT] Running autonomous CTI source discovery (Adversary Emulation Intelligence Skill)...`);

          // Build known domain list to prevent duplicate discovery
          const knownDomains: string[] = [];
          for (const s of sources) {
            try {
              const h = new URL(s.homepageUrl).hostname.replace(/^www\./, "").toLowerCase();
              if (h) knownDomains.push(h);
            } catch {
              // Source with an invalid homepage URL contributes no domain.
            }
          }
          try {
            const existingDiscovered = await mongoListDiscoveredSources();
            for (const ds of existingDiscovered) {
              if (ds.domain) knownDomains.push(ds.domain.toLowerCase());
            }
          } catch (err) {
            console.warn("[crawler] could not load discovered sources for dedup; continuing with seed domains only:", err);
          }

          let safetyTimer: ReturnType<typeof setTimeout> | undefined;
          const agentResult = await Promise.race([
            runUnifiedSourceDiscovery({
              limit: 4,
              existingDomains: Array.from(new Set(knownDomains)),
              model: sanitizeAgyModel(config.agentModel),
              timeoutSeconds: config.agentTimeoutSeconds || 45,
              allowSandboxFallback: ai.sandbox,
            }),
            new Promise<Awaited<ReturnType<typeof runUnifiedSourceDiscovery>>>((resolve) => {
              safetyTimer = setTimeout(() => {
                console.warn("[crawler] AI Agent source discovery reached safety timeout, proceeding with core crawler sources");
                resolve({
                  success: false,
                  fallback: true,
                  providerId: "safety_timeout",
                  providerName: "Crawler Safety Watchdog",
                  sources: [],
                  error: "Discovery safety timeout exceeded",
                });
              }, Math.max(5_000, aiDiscoveryDeadline - Date.now()));
            }),
          ]);
          clearTimeout(safetyTimer);

          if (agentResult.sources && agentResult.sources.length > 0) {
            logger.agent(
              "DISCOVERED",
              `Discovered ${agentResult.sources.length} new high-value CTI research endpoints!`,
              agentResult.sources.map((s) => s.domain).join(", ")
            );
            console.log(`[crawler] [AI AGENT] Discovered ${agentResult.sources.length} new high-value CTI sources!`);
            for (const s of agentResult.sources) {
              if (
                !s.domain ||
                !isSafePublicUrlString(s.domain) ||
                (s.base_url && !isSafePublicUrlString(s.base_url)) ||
                (s.crawl_pattern && !isSafeCrawlPatternString(s.crawl_pattern))
              ) {
                logger.warn("SECURITY", `Skipping agent-discovered source with unsafe domain/URL: ${String(s.domain).slice(0, 120)}`);
                continue;
              }
              try {
                const created = await mongoCreateDiscoveredSource({
                  domain: s.domain,
                  name: s.source_name,
                  homepageUrl: s.base_url || `https://${s.domain}`,
                  crawlPattern: s.crawl_pattern,
                  parentSource: "AGY Autonomous Discovery",
                  trustScore: 80,
                  origin: "agent_discovery",
                  notes: s.why_crawl,
                  whyCrawl: s.why_crawl,
                  status: "discovered",
                  enabled: true,
                });
                if (created) {
                  newSourcesCount++;
                  logger.agent("REGISTER", `Registered new source endpoint: ${s.source_name}`, s.base_url || s.domain);
                  console.log(`[crawler] [AI AGENT] Registered new source endpoint: ${s.source_name} (${s.base_url || s.domain})`);

                  // Coordinated Domain Harvesting: report permalinks for the new domain, while the AI
                  // discovery budget and the run's harvest allowance last.
                  if (aiHarvestsThisJob >= AI_HARVESTS_PER_JOB || aiDiscoveryDeadline - Date.now() < 15_000) continue;
                  aiHarvestsThisJob++;
                  try {
                    const domainHarvest = await runUnifiedDomainResourceDiscovery({
                      domain: s.domain,
                      baseUrl: s.base_url || `https://${s.domain}`,
                      model: config.agentModel,
                      timeoutSeconds: Math.max(10, Math.min(config.agentTimeoutSeconds || 45, 30, Math.floor((aiDiscoveryDeadline - Date.now()) / 1000) - 3)),
                      allowSandboxFallback: ai.sandbox,
                    });
                    if (domainHarvest.resources && domainHarvest.resources.length > 0) {
                      logger.agent("HARVEST", `Extracted ${domainHarvest.resources.length} coordinated resources from newly discovered domain ${s.domain}`);
                      for (const dr of domainHarvest.resources) {
                        try {
                          const canonical = canonicalizeUrl(dr.url);
                          preHarvestedItems.push({
                            url: dr.url,
                            canonicalUrl: canonical,
                            depth: 0,
                            priorityScore: dr.isHighValue ? 0.98 : 0.90,
                            parentUrl: s.base_url || `https://${s.domain}`,
                            parentSource: s.source_name,
                            discoveryPath: [s.base_url || `https://${s.domain}`, dr.url],
                            discoveryMethod: "agent_discovery",
                            sourceId: created.id || s.domain,
                            sourceSlug: s.domain.replace(/[^a-z0-9]/gi, "-").toLowerCase(),
                            publisher: s.source_name,
                            domain: s.domain,
                            title: dr.title,
                          });
                        } catch {
                          /* skip */
                        }
                      }
                    }
                  } catch (harvestErr) {
                    console.warn(`[crawler][agent] Domain harvest error for ${s.domain}:`, (harvestErr as Error).message);
                  }
                }
              } catch (err) {
                logger.warn("AI AGENT", `Error saving discovered source ${s.domain}: ${(err as Error).message}`);
              }
            }
          } else if (agentResult.error) {
            logger.agent("NOTE", `Discovery note: ${agentResult.error} — proceeding with core crawler sources.`);
            console.log(`[crawler] [AI AGENT] Discovery note: ${agentResult.error} — proceeding with core crawler sources.`);
          } else {
            logger.agent(
              "COMPLETED",
              `Source discovery run finished — candidate domains (${agentResult.candidateDomains?.join(", ") || "none"}) already present in registry. Proceeding with crawl.`
            );
          }
        } catch (agentErr) {
          logger.agent("FAILSAFE", `Autonomous discovery skipped (offline / timed out) — proceeding with core crawler: ${(agentErr as Error).message}`);
          console.warn(`[crawler] [AI AGENT] Autonomous discovery skipped (offline / timed out) — proceeding with core crawler:`, (agentErr as Error).message);
        }
      })();
    }

    // Merge enabled Discovered Sources if enabled in crawl config
    if (isMongoConfigured() && config.agentCrawlSourcesEnabled !== false) {
      try {
        const discoveredSourcesList = await mongoListDiscoveredSources();
        for (const ds of discoveredSourcesList) {
          if (ds.enabled !== false && ds.status !== "rejected" && ds.status !== "ignored") {
            const domain = ds.domain;
            if (!domain || !isSafePublicUrlString(domain)) {
              logger.warn("SECURITY", `Skipping discovered source with unsafe domain: ${String(domain).slice(0, 120)}`);
              continue;
            }
            if (ds.crawlPattern && !isSafeCrawlPatternString(ds.crawlPattern)) {
              logger.warn("SECURITY", `Skipping discovered source ${domain}: unsafe crawl pattern ${ds.crawlPattern.slice(0, 160)}`);
              continue;
            }
            if (ds.homepageUrl && !isSafePublicUrlString(ds.homepageUrl)) {
              logger.warn("SECURITY", `Skipping discovered source ${domain}: unsafe homepage URL ${ds.homepageUrl.slice(0, 160)}`);
              continue;
            }
            const slug = domain.replace(/[^a-z0-9]/gi, "-").toLowerCase();
            // Multi-entry patterns ("a/*, b/*") derive their root from the first entry.
            const firstPattern = ds.crawlPattern
              ? ds.crawlPattern.split(/[,;\n]+/).map((p) => p.trim()).find((p) => p && p !== "*")
              : undefined;
            const rootUrl = firstPattern ? firstPattern.replace(/\/\*+$/, "") : ds.homepageUrl || `https://${domain}`;
            const homepageUrl = rootUrl.startsWith("http") ? rootUrl : `https://${rootUrl}`;
            if (!validateSafePublicUrl(homepageUrl).safe) {
              logger.warn("SECURITY", `Skipping discovered source ${domain}: derived homepage URL is unsafe (${homepageUrl.slice(0, 160)})`);
              continue;
            }
            const archiveRoot = firstPattern ? firstPattern.replace(/\/\*+$/, "") : undefined;
            const researchArchives =
              archiveRoot && validateSafePublicUrl(archiveRoot).safe ? [archiveRoot] : undefined;
            sources.push({
              id: ds.id,
              name: ds.name || domain,
              slug,
              category: "discovered_source",
              homepageUrl,
              crawlPattern: ds.crawlPattern,
              feedUrl: undefined,
              researchArchives,
              enabled: true,
              priority: ds.trustScore ? Math.round(ds.trustScore / 10) : 6,
              trustLevel: ds.trustScore >= 70 ? "reputable" : "community",
              notes: ds.notes || ds.whyCrawl || "",
              lastIngestAt: null,
              isCurated: false,
              isDiscovered: true,
              origin: ds.origin === "agent_discovery" ? "agent_discovery" : "crawler_outlink",
            });
          }
        }
      } catch (err) {
        console.warn("[crawler] Error merging discovered sources into crawl job:", err);
      }
    }

    // Apply whitelist if configured
    if (config.activeSources && config.activeSources.length > 0 && !runOptions.backfill) {
      sources = sources.filter((s) => config.activeSources.includes(s.id) || config.activeSources.includes(s.slug));
    }

    // Per-source schedules and failure backoff (scheduled runs crawl only due sources).
    sources = collector.selectSources(sources, runOptions);
    if (collector.funnel.sourcesSkipped.length) {
      logger.info("collector", `Skipped ${collector.funnel.sourcesSkipped.length} source(s): ${collector.funnel.sourcesSkipped.slice(0, 5).map((s) => `${s.name} (${s.reason})`).join("; ")}`);
    }

    if (isMongoConfigured()) {
      try {
        await mongoUpdateCrawlJob(jobId, { sourceCount: sources.length });
      } catch {
        /* ignore */
      }
    }

    try {
      if (sql) await sql`update crawl_jobs set source_count = ${sources.length} where id = ${jobId}`;
    } catch {
      /* ignore sql fallback error */
    }

    // 2. Query existing storage for smart deduplication
    const storedCanonicalUrls = new Set<string>();
    const storedHashes = new Set<string>();
    // Near-duplicate index. `simhash` is computeReportSimHash(extractedText) stored at insert;
    // older records without it fall back to a hash of their stored excerpt (`fromExcerpt`),
    // which is compared against the candidate's excerpt computed the same way.
    const storedSimhashes: Array<{ id: string; simhash: string; title: string; fromExcerpt: boolean }> = [];

    if (isMongoConfigured()) {
      try {
        const existingReports = await mongoGetExistingReportsDedupIndex();
        for (const r of existingReports) {
          if (r.canonicalUrl && (r.wordCount === undefined || r.wordCount >= 500)) {
            storedCanonicalUrls.add(r.canonicalUrl);
          }
          if (r.textHash && (r.wordCount === undefined || r.wordCount >= 500)) {
            storedHashes.add(r.textHash);
          }
          if (r.simhash && /^[0-9a-f]{16}$/.test(r.simhash)) {
            storedSimhashes.push({ id: r.id, simhash: r.simhash, title: r.title || "", fromExcerpt: false });
          } else if (r.excerpt && r.excerpt.length >= 80) {
            storedSimhashes.push({
              id: r.id,
              simhash: computeReportSimHash(r.excerpt),
              title: r.title || "",
              fromExcerpt: true,
            });
          }
        }
      } catch {
        /* fallback to sql */
      }
    }

    try {
      if (sql) {
        const sqlExisting = await sql<{ canonical_url: string; text_hash: string }>`
          select canonical_url, text_hash from reports
        `;
        for (const r of sqlExisting) {
          if (r.canonical_url) storedCanonicalUrls.add(r.canonical_url);
          if (r.text_hash) storedHashes.add(r.text_hash);
        }
      }
    } catch {
      /* ignore sql fallback */
    }

    // 3. Initialize the Priority Frontier Queue & Scoped Endpoint Pattern Map
    const frontierQueue: FrontierItem[] = [];
    const enqueuedUrls = new Set<string>();
    const domainVisitCounts = new Map<string, number>();

    // Index all active crawl patterns by sourceId and domain
    const sourcePatternMap = new Map<string, string>();
    for (const s of sources) {
      if (s.crawlPattern) {
        sourcePatternMap.set(s.id, s.crawlPattern);
        try {
          const host = new URL(s.homepageUrl).hostname.toLowerCase().replace(/^www\./, "");
          sourcePatternMap.set(host, s.crawlPattern);
        } catch {
          // Invalid homepage URL: the pattern stays keyed by source id only.
        }
      }
    }

    const enqueue = (item: FrontierItem): boolean => {
      // One canonical form for every discovery path (outlinks come from discovery.ts's older stripper).
      try {
        item.canonicalUrl = canonicalizeUrl(item.canonicalUrl || item.url);
      } catch {
        return false;
      }
      if (enqueuedUrls.has(item.canonicalUrl)) return false;
      if (!validateSafePublicUrl(item.canonicalUrl).safe) return false;

      // Candidate Resource Gate: Filter out index, category roots, podcasts, webinars, and sitemaps early
      const isFeed = item.discoveryMethod === "rss_feed";
      const candCheck = isCandidateResourceUrl(item.canonicalUrl, isFeed);
      if (!candCheck.isResource) {
        return false;
      }

      // Strict Scoped Research Endpoint Guard:
      // If the resource belongs to a source with a defined crawlPattern, enforce strict path scoping.
      // This eliminates false data, marketing homepages, corporate sales, careers, and pricing pages.
      const itemDomain = item.domain.toLowerCase().replace(/^www\./, "");
      const pattern = (item.sourceId ? sourcePatternMap.get(item.sourceId) : undefined) || sourcePatternMap.get(itemDomain);
      if (pattern && !matchesCrawlPattern(item.canonicalUrl, pattern)) {
        return false;
      }

      // Relevance pre-score from what the listing tells us; it orders the frontier and gates the fetch.
      if (!item.relevance) {
        item.relevance = collector.prescore({
          title: item.title,
          summary: item.summary ?? item.preloadedText?.slice(0, 1200),
          url: item.canonicalUrl,
          sourceId: item.sourceId,
          targeted: isTargeted && item.discoveryMethod === "search_expansion",
        });
      }
      item.priorityScore = Math.max(0, Math.min(1.2, item.priorityScore + (item.relevance.score - 0.5) * 0.3));

      enqueuedUrls.add(item.canonicalUrl);
      frontierQueue.push(item);
      discoveredCount++;
      reportDiscovery();
      return true;
    };

    // Enqueue any items extracted during early autonomous source discovery
    for (const phi of preHarvestedItems.splice(0)) {
      enqueue(phi);
    }

    // Per-source feed outcome: drives feed autodiscovery, sitemap use and listing pagination.
    const feedOutcome = new Map<string, { status: "ok" | "not_modified" | "error" | "none"; items: number }>();
    const SHORT_FEED_ITEMS = 8;
    const enqueueFeedItems = (source: SourceRecord, feedTarget: string, xml: string): number => {
      let added = 0;
      for (const item of parseRssOrAtomXml(xml)) {
        try {
          const canonical = canonicalizeUrl(item.url);
          const domain = new URL(canonical).hostname.replace(/^www\./, "");
          const ok = enqueue({
            url: item.url,
            canonicalUrl: canonical,
            depth: 0,
            priorityScore: 0.9,
            parentUrl: feedTarget,
            parentSource: source.name,
            discoveryPath: [source.homepageUrl, item.url],
            discoveryMethod: "rss_feed",
            sourceId: source.id,
            sourceSlug: source.slug,
            publisher: source.name,
            domain,
            title: item.title,
            summary: item.summary,
            // Clean structured text from the feed content (never the raw HTML).
            preloadedText: item.contentText || item.summary,
            publishedAt: item.publishedAt ? item.publishedAt.slice(0, 10) : null,
            lastmodHint: item.publishedAt,
          });
          if (ok) added++;
        } catch {
          /* skip invalid */
        }
      }
      return added;
    };

    // Phase A: Seed Continuous Feeds (RSS & Atom) with conditional GET (ETag / Last-Modified)
    if (config.rssDiscovery !== false) {
      reportDiscovery(`Reading RSS/Atom feeds of ${sources.filter((x) => x.enabled).length} sources`, true);
      await settleWithin(Promise.allSettled(
        sources.map(async (source) => {
          if (!source.enabled || jobControl.cancel) return;
          const feedTarget = source.feedUrl || `${source.homepageUrl.replace(/\/+$/, "")}/feed/`;
          // SSRF-guarded conditional fetch: DNS-validated on every hop, size-capped; 304 means nothing new.
          const res = await collector.fetchSourceDocument(source.id, feedTarget, "feed", {
            timeoutMs: 4500,
            accept: "application/rss+xml, application/atom+xml, text/xml, */*",
            forceFull: Boolean(backfillPlan),
          });
          if (res.status !== "ok") {
            feedOutcome.set(source.id, { status: res.status === "error" ? "error" : "not_modified", items: 0 });
            return;
          }
          const items = parseRssOrAtomXml(res.body).length;
          feedOutcome.set(source.id, { status: items > 0 ? "ok" : "error", items });
          if (items === 0) collector.sourceReachable(source.id, true, `feed ${feedTarget.slice(0, 120)}: no RSS/Atom items`);
          enqueueFeedItems(source, feedTarget, res.body);
        }),
      ), Math.max(20_000, Math.min(discoveryTimeLeft(), 90_000)));
    }

    // Phase A2: Sitemaps (sitemap.xml / sitemap index with lastmod). Used for backfills, for sources whose
    // feed is short, missing or failing, and on wide crawls. Only entries modified since the source's last
    // crawl (or inside the backfill window) are enqueued.
    if (!jobControl.cancel) reportDiscovery("Reading sitemaps", true);
    const sitemapSources = sources.filter((source) => {
      if (!source.enabled) return false;
      if (backfillPlan) return source.id === backfillPlan.sourceId;
      if (!source.sitemapUrl) return false;
      const fo = feedOutcome.get(source.id);
      return breadth === "wide" || !fo || fo.status === "error" || (fo.status === "ok" && fo.items < SHORT_FEED_ITEMS);
    });
    await settleWithin(Promise.allSettled(
      sitemapSources.map(async (source) => {
        if (jobControl.cancel) return;
        const roots = source.sitemapUrl ? [source.sitemapUrl] : await collector.robotsSitemaps(source.homepageUrl);
        if (roots.length === 0 && backfillPlan) roots.push(`${new URL(source.homepageUrl).origin}/sitemap.xml`);
        const sinceIso =
          backfillPlan?.sinceIso ??
          (collector.lastCrawledAt(source.id) || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString());
        const perSourceCap = backfillPlan ? backfillPlan.maxArticles : 25;
        const maxChildren = backfillPlan ? backfillPlan.maxChildSitemaps : 2;
        let added = 0;
        for (const root of roots.slice(0, 2)) {
          if (added >= perSourceCap) break;
          const res = await collector.fetchSourceDocument(source.id, root, "sitemap", { timeoutMs: 8000, maxBytes: 8_000_000, accept: "application/xml,text/xml,*/*", forceFull: Boolean(backfillPlan) });
          if (res.status !== "ok") continue;
          let parsed = parseSitemapXml(res.body);
          const childUrls: string[] = [];
          if (parsed.type === "sitemapindex") {
            childUrls.push(...rankChildSitemaps(parsed.entries, { sinceIso, limit: maxChildren }).map((e) => e.loc));
            parsed = { type: "urlset", entries: [] };
          }
          const entrySets = [parsed.entries];
          for (const child of childUrls) {
            const cr = await collector.fetchSourceDocument(source.id, child, "sitemap", { timeoutMs: 8000, maxBytes: 8_000_000, accept: "application/xml,text/xml,*/*", forceFull: Boolean(backfillPlan) });
            if (cr.status === "ok") entrySets.push(parseSitemapXml(cr.body).entries);
          }
          for (const entries of entrySets) {
            for (const e of filterSitemapEntries(entries, { sinceIso, limit: perSourceCap - added })) {
              try {
                const canonical = canonicalizeUrl(e.loc);
                const ok = enqueue({
                  url: e.loc,
                  canonicalUrl: canonical,
                  depth: 0,
                  priorityScore: backfillPlan ? 0.86 : 0.8,
                  parentUrl: root,
                  parentSource: source.name,
                  discoveryPath: [source.homepageUrl, root, e.loc],
                  discoveryMethod: "sitemap",
                  sourceId: source.id,
                  sourceSlug: source.slug,
                  publisher: source.name,
                  domain: new URL(canonical).hostname.replace(/^www\./, ""),
                  title: titleFromSlug(e.loc),
                  lastmodHint: e.lastmod,
                });
                if (ok) {
                  added++;
                  collector.funnel.sitemapUrls++;
                }
              } catch {
                /* skip invalid */
              }
            }
          }
        }
      }),
    ), Math.max(15_000, Math.min(discoveryTimeLeft(), 60_000)));

    // Phase B: Seed Homepage Permalinks
    if (config.htmlDiscovery !== false) {
      if (!jobControl.cancel) reportDiscovery("Scanning source homepages for new reports", true);
      await settleWithin(Promise.allSettled(
        sources.map(async (source) => {
          if (!source.enabled || jobControl.cancel) return;
          try {
            const fo = feedOutcome.get(source.id);
            const feedWeak = !fo || fo.status === "error" || (fo.status === "ok" && fo.items < SHORT_FEED_ITEMS);
            // SSRF-guarded conditional fetch; read in full when the feed is weak (needed for feed autodiscovery).
            const homeRes = await collector.fetchSourceDocument(source.id, source.homepageUrl, "listing", {
              timeoutMs: 4500,
              accept: "text/html,application/xhtml+xml,text/plain",
              forceFull: feedWeak || Boolean(backfillPlan),
            });
            const html = homeRes.status === "ok" ? homeRes.body : null;

            // Feed autodiscovery (<link rel="alternate">) when the configured feed is missing, failing or short.
            if (html !== null && feedWeak && config.rssDiscovery !== false) {
              const configured = (source.feedUrl || "").replace(/\/+$/, "");
              const alt = discoverFeedLinks(html, source.homepageUrl).find((f) => f.url.replace(/\/+$/, "") !== configured);
              if (alt) {
                const ar = await collector.fetchSourceDocument(source.id, alt.url, "feed", { timeoutMs: 4500, accept: "application/rss+xml, application/atom+xml, text/xml, */*" });
                if (ar.status === "ok" && enqueueFeedItems(source, alt.url, ar.body) > 0) {
                  collector.funnel.feedsAutodiscovered++;
                  logger.info("collector", `Autodiscovered feed for ${source.name}: ${alt.url}`);
                }
              }
            }

            if (html !== null) {
              const { discoveredLinks, newDiscoveredSources, graphEdges } = extractOutlinksAndCitations(
                html,
                source.homepageUrl,
                {
                  sourceId: source.id,
                  publisher: source.name,
                  discoveryMethod: "crawl_source",
                  depth: 1,
                  allowExternalDomains: config.allowExternalDomains !== false,
                  domainAllowlist: config.domainAllowlist,
                  domainBlocklist: config.domainBlocklist,
                },
              );

              // Persist newly discovered sources and edges into MongoDB
              if (isMongoConfigured()) {
                for (const src of newDiscoveredSources) {
                  await mongoInsertDiscoveredSource(src);
                  newSourcesCount++;
                }
                if (graphEdges.length > 0) {
                  await mongoInsertGraphEdgesBatch(graphEdges.map((edge) => ({ ...edge, jobId })));
                }
              }

              for (const link of discoveredLinks) {
                // Filter out non-technical site navigation, legal, and boilerplate links
                if (/privacy|terms|contact|about|cookie|careers|login|signin|register|legal|jobs|pricing|subscribe|donate/i.test(link.canonicalUrl)) {
                  continue;
                }
                enqueue({
                  url: link.url,
                  canonicalUrl: link.canonicalUrl,
                  depth: 1,
                  priorityScore: link.priorityScore,
                  parentUrl: source.homepageUrl,
                  parentSource: source.name,
                  discoveryPath: link.discoveryPath,
                  discoveryMethod: link.isExternalDomain ? "outlink_citation" : "seed_source",
                  sourceId: source.id,
                  sourceSlug: source.slug,
                  publisher: link.publisher || source.name,
                  domain: link.domain,
                  title: link.title,
                });
              }

              // Coordinated Domain Harvesting: Fallback AI extraction ONLY if standard regex extracted 0 links
              if (
                ai.usable &&
                config.agentDiscoveryEnabled !== false &&
                html &&
                discoveredLinks.length === 0 &&
                aiHarvestsThisJob < AI_HARVESTS_PER_JOB &&
                discoveryTimeLeft() > 30_000
              ) {
                aiHarvestsThisJob++;
                try {
                  const sHost = new URL(source.homepageUrl).hostname.replace(/^www\./, "").toLowerCase();
                  const domainHarvest = await runUnifiedDomainResourceDiscovery({
                    domain: sHost,
                    baseUrl: source.homepageUrl,
                    htmlSnippet: html.slice(0, 4500),
                    model: config.agentModel,
                    timeoutSeconds: Math.max(10, Math.min(config.agentTimeoutSeconds || 45, 25, Math.floor(discoveryTimeLeft() / 1000) - 5)),
                    allowSandboxFallback: ai.sandbox,
                  });
                  if (domainHarvest.resources && domainHarvest.resources.length > 0) {
                    for (const dr of domainHarvest.resources) {
                      try {
                        const canonical = canonicalizeUrl(dr.url);
                        enqueue({
                          url: dr.url,
                          canonicalUrl: canonical,
                          depth: 0,
                          priorityScore: dr.isHighValue ? 0.96 : 0.88,
                          parentUrl: source.homepageUrl,
                          parentSource: source.name,
                          discoveryPath: [source.homepageUrl, dr.url],
                          discoveryMethod: "agent_discovery",
                          sourceId: source.id,
                          sourceSlug: source.slug,
                          publisher: source.name,
                          domain: new URL(canonical).hostname.replace(/^www\./, ""),
                          title: dr.title,
                        });
                      } catch {
                        /* skip */
                      }
                    }
                  }
                } catch {
                  /* ignore agent harvest error */
                }
              }

              // Deep Source Exploration: Crawl dedicated research archives if configured
              if (source.researchArchives && source.researchArchives.length > 0) {
                for (const archiveUrl of source.researchArchives) {
                  if (archiveUrl === source.homepageUrl) continue;
                  if (discoveryTimeLeft() <= 0) break;
                  try {
                    const archRes = await collector.fetchSourceDocument(source.id, archiveUrl, "listing", {
                      timeoutMs: 8000,
                      accept: "text/html,application/xhtml+xml,text/plain",
                      forceFull: Boolean(backfillPlan),
                    });
                    const archHtml = archRes.status === "ok" ? archRes.body : null;
                    if (archHtml !== null) {
                      const archLinks = extractOutlinksAndCitations(archHtml, archiveUrl, {
                        sourceId: source.id,
                        publisher: source.name,
                        discoveryMethod: "crawl_source",
                        depth: 1,
                        allowExternalDomains: config.allowExternalDomains !== false,
                        domainAllowlist: config.domainAllowlist,
                        domainBlocklist: config.domainBlocklist,
                      });
                      for (const l of archLinks.discoveredLinks) {
                        enqueue({
                          url: l.url,
                          canonicalUrl: l.canonicalUrl,
                          depth: 1,
                          priorityScore: l.priorityScore + 0.05,
                          parentUrl: archiveUrl,
                          parentSource: source.name,
                          discoveryPath: l.discoveryPath,
                          discoveryMethod: "seed_source",
                          sourceId: source.id,
                          sourceSlug: source.slug,
                          publisher: l.publisher || source.name,
                          domain: l.domain,
                          title: l.title,
                        });
                      }
                    }
                  } catch {
                    /* ignore */
                  }
                }
              }

              // Listing / archive pagination: research hubs whose feed is short are walked past page 1
              // (page pattern, rel=next or "Older posts"); a backfill walks up to its page budget. Stops at
              // the first page that adds no new candidates.
              const shortFeed = feedWeak;
              const maxPages = backfillPlan ? backfillPlan.maxListingPages : shortFeed ? 4 : breadth === "wide" || maxDepth >= 3 ? 2 : 1;
              const listingStart = source.researchArchives?.[0] || source.homepageUrl;
              if (maxPages >= 2 && (source.paginationPattern || shortFeed || backfillPlan)) {
                const queue = source.paginationPattern ? paginationUrls(source.paginationPattern, 2, maxPages) : [];
                let pageUrl: string | null = queue.shift() ?? null;
                let prevHtml = html;
                let prevUrl = listingStart;
                if (!pageUrl && prevHtml) pageUrl = findNextPageUrl(prevHtml, prevUrl);
                for (let page = 2; pageUrl && page <= maxPages && discoveryTimeLeft() > 0; page++) {
                  const pr = await collector.fetchSourceDocument(source.id, pageUrl, "listing", { timeoutMs: 8000, accept: "text/html,application/xhtml+xml,text/plain", forceFull: Boolean(backfillPlan) });
                  if (pr.status !== "ok") break;
                  collector.funnel.listingPages++;
                  const pLinks = extractOutlinksAndCitations(pr.body, pageUrl, {
                    sourceId: source.id,
                    publisher: source.name,
                    discoveryMethod: "crawl_source",
                    depth: 1,
                    allowExternalDomains: false,
                  });
                  let added = 0;
                  for (const l of pLinks.discoveredLinks) {
                    if (l.isExternalDomain) continue;
                    if (
                      enqueue({
                        url: l.url,
                        canonicalUrl: l.canonicalUrl,
                        depth: 1,
                        priorityScore: l.priorityScore,
                        parentUrl: pageUrl,
                        parentSource: source.name,
                        discoveryPath: l.discoveryPath,
                        discoveryMethod: "seed_source",
                        sourceId: source.id,
                        sourceSlug: source.slug,
                        publisher: l.publisher || source.name,
                        domain: l.domain,
                        title: l.title,
                      })
                    )
                      added++;
                  }
                  if (added === 0) break;
                  prevHtml = pr.body;
                  prevUrl = pageUrl;
                  pageUrl = source.paginationPattern ? queue.shift() ?? null : findNextPageUrl(prevHtml, prevUrl);
                }
              }
            }
          } catch {
            /* silent */
          }
        }),
      ), Math.max(30_000, discoveryTimeLeft()));
    }

    // Phase C: web search. A targeted hunt searches its own query; otherwise the analyst's keyword
    // phrases (rotating) and the research taxonomy (./research-taxonomy), thinnest categories first.
    if (config.searchDiscovery !== false || targetedQuery) {
      if (!jobControl.cancel) reportDiscovery("Searching the web for related reports", true);
      const research = normalizeResearchDiscovery(config.researchDiscovery);
      let counts: Partial<Record<ResearchCategoryId, number>> | undefined;
      if (!targetedQuery && research.enabled && isMongoConfigured()) {
        const coverage = await settleWithin(mongoResearchCoverage(), 4000);
        if (coverage.status === "fulfilled") counts = coverage.value.counts;
      }
      const plan = buildSearchPlan({
        targetedQuery,
        keywords: config.keywords,
        research,
        // Minutes since the epoch: every run rotates to different keywords and queries.
        round: Math.floor(Date.now() / 60_000),
        counts,
      });
      if (plan.length) logger.crawler("SEARCH", `Web search plan: ${plan.map((p) => p.query).join(" · ")}`, { jobId, searches: plan.length });

      const blocked = ["duckduckgo.com", "bing.com", "google.com", "youtube.com", "wikipedia.org", "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com"];
      // Engines in order (./web-search searchProviders): configured APIs first, then DuckDuckGo.
      // An engine that challenges or fails is skipped for the rest of the run.
      const engines = searchProviders(process.env);
      const disabledEngines = new Set<SearchProvider["id"]>();
      const searchWith = async (engine: SearchProvider, query: string): Promise<SearchResult[] | "challenged" | null> => {
        if (engine.id === "duckduckgo") {
          const html = await safeFetchText(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, {
            timeoutMs: 6000,
            maxBytes: 3_000_000,
            userAgent:
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            acceptHeader: "text/html,application/xhtml+xml,text/plain",
          });
          if (html === null) return null;
          return isSearchChallenge(html) ? "challenged" : parseDuckDuckGoHtml(html);
        }
        // Configured by the operator (a self-hosted SearXNG may be on a private address): plain fetch.
        const url =
          engine.id === "searxng"
            ? `${process.env.AIE_SEARXNG_URL!.trim().replace(/\/+$/, "")}/search?q=${encodeURIComponent(query)}&format=json`
            : `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=20`;
        const res = await fetch(url, {
          headers: { Accept: "application/json", ...(engine.id === "brave" ? { "X-Subscription-Token": process.env.BRAVE_SEARCH_API_KEY!.trim() } : {}) },
          signal: AbortSignal.timeout(8000),
        });
        if (res.status === 429 || res.status === 403) return "challenged";
        if (!res.ok) return null;
        const body = await res.json();
        return engine.id === "searxng" ? parseSearxngJson(body) : parseBraveJson(body);
      };
      let searchCandidates = 0;
      if (!engines.length && plan.length) logger.crawler("SEARCH", "Web search is off: no search engine is configured (AIE_DISABLE_DUCKDUCKGO=1 and no AIE_SEARXNG_URL or BRAVE_SEARCH_API_KEY)", { jobId });
      for (const [i, step] of plan.entries()) {
        if (jobControl.cancel || discoveryTimeLeft() <= 0) break;
        const usable = engines.filter((e) => !disabledEngines.has(e.id));
        if (!usable.length) break;
        if (i > 0) await new Promise((r) => setTimeout(r, Math.min(1500, Math.max(300, config.rateLimitMs || 0))));
        let results: SearchResult[] | null = null;
        let engineUsed = "";
        for (const engine of usable) {
          try {
            const r = await searchWith(engine, step.query);
            if (r === "challenged") {
              disabledEngines.add(engine.id);
              logger.crawler("SEARCH", `${engine.label} refused automated searches (bot check or rate limit); not used for the rest of this run`, { jobId });
              continue;
            }
            if (r === null) {
              logger.crawler("SEARCH", `"${step.query}": no response from ${engine.label}`, { jobId });
              continue;
            }
            results = r;
            engineUsed = engine.label;
            break;
          } catch (err) {
            logger.crawler("SEARCH", `"${step.query}": ${engine.label} failed (${err instanceof Error ? err.message : String(err)})`, { jobId });
          }
        }
        if (!results) continue;
        let kept = 0;
        for (const result of results) {
          try {
            const domain = new URL(result.url).hostname.toLowerCase().replace(/^www\./, "");
            if (blocked.some((b) => domain === b || domain.endsWith(`.${b}`))) continue;
            if (!isSafePublicUrlString(result.url)) continue;
            const check = isCandidateResourceUrl(result.url);
            if (!(check.isResource || /\.pdf(?:$|\?)/i.test(result.url) || /cve|threat|attack|ransomware|malware|incident|advisory|report/i.test(result.url))) continue;
            const added = enqueue({
              url: result.url,
              canonicalUrl: canonicalizeUrl(result.url),
              depth: 0,
              priorityScore: step.origin === "targeted" ? 0.99 : 0.9,
              parentUrl: null,
              parentSource: `Web search: ${step.query}`,
              discoveryPath: [result.url],
              discoveryMethod: "search_expansion",
              sourceId: "src_web_search",
              publisher: domain,
              domain,
              title: result.title || result.url.split("/").filter(Boolean).pop()?.replace(/[-_]/g, " ") || step.query,
              summary: result.snippet || undefined,
              discoveryQuery: step.query,
              researchCategory: step.category,
            });
            if (added) kept++;
          } catch {
            /* skip an invalid URL */
          }
        }
        searchCandidates += kept;
        logger.crawler("SEARCH", `"${step.query}" (${engineUsed}): ${results.length} result${results.length === 1 ? "" : "s"}, ${kept} new candidate${kept === 1 ? "" : "s"}`, { jobId, category: step.category ?? step.origin });
      }

      // AI-assisted discovery (./ai-report-discovery): when search brings too few new candidates,
      // the AI provider suggests specific recent reports (searching the web itself where it can)
      // and new publishers. Every URL still goes through the normal fetch and quality gates.
      if (
        searchCandidates < 5 &&
        plan.length &&
        !jobControl.cancel &&
        ai.usable &&
        config.agentDiscoveryEnabled !== false &&
        !runOptions.backfill &&
        discoveryTimeLeft() > 30_000
      ) {
        reportDiscovery("Asking the AI agent for recent reports", true);
        const knownDomains = Array.from(
          new Set(
            sources
              .map((src) => {
                try {
                  return new URL(src.homepageUrl).hostname.toLowerCase().replace(/^www\./, "");
                } catch {
                  return "";
                }
              })
              .filter(Boolean),
          ),
        );
        const since = new Date(Date.now() - 90 * 86_400_000).toISOString().slice(0, 10);
        const found = await settleWithin(
          runUnifiedReportDiscovery({
            topics: plan.map((p) => ({ query: p.query, category: p.category })),
            since,
            knownDomains,
            max: 20,
            timeoutSeconds: Math.max(45, Math.min(config.agentTimeoutSeconds || 90, 180, Math.floor(discoveryTimeLeft() / 1000) - 10)),
          }),
          Math.max(30_000, discoveryTimeLeft()),
        );
        if (found.status !== "fulfilled") {
          logger.agent("DISCOVERY", "AI report discovery did not answer in time");
        } else if (found.value.error) {
          logger.agent("DISCOVERY", `AI report discovery failed: ${found.value.error}`, found.value.provider);
        } else {
          const { reports, sources: newSources, dropped, provider, webSearch } = found.value;
          let kept = 0;
          for (const r of reports) {
            if (!isSafePublicUrlString(r.url)) continue;
            try {
              const domain = new URL(r.url).hostname.toLowerCase().replace(/^www\./, "");
              const added = enqueue({
                url: r.url,
                canonicalUrl: canonicalizeUrl(r.url),
                depth: 0,
                priorityScore: 0.92,
                parentUrl: null,
                parentSource: `AI discovery (${provider})`,
                discoveryPath: [r.url],
                discoveryMethod: "agent_discovery",
                sourceId: "src_web_search",
                publisher: r.publisher || domain,
                domain,
                title: r.title || r.url.split("/").filter(Boolean).pop()?.replace(/[-_]/g, " ") || r.url,
                summary: r.why || undefined,
                discoveryQuery: plan.find((p) => p.category && p.category === r.category)?.query,
                researchCategory: plan.find((p) => p.category && p.category === r.category)?.category,
              });
              if (added) kept++;
            } catch {
              /* skip an invalid URL */
            }
          }
          let registered = 0;
          if (isMongoConfigured()) {
            for (const src of newSources) {
              if (!isSafePublicUrlString(`https://${src.domain}`)) continue;
              try {
                await mongoCreateDiscoveredSource({
                  domain: src.domain,
                  name: src.name,
                  homepageUrl: `https://${src.domain}`,
                  parentSource: `AI discovery (${provider})`,
                  trustScore: 70,
                  origin: "agent_discovery",
                  notes: src.why,
                  whyCrawl: src.why,
                  status: "discovered",
                  enabled: true,
                });
                registered++;
              } catch {
                /* a source that cannot be saved is skipped */
              }
            }
          }
          logger.agent(
            "DISCOVERY",
            `AI report discovery (${provider}${webSearch ? ", web search" : ", from knowledge"}): ${reports.length} report${reports.length === 1 ? "" : "s"} suggested, ${kept} new candidate${kept === 1 ? "" : "s"}, ${dropped} dropped, ${registered} new source${registered === 1 ? "" : "s"} registered`,
          );
        }
      }

      // Also enqueue curated knowledge pool
      for (const item of DISCOVERY_KNOWLEDGE_POOL) {
        try {
          const canonical = canonicalizeUrl(item.url);
          const domain = new URL(canonical).hostname.replace(/^www\./, "");
          const matchingSource = sources.find((s) => s.slug === item.sourceSlug) || sources[0];

          enqueue({
            url: item.url,
            canonicalUrl: canonical,
            depth: 0,
            priorityScore: 0.95,
            parentUrl: null,
            parentSource: matchingSource?.name || "Verified Intelligence Pool",
            discoveryPath: [item.url],
            discoveryMethod: "search_expansion",
            sourceId: matchingSource?.id || "src_dfir",
            sourceSlug: item.sourceSlug,
            publisher: item.publisher,
            domain,
            title: item.title,
            preloadedText: item.sampleText,
          });
        } catch {
          /* skip */
        }
      }
    }

    // 4. ADAPTIVE CONCURRENT WORKER POOL & HOST-AWARE DISPATCHER
    // Distributes extraction across multiple target domains concurrently while respecting polite per-host spacing
    const maxConcurrency = Math.min(Math.max(config.concurrency || 4, 1), 8);
    const activeWorkerTasks = new Set<Promise<void>>();
    const activeDomains = new Set<string>();
    const domainLastAccessTimes = new Map<string, number>();
    const currentlyProcessingUrls = new Set<string>();
    let lastReportedProgressTime = 0;

    async function reportLiveProgress(force = false) {
      const now = Date.now();
      if (!force && now - lastReportedProgressTime < 1000) return;
      lastReportedProgressTime = now;

      const elapsedSec = Math.max((now - jobStartTime) / 1000, 1);
      const throughputDocsPerSec = Number((evaluatedCount / elapsedSec).toFixed(2));
      const activeUrlList = Array.from(currentlyProcessingUrls);

      if (isMongoConfigured()) {
        try {
          const stillRunning = await updateJobIfRunning(jobId, {
            discoveredCount,
            evaluatedCount,
            qualifiedCount,
            ingestedCount,
            duplicateCount,
            failedCount,
            rejectedCount,
            skippedCount,
            newSourcesCount,
            pdfGeneratedCount,
            currentUrl: activeUrlList[0] || (activeDomains.size > 0 ? `Spidertree across ${activeDomains.size} hosts` : "Exploring frontier..."),
            currentStage: "evaluated",
            activeWorkers: activeWorkerTasks.size,
            activeDomains: Array.from(activeDomains),
            throughputDocsPerSec,
          });
          // Status changed elsewhere (e.g. cancelled from another instance): stop taking work.
          if (!stillRunning) jobControl.cancel = true;
        } catch {
          /* non-critical telemetry update error */
        }
      }
    }

    function pickNextItem(): FrontierItem | null {
      if (frontierQueue.length === 0) return null;
      frontierQueue.sort((a, b) => b.priorityScore - a.priorityScore);

      for (let i = 0; i < frontierQueue.length; i++) {
        const item = frontierQueue[i];
        const currentDomainCount = domainVisitCounts.get(item.domain) || 0;
        if (currentDomainCount >= maxPerDomain && item.depth > 0 && item.discoveryMethod === "seed_source") {
          frontierQueue.splice(i, 1);
          i--;
          continue;
        }
        if (!activeDomains.has(item.domain)) {
          frontierQueue.splice(i, 1);
          return item;
        }
      }

      // If all items belong to busy domains, pop only if no workers are active
      if (activeWorkerTasks.size === 0 && frontierQueue.length > 0) {
        return frontierQueue.shift()!;
      }
      return null;
    }

    /** Writes a crawl job item (Mongo and the SQL audit table). */
    async function recordItem(
      current: FrontierItem,
      decision: string,
      reason: string,
      stage: CrawlPipelineStage,
      extra: Partial<CrawlJobItem> = {},
    ): Promise<void> {
      const item: CrawlJobItem = {
        id: newId("itm"),
        jobId,
        sourceId: current.sourceId || null,
        url: current.url,
        canonicalUrl: current.canonicalUrl,
        title: extra.title || current.title || "Untitled",
        classification: extra.classification || "THREAT_REPORT",
        decision,
        reason,
        stage,
        discoveryMethod: current.discoveryMethod,
        discoveryQuery: current.discoveryQuery ?? "",
        parentUrl: current.parentUrl,
        depth: current.depth,
        publisher: current.publisher || current.domain,
        discoveryPath: current.discoveryPath,
        createdAt: new Date().toISOString(),
        ...extra,
      };
      if (isMongoConfigured()) {
        try {
          await mongoInsertCrawlJobItem(item);
        } catch {
          /* telemetry only */
        }
      }
      if (sql) {
        try {
          await sql`
            insert into crawl_job_items (
              id, job_id, source_id, url, canonical_url, title, classification,
              decision, reason, discovery_method, discovery_query, depth, publisher
            ) values (
              ${item.id}, ${jobId}, ${item.sourceId}, ${item.url}, ${item.canonicalUrl}, ${item.title}, ${item.classification},
              ${decision}, ${reason}, ${current.discoveryMethod}, '', ${current.depth}, ${item.publisher}
            )
          `;
        } catch {
          /* ignore sql fallback error */
        }
      }
    }

    async function politeWait(current: FrontierItem) {
      const lastDomainHit = domainLastAccessTimes.get(current.domain) || 0;
      const timeSinceDomainHit = Date.now() - lastDomainHit;
      const politeDelay = Math.max(
        Math.min(config.rateLimitMs ?? 150, 300),
        backfillPlan?.hostSpacingMs ?? 0,
        await collector.crawlDelayMs(current.canonicalUrl),
      );
      if (timeSinceDomainHit < politeDelay) {
        await new Promise((r) => setTimeout(r, politeDelay - timeSinceDomainHit));
      }
      domainLastAccessTimes.set(current.domain, Date.now());
    }

    /**
     * Incremental crawl of an already-stored URL: conditional GET when the listing reports an update
     * (sitemap lastmod / feed date after our last fetch) or the periodic revalidation window passed.
     * 304 or the same normalised content → unchanged; changed content → a new version of the same
     * report (previous hash kept). Returns false when the URL was not revalidated.
     */
    async function revalidateKnownUrl(current: FrontierItem): Promise<boolean> {
      let stored: Awaited<ReturnType<typeof findStoredReportByCanonical>> = null;
      try {
        stored = await findStoredReportByCanonical(current.canonicalUrl);
      } catch {
        return false;
      }
      if (!stored) return false;
      const storedNorm = stored.normalizedTextHash ?? sha256Hex(normalizeForFingerprint(stored.extractedText || ""));
      await collector.ensureArticleBaseline(current.canonicalUrl, current.sourceId, {
        textHash: storedNorm,
        version: stored.version,
        reportId: stored.id,
        ingestedAt: stored.ingestedAt,
      });
      const decision = await collector.revalidationDecision(current.canonicalUrl, { lastmod: current.lastmodHint });
      if (!decision.revalidate) return false;
      if (!(await collector.robotsAllowed(current.canonicalUrl))) return false;

      evaluatedCount++;
      await politeWait(current);
      let res: Awaited<ReturnType<CollectorRun["fetchArticle"]>>;
      try {
        res = await collector.fetchArticle(current.canonicalUrl, {
          conditional: true,
          timeoutMs: 6000,
          userAgent: COLLECTOR_USER_AGENT,
          accept: "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        });
      } catch (err) {
        collector.count(current.sourceId, "failed");
        collector.funnel.failed++;
        logger.warn("collector", `Revalidation failed for ${current.canonicalUrl}: ${(err as Error).message}`);
        return false;
      }
      collector.count(current.sourceId, "fetched");
      const unchanged = async (reason: string) => {
        collector.funnel.unchanged++;
        collector.count(current.sourceId, "unchanged");
        duplicateCount++;
        await recordItem(current, "UNCHANGED", `${reason} · ${decision.reason}`, "duplicate", { title: stored!.title });
        return true;
      };
      if (res.status === "not_modified") {
        collector.funnel.notModified++;
        await collector.noteArticleFetch(current.canonicalUrl, current.sourceId, { status: 304 });
        return unchanged("Not modified since last fetch (HTTP 304)");
      }
      if (res.contentType.includes("pdf")) return unchanged("PDF re-fetch: content versioning applies to HTML pages");
      const ex = htmlToText(res.body, { structured: true });
      const norm = sha256Hex(normalizeForFingerprint(ex.text));
      const outcome = await collector.noteArticleFetch(current.canonicalUrl, current.sourceId, {
        status: res.httpStatus,
        etag: res.etag,
        lastModified: res.lastModified,
        textHash: norm,
        reportId: stored.id,
      });
      if (outcome !== "changed") return unchanged("Content unchanged (same normalised text hash)");
      // Rotating "related posts" blocks, dates or share counts change the hash but not the report.
      // A translated report is compared with its original, in the language the page is published in.
      const published = stored.originalText ?? stored.extractedText ?? "";
      const cosmetic = hammingDistance64(simhash64(normalizeForFingerprint(published)), simhash64(normalizeForFingerprint(ex.text)));
      if (cosmetic <= COSMETIC_CHANGE_DISTANCE) return unchanged(`Only cosmetic changes (SimHash distance ${cosmetic} ≤ ${COSMETIC_CHANGE_DISTANCE}); stored version kept`);
      const words = ex.text.split(/\s+/).filter(Boolean).length;
      const storedWords = stored.originalText ? published.split(/\s+/).filter(Boolean).length : stored.wordCount;
      if (words < 150 || words < storedWords * 0.5) {
        return unchanged(`Fetched copy has ${words} words vs ${storedWords} stored (paywall, error or partial page) — stored version kept`);
      }

      let title = ex.title && ex.title !== "Untitled report" ? ex.title : stored.title;
      let text = ex.text;
      let sections: TextSection[] | undefined = ex.sections;
      // A new version in another language is stored only translated, like a new report.
      let translation: ReportTranslation | null = null;
      const language = detectLanguage(articleProse(ex.text), declaredHtmlLang(res.body));
      if (!language.english && language.lang !== "und") {
        const langLabel = languageName(language.lang);
        const tai = config.translateNonEnglish === false ? null : await translationAi();
        if (!tai?.usable || translationsThisJob >= TRANSLATIONS_PER_JOB || translationMsThisJob >= TRANSLATION_JOB_BUDGET_MS) {
          return unchanged(`Content changed, in ${langLabel}: stored version kept until the new one can be translated`);
        }
        translationsThisJob++;
        const translationStarted = Date.now();
        const translated = await runUnifiedTranslation({
          title: ex.title && ex.title !== "Untitled report" ? ex.title : title,
          text: ex.text,
          lang: language.lang,
          model: sanitizeAgyModel(config.agentModel),
          timeoutSeconds: config.agentTimeoutSeconds,
          allowSandboxFallback: tai.sandbox,
          deadlineAt: translationStarted + Math.round(itemTimeoutMs(config.agentTimeoutSeconds) * TRANSLATION_ITEM_SHARE),
          cancelled: () => jobControl.cancel,
        });
        translationMsThisJob += Date.now() - translationStarted;
        if (!translated.ok) return unchanged(`Content changed, in ${langLabel}: the translation was not usable (${translated.reason}); stored version kept`);
        translation = {
          from: language.lang,
          provider: translated.provider,
          model: translated.model,
          originalTitle: title,
          originalText: ex.text.slice(0, ORIGINAL_TEXT_CAP),
          translatedChars: translated.translatedChars,
          totalChars: translated.totalChars,
          partial: translated.partial,
          translatedAt: new Date().toISOString(),
        };
        title = translated.title;
        text = translated.text;
        sections = undefined;
      }

      const { score, wordCount } = scoreQuality(text, title);
      const iocs = harvestIocs(text, { sourceDomain: current.domain });
      const analysis = config.autoAnalyze ? analyzeThreatIntelligence(text, title, "THREAT_REPORT") : undefined;
      const entities = analysis ? extractStructuredEntities(text, title, "THREAT_REPORT", analysis) : undefined;
      const refs = enrichAttackEntities(title, text, sections);
      const nextVersion = stored.version + 1;
      try {
        await applyReportVersion({
          reportId: stored.id,
          version: nextVersion,
          previous: { version: stored.version, textHash: stored.textHash, rawHash: stored.rawHash, wordCount: stored.wordCount, replacedAt: new Date().toISOString() },
          fields: {
            title,
            extractedText: text,
            textHash: sha256Hex(ex.text),
            rawHash: sha256Hex(res.bytes),
            wordCount,
            qualityScore: score,
            iocs,
            analysis,
            extractedEntities: withAttackRefs(entities, refs),
            fingerprints: computeFingerprints({ text: ex.text, title: translation?.originalTitle ?? title, publisher: current.publisher || current.domain }),
            contentType: res.contentType,
            translation: translation ?? (stored.originalText ? null : undefined),
          },
        });
      } catch (err) {
        logger.warn("collector", `New version not stored for ${stored.id}: ${(err as Error).message}`);
        return unchanged("Content changed but the new version could not be stored");
      }
      collector.funnel.newVersions++;
      collector.funnel.stored++;
      collector.count(current.sourceId, "versions");
      collector.count(current.sourceId, "accepted");
      collector.noteQuality(current.sourceId, score);
      await recordItem(
        current,
        "UPDATED",
        `Content changed since last fetch: stored as v${nextVersion} of ${stored.id} (previous hash ${stored.textHash.slice(0, 12)}… kept) · ${decision.reason}`,
        "ingested",
        { title, qualityScore: score },
      );
      return true;
    }

    // A provider that keeps failing (timeouts, a busy agent, quota) would cost every remaining article
    // its full timeout: after a few failures in a row the rest of the run uses the rules engine.
    function noteAiEvalFailure(reason: string): void {
      // A busy agent is working, just not for this article (it used the rules): not a reason to pause.
      if (/\bbusy\b/i.test(reason)) return;
      aiEvalFailuresInARow++;
      if (aiEvalPaused || aiEvalFailuresInARow < AI_FAILURES_BEFORE_PAUSE) return;
      aiEvalPaused = true;
      logger.agent(
        "PAUSED",
        `AI scoring paused for the rest of this run: ${AI_FAILURES_BEFORE_PAUSE} requests in a row failed (last: ${reason.slice(0, 160)}). Articles are qualified by the rules engine.`,
      );
    }

    async function processFrontierItem(current: FrontierItem): Promise<void> {
      if (jobControl.cancel) return;
      currentlyProcessingUrls.add(current.url);
      activeDomains.add(current.domain);

      try {
        const currentDomainCount = domainVisitCounts.get(current.domain) || 0;
        if (currentDomainCount >= maxPerDomain && current.depth > 0 && current.discoveryMethod === "seed_source") {
          return;
        }

        // 4.1 Deduplication Check
        let isDuplicate = false;
        if (config.dedupMethod === "canonical_url" || config.dedupMethod === "both" || config.dedupMethod === "smart_hybrid") {
          if (storedCanonicalUrls.has(current.canonicalUrl)) {
            isDuplicate = true;
          }
        }

        if (isDuplicate && (await revalidateKnownUrl(current))) return;

        if (isDuplicate) {
          duplicateCount++;
          collector.funnel.unchanged++;
          collector.count(current.sourceId, "unchanged");
          const itemId = newId("itm");
          const jobItem: CrawlJobItem = {
            id: itemId,
            jobId,
            sourceId: current.sourceId || null,
            url: current.url,
            canonicalUrl: current.canonicalUrl,
            title: current.title || "Untitled",
            classification: "THREAT_REPORT",
            decision: "DUPLICATE",
            reason: "Canonical URL already acquired in knowledge base",
            stage: "duplicate",
            discoveryMethod: current.discoveryMethod,
            discoveryQuery: current.discoveryQuery ?? "",
            parentUrl: current.parentUrl,
            depth: current.depth,
            publisher: current.publisher || current.domain,
            discoveryPath: current.discoveryPath,
            createdAt: new Date().toISOString(),
          };

          if (isMongoConfigured()) {
            await mongoInsertCrawlJobItem(jobItem);
          }
          if (sql) {
            try {
              await sql`
                insert into crawl_job_items (
                  id, job_id, source_id, url, canonical_url, title, classification,
                  decision, reason, discovery_method, discovery_query, depth, publisher
                ) values (
                  ${itemId}, ${jobId}, ${current.sourceId ?? null}, ${current.url}, ${current.canonicalUrl},
                  ${current.title ?? 'Untitled'}, 'THREAT_REPORT', 'DUPLICATE',
                  'Canonical URL already acquired in knowledge base',
                  ${current.discoveryMethod}, '', ${current.depth}, ${current.publisher ?? current.domain}
                )
              `;
            } catch {
              /* ignore sql fallback error */
            }
          }

          // Deep Graph Expansion: Even if canonical report is already acquired,
          // extract its outbound citations to discover fresh external threat papers and repositories!
          if (config.recursiveDiscovery !== false && current.depth < maxDepth) {
            try {
              let storedHtml = "";
              if (isMongoConfigured()) {
                const existing = await mongoFindReportByCanonical(current.canonicalUrl);
                storedHtml = existing?.rawHtml || existing?.extractedText || "";
              }
              if (storedHtml && storedHtml.length > 200) {
                const { discoveredLinks, newDiscoveredSources, graphEdges } = extractOutlinksAndCitations(
                  storedHtml,
                  current.canonicalUrl,
                  {
                    sourceId: current.sourceId,
                    publisher: current.publisher,
                    parentPath: current.discoveryPath,
                    depth: current.depth + 1,
                    allowExternalDomains: config.allowExternalDomains !== false,
                    domainAllowlist: config.domainAllowlist,
                    domainBlocklist: config.domainBlocklist,
                  },
                );

                if (isMongoConfigured()) {
                  for (const newSrc of newDiscoveredSources) {
                    await mongoInsertDiscoveredSource(newSrc);
                    newSourcesCount++;
                  }
                  if (graphEdges.length > 0) {
                    await mongoInsertGraphEdgesBatch(graphEdges.map((edge) => ({ ...edge, jobId })));
                  }
                }

                for (const outlink of discoveredLinks) {
                  enqueue({
                    url: outlink.url,
                    canonicalUrl: outlink.canonicalUrl,
                    depth: current.depth + 1,
                    priorityScore: outlink.priorityScore,
                    parentUrl: current.canonicalUrl,
                    parentSource: current.publisher || current.domain,
                    discoveryPath: outlink.discoveryPath,
                    discoveryMethod: outlink.isExternalDomain ? "outlink_citation" : "seed_source",
                    sourceId: current.sourceId,
                    publisher: outlink.publisher,
                    domain: outlink.domain,
                    title: outlink.title,
                  });
                }
              }
            } catch {
              /* ignore outlink expansion error */
            }
          }

          return;
        }

        // 4.15 Relevance pre-score gate (before any fetch): junk is skipped with a recorded reason.
        if (current.relevance?.decision === "skip") {
          skippedCount++;
          collector.recordRelevanceSkip(current.title || current.canonicalUrl, current.canonicalUrl, current.relevance);
          collector.count(current.sourceId, "skippedRelevance");
          await recordItem(current, "SKIPPED", current.relevance.reason, "rejected", { qualityScore: current.relevance.score });
          return;
        }
        collector.funnel.relevant++;

        // 4.2 Content Acquisition & Evaluation Increment
        evaluatedCount++;
        domainVisitCounts.set(current.domain, currentDomainCount + 1);
        void reportLiveProgress();

        let textContent = current.preloadedText || "";
        let docTitle = current.title || "Threat Intelligence Report";
        let contentType = "text/html";
        let rawBytes: Uint8Array | string = current.preloadedText || "";
        let fetchedHtmlBody = "";
        // Bytes exactly as fetched (null when the text came preloaded from a feed).
        let fetchedOriginal: Uint8Array | null = null;
        let textSections: TextSection[] | undefined;
        let fetchValidators: { status: number; etag: string | null; lastModified: string | null } | null = null;
        const attachments: ReportAttachment[] = [];

        const currentWordCount = textContent.split(/\s+/).filter(Boolean).length;
        const needsFullArticleFetch = currentWordCount < 300;

        const robotsOk = needsFullArticleFetch ? await collector.robotsAllowed(current.canonicalUrl) : true;
        if (!robotsOk && !textContent) {
          collector.funnel.robotsBlocked++;
          skippedCount++;
          await recordItem(current, "SKIPPED", "Disallowed by the publisher's robots.txt", "rejected");
          return;
        }

        if (needsFullArticleFetch && robotsOk) {
          try {
            // Polite per-host spacing (config, backfill plan and robots.txt crawl-delay).
            await politeWait(current);

            const fetchedRes = await collector.fetchArticle(current.canonicalUrl, {
              conditional: false,
              timeoutMs: 4500,
              userAgent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (compatible; AIE-Threat-Crawler/3.0)",
              accept: "text/html,application/xhtml+xml,application/pdf,text/plain;q=0.9,*/*;q=0.8",
            });
            if (fetchedRes.status !== "ok") throw new Error("Unexpected HTTP 304 to an unconditional request");
            const fetched = fetchedRes;
            fetchValidators = { status: fetched.httpStatus, etag: fetched.etag, lastModified: fetched.lastModified };
            collector.count(current.sourceId, "fetched");

            rawBytes = fetched.bytes;
            fetchedOriginal = fetched.bytes;
            contentType = fetched.contentType;

            if (contentType.includes("pdf")) {
              let pdfFailure = "";
              try {
                const pdfResult = await extractTextFromPdfBuffer(Buffer.from(fetched.bytes));
                if (!pdfResult.noText && pdfResult.text && pdfResult.text.length > 50) {
                  textContent = pdfResult.text;
                  if (pdfResult.title && pdfResult.title !== "Untitled report") {
                    docTitle = pdfResult.title;
                  }
                  if (pdfResult.author) {
                    current.author = pdfResult.author;
                  }
                  if (pdfResult.creationDate) current.pdfDate = pdfResult.creationDate;
                  console.log(`[crawler] PDF extracted: ${textContent.length} chars from ${current.canonicalUrl}`);
                } else {
                  pdfFailure = pdfResult.failureReason || "PDF has no extractable text layer";
                }
              } catch (pdfErr) {
                pdfFailure = `PDF extraction error: ${pdfErr instanceof Error ? pdfErr.message : String(pdfErr)}`;
              }
              if (pdfFailure) {
                // Never create a report from placeholder text: record the item as failed / needs OCR.
                failedCount++;
                console.warn(`[crawler] PDF needs OCR, not ingested: ${current.canonicalUrl} (${pdfFailure})`);
                const jobItem: CrawlJobItem = {
                  id: newId("itm"),
                  jobId,
                  sourceId: current.sourceId || null,
                  url: current.url,
                  canonicalUrl: current.canonicalUrl,
                  title: current.title || docTitle,
                  classification: "OTHER",
                  decision: "FAILED",
                  reason: `Needs OCR: ${pdfFailure} (${fetched.bytes.byteLength} bytes)`,
                  stage: "failed",
                  discoveryMethod: current.discoveryMethod,
                  discoveryQuery: current.discoveryQuery ?? "",
                  parentUrl: current.parentUrl,
                  depth: current.depth,
                  publisher: current.publisher || current.domain,
                  discoveryPath: current.discoveryPath,
                  createdAt: new Date().toISOString(),
                };
                if (isMongoConfigured()) {
                  await mongoInsertCrawlJobItem(jobItem);
                }
                return;
              }
            } else {
              const body = fetched.body;
              fetchedHtmlBody = body;
              // Structure-preserving extraction: headings, lists, tables (IOC appendices) and code blocks.
              const extracted = htmlToText(body, { structured: true });
              if (extracted.text && extracted.text.length > textContent.length) {
                textContent = extracted.text;
                textSections = extracted.sections;
              }

              // "Download the full report" → attach the PDF text (size-capped, per-job budget, robots).
              for (const link of findFullReportPdfLinks(body, current.canonicalUrl, 1)) {
                if (pdfAttachments >= maxPdfDownloads) {
                  attachments.push({ kind: "pdf", url: link.url, bytes: 0, chars: 0, status: "skipped", detail: "Per-job PDF budget reached" });
                  break;
                }
                if (storedCanonicalUrls.has(canonicalizeUrl(link.url)) || !(await collector.robotsAllowed(link.url))) break;
                pdfAttachments++;
                try {
                  const pdf = await safeFetchResource(link.url, { timeoutMs: 15000, maxBytes: 15_000_000, acceptHeader: "application/pdf,*/*;q=0.5" });
                  if (!pdf.contentType.includes("pdf") && !/\.pdf$/i.test(new URL(link.url).pathname)) {
                    attachments.push({ kind: "pdf", url: link.url, bytes: pdf.bytes.byteLength, chars: 0, status: "failed", detail: `Not a PDF (${pdf.contentType})` });
                    break;
                  }
                  const pr = await extractTextFromPdfBuffer(Buffer.from(pdf.bytes));
                  if (!pr.noText && pr.text && pr.text.trim().length > 500) {
                    textContent = appendPdfText(textContent, { url: link.url, text: pr.text, pages: pr.pageCount });
                    textSections = undefined;
                    attachments.push({ kind: "pdf", url: link.url, bytes: pdf.bytes.byteLength, chars: pr.text.length, pages: pr.pageCount, status: "attached" });
                    collector.funnel.pdfAttached++;
                  } else {
                    attachments.push({ kind: "pdf", url: link.url, bytes: pdf.bytes.byteLength, chars: 0, pages: pr.pageCount, status: "no_text", detail: pr.failureReason || "No extractable text layer" });
                  }
                } catch (pdfErr) {
                  const msg = pdfErr instanceof Error ? pdfErr.message : String(pdfErr);
                  attachments.push({ kind: "pdf", url: link.url, bytes: 0, chars: 0, status: /size limit|exceeded/i.test(msg) ? "too_large" : "failed", detail: msg.slice(0, 160) });
                }
              }
              if (extracted.title && extracted.title !== "Untitled report") {
                docTitle = extracted.title;
              }

              const htmlMeta = extractHtmlMetadata(body);
              if (htmlMeta.author && (!current.author || current.author === current.domain)) {
                current.author = htmlMeta.author;
              }
              if (htmlMeta.publisher && (!current.publisher || current.publisher === current.domain)) {
                current.publisher = htmlMeta.publisher;
              }
              if (current.domain === "cloud.google.com" || current.sourceId === "src_mandiant") {
                current.publisher = "Google Threat Intelligence Group";
                current.author = htmlMeta.author || "Google Threat Intelligence Group";
              }
            }
          } catch (fetchErr) {
            collector.funnel.failed++;
            collector.count(current.sourceId, "failed");
            if (!textContent) {
              failedCount++;
              const itemId = newId("itm");
              const errMsg = fetchErr instanceof Error ? fetchErr.message : "Fetch failed";
              const jobItem: CrawlJobItem = {
                id: itemId,
                jobId,
                sourceId: current.sourceId || null,
                url: current.url,
                canonicalUrl: current.canonicalUrl,
                title: current.title || "Fetch Failure",
                classification: "OTHER",
                decision: "FAILED",
                reason: errMsg,
                stage: "failed",
                discoveryMethod: current.discoveryMethod,
                discoveryQuery: current.discoveryQuery ?? "",
                parentUrl: current.parentUrl,
                depth: current.depth,
                publisher: current.publisher || current.domain,
                discoveryPath: current.discoveryPath,
                createdAt: new Date().toISOString(),
              };

              if (isMongoConfigured()) {
                await mongoInsertCrawlJobItem(jobItem);
              }
              return;
            }
          }
        }

        // Funnel "acquired": full text obtained, by fetch or supplied by the feed.
        collector.funnel.fetched++;

        // Publication date from the source itself (page structured data, feed, URL, byline), never the fetch time.
        const feedDate = current.publishedAt ?? null;
        current.publishedDate = resolvePublicationDate({
          html: fetchedHtmlBody || null,
          text: textContent,
          url: current.canonicalUrl,
          feedDate,
          pdfDate: current.pdfDate,
        });
        current.publishedAt = current.publishedDate.publishedAt;

        // Multi-hash content dedup (spec §18): SHA-256, normalised text, title+publisher, SimHash (Hamming <= 3).
        // The better canonical (primary publisher, higher tier, earlier date) wins; the other URL becomes a mirror.
        const textHash = sha256Hex(textContent);
        const fingerprints = computeFingerprints({ text: textContent, title: docTitle, publisher: current.publisher || current.domain });
        const candidateTier = (current.sourceId ? registryEntry(current.sourceId)?.tier : undefined) ?? 4;
        let supersedes: { id: string; mirror: ReportMirror } | null = null;
        if (config.dedupMethod !== "canonical_url") {
          const match = collector.dedup.findContentDuplicate({
            canonicalUrl: current.canonicalUrl,
            title: docTitle,
            publisher: current.publisher || current.domain,
            sourceDomain: current.domain,
            sourceTier: candidateTier,
            publishedAt: current.publishedAt ?? null,
            fingerprints,
          });
          if (match) {
            const mirrorOf = (url: string, canonicalUrl: string, publisher: string, sourceDomain: string, sourceId?: string | null): ReportMirror => ({
              url,
              canonicalUrl,
              publisher,
              sourceDomain,
              sourceId: sourceId ?? null,
              matchKind: match.kind,
              distance: match.distance,
              seenAt: new Date().toISOString(),
            });
            const label = `${DUPLICATE_KIND_LABEL[match.kind]}${match.distance !== undefined ? `, Hamming ${match.distance}` : ""}`;
            const winner = preferCanonical(
              { sourceDomain: match.entry.sourceDomain, sourceTier: match.entry.sourceTier, publishedAt: match.entry.publishedAt },
              { sourceDomain: current.domain, sourceTier: candidateTier, publishedAt: current.publishedAt },
            );
            collector.funnel.duplicates[match.kind] = (collector.funnel.duplicates[match.kind] ?? 0) + 1;
            if (winner === "existing") {
              duplicateCount++;
              collector.count(current.sourceId, "duplicate");
              try {
                await recordMirror(match.entry.id, mirrorOf(current.url, current.canonicalUrl, current.publisher || current.domain, current.domain, current.sourceId));
              } catch {
                /* mirror is best effort */
              }
              await recordItem(
                current,
                "DUPLICATE",
                `Duplicate of ${match.entry.id} ("${match.entry.title.slice(0, 60)}", ${match.entry.sourceDomain}) by ${label}; recorded as "also seen at"`,
                "duplicate",
                { title: docTitle },
              );
              return;
            }
            // The new copy is the better canonical: store it and link the older record to it.
            supersedes = { id: match.entry.id, mirror: mirrorOf(match.entry.canonicalUrl, match.entry.canonicalUrl, match.entry.publisher, match.entry.sourceDomain) };
            logger.info("collector", `"${docTitle.slice(0, 60)}" supersedes ${match.entry.id} as canonical (${label})`);
          }
        }
        if (
          !supersedes &&
          (config.dedupMethod === "content_hash" || config.dedupMethod === "both" || config.dedupMethod === "smart_hybrid") &&
          storedHashes.has(textHash)
        ) {
          duplicateCount++;
          collector.count(current.sourceId, "duplicate");
          collector.funnel.duplicates.content_sha256 = (collector.funnel.duplicates.content_sha256 ?? 0) + 1;
          return;
        }

        // Check Near-Duplicate & Syndication with SimHash
        if (!supersedes && (config.dedupMethod === "smart_hybrid" || config.dedupMethod === "content_hash" || config.dedupMethod === "both")) {
          const candidateSimhash = computeReportSimHash(textContent);
          const candidateExcerptSimhash = computeReportSimHash(excerptOf(textContent));
          const nearDuplicate = storedSimhashes.find(
            (s) => computeHammingDistance(s.simhash, s.fromExcerpt ? candidateExcerptSimhash : candidateSimhash) <= 3,
          );
          if (nearDuplicate) {
            duplicateCount++;
            collector.count(current.sourceId, "duplicate");
            collector.funnel.duplicates.simhash = (collector.funnel.duplicates.simhash ?? 0) + 1;
            console.log(`[crawler] SYNDICATED / NEAR-DUPLICATE of ${nearDuplicate.id}: "${docTitle.slice(0, 60)}"`);
            const itemId = newId("itm");
            const jobItem: CrawlJobItem = {
              id: itemId,
              jobId,
              sourceId: current.sourceId || null,
              url: current.url,
              canonicalUrl: current.canonicalUrl,
              title: docTitle,
              classification: "THREAT_REPORT",
              decision: "DUPLICATE",
              reason: `Syndicated or near-duplicate reproduction of canonical report ${nearDuplicate.id} ("${nearDuplicate.title.slice(0, 50)}")`,
              stage: "duplicate",
              discoveryMethod: current.discoveryMethod,
              discoveryQuery: current.discoveryQuery ?? "",
              parentUrl: current.parentUrl,
              depth: current.depth,
              publisher: current.publisher || current.domain,
              discoveryPath: current.discoveryPath,
              createdAt: new Date().toISOString(),
            };
            if (isMongoConfigured()) {
              await mongoInsertCrawlJobItem(jobItem);
            }
            return;
          }
        }

        collector.funnel.unique++;

        // Date window: the configured dateRangeDays, or the backfill window.
        const windowCutoff = backfillPlan
          ? Date.parse(backfillPlan.sinceIso)
          : config.dateRangeDays && config.dateRangeDays > 0
            ? Date.now() - config.dateRangeDays * 24 * 60 * 60 * 1000
            : NaN;
        if (Number.isFinite(windowCutoff)) {
          // Prefer the source-reported date; fall back to the first ISO-style date near the top. A report the
          // source updated, or a feed lists as new, is judged by its latest date so refreshed research is kept.
          // A low-confidence date (byline guess, URL month, update-only) never skips an item on its own.
          const confident = current.publishedDate?.confidence !== "low" ? current.publishedAt : null;
          const windowDate = [confident, current.publishedDate?.sourceUpdatedAt, feedDate]
            .filter((d): d is string => Boolean(d))
            .sort()
            .pop();
          const pubDateMatch = windowDate
            ? [windowDate]
            : textContent.slice(0, 1500).match(/\b((?:19|20)\d{2})[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b/);
          if (pubDateMatch) {
            const parsedPubDate = new Date(pubDateMatch[0]).getTime();
            if (!isNaN(parsedPubDate) && parsedPubDate < windowCutoff) {
              skippedCount++;
              await recordItem(current, "SKIPPED", `Published ${pubDateMatch[0]}, before the ${backfillPlan ? `${backfillPlan.months}-month backfill` : `${config.dateRangeDays}-day`} window`, "rejected", { title: docTitle });
              return;
            }
          }
        }

        // Check maxPdfDownloads limit
        const isPdf = contentType.includes("pdf") || /\.pdf$/i.test(current.canonicalUrl);
        if (isPdf && pdfGeneratedCount >= (config.maxPdfDownloads || 10)) {
          skippedCount++;
          return;
        }

        // 4.3 Recursive Citation & Graph Outlink Exploration
        if (
          config.recursiveDiscovery !== false &&
          current.depth < maxDepth &&
          fetchedHtmlBody &&
          discoveredCount < maxTotalResources * 2
        ) {
          const { discoveredLinks, newDiscoveredSources, graphEdges } = extractOutlinksAndCitations(
            fetchedHtmlBody,
            current.canonicalUrl,
            {
              sourceId: current.sourceId,
              publisher: current.publisher,
              parentPath: current.discoveryPath,
              depth: current.depth + 1,
              allowExternalDomains: config.allowExternalDomains !== false,
              domainAllowlist: config.domainAllowlist,
              domainBlocklist: config.domainBlocklist,
            },
          );

          if (isMongoConfigured()) {
            for (const newSrc of newDiscoveredSources) {
              await mongoInsertDiscoveredSource(newSrc);
              newSourcesCount++;
            }
            if (graphEdges.length > 0) {
              await mongoInsertGraphEdgesBatch(graphEdges.map((edge) => ({ ...edge, jobId })));
            }
          }

          for (const outlink of discoveredLinks) {
            enqueue({
              url: outlink.url,
              canonicalUrl: outlink.canonicalUrl,
              depth: current.depth + 1,
              priorityScore: outlink.priorityScore,
              parentUrl: current.canonicalUrl,
              parentSource: current.publisher || current.domain,
              discoveryPath: outlink.discoveryPath,
              discoveryMethod: outlink.isExternalDomain ? "outlink_citation" : "seed_source",
              sourceId: current.sourceId,
              publisher: outlink.publisher,
              domain: outlink.domain,
              title: outlink.title,
            });
          }
        }

        // 4.35 Reports in other languages are judged in English: the publisher's English version when
        // the page links one, else an AI translation (checked part by part). Without a usable
        // translation the report is held, not rejected; only acquired URLs are skipped by later
        // crawls, so the next run with AI available evaluates it.
        const sourceText = textContent;
        let translation: ReportTranslation | undefined;
        const language = detectLanguage(articleProse(textContent), fetchedHtmlBody ? declaredHtmlLang(fetchedHtmlBody) : null);
        if (!language.english && language.lang !== "und") {
          const langLabel = languageName(language.lang);
          const held = async (reason: string) => {
            skippedCount++;
            logger.qualification(current.canonicalUrl, "HELD", 0, reason);
            await recordItem(current, "HELD", reason, "evaluated", { title: docTitle });
          };

          const english = fetchedHtmlBody ? findEnglishAlternate(fetchedHtmlBody, current.canonicalUrl) : null;
          let englishCanonical: string | null = null;
          try {
            englishCanonical = english ? canonicalizeUrl(english) : null;
          } catch {
            englishCanonical = null;
          }
          if (english && englishCanonical) {
            if (storedCanonicalUrls.has(englishCanonical)) {
              duplicateCount++;
              collector.count(current.sourceId, "duplicate");
              await recordItem(current, "DUPLICATE", `In ${langLabel}; the publisher's English version is already in the library: ${english}`, "duplicate", { title: docTitle });
              return;
            }
            const inThisRun =
              enqueuedUrls.has(englishCanonical) ||
              enqueue({
                url: english,
                canonicalUrl: englishCanonical,
                depth: current.depth,
                priorityScore: Math.min(1.2, current.priorityScore + 0.2),
                parentUrl: current.canonicalUrl,
                parentSource: current.parentSource,
                discoveryPath: [...current.discoveryPath, current.canonicalUrl],
                discoveryMethod: current.discoveryMethod,
                sourceId: current.sourceId,
                publisher: current.publisher,
                domain: new URL(englishCanonical).hostname,
                title: docTitle,
                publishedAt: current.publishedAt ?? null,
                relevance: current.relevance,
              });
            if (inThisRun) {
              skippedCount++;
              await recordItem(current, "SKIPPED", `In ${langLabel}; the publisher's English version is evaluated instead: ${english}`, "duplicate", { title: docTitle });
              return;
            }
            // The English version is outside this source's crawl scope: translate this one instead.
          } else {
            // Localized copies of English posts (/blog/ja/… next to /blog/…) often link no English
            // edition. When the same path without the language segment is already in the library or
            // in this run, this page is that report again, not new intelligence.
            const guesses = guessEnglishUrls(current.canonicalUrl, language.lang).flatMap((u) => {
              try {
                return [canonicalizeUrl(u)];
              } catch {
                return [];
              }
            });
            const inLibrary = guesses.find((u) => storedCanonicalUrls.has(u));
            if (inLibrary) {
              duplicateCount++;
              collector.count(current.sourceId, "duplicate");
              await recordItem(current, "DUPLICATE", `In ${langLabel}; the English edition is already in the library: ${inLibrary}`, "duplicate", { title: docTitle });
              return;
            }
            const inRun = guesses.find((u) => enqueuedUrls.has(u));
            if (inRun) {
              skippedCount++;
              await recordItem(current, "SKIPPED", `In ${langLabel}; the English edition is evaluated in this crawl: ${inRun}`, "duplicate", { title: docTitle });
              return;
            }
          }

          if (config.translateNonEnglish === false) {
            await held(`In ${langLabel}: translation is turned off in crawl settings, so it waits until it is turned on.`);
            return;
          }
          const tai = await translationAi();
          if (!tai.usable) {
            await held(`In ${langLabel}: waiting for translation. Add an AI provider in the Marketplace to translate and evaluate reports in other languages (${tai.detail}).`);
            return;
          }
          if (translationsThisJob >= TRANSLATIONS_PER_JOB || translationMsThisJob >= TRANSLATION_JOB_BUDGET_MS) {
            await held(`In ${langLabel}: this run's translation budget is used; it is translated and evaluated by the next crawl.`);
            return;
          }
          translationsThisJob++;
          const translationStarted = Date.now();
          logger.agent("TRANSLATE", `"${docTitle.slice(0, 60)}": translating ${textContent.length.toLocaleString("en-US")} characters from ${langLabel}`);
          const translated = await runUnifiedTranslation({
            title: docTitle,
            text: textContent,
            lang: language.lang,
            model: sanitizeAgyModel(config.agentModel),
            timeoutSeconds: config.agentTimeoutSeconds,
            allowSandboxFallback: tai.sandbox,
            deadlineAt: translationStarted + Math.round(itemTimeoutMs(config.agentTimeoutSeconds) * TRANSLATION_ITEM_SHARE),
            cancelled: () => jobControl.cancel,
          });
          translationMsThisJob += Date.now() - translationStarted;
          if (!translated.ok) {
            await held(`In ${langLabel}: the translation was not usable (${translated.reason}). Held for the next crawl.`);
            return;
          }
          translation = {
            from: language.lang,
            provider: translated.provider,
            model: translated.model,
            originalTitle: docTitle,
            originalText: textContent.slice(0, ORIGINAL_TEXT_CAP),
            translatedChars: translated.translatedChars,
            totalChars: translated.totalChars,
            partial: translated.partial,
            translatedAt: new Date().toISOString(),
          };
          logger.agent(
            "TRANSLATED",
            `"${docTitle.slice(0, 50)}" → "${translated.title.slice(0, 50)}" from ${langLabel} by ${translated.provider} (${translated.calls} part${translated.calls === 1 ? "" : "s"}${translated.partial ? ", partial" : ""})`,
          );
          textContent = translated.text;
          docTitle = translated.title;
          textSections = undefined;
        }

        // 4.4 Heuristic Qualification Baseline & 5-Dimensional AI Agent Validation
        const isFeedEntry = current.discoveryMethod === "rss_feed";
        const qual = qualifyContent(textContent, docTitle, current.canonicalUrl, config, isFeedEntry);
        // What an emulation team gets out of it: attack chain / procedures / context / news.
        const emulation = assessEmulationValue({ title: docTitle, text: textContent });

        let agentResult: AgentEvaluationResult | null = null;

        // The AI reviews technical documents and may rescue ones the rules found too thin; it never
        // overturns a product page, strategy / trends piece, guidance post or news item without
        // technical detail, so those are not sent to it at all.
        const aiMayDecide = !qual.depth || qual.depth.pass || qual.depth.kind === "thin";
        const shouldRunAgent =
          ai.usable &&
          !aiEvalPaused &&
          (config.agentTaggingEnabled || config.agentApprovalEnabled) &&
          !qual.isIndexOrGeneric &&
          aiMayDecide &&
          textContent.trim().length > 60;

        if (shouldRunAgent) {
          try {
            agentResult = await runUnifiedResourceEvaluation({
              text: textContent,
              title: docTitle,
              url: current.canonicalUrl,
              domain: current.domain,
              timeoutSeconds: config.agentTimeoutSeconds || 45,
              model: sanitizeAgyModel(config.agentModel),
              allowSandboxFallback: ai.sandbox,
            });

            if (agentResult.success && !agentResult.fallback) aiEvalFailuresInARow = 0;
            else noteAiEvalFailure(agentResult.error || agentResult.rationale || "no answer");

            if (agentResult.success && !agentResult.fallback) {
              logger.agent(
                "EVALUATE:5D_DONE",
                `"${docTitle.slice(0, 50)}" → score=${agentResult.passScore}, approved=${agentResult.recommendApproval}, class=${agentResult.classification}`,
                {
                  breakdown: agentResult.scoreBreakdown,
                  actors: agentResult.threatActors?.length || 0,
                  malware: agentResult.malwareFamilies?.length || 0,
                  tech: agentResult.mitreTechniques?.length || 0,
                }
              );
              console.log(
                `[crawler][agent] 5D Evaluated "${docTitle.slice(0, 60)}" → score=${agentResult.passScore}, approved=${agentResult.recommendApproval}, class=${agentResult.classification}`,
              );

              const docWords = textContent.split(/\s+/).filter(Boolean).length;
              const hasEvidenceInQual = Boolean(
                qual.evidenceDetails &&
                (qual.evidenceDetails.commands.length > 0 ||
                  qual.evidenceDetails.registryKeys.length > 0 ||
                  qual.evidenceDetails.filePaths.length > 0 ||
                  qual.evidenceDetails.eventIds.length > 0)
              );
              const hasConcreteEvidence =
                hasEvidenceInQual ||
                Boolean(agentResult.threatActors && agentResult.threatActors.length > 0) ||
                Boolean(agentResult.mitreTechniques && agentResult.mitreTechniques.length > 0) ||
                Boolean(agentResult.cves && agentResult.cves.length > 0) ||
                Boolean(qual.isEmergingTechnique);

              const isApproved =
                agentResult.recommendApproval &&
                agentResult.passScore >= 50 &&
                agentResult.classification !== "OTHER" &&
                agentResult.classification !== "GENERIC_NEWS" &&
                docWords >= 200 &&
                hasConcreteEvidence;

              if (isApproved) {
                qual.qualified = true;
                qual.classification = agentResult.classification;
                qual.resourceKind = agentResult.resourceKind;
                qual.score = Math.max(qual.score, agentResult.passScore / 100);
                if (agentResult.scoreBreakdown) {
                  qual.simulationScore = Math.max(
                    qual.simulationScore,
                    agentResult.scoreBreakdown.emulationUtility / 20,
                  );
                }
              } else {
                qual.qualified = false;
                qual.rejectionReason = agentResult.rationale
                  ? `Rejected by AI Agent (score: ${agentResult.passScore}/100, class: ${agentResult.classification}): ${agentResult.rationale}`
                  : `Rejected by AI Agent: 5D score (${agentResult.passScore}/100) below adversary emulation threshold or classified as ${agentResult.classification}`;
                logger.agent(
                  "REJECTED_BY_AI",
                  `"${docTitle.slice(0, 50)}" rejected by cognitive AI: ${qual.rejectionReason}`,
                );
              }
            } else if (agentResult.error) {
              logger.agent("FALLBACK", `Agent evaluation error for "${docTitle.slice(0, 40)}": ${agentResult.error} — adhering to strict heuristic verdict (${qual.qualified})`);
            }
          } catch (agentErr) {
            logger.agent("FAILSAFE", `evaluateResourceWithAgent non-blocking fallback: ${(agentErr as Error).message}`);
            noteAiEvalFailure((agentErr as Error).message);
            agentResult = null;
          }
        }

        // Emulation value floor (Settings → crawler, default "context"): news, patch notes and
        // vulnerability notices without attacker procedures stay out, even when they name a CVE.
        // CERT / government advisories and tier-1 sources are exempt; so is a report in which the AI
        // reviewer found real procedures and attack progression that the rules missed.
        if (qual.qualified) {
          const minGrade = config.minEmulationGrade ?? "context";
          const below = EMULATION_GRADE_META[emulation.grade].rank < EMULATION_GRADE_META[minGrade].rank;
          const exempt = isAdvisoryPublisher(current.canonicalUrl) || registryEntry(current.sourceId ?? "")?.tier === 1;
          const aiSawProcedures =
            !!agentResult?.scoreBreakdown && agentResult.scoreBreakdown.proceduralDepth >= 15 && agentResult.scoreBreakdown.attackProgression >= 10;
          if (below && !exempt && !aiSawProcedures) {
            qual.qualified = false;
            qual.rejectionReason = `REJECTED: Emulation value "${EMULATION_GRADE_META[emulation.grade].label}" is below the minimum "${EMULATION_GRADE_META[minGrade].label}": ${emulation.signals[0] ?? "no attacker procedures"}`;
            logger.qualification(current.canonicalUrl, "REJECT", qual.score, qual.rejectionReason);
          }
        }

        if (!qual.qualified) {
          rejectedCount++;
          collector.count(current.sourceId, "rejectedQuality");
          const itemId = newId("itm");
          const rejectMsg = qual.rejectionReason || "Below qualification threshold";
          logger.qualification(current.canonicalUrl, "REJECT", qual.score, rejectMsg);

          const jobItem: CrawlJobItem = {
            id: itemId,
            jobId,
            sourceId: current.sourceId || null,
            url: current.url,
            canonicalUrl: current.canonicalUrl,
            title: docTitle,
            classification: qual.classification,
            decision: "REJECTED",
            reason: rejectMsg,
            stage: "rejected",
            discoveryMethod: current.discoveryMethod,
            discoveryQuery: current.discoveryQuery ?? "",
            parentUrl: current.parentUrl,
            depth: current.depth,
            publisher: current.publisher || current.domain,
            qualityScore: qual.score,
            simulationScore: qual.simulationScore,
            isEmergingTechnique: qual.isEmergingTechnique,
            noveltyRationale: qual.noveltyRationale,
            resourceKind: qual.resourceKind,
            discoveryPath: current.discoveryPath,
            agentScore: agentResult?.passScore,
            agentApproved: agentResult?.recommendApproval,
            agentRationale: agentResult?.rationale,
            agentTags: agentResult?.mitreTechniques,
            agentClassification: agentResult?.classification,
            agentResourceKind: agentResult?.resourceKind,
            scoreBreakdown: agentResult?.scoreBreakdown,
            createdAt: new Date().toISOString(),
          };

          if (isMongoConfigured()) {
            await mongoInsertCrawlJobItem(jobItem);
            await mongoUpsertDiscoveredResource({
              id: newId("dsc"),
              canonicalUrl: current.canonicalUrl,
              url: current.url,
              sourceId: current.sourceId || null,
              title: docTitle,
              publisher: current.publisher || current.domain,
              classification: qual.classification,
              resourceKind: qual.resourceKind,
              discoveryMethod: current.discoveryMethod,
              discoveryQuery: current.discoveryQuery ?? "",
              parentSource: current.parentSource || current.domain,
              parentUrl: current.parentUrl,
              sourceDomain: current.domain,
              contentType,
              status: "rejected",
              rejectReason: rejectMsg,
              qualityScore: qual.score,
              simulationScore: qual.simulationScore,
              isEmergingTechnique: qual.isEmergingTechnique,
              noveltyRationale: qual.noveltyRationale,
              discoveryPath: current.discoveryPath,
              agentScore: agentResult?.passScore,
              agentApproved: agentResult?.recommendApproval,
              agentRationale: agentResult?.rationale,
              agentTags: agentResult?.mitreTechniques,
              agentClassification: agentResult?.classification,
              agentResourceKind: agentResult?.resourceKind,
              scoreBreakdown: agentResult?.scoreBreakdown,
            });
          }

          if (sql) {
            try {
              await sql`
                insert into crawl_job_items (
                  id, job_id, source_id, url, canonical_url, title, classification,
                  decision, reason, discovery_method, discovery_query, depth, publisher
                ) values (
                  ${itemId}, ${jobId}, ${current.sourceId ?? null}, ${current.url}, ${current.canonicalUrl},
                  ${docTitle}, ${qual.classification}, 'REJECTED', ${rejectMsg},
                  ${current.discoveryMethod}, '', ${current.depth}, ${current.publisher ?? current.domain}
                )
              `;

              await sql`
                insert into discovered_resources (
                  id, canonical_url, url, source_id, title, publisher, classification,
                  discovery_method, discovery_query, parent_source, source_domain,
                  content_type, status, reject_reason, quality_score
                ) values (
                  ${newId("dsc")}, ${current.canonicalUrl}, ${current.url}, ${current.sourceId ?? null}, ${docTitle},
                  ${current.publisher ?? current.domain}, ${qual.classification}, ${current.discoveryMethod},
                  '', ${current.parentSource ?? current.domain}, ${current.domain},
                  ${contentType}, 'rejected', ${rejectMsg}, ${qual.score}
                )
                on conflict (canonical_url) do update
                set status = 'rejected', reject_reason = excluded.reject_reason, updated_at = now()
              `;
            } catch {
              /* ignore sql fallback error */
            }
          }
          return;
        }

        qualifiedCount++;
        collector.funnel.qualified++;
        logger.qualification(
          current.canonicalUrl,
          "PASS",
          qual.score,
          `Classification: ${qual.classification}, Resource: ${qual.resourceKind}`,
        );

        // 4.5 Structured Entity Extraction, ATT&CK Analysis & PDF Generation
        const { score, reasons, wordCount } = scoreQuality(textContent, docTitle);
        const iocs = harvestIocs(textContent, { sourceDomain: current.domain });
        const rawHash = sha256Hex(rawBytes || textContent);
        // Fingerprints stay on the published text, so a re-crawl of a translated report still matches.
        const reportSimhash = computeReportSimHash(sourceText);
        const reportId = newId("rpt");

        let intelAnalysis = null;
        let extractedEntities = undefined;
        if (config.autoAnalyze) {
          intelAnalysis = analyzeThreatIntelligence(textContent, docTitle, qual.classification);
          extractedEntities = extractStructuredEntities(textContent, docTitle, qual.classification, intelAnalysis);
        }
        // Canonical ATT&CK references (bundled knowledge) with the matched alias and first offset.
        const attackRefs = enrichAttackEntities(docTitle, textContent, textSections ?? sectionsOf(textContent));
        const relevanceNote = current.relevance ? { score: current.relevance.score, reason: current.relevance.reason } : undefined;

        // High-Fidelity PDF & HTML Layout Generation
        let pristineHtml = "";
        if (config.generatePdf !== false) {
          const isPdfResource = contentType.includes("pdf") || current.canonicalUrl.toLowerCase().endsWith(".pdf");
          pristineHtml = buildPristineDocumentHtml(isPdfResource ? textContent : (fetchedHtmlBody || textContent), {
            id: reportId,
            title: docTitle,
            url: current.url,
            canonicalUrl: current.canonicalUrl,
            publisher: current.publisher || current.domain,
            author: current.publisher || current.domain,
            publishedAt: current.publishedAt ?? null,
            ingestedAt: new Date().toISOString(),
            classification: qual.classification,
            rawHash,
            textHash,
            qualityScore: score,
            wordCount,
            iocs,
            analysis: intelAnalysis,
          });
          pdfGeneratedCount++;
        }

        // 4.6 Ingestion vs Human Review Queue
        const shouldAutoIngest =
          Boolean(config.autoIngest) ||
          Boolean(config.agentAutoIngestEnabled && agentResult?.recommendApproval && (agentResult.passScore ?? 0) >= 65);

        if (shouldAutoIngest) {
          ingestedCount++;
          ingestedReportIds.push(reportId);
          storedCanonicalUrls.add(current.canonicalUrl);
          storedHashes.add(textHash);
          collector.funnel.stored++;
          collector.count(current.sourceId, "new");
          collector.count(current.sourceId, "accepted");
          collector.noteQuality(current.sourceId, score);
          collector.dedup.add({
            id: reportId,
            canonicalUrl: current.canonicalUrl,
            title: docTitle,
            publisher: current.publisher || current.domain,
            sourceDomain: current.domain,
            sourceTier: candidateTier,
            publishedAt: current.publishedAt ?? null,
            fingerprints,
            textHash,
          });
          if (fetchValidators) {
            await collector.noteArticleFetch(current.canonicalUrl, current.sourceId, {
              ...fetchValidators,
              textHash: fingerprints.normalizedTextHash,
              reportId,
            });
          }
          logger.ingest(
            "ACQUIRED",
            docTitle,
            `Classification: ${qual.resourceKind}, Score: ${score.toFixed(2)}, Words: ${wordCount}, IOCs: ${iocs.length}, TTPs: ${intelAnalysis?.attackChain?.length ?? 0}`,
          );

          if (isMongoConfigured()) {
            try {
              const isGoogle = current.domain === "cloud.google.com" || current.sourceId === "src_mandiant";
              const effectivePublisher = current.publisher || (isGoogle ? "Google Threat Intelligence Group" : current.domain);
              const effectiveAuthor = current.author || effectivePublisher;
              const effectiveSourceName = isGoogle ? "Google Threat Intelligence" : current.publisher || current.domain;
              const effectiveSourceId = current.sourceId || (isGoogle ? "src_mandiant" : "src_expanded");

              const isAiVerified = Boolean(
                agentResult?.recommendApproval &&
                (agentResult.passScore ?? 0) >= 50 &&
                agentResult.classification !== "OTHER" &&
                agentResult.classification !== "GENERIC_NEWS"
              );
              const aiScore = agentResult?.passScore ? agentResult.passScore : Math.round(score * 100);
              const aiReason = isAiVerified
                ? `AI Cognitive Approval (${agentResult?.passScore}/100): ${agentResult?.rationale || "Verified by 5D rubric"}`
                : "Structural CTI Signal Qualified (Pending Cognitive AI Agent Evaluation)";

              if (agentResult) {
                if (agentResult.threatActors?.length) {
                  intelAnalysis = intelAnalysis || {
                    method: "llm" as const,
                    classification: qual.classification || "General Threat Intel",
                    threatActors: [],
                    malware: [],
                    vulnerabilities: [],
                    ttps: [],
                    ioas: [],
                    attackChain: [],
                    detections: [],
                    hunting: [],
                    emulation: [],
                  };
                  const mergedActors = new Set([...(intelAnalysis.threatActors || []), ...agentResult.threatActors]);
                  intelAnalysis.threatActors = Array.from(mergedActors);
                }
                if (agentResult.mitreTechniques?.length) {
                  extractedEntities = extractedEntities || {
                    threatActors: [],
                    malwareFamilies: [],
                    cves: [],
                    tactics: [],
                    techniques: [],
                    procedures: [],
                    detectionRules: [],
                    mitigations: [],
                    campaign: null,
                  };
                  const existingIds = new Set((extractedEntities.techniques || []).map((t) => t.id));
                  for (const techId of agentResult.mitreTechniques) {
                    if (!existingIds.has(techId)) {
                      // Resolve name/tactic from ATT&CK reference data; skip ids we can't verify.
                      const ref = lookupAttackTechnique(techId);
                      if (!ref) continue;
                      extractedEntities.techniques.push({ id: ref.id, name: ref.name, tactic: ref.tactic });
                      existingIds.add(ref.id);
                    }
                  }
                }
              }

              const provenanceSource = registryEntry(effectiveSourceId) ?? sources.find((s) => s.id === effectiveSourceId);
              const provenance = annotateReportProvenance({
                source: provenanceSource,
                title: docTitle,
                url: current.url,
                text: textContent,
                qualityScore: score,
                qualityReasons: reasons,
                classification: qual.classification,
                resourceKind: qual.resourceKind,
              });

              const reportDoc: ReportRecord & { simhash: string } = {
                id: reportId,
                simhash: reportSimhash,
                sourceId: effectiveSourceId,
                sourceName: effectiveSourceName,
                title: docTitle,
                url: current.url,
                canonicalUrl: current.canonicalUrl,
                publishedAt: current.publishedAt ?? null,
                publishedDate: current.publishedDate,
                contentType,
                status: "acquired",
                rawHash,
                textHash,
                qualityScore: score,
                qualityReasons: provenance.qualityReasons,
                wordCount,
                extractedText: textContent,
                iocs,
                ingestOrigin: current.depth > 0 ? "citation_expansion" : "crawl",
                ingestedAt: new Date().toISOString(),
                publisher: effectivePublisher,
                author: effectiveAuthor,
                classification: qual.classification,
                resourceKind: qual.resourceKind,
                docTypes: provenance.docTypes,
                sourceTier: provenance.sourceTier,
                sourceConfidence: provenance.sourceConfidence,
                extractedEntities: withAttackRefs(extractedEntities, attackRefs),
                fingerprints,
                attachments: attachments.length ? attachments : undefined,
                relevance: relevanceNote,
                discoveryMethod: current.discoveryMethod,
                discoveryQuery: current.discoveryQuery ?? "",
                parentSource: current.parentSource || current.domain,
                sourceDomain: current.domain,
                version: 1,
                rawHtml: pristineHtml,
                pdfUrl: "",
                analysis: intelAnalysis,
                discoveryPath: current.discoveryPath,
                simulationScore: qual.simulationScore,
                isEmergingTechnique: qual.isEmergingTechnique || emulation.novelty.length > 0,
                noveltyRationale: qual.noveltyRationale ?? emulation.novelty[0],
                emulation: summarizeEmulation(emulation),
                aiVerified: isAiVerified,
                aiQualityScore: aiScore,
                aiAuditReason: aiReason,
                scoreBreakdown: agentResult?.scoreBreakdown,
                aiTokensUsed: agentResult?.tokensUsed,
                aiProvider: agentResult?.providerName,
                translation,
                research: classifyResearch({ title: docTitle, text: textContent }),
                telemetry: extractTelemetryRefs(textContent),
              };
              await mongoInsertReport(reportDoc);

              if (fetchedOriginal) {
                try {
                  await mongoSaveReportOriginal(reportId, fetchedOriginal, contentType);
                } catch (origErr) {
                  console.warn("[mongodb] original content not stored:", origErr);
                }
              }

              storedSimhashes.push({ id: reportId, simhash: reportSimhash, title: docTitle, fromExcerpt: false });

              if (current.sourceId) {
                await mongoUpdateSourceLastIngest(current.sourceId);
              }

              await mongoUpsertDiscoveredResource({
                id: newId("dsc"),
                canonicalUrl: current.canonicalUrl,
                url: current.url,
                sourceId: current.sourceId || null,
                title: docTitle,
                publisher: effectivePublisher,
                classification: qual.classification,
                resourceKind: qual.resourceKind,
                discoveryMethod: current.discoveryMethod,
                discoveryQuery: current.discoveryQuery ?? "",
                parentSource: current.parentSource || current.domain,
                parentUrl: current.parentUrl,
                sourceDomain: current.domain,
                contentType,
                status: "ingested",
                qualityScore: score,
                simulationScore: qual.simulationScore,
                isEmergingTechnique: qual.isEmergingTechnique,
                noveltyRationale: qual.noveltyRationale,
                discoveryPath: current.discoveryPath,
                reportId,
                agentScore: agentResult?.passScore,
                agentApproved: agentResult?.recommendApproval,
                agentRationale: agentResult?.rationale,
                agentTags: agentResult?.mitreTechniques,
                agentClassification: agentResult?.classification,
                agentResourceKind: agentResult?.resourceKind,
                scoreBreakdown: agentResult?.scoreBreakdown,
              });
            } catch (mongoErr) {
              console.warn("[mongodb] report persistence error:", mongoErr);
            }
          }

          if (sql) {
            try {
              const isGoogle = current.domain === "cloud.google.com" || current.sourceId === "src_mandiant";
              const effectivePublisher = current.publisher || (isGoogle ? "Google Threat Intelligence Group" : current.domain);
              const effectiveAuthor = current.author || effectivePublisher;
              const effectiveSourceId = current.sourceId || (isGoogle ? "src_mandiant" : "src_dfir");

              await sql`
                insert into reports (
                  id, source_id, title, url, canonical_url, published_at, content_type,
                  status, raw_hash, text_hash, quality_score, quality_reasons, word_count,
                  extracted_text, iocs_json, ingest_origin, publisher, author,
                  classification, discovery_method, discovery_query, parent_source,
                  source_domain, version, analysis_json, raw_html
                ) values (
                  ${reportId}, ${effectiveSourceId}, ${docTitle}, ${current.url}, ${current.canonicalUrl},
                  ${current.publishedAt ?? null}, ${contentType}, 'acquired',
                  ${rawHash}, ${textHash}, ${score}, ${JSON.stringify(reasons)}, ${wordCount},
                  ${textContent}, ${JSON.stringify(iocs)}, ${current.depth > 0 ? 'citation_expansion' : 'crawl'},
                  ${effectivePublisher}, ${effectiveAuthor},
                  ${qual.classification}, ${current.discoveryMethod}, '', ${current.parentSource ?? current.domain},
                  ${current.domain}, 1, ${JSON.stringify(intelAnalysis)}, ${pristineHtml}
                )
              `;

              await sql`
                insert into discovered_resources (
                  id, canonical_url, url, source_id, title, publisher, classification,
                  discovery_method, discovery_query, parent_source, source_domain,
                  content_type, status, quality_score, report_id
                ) values (
                  ${newId("dsc")}, ${current.canonicalUrl}, ${current.url}, ${current.sourceId ?? null}, ${docTitle},
                  ${current.publisher ?? current.domain}, ${qual.classification}, ${current.discoveryMethod},
                  '', ${current.parentSource ?? current.domain}, ${current.domain},
                  ${contentType}, 'ingested', ${score}, ${reportId}
                )
                on conflict (canonical_url) do update
                set status = 'ingested', quality_score = ${score}, report_id = ${reportId}, updated_at = now()
              `;
              if (!isMongoConfigured()) {
                await mergeLocalReportMeta(reportId, {
                  fingerprints,
                  attackRefs,
                  attachments: attachments.length ? attachments : undefined,
                  relevance: relevanceNote,
                });
              }
            } catch {
              /* ignore SQL fallback error */
            }
          }

          if (supersedes) {
            try {
              await supersedeWithCanonical(supersedes.id, reportId, supersedes.mirror);
            } catch (err) {
              logger.warn("collector", `Could not link ${supersedes.id} to new canonical ${reportId}: ${(err as Error).message}`);
            }
          }

          const itemId = newId("itm");
          const jobItem: CrawlJobItem = {
            id: itemId,
            jobId,
            sourceId: current.sourceId || null,
            url: current.url,
            canonicalUrl: current.canonicalUrl,
            title: docTitle,
            classification: qual.classification,
            decision: "INGESTED",
            reason: `Qualified (${qual.resourceKind}): quality ${score} with ${iocs.length} IOCs · Depth ${current.depth}`,
            stage: "ingested",
            discoveryMethod: current.discoveryMethod,
            discoveryQuery: current.discoveryQuery ?? "",
            parentUrl: current.parentUrl,
            depth: current.depth,
            publisher: current.publisher || current.domain,
            qualityScore: score,
            resourceKind: qual.resourceKind,
            discoveryPath: current.discoveryPath,
            createdAt: new Date().toISOString(),
            ...(agentResult && agentResult.success && !agentResult.fallback
              ? {
                  agentScore: agentResult.passScore,
                  agentApproved: agentResult.recommendApproval,
                  agentRationale: agentResult.rationale,
                  agentClassification: agentResult.classification,
                  agentResourceKind: agentResult.resourceKind,
                  scoreBreakdown: agentResult.scoreBreakdown,
                  agentTags: [
                    ...(agentResult.threatActors || []).map((a) => `actor:${a}`),
                    ...(agentResult.malwareFamilies || []).map((m) => `malware:${m}`),
                    ...(agentResult.cves || []).map((c) => `cve:${c}`),
                    ...(agentResult.mitreTechniques || []).map((t) => `technique:${t}`),
                  ],
                }
              : {}),
          };

          if (isMongoConfigured()) {
            await mongoInsertCrawlJobItem(jobItem);
          }
          if (sql) {
            try {
              await sql`
                insert into crawl_job_items (
                  id, job_id, source_id, url, canonical_url, title, classification,
                  decision, reason, discovery_method, discovery_query, depth, publisher
                ) values (
                  ${itemId}, ${jobId}, ${current.sourceId ?? null}, ${current.url}, ${current.canonicalUrl},
                  ${docTitle}, ${qual.classification}, 'INGESTED',
                  ${`Qualified (${qual.resourceKind}): quality ${score} with ${iocs.length} IOCs · Depth ${current.depth}`},
                  ${current.discoveryMethod}, '', ${current.depth}, ${current.publisher ?? current.domain}
                )
              `;
            } catch {
              /* ignore */
            }
          }
        } else {
          skippedCount++;
          const itemId = newId("itm");
          const jobItem: CrawlJobItem = {
            id: itemId,
            jobId,
            sourceId: current.sourceId || null,
            url: current.url,
            canonicalUrl: current.canonicalUrl,
            title: docTitle,
            classification: qual.classification,
            decision: "AWAITING_APPROVAL",
            reason: `Qualified (${qual.resourceKind}): quality ${score}. Auto-ingest is disabled in settings; held in Discovery Queue for approval.`,
            stage: "qualified",
            discoveryMethod: current.discoveryMethod,
            discoveryQuery: current.discoveryQuery ?? "",
            parentUrl: current.parentUrl,
            depth: current.depth,
            publisher: current.publisher || current.domain,
            qualityScore: score,
            resourceKind: qual.resourceKind,
            discoveryPath: current.discoveryPath,
            createdAt: new Date().toISOString(),
            ...(agentResult && agentResult.success && !agentResult.fallback
              ? {
                  agentScore: agentResult.passScore,
                  agentApproved: agentResult.recommendApproval,
                  agentRationale: agentResult.rationale,
                  agentClassification: agentResult.classification,
                  agentResourceKind: agentResult.resourceKind,
                  agentTags: [
                    ...(agentResult.threatActors || []).map((a) => `actor:${a}`),
                    ...(agentResult.malwareFamilies || []).map((m) => `malware:${m}`),
                    ...(agentResult.cves || []).map((c) => `cve:${c}`),
                    ...(agentResult.mitreTechniques || []).map((t) => `technique:${t}`),
                  ],
                }
              : {}),
          };

          if (isMongoConfigured()) {
            try {
              await mongoInsertCrawlJobItem(jobItem);
              await mongoUpsertDiscoveredResource({
                id: newId("dsc"),
                canonicalUrl: current.canonicalUrl,
                url: current.url,
                sourceId: current.sourceId || null,
                title: docTitle,
                publisher: current.publisher || current.domain,
                classification: qual.classification,
                resourceKind: qual.resourceKind,
                discoveryMethod: current.discoveryMethod,
                discoveryQuery: current.discoveryQuery ?? "",
                parentSource: current.parentSource || current.domain,
                parentUrl: current.parentUrl,
                sourceDomain: current.domain,
                contentType,
                status: "awaiting_approval",
                qualityScore: score,
                discoveryPath: current.discoveryPath,
                ...(agentResult && agentResult.success && !agentResult.fallback
                  ? {
                      agentScore: agentResult.passScore,
                      agentApproved: agentResult.recommendApproval,
                      agentRationale: agentResult.rationale,
                      agentClassification: agentResult.classification,
                      agentResourceKind: agentResult.resourceKind,
                      scoreBreakdown: agentResult.scoreBreakdown,
                      agentTags: [
                        ...(agentResult.threatActors || []).map((a) => `actor:${a}`),
                        ...(agentResult.malwareFamilies || []).map((m) => `malware:${m}`),
                        ...(agentResult.cves || []).map((c) => `cve:${c}`),
                        ...(agentResult.mitreTechniques || []).map((t) => `technique:${t}`),
                      ],
                    }
                  : {}),
              });
            } catch (mongoErr) {
              console.warn("[mongodb] report persistence error:", mongoErr);
            }
          }

          if (sql) {
            try {
              await sql`
                insert into crawl_job_items (
                  id, job_id, source_id, url, canonical_url, title, classification,
                  decision, reason, discovery_method, discovery_query, depth, publisher
                ) values (
                  ${itemId}, ${jobId}, ${current.sourceId ?? null}, ${current.url}, ${current.canonicalUrl},
                  ${docTitle}, ${qual.classification}, 'AWAITING_APPROVAL',
                  'Qualified by engine; held in Discovery Queue for manual ingestion approval',
                  ${current.discoveryMethod}, '', ${current.depth}, ${current.publisher ?? current.domain}
                )
              `;
            } catch {
              /* ignore */
            }
          }
        }
      } finally {
        currentlyProcessingUrls.delete(current.url);
        activeDomains.delete(current.domain);
        await reportLiveProgress();
      }
    }

    // AI source discovery gets what is left of the budget; its later results are only saved as sources.
    await settleWithin(aiSourceDiscovery, Math.max(0, discoveryTimeLeft()));
    for (const phi of preHarvestedItems.splice(0)) enqueue(phi);

    // Persist what discovery found before processing starts, so the count survives whatever follows.
    discoveryPhaseOver = true;
    await reportLiveProgress(true);

    // One article that never finishes (an AI call, a PDF parse or a request that does not answer) must
    // not hold its worker forever: it gets a hard budget, then its slot (and its site) is freed.
    const perItemTimeoutMs = itemTimeoutMs(config.agentTimeoutSeconds);

    // Adaptive multi-worker concurrent dispatcher loop
    while ((frontierQueue.length > 0 || activeWorkerTasks.size > 0) && evaluatedCount < configuredMax) {
      if (jobControl.cancel) {
        console.warn(`[crawler] job ${jobId} cancelled; draining ${activeWorkerTasks.size} in-flight worker(s).`);
        break;
      }
      if (Date.now() - jobStartTime > MAX_JOB_EXECUTION_TIME_MS) {
        console.warn(`[crawler] max execution time (${maxRunTimeMinutes} min) reached; terminating.`);
        break;
      }

      while (!jobControl.cancel && activeWorkerTasks.size < maxConcurrency && frontierQueue.length > 0 && evaluatedCount + activeWorkerTasks.size < configuredMax) {
        const nextItem = pickNextItem();
        if (!nextItem) break;

        const task = (async () => {
          const outcome = await settleWithin(processFrontierItem(nextItem), perItemTimeoutMs);
          if (outcome.status === "rejected") {
            console.error(`[crawler] Error processing URL ${nextItem.url}:`, outcome.reason);
          } else if (outcome.status === "timeout") {
            failedCount++;
            collector.count(nextItem.sourceId, "failed");
            currentlyProcessingUrls.delete(nextItem.url);
            activeDomains.delete(nextItem.domain);
            console.warn(`[crawler] job ${jobId}: gave up on ${nextItem.url} after ${Math.round(perItemTimeoutMs / 1000)}s (it never finished)`);
          }
        })();

        activeWorkerTasks.add(task);
        task.finally(() => {
          activeWorkerTasks.delete(task);
        });
      }

      if (activeWorkerTasks.size === 0 && frontierQueue.length === 0) {
        break;
      }

      await Promise.race([
        ...Array.from(activeWorkerTasks),
        new Promise((resolve) => setTimeout(resolve, 50)),
      ]);

      await reportLiveProgress();
    }

    // Await in-flight workers, but never forever: after the time limit or a cancel the job finalizes
    // (and releases its lock) even if a worker is still stuck.
    if (activeWorkerTasks.size > 0) {
      const drained = await settleWithin(Promise.allSettled(Array.from(activeWorkerTasks)), WORKER_DRAIN_GRACE_MS);
      if (drained.status === "timeout") {
        console.warn(`[crawler] job ${jobId}: ${activeWorkerTasks.size} worker(s) still busy after ${WORKER_DRAIN_GRACE_MS / 1000}s; finalizing without them`);
      }
    }
    await reportLiveProgress(true);

    // Feeds / sitemaps / listings whose items were cut by caps keep no validators (next run reads them in full).
    for (const left of frontierQueue) collector.markUnfinished(left.parentUrl);
    const funnel = await collector.finish({ discovered: discoveredCount });

    // 5. Finalize Job
    const latestConfig = isMongoConfigured() ? await mongoGetCrawlConfig() : await getOrCreateCrawlConfig();
    const effectiveFreq = Math.max(5, latestConfig.frequencyMinutes || config.frequencyMinutes || 60);
    const nextRun = new Date(Date.now() + effectiveFreq * 60 * 1000).toISOString();
    const completedJobUpdates = {
      status: "completed" as const,
      completedAt: new Date().toISOString(),
      discoveredCount,
      evaluatedCount,
      qualifiedCount,
      ingestedCount,
      duplicateCount,
      failedCount,
      rejectedCount,
      skippedCount,
      newSourcesCount,
      pdfGeneratedCount,
      currentStage: "indexed" as CrawlPipelineStage,
      funnel,
    };

    console.log(
      `[crawler] COMPLETED job ${jobId}: discovered=${discoveredCount}, evaluated=${evaluatedCount}, qualified=${qualifiedCount}, ingested=${ingestedCount}, duplicates=${duplicateCount}, rejected=${rejectedCount}, newSources=${newSourcesCount}`
    );

    if (isMongoConfigured()) {
      // Conditional: a cancelled job must stay "cancelled".
      await updateJobIfRunning(jobId, completedJobUpdates);
      await mongoUpdateCrawlConfig({
        lastRunAt: new Date().toISOString(),
        nextRunAt: nextRun,
      });
      // Grounded AI analysis and safe review of what this run stored, newest published first, in the
      // background ("AI analysis of new reports" in Settings). Never deletes; see ./review-decision.
      // Serverless functions end with the request, so there the Library's "Analyse with AI" does it.
      const serverless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY);
      if (latestConfig.agentLibraryAuditEnabled !== false && ingestedReportIds.length > 0 && !serverless) {
        void mongoAnalyseNewlyIngested(ingestedReportIds).catch((err) => console.warn("[ai-analysis] after crawl failed:", err));
      }
    } else {
      try {
        const sql = await getSql();
        await sql`
          update crawl_jobs
          set status = 'completed', completed_at = now(),
              discovered_count = ${discoveredCount}, qualified_count = ${qualifiedCount},
              ingested_count = ${ingestedCount}, duplicate_count = ${duplicateCount},
              failed_count = ${failedCount}, rejected_count = ${rejectedCount},
              skipped_count = ${skippedCount}
          where id = ${jobId} and status = 'running'
        `;

        await sql`
          update crawl_config
          set last_run_at = now(), next_run_at = ${nextRun}
          where id = ${config.id}
        `;
      } catch {
        /* ignore sql fallback error */
      }
    }
  } catch (jobErr) {
    const errMsg = jobErr instanceof Error ? jobErr.message : "Crawl job error";
    console.error(`[crawler] job ${jobId} failed:`, jobErr);
    jobFailed = true;
    jobErrorSummary = errMsg;
    if (isMongoConfigured()) {
      try {
        await updateJobIfRunning(jobId, {
          status: "failed",
          completedAt: new Date().toISOString(),
          errorSummary: errMsg,
        });
      } catch (updErr) {
        console.warn(`[crawler] failed to record failure for job ${jobId}:`, updErr);
      }
    }
    if (sql) {
      try {
        await sql`
          update crawl_jobs
          set status = 'failed', completed_at = now(), error_summary = ${errMsg}
          where id = ${jobId} and status = 'running'
        `;
      } catch {
        /* ignore */
      }
    }
  } finally {
    stopLockHeartbeat(jobControl);
    // Only this job's own entry: after a cancel or a hung-job release the id may be gone already.
    if (activeJobs.get(jobId) === jobControl) activeJobs.delete(jobId);
    drainingJobs.delete(jobId);
    if (isMongo) await releaseCrawlLock(jobId);
  }

  return {
    id: jobId,
    status: jobControl.cancel ? "cancelled" : jobFailed ? "failed" : "completed",
    triggerType,
    startedAt: initialJob.startedAt,
    completedAt: new Date().toISOString(),
    sourceCount: sources.length,
    discoveredCount,
    evaluatedCount,
    qualifiedCount,
    ingestedCount,
    duplicateCount,
    failedCount,
    rejectedCount,
    updatedCount: 0,
    skippedCount,
    newSourcesCount,
    pdfGeneratedCount,
    errorSummary: jobErrorSummary,
  };
}

export async function createAndRunCrawlJob(
  trigger: CrawlTrigger = "MANUAL",
  targetedQuery?: string,
  runOptions: CrawlRunOptions = {},
): Promise<CrawlJob> {
  // In-memory guard (the only guard without Mongo). A cancelled job keeps its
  // entry until its loop has drained, so this also blocks overlap with it. A hung
  // job is released first, so it cannot block crawling until a restart.
  if (activeJobs.size > 0) await releaseHungJobs();
  if (activeJobs.size > 0) {
    throw new CrawlAlreadyRunningError(Array.from(activeJobs.keys())[0]);
  }

  const id = newId("job");
  const startedAt = new Date().toISOString();
  // Reserve synchronously (no await since the check above) so concurrent calls in this process can't both start.
  const control: JobControl = { cancel: false, pause: false, startedAt: Date.now(), maxRunMs: DEFAULT_JOB_MAX_RUN_MS };
  activeJobs.set(id, control);

  if (isMongoConfigured()) {
    try {
      const cfg = await mongoGetCrawlConfig();
      const maxRunTimeMinutes = runOptions.backfill
        ? planBackfill(runOptions.backfill.months).maxRunMinutes
        : cfg.maxRunTimeMinutes && cfg.maxRunTimeMinutes > 0
          ? cfg.maxRunTimeMinutes
          : 5;
      control.maxRunMs = maxRunTimeMinutes * 60 * 1000;
      await acquireCrawlLock(id, (maxRunTimeMinutes + 5) * 60 * 1000);
      startLockHeartbeat(id, control);
    } catch (err) {
      activeJobs.delete(id);
      throw err;
    }
  }

  const initialJob: CrawlJob = {
    id,
    status: "running",
    triggerType: trigger,
    startedAt,
    completedAt: null,
    sourceCount: 0,
    discoveredCount: 0,
    evaluatedCount: 0,
    qualifiedCount: 0,
    ingestedCount: 0,
    duplicateCount: 0,
    failedCount: 0,
    rejectedCount: 0,
    updatedCount: 0,
    skippedCount: 0,
    newSourcesCount: 0,
    pdfGeneratedCount: 0,
    errorSummary: "",
    currentStage: "discovered",
  };

  if (isMongoConfigured()) {
    try {
      await mongoInsertCrawlJob(initialJob);
    } catch (err) {
      console.warn("[mongodb] createAndRunCrawlJob initial insert:", err);
    }
  } else {
    try {
      const sql = await getSql();
      await sql`
        insert into crawl_jobs (id, status, trigger_type, started_at)
        values (${id}, 'running', ${trigger}, now())
      `;
    } catch {
      /* ignore sql fallback error */
    }
  }

  // Start asynchronous crawl in background so the UI immediately shows "Running" status
  void executeCrawlJob(id, trigger, targetedQuery, runOptions).catch(async (err) => {
    console.error(`[crawler] job ${id} error:`, err);
    // executeCrawlJob normally cleans up in its finally; this covers a throw before its try block.
    stopLockHeartbeat(control);
    if (activeJobs.get(id) === control) activeJobs.delete(id);
    drainingJobs.delete(id);
    if (isMongoConfigured()) await releaseCrawlLock(id);
  });

  return initialJob;
}

export async function cancelJob(jobId: string): Promise<boolean> {
  const job = activeJobs.get(jobId) ?? drainingJobs.get(jobId);
  // Signal the dispatcher and workers, and free the crawl slot now: the job stops taking work and only
  // winds down requests already in flight, so it must not block the next crawl (it used to, until it
  // fully drained, while the history already said "Cancelled").
  if (job) {
    job.cancel = true;
    job.cancelledAt ??= Date.now();
    stopLockHeartbeat(job);
    if (activeJobs.get(jobId) === job) {
      activeJobs.delete(jobId);
      drainingJobs.set(jobId, job);
    }
  }

  let cancelled = Boolean(job);
  const cancelUpdates: Partial<CrawlJob> = {
    status: "cancelled",
    completedAt: new Date().toISOString(),
    errorSummary: "Crawl job cancelled by operator",
    currentStage: "indexed",
  };
  if (isMongoConfigured()) {
    try {
      // Conditional on "running": finished/unknown jobs are not rewritten. A job
      // running on another instance sees the status change in its next
      // telemetry update (or loses its lease) and stops taking new items.
      if (await updateJobIfRunning(jobId, cancelUpdates)) cancelled = true;
    } catch (err) {
      console.warn(`[crawler] failed to persist cancellation for ${jobId}:`, err);
    }
    // Whoever holds the lock for this job, the job is over: free the slot.
    await releaseCrawlLock(jobId, true);
  }
  try {
    const sql = await getSql();
    const res = await sql`update crawl_jobs set status = 'cancelled', completed_at = now() where id = ${jobId} and status = 'running' returning id`;
    if (res.length > 0) cancelled = true;
  } catch (err) {
    console.debug(`[crawler] SQL cancellation update skipped for ${jobId}:`, err);
  }
  invalidateCrawlerStateCache();
  return cancelled;
}

// ---------------------------------------------------------------------------
// Autonomous Background Scheduler & Concurrency Lock
// ---------------------------------------------------------------------------

export interface ScheduleCheckResult {
  triggered: boolean;
  reason: string;
  jobId?: string;
  nextRunAt?: string | null;
  lastRunAt?: string | null;
}

let isCheckingSchedule = false;

export async function checkAndTriggerScheduledCrawl(): Promise<ScheduleCheckResult> {
  // 1. In-memory guards: skip if check in progress or crawler job active
  if (isCheckingSchedule) {
    return { triggered: false, reason: "Schedule check already in progress" };
  }

  if (activeJobs.size > 0) await releaseHungJobs();
  if (activeJobs.size > 0) {
    return { triggered: false, reason: "A crawl job is currently executing in server memory" };
  }

  isCheckingSchedule = true;
  try {
    if (!isMongoConfigured()) {
      return { triggered: false, reason: "MongoDB is not configured" };
    }

    const config = await mongoGetCrawlConfig();

    if (!config.enabled) {
      return {
        triggered: false,
        reason: "Master scheduler is disabled in configuration",
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    if (config.paused) {
      return {
        triggered: false,
        reason: "Autonomous scheduler is paused in configuration",
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    // 2. Atlas document lock & active job check
    const col = await getThreatIntelCollection();
    const runningJobs = await col
      .find({ docType: "crawl_job", status: "running" })
      .sort({ startedAt: -1 })
      .limit(5)
      .toArray();

    const maxRunMs = (config.maxRunTimeMinutes || 5) * 60 * 1000;
    const now = Date.now();

    let genuinelyActiveJobFound = false;
    for (const rj of runningJobs) {
      const startedMs = rj.startedAt ? new Date(rj.startedAt).getTime() : 0;
      const elapsedMs = now - startedMs;
      // Job is active if within runtime limit and (in active memory map OR started under 30s ago)
      if (elapsedMs < maxRunMs + 30_000 && (activeJobs.has(rj.id) || elapsedMs < 30_000)) {
        genuinelyActiveJobFound = true;
        break;
      }
    }

    if (genuinelyActiveJobFound) {
      return {
        triggered: false,
        reason: "A crawl job is currently actively executing in database",
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    // 3a. Real-time mode: full crawls back to back, a short pause after each run ends. The lock is
    // the same `nextRunAt` compare-and-set as scheduled runs, so two workers never both start one.
    if (config.realTime) {
      const pauseMs = Math.min(60, Math.max(1, config.realTimePauseMinutes ?? 2)) * 60_000;
      const last = await col.find({ docType: "crawl_job" }).sort({ startedAt: -1 }).limit(1).next();
      const lastEnd = last ? Date.parse(String(last.completedAt ?? last.startedAt ?? "")) || 0 : 0;
      const readyAt = lastEnd + pauseMs;
      if (lastEnd && now < readyAt) {
        return {
          triggered: false,
          reason: `Real time: next crawl in ${Math.ceil((readyAt - now) / 1000)}s`,
          nextRunAt: new Date(readyAt).toISOString(),
          lastRunAt: config.lastRunAt,
        };
      }
      const lock = await col.updateOne(
        {
          docType: "crawl_config",
          id: config.id,
          enabled: true,
          paused: { $ne: true },
          // Free when due, unset, or still holding a later time from scheduled mode; a real-time
          // claim by another worker sits within (now, now + pause] and loses this race.
          $or: [
            { nextRunAt: { $lte: new Date(now + 10_000).toISOString() } },
            { nextRunAt: { $gt: new Date(now + pauseMs + 10_000).toISOString() } },
            { nextRunAt: null },
            { nextRunAt: { $exists: false } },
          ],
        },
        { $set: { nextRunAt: new Date(now + pauseMs).toISOString(), updatedAt: new Date().toISOString() } },
      );
      if (lock.matchedCount === 0) {
        return { triggered: false, reason: "Autonomous lock acquired by concurrent worker", nextRunAt: config.nextRunAt, lastRunAt: config.lastRunAt };
      }
      invalidateCrawlerStateCache();
      logger.info("scheduler", `[REAL-TIME CRAWL] Starting a full crawl (pause between runs ${pauseMs / 60_000}m)`);
      try {
        const job = await createAndRunCrawlJob("REALTIME");
        return { triggered: true, jobId: job.id, reason: `Real-time crawl started (${job.id})`, nextRunAt: null, lastRunAt: config.lastRunAt };
      } catch (err) {
        if (err instanceof CrawlAlreadyRunningError) return { triggered: false, reason: err.message, nextRunAt: config.nextRunAt, lastRunAt: config.lastRunAt };
        throw err;
      }
    }

    // 3. Cadence and due condition evaluation
    const freqMinutes = Math.max(5, config.frequencyMinutes || 60);
    const freqMs = freqMinutes * 60 * 1000;
    const nextRunMs = config.nextRunAt ? new Date(config.nextRunAt).getTime() : 0;
    const lastRunMs = config.lastRunAt ? new Date(config.lastRunAt).getTime() : 0;

    const isDueByNextRun = nextRunMs > 0 && now >= nextRunMs;
    const isDueByFrequency = !config.nextRunAt && (!config.lastRunAt || now - lastRunMs >= freqMs);
    const isOverdue = lastRunMs > 0 && now - lastRunMs >= freqMs && (nextRunMs === 0 || nextRunMs <= now);

    const globalDue = isDueByNextRun || isDueByFrequency || isOverdue;

    // Per-source schedules (registry hint hourly / daily / weekly): a run is due when the global cadence
    // elapsed or any source is due (at least 30 minutes after the last run); the run crawls due sources only.
    const dueSources = await listDueSourceIds(now);
    const sourceDue = dueSources.length > 0 && (lastRunMs === 0 || now - lastRunMs >= 30 * 60 * 1000);
    if (globalDue && dueSources.length === 0) {
      const nextTime = new Date(now + freqMs).toISOString();
      await col.updateOne({ docType: "crawl_config", id: config.id }, { $set: { nextRunAt: nextTime, updatedAt: new Date().toISOString() } });
      invalidateCrawlerStateCache();
      return { triggered: false, reason: "No source is due under its schedule", nextRunAt: nextTime, lastRunAt: config.lastRunAt };
    }
    const isDue = globalDue || sourceDue;

    if (!isDue) {
      const targetTime = nextRunMs > 0 ? nextRunMs : (lastRunMs > 0 ? lastRunMs + freqMs : now);
      const remainingMs = Math.max(0, targetTime - now);
      const remainingMins = Math.ceil(remainingMs / 60_000);
      return {
        triggered: false,
        reason: `Next autonomous scan scheduled in ${remainingMins} min`,
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    // 4. ATOMIC MUTEX ACQUISITION: Advance nextRunAt in Atlas before launching job
    const nextScheduledTime = new Date(now + freqMs).toISOString();

    const lockFilter: any = {
      docType: "crawl_config",
      id: config.id,
      enabled: true,
      paused: { $ne: true },
    };

    if (nextRunMs > 0) {
      lockFilter.$or = [
        { nextRunAt: { $lte: new Date(now + 10_000).toISOString() } },
        { nextRunAt: null },
        { nextRunAt: { $exists: false } },
      ];
    }

    const lockResult = await col.updateOne(lockFilter, {
      $set: {
        nextRunAt: nextScheduledTime,
        updatedAt: new Date().toISOString(),
      },
    });

    if (lockResult.matchedCount === 0) {
      return {
        triggered: false,
        reason: "Autonomous lock acquired by concurrent worker",
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    // Lock successfully acquired! Invalidate caches so UI and subscribers see updated timestamp
    invalidateCrawlerStateCache();
    logger.info(
      "scheduler",
      `[AUTONOMOUS SCAN TRIGGERED] Cadence: ${freqMinutes}m, Next run set to: ${nextScheduledTime}`,
    );

    // 5. Dispatch the scheduled crawl job with triggerType: "SCHEDULED"
    let newJob: CrawlJob;
    try {
      newJob = await createAndRunCrawlJob("SCHEDULED");
    } catch (err) {
      if (err instanceof CrawlAlreadyRunningError) {
        return { triggered: false, reason: err.message, nextRunAt: nextScheduledTime, lastRunAt: config.lastRunAt };
      }
      throw err;
    }
    return {
      triggered: true,
      jobId: newJob.id,
      reason: `Autonomous scheduled crawl dispatched successfully (${newJob.id})`,
      nextRunAt: nextScheduledTime,
      lastRunAt: config.lastRunAt,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[scheduler] Error during checkAndTriggerScheduledCrawl:", err);
    return { triggered: false, reason: `Scheduler error: ${msg}` };
  } finally {
    isCheckingSchedule = false;
  }
}

/** Crawlable registry / discovered sources that are due under their schedule hint and not backing off. */
async function listDueSourceIds(now = Date.now()): Promise<string[]> {
  let health = new Map<string, { lastCrawledAt: string | null; backoffUntil: string | null }>();
  try {
    health = await getSourceHealthMap();
  } catch {
    /* no health yet: every source is due */
  }
  return SOURCE_SEED.filter((s) => s.enabled !== false && !isStructuredSource(s))
    .filter((s) => {
      const h = health.get(s.id);
      return computeDue(s.schedule, h?.lastCrawledAt ?? null, h?.backoffUntil ?? null, now).dueNow;
    })
    .map((s) => s.id);
}

// ---------------------------------------------------------------------------
// Background Scheduler Daemon Initializer
// ---------------------------------------------------------------------------

export function startCrawlerSchedulerDaemon() {
  // One daemon per process that always runs the newest code: a dev reload swaps the tick function,
  // it never starts a second timer.
  crawlerGlobals.__aieSchedulerTick = checkAndTriggerScheduledCrawl;
  if (crawlerGlobals.__aieSchedulerDaemon) return;

  const tick = (label: string) => () => {
    void crawlerGlobals.__aieSchedulerTick?.().catch((err) => {
      console.warn(`[scheduler-daemon] ${label} tick error:`, err);
    });
  };
  // Initial schedule check after a brief server startup grace delay (5s), then every 20 seconds.
  setTimeout(tick("Initial"), 5_000).unref?.();
  const timer = setInterval(tick("Periodic"), 20_000);
  timer.unref?.();
  crawlerGlobals.__aieSchedulerDaemon = timer;
  console.log("[scheduler] Autonomous crawler scheduler daemon initialized (20s interval)");
}

// Auto-register hooks and launch daemon on module load
registerScheduleChecker(checkAndTriggerScheduledCrawl);
startCrawlerSchedulerDaemon();

// Warm the database connection as soon as the server module loads, so the first page does not
// pay the cold connection cost. Backgrounded; a failure is retried by the normal request path.
if ((() => {
  try {
    return isMongoConfigured();
  } catch (err) {
    // Production without MONGODB_URI: every request reports it; do not crash on load.
    console.error(`[boot] ${err instanceof Error ? err.message : err}`);
    return false;
  }
})()) {
  void import("../mongodb/client.server")
    .then((m) => m.getMongoDb())
    .then(() => console.log("[boot] database connection warmed"))
    .catch((err) => console.warn("[boot] database warm-up failed (will retry on first request):", err instanceof Error ? err.message : err));
}
