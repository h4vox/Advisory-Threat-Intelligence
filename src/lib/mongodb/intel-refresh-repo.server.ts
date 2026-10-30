/**
 * Intel refresh: keeps every stored report's extracted intelligence current, so the Intel Graph,
 * entity context and search map the whole library — old reports as well as new ones, whatever
 * source they came from. Two background jobs, nothing deleted:
 *
 *  1. Rules (free, fast): reports whose evidence was labelled by older rules (./evidence
 *     EVIDENCE_RULES_VERSION), that have no analysis at all, or that lack the ATT&CK references
 *     found at ingest get them rebuilt from their stored text. A rule-based analysis is replaced;
 *     an AI-written analysis keeps its lists and gets fresh evidence only.
 *  2. AI (uses quota, rate-limited by Settings → crawler `aiBackfillPerHour`, default 30): the
 *     grounded AI analysis (../aie/report-ai-analysis) runs over reports that have none, newest
 *     first. A report the AI fails on is retried after a day; two failures in a row pause the job.
 *
 * `intelCoverage()` reports how much of the library each layer covers (shown on the Intel Graph).
 */
import type { AnyBulkWriteOperation, Document } from "mongodb";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import { invalidateReportsCache, mongoGetCrawlConfig } from "./repository.server";
import { mongoAnalyseAndReviewReport } from "./library-review-repo.server";
import { EVIDENCE_RULES_VERSION, buildEvidence } from "../aie/evidence";
import { analyzeThreatIntelligence } from "../aie/attack-chain";
import { lookupAttackTechnique } from "../aie/mitre-matrix";
import { enrichAttackEntities, withAttackRefs } from "../aie/collector/enrich";
import { REPORT_AI_ANALYSIS_VERSION } from "../aie/report-ai-analysis";
import { resolveCrawlerAiAvailability } from "../aie/ai-manager";
import type { ExtractedEntities, IntelAnalysis } from "../aie/types";
import { logger } from "../aie/logger";

/** Bump to re-run the rules job over every report. */
export const INTEL_REFRESH_VERSION = 1;
export const AI_BACKFILL_DEFAULT_PER_HOUR = 30;

// Small batches, spaced out: the server stays responsive while the library is re-extracted.
const RULES_BATCH = 40;
const RULES_EVERY_MS = 45_000;
/** The Library's report list is rebuilt at most this often while a refresh runs. */
const LIST_INVALIDATE_EVERY_MS = 10 * 60_000;
const AI_EVERY_MS = 60_000;
const AI_RETRY_AFTER_MS = 24 * 3600_000;
const AI_PAUSE_AFTER_FAILURES_MS = 30 * 60_000;
const TEXT_CHARS = 200_000;

const g = globalThis as typeof globalThis & {
  __intelRefreshTimer__?: ReturnType<typeof setInterval>;
  __intelRefreshBusy__?: boolean;
  __intelAiBusy__?: boolean;
  __intelAiPausedUntil__?: number;
  __intelAiLastRun__?: number;
  __intelAiBudget__?: number;
  __intelRulesLastRun__?: number;
  __intelListInvalidatedAt__?: number;
  __intelPendingInvalidate__?: boolean;
  __intelMemLogAt__?: number;
};

/**
 * Refreshed reports reach the Library's cached report list here. Clearing that cache after every
 * batch made each Library visit reload the whole library from the database (seconds of work, a
 * lot of memory) while a refresh ran: the server slowed down until requests failed. Now at most
 * every 10 minutes, and once when the refresh finishes.
 */
function noteListChanged(done: boolean): void {
  g.__intelPendingInvalidate__ = true;
  const now = Date.now();
  if (done || now - (g.__intelListInvalidatedAt__ ?? 0) >= LIST_INVALIDATE_EVERY_MS) {
    g.__intelListInvalidatedAt__ = now;
    g.__intelPendingInvalidate__ = false;
    invalidateReportsCache();
  }
}

/** True while a crawl job runs: the background jobs wait so the crawler and the pages keep the CPU. */
async function crawlRunning(): Promise<boolean> {
  try {
    const col = await getThreatIntelCollection();
    return (await col.countDocuments({ docType: "crawl_job", status: "running" }, { limit: 1 })) > 0;
  } catch {
    return false;
  }
}

/** Logs heap use every 5 minutes when it is high, so a memory problem shows up in the log. */
function logMemory(): void {
  const now = Date.now();
  if (now - (g.__intelMemLogAt__ ?? 0) < 5 * 60_000) return;
  g.__intelMemLogAt__ = now;
  const m = process.memoryUsage();
  const limit = (globalThis as { __v8HeapLimit__?: number }).__v8HeapLimit__;
  const mb = (n: number) => Math.round(n / 1048576);
  if (!limit || m.heapUsed / limit > 0.6) console.log(`[memory] heap ${mb(m.heapUsed)} MB used${limit ? ` of ${mb(limit)} MB` : ""}, rss ${mb(m.rss)} MB`);
}

const REPORT = { docType: "report", status: { $ne: "duplicate" }, discoveryMethod: { $ne: "structured_sync" } };

/** Reports whose rule-based intel is out of date (and not yet refreshed under this version). */
function staleFilter(): Document {
  return {
    ...REPORT,
    "intelRefresh.version": { $ne: INTEL_REFRESH_VERSION },
    $or: [
      { analysis: null },
      { analysis: { $exists: false } },
      { "analysis.evidence.rules": { $ne: EVIDENCE_RULES_VERSION } },
      { "extractedEntities.attackRefs": { $exists: false } },
    ],
  };
}

/** One batch of the rules job. Returns how many reports were refreshed. */
export async function mongoRefreshReportIntel(batch = RULES_BATCH): Promise<{ refreshed: number; remaining: number }> {
  if (!isMongoConfigured()) return { refreshed: 0, remaining: 0 };
  const col = await getThreatIntelCollection();
  const docs = await col
    .find(staleFilter(), {
      projection: { _id: 0, id: 1, title: 1, classification: 1, analysis: 1, extractedEntities: 1, extractedText: { $substrCP: ["$extractedText", 0, TEXT_CHARS] } },
    })
    .limit(batch)
    .toArray()
    .catch(async () =>
      // Older servers without projection expressions: read the whole text.
      col.find(staleFilter(), { projection: { _id: 0, id: 1, title: 1, classification: 1, analysis: 1, extractedEntities: 1, extractedText: 1 } }).limit(batch).toArray(),
    );
  const at = new Date().toISOString();
  const ops: AnyBulkWriteOperation<Document>[] = [];
  for (const d of docs) {
    // ~30 ms of CPU per report: let requests run between reports.
    await new Promise((r) => setImmediate(r));
    const text = String(d.extractedText ?? "").slice(0, TEXT_CHARS);
    const title = String(d.title ?? "");
    const $set: Document = { intelRefresh: { version: INTEL_REFRESH_VERSION, at } };
    if (text.trim().length >= 200) {
      try {
        const analysis = d.analysis as IntelAnalysis | null | undefined;
        if (!analysis || analysis.method === "heuristic") {
          $set.analysis = analyzeThreatIntelligence(text, title, String(d.classification ?? "THREAT_REPORT"));
        } else {
          $set["analysis.evidence"] = buildEvidence(text, { title, lookup: lookupAttackTechnique });
        }
        const ee = d.extractedEntities as ExtractedEntities | undefined;
        if (!ee?.attackRefs) $set.extractedEntities = withAttackRefs(ee, enrichAttackEntities(title, text));
      } catch (err) {
        console.warn(`[intel-refresh] ${d.id}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    ops.push({ updateOne: { filter: { docType: "report", id: d.id }, update: { $set } } });
  }
  if (ops.length) await col.bulkWrite(ops, { ordered: false });
  const remaining = docs.length < batch ? 0 : await col.countDocuments(staleFilter());
  if (ops.length || (remaining === 0 && g.__intelPendingInvalidate__)) noteListChanged(remaining === 0);
  if (ops.length) logger.intel("REFRESH", `Re-extracted intelligence for ${ops.length} report${ops.length === 1 ? "" : "s"} (current rules)`, { remaining });
  return { refreshed: ops.length, remaining };
}

/** Reports the AI has not analysed under the current analysis version (retry failures after a day). */
function aiPendingFilter(now = Date.now()): Document {
  return {
    ...REPORT,
    status: { $nin: ["rejected", "duplicate"] },
    "aiAnalysis.version": { $ne: REPORT_AI_ANALYSIS_VERSION },
    $or: [{ "aiAnalysisAttempt.at": { $exists: false } }, { "aiAnalysisAttempt.at": { $lt: new Date(now - AI_RETRY_AFTER_MS).toISOString() } }],
  };
}

/** One step of the AI job: analyses up to `n` reports. */
export async function mongoAiBackfillStep(n: number): Promise<{ analysed: number; failed: number }> {
  if (!isMongoConfigured() || n <= 0) return { analysed: 0, failed: 0 };
  const col = await getThreatIntelCollection();
  const next = await col.find(aiPendingFilter(), { projection: { _id: 0, id: 1 } }).sort({ publishedAt: -1, ingestedAt: -1 }).limit(n).toArray();
  let analysed = 0;
  let failed = 0;
  for (const d of next) {
    const id = String(d.id);
    try {
      await mongoAnalyseAndReviewReport(id);
      analysed++;
    } catch (err) {
      failed++;
      const msg = err instanceof Error ? err.message : String(err);
      await col.updateOne({ docType: "report", id }, { $set: { aiAnalysisAttempt: { at: new Date().toISOString(), error: msg.slice(0, 300) } } });
      if (failed >= 2) break;
    }
  }
  if (analysed || failed) logger.intel("AI-BACKFILL", `AI analysed ${analysed} report${analysed === 1 ? "" : "s"}${failed ? `, ${failed} failed` : ""}`);
  return { analysed, failed };
}

export type IntelCoverageStatus = {
  available: boolean;
  reports: number;
  /** Reports whose evidence follows the current rules. */
  rulesCurrent: number;
  /** Reports with a current grounded AI analysis. */
  aiAnalysed: number;
  aiPerHour: number;
  aiPaused: boolean;
};

export async function intelCoverage(): Promise<IntelCoverageStatus> {
  if (!isMongoConfigured()) return { available: false, reports: 0, rulesCurrent: 0, aiAnalysed: 0, aiPerHour: 0, aiPaused: false };
  const col = await getThreatIntelCollection();
  const visible = { ...REPORT, status: { $nin: ["rejected", "duplicate"] } };
  const [reports, rulesCurrent, aiAnalysed, cfg] = await Promise.all([
    col.countDocuments(visible),
    col.countDocuments({ ...visible, "analysis.evidence.rules": EVIDENCE_RULES_VERSION }),
    col.countDocuments({ ...visible, "aiAnalysis.version": REPORT_AI_ANALYSIS_VERSION }),
    mongoGetCrawlConfig().catch(() => null),
  ]);
  return {
    available: true,
    reports,
    rulesCurrent,
    aiAnalysed,
    aiPerHour: cfg?.aiBackfillPerHour ?? AI_BACKFILL_DEFAULT_PER_HOUR,
    aiPaused: (g.__intelAiPausedUntil__ ?? 0) > Date.now(),
  };
}

async function tick(): Promise<void> {
  if (!isMongoConfigured()) return;
  logMemory();
  // A running crawl has priority: both jobs wait for it to finish.
  if (await crawlRunning()) return;
  const now = Date.now();
  if (!g.__intelRefreshBusy__ && now - (g.__intelRulesLastRun__ ?? 0) >= RULES_EVERY_MS) {
    g.__intelRefreshBusy__ = true;
    g.__intelRulesLastRun__ = now;
    try {
      await mongoRefreshReportIntel();
    } catch (err) {
      console.warn("[intel-refresh] rules batch failed:", err instanceof Error ? err.message : err);
    } finally {
      g.__intelRefreshBusy__ = false;
    }
  }
  if (g.__intelAiBusy__ || now - (g.__intelAiLastRun__ ?? 0) < AI_EVERY_MS || (g.__intelAiPausedUntil__ ?? 0) > now) return;
  const cfg = await mongoGetCrawlConfig().catch(() => null);
  const perHour = cfg?.aiBackfillPerHour ?? AI_BACKFILL_DEFAULT_PER_HOUR;
  if (!perHour) return;
  // A per-minute budget that carries fractions over (30/hour = one report every two minutes).
  g.__intelAiBudget__ = Math.min(perHour / 60 + (g.__intelAiBudget__ ?? 0), Math.max(1, perHour / 6));
  const n = Math.floor(g.__intelAiBudget__);
  g.__intelAiLastRun__ = now;
  if (n < 1) return;
  // No provider configured: wait (no report is marked as failed for it).
  const ai = await resolveCrawlerAiAvailability().catch(() => ({ usable: false }));
  if (!ai.usable) {
    g.__intelAiPausedUntil__ = Date.now() + 5 * 60_000;
    g.__intelAiBudget__ = 0;
    return;
  }
  g.__intelAiBusy__ = true;
  try {
    const r = await mongoAiBackfillStep(n);
    g.__intelAiBudget__ -= r.analysed + r.failed;
    if (r.failed >= 2 || (r.failed && !r.analysed)) {
      g.__intelAiPausedUntil__ = Date.now() + AI_PAUSE_AFTER_FAILURES_MS;
      logger.intel("AI-BACKFILL", "Paused for 30 minutes after AI failures");
    }
  } catch (err) {
    console.warn("[intel-refresh] AI step failed:", err instanceof Error ? err.message : err);
  } finally {
    g.__intelAiBusy__ = false;
  }
}

/** Starts the background refresh once per process (a dev reload reuses the timer). */
export function startIntelRefreshDaemon(): void {
  if (g.__intelRefreshTimer__) return;
  const run = () => void tick().catch(() => undefined);
  setTimeout(run, 15_000).unref?.();
  const timer = setInterval(run, 15_000);
  timer.unref?.();
  g.__intelRefreshTimer__ = timer;
}
