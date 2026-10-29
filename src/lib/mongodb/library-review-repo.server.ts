/**
 * AI analysis and review of stored reports (../aie/report-ai-analysis, ../aie/review-decision).
 *
 * One report at a time: the active AI provider analyses the report text, every item is checked
 * against that text, and the review decides what may happen to the report. Nothing is deleted.
 * The report text, the stored indicators and the deterministic analysis are never changed; the AI
 * results live beside them in `aiAnalysis`, and the review in `review` / `needsReview`.
 *
 * Also recovers reports the earlier AI audit hid although they carry evidence of value: they are
 * restored and flagged for an analyst ("Needs review"), without any AI call.
 */
import type { Document } from "mongodb";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import { invalidateDashboardCache, invalidateReportsCache, mongoGetCrawlConfig } from "./repository.server";
import { runUnifiedReportAnalysis } from "../aie/ai-manager";
import { getTechnique } from "../aie/attack-knowledge";
import { assessTechnicalDepth } from "../aie/technical-depth";
import { REPORT_AI_ANALYSIS_VERSION, type ReportAiAnalysis } from "../aie/report-ai-analysis";
import { PUBLISHED_DATE_VERSION, type PublishedDate } from "../aie/published-date";
import {
  REVIEW_DECISION_VERSION,
  decideReviewAction,
  protectiveEvidence,
  type HiddenBy,
  type ReviewAction,
  type ReviewSignals,
} from "../aie/review-decision";

export type ReportReview = {
  version: number;
  action: ReviewAction;
  reason: string;
  protectedBy: string[];
  verdict?: "useful" | "not_useful" | "unsure";
  confidence?: number;
  reviewedAt: string;
  /** "ai" when the AI review decided; "recovery" for the restore of reports the earlier audit hid. */
  by: "ai" | "recovery" | "analyst";
};

export type AnalyseReportResult = {
  id: string;
  title: string;
  action: ReviewAction;
  reason: string;
  analysis: ReportAiAnalysis;
};

const REVIEW_TEXT_CHARS = 150_000;

/** Reports the earlier AI audit hid (it set no `rejectedBy`): eligible for recovery and re-review. */
const OLD_AUDIT_REASON = /^Rejected by (?:AI\b|Quality Gate:)/;

const PROJECTION = {
  _id: 0,
  id: 1,
  title: 1,
  url: 1,
  publisher: 1,
  sourceName: 1,
  status: 1,
  previousStatus: 1,
  rejectedBy: 1,
  aiAuditReason: 1,
  publishedAt: 1,
  publishedDate: 1,
  extractedText: 1,
  iocs: 1,
  qualityScore: 1,
  wordCount: 1,
  discoveryMethod: 1,
  structured: 1,
  "extractedEntities.cves": 1,
  "extractedEntities.techniques": 1,
  "analysis.attackChain": 1,
  "analysis.threatActors": 1,
  "analysis.malware": 1,
  "gate.override": 1,
  "gate.verdict": 1,
};

function len(v: unknown): number {
  return Array.isArray(v) ? v.filter((x) => x && x !== "None Identified").length : 0;
}

export function hiddenByOf(doc: Document): HiddenBy {
  if (doc.status !== "rejected") return null;
  if (doc.rejectedBy === "rules" || doc.rejectedBy === "analyst") return doc.rejectedBy;
  if (doc.rejectedBy === "ai-review") return "ai";
  // The library rules would hide it too: their decision stands.
  if (doc.gate?.verdict === "reject") return "rules";
  return OLD_AUDIT_REASON.test(String(doc.aiAuditReason ?? "")) ? "ai" : "rules";
}

function signalsOf(doc: Document, ai?: ReportAiAnalysis | null): ReviewSignals {
  const text = String(doc.extractedText ?? "").slice(0, REVIEW_TEXT_CHARS);
  const depth = text.length >= 300 ? assessTechnicalDepth({ title: String(doc.title ?? ""), url: String(doc.url ?? ""), text }) : null;
  return {
    iocCount: Math.max(len(doc.iocs), ai?.iocs.length ?? 0),
    cves: len(doc.extractedEntities?.cves),
    techniques: len(doc.extractedEntities?.techniques),
    attackChainSteps: Math.max(len(doc.analysis?.attackChain), ai?.attackChain.length ?? 0),
    entities: len(doc.analysis?.threatActors) + len(doc.analysis?.malware),
    qualityScore: Number(doc.qualityScore ?? 0) || 0,
    depthPass: Boolean(depth?.pass),
    wordCount: Number(doc.wordCount ?? 0) || 0,
    structured: Boolean(doc.structured) || doc.discoveryMethod === "structured_sync",
    analystKeep: doc.gate?.override === "keep",
  };
}

/** The $set / $unset for a review decision. Hiding keeps the previous status for Restore. */
function reviewUpdate(doc: Document, review: ReportReview): { $set: Document; $unset?: Document } {
  const at = review.reviewedAt;
  const $set: Document = { review, updatedAt: at };
  switch (review.action) {
    case "keep":
      $set.needsReview = false;
      break;
    case "flag":
      $set.needsReview = true;
      break;
    case "hide":
      $set.needsReview = false;
      $set.status = "rejected";
      $set.previousStatus = doc.status && doc.status !== "rejected" ? doc.status : "acquired";
      $set.rejectedBy = "ai-review";
      $set.aiAuditReason = review.reason;
      break;
    case "restore_and_flag":
      $set.needsReview = true;
      $set.status = doc.previousStatus && doc.previousStatus !== "rejected" ? doc.previousStatus : "acquired";
      $set.aiAuditReason = review.reason;
      return { $set, $unset: { rejectedBy: "", previousStatus: "" } };
    case "unchanged":
      break;
  }
  return { $set };
}

/**
 * Analyses one report with AI and applies the review decision. Throws when the report does not
 * exist or the AI fails; in that case nothing is written.
 */
export async function mongoAnalyseAndReviewReport(id: string, opts: { signal?: AbortSignal } = {}): Promise<AnalyseReportResult> {
  if (!isMongoConfigured()) throw new Error("AI analysis needs the MongoDB library.");
  const col = await getThreatIntelCollection();
  const doc = await col.findOne({ docType: "report", id }, { projection: PROJECTION });
  if (!doc) throw new Error(`Report not found: ${id}`);
  const text = String(doc.extractedText ?? "");
  if (text.trim().length < 80) throw new Error("This report has too little text to analyse.");

  const analysis = await runUnifiedReportAnalysis({
    title: String(doc.title ?? ""),
    url: String(doc.url ?? ""),
    publisher: String(doc.publisher || doc.sourceName || ""),
    publishedAt: doc.publishedAt ?? null,
    text,
    techniqueName: (tid) => getTechnique(tid)?.name,
    signal: opts.signal,
  });

  const allowHide = Boolean((await mongoGetCrawlConfig().catch(() => null))?.agentAutoPruneJunkEnabled);
  const decision = decideReviewAction(analysis.review, signalsOf(doc, analysis), hiddenByOf(doc), allowHide);
  const review: ReportReview = {
    version: REVIEW_DECISION_VERSION,
    action: decision.action,
    reason: decision.reason,
    protectedBy: decision.protectedBy,
    verdict: analysis.review.verdict,
    confidence: analysis.review.confidence,
    reviewedAt: analysis.analysedAt,
    by: "ai",
  };
  const update = reviewUpdate(doc, review);
  update.$set.aiAnalysis = analysis;
  // The AI's grounded emulation grade sits beside the rules' grade (the Library prefers it).
  if (analysis.emulation) {
    update.$set["emulation.ai"] = {
      grade: analysis.emulation.grade,
      reproducible: analysis.emulation.reproducible,
      verifiedSteps: analysis.emulation.steps.length,
      at: analysis.analysedAt,
    };
  }
  // A date line the AI located and AIE verified in the text fills a missing publication date only.
  if (!doc.publishedAt && analysis.publishedDate) {
    const publishedDate: PublishedDate = {
      publishedAt: analysis.publishedDate.date,
      sourceUpdatedAt: null,
      source: "ai",
      confidence: "medium",
      evidence: `"${analysis.publishedDate.quote.slice(0, 120)}"`,
      version: PUBLISHED_DATE_VERSION,
    };
    update.$set.publishedAt = publishedDate.publishedAt;
    update.$set.publishedDate = publishedDate;
  }
  await col.updateOne({ docType: "report", id }, update);
  invalidateReportsCache();
  invalidateDashboardCache();
  return { id, title: String(doc.title ?? ""), action: decision.action, reason: decision.reason, analysis };
}

/**
 * Reports to analyse next: visible reports without a current AI analysis, newest publication date
 * first (undated last), then reports hidden by the earlier AI audit so they get a fair second look.
 */
export async function mongoReportsToAnalyse(limit = 10, onlyIds?: string[]): Promise<Array<{ id: string; title: string }>> {
  if (!isMongoConfigured()) return [];
  const col = await getThreatIntelCollection();
  const n = Math.max(1, Math.min(50, limit));
  const notAnalysed = { "aiAnalysis.version": { $ne: REPORT_AI_ANALYSIS_VERSION } };
  const scope = onlyIds?.length ? { id: { $in: onlyIds } } : {};
  const visible = await col
    .find({ docType: "report", status: { $nin: ["rejected", "duplicate"] }, discoveryMethod: { $ne: "structured_sync" }, ...notAnalysed, ...scope }, { projection: { _id: 0, id: 1, title: 1 } })
    .sort({ publishedAt: -1, ingestedAt: -1 })
    .limit(n)
    .toArray();
  const out = visible.map((d) => ({ id: String(d.id), title: String(d.title ?? "") }));
  if (out.length < n && !onlyIds?.length) {
    const hidden = await col
      .find({ docType: "report", status: "rejected", rejectedBy: { $exists: false }, aiAuditReason: OLD_AUDIT_REASON, ...notAnalysed }, { projection: { _id: 0, id: 1, title: 1 } })
      .sort({ publishedAt: -1, ingestedAt: -1 })
      .limit(n - out.length)
      .toArray();
    out.push(...hidden.map((d) => ({ id: String(d.id), title: String(d.title ?? "") })));
  }
  return out;
}

/**
 * Restores reports the earlier AI audit hid although they carry evidence of value (indicators,
 * CVEs, techniques, an attack chain, named actors or malware, technical depth, high quality), and
 * flags them for an analyst. Deterministic: no AI call. Each report is considered once.
 */
export async function mongoRecoverAiHiddenReports(limit = 200): Promise<{ restored: number; checked: number; remaining: number }> {
  if (!isMongoConfigured()) return { restored: 0, checked: 0, remaining: 0 };
  const col = await getThreatIntelCollection();
  const filter = { docType: "report", status: "rejected", rejectedBy: { $exists: false }, aiAuditReason: OLD_AUDIT_REASON, "review.by": { $nin: ["recovery", "ai", "analyst"] } };
  const docs = await col.find(filter, { projection: PROJECTION }).limit(Math.max(1, Math.min(500, limit))).toArray();
  const at = new Date().toISOString();
  let restored = 0;
  for (const doc of docs) {
    const protectedBy = hiddenByOf(doc) === "ai" ? protectiveEvidence(signalsOf(doc)) : [];
    const review: ReportReview = protectedBy.length
      ? {
          version: REVIEW_DECISION_VERSION,
          action: "restore_and_flag",
          reason: `Restored: the earlier AI audit hid it, but it carries ${protectedBy.join(", ")}. Confirm it.`,
          protectedBy,
          reviewedAt: at,
          by: "recovery",
        }
      : { version: REVIEW_DECISION_VERSION, action: "unchanged", reason: "Hidden by the earlier AI audit; no evidence of technical value found.", protectedBy, reviewedAt: at, by: "recovery" };
    if (review.action === "restore_and_flag") restored++;
    await col.updateOne({ docType: "report", id: doc.id }, reviewUpdate(doc, review));
  }
  if (restored) {
    invalidateReportsCache();
    invalidateDashboardCache();
  }
  return { restored, checked: docs.length, remaining: await col.countDocuments(filter) };
}

/** An analyst settles a flagged report: keep it (clears the flag) or hide it (reversible). */
export async function mongoResolveReview(id: string, decision: "keep" | "hide", by: string): Promise<{ ok: boolean }> {
  if (!isMongoConfigured()) return { ok: false };
  const col = await getThreatIntelCollection();
  const doc = await col.findOne({ docType: "report", id }, { projection: PROJECTION });
  if (!doc) return { ok: false };
  const at = new Date().toISOString();
  const review: ReportReview = {
    version: REVIEW_DECISION_VERSION,
    action: decision === "keep" ? "keep" : "unchanged",
    reason: decision === "keep" ? `Confirmed useful by ${by}.` : `Hidden by ${by} after review.`,
    protectedBy: [],
    reviewedAt: at,
    by: "analyst",
  };
  const $set: Document = { review, needsReview: false, updatedAt: at };
  if (decision === "keep") {
    // An analyst's keep is final: the rules and the AI review never hide it again.
    $set["gate.override"] = "keep";
  } else if (doc.status !== "rejected") {
    Object.assign($set, { previousStatus: doc.status ?? "acquired", status: "rejected", rejectedBy: "analyst", aiAuditReason: `Hidden by ${by}`, "gate.override": "hide" });
  }
  await col.updateOne({ docType: "report", id }, { $set });
  invalidateReportsCache();
  invalidateDashboardCache();
  return { ok: true };
}

const queue = globalThis as typeof globalThis & { __aiAnalysisQueue__?: boolean };

/**
 * After a crawl: analyses newly ingested reports, newest published first, one at a time on the
 * background agent lane. Runs one queue at a time and stops when the provider fails twice in a row.
 */
export async function mongoAnalyseNewlyIngested(ids: string[], max = 10): Promise<{ analysed: number; failed: number }> {
  if (!isMongoConfigured() || ids.length === 0 || queue.__aiAnalysisQueue__) return { analysed: 0, failed: 0 };
  queue.__aiAnalysisQueue__ = true;
  let analysed = 0;
  let failed = 0;
  let failedInRow = 0;
  try {
    const next = await mongoReportsToAnalyse(max, ids.slice(0, 200));
    for (const item of next) {
      try {
        await mongoAnalyseAndReviewReport(item.id);
        analysed++;
        failedInRow = 0;
      } catch (err) {
        failed++;
        failedInRow++;
        console.warn(`[ai-analysis] ${item.id}: ${err instanceof Error ? err.message : String(err)}`);
        if (failedInRow >= 2) break;
      }
    }
  } finally {
    queue.__aiAnalysisQueue__ = false;
  }
  if (analysed || failed) console.log(`[ai-analysis] after crawl: ${analysed} analysed, ${failed} failed`);
  return { analysed, failed };
}
