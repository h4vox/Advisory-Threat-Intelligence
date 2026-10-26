/**
 * AI analysis and review server functions (storage: ../mongodb/library-review-repo.server).
 *
 *   analyseReportWithAi    grounded AI analysis of one report, then the safe review decision
 *   reportsToAnalyse       the next reports to analyse: newest published first
 *   recoverHiddenReports   restores reports the earlier AI audit hid that carry evidence of value
 *   resolveReportReview    an analyst keeps or hides a report flagged "Needs review"
 *
 * The review never deletes. See ./review-decision for exactly what it may do.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import {
  mongoAnalyseAndReviewReport,
  mongoRecoverAiHiddenReports,
  mongoReportsToAnalyse,
  mongoResolveReview,
} from "../mongodb/library-review-repo.server";

const reportId = z.string().min(1).max(200);

export const analyseReportWithAi = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: reportId }))
  .handler(async ({ data }) => {
    try {
      const r = await mongoAnalyseAndReviewReport(data.id);
      return {
        ok: true as const,
        id: r.id,
        title: r.title,
        action: r.action,
        reason: r.reason,
        verdict: r.analysis.review.verdict,
        confidence: r.analysis.review.confidence,
        provider: r.analysis.provider,
        counts: { iocs: r.analysis.iocs.length, steps: r.analysis.attackChain.length, findings: r.analysis.keyFindings.length },
        dropped: r.analysis.dropped,
      };
    } catch (err) {
      return { ok: false as const, id: data.id, error: err instanceof Error ? err.message : "AI analysis failed." };
    }
  });

export const reportsToAnalyse = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ limit: z.number().int().min(1).max(50).optional() }).optional())
  .handler(async ({ data }) => mongoReportsToAnalyse(data?.limit ?? 10));

export const recoverHiddenReports = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .handler(async () => mongoRecoverAiHiddenReports(200));

export const resolveReportReview = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: reportId, decision: z.enum(["keep", "hide"]) }))
  .handler(async ({ data, context }) => {
    const by = context.identity.username ?? context.userEmail ?? "an analyst";
    return mongoResolveReview(data.id, data.decision, by);
  });
