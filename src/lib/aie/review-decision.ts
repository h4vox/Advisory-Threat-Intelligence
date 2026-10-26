/**
 * What the AI review may do to a report. The AI's opinion alone never removes anything:
 *
 *   - nothing is ever deleted; hiding is reversible (Library → Hidden → Restore)
 *   - a report an analyst restored or kept is never hidden or flagged again
 *   - a report with evidence of technical value (indicators, CVEs, ATT&CK techniques, an attack
 *     chain, named actors or malware, a passed technical-depth check, a high quality score, a
 *     structured source) is never hidden: when the AI calls it not useful, it is flagged for an
 *     analyst instead
 *   - an uncertain or low-confidence verdict flags the report for review
 *   - a report is hidden only when the AI is confident it is not useful AND the deterministic
 *     technical-depth check fails AND none of the evidence above is present
 *   - when the AI fails, nothing changes
 *
 * Reports the earlier AI audit hid while they carry such evidence are restored and flagged, so
 * useful research it removed comes back for an analyst to confirm.
 *
 * Pure, unit-tested.
 */
import type { AiReview } from "./report-ai-analysis.ts";

export const REVIEW_DECISION_VERSION = 1;

/** The AI must be at least this sure before a report without evidence of value may be hidden. */
export const HIDE_MIN_CONFIDENCE = 0.85;

export type ReviewSignals = {
  iocCount: number;
  cves: number;
  techniques: number;
  attackChainSteps: number;
  /** Named actors, malware or campaigns. */
  entities: number;
  /** 0–1. */
  qualityScore: number;
  /** The deterministic technical-depth check (./technical-depth) passed. */
  depthPass: boolean;
  wordCount: number;
  structured?: boolean;
  /** An analyst restored the report: never hide it again. */
  analystKeep?: boolean;
};

/** Who hid the report, when it is hidden now. */
export type HiddenBy = "rules" | "analyst" | "ai" | null;

export type ReviewAction = "keep" | "flag" | "hide" | "restore_and_flag" | "unchanged";

export type ReviewDecision = {
  action: ReviewAction;
  /** Plain-language reason shown to analysts. */
  reason: string;
  /** Evidence of technical value that protected the report. */
  protectedBy: string[];
};

export function protectiveEvidence(s: ReviewSignals): string[] {
  const out: string[] = [];
  if (s.analystKeep) out.push("restored by an analyst");
  if (s.structured) out.push("structured intelligence source");
  if (s.iocCount >= 2) out.push(`${s.iocCount} indicators`);
  if (s.cves > 0) out.push(`${s.cves} CVE${s.cves === 1 ? "" : "s"}`);
  if (s.techniques > 0) out.push(`${s.techniques} ATT&CK technique${s.techniques === 1 ? "" : "s"}`);
  if (s.attackChainSteps > 0) out.push("an attack chain");
  if (s.entities >= 2) out.push("named actors or malware");
  if (s.depthPass) out.push("passed the technical-depth check");
  if (s.qualityScore >= 0.7) out.push(`quality ${Math.round(s.qualityScore * 100)}%`);
  return out;
}

/**
 * `allowHide` is the "Let the AI review hide reports" setting: when off (the default), a report the
 * AI would hide is flagged for review instead.
 */
export function decideReviewAction(review: AiReview | null, signals: ReviewSignals, hiddenBy: HiddenBy, allowHide = false): ReviewDecision {
  const protectedBy = protectiveEvidence(signals);
  if (!review) return { action: "unchanged", reason: "The AI review did not complete; nothing was changed.", protectedBy };

  // Hidden by the rules or an analyst: the review records its opinion and never overrides them.
  if (hiddenBy === "rules" || hiddenBy === "analyst") {
    return {
      action: "unchanged",
      reason: hiddenBy === "analyst" ? "Hidden by an analyst; the AI review does not change that." : "Hidden by the library rules; restore it to keep it.",
      protectedBy,
    };
  }

  const pct = Math.round(review.confidence * 100);
  const why = review.reasons.length ? `: ${review.reasons.slice(0, 2).join("; ")}` : "";

  // An analyst already decided to keep it: the review records its opinion and never re-flags it.
  if (signals.analystKeep && hiddenBy === null) {
    return {
      action: "keep",
      reason: review.verdict === "useful" ? `Useful threat intelligence (${pct}% sure)${why}. Kept by an analyst.` : `Kept by an analyst. The AI ${review.verdict === "unsure" ? "was unsure" : `judged it not useful (${pct}% sure)`}${why}.`,
      protectedBy,
    };
  }

  if (hiddenBy === "ai") {
    // Hidden earlier by the AI audit alone. Bring back anything with evidence of value.
    if (review.verdict === "useful" || protectedBy.length > 0) {
      return {
        action: "restore_and_flag",
        reason: `Restored: hidden earlier by the AI audit, but ${review.verdict === "useful" ? "the review finds it useful" : `it carries ${protectedBy.join(", ")}`}. Confirm it.`,
        protectedBy,
      };
    }
    return { action: "unchanged", reason: `Stays hidden: the review agrees it is not threat research (${pct}% sure)${why}.`, protectedBy };
  }

  if (review.verdict === "useful") return { action: "keep", reason: `Useful threat intelligence (${pct}% sure)${why}.`, protectedBy };

  if (review.verdict === "unsure") return { action: "flag", reason: `The AI is unsure whether this is useful${why}. Kept for an analyst to decide.`, protectedBy };

  // not_useful
  if (protectedBy.length > 0) {
    return { action: "flag", reason: `The AI judged it not useful${why}, but it carries ${protectedBy.join(", ")}. Kept for an analyst to decide.`, protectedBy };
  }
  if (review.confidence < HIDE_MIN_CONFIDENCE) {
    return { action: "flag", reason: `The AI judged it not useful with ${pct}% confidence${why}. Kept for an analyst to decide.`, protectedBy };
  }
  if (!allowHide) {
    return {
      action: "flag",
      reason: `The AI is ${pct}% sure this is not threat research${why}, and it has no indicators, techniques or technical depth. Kept for you to decide (the AI review does not hide reports unless that is turned on in Settings).`,
      protectedBy,
    };
  }
  return {
    action: "hide",
    reason: `Hidden by the AI review (${pct}% sure it is not threat research${why}); no indicators, techniques or technical depth found. Restore it from Hidden if this is wrong.`,
    protectedBy,
  };
}
