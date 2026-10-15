import { createContext, useContext } from "react";
import type { Evidence, EvidenceLabel, IntelAnalysis, TargetingFact } from "@/lib/aie/types";

/** Opens the source-text dialog scrolled to an evidence range. */
export const QuoteOpenContext = createContext<((evidence: Evidence) => void) | null>(null);

export function useOpenQuote() {
  return useContext(QuoteOpenContext);
}

export const LABEL_TEXT: Record<EvidenceLabel, string> = {
  observed: "Observed",
  inferred: "Inferred",
  defensive: "Defensive",
  negated: "Negated",
  hypothetical: "Hypothetical",
  reference: "Reference",
};

export const LABEL_HINT: Record<EvidenceLabel, string> = {
  observed: "The source reports the adversary doing this.",
  inferred: "Mapped from a behaviour keyword, not stated as an ATT&CK ID in the source.",
  defensive: "Mitigation, detection or hardening advice, not adversary activity.",
  negated: "The source says this did not happen, or found no evidence of it.",
  hypothetical: "A could/may/if statement, example or generic capability.",
  reference: "Background or generic ATT&CK description, not this incident.",
};

export const MAPPED_BY_TEXT: Record<"explicit_id" | "keyword" | "model", string> = {
  explicit_id: "Explicit ID in text",
  keyword: "Behaviour keyword",
  model: "AI model",
};

export const TARGET_KIND_TEXT: Record<TargetingFact["kind"], string> = {
  sector: "Sectors",
  geography: "Geographies",
  platform: "Platforms",
  victim_type: "Victim types",
  objective: "Objectives",
};

export const TARGET_STATUS_TEXT: Record<TargetingFact["status"], string> = {
  targeted: "Targeted",
  compromised: "Compromised",
  at_risk: "At risk",
  mentioned: "Mentioned",
};

export const PREDICATE_TEXT: Record<string, string> = {
  uses: "uses",
  performed: "performed",
  targeted: "targeted",
  attributed_to: "attributed to",
  communicates_with: "communicates with",
};

export const FIELD_TEXT: Record<keyof NonNullable<IntelAnalysis["fieldOrigins"]>, string> = {
  threatActors: "threat actors",
  malware: "malware",
  vulnerabilities: "vulnerabilities",
  ttps: "techniques",
  ioas: "behavioural indicators",
  detections: "detection ideas",
  hunting: "hunting ideas",
  emulation: "emulation ideas",
};

export function formatConfidence(value: number | undefined) {
  if (typeof value !== "number" || Number.isNaN(value)) return null;
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

/**
 * Resolve an evidence range inside the extracted text. Prefers the recorded
 * offsets; falls back to the first occurrence of the quote if the offsets no
 * longer line up (e.g. the text was re-normalised after analysis).
 */
export function resolveRange(
  text: string,
  evidence: Evidence,
): { start: number; end: number; exact: boolean } | null {
  const { start, end, quote } = evidence;
  if (
    Number.isInteger(start) &&
    Number.isInteger(end) &&
    start >= 0 &&
    end > start &&
    end <= text.length
  ) {
    const slice = text.slice(start, end);
    if (!quote || slice === quote || slice.trim() === quote.trim()) {
      return { start, end, exact: true };
    }
  }
  if (quote) {
    const idx = text.indexOf(quote);
    if (idx >= 0) return { start: idx, end: idx + quote.length, exact: false };
  }
  return null;
}
