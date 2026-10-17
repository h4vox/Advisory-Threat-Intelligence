/**
 * Reduces a stored library report to the technique evidence the purple path generator scores on.
 * Pure: takes the report fields it needs, no store or ATT&CK lookups.
 */
import type { IntelAnalysis } from "../types.ts";
import type { LibraryEvidence, ObservedTechnique } from "./types.ts";

const TID = /\bT\d{4}(?:\.\d{3})?\b/gi;
const ADVERSARY_LABELS = new Set(["observed", "inferred"]);

export type ReportLike = {
  id: string;
  title: string;
  publishedAt: string | null;
  sourceConfidence: number;
  analysis?: IntelAnalysis | null;
};

function idsIn(s: string | undefined | null): string[] {
  return s ? Array.from(s.matchAll(TID), (m) => m[0].toUpperCase()) : [];
}

/**
 * Techniques the report attributes to adversary activity:
 * - evidence-labelled facts (observed / inferred) with their verbatim quotes;
 * - techniques the analysis lists without a labelled passage ("mapped"), unless the evidence
 *   explicitly classes them as defensive / negated / hypothetical / reference only.
 * `position` follows the evidence chain (source order) when the report records one.
 */
export function libraryEvidenceFromReport(r: ReportLike): LibraryEvidence {
  const a = r.analysis ?? null;
  const out = new Map<string, ObservedTechnique>();
  const ev = a?.evidence;

  const positions = new Map<string, number>();
  if (ev?.chain?.orderBasis === "reported") {
    const steps = [...(ev.chain.steps ?? [])].sort((x, y) => x.order - y.order || x.position - y.position);
    let n = 0;
    for (const s of steps) for (const t of s.techniques) if (!positions.has(t.toUpperCase())) positions.set(t.toUpperCase(), n++);
  }

  for (const f of ev?.techniques ?? []) {
    if (!ADVERSARY_LABELS.has(f.label)) continue;
    const id = f.id.toUpperCase();
    const prev = out.get(id);
    const quotes = (f.evidence ?? []).map((e) => e.quote).filter(Boolean);
    if (prev) {
      if (prev.label !== "observed" && f.label === "observed") prev.label = "observed";
      for (const q of quotes) if (!prev.quotes.includes(q)) prev.quotes.push(q);
      continue;
    }
    out.set(id, { id, label: f.label as "observed" | "inferred", tactic: f.tactic || undefined, quotes, position: positions.get(id) });
  }

  const nonAdversary = new Set((ev?.excluded ?? []).map((x) => x.techniqueId.toUpperCase()));
  const listed = [
    ...(a?.ttps ?? []).flatMap(idsIn),
    ...(a?.attackChain ?? []).flatMap((s) => s.techniques.flatMap(idsIn).map((id) => ({ id, tactic: s.tactic }))),
  ];
  for (const item of listed) {
    const id = typeof item === "string" ? item : item.id;
    const tactic = typeof item === "string" ? undefined : item.tactic;
    if (out.has(id)) {
      const t = out.get(id)!;
      if (!t.tactic && tactic) t.tactic = tactic;
      continue;
    }
    if (nonAdversary.has(id)) continue;
    out.set(id, { id, label: "mapped", tactic, quotes: [], position: positions.get(id) });
  }

  for (const t of out.values()) t.quotes = t.quotes.slice(0, 3);
  return {
    reportId: r.id,
    title: r.title,
    publishedAt: r.publishedAt,
    sourceConfidence: r.sourceConfidence,
    techniques: [...out.values()],
  };
}

/** Actor / campaign names a report states (analysis lists plus evidence-labelled actors). */
export function namesInReport(r: { title?: string; analysis?: IntelAnalysis | null; extractedEntities?: { threatActors?: string[]; campaign?: string | null } }): string[] {
  const a = r.analysis;
  const names = [
    ...(a?.threatActors ?? []),
    ...(a?.evidence?.actors ?? []).filter((x) => x.label !== "negated" && x.label !== "hypothetical").map((x) => x.value),
    ...(r.extractedEntities?.threatActors ?? []),
    ...(r.extractedEntities?.campaign ? [r.extractedEntities.campaign] : []),
  ];
  return Array.from(new Set(names.map((n) => n.trim()).filter(Boolean)));
}

/** True when the report evidence records a source-reported order. */
export function hasReportedOrder(a: IntelAnalysis | null | undefined): boolean {
  return a?.evidence?.chain?.orderBasis === "reported";
}
