/**
 * AI brief for one entity of the intelligence graph: a short assessment of what the library says
 * about it, its notable relationships, possible hidden links worth checking and gaps.
 *
 * Grounded: the model sees only facts taken from the graph (entities, links with report counts and
 * confidence, similar entities, report titles), each with an ID. Every point it makes must cite
 * those IDs; points that cite nothing known are dropped, and IDs it invents are removed.
 * Pure; unit-tested.
 */
import type { SimilarEntity } from "./analyze.ts";
import type { GraphEdge, GraphNode, GraphReportRef } from "./types.ts";
import { NODE_TYPE_LABEL, PREDICATE_LABEL } from "./types.ts";

export type BriefFacts = {
  node: GraphNode;
  links: Array<{ edge: GraphEdge; other: GraphNode; outgoing: boolean }>;
  similar: SimilarEntity[];
  reports: GraphReportRef[];
};

export type BriefPoint = { text: string; refs: string[] };
export type GraphBrief = {
  summary: string;
  points: BriefPoint[];
  hiddenLinks: BriefPoint[];
  gaps: string[];
  dropped: number;
  provider: string;
  generatedAt: string;
};

export const BRIEF_SYSTEM = `You are a senior cyber threat intelligence analyst. You write short, precise assessments for defenders from a knowledge graph built from published threat reports. You use only the facts given, cite them by ID, and say plainly when the evidence is thin. You never invent entities, relationships, reports or IDs. Answer with one JSON object only.`;

function fmtDate(d: string | null | undefined) {
  return d ? d.slice(0, 10) : "undated";
}

export function buildBriefPrompt(f: BriefFacts): string {
  const n = f.node;
  const lines: string[] = [];
  lines.push(`ENTITY [${n.id}] ${NODE_TYPE_LABEL[n.type].one}: ${n.label}${n.attackId ? ` (ATT&CK ${n.attackId})` : ""}${n.aliases?.length ? `; also written as ${n.aliases.join(", ")}` : ""}`);
  lines.push(`Seen in ${n.reportCount} report(s), first ${fmtDate(n.firstSeen)}, last ${fmtDate(n.lastSeen)}.`);
  lines.push("", "LINKS (strongest first; 'stated' = a report states it in one sentence, 'co-reported' = both appear in the same report):");
  for (const l of f.links.slice(0, 40)) {
    const rel = PREDICATE_LABEL[l.edge.predicate];
    const phrase = l.outgoing ? `${n.label} ${rel} ${l.other.label}` : `${l.other.label} ${rel} ${n.label}`;
    lines.push(`- [${l.other.id}] ${phrase} — ${NODE_TYPE_LABEL[l.other.type].one.toLowerCase()}, ${l.edge.basis}, ${l.edge.weight} report(s), confidence ${l.edge.confidence}`);
  }
  if (f.similar.length) {
    lines.push("", "SIMILAR ENTITIES (shared behaviour/tooling/targets, weighted by rarity; not stated by any report):");
    for (const s of f.similar) lines.push(`- [${s.node.id}] ${s.node.label}: similarity ${s.score}, shares ${s.shared.map((x) => `[${x.id}] ${x.label}`).join(", ")}${s.linked ? " (already linked)" : ""}`);
  }
  lines.push("", "REPORTS:");
  for (const r of f.reports.slice(0, 15)) lines.push(`- [report:${r.id}] ${r.title} — ${r.publisher || "unknown publisher"}, ${fmtDate(r.publishedAt)}`);
  lines.push(
    "",
    `Write an assessment of ${n.label} from these facts only. Return JSON:
{
  "summary": "2-3 sentences: who/what it is in this library and why it matters",
  "points": [{ "text": "a notable relationship or pattern", "refs": ["IDs in square brackets above"] }],
  "hiddenLinks": [{ "text": "a connection worth checking that no report states (from SIMILAR ENTITIES or shared links), and why", "refs": ["IDs"] }],
  "gaps": ["what the library lacks to be confident (e.g. single-source links, no recent reports)"]
}
At most 6 points, 3 hiddenLinks, 3 gaps. Every point needs at least one ref.`,
  );
  return lines.join("\n");
}

function str(v: unknown, max: number) {
  return typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, max) : "";
}

/** Keeps only points that cite known IDs; removes unknown IDs from each point. */
export function parseBrief(parsed: unknown, f: BriefFacts, provider: string, now = new Date()): GraphBrief {
  const o = (parsed && typeof parsed === "object" ? parsed : {}) as Record<string, unknown>;
  const known = new Set<string>([f.node.id, ...f.links.map((l) => l.other.id), ...f.similar.flatMap((s) => [s.node.id, ...s.shared.map((x) => x.id)]), ...f.reports.map((r) => `report:${r.id}`)]);
  let dropped = 0;
  const points = (v: unknown, max: number): BriefPoint[] => {
    const out: BriefPoint[] = [];
    for (const raw of Array.isArray(v) ? v.slice(0, 20) : []) {
      const p = (raw ?? {}) as Record<string, unknown>;
      const text = str(p.text, 400);
      const refs = (Array.isArray(p.refs) ? p.refs : []).map((r) => str(r, 200).replace(/^\[|\]$/g, "")).filter((r) => known.has(r));
      if (!text || !refs.length) {
        dropped++;
        continue;
      }
      out.push({ text, refs: [...new Set(refs)].slice(0, 6) });
      if (out.length >= max) break;
    }
    return out;
  };
  return {
    summary: str(o.summary, 700),
    points: points(o.points, 6),
    hiddenLinks: points(o.hiddenLinks, 3),
    gaps: (Array.isArray(o.gaps) ? o.gaps : []).map((g) => str(g, 240)).filter(Boolean).slice(0, 3),
    dropped,
    provider,
    generatedAt: now.toISOString(),
  };
}
