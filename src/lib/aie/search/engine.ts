/**
 * Unified intelligence search over prepared library reports plus the bundled
 * ATT&CK knowledge: scoring (rank.ts), duplicate collapse, publisher
 * diversity, grouping, facets, pagination and explainable result cards with a
 * best-passage snippet.
 *
 * Pure apart from the ATT&CK snapshot; used by server-search.ts and the
 * retrieval eval.
 */
import { excerptAround, selectPassages } from "../retrieval.ts";
import type { DocType } from "../types.ts";
import { knowledgeCorpus } from "./knowledge-docs.ts";
import { docTypeLabel } from "./query.ts";
import { collapseDuplicates, diversify, scoreDocs, type CollapsedDoc, type PreparedDoc, type ScoredDoc } from "./rank.ts";
import { isEmulationDocType } from "./report-docs.ts";
import type {
  FacetBucket,
  InterpretedQuery,
  SearchFacets,
  SearchFilters,
  SearchGroupKey,
  SearchResult,
} from "./types.ts";

export const GROUP_KEYS: SearchGroupKey[] = ["all", "reports", "actors", "techniques", "software", "campaigns", "emulation", "vulnerabilities"];

export type EngineOptions = {
  group?: SearchGroupKey;
  limit?: number;
  offset?: number;
  filters?: SearchFilters;
  includeKnowledge?: boolean;
  now?: number;
  /** Extra emulation rows (synced emulation options), already shaped as results. */
  emulationExtras?: SearchResult[];
  /** KEV details by CVE id, when the KEV source has synced. */
  kev?: Map<string, { vendor: string; product: string; dateAdded: string; ransomwareUse?: string }>;
};

export type EngineOutput = {
  group: SearchGroupKey;
  counts: Record<SearchGroupKey, number>;
  results: SearchResult[];
  total: number;
  facets: SearchFacets;
  /** Ranked report docs (after filters, collapse and diversity), for chat grounding and evals. */
  rankedReports: CollapsedDoc[];
  /** Technique ids worth looking up emulation options for. */
  emulationTechniques: string[];
};

// ---------------------------------------------------------------------------
// Facets
// ---------------------------------------------------------------------------

function bucket(values: string[][], label: (v: string) => string = (v) => v, limit = 12): FacetBucket[] {
  const m = new Map<string, number>();
  for (const vs of values) for (const v of new Set(vs)) if (v) m.set(v, (m.get(v) ?? 0) + 1);
  return [...m.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([value, count]) => ({ value, label: label(value), count }));
}

function yearOf(d: string | null | undefined): string {
  const m = String(d ?? "").match(/^(\d{4})/);
  return m ? m[1] : "";
}

export function computeFacets(reports: ScoredDoc[]): SearchFacets {
  const docs = reports.map((r) => r.prepared.doc);
  return {
    docType: bucket(docs.map((d) => d.docTypes), (v) => docTypeLabel(v as DocType), 20),
    tier: bucket(docs.map((d) => [d.tier ? String(d.tier) : "unrated"]), (v) => (v === "unrated" ? "Unrated source" : `Tier ${v}`)).sort((a, b) => a.value.localeCompare(b.value)),
    publisher: bucket(docs.map((d) => [d.publisher || "Unknown publisher"])),
    actor: bucket(docs.map((d) => d.actorNames ?? [])),
    year: bucket(docs.map((d) => [yearOf(d.publishedAt)]), (v) => v, 20).sort((a, b) => b.value.localeCompare(a.value)),
  };
}

function applyFacetFilters<T extends ScoredDoc>(reports: T[], f: SearchFilters | undefined): T[] {
  if (!f) return reports;
  const any = (sel: string[] | undefined, vals: string[]) => !sel || sel.length === 0 || sel.some((s) => vals.some((v) => v.toLowerCase() === s.toLowerCase()));
  return reports.filter((r) => {
    const d = r.prepared.doc;
    return (
      any(f.docTypes, d.docTypes) &&
      any(f.tiers, [d.tier ? String(d.tier) : "unrated"]) &&
      any(f.publishers, [d.publisher || "Unknown publisher"]) &&
      any(f.actors, d.actorNames ?? []) &&
      any(f.years, [yearOf(d.publishedAt)])
    );
  });
}

// ---------------------------------------------------------------------------
// Result cards
// ---------------------------------------------------------------------------

function sub(name: string): string {
  return name.includes(": ") ? name.split(": ").slice(1).join(": ") : name;
}

/** Strings the snippet should be centred on / highlighted with. */
function highlightTerms(iq: InterpretedQuery, r: ScoredDoc): string[] {
  const out = new Set<string>();
  for (const e of r.why.matchedEntities) {
    out.add(e.via);
    if (e.name !== e.via) out.add(e.name);
  }
  for (const id of r.why.matchedIds) out.add(id);
  for (const t of r.why.matchedTechniques) {
    out.add(t.id);
    out.add(sub(t.name));
  }
  for (const p of iq.phrases) out.add(p);
  for (const w of iq.raw.split(/\s+/)) {
    const v = w.replace(/^[-"(]+|[")?,.;:!]+$/g, "");
    if (!v || w.startsWith("-") || /^[a-z-]+:/i.test(v)) continue;
    if (r.why.matchedTerms.some((t) => v.toLowerCase() === t || v.toLowerCase().includes(t))) out.add(v);
  }
  for (const t of r.why.matchedTerms) if (t.length >= 3) out.add(t);
  return [...out].filter((s) => s.length >= 2).slice(0, 16);
}

function snippetFor(iq: InterpretedQuery, r: ScoredDoc, highlights: string[]): string | undefined {
  const d = r.prepared.doc;
  const q = highlights.join(" ");
  if (d.kind === "report") {
    if (d.body && q.trim()) {
      const [best] = selectPassages([{ id: d.id, title: d.title, text: d.body }], q, { k: 1, perDoc: 1, minScore: 0, chunkSize: 700, chunkOverlap: 120 });
      if (best) return excerptAround(best.text, q, 260);
    }
    return d.summary ? excerptAround(d.summary, q || iq.raw, 260) : undefined;
  }
  const text = d.summary || d.body;
  return text ? excerptAround(text, q || d.title, 240) : undefined;
}

const ENTITY_CHIP_KIND = { group: "actor", campaign: "actor", software: "malware", technique: "technique" } as const;

function toResult(iq: InterpretedQuery, r: ScoredDoc | CollapsedDoc, withSnippet: boolean): SearchResult {
  const d = r.prepared.doc;
  const highlights = highlightTerms(iq, r);
  const score = r.adjusted ?? r.score;
  const base = {
    id: d.id,
    title: d.title,
    highlights,
    docTypes: d.docTypes,
    publisher: d.publisher,
    tier: d.tier,
    score,
    why: { ...r.why, score },
    snippet: withSnippet ? snippetFor(iq, r, highlights) : undefined,
  };
  const meta = (d.meta ?? {}) as Record<string, unknown>;
  if (d.kind === "report") {
    const matchedIds = new Set(r.why.matchedEntities.map((e) => `${e.kind}:${e.id}`));
    const ents = [...d.entities]
      .filter((e) => e.kind !== "technique")
      .sort((a, b) => Number(matchedIds.has(`${b.kind}:${b.id}`)) - Number(matchedIds.has(`${a.kind}:${a.id}`)) || b.count - a.count)
      .slice(0, 4)
      .map((e) => ({ kind: ENTITY_CHIP_KIND[e.kind], label: e.name, id: e.id }));
    const techs = r.why.matchedTechniques.slice(0, 3).map((t) => ({ kind: "technique" as const, label: t.id, id: t.id }));
    const cves = (r.why.matchedIds.filter((x) => x.startsWith("CVE-")).length ? r.why.matchedIds.filter((x) => x.startsWith("CVE-")) : d.cves.slice(0, 2)).map((c) => ({ kind: "cve" as const, label: c }));
    const dups = "duplicates" in r ? r.duplicates.map((x) => ({ id: x.doc.id, title: x.doc.title, publisher: x.doc.publisher })) : [];
    return {
      ...base,
      kind: "report",
      subtitle: [d.publisher, d.publishedAt ? String(d.publishedAt).slice(0, 10) : null].filter(Boolean).join(" · "),
      publishedAt: d.publishedAt ?? null,
      href: { to: "/library/$reportId", params: { reportId: d.id } },
      externalUrl: d.url || undefined,
      entities: [...ents, ...techs, ...cves],
      ...(dups.length ? { duplicates: dups } : {}),
    };
  }
  if (d.kind === "group") {
    const aliases = (meta.aliases as string[]) ?? [];
    return {
      ...base,
      kind: "group",
      subtitle: `${d.id} · ATT&CK group${aliases.length ? ` · aka ${aliases.slice(0, 4).join(", ")}${aliases.length > 4 ? "…" : ""}` : ""}`,
      href: { to: "/actors/$actorId", params: { actorId: d.id } },
      externalUrl: d.url,
      pivot: { label: "Reports on this actor", q: `actor:${d.id}` },
      entities: [],
      stats: [
        { label: "Techniques", value: Number(meta.techniqueCount ?? 0) },
        { label: "Software", value: Number(meta.softwareCount ?? 0) },
      ],
    };
  }
  if (d.kind === "software") {
    const groups = (meta.groups as string[]) ?? [];
    return {
      ...base,
      kind: "software",
      subtitle: `${d.id} · ${meta.softwareType === "tool" ? "Tool" : "Malware"}${Array.isArray(meta.platforms) && meta.platforms.length ? ` · ${(meta.platforms as string[]).slice(0, 3).join(", ")}` : ""}`,
      href: groups.length === 1 ? { to: "/actors/$actorId", params: { actorId: groups[0] } } : { to: "/search", search: { q: `malware:${d.id}` } },
      externalUrl: d.url,
      pivot: { label: "Reports mentioning it", q: `malware:${d.id}` },
      entities: d.entities.filter((e) => e.rel === "uses" && e.kind === "group").slice(0, 3).map((e) => ({ kind: "actor" as const, label: e.name, id: e.id })),
      stats: [
        { label: "Techniques", value: Number(meta.techniqueCount ?? 0) },
        { label: "Used by", value: groups.length },
      ],
    };
  }
  if (d.kind === "campaign") {
    const groups = (meta.groups as string[]) ?? [];
    const window = [meta.firstSeen, meta.lastSeen].filter(Boolean).map((x) => String(x).slice(0, 7));
    return {
      ...base,
      kind: "campaign",
      subtitle: `${d.id} · ATT&CK campaign${window.length ? ` · ${window.join(" – ")}` : ""}`,
      href: groups.length ? { to: "/actors/$actorId", params: { actorId: groups[0] } } : { to: "/search", search: { q: `campaign:${d.id}` } },
      externalUrl: d.url,
      pivot: { label: "Reports on this campaign", q: `campaign:${d.id}` },
      entities: d.entities.filter((e) => e.rel === "uses" && e.kind === "group").slice(0, 3).map((e) => ({ kind: "actor" as const, label: e.name, id: e.id })),
      stats: [{ label: "Techniques", value: Number(meta.techniqueCount ?? 0) }],
    };
  }
  // technique
  return {
    ...base,
    kind: "technique",
    title: `${d.id} ${d.title}`,
    subtitle: d.tactics.join(" · "),
    href: { to: "/matrix", search: { technique: d.id } },
    externalUrl: d.url,
    pivot: { label: "Reports using it", q: `technique:${d.id}` },
    entities: [],
    stats: [
      { label: "Platforms", value: ((meta.platforms as string[]) ?? []).slice(0, 4).join(", ") || "—" },
      { label: "Data components", value: ((meta.dataSources as string[]) ?? []).length },
    ],
  };
}

function vulnerabilityResults(iq: InterpretedQuery, reports: ScoredDoc[], kev: EngineOptions["kev"]): SearchResult[] {
  const byCve = new Map<string, { score: number; reports: Array<{ id: string; title: string; publisher?: string }> }>();
  const touch = (c: string) => {
    const v = byCve.get(c) ?? { score: 0, reports: [] };
    byCve.set(c, v);
    return v;
  };
  for (const c of iq.cves) touch(c).score += 20;
  for (const r of reports.slice(0, 50)) {
    for (const c of r.prepared.doc.cves) {
      const v = touch(c);
      v.score += r.score * 0.5;
      if (v.reports.length < 5) v.reports.push({ id: r.prepared.doc.id, title: r.prepared.doc.title, publisher: r.prepared.doc.publisher });
    }
  }
  return [...byCve.entries()]
    .sort((a, b) => b[1].score - a[1].score || a[0].localeCompare(b[0]))
    .map(([cve, v]) => {
      const k = kev?.get(cve);
      const named = iq.cves.includes(cve);
      return {
        id: cve,
        kind: "vulnerability" as const,
        title: cve,
        subtitle: k ? `${k.vendor} ${k.product} · in CISA KEV since ${k.dateAdded}` : `Mentioned in ${v.reports.length} matching report${v.reports.length === 1 ? "" : "s"}`,
        snippet: v.reports.length ? `Reports: ${v.reports.map((x) => x.title).join(" · ")}` : named ? "No stored report mentions this CVE yet." : undefined,
        highlights: [cve],
        href: { to: "/search", search: { q: `cve:${cve}` } },
        externalUrl: `https://nvd.nist.gov/vuln/detail/${cve}`,
        docTypes: k ? (["KEV_ENTRY"] as DocType[]) : [],
        entities: [{ kind: "cve" as const, label: cve }],
        score: Math.round(v.score * 1000) / 1000,
        stats: [
          { label: "Reports", value: v.reports.length },
          ...(k ? [{ label: "KEV", value: k.ransomwareUse === "Known" ? "Known ransomware use" : "Listed" }] : []),
        ],
        why: {
          matchedFields: named ? ["cves"] : [],
          matchedTerms: [],
          matchedEntities: [],
          matchedTechniques: [],
          matchedIds: named ? [cve] : [],
          breakdown: [
            ...(named ? [{ key: "exactId", label: "Named in the query", value: 20 }] : []),
            ...(v.reports.length ? [{ key: "reports", label: `Half the score of ${v.reports.length} matching report(s)`, value: Math.round((v.score - (named ? 20 : 0)) * 1000) / 1000 }] : []),
          ],
          score: Math.round(v.score * 1000) / 1000,
        },
      };
    });
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

export function runSearch(reportDocs: PreparedDoc[], iq: InterpretedQuery, opts: EngineOptions = {}): EngineOutput {
  const group = opts.group ?? "all";
  const limit = Math.max(1, Math.min(100, opts.limit ?? 20));
  const offset = Math.max(0, opts.offset ?? 0);
  // Structured ATT&CK copies in the library duplicate the bundled knowledge cards.
  const reports = reportDocs.filter((p) => !/^attack_(group|software|campaign)$/.test(String(p.doc.meta?.structuredKind ?? "")));
  const knowledge = opts.includeKnowledge === false ? [] : knowledgeCorpus();
  const scored = scoreDocs([...reports, ...knowledge], iq, { now: opts.now });

  const byKind = { report: [] as ScoredDoc[], group: [] as ScoredDoc[], software: [] as ScoredDoc[], campaign: [] as ScoredDoc[], technique: [] as ScoredDoc[] };
  for (const s of scored) byKind[s.prepared.doc.kind].push(s);

  const collapsed = collapseBounded(byKind.report);
  const facets = computeFacets(collapsed);
  const faceted = applyFacetFilters(collapsed, opts.filters);
  // Diversity only reorders the head of the ranking; the tail keeps its score order.
  const filteredReports = [...diversify(faceted.slice(0, DIVERSIFY_HEAD)), ...faceted.slice(DIVERSIFY_HEAD)];

  const emulationReports = filteredReports.filter((r) => r.prepared.doc.docTypes.some(isEmulationDocType));
  const emulation: Array<ScoredDoc | SearchResult> = [...emulationReports, ...(opts.emulationExtras ?? [])];
  const vulns = vulnerabilityResults(iq, filteredReports, opts.kev);

  const counts: Record<SearchGroupKey, number> = {
    all: 0,
    reports: filteredReports.length,
    actors: byKind.group.length,
    techniques: byKind.technique.length,
    software: byKind.software.length,
    campaigns: byKind.campaign.length,
    emulation: emulation.length,
    vulnerabilities: vulns.length,
  };

  let list: Array<ScoredDoc | SearchResult>;
  switch (group) {
    case "reports":
      list = filteredReports;
      break;
    case "actors":
      list = byKind.group;
      break;
    case "techniques":
      list = byKind.technique;
      break;
    case "software":
      list = byKind.software;
      break;
    case "campaigns":
      list = byKind.campaign;
      break;
    case "emulation":
      list = emulation;
      break;
    case "vulnerabilities":
      list = vulns;
      break;
    default: {
      const named = vulns.filter((v) => iq.cves.includes(v.id));
      list = [...filteredReports, ...byKind.group, ...byKind.technique, ...byKind.software, ...byKind.campaign, ...named].sort(
        (a, b) => scoreOf(b) - scoreOf(a),
      );
    }
  }
  counts.all = filteredReports.length + byKind.group.length + byKind.technique.length + byKind.software.length + byKind.campaign.length + vulns.filter((v) => iq.cves.includes(v.id)).length;

  const page = list.slice(offset, offset + limit).map((x) => ("prepared" in x ? toResult(iq, x, true) : x));
  return {
    group,
    counts,
    results: page,
    total: list.length,
    facets,
    rankedReports: filteredReports,
    emulationTechniques: emulationTechniqueIds(iq, byKind.group),
  };
}

// Shingle comparison and diversity are quadratic: run them on the head of the ranking only.
const COLLAPSE_HEAD = 400;
const DIVERSIFY_HEAD = 200;

/**
 * Near-duplicate collapse over the top of the ranking (content hash, canonical URL or shingle
 * similarity), then exact-key collapse (content hash / canonical URL) for the long tail.
 */
function collapseBounded(ranked: ScoredDoc[]): CollapsedDoc[] {
  const head = collapseDuplicates(ranked.slice(0, COLLAPSE_HEAD));
  if (ranked.length <= COLLAPSE_HEAD) return head;
  const byKey = new Map<string, CollapsedDoc>();
  for (const h of head) if (h.prepared.doc.dupKey) byKey.set(h.prepared.doc.dupKey, h);
  const out = [...head];
  for (const r of ranked.slice(COLLAPSE_HEAD)) {
    const key = r.prepared.doc.dupKey;
    const host = key ? byKey.get(key) : undefined;
    if (host) {
      host.duplicates.push(r.prepared);
      continue;
    }
    const c: CollapsedDoc = { ...r, duplicates: [] };
    if (key) byKey.set(key, c);
    out.push(c);
  }
  return out;
}

function scoreOf(x: ScoredDoc | SearchResult): number {
  return "prepared" in x ? x.adjusted ?? x.score : x.score;
}

function emulationTechniqueIds(iq: InterpretedQuery, groups: ScoredDoc[]): string[] {
  const ids = new Set<string>();
  for (const t of iq.techniques) if (!t.negated) ids.add(t.id);
  const top = groups[0];
  if (top && top.why.matchedEntities.length) for (const t of top.prepared.doc.techniques.slice(0, 60)) ids.add(t);
  return [...ids].slice(0, 120);
}

/** Result card for a document (used by chat grounding traces and evals). */
export function resultFor(iq: InterpretedQuery, r: ScoredDoc, withSnippet = true): SearchResult {
  return toResult(iq, r, withSnippet);
}
