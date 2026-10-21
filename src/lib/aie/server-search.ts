/**
 * Intelligence search server functions (phase 9).
 *
 *   searchIntel       unified, grouped, faceted search over library reports and the
 *                     bundled ATT&CK knowledge, with the interpreted query
 *   searchLibrary     the same ranker for the library page's search box
 *   suggestEntities   autocomplete over ATT&CK names, aliases, tactics and doc types
 *
 * Query understanding and ranking live in ./search (pure, unit-tested).
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { isMongoConfigured } from "../mongodb/client.server";
import { mongoGetEmulationOptions, mongoGetKevEntries } from "../mongodb/repository.server";
import { attackCampaigns, attackGroups, attackSoftware, attackTechniques, getTechnique, normalizeEntityName, TACTIC_ORDER } from "./attack-knowledge";
import { listReports } from "./server";
import { loadCorpus } from "./search/corpus.server";
import { GROUP_KEYS, runSearch } from "./search/engine";
import { knowledgeCounts } from "./search/knowledge-docs";
import { docTypeLabel, understandQuery } from "./search/query";
import { prepareReport } from "./search/report-docs";
import type { EntitySuggestion, SearchGroupKey, SearchResponse, SearchResult } from "./search/types";
import type { DocType, EmulationOption, ReportListItem } from "./types";

/** Local store: ensureSeeded (internal to server.ts) initializes indexes and purges any legacy demo data; only real reports are returned. */
async function ensureSeeded(): Promise<void> {
  try {
    await listReports({ data: { limit: 1 } });
  } catch {
    /* search still runs over whatever is stored */
  }
}

const filtersSchema = z
  .object({
    docTypes: z.array(z.string().max(40)).max(30).optional(),
    tiers: z.array(z.string().max(10)).max(5).optional(),
    publishers: z.array(z.string().max(200)).max(30).optional(),
    actors: z.array(z.string().max(200)).max(30).optional(),
    years: z.array(z.string().max(4)).max(30).optional(),
  })
  .optional();

const EMULATION_KIND_LABEL: Record<EmulationOption["kind"], string> = {
  atomic_test: "Atomic test",
  caldera_ability: "CALDERA ability",
  ctid_procedure: "CTID procedure",
  attack_flow: "Attack flow",
  custom: "Custom",
};

function emulationResults(map: Record<string, EmulationOption[]>): SearchResult[] {
  return Object.entries(map)
    .filter(([, opts]) => opts.length > 0)
    .map(([tid, opts]) => {
      const t = getTechnique(tid);
      const byKind = new Map<string, number>();
      for (const o of opts) byKind.set(o.kind, (byKind.get(o.kind) ?? 0) + 1);
      const kinds = [...byKind.entries()].map(([k, n]) => `${n} ${EMULATION_KIND_LABEL[k as EmulationOption["kind"]] ?? k}${n === 1 ? "" : "s"}`);
      return {
        id: `emu:${tid}`,
        kind: "emulation" as const,
        title: `${tid} ${t?.name ?? ""}`.trim(),
        subtitle: kinds.join(" · "),
        snippet: opts
          .slice(0, 4)
          .map((o) => o.name)
          .join(" · "),
        highlights: [],
        href: { to: "/purple" },
        externalUrl: opts[0]?.sourceUrl,
        docTypes: [...new Set(opts.map((o) => (o.kind === "atomic_test" ? "ATOMIC_TEST" : o.kind === "caldera_ability" ? "CALDERA_ABILITY" : o.kind === "attack_flow" ? "ATTACK_FLOW" : "ADVERSARY_EMULATION_PLAN")))] as DocType[],
        entities: [{ kind: "technique" as const, label: tid, id: tid }],
        score: opts.length,
        stats: [{ label: "Options", value: opts.length }],
        why: {
          matchedFields: ["techniques"],
          matchedTerms: [],
          matchedEntities: [],
          matchedTechniques: t ? [{ id: tid, name: t.name, relation: "exact" as const }] : [],
          matchedIds: [tid],
          breakdown: [{ key: "emulation", label: "Synced emulation options for a technique the query names (or the top actor uses)", value: opts.length }],
          score: opts.length,
        },
      };
    })
    .sort((a, b) => b.score - a.score);
}

/** Unified intelligence search: grouped results, facets and the interpreted query. */
export const searchIntel = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(
    z.object({
      q: z.string().max(500),
      group: z.enum(GROUP_KEYS as [SearchGroupKey, ...SearchGroupKey[]]).optional(),
      filters: filtersSchema,
      limit: z.number().int().min(1).max(100).optional(),
      offset: z.number().int().min(0).max(10_000).optional(),
    }),
  )
  .handler(async ({ data }): Promise<SearchResponse> => {
    const t0 = Date.now();
    const iq = understandQuery(data.q);
    const empty = !data.q.trim();
    const corpus = empty ? { persistence: (isMongoConfigured() ? "mongodb" : "local") as "mongodb" | "local", reports: [] } : await loadCorpus(iq, { ensureLocal: ensureSeeded });
    const docs = corpus.reports.map(prepareReport);

    // First pass decides which techniques to look up emulation options / KEV rows for.
    let emulationExtras: SearchResult[] = [];
    let emulation: SearchResponse["sources"]["emulation"] = corpus.persistence === "mongodb" ? "not_synced" : "unavailable";
    let kevStatus: SearchResponse["sources"]["kev"] = corpus.persistence === "mongodb" ? "not_synced" : "unavailable";
    let kev: Map<string, { vendor: string; product: string; dateAdded: string; ransomwareUse?: string }> | undefined;
    const group = data.group ?? "all";
    if (empty) {
      return {
        interpreted: iq,
        group,
        counts: Object.fromEntries(GROUP_KEYS.map((k) => [k, 0])) as Record<SearchGroupKey, number>,
        results: [],
        total: 0,
        facets: { docType: [], tier: [], publisher: [], actor: [], year: [] },
        sources: { persistence: corpus.persistence, reportsSearched: 0, knowledge: knowledgeCounts(), emulation, kev: kevStatus },
        tookMs: Date.now() - t0,
      };
    }
    const first = runSearch(docs, iq, { group: "reports", limit: 1, filters: data.filters });
    if (corpus.persistence === "mongodb") {
      try {
        const map = await mongoGetEmulationOptions(first.emulationTechniques);
        emulationExtras = emulationResults(map);
        if (emulationExtras.length) emulation = "synced";
      } catch {
        emulation = "unavailable";
      }
      try {
        const cves = new Set<string>(iq.cves);
        for (const r of first.rankedReports.slice(0, 50)) for (const c of r.prepared.doc.cves) cves.add(c);
        const rows = await mongoGetKevEntries([...cves]);
        if (rows.length) {
          kevStatus = "synced";
          kev = new Map(rows.map((r) => [r.cveId.toUpperCase(), { vendor: r.vendor, product: r.product, dateAdded: r.dateAdded, ransomwareUse: r.ransomwareUse }]));
        }
      } catch {
        kevStatus = "unavailable";
      }
    }
    const out = runSearch(docs, iq, { group, limit: data.limit ?? 20, offset: data.offset ?? 0, filters: data.filters, emulationExtras, kev });
    return {
      interpreted: iq,
      group: out.group,
      counts: out.counts,
      results: out.results,
      total: out.total,
      facets: out.facets,
      sources: { persistence: corpus.persistence, reportsSearched: docs.length, knowledge: knowledgeCounts(), emulation, kev: kevStatus },
      tookMs: Date.now() - t0,
    };
  });

export type LibrarySearchHit = {
  id: string;
  rank: number;
  score: number;
  matchedSnippet?: string;
  why: string;
  item: ReportListItem;
};

export type LibrarySearchResponse = { hits: LibrarySearchHit[]; interpreted: { summary: string; chips: Array<{ label: string; detail?: string }> }; tookMs: number };

/** Library search box: the hybrid ranker over reports only, with snippets. */
export const searchLibrary = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ q: z.string().max(500), limit: z.number().int().min(1).max(500).optional() }))
  .handler(async ({ data }): Promise<LibrarySearchResponse> => {
    const t0 = Date.now();
    const iq = understandQuery(data.q);
    if (!data.q.trim()) return { hits: [], interpreted: { summary: "", chips: [] }, tookMs: 0 };
    const corpus = await loadCorpus(iq, { ensureLocal: ensureSeeded, limit: 300 });
    const byId = new Map(corpus.reports.map((r) => [r.id, r]));
    const out = runSearch(corpus.reports.map(prepareReport), iq, { group: "reports", limit: Math.min(100, data.limit ?? 100), includeKnowledge: false });
    const hits: LibrarySearchHit[] = out.results.map((r, i) => {
      const base = byId.get(r.id)!;
      const reasons = [
        r.why.matchedEntities.length ? r.why.matchedEntities.map((e) => (e.via !== e.name ? `${e.via} → ${e.name}` : e.name)).join(", ") : "",
        r.why.matchedTechniques.length ? r.why.matchedTechniques.map((t) => t.id).join(", ") : "",
        r.why.matchedIds.filter((x) => x.startsWith("CVE-")).join(", "),
      ].filter(Boolean);
      return {
        id: r.id,
        rank: i + 1,
        score: r.score,
        matchedSnippet: r.snippet,
        why: reasons.join(" · "),
        item: { ...base.listItem, matchedSnippet: r.snippet },
      };
    });
    return { hits, interpreted: { summary: iq.summary, chips: iq.chips.map((c) => ({ label: c.label, detail: c.detail })) }, tookMs: Date.now() - t0 };
  });

// ---------------------------------------------------------------------------
// Autocomplete
// ---------------------------------------------------------------------------

type SuggestEntry = { kind: EntitySuggestion["kind"]; id: string; name: string; alias: string; key: string; weight: number };
let suggestIndex: SuggestEntry[] | null = null;

const DOC_TYPE_SUGGEST: Array<[string, string]> = [
  ["advisory", "THREAT_ADVISORY"],
  ["dfir", "DFIR_REPORT"],
  ["incident", "INCIDENT_REPORT"],
  ["malware", "MALWARE_REPORT"],
  ["vulnerability", "VULNERABILITY_ADVISORY"],
  ["campaign", "CAMPAIGN_REPORT"],
  ["emulation", "ADVERSARY_EMULATION_PLAN"],
  ["atomic", "ATOMIC_TEST"],
  ["flow", "ATTACK_FLOW"],
  ["detection", "DETECTION_RESEARCH"],
  ["hunting", "THREAT_HUNTING_REPORT"],
  ["kev", "KEV_ENTRY"],
];

function buildSuggestIndex(): SuggestEntry[] {
  const out: SuggestEntry[] = [];
  const push = (kind: SuggestEntry["kind"], id: string, name: string, alias: string, weight: number) =>
    out.push({ kind, id, name, alias, key: normalizeEntityName(alias), weight });
  for (const g of attackGroups()) for (const a of [g.name, ...g.aliases]) push("group", g.id, g.name, a, 4);
  for (const c of attackCampaigns()) for (const a of [c.name, ...c.aliases]) push("campaign", c.id, c.name, a, 2);
  for (const s of attackSoftware()) for (const a of [s.name, ...s.aliases]) push("software", s.id, s.name, a, 3);
  for (const t of attackTechniques()) {
    push("technique", t.id, t.name, t.name, 1);
    if (t.name.includes(": ")) push("technique", t.id, t.name, t.name.split(": ").slice(1).join(": "), 1);
  }
  for (const t of TACTIC_ORDER) push("tactic", t, t, t, 2);
  for (const [k, v] of DOC_TYPE_SUGGEST) push("type", v, docTypeLabel(v as DocType), k, 1);
  return out;
}

function insertFor(e: SuggestEntry): string {
  const q = (s: string) => (/\s/.test(s) ? `"${s}"` : s);
  switch (e.kind) {
    case "group":
      return `actor:${q(e.name)}`;
    case "software":
      return `malware:${q(e.name)}`;
    case "campaign":
      return `campaign:${q(e.name)}`;
    case "technique":
      return `technique:${e.id}`;
    case "tactic":
      return `tactic:${q(e.name)}`;
    default:
      return `type:${e.alias}`;
  }
}

/** Autocomplete: ATT&CK groups / software / campaigns / techniques (by name, alias or id), tactics and doc types. */
export const suggestEntities = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ prefix: z.string().max(120), limit: z.number().int().min(1).max(20).optional() }))
  .handler(async ({ data }): Promise<EntitySuggestion[]> => {
    const raw = data.prefix.trim();
    if (raw.length < 2) return [];
    suggestIndex ??= buildSuggestIndex();
    const limit = data.limit ?? 8;
    const p = normalizeEntityName(raw);
    const idQuery = raw.toUpperCase();
    const scored: Array<{ e: SuggestEntry; s: number }> = [];
    for (const e of suggestIndex) {
      let s = 0;
      if (e.id.toUpperCase() === idQuery) s = 100;
      else if (/^[TGSC]\d/.test(idQuery) && e.id.toUpperCase().startsWith(idQuery)) s = 60;
      else if (e.key === p) s = 80;
      else if (e.key.startsWith(p)) s = 50 - Math.min(20, e.key.length - p.length) / 2;
      else if (p.length >= 3 && e.key.includes(` ${p}`)) s = 25;
      if (s > 0) scored.push({ e, s: s + e.weight + (e.alias === e.name ? 1 : 0) });
    }
    scored.sort((a, b) => b.s - a.s || a.e.name.localeCompare(b.e.name));
    const seen = new Set<string>();
    const out: EntitySuggestion[] = [];
    for (const { e } of scored) {
      const key = `${e.kind}:${e.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ kind: e.kind, id: e.id, name: e.name, ...(e.alias !== e.name ? { alias: e.alias } : {}), insert: insertFor(e) });
      if (out.length >= limit) break;
    }
    return out;
  });
