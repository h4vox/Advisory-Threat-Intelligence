/**
 * Purple path server functions (spec §32–36, MVP 5 §60).
 *
 * buildPurplePath resolves a seed (ATT&CK group or free-text actor, library report, campaign or
 * technique list) against the bundled ATT&CK knowledge and the library, looks up synced emulation
 * options, and runs the pure generator in ./purple. suggestPurpleSeeds autocompletes the builder.
 * Planning only: nothing here executes a procedure.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { getEmulationOptions, getIntelCoverage, getReport, listReports } from "./server";
import { isMongoConfigured, getThreatIntelCollection } from "../mongodb/client.server";
import {
  TACTIC_ORDER,
  attackCampaigns,
  attackGroups,
  attackTechniques,
  findEntitiesInText,
  getCampaign,
  getGroup,
  getTechnique,
  normalizeEntityName,
  resolveEntity,
  techniquePrevalence,
} from "./attack-knowledge";
import { registryEntry } from "./catalog";
import { SOURCE_CONFIDENCE, type ReportListItem } from "./types";
import { generatePurplePath } from "./purple/generate";
import { libraryEvidenceFromReport, namesInReport, hasReportedOrder } from "./purple/evidence";
import type { EmulationContext, LibraryEvidence, PurpleOptions, PurplePath, PurpleSeed } from "./purple/types";

const PAGE = 500;
const MAX_REPORTS = 3_000;
const TID = /^T\d{4}(?:\.\d{3})?$/;

async function loadLibrary(): Promise<ReportListItem[]> {
  const out: ReportListItem[] = [];
  for (let offset = 0; offset < MAX_REPORTS; offset += PAGE) {
    const page = await listReports({ data: { limit: PAGE, offset } });
    out.push(...page);
    if (page.length < PAGE) break;
  }
  // Structured-sync records (ATT&CK objects, Atomic tests, CTID plans) are not library reports.
  return out.filter((r) => r.discoveryMethod !== "structured_sync" && r.status !== "rejected");
}

function confidenceOf(r: { sourceConfidence?: number; sourceId: string }): number {
  if (typeof r.sourceConfidence === "number") return r.sourceConfidence;
  const reg = registryEntry(r.sourceId);
  return SOURCE_CONFIDENCE[reg?.confidenceClass ?? "UNKNOWN"];
}

function toEvidence(r: ReportListItem): LibraryEvidence {
  return libraryEvidenceFromReport({ id: r.id, title: r.title, publishedAt: r.publishedAt, sourceConfidence: confidenceOf(r), analysis: r.analysis });
}

/** Entities (ATT&CK ids) and normalized names a library report mentions. */
function mentions(r: ReportListItem): { ids: Set<string>; names: Set<string> } {
  const names = namesInReport(r);
  const ids = new Set<string>();
  for (const n of names) for (const e of resolveEntity(n, ["group", "campaign"])) ids.add(e.id);
  for (const e of findEntitiesInText(`${r.title}\n${r.excerpt ?? ""}`, { kinds: ["group", "campaign"] })) ids.add(e.id);
  return { ids, names: new Set(names.map(normalizeEntityName)) };
}

type CtidPlan = { reportId: string; title: string; adversary: string; techniques: string[] };
async function loadEmulationPlans(): Promise<CtidPlan[]> {
  if (!isMongoConfigured()) return [];
  try {
    const col = await getThreatIntelCollection();
    const rows = await col
      .find({ docType: "report", "structured.kind": "emulation_plan" })
      .project({ _id: 0, id: 1, title: 1, structured: 1 })
      .limit(1000)
      .toArray();
    return rows.map((p) => {
      const s = (p as { structured?: { adversary?: string; techniques?: string[] } }).structured ?? {};
      return { reportId: String(p.id), title: String(p.title ?? s.adversary ?? "Emulation plan"), adversary: String(s.adversary ?? ""), techniques: Array.isArray(s.techniques) ? s.techniques : [] };
    });
  } catch (err) {
    console.warn("[purple] emulation plan lookup failed:", err);
    return [];
  }
}

export type PurpleSeedInfo = {
  kind: PurpleSeed["kind"];
  id: string;
  name: string;
  /** ATT&CK id when the seed resolved to one. */
  attackId?: string;
  attackUrl?: string;
  aliases: string[];
  description?: string;
  /** Library reports the path draws on (id + title). */
  reports: Array<{ id: string; title: string; publishedAt: string | null }>;
  /** Input that did not resolve (free-text actor, unknown technique ids). */
  notes: string[];
};

export type PurpleCoverage = {
  persistence: "mongodb" | "local";
  emulationSynced: boolean;
  atomicTechniques: number;
  emulationTechniques: number;
  libraryReports: number;
};

export type PurpleBuildResult = { path: PurplePath; seed: PurpleSeedInfo; coverage: PurpleCoverage };

const PLATFORM = z.enum(["windows", "linux", "macos", "cloud", "saas", "identity", "network"]);
const BuildInput = z.object({
  kind: z.enum(["actor", "report", "campaign", "custom"]),
  value: z.string().trim().max(200).default(""),
  techniques: z.array(z.string().trim().max(16)).max(100).optional(),
  options: z.object({
    platforms: z.array(PLATFORM).max(7).default([]),
    excludeHighRisk: z.boolean().default(false),
    maxSteps: z.number().int().min(1).max(40).default(12),
  }),
});
export type BuildPurpleInput = z.input<typeof BuildInput>;

class SeedError extends Error {}

async function resolveSeed(input: z.output<typeof BuildInput>, library: ReportListItem[], plans: CtidPlan[]): Promise<{ seed: PurpleSeed; info: PurpleSeedInfo }> {
  const value = input.value.trim();
  const reportsOf = (items: ReportListItem[]) => items.map((r) => ({ id: r.id, title: r.title, publishedAt: r.publishedAt }));

  if (input.kind === "report") {
    const r = await getReport({ data: { id: value } });
    if (!r) throw new SeedError(`Report ${value} was not found in the library`);
    const ev = libraryEvidenceFromReport({ id: r.id, title: r.title, publishedAt: r.publishedAt, sourceConfidence: confidenceOf(r), analysis: r.analysis });
    return {
      seed: { kind: "report", id: r.id, name: r.title, attributed: [], reports: [ev], reportedOrder: hasReportedOrder(r.analysis) },
      info: {
        kind: "report",
        id: r.id,
        name: r.title,
        aliases: [],
        description: r.publisher || r.sourceName,
        reports: [{ id: r.id, title: r.title, publishedAt: r.publishedAt }],
        notes: ev.techniques.length ? [] : ["The report has no ATT&CK techniques mapped yet"],
      },
    };
  }

  if (input.kind === "custom") {
    const raw = [...(input.techniques ?? []), ...value.split(/[\s,;]+/)].map((x) => x.trim().toUpperCase()).filter(Boolean);
    const ids = Array.from(new Set(raw.filter((x) => TID.test(x))));
    const unknown = raw.filter((x) => !TID.test(x) || !getTechnique(x));
    if (!ids.length) throw new SeedError("Add at least one ATT&CK technique id, for example T1059.001");
    const reports = library.map(toEvidence).filter((e) => e.techniques.some((t) => ids.includes(t.id)));
    return {
      seed: { kind: "custom", id: "custom", name: "Custom technique list", attributed: [], custom: ids, reports },
      info: {
        kind: "custom",
        id: "custom",
        name: "Custom technique list",
        aliases: [],
        reports: reports.map((e) => ({ id: e.reportId, title: e.title, publishedAt: e.publishedAt })),
        notes: unknown.length ? [`Not recognised as ATT&CK techniques: ${Array.from(new Set(unknown)).join(", ")}`] : [],
      },
    };
  }

  if (input.kind === "campaign") {
    const c = getCampaign(value) ?? (resolveEntity(value, ["campaign"])[0] ? getCampaign(resolveEntity(value, ["campaign"])[0].id) : undefined);
    if (!c) throw new SeedError(`"${value}" is not an ATT&CK campaign. Use a C-ID (for example C0024) or a campaign name`);
    const names = new Set([c.name, ...c.aliases].map(normalizeEntityName));
    const matched = library.filter((r) => {
      const m = mentions(r);
      return m.ids.has(c.id) || [...m.names].some((n) => names.has(n));
    });
    const url = `https://attack.mitre.org/campaigns/${c.id}/`;
    const groups = c.groups.map((g) => getGroup(g)?.name ?? g);
    return {
      seed: { kind: "campaign", id: c.id, name: c.name, attributed: c.techniques, attributedBy: { id: c.id, url }, reports: matched.map(toEvidence) },
      info: {
        kind: "campaign",
        id: c.id,
        name: c.name,
        attackId: c.id,
        attackUrl: url,
        aliases: c.aliases,
        description: [groups.length ? `Attributed to ${groups.join(", ")}` : "", c.firstSeen ? `active ${c.firstSeen.slice(0, 7)} to ${c.lastSeen?.slice(0, 7) ?? "?"}` : ""].filter(Boolean).join("; "),
        reports: reportsOf(matched),
        notes: [],
      },
    };
  }

  // Actor: ATT&CK group, or a free-text name ATT&CK does not track.
  const hit = getGroup(value) ? { id: value.toUpperCase() } : resolveEntity(value, ["group"])[0];
  const g = hit ? getGroup(hit.id) : undefined;
  if (g) {
    const names = new Set([g.name, ...g.aliases].map(normalizeEntityName));
    const matched = library.filter((r) => {
      const m = mentions(r);
      return m.ids.has(g.id) || [...m.names].some((n) => names.has(n));
    });
    const groupPlans = plans.filter((p) => p.adversary && resolveEntity(p.adversary, ["group"])[0]?.id === g.id);
    const url = `https://attack.mitre.org/groups/${g.id}/`;
    return {
      seed: {
        kind: "actor",
        id: g.id,
        name: g.name,
        attributed: g.techniques,
        attributedBy: { id: g.id, url },
        reports: matched.map(toEvidence),
        emulationPlans: groupPlans.map((p) => ({ reportId: p.reportId, title: p.title, techniques: p.techniques })),
      },
      info: {
        kind: "actor",
        id: g.id,
        name: g.name,
        attackId: g.id,
        attackUrl: url,
        aliases: g.aliases,
        description: g.description ? g.description.slice(0, 280) : undefined,
        reports: reportsOf(matched),
        notes: groupPlans.length ? [`${groupPlans.length} emulation plan${groupPlans.length === 1 ? "" : "s"} synced for this group`] : [],
      },
    };
  }
  if (!value) throw new SeedError("Enter a threat actor name or ATT&CK group id");
  const norm = normalizeEntityName(value);
  const matched = library.filter((r) => {
    const m = mentions(r);
    return [...m.names].includes(norm) || r.title.toLowerCase().includes(value.toLowerCase());
  });
  return {
    seed: { kind: "actor", id: norm.replace(/\s+/g, "-") || "actor", name: value, attributed: [], reports: matched.map(toEvidence) },
    info: {
      kind: "actor",
      id: norm.replace(/\s+/g, "-"),
      name: value,
      aliases: [],
      reports: reportsOf(matched),
      notes: [
        `"${value}" is not an ATT&CK group, so no techniques are attributed; the path uses library reports that name it only.`,
        ...(matched.length ? [] : ["No library report names this actor yet"]),
      ],
    },
  };
}

/** Builds a purple path from an actor, report, campaign or technique list. Planning only. */
export const buildPurplePath = createServerFn({ method: "POST" }).middleware([analystMiddleware])
  .validator(BuildInput)
  .handler(async ({ data }): Promise<PurpleBuildResult | { error: string }> => {
    const [library, plans, coverage] = await Promise.all([
      data.kind === "report" ? Promise.resolve([] as ReportListItem[]) : loadLibrary(),
      data.kind === "actor" ? loadEmulationPlans() : Promise.resolve([] as CtidPlan[]),
      getIntelCoverage().catch(() => null),
    ]);
    let resolved: Awaited<ReturnType<typeof resolveSeed>>;
    try {
      resolved = await resolveSeed(data, library, plans);
    } catch (err) {
      if (err instanceof SeedError) return { error: err.message };
      throw err;
    }
    const { seed, info } = resolved;

    const atomic = coverage?.atomicTechniques ?? 0;
    const emuTechniques = coverage?.emulationTechniques ?? 0;
    const synced = atomic + emuTechniques > 0;
    let emu: EmulationContext = { synced, options: {} };
    if (synced) {
      const ids = Array.from(new Set([...seed.attributed, ...(seed.custom ?? []), ...seed.reports.flatMap((r) => r.techniques.map((t) => t.id))])).slice(0, 200);
      try {
        emu = { synced, options: await getEmulationOptions({ data: { techniqueIds: ids } }) };
      } catch {
        emu = { synced, options: {} };
      }
    }

    const options: PurpleOptions = { platforms: data.options.platforms, excludeHighRisk: data.options.excludeHighRisk, maxSteps: data.options.maxSteps };
    const path = generatePurplePath(seed, options, emu, { getTechnique, tacticOrder: TACTIC_ORDER, prevalence: techniquePrevalence });
    return {
      path,
      seed: info,
      coverage: {
        persistence: coverage?.persistence ?? (isMongoConfigured() ? "mongodb" : "local"),
        emulationSynced: synced,
        atomicTechniques: atomic,
        emulationTechniques: emuTechniques,
        libraryReports: data.kind === "report" ? 1 : library.length,
      },
    };
  });

export type PurpleSuggestion = {
  kind: "actor" | "campaign" | "report" | "technique";
  id: string;
  name: string;
  hint: string;
};

const EXAMPLE_GROUPS = ["G0016", "G1015", "G1024"];

/** Autocomplete for the builder: ATT&CK groups (with aliases), campaigns, library reports and techniques. */
export const suggestPurpleSeeds = createServerFn({ method: "POST" }).middleware([analystMiddleware])
  .validator(z.object({ q: z.string().max(120).default(""), kind: z.enum(["actor", "report", "campaign", "custom"]).optional() }))
  .handler(async ({ data }): Promise<{ items: PurpleSuggestion[]; examples: PurpleSuggestion[] }> => {
    const q = data.q.trim().toLowerCase();
    const items: PurpleSuggestion[] = [];
    const want = (k: PurpleSuggestion["kind"]) =>
      !data.kind || (data.kind === "actor" && k === "actor") || (data.kind === "campaign" && k === "campaign") || (data.kind === "report" && k === "report") || (data.kind === "custom" && k === "technique");

    const needLibrary = want("report") || !q;
    const library = needLibrary ? await loadLibrary().catch(() => [] as ReportListItem[]) : [];

    if (q) {
      if (want("actor")) {
        const scored: Array<{ s: number; item: PurpleSuggestion }> = [];
        for (const g of attackGroups()) {
          const all = [g.name, ...g.aliases];
          const idHit = g.id.toLowerCase() === q;
          const match = all.find((a) => a.toLowerCase().startsWith(q)) ?? all.find((a) => a.toLowerCase().includes(q));
          if (!idHit && !match) continue;
          const alias = match && match !== g.name ? `alias ${match}` : g.aliases.slice(0, 3).join(", ");
          const s = idHit ? 0 : match!.toLowerCase().startsWith(q) ? (match === g.name ? 1 : 2) : 3;
          scored.push({ s, item: { kind: "actor", id: g.id, name: g.name, hint: [g.id, alias].filter(Boolean).join(" · ") } });
        }
        items.push(...scored.sort((a, b) => a.s - b.s || a.item.name.localeCompare(b.item.name)).slice(0, 8).map((x) => x.item));
      }
      if (want("campaign")) {
        for (const c of attackCampaigns()) {
          const all = [c.name, ...c.aliases];
          if (c.id.toLowerCase() !== q && !all.some((a) => a.toLowerCase().includes(q))) continue;
          items.push({ kind: "campaign", id: c.id, name: c.name, hint: [c.id, c.groups.map((g) => getGroup(g)?.name ?? g).join(", ")].filter(Boolean).join(" · ") });
          if (items.filter((i) => i.kind === "campaign").length >= 6) break;
        }
      }
      if (want("report")) {
        for (const r of library) {
          if (!`${r.id} ${r.title}`.toLowerCase().includes(q)) continue;
          items.push({ kind: "report", id: r.id, name: r.title, hint: [r.id, r.publishedAt?.slice(0, 10), r.publisher || r.sourceName].filter(Boolean).join(" · ") });
          if (items.filter((i) => i.kind === "report").length >= 6) break;
        }
      }
      if (want("technique")) {
        for (const t of attackTechniques()) {
          if (!t.id.toLowerCase().startsWith(q) && !t.name.toLowerCase().includes(q)) continue;
          items.push({ kind: "technique", id: t.id, name: t.name, hint: `${t.id} · ${t.tactics.join(", ")}` });
          if (items.filter((i) => i.kind === "technique").length >= 8) break;
        }
      }
    } else if (want("report")) {
      for (const r of library.slice(0, 6)) items.push({ kind: "report", id: r.id, name: r.title, hint: [r.id, r.publishedAt?.slice(0, 10)].filter(Boolean).join(" · ") });
    }

    const examples: PurpleSuggestion[] = EXAMPLE_GROUPS.map((id) => getGroup(id))
      .filter((g): g is NonNullable<typeof g> => Boolean(g))
      .map((g) => ({ kind: "actor" as const, id: g.id, name: g.name, hint: `${g.id} · ${g.techniques.length} ATT&CK techniques` }));
    const c = getCampaign("C0024");
    if (c) examples.push({ kind: "campaign", id: c.id, name: c.name, hint: `${c.id} · ${c.techniques.length} techniques` });
    const withTechniques = library.find((r) => (r.analysis?.ttps?.length ?? 0) > 0 || (r.analysis?.evidence?.techniques?.length ?? 0) > 0);
    if (withTechniques) examples.push({ kind: "report", id: withTechniques.id, name: withTechniques.title, hint: `Library report · ${withTechniques.id}` });
    return { items, examples };
  });
