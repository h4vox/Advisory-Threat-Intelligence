/**
 * Threat-actor server functions: the actor list, actor profiles and name suggestions, built from the
 * library reports (both Mongo and local modes, via listReports) plus the bundled ATT&CK knowledge.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { listReports } from "./server";
import { isMongoConfigured, getThreatIntelCollection } from "../mongodb/client.server";
import { resolveEntity } from "./attack-knowledge";
import {
  actorKpis,
  actorProfile,
  actorRow,
  buildActorIndex,
  filterActors,
  findActor,
  sortActorRows,
  suggestActors as suggestFromIndex,
  NO_EMULATION,
  type ActorIndex,
  type EmulationContext,
} from "./actors/aggregate";
import type { ActorCtidPlan, ActorListResult, ActorProfile, ActorSuggestion } from "./actors/types";
import { ATTACK_VERSION } from "./attack-knowledge";

const CACHE_MS = 30_000;
const PAGE = 500;
const MAX_REPORTS = 5_000;

type Cached = { at: number; index: ActorIndex; emu: EmulationContext };
let cache: Cached | null = null;
let inflight: Promise<Cached> | null = null;

async function loadReports() {
  const out: Awaited<ReturnType<typeof listReports>> = [];
  for (let offset = 0; offset < MAX_REPORTS; offset += PAGE) {
    const page = await listReports({ data: { limit: PAGE, offset } });
    out.push(...page);
    if (page.length < PAGE) break;
  }
  return out;
}

/** CTID plans and the Atomic technique index; only exist once the structured sources are synced (Mongo). */
async function loadEmulation(): Promise<EmulationContext> {
  if (!isMongoConfigured()) return NO_EMULATION;
  try {
    const col = await getThreatIntelCollection();
    const [atomic, plans] = await Promise.all([
      col.distinct("techniqueId", { docType: "emulation_index", kind: "atomic_test" }),
      col
        .find({ docType: "report", "structured.kind": "emulation_plan" })
        .project({ _id: 0, id: 1, title: 1, url: 1, structured: 1 })
        .limit(1000)
        .toArray(),
    ]);
    const plansByGroup = new Map<string, ActorCtidPlan[]>();
    for (const p of plans as any[]) {
      const s = p.structured;
      const g = s?.adversary ? resolveEntity(String(s.adversary), ["group"])[0] : undefined;
      if (!g) continue;
      const list = plansByGroup.get(g.id) ?? [];
      list.push({
        reportId: String(p.id),
        title: String(p.title ?? s.adversary),
        url: String(p.url ?? ""),
        planType: s.planType === "micro" ? "micro" : "full",
        techniques: Array.isArray(s.techniques) ? s.techniques.length : 0,
      });
      plansByGroup.set(g.id, list);
    }
    const atomicTechniques = new Set((atomic as unknown[]).map((t) => String(t).toUpperCase()));
    // "Synced" = at least one structured emulation source has landed.
    const synced = atomicTechniques.size > 0 || plans.length > 0;
    return { synced, atomicTechniques: synced ? atomicTechniques : null, plansByGroup };
  } catch (err) {
    console.warn("[actors] emulation index lookup failed:", err);
    return NO_EMULATION;
  }
}

async function getIndex(): Promise<Cached> {
  if (cache && Date.now() - cache.at < CACHE_MS) return cache;
  inflight ??= (async () => {
    try {
      const [reports, emu] = await Promise.all([loadReports(), loadEmulation()]);
      cache = { at: Date.now(), index: buildActorIndex(reports), emu };
      return cache;
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

export const listActors = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(
    z.object({
      q: z.string().max(120).optional(),
      observedOnly: z.boolean().optional(),
      sort: z.enum(["recent", "reports", "techniques", "name"]).default("recent"),
      limit: z.number().int().min(1).max(200).default(25),
      offset: z.number().int().min(0).max(10_000).default(0),
    }),
  )
  .handler(async ({ data }): Promise<ActorListResult> => {
    const { index, emu } = await getIndex();
    const matched = filterActors(index, { q: data.q?.trim(), observedOnly: data.observedOnly });
    const rows = sortActorRows(
      matched.map((a) => actorRow(a, emu)),
      data.sort,
    );
    return {
      rows: rows.slice(data.offset, data.offset + data.limit),
      total: rows.length,
      kpis: actorKpis(index),
      attackVersion: ATTACK_VERSION ?? null,
      emulationSynced: emu.synced,
    };
  });

export const getActorProfile = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ actorId: z.string().min(1).max(120) }))
  .handler(async ({ data }): Promise<ActorProfile | null> => {
    const { index, emu } = await getIndex();
    const rec = findActor(index, data.actorId);
    return rec ? actorProfile(rec, emu) : null;
  });

export const suggestActors = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(
    z.object({ prefix: z.string().max(80), limit: z.number().int().min(1).max(20).optional() }),
  )
  .handler(async ({ data }): Promise<ActorSuggestion[]> => {
    const { index } = await getIndex();
    return suggestFromIndex(index, data.prefix, data.limit ?? 8);
  });
