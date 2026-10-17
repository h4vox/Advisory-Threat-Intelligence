/**
 * Collector server functions (phase 9).
 *
 *   getCollectorOverview   per-source health and yield (fetched / new / unchanged / duplicate /
 *                          skipped by relevance / rejected / accepted, average quality, last error,
 *                          consecutive failures, backoff) and per-source schedule (next due, due now)
 *   getCrawlJobFunnels     the collection funnel of crawl jobs (discovered → … → stored) and the
 *                          reasons items left it
 *   startSourceBackfill    bounded, polite per-source backfill over a 6 / 12 / 24 month window
 *   checkRelevance         the pre-fetch relevance score for a title / URL (explains a skip)
 *   getReportCollectorMeta fingerprints, mirrors ("also seen at"), versions, attachments, ATT&CK refs
 *
 * Only server functions and types are exported from this module.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { isMongoConfigured } from "../mongodb/client.server";
import { mongoListSources } from "../mongodb/repository.server";
import {
  collectorPersistence,
  countFetchStates,
  getJobFunnels,
  getReportCollectorMeta as repoGetReportCollectorMeta,
  getSourceHealthMap,
  type ReportCollectorMeta,
} from "../mongodb/collector-repo.server";
import { getSql } from "@/lib/db";
import { SOURCE_SEED, isStructuredSource } from "./catalog";
import { CrawlAlreadyRunningError, createAndRunCrawlJob, getOrCreateCrawlConfig } from "./crawler";
import { acceptanceRatio, averageQuality, computeDue, healthStatus, type DueInfo, type HealthStatus, type SourceHealth } from "./collector/health";
import { planBackfill } from "./collector/discovery-depth";
import { scoreRelevance, type RelevanceResult } from "./collector/relevance";
import type { CrawlFunnel, SourceTier } from "./types";

export type CollectorSourceRow = {
  sourceId: string;
  name: string;
  homepageUrl: string;
  tier: SourceTier;
  schedule: string;
  connector: string;
  enabled: boolean;
  discovered: boolean;
  status: HealthStatus;
  health: SourceHealth | null;
  acceptance: number | null;
  avgQuality: number | null;
  due: DueInfo;
};

export type CollectorOverview = {
  persistence: "mongodb" | "local";
  /** The autonomous scheduler needs MongoDB (cross-instance lock); locally crawls run on demand. */
  schedulerActive: boolean;
  schedulerNote: string;
  sources: CollectorSourceRow[];
  totals: { fetched: number; new: number; unchanged: number; duplicate: number; skippedRelevance: number; rejectedQuality: number; accepted: number; versions: number; failed: number };
  dueNow: number;
  failing: number;
  trackedUrls: number;
  generatedAt: string;
};

async function liveEnabled(): Promise<Map<string, boolean>> {
  const out = new Map<string, boolean>();
  try {
    if (isMongoConfigured()) {
      for (const s of await mongoListSources()) out.set(s.id, s.enabled !== false);
    } else {
      const sql = await getSql();
      const rows = await sql<{ id: string; enabled: boolean }>`select id, enabled from sources`;
      for (const r of rows) out.set(r.id, Boolean(r.enabled));
    }
  } catch {
    /* registry defaults */
  }
  return out;
}

export const getCollectorOverview = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async (): Promise<CollectorOverview> => {
    const now = Date.now();
    let health = new Map<string, SourceHealth>();
    try {
      health = await getSourceHealthMap();
    } catch (err) {
      console.warn("[collector] health unavailable:", (err as Error).message);
    }
    const enabled = await liveEnabled();
    const rows: CollectorSourceRow[] = [];
    const seen = new Set<string>();
    for (const s of SOURCE_SEED) {
      if (isStructuredSource(s)) continue;
      seen.add(s.id);
      const h = health.get(s.id) ?? null;
      rows.push({
        sourceId: s.id,
        name: s.name,
        homepageUrl: s.homepageUrl,
        tier: s.tier,
        schedule: s.schedule,
        connector: s.connector,
        enabled: enabled.get(s.id) ?? s.enabled,
        discovered: false,
        status: healthStatus(h, now),
        health: h,
        acceptance: h ? acceptanceRatio(h.totals) : null,
        avgQuality: h ? averageQuality(h.totals) : null,
        due: computeDue(s.schedule, h?.lastCrawledAt ?? null, h?.backoffUntil ?? null, now),
      });
    }
    // Discovered / community sources the crawler has collected from.
    for (const [id, h] of health) {
      if (seen.has(id) || id === "src_web_search") continue;
      rows.push({
        sourceId: id,
        name: h.name || id,
        homepageUrl: "",
        tier: 4,
        schedule: "daily",
        connector: "html",
        enabled: true,
        discovered: true,
        status: healthStatus(h, now),
        health: h,
        acceptance: acceptanceRatio(h.totals),
        avgQuality: averageQuality(h.totals),
        due: computeDue("daily", h.lastCrawledAt, h.backoffUntil, now),
      });
    }
    const totals = { fetched: 0, new: 0, unchanged: 0, duplicate: 0, skippedRelevance: 0, rejectedQuality: 0, accepted: 0, versions: 0, failed: 0 };
    for (const r of rows) {
      if (!r.health) continue;
      for (const k of Object.keys(totals) as Array<keyof typeof totals>) totals[k] += r.health.totals[k] ?? 0;
    }
    let trackedUrls = 0;
    try {
      trackedUrls = await countFetchStates();
    } catch {
      /* table not created yet */
    }
    let schedulerActive = false;
    let schedulerNote = "Crawls run on demand in this workspace: the autonomous scheduler needs MongoDB for its cross-instance lock.";
    if (isMongoConfigured()) {
      try {
        const cfg = await getOrCreateCrawlConfig();
        schedulerActive = cfg.enabled && !cfg.paused;
        schedulerNote = schedulerActive
          ? "The scheduler crawls each source when its schedule hint is due and skips sources that are backing off."
          : cfg.paused
            ? "The scheduler is paused in crawler settings."
            : "The scheduler is disabled in crawler settings.";
      } catch {
        schedulerNote = "Scheduler state unavailable.";
      }
    }
    return {
      persistence: collectorPersistence(),
      schedulerActive,
      schedulerNote,
      sources: rows,
      totals,
      dueNow: rows.filter((r) => r.enabled && r.due.dueNow).length,
      failing: rows.filter((r) => r.status === "failing" || r.status === "backoff").length,
      trackedUrls,
      generatedAt: new Date(now).toISOString(),
    };
  });

export const getCrawlJobFunnels = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ jobIds: z.array(z.string().min(1).max(80)).max(200) }))
  .handler(async ({ data }): Promise<Record<string, CrawlFunnel>> => {
    try {
      return await getJobFunnels(data.jobIds);
    } catch (err) {
      console.warn("[collector] funnels unavailable:", (err as Error).message);
      return {};
    }
  });

export const startSourceBackfill = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ sourceId: z.string().min(1).max(80), months: z.union([z.literal(6), z.literal(12), z.literal(24)]) }))
  .handler(async ({ data }) => {
    const seed = SOURCE_SEED.find((s) => s.id === data.sourceId);
    if (seed && isStructuredSource(seed)) {
      return { ok: false as const, error: `${seed.name} is a structured connector; use "Sync now" instead of a backfill.` };
    }
    const plan = planBackfill(data.months);
    try {
      const job = await createAndRunCrawlJob("BACKFILL", undefined, { backfill: { sourceId: data.sourceId, months: data.months } });
      return {
        ok: true as const,
        job,
        plan: { sinceIso: plan.sinceIso, maxArticles: plan.maxArticles, maxListingPages: plan.maxListingPages, hostSpacingMs: plan.hostSpacingMs, maxRunMinutes: plan.maxRunMinutes },
      };
    } catch (err) {
      if (err instanceof CrawlAlreadyRunningError) return { ok: false as const, error: err.message };
      throw err;
    }
  });

export const checkRelevance = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ title: z.string().max(400), url: z.string().max(2048).optional(), summary: z.string().max(2000).optional() }))
  .handler(async ({ data }): Promise<RelevanceResult> => scoreRelevance({ title: data.title, url: data.url, summary: data.summary }));

export const getReportCollectorMeta = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ reportId: z.string().min(1).max(80) }))
  .handler(async ({ data }): Promise<ReportCollectorMeta | null> => {
    try {
      return await repoGetReportCollectorMeta(data.reportId);
    } catch {
      return null;
    }
  });
