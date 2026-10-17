/**
 * Per-source health and yield (AIE Web Extraction spec §44, §53) and per-source schedules.
 * Pure: counters, automatic backoff after repeated failures, health classification and the
 * "due now" computation from each registry source's schedule hint.
 */

export type SyncSchedule = "hourly" | "daily" | "weekly";

export type YieldCounters = {
  /** Article (and source-level) fetches attempted. */
  fetched: number;
  /** New documents stored. */
  new: number;
  /** Known URLs that were not modified (304, same content hash, or not due for revalidation). */
  unchanged: number;
  /** Content duplicates of another stored document (exact, normalised, title+publisher or SimHash). */
  duplicate: number;
  skippedRelevance: number;
  rejectedQuality: number;
  /** Stored (new + new versions). */
  accepted: number;
  /** New versions of already stored documents. */
  versions: number;
  failed: number;
  qualitySum: number;
  qualityCount: number;
};

export type SourceHealth = {
  sourceId: string;
  name?: string;
  totals: YieldCounters;
  lastRun: (YieldCounters & { jobId: string; at: string }) | null;
  lastCrawledAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastErrorAt: string | null;
  consecutiveFailures: number;
  backoffUntil: string | null;
  /** Feed / homepage / sitemap fetches answered 304 in the last run. */
  lastRunNotModified: number;
  runs: number;
  updatedAt: string;
};

export type HealthStatus = "healthy" | "degraded" | "failing" | "backoff" | "idle";

export function emptyCounters(): YieldCounters {
  return { fetched: 0, new: 0, unchanged: 0, duplicate: 0, skippedRelevance: 0, rejectedQuality: 0, accepted: 0, versions: 0, failed: 0, qualitySum: 0, qualityCount: 0 };
}

export function emptyHealth(sourceId: string, name?: string): SourceHealth {
  return {
    sourceId,
    name,
    totals: emptyCounters(),
    lastRun: null,
    lastCrawledAt: null,
    lastSuccessAt: null,
    lastError: null,
    lastErrorAt: null,
    consecutiveFailures: 0,
    backoffUntil: null,
    lastRunNotModified: 0,
    runs: 0,
    updatedAt: new Date(0).toISOString(),
  };
}

export function addCounters(a: YieldCounters, b: Partial<YieldCounters>): YieldCounters {
  const out = { ...a };
  for (const k of Object.keys(out) as Array<keyof YieldCounters>) out[k] = (out[k] ?? 0) + (b[k] ?? 0);
  return out;
}

/** Failures before the first backoff, base delay and cap. */
export const BACKOFF_AFTER_FAILURES = 3;
const BACKOFF_BASE_MS = 2 * 60 * 60 * 1000;
const BACKOFF_CAP_MS = 7 * 24 * 60 * 60 * 1000;

/** Exponential backoff: 2h after the 3rd consecutive failure, doubling, capped at 7 days. */
export function backoffMs(consecutiveFailures: number): number {
  if (consecutiveFailures < BACKOFF_AFTER_FAILURES) return 0;
  return Math.min(BACKOFF_BASE_MS * 2 ** (consecutiveFailures - BACKOFF_AFTER_FAILURES), BACKOFF_CAP_MS);
}

export type RunOutcome = {
  jobId: string;
  at: string;
  counters: Partial<YieldCounters>;
  /** True when the source answered at least one source-level request (feed, homepage, sitemap, archive). */
  reachable: boolean;
  /** Source-level request answered 304. */
  notModified?: number;
  error?: string | null;
};

/** Folds one crawl run into a source's health record. */
export function applyRunOutcome(prev: SourceHealth | null | undefined, sourceId: string, outcome: RunOutcome, name?: string): SourceHealth {
  const h: SourceHealth = prev ? { ...prev, totals: { ...prev.totals } } : emptyHealth(sourceId, name);
  if (name) h.name = name;
  const run = addCounters(emptyCounters(), outcome.counters);
  h.totals = addCounters(h.totals, run);
  h.lastRun = { ...run, jobId: outcome.jobId, at: outcome.at };
  h.lastCrawledAt = outcome.at;
  h.lastRunNotModified = outcome.notModified ?? 0;
  h.runs += 1;
  h.updatedAt = outcome.at;
  if (outcome.reachable) {
    h.lastSuccessAt = outcome.at;
    h.consecutiveFailures = 0;
    h.backoffUntil = null;
  } else {
    h.consecutiveFailures += 1;
    h.lastError = outcome.error || "Source unreachable";
    h.lastErrorAt = outcome.at;
    const wait = backoffMs(h.consecutiveFailures);
    h.backoffUntil = wait ? new Date(Date.parse(outcome.at) + wait).toISOString() : null;
  }
  if (outcome.reachable && outcome.error) {
    // Partial failure (e.g. feed down but homepage fine): keep the message, no backoff.
    h.lastError = outcome.error;
    h.lastErrorAt = outcome.at;
  }
  return h;
}

/** Accepted / (accepted + rejected by quality + skipped by relevance); null before any decision. */
export function acceptanceRatio(c: YieldCounters): number | null {
  const decided = c.accepted + c.rejectedQuality + c.skippedRelevance;
  return decided > 0 ? c.accepted / decided : null;
}

export function averageQuality(c: YieldCounters): number | null {
  return c.qualityCount > 0 ? c.qualitySum / c.qualityCount : null;
}

export function healthStatus(h: SourceHealth | null | undefined, now = Date.now()): HealthStatus {
  if (!h || h.runs === 0) return "idle";
  if (h.backoffUntil && Date.parse(h.backoffUntil) > now) return "backoff";
  if (h.consecutiveFailures >= 1) return "failing";
  const last = h.lastRun;
  if (last && last.failed > 0 && last.failed >= Math.max(1, last.fetched / 2)) return "degraded";
  if (h.lastError && h.lastErrorAt && h.lastErrorAt === h.lastCrawledAt) return "degraded";
  return "healthy";
}

// ---------------------------------------------------------------------------
// Schedules
// ---------------------------------------------------------------------------

export const SCHEDULE_INTERVAL_MS: Record<SyncSchedule, number> = {
  hourly: 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
};

/** Small grace so a daily source crawled at 09:05 is due again at a 09:00 tick the next day. */
const DUE_GRACE_MS = 10 * 60 * 1000;

export type DueInfo = { dueNow: boolean; nextDueAt: string | null; reason: string };

/** When a source is next due given its schedule hint, last crawl and any backoff. */
export function computeDue(
  schedule: SyncSchedule | string | undefined,
  lastCrawledAt: string | null | undefined,
  backoffUntil: string | null | undefined,
  now = Date.now(),
): DueInfo {
  const interval = SCHEDULE_INTERVAL_MS[(schedule as SyncSchedule) ?? "daily"] ?? SCHEDULE_INTERVAL_MS.daily;
  const backoff = backoffUntil ? Date.parse(backoffUntil) : NaN;
  if (Number.isFinite(backoff) && backoff > now) {
    return { dueNow: false, nextDueAt: new Date(backoff).toISOString(), reason: "Backing off after repeated failures" };
  }
  const last = lastCrawledAt ? Date.parse(lastCrawledAt) : NaN;
  if (!Number.isFinite(last)) return { dueNow: true, nextDueAt: null, reason: "Never crawled" };
  const next = last + interval;
  if (next - DUE_GRACE_MS <= now) return { dueNow: true, nextDueAt: new Date(next).toISOString(), reason: `${schedule ?? "daily"} schedule elapsed` };
  return { dueNow: false, nextDueAt: new Date(next).toISOString(), reason: `Next ${schedule ?? "daily"} crawl` };
}
