/**
 * Per-crawl-job collector context (SERVER ONLY). Holds the state the crawler needs to collect
 * incrementally and efficiently: source selection by schedule and backoff, conditional fetches
 * with per-URL fetch state, robots.txt, relevance pre-scoring, the multi-hash dedup index, the
 * per-source yield counters and the job funnel. All fetches go through the SSRF-guarded fetchers.
 */
import { safeConditionalFetch, safeFetchText, SsrfBlockedError } from "../security";
import { sha256Hex } from "../extract";
import { registryEntry } from "../catalog";
import type { CrawlFunnel, CrawlTrigger, SourceRecord } from "../types";
import {
  collectorPersistence,
  getFetchStates,
  getSourceHealthMap,
  loadDedupIndexEntries,
  putFetchStates,
  putJobFunnel,
  putSourceHealth,
} from "../../mongodb/collector-repo.server";
import { decideFetchOutcome, needsRevalidation, type FetchKind, type FetchOutcome, type FetchState } from "./fetch-state";
import { DedupIndex } from "./dedup";
import { applyRunOutcome, computeDue, emptyCounters, type SourceHealth, type YieldCounters } from "./health";
import { parseRobotsTxt, robotsAllows, robotsCrawlDelayMs, planBackfill, type BackfillPlan, type BackfillWindowMonths, type RobotsRules } from "./discovery-depth";
import { scoreRelevance, RELEVANCE_SKIP_THRESHOLD, type RelevanceResult } from "./relevance";

export const COLLECTOR_USER_AGENT = "AIE-Autonomous-Threat-Crawler/3.0 (+https://aie-intel.internal; cti-discovery-graph)";

/** Known articles are re-fetched (conditionally) at most this often unless a listing reports an update. */
export const ARTICLE_REVALIDATE_MS = 14 * 24 * 60 * 60 * 1000;

export type CrawlRunOptions = {
  /** Restrict the run to these registry / discovered source ids. */
  sourceIds?: string[];
  backfill?: { sourceId: string; months: BackfillWindowMonths } | null;
};

export type SourceFetchResult =
  | { status: "ok"; body: string; finalUrl: string; contentType: string }
  | { status: "not_modified" | "unchanged" }
  | { status: "error"; error: string };

export type ArticleFetchResult =
  | { status: "ok"; body: string; bytes: Uint8Array; contentType: string; finalUrl: string; etag: string | null; lastModified: string | null; httpStatus: number }
  | { status: "not_modified" };

type SourceRunState = { counters: YieldCounters; reachable: boolean; errors: string[]; notModified: number; name: string };

export function emptyFunnel(): CrawlFunnel {
  return {
    discovered: 0,
    relevant: 0,
    fetched: 0,
    unique: 0,
    qualified: 0,
    stored: 0,
    skippedRelevance: 0,
    unchanged: 0,
    notModified: 0,
    duplicates: {},
    newVersions: 0,
    robotsBlocked: 0,
    failed: 0,
    pdfAttached: 0,
    sourcesCrawled: 0,
    sourcesSkipped: [],
    feedsNotModified: 0,
    sitemapUrls: 0,
    feedsAutodiscovered: 0,
    listingPages: 0,
    relevanceSamples: [],
    mode: "incremental",
    backfill: null,
  };
}

function errMsg(err: unknown): string {
  if (err instanceof SsrfBlockedError) return `Blocked by SSRF policy: ${err.message}`;
  const m = err instanceof Error ? err.message : String(err);
  return m.replace(/\s+/g, " ").slice(0, 200);
}

export class CollectorRun {
  readonly jobId: string;
  readonly trigger: CrawlTrigger;
  readonly funnel: CrawlFunnel = emptyFunnel();
  readonly backfillPlan: (BackfillPlan & { sourceId: string }) | null;
  readonly persistence = collectorPersistence();
  dedup = new DedupIndex();
  private health = new Map<string, SourceHealth>();
  private perSource = new Map<string, SourceRunState>();
  private states = new Map<string, FetchState | null>();
  private dirty = new Map<string, FetchState>();
  private robots = new Map<string, Promise<RobotsRules | null>>();
  /** Feed / listing URLs whose items were not all processed this run (validators are not saved). */
  private unfinishedParents = new Set<string>();

  private constructor(jobId: string, trigger: CrawlTrigger, options: CrawlRunOptions) {
    this.jobId = jobId;
    this.trigger = trigger;
    this.backfillPlan = options.backfill ? { ...planBackfill(options.backfill.months), sourceId: options.backfill.sourceId } : null;
    if (this.backfillPlan) {
      this.funnel.mode = "backfill";
      this.funnel.backfill = { sourceId: this.backfillPlan.sourceId, months: this.backfillPlan.months, sinceIso: this.backfillPlan.sinceIso };
    }
  }

  static async start(jobId: string, trigger: CrawlTrigger, options: CrawlRunOptions = {}): Promise<CollectorRun> {
    const run = new CollectorRun(jobId, trigger, options);
    try {
      run.health = await getSourceHealthMap();
    } catch (err) {
      console.warn("[collector] source health unavailable:", errMsg(err));
    }
    try {
      run.dedup = new DedupIndex(await loadDedupIndexEntries());
    } catch (err) {
      console.warn("[collector] dedup index unavailable:", errMsg(err));
    }
    return run;
  }

  // -------------------------------------------------------------------------
  // Source selection
  // -------------------------------------------------------------------------

  /**
   * Scheduled runs crawl only sources whose schedule hint says they are due; every run skips
   * sources in failure backoff (a backfill of that one source excepted). Skips are recorded.
   */
  selectSources(sources: SourceRecord[], options: CrawlRunOptions, now = Date.now()): SourceRecord[] {
    const wanted = options.backfill ? [options.backfill.sourceId] : options.sourceIds;
    const out: SourceRecord[] = [];
    for (const s of sources) {
      if (wanted && wanted.length && !wanted.includes(s.id)) continue;
      const h = this.health.get(s.id);
      const schedule = registryEntry(s.id)?.schedule ?? "daily";
      const due = computeDue(schedule, h?.lastCrawledAt ?? null, h?.backoffUntil ?? null, now);
      const inBackoff = !!h?.backoffUntil && Date.parse(h.backoffUntil) > now;
      if (inBackoff && !options.backfill) {
        this.funnel.sourcesSkipped.push({ sourceId: s.id, name: s.name, reason: `${due.reason} until ${h!.backoffUntil!.slice(0, 16).replace("T", " ")} UTC (${h!.consecutiveFailures} consecutive failures: ${h!.lastError ?? "unreachable"})` });
        continue;
      }
      if (this.trigger === "SCHEDULED" && !due.dueNow) {
        this.funnel.sourcesSkipped.push({ sourceId: s.id, name: s.name, reason: `Not due (${schedule}); next ${due.nextDueAt?.slice(0, 16).replace("T", " ")} UTC` });
        continue;
      }
      out.push(s);
    }
    this.funnel.sourcesCrawled = out.length;
    for (const s of out) this.src(s.id, s.name);
    return out;
  }

  private src(sourceId: string | null | undefined, name?: string): SourceRunState | null {
    if (!sourceId) return null;
    let st = this.perSource.get(sourceId);
    if (!st) {
      st = { counters: emptyCounters(), reachable: false, errors: [], notModified: 0, name: name ?? sourceId };
      this.perSource.set(sourceId, st);
    }
    return st;
  }

  count(sourceId: string | null | undefined, key: keyof YieldCounters, n = 1) {
    const st = this.src(sourceId);
    if (st) st.counters[key] += n;
  }

  noteQuality(sourceId: string | null | undefined, score: number) {
    const st = this.src(sourceId);
    if (st) {
      st.counters.qualitySum += score;
      st.counters.qualityCount += 1;
    }
  }

  sourceReachable(sourceId: string | null | undefined, ok: boolean, error?: string) {
    const st = this.src(sourceId);
    if (!st) return;
    if (ok) st.reachable = true;
    if (error) st.errors.push(error);
  }

  lastCrawledAt(sourceId: string): string | null {
    return this.health.get(sourceId)?.lastCrawledAt ?? null;
  }

  /** Historical accepted / rejected decisions for the relevance scorer. */
  sourceHistory(sourceId: string | null | undefined): { accepted: number; rejected: number } | null {
    if (!sourceId) return null;
    const t = this.health.get(sourceId)?.totals;
    return t ? { accepted: t.accepted, rejected: t.rejectedQuality + t.skippedRelevance } : null;
  }

  // -------------------------------------------------------------------------
  // Relevance
  // -------------------------------------------------------------------------

  prescore(item: { title?: string; summary?: string; url: string; sourceId?: string | null; targeted?: boolean }): RelevanceResult {
    const tier = item.sourceId ? registryEntry(item.sourceId)?.tier ?? null : null;
    // Targeted hunts are user-directed: only clear junk is skipped there.
    const threshold = item.targeted ? RELEVANCE_SKIP_THRESHOLD - 0.1 : RELEVANCE_SKIP_THRESHOLD;
    return scoreRelevance({ title: item.title, summary: item.summary, url: item.url, sourceHistory: this.sourceHistory(item.sourceId), sourceTier: tier }, threshold);
  }

  recordRelevanceSkip(title: string, url: string, r: RelevanceResult) {
    this.funnel.skippedRelevance += 1;
    const samples = this.funnel.relevanceSamples;
    samples.push({ title: title.slice(0, 160), url, score: r.score, reason: r.reason.slice(0, 240) });
    samples.sort((a, b) => a.score - b.score);
    if (samples.length > 25) samples.length = 25;
  }

  // -------------------------------------------------------------------------
  // Fetch state
  // -------------------------------------------------------------------------

  async state(url: string): Promise<FetchState | null> {
    if (this.states.has(url)) return this.states.get(url) ?? null;
    try {
      const m = await getFetchStates([url]);
      const s = m.get(url) ?? null;
      this.states.set(url, s);
      return s;
    } catch {
      this.states.set(url, null);
      return null;
    }
  }

  async preloadStates(urls: string[]) {
    const missing = urls.filter((u) => !this.states.has(u));
    if (!missing.length) return;
    try {
      const m = await getFetchStates(missing);
      for (const u of missing) this.states.set(u, m.get(u) ?? null);
    } catch {
      for (const u of missing) this.states.set(u, null);
    }
  }

  private commit(next: FetchState) {
    this.states.set(next.url, next);
    this.dirty.set(next.url, next);
  }

  markUnfinished(parentUrl: string | null | undefined) {
    if (parentUrl) this.unfinishedParents.add(parentUrl);
  }

  /**
   * Source-level document (feed, sitemap, listing, homepage) with a conditional GET.
   * 304 or an identical body short-circuits: nothing new to parse.
   */
  async fetchSourceDocument(
    sourceId: string | null | undefined,
    url: string,
    kind: FetchKind,
    opts: { timeoutMs?: number; maxBytes?: number; accept?: string; forceFull?: boolean } = {},
  ): Promise<SourceFetchResult> {
    if (!(await this.robotsAllowed(url))) {
      this.funnel.robotsBlocked += 1;
      return { status: "error", error: "Disallowed by robots.txt" };
    }
    const prev = opts.forceFull ? null : await this.state(url);
    try {
      const r = await safeConditionalFetch(url, {
        etag: prev?.etag,
        lastModified: prev?.lastModified,
        timeoutMs: opts.timeoutMs ?? 6000,
        maxBytes: opts.maxBytes ?? 3_000_000,
        userAgent: COLLECTOR_USER_AGENT,
        acceptHeader: opts.accept,
      });
      this.sourceReachable(sourceId, true);
      if (r.notModified) {
        const d = decideFetchOutcome(prev, { status: 304, etag: r.etag, lastModified: r.lastModified }, { url, kind, sourceId });
        this.commit(d.next);
        this.src(sourceId)!.notModified += 1;
        if (kind === "feed") this.funnel.feedsNotModified += 1;
        return { status: "not_modified" };
      }
      const d = decideFetchOutcome(prev, { status: r.status, etag: r.etag, lastModified: r.lastModified, contentHash: sha256Hex(r.bytes) }, { url, kind, sourceId });
      this.commit(d.next);
      if (d.outcome === "unchanged" && !opts.forceFull) {
        if (kind === "feed") this.funnel.feedsNotModified += 1;
        return { status: "unchanged" };
      }
      return { status: "ok", body: r.body, finalUrl: r.finalUrl, contentType: r.contentType };
    } catch (err) {
      const e = errMsg(err);
      this.sourceReachable(sourceId, false, `${kind[0].toUpperCase()}${kind.slice(1)} fetch failed: ${e}`);
      return { status: "error", error: e };
    }
  }

  /** Article fetch with validators from a previous fetch (304 → not_modified). */
  async fetchArticle(url: string, opts: { timeoutMs?: number; maxBytes?: number; userAgent?: string; accept?: string; conditional: boolean }): Promise<ArticleFetchResult> {
    const prev = opts.conditional ? await this.state(url) : null;
    const r = await safeConditionalFetch(url, {
      etag: prev?.etag,
      lastModified: prev?.lastModified,
      timeoutMs: opts.timeoutMs ?? 4500,
      maxBytes: opts.maxBytes,
      userAgent: opts.userAgent,
      acceptHeader: opts.accept,
    });
    if (r.notModified) return { status: "not_modified" };
    return { status: "ok", body: r.body, bytes: r.bytes, contentType: r.contentType, finalUrl: r.finalUrl, etag: r.etag, lastModified: r.lastModified, httpStatus: r.status };
  }

  /** Records an article fetch (content hash of the extracted text) and classifies it. */
  async noteArticleFetch(
    url: string,
    sourceId: string | null | undefined,
    obs: { status: number; etag?: string | null; lastModified?: string | null; textHash?: string | null; reportId?: string | null },
  ): Promise<FetchOutcome> {
    const prev = await this.state(url);
    const d = decideFetchOutcome(prev, { status: obs.status, etag: obs.etag, lastModified: obs.lastModified, contentHash: obs.textHash }, { url, kind: "article", sourceId });
    if (obs.reportId) d.next.reportId = obs.reportId;
    this.commit(d.next);
    return d.outcome;
  }

  /** Seeds fetch state for an already-stored article that has none yet (first revalidation baseline). */
  async ensureArticleBaseline(url: string, sourceId: string | null | undefined, stored: { textHash: string; version: number; reportId: string; ingestedAt?: string | null }) {
    const prev = await this.state(url);
    if (prev?.contentHash) return prev;
    const base: FetchState = {
      url,
      kind: "article",
      sourceId: sourceId ?? null,
      contentHash: stored.textHash,
      version: stored.version,
      previousHashes: [],
      notModifiedCount: 0,
      reportId: stored.reportId,
      // The stored copy is the baseline: it was fetched when it was ingested.
      lastFetchedAt: stored.ingestedAt ?? new Date().toISOString(),
    };
    this.states.set(url, base);
    return base;
  }

  async revalidationDecision(url: string, hint: { lastmod?: string | null; updatedAt?: string | null }) {
    return needsRevalidation(await this.state(url), hint, Date.now(), ARTICLE_REVALIDATE_MS);
  }

  // -------------------------------------------------------------------------
  // robots.txt
  // -------------------------------------------------------------------------

  private robotsFor(url: string): Promise<RobotsRules | null> {
    let origin: string;
    try {
      origin = new URL(url).origin;
    } catch {
      return Promise.resolve(null);
    }
    let p = this.robots.get(origin);
    if (!p) {
      p = safeFetchText(`${origin}/robots.txt`, { timeoutMs: 3500, maxBytes: 500_000, userAgent: COLLECTOR_USER_AGENT, acceptHeader: "text/plain,*/*;q=0.5" })
        .then((txt) => (txt && !/<html[\s>]/i.test(txt.slice(0, 500)) ? parseRobotsTxt(txt) : null))
        .catch(() => null);
      this.robots.set(origin, p);
    }
    return p;
  }

  async robotsAllowed(url: string): Promise<boolean> {
    return robotsAllows(await this.robotsFor(url), COLLECTOR_USER_AGENT, url);
  }

  async crawlDelayMs(url: string): Promise<number> {
    return robotsCrawlDelayMs(await this.robotsFor(url), COLLECTOR_USER_AGENT);
  }

  async robotsSitemaps(url: string): Promise<string[]> {
    return (await this.robotsFor(url))?.sitemaps ?? [];
  }

  // -------------------------------------------------------------------------
  // Finish
  // -------------------------------------------------------------------------

  sourceSummary(): Array<{ sourceId: string; name: string; counters: YieldCounters; reachable: boolean; errors: string[] }> {
    return [...this.perSource.entries()].map(([sourceId, s]) => ({ sourceId, name: s.name, counters: s.counters, reachable: s.reachable, errors: s.errors }));
  }

  /** Persists fetch states, per-source health and the job funnel. Never throws. */
  async finish(jobCounts: { discovered: number }): Promise<CrawlFunnel> {
    this.funnel.discovered = jobCounts.discovered;
    const now = new Date().toISOString();
    const states = [...this.dirty.values()].filter((s) => !this.unfinishedParents.has(s.url));
    // Feeds whose items were cut by caps keep no validators, so the next run reads them in full.
    for (const parent of this.unfinishedParents) {
      const s = this.dirty.get(parent) ?? this.states.get(parent);
      if (s) states.push({ ...s, etag: null, lastModified: null, contentHash: null, version: s.version });
    }
    try {
      for (let i = 0; i < states.length; i += 500) await putFetchStates(states.slice(i, i + 500));
    } catch (err) {
      console.warn("[collector] fetch state not saved:", errMsg(err));
    }
    const updated: SourceHealth[] = [];
    for (const [sourceId, s] of this.perSource) {
      // A source that was selected but had nothing attempted (e.g. feed discovery disabled) is not a failure.
      const attempted = s.reachable || s.errors.length > 0;
      if (!attempted && s.counters.fetched === 0) continue;
      updated.push(
        applyRunOutcome(this.health.get(sourceId), sourceId, {
          jobId: this.jobId,
          at: now,
          counters: s.counters,
          reachable: s.reachable,
          notModified: s.notModified,
          error: s.errors.length ? s.errors[s.errors.length - 1] : null,
        }, s.name),
      );
    }
    try {
      await putSourceHealth(updated);
    } catch (err) {
      console.warn("[collector] source health not saved:", errMsg(err));
    }
    try {
      await putJobFunnel(this.jobId, this.funnel);
    } catch (err) {
      console.warn("[collector] job funnel not saved:", errMsg(err));
    }
    return this.funnel;
  }
}
