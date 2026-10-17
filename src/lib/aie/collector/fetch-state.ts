/**
 * Incremental crawling (AIE Web Extraction spec §45): per-URL fetch state, conditional GET
 * headers and the decision taken after a fetch. Pure; persistence lives in
 * src/lib/mongodb/collector-repo.server.ts.
 *
 * Outcomes
 *  - not_modified   HTTP 304 to a conditional request: nothing downloaded, nothing re-processed
 *  - unchanged      200, but the content hash equals the last stored one (server ignores validators)
 *  - new            first time this URL is fetched
 *  - changed        the content hash differs: a new version (version + 1, previous hash kept)
 */

export type FetchKind = "feed" | "article" | "sitemap" | "listing" | "pdf";

export type FetchState = {
  url: string;
  kind: FetchKind;
  sourceId?: string | null;
  etag?: string | null;
  lastModified?: string | null;
  /** Hash of the extracted text (articles) or of the raw body (feeds, sitemaps, listings). */
  contentHash?: string | null;
  lastStatus?: number | null;
  lastFetchedAt?: string | null;
  lastChangedAt?: string | null;
  version: number;
  /** Most recent first; capped at MAX_PREVIOUS_HASHES. */
  previousHashes: string[];
  notModifiedCount: number;
  reportId?: string | null;
};

export const MAX_PREVIOUS_HASHES = 10;

export type FetchOutcome = "not_modified" | "unchanged" | "new" | "changed";

export type FetchObservation = {
  status: number;
  etag?: string | null;
  lastModified?: string | null;
  /** Required unless status is 304. */
  contentHash?: string | null;
  fetchedAt?: string;
};

export function emptyFetchState(url: string, kind: FetchKind, sourceId?: string | null): FetchState {
  return { url, kind, sourceId: sourceId ?? null, version: 0, previousHashes: [], notModifiedCount: 0 };
}

/** Conditional request headers for a previously fetched URL (none for a first fetch). */
export function conditionalHeaders(state?: FetchState | null): Record<string, string> {
  const h: Record<string, string> = {};
  if (!state || !state.lastFetchedAt) return h;
  if (state.etag) h["if-none-match"] = state.etag;
  if (state.lastModified) h["if-modified-since"] = state.lastModified;
  return h;
}

/** Applies a fetch observation to the stored state and classifies it. */
export function decideFetchOutcome(
  prev: FetchState | null | undefined,
  obs: FetchObservation,
  base: { url: string; kind: FetchKind; sourceId?: string | null },
): { outcome: FetchOutcome; next: FetchState; previousHash: string | null } {
  const now = obs.fetchedAt ?? new Date().toISOString();
  const state: FetchState = prev ? { ...prev, previousHashes: [...prev.previousHashes] } : emptyFetchState(base.url, base.kind, base.sourceId);
  state.lastStatus = obs.status;
  state.lastFetchedAt = now;
  // Keep validators unless the server sent new ones (a 304 may omit them).
  if (obs.etag) state.etag = obs.etag;
  if (obs.lastModified) state.lastModified = obs.lastModified;

  if (obs.status === 304) {
    state.notModifiedCount += 1;
    return { outcome: "not_modified", next: state, previousHash: state.contentHash ?? null };
  }

  const hash = obs.contentHash ?? null;
  if (!prev || !prev.contentHash || prev.version === 0) {
    state.contentHash = hash;
    state.version = Math.max(1, prev?.version ?? 0);
    state.lastChangedAt = now;
    return { outcome: "new", next: state, previousHash: null };
  }
  if (hash && hash === prev.contentHash) {
    return { outcome: "unchanged", next: state, previousHash: prev.contentHash };
  }
  state.previousHashes = [prev.contentHash, ...prev.previousHashes.filter((h) => h !== prev.contentHash)].slice(
    0,
    MAX_PREVIOUS_HASHES,
  );
  state.contentHash = hash;
  state.version = prev.version + 1;
  state.lastChangedAt = now;
  return { outcome: "changed", next: state, previousHash: prev.contentHash };
}

function ts(s?: string | null): number {
  if (!s) return NaN;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : NaN;
}

/**
 * Should a URL that is already stored be fetched again?
 *  - never fetched (no state)                         → yes
 *  - the listing says it changed after our last fetch → yes (sitemap lastmod, feed updated date)
 *  - older than maxAgeMs since the last fetch          → yes (periodic revalidation; conditional GET keeps it cheap)
 *  - otherwise                                         → no
 */
export function needsRevalidation(
  state: FetchState | null | undefined,
  hint: { lastmod?: string | null; updatedAt?: string | null },
  now: number,
  maxAgeMs: number,
): { revalidate: boolean; reason: string } {
  if (!state || !state.lastFetchedAt) return { revalidate: true, reason: "No fetch state recorded" };
  const last = ts(state.lastFetchedAt);
  const changedAt = Math.max(ts(hint.lastmod) || 0, ts(hint.updatedAt) || 0);
  if (changedAt && Number.isFinite(last) && changedAt > last) {
    return { revalidate: true, reason: `Source lists an update (${new Date(changedAt).toISOString().slice(0, 10)}) after the last fetch` };
  }
  if (Number.isFinite(last) && now - last >= maxAgeMs) {
    return { revalidate: true, reason: "Periodic revalidation (conditional GET)" };
  }
  return { revalidate: false, reason: "Unchanged since last fetch" };
}
