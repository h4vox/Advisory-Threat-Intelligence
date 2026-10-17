/**
 * Duplicate and near-duplicate matching over stored fingerprints (AIE Web Extraction spec §18),
 * and the choice of which copy is canonical. Pure.
 *
 * Match order (first hit wins): canonical URL → content SHA-256 → normalised-text hash →
 * title+publisher hash → SimHash (Hamming <= 3). A duplicate is linked to the canonical report and
 * its URL is recorded as a mirror ("also seen at"). When the new copy is the better canonical
 * (higher tier, primary publisher rather than a news re-post), the new copy is stored and the
 * existing one is linked to it instead.
 */
import { hammingDistance64, SIMHASH_NEAR_DUPLICATE_DISTANCE, type DocumentFingerprints } from "./fingerprint.ts";

export type DedupIndexEntry = {
  id: string;
  canonicalUrl: string;
  title: string;
  publisher: string;
  sourceDomain: string;
  sourceTier?: number | null;
  publishedAt?: string | null;
  ingestedAt?: string | null;
  fingerprints?: Partial<DocumentFingerprints> | null;
  /** Legacy textHash (exact extracted-text SHA-256) for records without fingerprints. */
  textHash?: string | null;
};

export type DedupCandidate = {
  canonicalUrl: string;
  title: string;
  publisher: string;
  sourceDomain: string;
  sourceTier?: number | null;
  publishedAt?: string | null;
  fingerprints: DocumentFingerprints;
};

export type DuplicateKind = "canonical_url" | "content_sha256" | "normalized_text" | "title_publisher" | "simhash";

export type DuplicateMatch = { kind: DuplicateKind; entry: DedupIndexEntry; distance?: number };

export const DUPLICATE_KIND_LABEL: Record<DuplicateKind, string> = {
  canonical_url: "same canonical URL",
  content_sha256: "identical content (SHA-256)",
  normalized_text: "identical normalised text",
  title_publisher: "same title and publisher",
  simhash: "near-duplicate (SimHash)",
};

/** In-memory index with O(1) exact lookups and a linear SimHash scan. */
export class DedupIndex {
  private byUrl = new Map<string, DedupIndexEntry>();
  private bySha = new Map<string, DedupIndexEntry>();
  private byNorm = new Map<string, DedupIndexEntry>();
  private byTitle = new Map<string, DedupIndexEntry>();
  private sims: Array<{ simhash: string; entry: DedupIndexEntry }> = [];

  constructor(entries: DedupIndexEntry[] = []) {
    for (const e of entries) this.add(e);
  }

  get size() {
    return this.byUrl.size;
  }

  add(e: DedupIndexEntry) {
    if (e.canonicalUrl) this.byUrl.set(e.canonicalUrl, e);
    const sha = e.fingerprints?.contentSha256 || e.textHash;
    if (sha) this.bySha.set(sha, e);
    if (e.fingerprints?.normalizedTextHash) this.byNorm.set(e.fingerprints.normalizedTextHash, e);
    if (e.fingerprints?.titlePublisherHash) this.byTitle.set(e.fingerprints.titlePublisherHash, e);
    if (e.fingerprints?.simhash && /^[0-9a-f]{16}$/i.test(e.fingerprints.simhash) && e.fingerprints.simhash !== "0000000000000000") {
      this.sims.push({ simhash: e.fingerprints.simhash, entry: e });
    }
  }

  hasUrl(canonicalUrl: string) {
    return this.byUrl.has(canonicalUrl);
  }

  getByUrl(canonicalUrl: string) {
    return this.byUrl.get(canonicalUrl);
  }

  /** Content match only (the canonical-URL check happens before the fetch). */
  findContentDuplicate(c: DedupCandidate, opts: { maxDistance?: number; minTokens?: number } = {}): DuplicateMatch | null {
    const notSelf = (e?: DedupIndexEntry) => (e && e.canonicalUrl !== c.canonicalUrl ? e : undefined);
    const fp = c.fingerprints;
    let e = notSelf(this.bySha.get(fp.contentSha256));
    if (e) return { kind: "content_sha256", entry: e };
    e = notSelf(this.byNorm.get(fp.normalizedTextHash));
    if (e) return { kind: "normalized_text", entry: e };
    if (fp.titlePublisherHash) {
      e = notSelf(this.byTitle.get(fp.titlePublisherHash));
      if (e && titleMatchConfirmed(c, e)) return { kind: "title_publisher", entry: e };
    }
    // Very short texts collide by chance; require enough tokens for SimHash.
    if (fp.tokens >= (opts.minTokens ?? 80) && fp.simhash !== "0000000000000000") {
      const max = opts.maxDistance ?? SIMHASH_NEAR_DUPLICATE_DISTANCE;
      let best: DuplicateMatch | null = null;
      for (const s of this.sims) {
        if (s.entry.canonicalUrl === c.canonicalUrl) continue;
        const d = hammingDistance64(fp.simhash, s.simhash);
        if (d <= max && (!best || d < (best.distance ?? 64))) best = { kind: "simhash", entry: s.entry, distance: d };
      }
      if (best) return best;
    }
    return null;
  }
}

/** Loose SimHash similarity that still separates unrelated texts (random pairs average ~32 bits apart). */
const TITLE_MATCH_MAX_DISTANCE = 16;
const TITLE_MATCH_MAX_DAYS = 3;

/**
 * A same-title-and-publisher hit is only a duplicate with supporting evidence: loosely similar content,
 * or publication within a few days. Recurring series ("Weekly Threat Report", "Monthly ransomware
 * roundup") reuse one title for different issues and must not be dropped as duplicates.
 */
function titleMatchConfirmed(c: DedupCandidate, e: DedupIndexEntry): boolean {
  const sim = e.fingerprints?.simhash;
  if (sim && /^[0-9a-f]{16}$/i.test(sim) && sim !== "0000000000000000" && c.fingerprints.simhash !== "0000000000000000") {
    if (hammingDistance64(c.fingerprints.simhash, sim) <= TITLE_MATCH_MAX_DISTANCE) return true;
  }
  const a = c.publishedAt ? Date.parse(c.publishedAt) : NaN;
  const b = e.publishedAt ? Date.parse(e.publishedAt) : NaN;
  return Number.isFinite(a) && Number.isFinite(b) && Math.abs(a - b) <= TITLE_MATCH_MAX_DAYS * 86_400_000;
}

/** News and aggregation sites that re-post vendor research; never preferred as canonical. */
const SYNDICATORS = [
  "thehackernews.com", "bleepingcomputer.com", "securityweek.com", "darkreading.com", "therecord.media",
  "infosecurity-magazine.com", "securityaffairs.com", "cybersecuritynews.com", "gbhackers.com", "hackread.com",
  "helpnetsecurity.com", "scmagazine.com", "csoonline.com", "zdnet.com", "techcrunch.com", "theregister.com",
  "cyberscoop.com", "medium.com", "substack.com", "linkedin.com", "reddit.com", "news.ycombinator.com",
  "feedly.com", "cybersecurity-help.cz", "redpacketsecurity.com", "socradar.io", "cybermaterial.com",
];

export function isSyndicatorDomain(domain: string): boolean {
  const d = (domain || "").toLowerCase().replace(/^www\./, "");
  return SYNDICATORS.some((s) => d === s || d.endsWith(`.${s}`));
}

type Comparable = { sourceTier?: number | null; sourceDomain: string; publishedAt?: string | null; ingestedAt?: string | null };

/**
 * Which copy should be canonical? Returns "candidate" or "existing".
 * 1. Primary publisher beats a syndicator / news re-post.
 * 2. Lower tier number (1 authoritative … 4 community) wins.
 * 3. Earlier publication date wins; ties keep the existing record (stable).
 */
export function preferCanonical(existing: Comparable, candidate: Comparable): "existing" | "candidate" {
  const synE = isSyndicatorDomain(existing.sourceDomain);
  const synC = isSyndicatorDomain(candidate.sourceDomain);
  if (synE !== synC) return synE ? "candidate" : "existing";
  const tE = existing.sourceTier ?? 4;
  const tC = candidate.sourceTier ?? 4;
  if (tE !== tC) return tC < tE ? "candidate" : "existing";
  const pE = existing.publishedAt ? Date.parse(existing.publishedAt) : NaN;
  const pC = candidate.publishedAt ? Date.parse(candidate.publishedAt) : NaN;
  if (Number.isFinite(pE) && Number.isFinite(pC) && pC < pE) return "candidate";
  return "existing";
}

export type MirrorRecord = {
  url: string;
  canonicalUrl: string;
  publisher: string;
  sourceDomain: string;
  sourceId?: string | null;
  matchKind: DuplicateKind;
  distance?: number;
  seenAt: string;
};

/** Adds a mirror without duplicating URLs; newest first, capped. */
export function mergeMirrors(existing: MirrorRecord[] | null | undefined, add: MirrorRecord[], cap = 50): MirrorRecord[] {
  const out: MirrorRecord[] = [];
  const seen = new Set<string>();
  for (const m of [...add, ...(existing ?? [])]) {
    if (seen.has(m.canonicalUrl)) continue;
    seen.add(m.canonicalUrl);
    out.push(m);
  }
  return out.slice(0, cap);
}
