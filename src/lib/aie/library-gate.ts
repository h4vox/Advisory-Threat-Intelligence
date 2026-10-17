/**
 * Library gate: decides whether a stored report belongs in the threat-intelligence library.
 *
 * Rule-based for now; an AI reviewer can later supply the same verdict shape (see `GateVerdict`).
 * Reports it rejects are hidden, never deleted: they keep `status: "rejected"` with the reasons, the
 * Library's "Hidden" view lists them, and Restore brings one back for good (`keep` override).
 *
 * Order of rules:
 *  1. Protected: anything with real threat evidence (ATT&CK techniques, CVEs, two or more
 *     indicators, an attack chain, recognised actors / malware / campaigns, high quality score) or
 *     coming from a structured source is always kept.
 *  2. Page type: homepages, sitemaps, index / listing pages, legal and contact pages, search
 *     results, non-CTI government service sites.
 *  3. Topic: the relevance pre-score (title, summary, URL) finds only off-topic signals — webinars,
 *     podcasts, product launches, earnings, hiring, marketing, events — and nothing adversarial.
 *  4. Stub: under 120 words (when the count is known) with no technical content at all.
 *
 * SERVER ONLY (the topic rule uses the bundled ATT&CK knowledge through scoreRelevance).
 */
import { RELEVANCE_SKIP_THRESHOLD, scoreRelevance } from "./collector/relevance.ts";

/** Bump when the rules change so stored reports are checked again. */
export const LIBRARY_GATE_VERSION = 1;

export type GateRule = "page_type" | "topic" | "stub";

export type GateInput = {
  title: string;
  url: string;
  /** Feed summary or the first part of the text. */
  summary?: string | null;
  wordCount: number;
  iocCount: number;
  techniques: number;
  cves: number;
  attackChainSteps: number;
  /** Actors, malware and campaigns recognised in the report (ATT&CK references or analysis). */
  entities: number;
  qualityScore: number;
  sourceTier?: 1 | 2 | 3 | 4 | null;
  /** Records from structured connectors (ATT&CK, KEV, CTID, Atomic, Attack Flow). */
  structured?: boolean;
  /** Set by an analyst's Restore: never hide again. */
  keep?: boolean;
};

export type GateVerdict = {
  verdict: "keep" | "reject";
  rule: GateRule | null;
  /** Plain-language reasons, most important first. */
  reasons: string[];
  /** What protected a report that would otherwise have been rejected. */
  protectedBy: string[];
  /** Relevance pre-score when the topic rule ran (0–1). */
  relevance: number | null;
};

const NON_CTI_HOSTS = [/^(?:www\.)?(?:uscis|ice|e-verify)\.gov$/i, /^edit\.dhs\.gov$/i];

const INDEX_PATH_ENDINGS =
  /\/(?:podcasts?|webinars?|webcasts?|events?|white-?papers?|ebooks?|datasheets?|resources|resource-center|library|latest-publications|publications|projects|tips-advice|business-security|news|newsroom|press(?:-releases?)?|blog|blogs|insights|archives?|all-posts|topics?|categories)$/i;
const LISTING_SEGMENTS = /\/(?:tag|tags|category|categories|author|authors|topic|topics|page)\/[^/]+(?:\/page\/\d+)?$/i;
const UTILITY_PATHS = /\/(?:privacy(?:-policy|-notice)?|cookie(?:-policy|s)?|terms(?:-of-(?:use|service))?|legal|disclosure-policy|contact(?:-us)?|about(?:-us)?|careers?|jobs|login|sign-?in|register|subscribe|unsubscribe|search|404|sitemap[\w.-]*)$/i;
const UTILITY_TITLES =
  /^(?:podcasts?|webinars?|white papers|tips & advice|privacy (?:policy|notice)|cookie policy|terms of (?:use|service)|contact(?: us)?|about(?: us)?|careers|sitemap|search results?|subscribe|log ?in|sign ?in)$|\bpage not found\b|\b404\b.*\bnot found\b|\baccess denied\b|\bjust a moment\b|\battention required\b/i;

function pageTypeReason(url: string, title: string): string | null {
  const t = title.replace(/\s+/g, " ").trim();
  if (UTILITY_TITLES.test(t)) return `Not an article: "${t.slice(0, 60)}" page`;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  if (NON_CTI_HOSTS.some((re) => re.test(host))) return `Government service site, not threat intelligence (${host.replace(/^www\./, "")})`;
  const params = u.searchParams;
  if (params.has("s") || params.has("q") || params.has("query") || [...params.keys()].some((k) => /^f\[|^f%5b|^filter/i.test(k))) {
    return "Search or filter results page, not a single report";
  }
  const path = u.pathname.replace(/\/+$/, "").toLowerCase();
  if (path === "" || /^\/(?:[a-z]{2}(?:[-_][a-z]{2})?|index\.html?|home)$/.test(path)) return "Website homepage, not a report";
  if (/sitemap/.test(path)) return "Sitemap page, not a report";
  if (UTILITY_PATHS.test(path)) return `Site utility page (${path.split("/").pop()})`;
  if (INDEX_PATH_ENDINGS.test(path)) return `Listing / index page (${path.split("/").pop()}), not a single report`;
  if (LISTING_SEGMENTS.test(path)) return "Tag, category or author listing, not a single report";
  return null;
}

export function evaluateLibraryReport(input: GateInput): GateVerdict {
  const protectedBy: string[] = [];
  if (input.keep) protectedBy.push("kept by an analyst");
  if (input.structured) protectedBy.push("structured source");
  if (input.techniques > 0) protectedBy.push(`${input.techniques} ATT&CK technique${input.techniques === 1 ? "" : "s"}`);
  if (input.cves > 0) protectedBy.push(`${input.cves} CVE${input.cves === 1 ? "" : "s"}`);
  if (input.iocCount >= 2) protectedBy.push(`${input.iocCount} indicators`);
  if (input.attackChainSteps > 0) protectedBy.push("attack chain");
  if (input.entities > 0) protectedBy.push(`${input.entities} known actor / malware / campaign reference${input.entities === 1 ? "" : "s"}`);
  if (input.qualityScore >= 0.7) protectedBy.push(`quality ${Math.round(input.qualityScore * 100)}%`);

  const title = input.title ?? "";
  const url = input.url ?? "";
  const keep = (relevance: number | null = null): GateVerdict => ({ verdict: "keep", rule: null, reasons: [], protectedBy, relevance });
  const reject = (rule: GateRule, reasons: string[], relevance: number | null = null): GateVerdict =>
    protectedBy.length ? keep(relevance) : { verdict: "reject", rule, reasons, protectedBy, relevance };

  const page = pageTypeReason(url, title);
  if (page) return reject("page_type", [page]);

  const rel = scoreRelevance({ title, summary: input.summary ?? "", url, sourceTier: input.sourceTier ?? null });
  if (rel.decision === "skip" && !rel.strongPositive && rel.score < RELEVANCE_SKIP_THRESHOLD) {
    const off = [...new Set(rel.signals.filter((s) => s.polarity === "negative").map((s) => s.label))];
    const reasons = off.length
      ? [`Off-topic: ${off.slice(0, 3).join(", ")}`, "No threat-intelligence signals in the title or summary"]
      : ["No threat-intelligence signals in the title or summary"];
    return reject("topic", reasons, rel.score);
  }

  // Only when the word count is known: older or PDF-only records can have none stored.
  if (input.wordCount > 0 && input.wordCount < 120 && input.iocCount === 0) {
    return reject("stub", [`Too short to be a report (${input.wordCount} words) and no technical content`], rel.score);
  }
  return keep(rel.score);
}

/** One line for the report card / table ("Hidden as unrelated: …"). */
export function gateReasonLine(v: Pick<GateVerdict, "reasons">): string {
  return `Hidden as unrelated: ${v.reasons.join(" · ")}`;
}
