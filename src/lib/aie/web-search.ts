/**
 * Web-search discovery for the crawler: which searches a run makes (the analyst's keywords, a
 * targeted hunt, and the research taxonomy), and how a DuckDuckGo HTML results page is read.
 * Pure and unit-tested; the crawler does the fetching.
 */
import { pickResearchQueries, splitKeywordPhrases, type ResearchCategoryId, type ResearchDiscoveryConfig } from "./research-taxonomy.ts";

export type SearchPlanItem = {
  query: string;
  /** Where the search comes from, shown with the reports it finds. */
  origin: "targeted" | "keyword" | "research";
  category?: ResearchCategoryId;
};

/** Keyword searches per run (rotating through the analyst's list). */
const KEYWORD_QUERIES_PER_RUN = 2;

/**
 * The searches for one crawl run.
 *
 * - A targeted hunt searches its own query only.
 * - Otherwise: up to two of the analyst's keyword phrases (rotating by round) and, when enabled,
 *   `queriesPerRun` taxonomy queries, the thinnest categories first.
 */
export function buildSearchPlan(opts: {
  targetedQuery?: string | null;
  keywords?: string;
  research: ResearchDiscoveryConfig;
  round: number;
  counts?: Partial<Record<ResearchCategoryId, number>>;
}): SearchPlanItem[] {
  const targeted = String(opts.targetedQuery ?? "").replace(/\s+/g, " ").trim();
  if (targeted) {
    const q = targeted.slice(0, 160);
    return [
      { query: `${q} threat intelligence technical analysis`, origin: "targeted" },
      { query: `${q} attack chain indicators of compromise`, origin: "targeted" },
      { query: `${q} TTPs technical report`, origin: "targeted" },
    ];
  }
  const plan: SearchPlanItem[] = [];
  const phrases = splitKeywordPhrases(opts.keywords ?? "");
  const round = Math.max(0, Math.floor(opts.round));
  for (let i = 0; i < Math.min(KEYWORD_QUERIES_PER_RUN, phrases.length); i++) {
    const phrase = phrases[(round * KEYWORD_QUERIES_PER_RUN + i) % phrases.length];
    const query = `${phrase} threat intelligence technical analysis`;
    if (!plan.some((p) => p.query === query)) plan.push({ query, origin: "keyword" });
  }
  if (opts.research.enabled && opts.research.queriesPerRun > 0) {
    for (const r of pickResearchQueries({ round, count: opts.research.queriesPerRun, counts: opts.counts, includeBas: opts.research.bas })) {
      plan.push({ query: r.query, origin: "research", category: r.category });
    }
  }
  return plan;
}

export type SearchResult = { url: string; title: string; snippet: string };

function textOf(html: string): string {
  return html
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** The target URL in a DuckDuckGo redirect link ("//duckduckgo.com/l/?uddg=<encoded>&rut=…"). */
function targetOf(href: string): string | null {
  const m = href.replace(/&amp;/g, "&").match(/[?&]uddg=([^&]+)/);
  const raw = m ? m[1] : href;
  try {
    const url = new URL(decodeURIComponent(raw), "https://duckduckgo.com");
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (/(^|\.)duckduckgo\.com$/i.test(url.hostname)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * Results of a DuckDuckGo HTML page, in order, with their titles and snippets. Falls back to the
 * bare redirect links (no titles) when the result markup is not recognised.
 */
export function parseDuckDuckGoHtml(html: string, max = 30): SearchResult[] {
  const out: SearchResult[] = [];
  const seen = new Set<string>();
  const anchor = /<a\b[^>]*class="[^"]*\bresult__a\b[^"]*"[^>]*>([\s\S]*?)<\/a>/gi;
  for (let m = anchor.exec(html); m && out.length < max; m = anchor.exec(html)) {
    const href = m[0].match(/\bhref="([^"]+)"/i)?.[1];
    const url = href ? targetOf(href) : null;
    if (!url || seen.has(url)) continue;
    seen.add(url);
    // The snippet follows the title within the same result block.
    const rest = html.slice(m.index + m[0].length, m.index + m[0].length + 4000);
    const next = rest.search(/class="[^"]*\bresult__a\b/);
    const block = next >= 0 ? rest.slice(0, next) : rest;
    const snippet = block.match(/class="[^"]*\bresult__snippet\b[^"]*"[^>]*>([\s\S]*?)<\/(?:a|div|td)>/i)?.[1];
    out.push({ url, title: textOf(m[1]).slice(0, 240), snippet: snippet ? textOf(snippet).slice(0, 400) : "" });
  }
  if (out.length) return out;
  for (const m of html.matchAll(/uddg=([^"&]+)/g)) {
    const url = targetOf(`?uddg=${m[1]}`);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ url, title: "", snippet: "" });
    if (out.length >= max) break;
  }
  return out;
}

/**
 * True when DuckDuckGo answered with its anti-bot challenge instead of results (it does this to
 * servers that search often). The crawler then stops asking it for the rest of the run.
 */
export function isSearchChallenge(html: string): boolean {
  return /anomaly-modal|bots use DuckDuckGo too|challenge-form|Unfortunately, bots|captcha/i.test(html) && !/class="[^"]*\bresult__a\b/.test(html);
}

function cleanResult(url: unknown, title: unknown, snippet: unknown): SearchResult | null {
  if (typeof url !== "string") return null;
  try {
    const u = new URL(url);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    return { url: u.toString(), title: textOf(String(title ?? "")).slice(0, 240), snippet: textOf(String(snippet ?? "")).slice(0, 400) };
  } catch {
    return null;
  }
}

/** Results of a SearXNG JSON response (`/search?format=json`). */
export function parseSearxngJson(body: unknown, max = 30): SearchResult[] {
  const results = (body as { results?: Array<{ url?: unknown; title?: unknown; content?: unknown }> })?.results;
  if (!Array.isArray(results)) return [];
  const out: SearchResult[] = [];
  const seen = new Set<string>();
  for (const r of results) {
    const c = cleanResult(r?.url, r?.title, r?.content);
    if (!c || seen.has(c.url)) continue;
    seen.add(c.url);
    out.push(c);
    if (out.length >= max) break;
  }
  return out;
}

/** Results of a Brave Search API response (`/res/v1/web/search`). */
export function parseBraveJson(body: unknown, max = 30): SearchResult[] {
  const results = (body as { web?: { results?: Array<{ url?: unknown; title?: unknown; description?: unknown }> } })?.web?.results;
  if (!Array.isArray(results)) return [];
  const out: SearchResult[] = [];
  const seen = new Set<string>();
  for (const r of results) {
    const c = cleanResult(r?.url, r?.title, r?.description);
    if (!c || seen.has(c.url)) continue;
    seen.add(c.url);
    out.push(c);
    if (out.length >= max) break;
  }
  return out;
}

export type SearchProvider = { id: "searxng" | "brave" | "duckduckgo"; label: string };

/**
 * Search engines to use, in order: the ones configured in the environment (reliable APIs) first,
 * then DuckDuckGo's HTML page (free, but it challenges servers that search often).
 *   AIE_SEARXNG_URL        a SearXNG instance with the JSON format enabled (self-hostable, free)
 *   BRAVE_SEARCH_API_KEY   Brave Search API (free tier available)
 */
export function searchProviders(env: Record<string, string | undefined>): SearchProvider[] {
  const out: SearchProvider[] = [];
  if (env.AIE_SEARXNG_URL?.trim()) out.push({ id: "searxng", label: "SearXNG" });
  if (env.BRAVE_SEARCH_API_KEY?.trim()) out.push({ id: "brave", label: "Brave Search" });
  if (env.AIE_DISABLE_DUCKDUCKGO?.trim() !== "1") out.push({ id: "duckduckgo", label: "DuckDuckGo" });
  return out;
}
