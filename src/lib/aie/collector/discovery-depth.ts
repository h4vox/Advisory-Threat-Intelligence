/**
 * Discovery depth (AIE Web Extraction spec §15–16, §45): sitemap and sitemap-index parsing with
 * lastmod, feed autodiscovery from <link rel="alternate">, listing/archive pagination, robots.txt
 * rules and the bounded per-source backfill plan. Pure string parsing; fetching stays in the
 * crawler through the SSRF-guarded fetchers.
 */

// ---------------------------------------------------------------------------
// Sitemaps
// ---------------------------------------------------------------------------

export type SitemapEntry = { loc: string; lastmod: string | null };
export type ParsedSitemap = { type: "urlset" | "sitemapindex" | "unknown"; entries: SitemapEntry[] };

function decodeXml(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .trim();
}

/** Normalises a W3C datetime / date to an ISO string; null when unparseable. */
export function parseLastmod(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const s = raw.trim();
  if (!s) return null;
  const t = Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(s) ? `${s}T00:00:00Z` : s);
  if (!Number.isFinite(t)) return null;
  const year = new Date(t).getUTCFullYear();
  if (year < 1995 || year > 2100) return null;
  return new Date(t).toISOString();
}

/** Parses a sitemap <urlset> or <sitemapindex> (namespaces and CDATA tolerated). */
export function parseSitemapXml(xml: string, maxEntries = 50_000): ParsedSitemap {
  if (!xml) return { type: "unknown", entries: [] };
  const isIndex = /<(?:\w+:)?sitemapindex\b/i.test(xml);
  const isUrlset = /<(?:\w+:)?urlset\b/i.test(xml);
  const tag = isIndex ? "sitemap" : "url";
  const blockRe = new RegExp(`<(?:\\w+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:\\w+:)?${tag}>`, "gi");
  const entries: SitemapEntry[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(xml)) && entries.length < maxEntries) {
    const body = m[1];
    const loc = body.match(/<(?:\w+:)?loc\b[^>]*>([\s\S]*?)<\/(?:\w+:)?loc>/i)?.[1];
    if (!loc) continue;
    const url = decodeXml(loc);
    if (!/^https?:\/\//i.test(url) || seen.has(url)) continue;
    seen.add(url);
    const lastmod = body.match(/<(?:\w+:)?lastmod\b[^>]*>([\s\S]*?)<\/(?:\w+:)?lastmod>/i)?.[1];
    entries.push({ loc: url, lastmod: parseLastmod(lastmod ? decodeXml(lastmod) : null) });
  }
  return { type: isIndex ? "sitemapindex" : isUrlset ? "urlset" : "unknown", entries };
}

/** Entries modified on/after `sinceIso` (entries without lastmod are kept only when keepUndated). */
export function filterSitemapEntries(
  entries: SitemapEntry[],
  opts: { sinceIso?: string | null; untilIso?: string | null; keepUndated?: boolean; limit?: number },
): SitemapEntry[] {
  const since = opts.sinceIso ? Date.parse(opts.sinceIso) : NaN;
  const until = opts.untilIso ? Date.parse(opts.untilIso) : NaN;
  const kept = entries.filter((e) => {
    if (!e.lastmod) return opts.keepUndated ?? false;
    const t = Date.parse(e.lastmod);
    return (!Number.isFinite(since) || t >= since) && (!Number.isFinite(until) || t < until);
  });
  kept.sort((a, b) => (b.lastmod ?? "").localeCompare(a.lastmod ?? ""));
  return opts.limit ? kept.slice(0, opts.limit) : kept;
}

/**
 * Chooses which child sitemaps of an index to open: recent lastmod first, and names that look like
 * posts/articles ahead of tags, categories, authors, products and images.
 */
export function rankChildSitemaps(entries: SitemapEntry[], opts: { sinceIso?: string | null; limit: number }): SitemapEntry[] {
  const since = opts.sinceIso ? Date.parse(opts.sinceIso) : NaN;
  const score = (e: SitemapEntry) => {
    const u = e.loc.toLowerCase();
    let s = 0;
    if (/post|article|blog|research|report|threat|advisor|news|20\d{2}/.test(u)) s += 2;
    if (/tag|categor|author|product|page-sitemap|image|video|attachment|event|career|job|landing/.test(u)) s -= 3;
    // Nothing in a child sitemap last modified before the window can be new.
    if (e.lastmod && Number.isFinite(since) && Date.parse(e.lastmod) < since) return -99;
    return s;
  };
  return [...entries]
    .filter((e) => score(e) > -5)
    .sort((a, b) => score(b) - score(a) || (b.lastmod ?? "").localeCompare(a.lastmod ?? ""))
    .slice(0, opts.limit);
}

/** Readable title from a URL slug ("/2025/03/akira-ransomware-esxi/" → "akira ransomware esxi"). */
export function titleFromSlug(url: string): string {
  try {
    const segs = new URL(url).pathname.split("/").filter(Boolean);
    const last = [...segs].reverse().find((s) => !/^\d+$/.test(s) && !/^(?:index|page)\b/.test(s)) ?? "";
    return decodeURIComponent(last.replace(/\.(?:html?|php|aspx?)$/i, ""))
      .replace(/[-_+]+/g, " ")
      .trim();
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Feed autodiscovery
// ---------------------------------------------------------------------------

export type DiscoveredFeed = { url: string; type: "rss" | "atom" | "json" | "unknown"; title: string };

function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return m ? (m[1] ?? m[2] ?? m[3] ?? "").trim() : null;
}

/**
 * Feeds advertised by a page: <link rel="alternate" type="application/rss+xml|atom+xml|feed+json">,
 * then (fallback) anchors to obvious feed paths (/feed, /rss, /atom.xml, feed.xml, index.xml).
 * Comment feeds are skipped. Same-site feeds come first.
 */
export function discoverFeedLinks(html: string, baseUrl: string): DiscoveredFeed[] {
  if (!html) return [];
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }
  const out: DiscoveredFeed[] = [];
  const seen = new Set<string>();
  const push = (href: string | null, type: DiscoveredFeed["type"], title: string) => {
    if (!href) return;
    try {
      const u = new URL(href, base);
      if (!/^https?:$/.test(u.protocol)) return;
      u.hash = "";
      const key = u.toString();
      if (seen.has(key) || /comments?\/feed|\/comments\b|wp-json\/oembed/i.test(key)) return;
      seen.add(key);
      out.push({ url: key, type, title });
    } catch {
      /* ignore bad href */
    }
  };
  for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
    const tag = m[0];
    const rel = (attr(tag, "rel") ?? "").toLowerCase();
    if (!rel.split(/\s+/).includes("alternate")) continue;
    const type = (attr(tag, "type") ?? "").toLowerCase();
    const kind: DiscoveredFeed["type"] | null = type.includes("rss")
      ? "rss"
      : type.includes("atom")
        ? "atom"
        : type.includes("feed+json") || type === "application/json"
          ? "json"
          : null;
    if (!kind) continue;
    push(attr(tag, "href"), kind, attr(tag, "title") ?? "");
  }
  if (out.length === 0) {
    for (const m of html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
      const href = m[1];
      if (/(?:^|\/)(?:feed|rss|atom)(?:\/|\.xml)?(?:$|[?#])|(?:^|\/)(?:feed|rss|atom|index)\.xml$/i.test(href)) push(href, "unknown", "");
    }
  }
  const host = base.hostname.replace(/^www\./, "");
  return out.sort((a, b) => Number(new URL(b.url).hostname.endsWith(host)) - Number(new URL(a.url).hostname.endsWith(host)));
}

// ---------------------------------------------------------------------------
// Listing / archive pagination
// ---------------------------------------------------------------------------

/**
 * The "next page" of a listing: rel="next" (link or anchor), then an anchor labelled
 * Next / Older posts / Load more / ›, then the page+1 variant of /page/N/ or ?page=N in the URL.
 */
export function findNextPageUrl(html: string, pageUrl: string): string | null {
  let base: URL;
  try {
    base = new URL(pageUrl);
  } catch {
    return null;
  }
  const resolve = (href: string | null) => {
    if (!href) return null;
    try {
      const u = new URL(href, base);
      if (u.hostname !== base.hostname || u.toString() === base.toString()) return null;
      return u.toString();
    } catch {
      return null;
    }
  };
  for (const m of html.matchAll(/<(?:link|a)\b[^>]*>/gi)) {
    const rel = (attr(m[0], "rel") ?? "").toLowerCase().split(/\s+/);
    if (rel.includes("next")) {
      const r = resolve(attr(m[0], "href"));
      if (r) return r;
    }
  }
  for (const m of html.matchAll(/<a\b([^>]*)>([\s\S]{0,200}?)<\/a>/gi)) {
    const label = m[2].replace(/<[^>]+>/g, " ").replace(/&[a-z#0-9]+;/gi, " ").replace(/\s+/g, " ").trim().toLowerCase();
    const cls = (attr(m[1], "class") ?? "") + " " + (attr(m[1], "aria-label") ?? "");
    if (/^(?:next|next page|older|older posts|older entries|load more|more posts|›|»|→|next ›|next »)$/.test(label) || /\bnext\b/i.test(cls)) {
      const r = resolve(attr(m[1], "href"));
      if (r) return r;
    }
  }
  return nextPageFromPattern(pageUrl);
}

/** /page/3/ → /page/4/, ?page=3 → ?page=4, /p/3 → /p/4; a first page becomes page 2 for a given pattern. */
export function nextPageFromPattern(pageUrl: string): string | null {
  try {
    const u = new URL(pageUrl);
    const pathM = u.pathname.match(/^(.*\/(?:page|p))\/(\d{1,4})(\/?)$/i);
    if (pathM) {
      u.pathname = `${pathM[1]}/${Number(pathM[2]) + 1}${pathM[3]}`;
      return u.toString();
    }
    for (const key of ["page", "paged", "p", "pg"]) {
      const v = u.searchParams.get(key);
      if (v && /^\d{1,4}$/.test(v)) {
        u.searchParams.set(key, String(Number(v) + 1));
        return u.toString();
      }
    }
  } catch {
    /* ignore */
  }
  return null;
}

/** Page URLs 2..maxPage from a "{n}" pattern ("https://x/reports/page/{n}/"). */
export function paginationUrls(pattern: string, fromPage: number, toPage: number): string[] {
  if (!pattern.includes("{n}")) return [];
  const out: string[] = [];
  for (let n = Math.max(2, fromPage); n <= toPage; n++) out.push(pattern.replace("{n}", String(n)));
  return out;
}

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

export type RobotsRules = {
  groups: Array<{ agents: string[]; allow: string[]; disallow: string[]; crawlDelaySec: number | null }>;
  sitemaps: string[];
};

export function parseRobotsTxt(txt: string): RobotsRules {
  const rules: RobotsRules = { groups: [], sitemaps: [] };
  let current: RobotsRules["groups"][number] | null = null;
  let lastWasAgent = false;
  for (const rawLine of (txt || "").split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === "sitemap") {
      if (/^https?:\/\//i.test(value)) rules.sitemaps.push(value);
      continue;
    }
    if (key === "user-agent") {
      if (!current || !lastWasAgent) {
        current = { agents: [], allow: [], disallow: [], crawlDelaySec: null };
        rules.groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (!current) continue;
    if (key === "allow" && value) current.allow.push(value);
    else if (key === "disallow" && value) current.disallow.push(value);
    else if (key === "crawl-delay") {
      const n = Number(value);
      if (Number.isFinite(n) && n >= 0) current.crawlDelaySec = n;
    }
  }
  return rules;
}

function robotsGroupFor(rules: RobotsRules, userAgent: string) {
  const ua = userAgent.toLowerCase();
  let best: RobotsRules["groups"][number] | null = null;
  let bestLen = -1;
  for (const g of rules.groups) {
    for (const a of g.agents) {
      if (a === "*" && bestLen < 0) {
        best = g;
        bestLen = 0;
      } else if (a !== "*" && ua.includes(a) && a.length > bestLen) {
        best = g;
        bestLen = a.length;
      }
    }
  }
  return best;
}

function robotsPatternMatch(pattern: string, path: string): number {
  // Returns the match length (specificity) or -1.
  const anchored = pattern.endsWith("$");
  const body = anchored ? pattern.slice(0, -1) : pattern;
  const re = new RegExp(`^${body.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}${anchored ? "$" : ""}`);
  return re.test(path) ? body.length : -1;
}

/** Longest-match Allow/Disallow evaluation (RFC 9309); allowed when no rule matches. */
export function robotsAllows(rules: RobotsRules | null | undefined, userAgent: string, url: string): boolean {
  if (!rules) return true;
  const group = robotsGroupFor(rules, userAgent);
  if (!group) return true;
  let path = "/";
  try {
    const u = new URL(url);
    path = `${u.pathname}${u.search}`;
  } catch {
    return true;
  }
  let allowLen = -1;
  let disallowLen = -1;
  for (const p of group.allow) allowLen = Math.max(allowLen, robotsPatternMatch(p, path));
  for (const p of group.disallow) disallowLen = Math.max(disallowLen, robotsPatternMatch(p, path));
  if (disallowLen < 0) return true;
  return allowLen >= disallowLen;
}

export function robotsCrawlDelayMs(rules: RobotsRules | null | undefined, userAgent: string, capMs = 10_000): number {
  const g = rules ? robotsGroupFor(rules, userAgent) : null;
  return g?.crawlDelaySec ? Math.min(g.crawlDelaySec * 1000, capMs) : 0;
}

// ---------------------------------------------------------------------------
// Backfill plan
// ---------------------------------------------------------------------------

export type BackfillWindowMonths = 6 | 12 | 24;

export type BackfillPlan = {
  months: BackfillWindowMonths;
  sinceIso: string;
  /** Upper bound of article fetches for the whole backfill. */
  maxArticles: number;
  /** Listing pages walked per archive. */
  maxListingPages: number;
  /** Child sitemaps opened from a sitemap index. */
  maxChildSitemaps: number;
  /** Minimum spacing between requests to the source host. */
  hostSpacingMs: number;
  maxRunMinutes: number;
};

/** Bounded, polite backfill parameters for a date window. */
export function planBackfill(months: BackfillWindowMonths, now = Date.now()): BackfillPlan {
  const since = new Date(now);
  since.setUTCMonth(since.getUTCMonth() - months);
  const scale = months === 6 ? 1 : months === 12 ? 1.6 : 2.4;
  return {
    months,
    sinceIso: since.toISOString(),
    maxArticles: Math.round(80 * scale),
    maxListingPages: Math.round(8 * scale),
    maxChildSitemaps: Math.round(4 * scale),
    hostSpacingMs: 1500,
    maxRunMinutes: Math.round(10 * scale),
  };
}

// ---------------------------------------------------------------------------
// Real-time sitemap walk
// ---------------------------------------------------------------------------

/** Days of sitemap entries one real-time run reads per source. */
export const REALTIME_SITEMAP_WINDOW_DAYS = 60;
/** How far back the walk goes before it starts over from today. */
export const REALTIME_SITEMAP_MAX_DAYS = 3 * 365;

/**
 * The sitemap date window for the next real-time run of a source: the 60 days before where the
 * previous run stopped (`cursorUntil`), starting from now; past three years it starts over. Each
 * run therefore reads an older slice of the archive than the last.
 */
export function realtimeSitemapWindow(cursorUntil: string | null | undefined, now = Date.now()): { sinceIso: string; untilIso: string } {
  const day = 86_400_000;
  let until = cursorUntil ? Date.parse(cursorUntil) : NaN;
  if (!Number.isFinite(until) || until > now || until < now - REALTIME_SITEMAP_MAX_DAYS * day) until = now + day;
  return { sinceIso: new Date(until - REALTIME_SITEMAP_WINDOW_DAYS * day).toISOString(), untilIso: new Date(until).toISOString() };
}
