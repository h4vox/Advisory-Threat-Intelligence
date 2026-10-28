/**
 * AI-assisted discovery for the crawler: the active AI provider suggests specific, recent research
 * reports (and the publishers behind them) for the research topics the library is thinnest on.
 *
 * Used when web search brings too few new candidates. Where the provider can search the web
 * (Gemini with Google Search grounding, Claude with its web search tool) it searches live;
 * otherwise it answers from what it knows. Nothing it says is trusted: every URL goes through the
 * crawler's normal fetch, relevance, quality and depth gates, so an invented or dead link simply
 * fails to fetch and is recorded as such.
 *
 * Pure: prompt building and answer validation. Unit-tested.
 */

export type DiscoveryTopic = { query: string; category?: string };

export type SuggestedReport = { url: string; title: string; publisher: string; published: string | null; category?: string; why: string };
export type SuggestedSource = { domain: string; name: string; why: string };

export const REPORT_DISCOVERY_SYSTEM = `You are a cyber threat intelligence research librarian. You find published, technical threat research: intrusion and incident reports, malware analysis, campaign and threat actor research, vulnerability exploitation analysis, detection engineering write-ups. You give exact URLs of individual articles or PDFs, never homepages, search pages, social media posts or news aggregators, and never invent a URL. Answer with one JSON object only.`;

export function buildReportDiscoveryPrompt(opts: { topics: DiscoveryTopic[]; since: string; knownDomains: string[]; webSearch: boolean; max: number }): string {
  const topics = opts.topics
    .slice(0, 8)
    .map((t, i) => `${i + 1}. ${t.query}${t.category ? ` [category: ${t.category}]` : ""}`)
    .join("\n");
  const known = opts.knownDomains.slice(0, 80).join(", ");
  return `${opts.webSearch ? "Search the web for" : "From what you know, list"} specific technical threat research reports on these topics, published on or after ${opts.since} (the most recent first):
${topics}

Rules:
- Each URL must be one article or PDF with technical detail (behaviour, TTPs, indicators, attack chain, detection), from the original publisher (security vendor research blog, CERT/government advisory, DFIR firm, researcher blog).
- ${opts.webSearch ? "Only URLs you found in search results." : "Only URLs you are confident exist exactly as written; leave out anything uncertain."}
- At most ${opts.max} reports. Prefer publishers not in this list (already followed): ${known || "none"}.
- Also name up to 5 publishers of such research that are not in that list.

Return JSON:
{
  "reports": [{ "url": "https://…", "title": "…", "publisher": "…", "published": "YYYY-MM-DD or empty", "category": "the topic's category", "why": "one line: what technical content it has" }],
  "sources": [{ "domain": "example.com", "name": "…", "why": "one line" }]
}`;
}

const NOT_ARTICLES =
  /(^|\.)(google|bing|duckduckgo|yahoo|baidu|yandex|youtube|youtu\.be|facebook|twitter|x|linkedin|instagram|reddit|tiktok|t\.me|telegram|medium\.com\/tag|news\.ycombinator|wikipedia|vertexaisearch\.cloud\.google)\.[a-z.]+$/i;

function hostOf(url: URL): string {
  return url.hostname.toLowerCase().replace(/^www\./, "");
}

function str(v: unknown, max: number): string {
  return typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, max) : "";
}

/** Keeps well-formed article URLs and new publisher domains from the model's answer. */
export function parseReportSuggestions(
  parsed: unknown,
  opts: { categories?: string[]; knownDomains?: string[]; max?: number },
): { reports: SuggestedReport[]; sources: SuggestedSource[]; dropped: number } {
  const o = (parsed && typeof parsed === "object" ? parsed : {}) as { reports?: unknown; sources?: unknown };
  const max = opts.max ?? 25;
  const known = new Set((opts.knownDomains ?? []).map((d) => d.toLowerCase().replace(/^www\./, "")));
  const cats = new Set(opts.categories ?? []);
  const reports: SuggestedReport[] = [];
  const seen = new Set<string>();
  let dropped = 0;
  for (const raw of Array.isArray(o.reports) ? o.reports.slice(0, 100) : []) {
    const r = (raw ?? {}) as Record<string, unknown>;
    let url: URL;
    try {
      url = new URL(str(r.url, 2000));
    } catch {
      dropped++;
      continue;
    }
    const path = url.pathname.replace(/\/+$/, "");
    const host = hostOf(url);
    if ((url.protocol !== "https:" && url.protocol !== "http:") || NOT_ARTICLES.test(host) || path === "" || /^\/(?:[a-z]{2}(?:-[a-z]{2})?|blog|research|news|search)$/i.test(path) || url.searchParams.has("q") || seen.has(url.toString())) {
      dropped++;
      continue;
    }
    seen.add(url.toString());
    const published = /^\d{4}-\d{2}-\d{2}$/.test(str(r.published, 10)) ? str(r.published, 10) : null;
    const category = cats.has(str(r.category, 40)) ? str(r.category, 40) : undefined;
    reports.push({ url: url.toString(), title: str(r.title, 240), publisher: str(r.publisher, 120) || host, published, ...(category ? { category } : {}), why: str(r.why, 240) });
    if (reports.length >= max) break;
  }
  const sources: SuggestedSource[] = [];
  for (const raw of Array.isArray(o.sources) ? o.sources.slice(0, 20) : []) {
    const s = (raw ?? {}) as Record<string, unknown>;
    const domain = str(s.domain, 120).toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "");
    if (!/^(?=.{4,120}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(domain) || NOT_ARTICLES.test(domain) || known.has(domain) || sources.some((x) => x.domain === domain)) continue;
    sources.push({ domain, name: str(s.name, 120) || domain, why: str(s.why, 240) });
    if (sources.length >= 5) break;
  }
  return { reports, sources, dropped };
}
