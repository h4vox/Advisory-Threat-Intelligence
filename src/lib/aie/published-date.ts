/**
 * Publication date of a resource, taken from the source itself: when the report was first
 * published (and last updated, when the page says so), never when AIE fetched it.
 *
 * Evidence is read in order of reliability and the first plausible date wins:
 *   1. structured data the publisher writes for machines: JSON-LD (including `@graph`),
 *      `<meta>` tags (Open Graph article:*, Dublin Core, citation_*, Parse.ly…) and
 *      `itemprop="datePublished"`
 *   2. the feed entry that listed the page (RSS pubDate / Atom published)
 *   3. a full date in the URL path (/2024/05/21/…)
 *   4. a `<time datetime>` the page marks as the publish date, then the first one in the page
 *   5. a labelled date in the text ("Published: 6 June 2022", "Posted on June 6, 2022")
 *   6. a byline-like line near the top of the text that holds just a date
 *   7. a year and month in the URL path (/2024/05/…), dated to the first of that month
 *
 * A date in the future or before 1995 is never accepted. Pure: no I/O, unit-tested.
 */

export type PublishedDateSource =
  | "json-ld"
  | "meta"
  | "feed"
  | "pdf"
  | "url"
  | "time-tag"
  | "text"
  /** Kept from an earlier ingestion (feed or page metadata) when the source offers nothing better. */
  | "recorded"
  /** A date line in the report text that the AI analysis located and AIE verified in the text. */
  | "ai"
  | "none";

export type PublishedDateConfidence = "high" | "medium" | "low";

/** How each source reads to an analyst. */
export const PUBLISHED_DATE_SOURCE_LABEL: Record<PublishedDateSource, string> = {
  "json-ld": "page structured data",
  meta: "page metadata",
  feed: "the publisher's feed",
  pdf: "the PDF document information",
  url: "the URL",
  "time-tag": "the page's date element",
  text: "the report text",
  recorded: "the date recorded at ingestion",
  ai: "the report text (located by AI, verified)",
  none: "no date found",
};

export type PublishedDate = {
  /** YYYY-MM-DD, or null when the source gives no usable date. */
  publishedAt: string | null;
  /** Last update the source states (YYYY-MM-DD), when it differs from the publication date. */
  sourceUpdatedAt: string | null;
  source: PublishedDateSource;
  confidence: PublishedDateConfidence;
  /** The evidence the date came from, e.g. `article:published_time` or `URL /2024/05/21/`. */
  evidence: string;
  /** Resolver version, so stored reports can be re-dated when the rules improve. */
  version: number;
};

export const PUBLISHED_DATE_VERSION = 1;

export type PublishedDateInput = {
  html?: string | null;
  /** Extracted text of the page or document. */
  text?: string | null;
  url?: string | null;
  /** Date the feed or listing reported for the entry. */
  feedDate?: string | null;
  /** Creation date from a PDF's document information. */
  pdfDate?: string | null;
  /** Clock for the plausibility check (tests). */
  now?: Date;
};

const MIN_YEAR = 1995;

const MONTHS: Record<string, number> = {
  jan: 1, january: 1, feb: 2, february: 2, mar: 3, march: 3, apr: 4, april: 4, may: 5, jun: 6, june: 6,
  jul: 7, july: 7, aug: 8, august: 8, sep: 9, sept: 9, september: 9, oct: 10, october: 10, nov: 11,
  november: 11, dec: 12, december: 12,
};
const MONTH_RE = "(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\\.?";

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

function ymd(y: number, m: number, d: number): string | null {
  if (!Number.isInteger(y) || !Number.isInteger(m) || !Number.isInteger(d)) return null;
  if (m < 1 || m > 12 || d < 1 || d > 31) return null;
  const dt = new Date(Date.UTC(y, m - 1, d));
  // Rejects 31 June and 29 February outside leap years.
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
  return `${y}-${pad(m)}-${pad(d)}`;
}

function plausible(date: string | null, now: Date): string | null {
  if (!date) return null;
  const y = Number(date.slice(0, 4));
  if (y < MIN_YEAR) return null;
  // One day of slack for time zones ahead of UTC.
  if (Date.parse(`${date}T00:00:00Z`) > now.getTime() + 36 * 3600_000) return null;
  return date;
}

/**
 * Normalises one date value to YYYY-MM-DD. The calendar date the source wrote is kept as written
 * (an ISO timestamp is not shifted into UTC, so a late-evening post keeps its own day).
 */
export function normaliseDate(raw: unknown): string | null {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    // Unix seconds or milliseconds.
    const ms = raw > 1e11 ? raw : raw * 1000;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? null : ymd(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
  }
  if (typeof raw !== "string") return null;
  // PDF document information writes dates as D:YYYYMMDDHHmmSS.
  const s = raw.trim().replace(/^D:/, "");
  if (!s) return null;
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T\s]|$)/);
  if (m) return ymd(+m[1], +m[2], +m[3]);
  m = s.match(/^(\d{4})(\d{2})(\d{2})(?:T|\d{2}|$)/);
  if (m) return ymd(+m[1], +m[2], +m[3]);
  m = s.match(/^(\d{4})[/.](\d{1,2})[/.](\d{1,2})\b/);
  if (m) return ymd(+m[1], +m[2], +m[3]);
  if (/^\d{10}(\d{3})?$/.test(s)) return normaliseDate(Number(s));
  const text = textDate(s);
  if (text) return text.date;
  // RFC 2822 and other forms Date understands ("Mon, 06 Jun 2022 10:00:00 GMT").
  if (/[a-z]{3}/i.test(s) && /\d{4}/.test(s)) {
    const d = new Date(s);
    if (!Number.isNaN(d.getTime())) return ymd(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
  }
  return null;
}

/** First written date in a string: "6 June 2022", "June 6th, 2022", "2022-06-06", "Jun. 6 2022". */
export function findWrittenDate(s: string): string | null {
  return textDate(s)?.date ?? null;
}

function textDate(s: string): { date: string; index: number; length: number } | null {
  const patterns: Array<[RegExp, (m: RegExpMatchArray) => string | null]> = [
    [new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(?:of\\s+)?${MONTH_RE},?\\s+(\\d{4})\\b`, "i"), (m) => ymd(+m[3], MONTHS[m[2].toLowerCase()], +m[1])],
    [new RegExp(`\\b${MONTH_RE}\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})\\b`, "i"), (m) => ymd(+m[3], MONTHS[m[1].toLowerCase()], +m[2])],
    [/\b((?:19|20)\d{2})-(0?[1-9]|1[0-2])-(0?[1-9]|[12]\d|3[01])\b/, (m) => ymd(+m[1], +m[2], +m[3])],
    [/\b((?:19|20)\d{2})\/(0?[1-9]|1[0-2])\/(0?[1-9]|[12]\d|3[01])\b/, (m) => ymd(+m[1], +m[2], +m[3])],
  ];
  let best: { date: string; index: number; length: number } | null = null;
  for (const [re, toDate] of patterns) {
    const m = s.match(re);
    if (!m || m.index === undefined) continue;
    const date = toDate(m);
    if (date && (!best || m.index < best.index)) best = { date, index: m.index, length: m[0].length };
  }
  return best;
}

// ── HTML evidence ───────────────────────────────────────────────────────────

const PUBLISHED_META = [
  "article:published_time", "og:article:published_time", "og:published_time", "published_time", "article.published",
  "datepublished", "publish-date", "publish_date", "publishdate", "pubdate", "date", "dc.date", "dc.date.issued",
  "dc.date.created", "dcterms.date", "dcterms.issued", "dcterms.created", "citation_publication_date",
  "citation_online_date", "citation_date", "parsely-pub-date", "sailthru.date", "original-publish-date",
  "track-metadata-page_first_published", "release_date", "article:post_date", "post_date", "created",
];
const MODIFIED_META = [
  "article:modified_time", "og:updated_time", "og:article:modified_time", "modified_time", "datemodified",
  "dcterms.modified", "dc.date.modified", "last-modified", "lastmod", "article.updated", "revised",
  "track-metadata-page_last_modified",
];

function attrs(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of tag.matchAll(/([a-zA-Z_:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g)) {
    out[m[1].toLowerCase()] = (m[2] ?? m[3] ?? m[4] ?? "").trim();
  }
  return out;
}

/** <meta> name/property/itemprop → content, first occurrence wins. */
function metaMap(html: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const a = attrs(m[0]);
    const key = (a.property || a.name || a.itemprop || a["http-equiv"] || "").toLowerCase();
    if (key && a.content && !map.has(key)) map.set(key, a.content);
  }
  return map;
}

type Found = { date: string; evidence: string };

function fromMeta(meta: Map<string, string>, keys: string[], now: Date): Found | null {
  for (const key of keys) {
    const v = meta.get(key);
    const date = plausible(normaliseDate(v), now);
    if (date) return { date, evidence: `<meta ${key}>` };
  }
  // Parse.ly keeps its metadata as JSON in one tag.
  const parsely = meta.get("parsely-page");
  if (parsely && keys === PUBLISHED_META) {
    try {
      const date = plausible(normaliseDate(JSON.parse(parsely)?.pub_date), now);
      if (date) return { date, evidence: "<meta parsely-page>" };
    } catch {
      /* not JSON */
    }
  }
  return null;
}

const ARTICLE_TYPES = /article|posting|report|news|scholarly|techarticle|blog|creativework|analysis/i;

/** JSON-LD nodes, flattening arrays, `@graph` and `mainEntity`. */
function jsonLdNodes(html: string): Array<Record<string, unknown>> {
  const nodes: Array<Record<string, unknown>> = [];
  const visit = (v: unknown, depth: number) => {
    if (depth > 6 || v === null || typeof v !== "object") return;
    if (Array.isArray(v)) {
      for (const x of v) visit(x, depth + 1);
      return;
    }
    const o = v as Record<string, unknown>;
    nodes.push(o);
    if (o["@graph"]) visit(o["@graph"], depth + 1);
    if (o.mainEntity) visit(o.mainEntity, depth + 1);
    if (o.mainEntityOfPage && typeof o.mainEntityOfPage === "object") visit(o.mainEntityOfPage, depth + 1);
  };
  for (const m of html.matchAll(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    const body = m[1].trim().replace(/^<!\[CDATA\[|\]\]>$/g, "");
    try {
      visit(JSON.parse(body), 0);
    } catch {
      /* malformed block */
    }
  }
  return nodes;
}

function typeOf(node: Record<string, unknown>): string {
  const t = node["@type"];
  return Array.isArray(t) ? t.join(" ") : typeof t === "string" ? t : "";
}

function fromJsonLd(html: string, now: Date): { published: Found | null; modified: Found | null } {
  const nodes = jsonLdNodes(html);
  // Article-like nodes describe the report itself; a WebPage or WebSite node comes second.
  const ranked = [...nodes.filter((n) => ARTICLE_TYPES.test(typeOf(n))), ...nodes.filter((n) => !ARTICLE_TYPES.test(typeOf(n)))];
  let published: Found | null = null;
  let modified: Found | null = null;
  for (const n of ranked) {
    const label = typeOf(n) || "JSON-LD";
    if (!published) {
      for (const k of ["datePublished", "dateCreated", "uploadDate"]) {
        const date = plausible(normaliseDate(n[k]), now);
        if (date) {
          published = { date, evidence: `JSON-LD ${label}.${k}` };
          break;
        }
      }
    }
    if (!modified) {
      const date = plausible(normaliseDate(n.dateModified), now);
      if (date) modified = { date, evidence: `JSON-LD ${label}.dateModified` };
    }
    if (published && modified) break;
  }
  return { published, modified };
}

/** Elements carrying `itemprop="datePublished"` (time, span, meta) with a datetime or content value. */
function fromItemprop(html: string, prop: string, now: Date): Found | null {
  const re = new RegExp(`<[a-z]+\\b[^>]*itemprop\\s*=\\s*["']${prop}["'][^>]*>`, "gi");
  for (const m of html.matchAll(re)) {
    const a = attrs(m[0]);
    const date = plausible(normaliseDate(a.datetime || a.content), now);
    if (date) return { date, evidence: `itemprop=${prop}` };
    // <span itemprop="datePublished">June 6, 2022</span>
    const after = html.slice((m.index ?? 0) + m[0].length, (m.index ?? 0) + m[0].length + 80).replace(/<[^>]*>/g, " ");
    const t = textDate(after);
    const d2 = plausible(t?.date ?? null, now);
    if (d2 && t && t.index < 10) return { date: d2, evidence: `itemprop=${prop}` };
  }
  return null;
}

/** `<time datetime>`: one marked as the publish date first, then the first one in the main content. */
function fromTimeTags(html: string, now: Date): { marked: Found | null; first: Found | null } {
  let marked: Found | null = null;
  let first: Found | null = null;
  // Skip navigation, sidebars and footers, where "recent posts" carry other dates.
  const body = html.replace(/<(nav|aside|footer)\b[\s\S]*?<\/\1>/gi, " ");
  for (const m of body.matchAll(/<time\b[^>]*>/gi)) {
    const a = attrs(m[0]);
    const date = plausible(normaliseDate(a.datetime), now);
    if (!date) continue;
    const cls = `${a.class ?? ""} ${a.id ?? ""} ${a.pubdate !== undefined ? "pubdate" : ""}`;
    if (!marked && /publish|posted|entry-date|post-date|article-date|pubdate|date-published|created/i.test(cls) && !/updat|modif/i.test(cls)) {
      marked = { date, evidence: "<time> marked published" };
    }
    if (!first && !/updat|modif|comment/i.test(cls)) first = { date, evidence: "first <time datetime>" };
    if (marked && first) break;
  }
  return { marked, first };
}

function fromUrl(url: string | null | undefined, now: Date): { full: Found | null; month: Found | null } {
  if (!url) return { full: null, month: null };
  let path = url;
  try {
    path = new URL(url).pathname;
  } catch {
    /* use as given */
  }
  const full = path.match(/(?:^|[/_-])((?:19|20)\d{2})[/_-](0[1-9]|1[0-2])[/_-](0[1-9]|[12]\d|3[01])(?=[/_.-]|$)/);
  if (full) {
    const date = plausible(ymd(+full[1], +full[2], +full[3]), now);
    if (date) return { full: { date, evidence: `URL ${full[0].replace(/^[/_-]/, "")}` }, month: null };
  }
  const compact = path.match(/(?:^|[/_-])((?:19|20)\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?=[/_.-]|$)/);
  if (compact) {
    const date = plausible(ymd(+compact[1], +compact[2], +compact[3]), now);
    if (date) return { full: { date, evidence: `URL ${compact[1]}${compact[2]}${compact[3]}` }, month: null };
  }
  const month = path.match(/\/((?:19|20)\d{2})\/(0[1-9]|1[0-2])\//);
  if (month) {
    const date = plausible(ymd(+month[1], +month[2], 1), now);
    if (date) return { full: null, month: { date, evidence: `URL /${month[1]}/${month[2]}/` } };
  }
  return { full: null, month: null };
}

// ── Text evidence ───────────────────────────────────────────────────────────

const PUBLISHED_LABEL = /\b(?:first\s+published|originally\s+published|published(?:\s+on|\s+date)?|posted(?:\s+on)?|released(?:\s+on)?|publication\s+date|date\s+published|release\s+date)\s*[:\-–—]?\s*/gi;
const UPDATED_LABEL = /\b(?:last\s+updated|updated(?:\s+on)?|last\s+modified|revised(?:\s+on)?)\s*[:\-–—]?\s*/gi;

function labelledDate(head: string, label: RegExp, now: Date): Found | null {
  for (const m of head.matchAll(label)) {
    const start = (m.index ?? 0) + m[0].length;
    const t = textDate(head.slice(start, start + 40));
    if (t && t.index <= 4) {
      const date = plausible(t.date, now);
      if (date) return { date, evidence: `"${(m[0] + head.slice(start, start + t.index + t.length)).replace(/\s+/g, " ").trim()}"` };
    }
  }
  return null;
}

/**
 * A short line near the top that is little more than a date (a byline such as
 * "Jane Doe · 6 June 2022 · 8 min read"). Dates inside sentences are skipped: those are usually
 * when an incident happened, not when the report was written.
 */
function bylineDate(text: string, now: Date): Found | null {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 15);
  for (const line of lines) {
    if (line.length > 90) continue;
    const t = textDate(line);
    if (!t) continue;
    const rest = (line.slice(0, t.index) + line.slice(t.index + t.length)).trim();
    // A sentence ends with a period or has many words; a byline does neither.
    if (rest.split(/\s+/).filter(Boolean).length > 8 || /[a-z]{3,}\.\s*$/i.test(rest)) continue;
    const date = plausible(t.date, now);
    if (date) return { date, evidence: `byline "${line.slice(0, 80)}"` };
  }
  return null;
}

/** Visible text of the top of a page, for labelled dates written in the HTML. */
function htmlHeadText(html: string): string {
  const body = html.match(/<body\b[^>]*>([\s\S]*)$/i)?.[1] ?? html;
  return body
    .replace(/<(script|style|noscript|svg|nav|footer|aside)\b[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;|&#160;/g, " ")
    .replace(/\s+/g, " ")
    .slice(0, 6000);
}

// ── Resolver ────────────────────────────────────────────────────────────────

function result(found: Found | null, source: PublishedDateSource, confidence: PublishedDateConfidence, updated: Found | null): PublishedDate {
  const publishedAt = found?.date ?? null;
  const sourceUpdatedAt = updated && publishedAt && updated.date > publishedAt ? updated.date : null;
  return {
    publishedAt,
    sourceUpdatedAt,
    source: publishedAt ? source : "none",
    confidence: publishedAt ? confidence : "low",
    evidence: found?.evidence ?? "",
    version: PUBLISHED_DATE_VERSION,
  };
}

export function resolvePublicationDate(input: PublishedDateInput): PublishedDate {
  const now = input.now ?? new Date();
  const html = input.html ?? "";
  const text = input.text ?? "";
  const head = html ? htmlHeadText(html) : text.slice(0, 6000);

  const ld = html ? fromJsonLd(html, now) : { published: null, modified: null };
  const meta = html ? metaMap(html) : new Map<string, string>();
  const metaPublished = html ? fromMeta(meta, PUBLISHED_META, now) : null;
  const updated =
    ld.modified ??
    (html ? fromMeta(meta, MODIFIED_META, now) : null) ??
    (html ? fromItemprop(html, "dateModified", now) : null) ??
    labelledDate(head, UPDATED_LABEL, now) ??
    (text && html ? labelledDate(text.slice(0, 6000), UPDATED_LABEL, now) : null);

  if (ld.published) return result(ld.published, "json-ld", "high", updated);
  if (metaPublished) return result(metaPublished, "meta", "high", updated);
  const itemprop = html ? fromItemprop(html, "datePublished", now) : null;
  if (itemprop) return result(itemprop, "meta", "high", updated);

  const feed = plausible(normaliseDate(input.feedDate), now);
  if (feed) return result({ date: feed, evidence: "feed entry date" }, "feed", "high", updated);

  const pdf = plausible(normaliseDate(input.pdfDate), now);
  const url = fromUrl(input.url, now);
  if (url.full) return result(url.full, "url", "high", updated);

  const time = html ? fromTimeTags(html, now) : { marked: null, first: null };
  if (time.marked) return result(time.marked, "time-tag", "medium", updated);

  const labelled = labelledDate(head, PUBLISHED_LABEL, now) ?? (text && html ? labelledDate(text.slice(0, 6000), PUBLISHED_LABEL, now) : null);
  if (labelled) return result(labelled, "text", "medium", updated);

  if (time.first) return result(time.first, "time-tag", "medium", updated);
  if (pdf) return result({ date: pdf, evidence: "PDF creation date" }, "pdf", "medium", updated);

  const byline = text ? bylineDate(text, now) : null;
  if (byline) return result(byline, "text", "low", updated);
  if (url.month) return result(url.month, "url", "low", updated);

  // Only an update date: better than none, and labelled as such.
  if (updated) {
    const src: PublishedDateSource = updated.evidence.startsWith("JSON-LD") ? "json-ld" : /^(<meta|itemprop)/.test(updated.evidence) ? "meta" : "text";
    return result({ date: updated.date, evidence: `${updated.evidence} (last update)` }, src, "low", null);
  }
  return result(null, "none", "low", null);
}

/** Newest publication date first; undated reports last, newest ingested first among equals. */
export function comparePublishedDesc(
  a: { publishedAt?: string | null; ingestedAt?: string | null },
  b: { publishedAt?: string | null; ingestedAt?: string | null },
): number {
  const pa = (a.publishedAt ?? "").slice(0, 10);
  const pb = (b.publishedAt ?? "").slice(0, 10);
  if (pa !== pb) return pa < pb ? 1 : -1;
  const ia = a.ingestedAt ?? "";
  const ib = b.ingestedAt ?? "";
  return ia === ib ? 0 : ia < ib ? 1 : -1;
}
