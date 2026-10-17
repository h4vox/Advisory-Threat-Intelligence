import type { Evidence, IocHit, QualityReason } from "./types.ts";
export { formatDateTime, toIsoString } from "./format.ts";

export const MAX_BYTES = 1_500_000;

function rightRotate(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

export function sha256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  let H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
  let H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;

  const bitLength = bytes.length * 8;
  const newByteLength = (((bytes.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(newByteLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(newByteLength - 4, bitLength, false);

  const W = new Uint32Array(64);

  for (let i = 0; i < newByteLength; i += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = rightRotate(W[t - 15], 7) ^ rightRotate(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = rightRotate(W[t - 2], 17) ^ rightRotate(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
    }

    let a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;

    for (let t = 0; t < 64; t++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    H0 = (H0 + a) | 0;
    H1 = (H1 + b) | 0;
    H2 = (H2 + c) | 0;
    H3 = (H3 + d) | 0;
    H4 = (H4 + e) | 0;
    H5 = (H5 + f) | 0;
    H6 = (H6 + g) | 0;
    H7 = (H7 + h) | 0;
  }

  return [H0, H1, H2, H3, H4, H5, H6, H7]
    .map((h) => (h >>> 0).toString(16).padStart(8, "0"))
    .join("");
}

// Query parameters that only track the visitor and never change the document.
// NOTE: discovery.ts keeps its own (older) tracking-param stripper; keep the two in sync.
const TRACKING_PARAMS = new Set([
  "fbclid", "gclid", "dclid", "gbraid", "wbraid", "msclkid", "yclid", "igshid", "twclid", "li_fat_id",
  "mc_cid", "mc_eid", "mkt_tok", "_hsenc", "_hsmi", "_gl", "ref", "ref_src", "ref_url", "referrer",
  "share", "replytocom", "amp", "amp_js_v", "usqp",
]);

function decodeParamPart(raw: string): string {
  try {
    return decodeURIComponent(raw.replace(/\+/g, " "));
  } catch {
    return raw;
  }
}

function isTrackingParam(rawKey: string): boolean {
  const key = decodeParamPart(rawKey).toLowerCase();
  return key.startsWith("utm_") || TRACKING_PARAMS.has(key);
}

/** Query params that only select an alternate rendition (print view, AMP) of the same document. */
function isRenditionParam(rawKey: string, rawValue: string | undefined): boolean {
  const key = decodeParamPart(rawKey).toLowerCase();
  const value = decodeParamPart(rawValue ?? "").toLowerCase();
  if (key === "output" || key === "outputtype" || key === "format" || key === "view" || key === "mode") {
    return value === "print" || value === "amp" || value === "printable";
  }
  if (key === "print" || key === "printable" || key === "printer_friendly") {
    return value === "" || value === "1" || value === "true" || value === "yes";
  }
  return false;
}

/** amp.example.com, m.example.com, mobile.example.com → example.com (only when a registrable host remains). */
function desktopHost(host: string): string {
  const m = host.match(/^(?:amp|m|mobile)\.(.+)$/);
  if (m && m[1].split(".").length >= 2) return m[1];
  return host;
}

/**
 * Canonical form used for de-duplication: lower-case host, no default port,
 * no fragment, no tracking params, remaining query params sorted by key
 * (original encoding kept), no trailing slash except on the root path.
 * Alternate renditions of the same document collapse to the desktop article:
 * AMP (Google AMP cache URLs, amp./m./mobile. hosts, /amp path segments,
 * .amp.html, ?amp), print views (/print, ?output=print, ?print=1) and
 * trailing index.html.
 */
export function canonicalizeUrl(raw: string): string {
  let u = new URL(raw.trim());
  // Google AMP cache: https://www-example-com.cdn.ampproject.org/c/s/www.example.com/path
  if (u.hostname.toLowerCase().endsWith(".cdn.ampproject.org")) {
    const m = u.pathname.match(/^\/(?:[a-z]\/)+?(s\/)?([^/]+\.[^/]+)(\/.*)?$/i);
    if (m) u = new URL(`${m[1] ? "https" : "http"}://${m[2]}${m[3] ?? "/"}${u.search}`);
  }
  u.hash = "";
  u.hostname = desktopHost(u.hostname.toLowerCase());
  // WHATWG URL already drops a scheme's default port; cover explicit ones too.
  if ((u.protocol === "http:" && u.port === "80") || (u.protocol === "https:" && u.port === "443")) {
    u.port = "";
  }
  let path = u.pathname.replace(/\/{2,}/g, "/");
  path = path
    .replace(/^\/amp(?=\/.)/i, "")
    .replace(/\/(?:amp|print|printable)\/?$/i, "")
    .replace(/\.amp(\.html?)$/i, "$1")
    .replace(/\/index\.(?:html?|php)$/i, "/");
  if (path.endsWith("/") && path.length > 1) path = path.slice(0, -1);
  u.pathname = path || "/";
  if (u.search) {
    const params = u.search
      .slice(1)
      .split("&")
      .filter((p) => p.length > 0)
      .filter((p) => {
        const eq = p.indexOf("=");
        const key = eq >= 0 ? p.slice(0, eq) : p;
        return !isTrackingParam(key) && !isRenditionParam(key, eq >= 0 ? p.slice(eq + 1) : undefined);
      });
    // Stable sort by key only, so repeated keys keep their relative order.
    const keyOf = (p: string) => p.split("=")[0];
    params.sort((a, b) => (keyOf(a) < keyOf(b) ? -1 : keyOf(a) > keyOf(b) ? 1 : 0));
    u.search = params.length ? `?${params.join("&")}` : "";
  }
  return u.toString();
}

// ---------------------------------------------------------------------------
// HTML -> text: balanced-tag element finder (no lazy regex that stops at the
// first nested closing tag), content-block selection by largest stripped text.
// ---------------------------------------------------------------------------

type ElementRange = { tag: string; attrs: string; start: number; openEnd: number; end: number };

/** Find elements by tag name; `end` is the index just past the matching close tag (or input end if unclosed). */
function findElements(
  html: string,
  tags: readonly string[],
  attrTest?: (attrs: string, tag: string) => boolean,
  limit = 2000,
): ElementRange[] {
  const out: ElementRange[] = [];
  const openRe = new RegExp(`<(${tags.join("|")})(?=[\\s>/])([^>]*)>`, "gi");
  let m: RegExpExecArray | null;
  while ((m = openRe.exec(html)) && out.length < limit) {
    const tag = m[1].toLowerCase();
    const attrs = m[2] || "";
    if (attrTest && !attrTest(attrs, tag)) continue;
    const start = m.index;
    const openEnd = m.index + m[0].length;
    if (/\/\s*$/.test(attrs)) {
      out.push({ tag, attrs, start, openEnd, end: openEnd });
      continue;
    }
    const tagRe = new RegExp(`<(/?)${tag}(?=[\\s>/])[^>]*>`, "gi");
    tagRe.lastIndex = openEnd;
    let depth = 1;
    let end = html.length;
    let t: RegExpExecArray | null;
    while ((t = tagRe.exec(html))) {
      if (t[1]) depth--;
      else if (!/\/\s*>$/.test(t[0])) depth++;
      if (depth === 0) {
        end = t.index + t[0].length;
        break;
      }
    }
    out.push({ tag, attrs, start, openEnd, end });
  }
  return out;
}

function removeRanges(html: string, ranges: ElementRange[]): string {
  if (ranges.length === 0) return html;
  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  let out = "";
  let pos = 0;
  for (const r of sorted) {
    if (r.start < pos) continue; // nested inside an already removed range
    out += html.slice(pos, r.start) + " ";
    pos = r.end;
  }
  return out + html.slice(pos);
}

function removeElements(html: string, tags: readonly string[], attrTest?: (attrs: string, tag: string) => boolean): string {
  return removeRanges(html, findElements(html, tags, attrTest));
}

const BOILERPLATE_TAGS = ["nav", "footer", "header", "aside", "form", "svg", "iframe", "button", "dialog", "select"] as const;
const RELATED_ATTR_RE =
  /\b(?:class|id|data-bi-an|aria-label|data-section)\s*=\s*["'][^"']*\b(?:related|share-?(?:bar|buttons|links)|social-share|newsletter|subscribe|breadcrumbs?|cookie-?(?:banner|consent))\b[^"']*["']/i;
const CONTENT_ATTR_RE =
  /\b(?:class|id)\s*=\s*["'][^"']*\b(?:entry-content|post-content|article-body|article-content|article__body|post-body|story-body|blog-content|blog-post-content|main-content|content-body|single-content|rich-text)\b[^"']*["']/i;
const CONTENT_ID_RE = /\bid\s*=\s*["'](?:content|main|main-content|article|primary)["']/i;
const ROLE_MAIN_RE = /\brole\s*=\s*["']main["']/i;

function preStripHtml(html: string): string {
  return html
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style\s*>/gi, " ")
    .replace(/<noscript\b[\s\S]*?<\/noscript\s*>/gi, " ")
    .replace(/<template\b[\s\S]*?<\/template\s*>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ");
}

function stripBoilerplate(fragment: string): string {
  let out = removeElements(fragment, ["div", "section", "aside", "ul", "ol", "article", "nav"], (attrs) =>
    RELATED_ATTR_RE.test(attrs),
  );
  out = removeElements(out, BOILERPLATE_TAGS);
  return out;
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ensp: " ", emsp: " ", thinsp: " ",
  lsquo: "‘", rsquo: "’", sbquo: "‚", ldquo: "“", rdquo: "”", bdquo: "„",
  mdash: "—", ndash: "–", hellip: "…", bull: "•", middot: "·", laquo: "«", raquo: "»",
  copy: "©", reg: "®", trade: "™", deg: "°", times: "×", divide: "÷", sect: "§", para: "¶",
  rarr: "→", larr: "←", harr: "↔", uarr: "↑", darr: "↓", zwj: "", zwnj: "", shy: "", lrm: "", rlm: "",
};

/**
 * Single-pass entity decoder for PLAIN TEXT output (decodes &lt; / &gt; too,
 * so it must never be applied to markup that is rendered as HTML).
 */
export function decodeHtmlText(s: string): string {
  if (!s) return "";
  return s.replace(/&(#[xX][0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-zA-Z][a-zA-Z0-9]{1,31});/g, (whole, body: string) => {
    if (body[0] === "#") {
      const code = body[1] === "x" || body[1] === "X" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return "";
      return code === 0xa0 ? " " : String.fromCodePoint(code);
    }
    const named = NAMED_ENTITIES[body] ?? NAMED_ENTITIES[body.toLowerCase()];
    return named ?? whole;
  });
}

function fragmentToText(fragment: string): string {
  const text = fragment
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(?:p|div|h[1-6]|li|tr|section|article|main|pre|blockquote|table|thead|tbody|ul|ol|dl|dt|dd|figure|figcaption|header|details|summary)\s*>/gi, "\n")
    .replace(/<(?:p|h[1-6]|pre|blockquote|table|tr)(?=[\s>/])[^>]*>/gi, "\n")
    .replace(/<li(?=[\s>/])[^>]*>/gi, "• ")
    .replace(/<\/(?:td|th)\s*>/gi, " \t")
    .replace(/<[^>]+>/g, " ");
  return decodeHtmlText(text)
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

/**
 * Pick the main content block: among <article>, <main>, [role=main] and common
 * content containers, take the one with the most text after boilerplate
 * stripping; prefer a tighter block holding >= 85% of that text. Falls back to
 * <body> when no candidate has substantial text.
 */
function selectContentFragment(html: string): { fragment: string; text: string } {
  const pre = preStripHtml(html);
  const bodyRange = findElements(pre, ["body"], undefined, 1)[0];
  const scope = bodyRange ? pre.slice(bodyRange.openEnd, bodyRange.end) : pre;

  const candidates = findElements(
    scope,
    ["article", "main", "div", "section"],
    (attrs, tag) => {
      if (RELATED_ATTR_RE.test(attrs)) return false;
      if (tag === "article" || tag === "main") return true;
      return ROLE_MAIN_RE.test(attrs) || CONTENT_ATTR_RE.test(attrs) || CONTENT_ID_RE.test(attrs);
    },
    80,
  );

  const scored = candidates.map((c) => {
    const fragment = stripBoilerplate(scope.slice(c.openEnd, c.end));
    return { span: c.end - c.start, fragment, text: fragmentToText(fragment) };
  });
  const bestLen = scored.reduce((max, s) => Math.max(max, s.text.length), 0);

  if (bestLen < 400) {
    const bodyFragment = stripBoilerplate(scope);
    const bodyText = fragmentToText(bodyFragment);
    if (bodyText.length > bestLen) return { fragment: bodyFragment, text: bodyText };
  }
  if (scored.length === 0) return { fragment: "", text: "" };

  let chosen = scored[0];
  for (const s of scored) {
    if (s.text.length < bestLen * 0.85) continue;
    if (chosen.text.length < bestLen * 0.85 || s.span < chosen.span) chosen = s;
  }
  return { fragment: chosen.fragment, text: chosen.text };
}

// ---------------------------------------------------------------------------
// Structure-preserving rendering (spec §19-20): headings, lists, tables and
// code blocks become markdown-ish text with section names, so evidence keeps
// its section context and IOC appendix tables stay row-aligned. Only block
// markers are added (never inline markup), so every prose block of the plain
// rendering still appears verbatim in the structured one.
// ---------------------------------------------------------------------------

export type TextSection = { heading: string; level: number; start: number; end: number };

function inlineText(fragment: string): string {
  return decodeHtmlText(fragment.replace(/<br\s*\/?>/gi, " ").replace(/<[^>]+>/g, " "))
    .replace(/\u00a0/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function preText(fragment: string): string {
  return decodeHtmlText(fragment.replace(/<br\s*\/?>/gi, "\n").replace(/<\/(?:div|p|li|tr)\s*>/gi, "\n").replace(/<[^>]+>/g, ""))
    .replace(/\u00a0/g, " ")
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t]+$/gm, "")
    .replace(/^\n+|\n+$/g, "");
}

function tableToMarkdown(tableHtml: string): string | null {
  const rows = findElements(tableHtml, ["tr"], undefined, 5000).map((r) => tableHtml.slice(r.openEnd, r.end));
  if (rows.length === 0) return null;
  const lines: string[] = [];
  let width = 0;
  for (let i = 0; i < rows.length; i++) {
    const cells = findElements(rows[i], ["td", "th"], undefined, 200);
    if (cells.length === 0) continue;
    const texts = cells.map((c) => inlineText(rows[i].slice(c.openEnd, c.end)).replace(/\|/g, "\\|"));
    // Layout tables (long prose in a cell) are not data tables.
    if (texts.some((t) => t.length > 600)) return null;
    width = Math.max(width, texts.length);
    lines.push(`| ${texts.join(" | ")} |`);
    if (lines.length === 1) lines.push(`|${" --- |".repeat(texts.length)}`);
  }
  if (lines.length === 0 || width === 0) return null;
  return lines.join("\n");
}

function fragmentToStructuredText(fragment: string): string {
  const blocks: string[] = [];
  const hold = (s: string) => `\n\n\uE000${blocks.push(s) - 1}\uE000\n\n`;
  let html = fragment;

  // 1. Code blocks keep their line breaks and indentation.
  html = html.replace(/<pre\b[^>]*>([\s\S]*?)<\/pre\s*>/gi, (_, inner: string) => {
    const code = preText(inner);
    return code.trim() ? hold("```\n" + code + "\n```") : " ";
  });

  // 2. Data tables become pipe tables (outermost tables first; layout tables fall through).
  const tables = findElements(html, ["table"], undefined, 400);
  if (tables.length) {
    let out = "";
    let pos = 0;
    for (const t of tables.sort((a, b) => a.start - b.start)) {
      if (t.start < pos) continue;
      const md = tableToMarkdown(html.slice(t.openEnd, t.end));
      out += html.slice(pos, t.start) + (md ? hold(md) : html.slice(t.start, t.end).replace(/<\/?(?:table|tbody|thead|tfoot|tr|td|th)\b[^>]*>/gi, "\n"));
      pos = t.end;
    }
    html = out + html.slice(pos);
  }

  // 3. Headings with their level.
  html = html.replace(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1\s*>/gi, (_, level: string, inner: string) => {
    const t = inlineText(inner);
    return t ? `\n\n${"#".repeat(Number(level))} ${t}\n\n` : " ";
  });

  // 4. Lists: ordered items numbered, unordered items bulleted.
  html = html.replace(/<ol\b[^>]*>([\s\S]*?)<\/ol\s*>/gi, (_, inner: string) => {
    let n = 0;
    return `\n${inner.replace(/<li(?=[\s>/])[^>]*>/gi, () => `\n${++n}. `)}\n`;
  });
  html = html.replace(/<li(?=[\s>/])[^>]*>/gi, "\n- ");

  // 5. Remaining blocks as in the plain rendering.
  const text = fragmentToText(html.replace(/<\/li\s*>/gi, "\n"));
  return text
    .replace(/\uE000(\d+)\uE000/g, (_, i: string) => blocks[Number(i)] ?? "")
    .replace(/^• /gm, "- ")
    // A list item whose content is a paragraph renders as "1.\n\nText": keep marker and text together.
    .replace(/^(\d{1,3}\.|-)[ \t]*\n+(?=\S)/gm, "$1 ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** Section boundaries from markdown-ish headings ("## Name") in structured text. */
export function sectionsOf(text: string): TextSection[] {
  const out: TextSection[] = [];
  const re = /^(?:(#{1,6}) (.+)|```.*)$/gm;
  let inFence = false;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (!m[1]) {
      inFence = !inFence; // comment lines inside code blocks ("# step 1") are not headings
      continue;
    }
    if (inFence) continue;
    if (out.length) out[out.length - 1].end = m.index;
    out.push({ heading: m[2].trim(), level: m[1].length, start: m.index, end: text.length });
  }
  return out;
}

/** The section heading that contains a character offset (nearest preceding heading). */
export function sectionAt(sections: TextSection[], offset: number): string | undefined {
  let found: TextSection | undefined;
  for (const s of sections) if (s.start <= offset) found = s;
  return found?.heading;
}

/**
 * Title and main-content text of an HTML page. `structured: true` renders headings, lists, tables
 * and code blocks as markdown-ish text and returns the section boundaries; the default plain
 * rendering is unchanged.
 */
export function htmlToText(
  html: string,
  opts: { structured?: boolean } = {},
): { title: string; text: string; sections?: TextSection[] } {
  const ogTitle =
    html.match(/<meta\s+[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
    html.match(/<meta\s+[^>]*name=["']twitter:title["'][^>]*content=["']([^"']+)["']/i)?.[1];

  const articleH1 = html.match(/<(?:article|main)\b[^>]*>[\s\S]*?<h1\b[^>]*>([\s\S]*?)<\/h1>/i)?.[1];
  const firstH1 = html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i)?.[1];
  const pageTitle = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1];

  const cleanHeader = (s?: string) => (s ? decodeHtmlText(s.replace(/<[^>]+>/g, "")).replace(/\s+/g, " ").trim() : "");
  const isGenericHeading = (s?: string) =>
    !s || s.length < 4 || /social media|social mediach|newsletter|subscribe|menu|navigation|footer|search|kontakt|baza wiedzy/i.test(s);

  let rawTitle = "";
  if (articleH1 && !isGenericHeading(cleanHeader(articleH1))) {
    rawTitle = cleanHeader(articleH1);
  } else if (ogTitle && !isGenericHeading(cleanHeader(ogTitle))) {
    rawTitle = cleanHeader(ogTitle);
  } else if (pageTitle && !isGenericHeading(cleanHeader(pageTitle))) {
    rawTitle = cleanHeader(pageTitle);
  } else if (firstH1 && !isGenericHeading(cleanHeader(firstH1))) {
    rawTitle = cleanHeader(firstH1);
  } else {
    rawTitle = cleanHeader(pageTitle) || cleanHeader(firstH1) || "Untitled report";
  }

  // Clean blog / publisher branding suffixes from title
  rawTitle = rawTitle
    .replace(/\s*[|–—]\s*(Google Cloud Blog|The DFIR Report|Microsoft Security Blog|Unit 42|SentinelOne|Cisco Talos|Huntress|BleepingComputer|Mandiant|CERT Polska).*$/i, "")
    .trim();

  const selected = selectContentFragment(html);
  if (opts.structured) {
    const text = selected.fragment ? fragmentToStructuredText(selected.fragment) : selected.text;
    return { title: rawTitle.slice(0, 240), text, sections: sectionsOf(text) };
  }
  return { title: rawTitle.slice(0, 240), text: selected.text };
}

export function extractHtmlMetadata(html: string): {
  author?: string;
  publisher?: string;
  publishedAt?: string;
} {
  let author: string | undefined;
  let publisher: string | undefined;
  let publishedAt: string | undefined;

  // 1. Check in-article author patterns like "Written by: Alice, Bob" or "By: Alice"
  const writtenByMatch = html.match(/<(?:p|span|div)[^>]*>(?:Written\s+by|By):\s*([^<]+)<\/(?:p|span|div)>/i);
  if (writtenByMatch && writtenByMatch[1].trim().length > 2 && writtenByMatch[1].trim().length < 150) {
    author = decodeEntities(writtenByMatch[1].trim());
  }

  // 2. JSON-LD schema
  try {
    const jsonLdMatches = html.matchAll(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi);
    for (const match of jsonLdMatches) {
      try {
        const data = JSON.parse(match[1]);
        const items = Array.isArray(data) ? data : [data];
        for (const item of items) {
          if (!author && item.author) {
            if (Array.isArray(item.author)) {
              author = item.author.map((a: any) => (typeof a === "string" ? a : a.name)).filter(Boolean).join(", ");
            } else if (typeof item.author === "object" && item.author.name) {
              author = item.author.name;
            } else if (typeof item.author === "string") {
              author = item.author;
            }
          }
          if (!publisher && item.publisher) {
            publisher = typeof item.publisher === "object" ? item.publisher.name : item.publisher;
          }
          if (!publishedAt && (item.datePublished || item.dateCreated)) {
            publishedAt = (item.datePublished || item.dateCreated).slice(0, 10);
          }
        }
      } catch {
        /* malformed JSON-LD block */
      }
    }
  } catch {
    /* ignore */
  }

  // 3. Meta tags
  if (!author) {
    const authorMeta =
      html.match(/<meta\s+[^>]*name=["']authors?["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
      html.match(/<meta\s+[^>]*content=["']([^"']+)["'][^>]*name=["']authors?["']/i)?.[1] ||
      html.match(/<meta\s+[^>]*name=["']track-metadata-page_post_author["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
      html.match(/<meta\s+[^>]*property=["']article:author["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
      html.match(/<meta\s+[^>]*name=["']twitter:creator["'][^>]*content=["']([^"']+)["']/i)?.[1];
    if (authorMeta) author = decodeEntities(authorMeta.trim());
  }

  if (!publisher) {
    const pubMeta =
      html.match(/<meta\s+[^>]*property=["']og:site_name["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
      html.match(/<meta\s+[^>]*name=["']publisher["'][^>]*content=["']([^"']+)["']/i)?.[1];
    if (pubMeta) publisher = decodeEntities(pubMeta.trim());
  }

  if (!publishedAt) {
    const dateMeta =
      html.match(/<meta\s+[^>]*property=["']article:published_time["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
      html.match(/<meta\s+[^>]*name=["']published_time["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
      html.match(/<meta\s+[^>]*name=["']track-metadata-page_first_published["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
      html.match(/<meta\s+[^>]*name=["']publish-date["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
      html.match(/<time\s+[^>]*datetime=["']([^"']+)["']/i)?.[1];
    if (dateMeta) publishedAt = dateMeta.slice(0, 10);
  }

  return { author, publisher, publishedAt };
}

export function decodeEntities(s: string): string {
  if (!s) return "";
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => {
      try {
        return String.fromCodePoint(parseInt(n, 16));
      } catch {
        return "";
      }
    })
    .replace(/&#([0-9]+);/g, (_, n) => {
      try {
        return String.fromCodePoint(parseInt(n, 10));
      } catch {
        return "";
      }
    })
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&lsquo;/g, "‘")
    .replace(/&rsquo;/g, "’")
    .replace(/&ldquo;/g, "“")
    .replace(/&rdquo;/g, "”")
    .replace(/&mdash;/g, "—")
    .replace(/&ndash;/g, "–")
    .replace(/&hellip;/g, "…")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&");
}

// ---------------------------------------------------------------------------
// IOC harvesting: defang-aware, with exact evidence offsets into `text`.
// ---------------------------------------------------------------------------

const TECH_RE = /\bT1[0-9]{3}(?:\.[0-9]{3})?\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const HEX_RE = /(?<![A-Za-z0-9])[A-Fa-f0-9]{32,128}(?![A-Za-z0-9])/g;

// Separators as they appear in defanged indicators.
const DOT_SRC = String.raw`(?:\.|\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\s?\[\s*dot\s*\]\s?|\s?\(\s*dot\s*\)\s?|\s?\{\s*dot\s*\}\s?)`;
const AT_SRC = String.raw`(?:@|\[\s*@\s*\]|\(\s*@\s*\)|\s?\[\s*at\s*\]\s?|\s?\(\s*at\s*\)\s?|\s?\{\s*at\s*\}\s?)`;
const LABEL_SRC = String.raw`[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?`;
const TLD_SRC = String.raw`(?:[A-Za-z]{2,24}|xn--[A-Za-z0-9-]{2,59})`;
const HOST_SRC = String.raw`(?:${LABEL_SRC}${DOT_SRC})+${TLD_SRC}`;
const IP_SRC = String.raw`(?:\d{1,3}${DOT_SRC}){3}\d{1,3}`;
const SCHEME_SRC = String.raw`(?:h[tx]{2}ps?|f[tx]p|s?f[tx]p)(?:\[\s*:\s*\]\/\/|\[\s*:\/\/\s*\]|:\/\/|\[:\]\[\/\/\])`;
const PATH_CHAR_SRC = String.raw`(?:[A-Za-z0-9\-._~:/?#@!$&*+,;=%]|\[\s*\.\s*\]|\[\s*:\s*\])`;

const URL_RE = new RegExp(
  String.raw`(?<![A-Za-z0-9])${SCHEME_SRC}(?:${HOST_SRC}|${IP_SRC}|\[[0-9a-fA-F:]+\])(?:(?::|\[\s*:\s*\])\d{1,5})?(?:[/?#]${PATH_CHAR_SRC}*)?`,
  "gi",
);
const EMAIL_RE = new RegExp(String.raw`(?<![A-Za-z0-9._%+-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}${AT_SRC}${HOST_SRC}(?![A-Za-z0-9-])`, "g");
const DOMAIN_RE = new RegExp(String.raw`(?<![A-Za-z0-9_@.$\-])${HOST_SRC}(?![A-Za-z0-9_\-]|\.[A-Za-z0-9])`, "g");
const IPV4_RE = new RegExp(String.raw`(?<![\d.\]])${IP_SRC}(?![\d]|\.\d|\[\s*\.)`, "g");

const DEFANG_MARK_RE = /\[\s*(?:\.|dot|:|:\/\/|@|at)\s*\]|\(\s*(?:\.|dot|@|at)\s*\)|\{\s*(?:\.|dot|at)\s*\}|\bh[x]{2}ps?|\bf[x]p/i;

/** Re-fang a defanged indicator: hxxp→http, [.]/(.)/{.}/[dot]→., [:]→:, [at]/[@]→@ */
export function refang(s: string): string {
  return s
    .replace(/\bh[tx]{2}p(s?)(?=\[|:)/gi, "http$1")
    .replace(/\bf[tx]p(?=\[|:)/gi, "ftp")
    .replace(/\[\s*:\/\/\s*\]/g, "://")
    .replace(/\[:\]\[\/\/\]/g, "://")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\s?[[({]\s*dot\s*[\])}]\s?/gi, ".")
    .replace(/[[({]\s*\.\s*[\])}]/g, ".")
    .replace(/\s?[[({]\s*at\s*[\])}]\s?/gi, "@")
    .replace(/[[({]\s*@\s*[\])}]/g, "@");
}

// Executable / document / script extensions that look like TLDs in prose
// ("payload.zip", "loader.ps1", "config.json"): excluded unless defanged.
const FILE_EXTENSIONS = new Set(
  (
    "exe dll sys drv ocx cpl scr bat cmd ps1 psm1 psd1 vbs vbe js jse wsf wsh hta lnk msi msp msc reg inf " +
    "zip rar 7z gz tgz tar bz2 xz cab iso img vhd vhdx dmg pkg deb rpm apk ipa jar war ear class " +
    "doc docx docm dot dotm xls xlsx xlsm xlsb ppt pptx pptm pdf rtf odt txt log csv tsv json xml yaml yml ini " +
    "cfg conf config dat bin tmp bak old py pyc sh bash zsh pl pm rb php phtml asp aspx ashx asmx jsp jspx cgi " +
    "html htm xhtml css scss md rst mov mp4 mp3 wav avi mkv jpg jpeg png gif bmp ico svg webp tif tiff " +
    "db sqlite sql mdb dmp evtx etl pcap pcapng pf lck key pem crt cer der csr pfx p12 p7b ps go rs c cpp cc h hpp " +
    "cs vb java kt swift ts tsx jsx mjs cjs vue lua so ko elf o a lib dylib ova ovf vmdk vmx yar yara rules sigma nse"
  ).split(" "),
);

const COMMON_GTLDS = new Set(
  (
    "com net org info biz io co me tv cc us uk ru cn su top xyz online site club store app dev cloud live tech space " +
    "website fun icu vip pw ws la tk ml ga cf gq buzz shop link click work life world today news email host services " +
    "support digital solutions network systems center agency global group company zone one pro name mobi asia tel " +
    "jobs travel gov edu mil int xxx win bid loan date download racing review stream trade party science men cricket " +
    "accountant faith webcam kim ink rest bar best cyou monster quest sbs cfd lol beauty hair skin makeup homes autos " +
    "motorcycles boats yachts mom ltd llc inc biz page blog art design studio media social chat run fyi wiki cam " +
    "gdn ooo rocks ninja guru expert tips tools domains business finance money cash bank capital fund investments"
  ).split(" "),
);

// ISO 3166 country-code TLDs (plus eu/ac/uk); any other two-letter "TLD" (e.g. ".ip" in "e.target.ip") is not a host.
const CC_TLDS = new Set(
  (
    "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz " +
    "ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm " +
    "fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it " +
    "je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn " +
    "mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps " +
    "pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj " +
    "tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"
  ).split(" "),
);

// Reference / schema infrastructure that shows up in reports but is never an IOC (unless defanged).
const BENIGN_DOMAINS = [
  "w3.org", "schema.org", "purl.org", "xmlsoap.org", "ogp.me", "example.com", "example.net", "example.org",
  "mitre.org", "nist.gov", "first.org", "iana.org", "ietf.org", "rfc-editor.org",
  // "Follow us" / share links and vendor short-links in report footers.
  "twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com", "aka.ms",
];

function registrableDomain(host: string): string {
  const parts = host.toLowerCase().replace(/^www\./, "").split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const sld = parts[parts.length - 2];
  const secondLevelCc = parts[parts.length - 1].length === 2 && /^(?:co|com|net|org|gov|edu|ac|or|ne|go)$/.test(sld);
  return parts.slice(secondLevelCc ? -3 : -2).join(".");
}

function domainMatches(host: string, base: string): boolean {
  return host === base || host.endsWith(`.${base}`);
}

const PRIVATE_V4: Array<[number, number]> = [
  // [network as uint32, prefix length]
  [0x00000000, 8], // 0.0.0.0/8
  [0x0a000000, 8], // 10/8
  [0x64400000, 10], // 100.64/10 CGNAT
  [0x7f000000, 8], // loopback
  [0xa9fe0000, 16], // link-local
  [0xac100000, 12], // 172.16/12
  [0xc0000000, 24], // 192.0.0/24
  [0xc0000200, 24], // TEST-NET-1
  [0xc0a80000, 16], // 192.168/16
  [0xc6120000, 15], // 198.18/15 benchmarking
  [0xc6336400, 24], // TEST-NET-2
  [0xcb007100, 24], // TEST-NET-3
  [0xe0000000, 4], // multicast 224/4
  [0xf0000000, 4], // reserved 240/4 (incl. broadcast)
];

function parseIpv4(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p[0] === "0")) return null;
    const o = Number(p);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n >>> 0;
}

export function isNonPublicIpv4(value: string): boolean {
  const n = parseIpv4(value);
  if (n === null) return true;
  return PRIVATE_V4.some(([net, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((n & mask) >>> 0) === net;
  });
}

// Strong roles name what the indicator was used for; weak ones (staging/hosting) only
// count when no strong role is stated ("file-hosting services ... for exfiltration").
const ROLE_RULES: Array<{ role: string; re: RegExp; strong: boolean }> = [
  { role: "C2", re: /\b(?:c2|c&c|cnc|command[\s-]+(?:and|&)[\s-]+control|beacon(?:s|ed|ing)?)\b/i, strong: true },
  { role: "exfiltration", re: /\bexfiltrat\w*/i, strong: true },
  { role: "payload delivery", re: /\b(?:payloads?|download(?:s|ed|ing|er)?|deliver(?:y|ed|s|ing)?|dropper)\b/i, strong: true },
  { role: "phishing", re: /\bphish\w*/i, strong: true },
  { role: "staging", re: /\bstag(?:ing|ed)\b/i, strong: false },
  { role: "hosting", re: /\bhost(?:ing|ed)\b/i, strong: false },
];
const ROLE_NEGATION_RE = /\b(?:not|never|no evidence|benign|legitimate|false positive)\b/i;

/** Conservative: a role only when exactly one role family (strong first) appears in the passage and it is not negated. */
function roleFromPassage(passage: string): string | undefined {
  if (ROLE_NEGATION_RE.test(passage)) return undefined;
  const hits = ROLE_RULES.filter((r) => r.re.test(passage));
  const strong = hits.filter((r) => r.strong);
  if (strong.length > 0) return strong.length === 1 ? strong[0].role : undefined;
  return hits.length === 1 ? hits[0].role : undefined;
}

/** Containing sentence (or table row / line) for [start, end), as exact offsets into text. */
function passageAround(text: string, start: number, end: number): Evidence {
  let lineStart = text.lastIndexOf("\n", start - 1) + 1;
  let lineEnd = text.indexOf("\n", end);
  if (lineEnd === -1) lineEnd = text.length;

  // Sentence boundaries inside the line: ". " / "! " / "? " followed by a capital/digit/quote.
  let s = lineStart;
  const before = text.slice(lineStart, start);
  const boundaryRe = /[.!?]["'”’)]?\s+(?=["'“‘(]?[A-Z0-9])/g;
  let b: RegExpExecArray | null;
  while ((b = boundaryRe.exec(before))) s = lineStart + b.index + b[0].length;
  let e = lineEnd;
  const after = text.slice(end, lineEnd);
  const fwd = /[.!?]["'”’)]?(?=\s+["'“‘(]?[A-Z0-9])|[.!?]["'”’)]?$/.exec(after);
  if (fwd) e = end + fwd.index + fwd[0].length;

  // Keep very long passages (minified tables, code) bounded around the hit.
  if (e - s > 600) {
    s = Math.max(s, start - 250);
    e = Math.min(e, end + 250);
  }
  lineStart = s;
  lineEnd = e;
  while (lineStart < start && /\s/.test(text[lineStart])) lineStart++;
  while (lineEnd > end && /\s/.test(text[lineEnd - 1])) lineEnd--;
  return { quote: text.slice(lineStart, lineEnd), start: lineStart, end: lineEnd };
}

export type HarvestIocsOptions = {
  /** Host (or URL) of the report itself; its domain is never reported unless defanged. */
  sourceDomain?: string;
  /** Maximum hits returned (default 500). */
  limit?: number;
};

const KIND_ORDER: IocHit["kind"][] = ["cve", "technique", "sha256", "sha1", "md5", "ipv4", "domain", "url", "email"];

export function harvestIocs(text: string, options: HarvestIocsOptions = {}): IocHit[] {
  const limit = options.limit ?? 500;
  let ownDomain = "";
  if (options.sourceDomain) {
    try {
      const host = /^[a-z]+:\/\//i.test(options.sourceDomain) ? new URL(options.sourceDomain).hostname : options.sourceDomain;
      ownDomain = registrableDomain(host);
    } catch {
      ownDomain = "";
    }
  }

  const byKey = new Map<string, IocHit & { order: number }>();
  let order = 0;
  const push = (kind: IocHit["kind"], value: string, start: number, end: number, original: string, defanged: boolean) => {
    const key = `${kind}:${value.toLowerCase()}`;
    const evidence = passageAround(text, start, end);
    // Role words inside the indicator itself ("staging-files[.]xyz") do not count.
    const role = kind === "cve" || kind === "technique" ? undefined : roleFromPassage(evidence.quote.split(original).join(" "));
    const existing = byKey.get(key);
    if (existing) {
      if (!existing.role && role) {
        existing.role = role;
        existing.evidence = evidence;
      }
      if (defanged && !existing.defanged) {
        existing.defanged = true;
        existing.original = original;
      }
      return;
    }
    const hit: IocHit & { order: number } = { kind, value, evidence, order: order++ };
    if (original !== value) hit.original = original;
    if (defanged) hit.defanged = true;
    if (role) hit.role = role;
    byKey.set(key, hit);
  };

  const isExcludedHost = (host: string) =>
    (ownDomain !== "" && domainMatches(host, ownDomain)) || BENIGN_DOMAINS.some((d) => domainMatches(host, d));

  /** Validate a refanged host; returns null when it should not be reported. */
  const acceptHost = (host: string, original: string, defanged: boolean): string | null => {
    const h = host.toLowerCase().replace(/\.$/, "");
    const labels = h.split(".");
    if (labels.length < 2 || labels.some((l) => l.length === 0 || l.length > 63)) return null;
    const tld = labels[labels.length - 1];
    if (/^\d+$/.test(tld)) return null;
    if (defanged) return h;
    if (FILE_EXTENSIONS.has(tld)) return null;
    if (!(CC_TLDS.has(tld) || COMMON_GTLDS.has(tld) || tld.startsWith("xn--"))) return null;
    // Code identifiers (System.IO, Microsoft.Graph) capitalise the last segment; hosts in prose
    // may be brand-cased ("GoFile.io") but keep a lower-case TLD.
    const origTld = original.split(/[.\])}]/).filter(Boolean).pop() ?? "";
    if (origTld !== origTld.toLowerCase()) return null;
    if (isExcludedHost(h)) return null;
    return h;
  };

  // Spans already claimed by URLs / emails (their hosts are not re-reported as bare domains).
  const claimed: Array<[number, number]> = [];
  const isClaimed = (s: number, e: number) => claimed.some(([a, b]) => s >= a && e <= b);

  for (const m of text.matchAll(CVE_RE)) push("cve", m[0].toUpperCase(), m.index ?? 0, (m.index ?? 0) + m[0].length, m[0].toUpperCase(), false);
  for (const m of text.matchAll(TECH_RE)) push("technique", m[0].toUpperCase(), m.index ?? 0, (m.index ?? 0) + m[0].length, m[0].toUpperCase(), false);

  for (const m of text.matchAll(HEX_RE)) {
    const v = m[0].toLowerCase();
    const kind = v.length === 64 ? "sha256" : v.length === 40 ? "sha1" : v.length === 32 ? "md5" : null;
    if (!kind) continue; // sha512 or other lengths: never split into shorter hashes
    if (/^(.)\1+$/.test(v) || !/[a-f]/.test(v) || !/\d/.test(v)) continue;
    push(kind, v, m.index ?? 0, (m.index ?? 0) + m[0].length, m[0], false);
  }

  for (const m of text.matchAll(URL_RE)) {
    let original = m[0];
    // Trim trailing punctuation and unbalanced closing brackets.
    while (/[.,;:!?'"*]$/.test(original) || (/\)$/.test(original) && (original.match(/\(/g)?.length ?? 0) < (original.match(/\)/g)?.length ?? 0))) {
      original = original.slice(0, -1);
    }
    const start = m.index ?? 0;
    const end = start + original.length;
    const defanged = DEFANG_MARK_RE.test(original);
    let parsed: URL;
    try {
      parsed = new URL(refang(original));
    } catch {
      continue;
    }
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    claimed.push([start, end]);
    const isIp = parseIpv4(host) !== null;
    if (!defanged) {
      if (isIp ? isNonPublicIpv4(host) : isExcludedHost(host)) continue;
      if (!isIp && !acceptHost(host, host, false)) continue;
    }
    let value = parsed.toString();
    if (parsed.pathname === "/" && !parsed.search && value.endsWith("/") && !refang(original).endsWith("/")) value = value.slice(0, -1);
    push("url", value, start, end, original, defanged);
    if (isIp) {
      if (defanged || !isNonPublicIpv4(host)) push("ipv4", host, start, end, original, defanged);
    } else {
      const hostIdx = original.indexOf("//") + 2;
      const hostOrig = original.slice(hostIdx).split(/[/?#]|(?::|\[\s*:\s*\])\d/)[0];
      const accepted = acceptHost(host, defanged ? hostOrig : host, defanged);
      if (accepted) push("domain", accepted, start + hostIdx, start + hostIdx + hostOrig.length, hostOrig, DEFANG_MARK_RE.test(hostOrig));
    }
  }

  for (const m of text.matchAll(EMAIL_RE)) {
    const start = m.index ?? 0;
    const end = start + m[0].length;
    if (isClaimed(start, end)) continue;
    const original = m[0];
    const defanged = DEFANG_MARK_RE.test(original);
    const value = refang(original).replace(/\s+/g, "").toLowerCase();
    const at = value.lastIndexOf("@");
    if (at <= 0) continue;
    claimed.push([start, end]);
    const host = value.slice(at + 1);
    if (!acceptHost(host, host, defanged)) continue;
    push("email", value, start, end, original, defanged);
  }

  for (const m of text.matchAll(DOMAIN_RE)) {
    const start = m.index ?? 0;
    const end = start + m[0].length;
    if (isClaimed(start, end)) continue;
    const original = m[0];
    const defanged = DEFANG_MARK_RE.test(original);
    // A bare dotted quad is an IP, handled below.
    const refanged = refang(original).replace(/\s+/g, "");
    if (/^[\d.]+$/.test(refanged)) continue;
    const host = acceptHost(refanged, original, defanged);
    if (host) push("domain", host, start, end, original, defanged);
  }

  for (const m of text.matchAll(IPV4_RE)) {
    const start = m.index ?? 0;
    const end = start + m[0].length;
    const original = m[0];
    const defanged = DEFANG_MARK_RE.test(original);
    const value = refang(original).replace(/\s+/g, "");
    if (parseIpv4(value) === null) continue;
    if (!defanged) {
      if (isNonPublicIpv4(value)) continue;
      // Version strings ("version 2.0.0.1", "v1.2.3.4") are not addresses.
      if (/\b(?:v|ver\.?|version|build|release)\s*$/i.test(text.slice(Math.max(0, start - 12), start))) continue;
    }
    push("ipv4", value, start, end, original, defanged);
  }

  return [...byKey.values()]
    .sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || a.order - b.order)
    .slice(0, limit)
    .map(({ order: _order, ...hit }) => hit);
}

const SIGNAL_WORDS = [
  "ransomware",
  "credential",
  "lateral movement",
  "persistence",
  "command and control",
  "exfiltration",
  "initial access",
  "privilege escalation",
  "defense evasion",
  "att&ck",
  "mitre",
  "powershell",
  "mimikatz",
  "ntds.dit",
  "rdp",
  "cobalt strike",
  "c2",
  "ioc",
  "ttp",
];

export function scoreQuality(text: string, title: string): {
  score: number;
  reasons: QualityReason[];
  wordCount: number;
} {
  const reasons: QualityReason[] = [];
  const body = `${title}\n${text}`.toLowerCase();
  const wordCount = text.split(/\s+/).filter(Boolean).length;

  // Technical commands check
  const hasCommands =
    /(?:(?:powershell|cmd|wmic|schtasks|vssadmin|rundll32|certutil|reg|psexec|whoami|nltest|net\s+user|mimikatz|rubeus)\b[^\r\n]{5,100})/i.test(
      text,
    );
  const hasRegistry = /\b(?:HKLM|HKCU)\\[a-zA-Z0-9_\\]{4,80}\b/i.test(text);
  const hasEventId = /\b(?:Event\s*ID\s*(?:4688|4624|7045|1102)|Sysmon\s*(?:1|3|10))\b/i.test(text);
  const hasCve = /CVE-\d{4}-\d+/i.test(text);

  if (wordCount >= 2500) reasons.push({ label: "Long-form technical depth", delta: 0.28 });
  else if (wordCount >= 1200) reasons.push({ label: "Substantial article length", delta: 0.2 });
  else if (wordCount >= 500) reasons.push({ label: "Standard article length", delta: 0.1 });
  else if (hasCommands || hasRegistry || hasCve) {
    reasons.push({ label: "Concise technical artifact with actionable commands", delta: 0.16 });
  } else {
    reasons.push({ label: "Short non-procedural document", delta: -0.12 });
  }

  const hits = SIGNAL_WORDS.filter((w) => body.includes(w));
  if (hits.length >= 8) reasons.push({ label: `Dense adversary vocabulary (${hits.length})`, delta: 0.28 });
  else if (hits.length >= 4) reasons.push({ label: `Relevant threat terms (${hits.length})`, delta: 0.18 });
  else if (hits.length >= 2) reasons.push({ label: "Some threat terms", delta: 0.08 });
  else reasons.push({ label: "Weak threat vocabulary", delta: -0.10 });

  if (hasCommands) {
    reasons.push({ label: "Adversary execution commands / tradecraft present", delta: 0.22 });
  }
  if (hasRegistry) {
    reasons.push({ label: "Persistence registry keys / system artifacts", delta: 0.12 });
  }
  if (hasEventId) {
    reasons.push({ label: "Telemetry & detection event IDs", delta: 0.12 });
  }

  if (/\bstage\s*[123]|infection chain|attack chain|kill chain|lateral movement.*exfil/i.test(body)) {
    reasons.push({ label: "Named stages / attack chain language", delta: 0.18 });
  }
  if (/\bT1\d{3}\b/.test(text) || /att&ck/.test(body)) {
    reasons.push({ label: "ATT&CK identifiers present", delta: 0.12 });
  }
  if (hasCve) {
    reasons.push({ label: "CVE references", delta: 0.10 });
  }

  // Detect emerging techniques (BYOVD, unhooking, direct syscalls, PRT theft)
  if (/\b(?:byovd|direct syscalls|unhooking|amsi bypass|aadrefreshtoken|lotc)\b/i.test(body)) {
    reasons.push({ label: "Emerging / novel technique tradecraft", delta: 0.16 });
  }

  const score = Math.max(0, Math.min(1, reasons.reduce((s, r) => s + r.delta, 0.22)));
  return { score: Math.round(score * 100) / 100, reasons, wordCount };
}

export function excerptOf(text: string, n = 220): string {
  // Records stored before feed content was converted can hold markup: never show tags in an excerpt.
  const plain = /<[a-z!/][^>]*>/i.test(text) ? text.replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ") : text;
  const t = plain.replace(/\s+/g, " ").trim();
  return t.length <= n ? t : `${t.slice(0, n).trim()}…`;
}

const COMMON_STOP_WORDS = new Set([
  "the", "and", "is", "in", "to", "of", "it", "that", "you", "he", "was", "for", "on", "are",
  "as", "with", "his", "they", "at", "be", "this", "have", "from", "or", "one", "had", "by",
  "word", "but", "not", "what", "all", "were", "we", "when", "your", "can", "said", "there",
]);

function fnv1a64(str: string): bigint {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash = (hash * prime) & 0xffffffffffffffffn;
  }
  return hash;
}

export function computeSimHash64(text: string): string {
  const words = text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length >= 3 && !COMMON_STOP_WORDS.has(w));

  if (words.length === 0) return "0000000000000000";

  const v = new Int32Array(64);

  // Form 2-grams (shingles) for structural sentence similarity
  const step = Math.max(1, Math.floor(words.length / 500));
  for (let i = 0; i < words.length - 1; i += step) {
    const shingle = `${words[i]} ${words[i + 1]}`;
    const h = fnv1a64(shingle);
    for (let bit = 0; bit < 64; bit++) {
      if ((h >> BigInt(bit)) & 1n) {
        v[bit] += 1;
      } else {
        v[bit] -= 1;
      }
    }
  }

  let fingerprint = 0n;
  for (let bit = 0; bit < 64; bit++) {
    if (v[bit] > 0) {
      fingerprint |= 1n << BigInt(bit);
    }
  }

  return fingerprint.toString(16).padStart(16, "0");
}

export function computeHammingDistance(hashA: string, hashB: string): number {
  try {
    const a = BigInt("0x" + hashA);
    const b = BigInt("0x" + hashB);
    let xor = a ^ b;
    let dist = 0;
    while (xor > 0n) {
      dist += Number(xor & 1n);
      xor >>= 1n;
    }
    return dist;
  } catch {
    return 64;
  }
}


/** Length of the extracted-text window used for near-duplicate SimHash. */
export const SIMHASH_WINDOW_CHARS = 3000;

/**
 * Near-duplicate fingerprint of a report. Both stored reports and crawl
 * candidates must use this (same normalized window of extractedText, title
 * excluded) so their Hamming distances are comparable.
 */
export function computeReportSimHash(extractedText: string): string {
  const window = (extractedText || "").replace(/\s+/g, " ").trim().slice(0, SIMHASH_WINDOW_CHARS);
  return computeSimHash64(window);
}
