/**
 * Non-English reports. Before a report in another language is evaluated or stored, the crawler
 * 1. follows the publisher's own English version when the page links one (hreflang alternate, or a
 *    language switcher to the same path under /en/), and otherwise
 * 2. translates the text with the configured AI, checks the translation, and evaluates and stores the
 *    English text, keeping the original as evidence.
 * Without AI the report is held, not rejected: the next crawl with AI available evaluates it.
 *
 * Pure helpers (no I/O); the model call is runUnifiedTranslation in ./ai-manager.
 */
import { detectLanguage } from "./technical-depth.ts";
import { UNTRUSTED_CONTENT_NOTICE, wrapUntrustedContent } from "./agent-framework/types.ts";
import type { ReportTranslation } from "./types.ts";

/** Characters per model call: about 1,500 tokens of output, well inside every provider's limit. */
export const TRANSLATION_CHUNK_CHARS = 6000;
/** Characters translated per report (four calls). Past it, the rest is kept in the original. */
export const TRANSLATION_MAX_CHARS = 24_000;
/** Characters of the original text kept with a translated report. */
export const ORIGINAL_TEXT_CAP = 150_000;
/** AI translations per crawl run; reports beyond it are held for the next run. */
export const TRANSLATIONS_PER_JOB = 12;
/** Total translation time per crawl run, so translations cannot stretch a run. */
export const TRANSLATION_JOB_BUDGET_MS = 10 * 60_000;
/** Share of the crawler's per-report time limit a translation may use (evaluation needs the rest). */
export const TRANSLATION_ITEM_SHARE = 0.6;

export type TranslationRecord = ReportTranslation;

const LANGUAGE_NAMES: Record<string, string> = {
  pl: "Polish",
  de: "German",
  fr: "French",
  es: "Spanish",
  it: "Italian",
  pt: "Portuguese",
  nl: "Dutch",
  cs: "Czech",
  ru: "Russian",
  uk: "Ukrainian",
  ja: "Japanese",
  ko: "Korean",
  zh: "Chinese",
  ar: "Arabic",
};

export function languageName(code: string): string {
  if (LANGUAGE_NAMES[code]) return LANGUAGE_NAMES[code];
  try {
    const name = new Intl.DisplayNames(["en"], { type: "language" }).of(code);
    if (name && name !== code) return name;
  } catch {
    /* not a language code */
  }
  return code.toUpperCase();
}

// ---------------------------------------------------------------------------
// The publisher's English version
// ---------------------------------------------------------------------------

function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return m ? (m[1] ?? m[2] ?? m[3] ?? "").trim() : null;
}

function siteOf(host: string): string {
  return host.toLowerCase().replace(/^www\./, "");
}

function sameSite(a: URL, b: URL): boolean {
  const x = siteOf(a.hostname);
  const y = siteOf(b.hostname);
  return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
}

function samePage(a: URL, b: URL): boolean {
  const norm = (u: URL) => `${siteOf(u.hostname)}${u.pathname.replace(/\/+$/, "")}${u.search}`;
  return norm(a) === norm(b);
}

function resolveHttp(href: string, base: URL): URL | null {
  try {
    const u = new URL(href.replace(/&amp;/g, "&"), base);
    return u.protocol === "https:" || u.protocol === "http:" ? u : null;
  } catch {
    return null;
  }
}

/** Paths that are the English edition of `page`: /en + path, or the language segment swapped for /en. */
function englishPathsOf(page: URL): string[] {
  const path = page.pathname.replace(/\/+$/, "") || "/";
  const out = [`/en${path}`, `/en-us${path}`, `/en-gb${path}`];
  const lead = path.match(/^\/([a-z]{2})(?:[-_][a-z]{2})?(\/.*)$/i);
  if (lead && lead[1].toLowerCase() !== "en") out.push(`/en${lead[2]}`);
  return out.map((p) => p.toLowerCase());
}

/**
 * The URL of the English edition the page itself links to, or null. Only links on the same site
 * count, so a page cannot send the crawler elsewhere.
 */
export function findEnglishAlternate(html: string, pageUrl: string): string | null {
  let page: URL;
  try {
    page = new URL(pageUrl);
  } catch {
    return null;
  }
  const head = html.slice(0, 400_000);
  const pick = (u: URL | null): string | null => (u && sameSite(u, page) && !samePage(u, page) ? u.toString() : null);

  // 1. <link rel="alternate" hreflang="en"> and <a hreflang="en">: the publisher's own declaration.
  for (const m of head.matchAll(/<(?:link|a)\b[^>]*\shreflang\s*=[^>]*>/gi)) {
    const tag = m[0];
    const lang = (attr(tag, "hreflang") ?? "").toLowerCase();
    if (!/^en(?:[-_][a-z]{2})?$/.test(lang)) continue;
    if (/^<link/i.test(tag) && !/\balternate\b/i.test(attr(tag, "rel") ?? "")) continue;
    const found = pick(resolveHttp(attr(tag, "href") ?? "", page));
    if (found) return found;
  }

  // 2. A language switcher: a link to the same path under /en/ (cert.pl/posts/… → cert.pl/en/posts/…).
  const wanted = new Set(englishPathsOf(page));
  for (const m of head.matchAll(/<a\b[^>]*\shref\s*=[^>]*>/gi)) {
    const u = resolveHttp(attr(m[0], "href") ?? "", page);
    if (!u || !sameSite(u, page)) continue;
    const path = (u.pathname.replace(/\/+$/, "") || "/").toLowerCase();
    if (wanted.has(path)) return pick(u);
  }
  return null;
}

/**
 * Where the English edition of a localized URL would be: the language segment removed
 * (/blog/ja/topics/x → /blog/topics/x) or swapped for /en/. Only a path segment equal to the page's
 * own detected language is touched, so /it/ in an English URL is never mistaken for Italian. These
 * are guesses: the crawler only matches them against reports it already has or has queued, and
 * never fetches them.
 */
export function guessEnglishUrls(pageUrl: string, lang: string): string[] {
  let page: URL;
  try {
    page = new URL(pageUrl);
  } catch {
    return [];
  }
  const code = lang.toLowerCase();
  if (!/^[a-z]{2,3}$/.test(code) || code === "en") return [];
  const segments = page.pathname.split("/");
  const at = segments.findIndex((seg) => {
    const s = seg.toLowerCase();
    return s === code || s.startsWith(`${code}-`) || s.startsWith(`${code}_`);
  });
  if (at < 1) return [];
  const build = (replacement: string[]) => {
    const u = new URL(page.toString());
    u.pathname = [...segments.slice(0, at), ...replacement, ...segments.slice(at + 1)].join("/") || "/";
    return u.toString();
  };
  return [...new Set([build([]), build(["en"]), build(["en-us"])])].filter((u) => u !== page.toString());
}

/** The language the page declares on <html lang>, if any. */
export function declaredHtmlLang(html: string): string | null {
  const tag = html.slice(0, 5000).match(/<html\b[^>]*>/i)?.[0];
  const lang = tag ? attr(tag, "lang") : null;
  return lang && /^[a-z]{2,3}(?:[-_][a-z0-9]{2,8})?$/i.test(lang) ? lang.toLowerCase() : null;
}

// ---------------------------------------------------------------------------
// Chunking and prompts
// ---------------------------------------------------------------------------

/** Splits at paragraph, then line, then sentence boundaries; never mid-token unless a run has none. */
export function splitForTranslation(
  text: string,
  maxChunk = TRANSLATION_CHUNK_CHARS,
  maxTotal = TRANSLATION_MAX_CHARS,
): { chunks: string[]; translatedChars: number; totalChars: number; partial: boolean } {
  const source = text.trim();
  const pieces: string[] = [];
  const pushPiece = (p: string) => {
    if (p.length <= maxChunk) {
      pieces.push(p);
      return;
    }
    const parts = p.includes("\n") ? p.split(/(?<=\n)/) : p.split(/(?<=[.!?。！？])\s+/);
    if (parts.length > 1) {
      for (const q of parts) pushPiece(q);
      return;
    }
    for (let i = 0; i < p.length; i += maxChunk) pieces.push(p.slice(i, i + maxChunk));
  };
  for (const para of source.split(/(\n\s*\n)/)) if (para) pushPiece(para);

  const chunks: string[] = [];
  let current = "";
  let used = 0;
  let partial = false;
  for (const piece of pieces) {
    if (used + piece.length > maxTotal) {
      partial = true;
      break;
    }
    if (current.length + piece.length > maxChunk && current.trim()) {
      chunks.push(current.trim());
      current = "";
    }
    current += piece;
    used += piece.length;
  }
  if (current.trim()) chunks.push(current.trim());
  return { chunks, translatedChars: used, totalChars: source.length, partial };
}

export const TRANSLATION_SYSTEM_PROMPT = [
  "You translate cyber threat intelligence reports into English for security analysts.",
  "Translate faithfully and completely. Do not summarise, shorten, explain, add notes or comment.",
  "Copy exactly as written, without translating or reformatting: indicators (file hashes, IP addresses, domains, URLs, e-mail addresses, file names and paths, registry keys), commands and code, CVE and ATT&CK identifiers, version numbers, and the names of products, malware, tools and threat actors.",
  "Keep the paragraph and line structure, including any markdown such as headings, lists and tables.",
  "Output only the English translation.",
  UNTRUSTED_CONTENT_NOTICE,
].join("\n");

export function translationPrompt(chunk: string, lang: string, part: number, parts: number, title?: string): string {
  const where = parts > 1 ? ` This is part ${part} of ${parts} of one report.` : "";
  const titled = title ? `# ${title.replace(/\s+/g, " ").trim()}\n\n${chunk}` : chunk;
  const titleRule = title ? " The first line is the report title: keep it as the first line, starting with \"# \"." : "";
  return `Translate the ${languageName(lang)} text below into English.${where}${titleRule}\n\n${wrapUntrustedContent(titled)}`;
}

/** Removes what models wrap around a translation: code fences, the data tags, "Here is…" lead-ins. */
export function cleanTranslationOutput(raw: string): string {
  let t = raw.replace(/\r\n/g, "\n").trim();
  t = t.replace(/^<\s*untrusted_source_content\s*>\s*/i, "").replace(/\s*<\s*\/\s*untrusted_source_content\s*>$/i, "");
  const fenced = t.match(/^```[a-z]*\n([\s\S]*?)\n```$/i);
  if (fenced) t = fenced[1];
  t = t.replace(/^(?:here is|here's|below is)[^\n]{0,80}translation[^\n]*:\s*\n/i, "");
  return t.trim();
}

/** Splits the translated title line ("# …") off the first chunk; keeps the original title otherwise. */
export function takeTranslatedTitle(firstChunk: string, originalTitle: string): { title: string; body: string } {
  const m = firstChunk.match(/^\s*#\s+([^\n]{1,300})\n?/);
  if (!m) return { title: originalTitle, body: firstChunk };
  return { title: m[1].trim(), body: firstChunk.slice(m[0].length).trim() };
}

// ---------------------------------------------------------------------------
// Checking a translation
// ---------------------------------------------------------------------------

/** Values a faithful translation keeps byte for byte; normalised so a defanged IP equals its plain form. */
export function protectedTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi)) out.add(m[0].toUpperCase());
  for (const m of text.matchAll(/\bT1\d{3}(?:\.\d{3})?\b/g)) out.add(m[0]);
  for (const m of text.matchAll(/\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi)) out.add(m[0].toLowerCase());
  for (const m of text.matchAll(/\b\d{1,3}(?:(?:\[\.\]|\(\.\)|\.)\d{1,3}){3}\b/g)) {
    const ip = m[0].replace(/\[\.\]|\(\.\)/g, ".");
    if (ip.split(".").every((o) => Number(o) <= 255)) out.add(ip);
  }
  for (const m of text.matchAll(/\b[\w-]+(?:\[\.\][\w-]+)+/g)) {
    if (/[a-z]/i.test(m[0])) out.add(m[0].toLowerCase().replace(/\[\.\]/g, "."));
  }
  return out;
}

export type TranslationCheck = { ok: true } | { ok: false; reason: string };

/**
 * A translation is used only when it kept every indicator and identifier, invented none, has a
 * plausible length, and reads as English. A model that drops or makes up an IP address or a hash
 * would put false intelligence into the library; such output is refused and the report is held.
 */
export function checkTranslation(original: string, translated: string): TranslationCheck {
  const src = original.trim();
  const out = translated.trim();
  if (!out) return { ok: false, reason: "the model returned no text" };
  const ratio = out.length / Math.max(1, src.length);
  // Chinese, Japanese and Korean pack a word into one or two characters: English runs 2-3x longer.
  const dense = (src.match(/[぀-ヿ가-힯一-鿿]/g) ?? []).length > src.length * 0.3;
  const [low, high] = dense ? [0.5, 7] : [0.3, 4];
  if (src.length > 200 && (ratio < low || ratio > high)) {
    return { ok: false, reason: `the translation is ${ratio < 1 ? "much shorter" : "much longer"} than the original (${Math.round(ratio * 100)}%)` };
  }
  const before = protectedTokens(src);
  const after = protectedTokens(out);
  const added = [...after].filter((t) => !before.has(t));
  if (added.length) return { ok: false, reason: `the translation contains indicators that are not in the original (${added.slice(0, 3).join(", ")})` };
  const missing = [...before].filter((t) => !after.has(t));
  if (missing.length > Math.floor(before.size * 0.1)) {
    return { ok: false, reason: `the translation dropped ${missing.length} of ${before.size} indicators or identifiers (${missing.slice(0, 3).join(", ")})` };
  }
  const words = out.split(/\s+/).filter(Boolean).length;
  if (words >= 40 && !detectLanguage(out).english) return { ok: false, reason: "the output is not in English" };
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Translating a report
// ---------------------------------------------------------------------------

/** One model call: returns the model's text for (prompt, system instruction). */
export type ChunkTranslator = (prompt: string, system: string) => Promise<{ success: boolean; text: string; error?: string }>;

export type DocumentTranslation =
  | { ok: true; title: string; text: string; translatedChars: number; totalChars: number; partial: boolean; calls: number }
  | { ok: false; reason: string; calls: number };

/**
 * Translates a report chunk by chunk, in order, checking each chunk (checkTranslation). Any failed
 * call or check fails the whole translation: a report is stored in English only when every part of
 * it was translated faithfully. Past the size budget, the rest of the original is appended unchanged
 * under a marker, so indicator appendices at the end of long reports are still extracted.
 */
export async function translateDocument(
  input: { title: string; text: string; lang: string },
  call: ChunkTranslator,
  options: { stopReason?: () => string | null } = {},
): Promise<DocumentTranslation> {
  const split = splitForTranslation(input.text);
  if (!split.chunks.length) return { ok: false, reason: "no text to translate", calls: 0 };
  const parts: string[] = [];
  let title = input.title;
  let calls = 0;
  for (let i = 0; i < split.chunks.length; i++) {
    const chunk = split.chunks[i];
    const where = split.chunks.length > 1 ? `part ${i + 1} of ${split.chunks.length}: ` : "";
    const withTitle = i === 0 && input.title.trim() ? input.title.replace(/\s+/g, " ").trim() : undefined;
    const stop = options.stopReason?.();
    if (stop) return { ok: false, reason: `${where}${stop}`, calls };
    calls += 1;
    const res = await call(translationPrompt(chunk, input.lang, i + 1, split.chunks.length, withTitle), TRANSLATION_SYSTEM_PROMPT).catch((err: unknown) => ({
      success: false,
      text: "",
      error: err instanceof Error ? err.message : String(err),
    }));
    if (!res.success) return { ok: false, reason: `${where}${(res.error || "the model did not answer").slice(0, 200)}`, calls };
    let body = cleanTranslationOutput(res.text);
    const check = checkTranslation(withTitle ? `# ${withTitle}\n\n${chunk}` : chunk, body);
    if (!check.ok) return { ok: false, reason: `${where}${check.reason}`, calls };
    if (withTitle) ({ title, body } = takeTranslatedTitle(body, input.title));
    parts.push(body);
  }
  let text = parts.join("\n\n");
  if (split.partial) {
    const rest = input.text.trim().slice(split.translatedChars).trim();
    text += `\n\n[Translated the first ${split.translatedChars.toLocaleString("en-US")} of ${split.totalChars.toLocaleString("en-US")} characters. The rest follows in the original ${languageName(input.lang)}.]\n\n${rest}`;
  }
  return { ok: true, title, text, translatedChars: split.translatedChars, totalChars: split.totalChars, partial: split.partial, calls };
}
