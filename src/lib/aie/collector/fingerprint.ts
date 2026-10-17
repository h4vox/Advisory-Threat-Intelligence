/**
 * Multi-hash document fingerprints for de-duplication (AIE Web Extraction spec §18).
 *
 *  - contentSha256        exact extracted text (same as ReportRecord.textHash)
 *  - normalizedTextHash   text after case/whitespace/punctuation and volatile-boilerplate normalisation,
 *                         so "Published 2 hours ago" vs "3 hours ago" or a cookie line do not split copies
 *  - titlePublisherHash   normalised title + publisher (catches the same post fetched from two URLs)
 *  - simhash              64-bit SimHash over the normalised text; Hamming distance <= 3 marks a
 *                         syndicated or mirrored copy (news re-posts of a vendor report)
 *
 * Pure and dependency-free apart from the SHA-256 helper, so it runs in unit tests.
 */
import { sha256Hex } from "../extract.ts";

export const SIMHASH_NEAR_DUPLICATE_DISTANCE = 3;

export type DocumentFingerprints = {
  contentSha256: string;
  normalizedTextHash: string;
  /** null when the title is too short or generic to identify a document. */
  titlePublisherHash: string | null;
  /** 16 hex chars. */
  simhash: string;
  /** Normalised token count the SimHash was computed over. */
  tokens: number;
};

const VOLATILE_LINE_PATTERNS: RegExp[] = [
  /\b(?:published|posted|updated|last updated|modified)\b[^\n]{0,40}\b(?:ago|today|yesterday)\b/gi,
  /\b\d{1,3}\s*(?:min(?:ute)?s?|hours?|hrs?|days?)\s+(?:ago|read)\b/gi,
  /\b(?:\d[\d,.]*\s*)?(?:views?|shares?|comments?|likes?)\b(?=\s*$)/gim,
  /\bwe use cookies\b[^\n]*/gi,
  /\b(?:share this|share on|follow us on|subscribe to our newsletter)\b[^\n]*/gi,
  /\b(?:this (?:article|post|story) (?:originally )?appeared (?:first )?on|originally published (?:on|at|by))\b[^\n]*/gi,
];

/** Lower-case, accent-free, punctuation-free text with volatile boilerplate removed. */
export function normalizeForFingerprint(text: string): string {
  let t = (text || "").normalize("NFKD").replace(/[̀-ͯ]/g, "");
  for (const re of VOLATILE_LINE_PATTERNS) t = t.replace(re, " ");
  // Rendering markers (list numbering, bullets, headings, table rules) are not content, so the plain and
  // structured renderings of the same page normalise identically.
  t = t.replace(/^[ \t]*(?:\d{1,3}[.)]|[-*•]|#{1,6})(?:[ \t]+|$)/gm, " ");
  return t
    .toLowerCase()
    .replace(/\[(\.|dot)\]/g, ".") // defanged dots count as dots
    .replace(/[^a-z0-9.]+/g, " ")
    .replace(/(?<![a-z0-9])\.|\.(?![a-z0-9])/g, " ") // keep dots only inside tokens (IPs, domains, versions)
    .replace(/\s+/g, " ")
    .trim();
}

const PUBLISHER_SUFFIX_RE = /\s*[|–—:-]\s*[^|–—:-]{2,60}$/;

/** Title without a trailing " | Publisher" branding segment, normalised. */
export function normalizeTitle(title: string): string {
  let t = (title || "").trim();
  // Strip at most two trailing branding segments ("Title | Blog | Vendor").
  for (let i = 0; i < 2; i++) {
    const m = t.match(PUBLISHER_SUFFIX_RE);
    if (!m || t.length - m[0].length < 16) break;
    t = t.slice(0, t.length - m[0].length);
  }
  return normalizeForFingerprint(t);
}

export function normalizePublisher(publisher: string): string {
  return normalizeForFingerprint(publisher || "")
    .replace(/\b(?:inc|llc|ltd|corp|corporation|blog|security|threat intelligence|research|labs?)\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** sha256(title|publisher) when the title has >= 4 meaningful words; else null. */
export function titlePublisherHash(title: string, publisher: string): string | null {
  const t = normalizeTitle(title);
  const words = t.split(" ").filter((w) => w.length > 1);
  if (words.length < 4) return null;
  if (/^(?:untitled report|threat intelligence report|pasted report|home|blog)$/.test(t)) return null;
  return sha256Hex(`${t}|${normalizePublisher(publisher)}`);
}

// ---------------------------------------------------------------------------
// 64-bit SimHash. Features are word unigrams (weight = term frequency) and word
// 3-gram shingles (weight 1) over the normalised text, hashed with two
// independent 32-bit FNV-1a variants (number arithmetic, no BigInt in the hot loop).
// Term-frequency weighting keeps the fingerprint stable when a re-post adds an
// intro or a footer; shingles keep different articles on the same topic apart.
// ---------------------------------------------------------------------------

const STOP = new Set(
  "the and for are was were with that this from have has had not but you your our their they them its his her she him what when which who will would can could into than then there these those been being also such over more most other some any all about after before under between while where how may might must shall should each very just only both onto upon per via".split(
    " ",
  ),
);

function fnv32(str: string, seed: number): number {
  let h = seed >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  // final avalanche (murmur3 fmix32)
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}

function addFeature(v: Float64Array, feature: string, weight: number) {
  const hi = fnv32(feature, 0x811c9dc5);
  const lo = fnv32(feature, 0x9747b28c);
  for (let bit = 0; bit < 32; bit++) {
    v[bit] += (lo >>> bit) & 1 ? weight : -weight;
    v[bit + 32] += (hi >>> bit) & 1 ? weight : -weight;
  }
}

export function tokensForSimhash(normalized: string): string[] {
  return normalized.split(" ").filter((w) => w.length >= 3 && !STOP.has(w));
}

/** 64-bit SimHash (16 hex chars) of already-normalised text. */
export function simhash64(normalized: string): string {
  const tokens = tokensForSimhash(normalized);
  if (tokens.length === 0) return "0000000000000000";
  const v = new Float64Array(64);
  const tf = new Map<string, number>();
  for (const t of tokens) tf.set(t, (tf.get(t) ?? 0) + 1);
  for (const [term, count] of tf) addFeature(v, `u:${term}`, count);
  for (let i = 0; i + 2 < tokens.length; i++) addFeature(v, `s:${tokens[i]} ${tokens[i + 1]} ${tokens[i + 2]}`, 1);
  let lo = 0;
  let hi = 0;
  for (let bit = 0; bit < 32; bit++) {
    if (v[bit] > 0) lo |= 1 << bit;
    if (v[bit + 32] > 0) hi |= 1 << bit;
  }
  return (hi >>> 0).toString(16).padStart(8, "0") + (lo >>> 0).toString(16).padStart(8, "0");
}

function popcount32(x: number): number {
  x = x - ((x >>> 1) & 0x55555555);
  x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
  x = (x + (x >>> 4)) & 0x0f0f0f0f;
  return Math.imul(x, 0x01010101) >>> 24;
}

/** Hamming distance between two 16-hex-char SimHashes (64 when either is malformed). */
export function hammingDistance64(a: string, b: string): number {
  if (!/^[0-9a-f]{16}$/i.test(a) || !/^[0-9a-f]{16}$/i.test(b)) return 64;
  const ah = parseInt(a.slice(0, 8), 16);
  const al = parseInt(a.slice(8), 16);
  const bh = parseInt(b.slice(0, 8), 16);
  const bl = parseInt(b.slice(8), 16);
  return popcount32((ah ^ bh) >>> 0) + popcount32((al ^ bl) >>> 0);
}

export function computeFingerprints(input: { text: string; title: string; publisher: string }): DocumentFingerprints {
  const normalized = normalizeForFingerprint(input.text);
  return {
    contentSha256: sha256Hex(input.text),
    normalizedTextHash: sha256Hex(normalized),
    titlePublisherHash: titlePublisherHash(input.title, input.publisher),
    simhash: simhash64(normalized),
    tokens: tokensForSimhash(normalized).length,
  };
}
