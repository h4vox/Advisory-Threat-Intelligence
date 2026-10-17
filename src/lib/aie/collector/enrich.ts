/**
 * Ingest-time enrichment (AIE Web Extraction spec §21, §27):
 *  - canonical ATT&CK references (groups G-IDs, software S-IDs, campaigns C-IDs) found in the title and
 *    body through the bundled knowledge index, with the matched alias and first offset as evidence;
 *  - "Download the full report" PDF links on a blog post, so the crawler can attach the PDF text.
 *
 * SERVER ONLY (imports the ATT&CK knowledge index).
 */
import { findEntitiesInText } from "../attack-knowledge.ts";
import { sectionAt, type TextSection } from "../extract.ts";
import type { AttackEntityRef, ExtractedEntities } from "../types.ts";

/** Body scan cap: the knowledge regexes are linear, but very long PDFs are bounded. */
const MAX_SCAN_CHARS = 400_000;

export function enrichAttackEntities(title: string, text: string, sections?: TextSection[]): AttackEntityRef[] {
  const body = (text || "").slice(0, MAX_SCAN_CHARS);
  const inBody = findEntitiesInText(body, { limit: 60 });
  const inTitle = findEntitiesInText(title || "", { limit: 10 });
  const refs = new Map<string, AttackEntityRef>();
  for (const h of inBody) {
    if (h.kind === "technique") continue;
    refs.set(`${h.kind}:${h.id}`, {
      kind: h.kind,
      id: h.id,
      name: h.name,
      matched: h.matched,
      firstOffset: h.firstIndex,
      count: h.count,
      ...(sections?.length ? { section: sectionAt(sections, h.firstIndex) } : {}),
    });
  }
  for (const h of inTitle) {
    if (h.kind === "technique") continue;
    const key = `${h.kind}:${h.id}`;
    const prev = refs.get(key);
    if (prev) prev.inTitle = true;
    else refs.set(key, { kind: h.kind, id: h.id, name: h.name, matched: h.matched, firstOffset: -1, count: 0, inTitle: true });
  }
  const kindRank = { group: 0, campaign: 1, software: 2 } as const;
  return [...refs.values()].sort((a, b) => kindRank[a.kind] - kindRank[b.kind] || Number(b.inTitle ?? false) - Number(a.inTitle ?? false) || b.count - a.count);
}

const EMPTY_ENTITIES: ExtractedEntities = {
  threatActors: [],
  malwareFamilies: [],
  cves: [],
  tactics: [],
  techniques: [],
  procedures: [],
  detectionRules: [],
  mitigations: [],
  campaign: null,
};

/** Adds attackRefs to extracted entities without touching the heuristic / LLM fields. */
export function withAttackRefs(entities: ExtractedEntities | undefined | null, refs: AttackEntityRef[]): ExtractedEntities {
  return { ...(entities ?? EMPTY_ENTITIES), attackRefs: refs };
}

// ---------------------------------------------------------------------------
// Full-report PDF links
// ---------------------------------------------------------------------------

export type ReportPdfLink = { url: string; anchor: string; score: number };

const POSITIVE_ANCHOR =
  /\b(?:full report|download (?:the |our )?(?:full |complete |technical )?(?:report|whitepaper|white paper|paper|pdf|analysis|advisory)|read the (?:full |complete )?(?:report|paper|analysis)|technical (?:report|analysis|paper)|white ?paper|joint (?:cybersecurity )?advisory|advisory \(pdf\)|report \(pdf\)|pdf version|\bpdf\b)/i;
const NEGATIVE_PDF = /\b(?:datasheet|data-sheet|brochure|solution[- ]brief|product[- ]brief|pricing|e-?book|infographic|one[- ]pager|press[- ]kit|terms|privacy|cookie|careers?|annual[- ]report|10-k|investor)\b/i;
const POSITIVE_FILE = /(?:report|whitepaper|white-paper|analysis|advisory|threat|apt|campaign|research|aa\d{2}-\d{3}|cve-\d{4})/i;

/**
 * PDF links on a page that look like the full version of the report ("Download the full report",
 * "Read the technical analysis (PDF)"), best first. Marketing PDFs (datasheets, brochures, e-books)
 * are excluded.
 */
export function findFullReportPdfLinks(html: string, pageUrl: string, limit = 2): ReportPdfLink[] {
  if (!html) return [];
  let base: URL;
  try {
    base = new URL(pageUrl);
  } catch {
    return [];
  }
  const found = new Map<string, ReportPdfLink>();
  for (const m of html.matchAll(/<a\b([^>]*?)\bhref\s*=\s*(["'])(.*?)\2([^>]*)>([\s\S]{0,400}?)<\/a>/gi)) {
    const href = m[3].trim();
    const anchor = m[5].replace(/<[^>]+>/g, " ").replace(/&[a-z#0-9]+;/gi, " ").replace(/\s+/g, " ").trim();
    const attrs = `${m[1]} ${m[4]}`;
    let u: URL;
    try {
      u = new URL(href, base);
    } catch {
      continue;
    }
    if (!/^https?:$/.test(u.protocol)) continue;
    const isPdf = /\.pdf(?:$|[?#])/i.test(u.pathname + u.search) || /\bdownload\b/i.test(attrs) || /type\s*=\s*["']application\/pdf/i.test(attrs);
    if (!isPdf) continue;
    if (NEGATIVE_PDF.test(anchor) || NEGATIVE_PDF.test(u.pathname)) continue;
    let score = 0;
    if (/\.pdf(?:$|[?#])/i.test(u.pathname)) score += 1;
    if (POSITIVE_ANCHOR.test(anchor)) score += 2;
    if (POSITIVE_FILE.test(u.pathname.split("/").pop() ?? "")) score += 1;
    if (u.hostname.replace(/^www\./, "") === base.hostname.replace(/^www\./, "")) score += 0.5;
    if (score < 2) continue;
    u.hash = "";
    const key = u.toString();
    const prev = found.get(key);
    if (!prev || prev.score < score) found.set(key, { url: key, anchor: anchor.slice(0, 160), score });
  }
  return [...found.values()].sort((a, b) => b.score - a.score).slice(0, limit);
}

/** Text appended to a report when its full-report PDF is attached. */
export function appendPdfText(articleText: string, pdf: { url: string; text: string; pages?: number }): string {
  const heading = `## Full report (PDF${pdf.pages ? `, ${pdf.pages} pages` : ""})`;
  return `${articleText.trimEnd()}\n\n${heading}\n\nSource: ${pdf.url}\n\n${pdf.text.trim()}`;
}
