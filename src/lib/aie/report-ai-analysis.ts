/**
 * AI analysis of one stored report, grounded in the report itself.
 *
 * The model reads the report text and returns a summary, key findings, indicators, the attack
 * chain as a sequence of stages, an adversary profile, the publication date line and a usefulness
 * review. Nothing it says is stored on trust: every item is checked against the report text and
 * dropped when the text does not support it.
 *   - indicators: the re-fanged value must appear in the re-fanged text, and match its type
 *   - attack-chain steps: the quote must appear in the text; technique IDs must exist in ATT&CK
 *   - key findings: the quote must appear in the text
 *   - adversary profile: names, aliases, malware, tools, sectors and regions must appear in the text
 *   - summary: sentences naming a CVE, technique ID, IP, hash or domain the text lacks are removed
 *   - publication date: the quote must appear in the text and state that date
 * What was dropped is counted, so the report page can say how much the check removed.
 *
 * Pure: the caller supplies the model call and the ATT&CK lookup. Unit-tested.
 */
import { refang } from "./extract.ts";
import { findWrittenDate } from "./published-date.ts";

export const REPORT_AI_ANALYSIS_VERSION = 1;

/** Report text sent to the model; longer reports are cut here and marked as truncated. */
export const ANALYSIS_TEXT_CHARS = 24_000;

export type AiIocType = "ipv4" | "ipv6" | "domain" | "url" | "sha256" | "sha1" | "md5" | "email" | "cve" | "filename" | "registry";

export type AiIoc = { type: AiIocType; value: string; context?: string };

export type AiChainStep = {
  order: number;
  /** ATT&CK tactic, e.g. "Initial Access". */
  stage: string;
  technique?: { id: string; name: string };
  /** What happened at this stage, in the model's words. */
  summary: string;
  /** Sentence from the report that supports the step (verified). */
  quote: string;
};

export type AiFinding = { text: string; quote: string };

export type AiAdversaryProfile = {
  name: string;
  aliases: string[];
  type: "state-sponsored" | "cybercrime" | "hacktivist" | "insider" | "unknown";
  motivation: string;
  sectors: string[];
  regions: string[];
  malware: string[];
  tools: string[];
  summary: string;
};

export type AiReviewVerdict = "useful" | "not_useful" | "unsure";

export type AiReview = {
  verdict: AiReviewVerdict;
  /** 0–1. */
  confidence: number;
  reasons: string[];
};

export type ReportAiAnalysis = {
  version: number;
  summary: string;
  keyFindings: AiFinding[];
  iocs: AiIoc[];
  attackChain: AiChainStep[];
  adversary: AiAdversaryProfile | null;
  /** Publication date the report states, with the line that states it (verified). */
  publishedDate: { date: string; quote: string } | null;
  review: AiReview;
  /** Items the grounding check removed because the report text does not support them. */
  dropped: { iocs: number; steps: number; findings: number; adversaryTerms: number; summarySentences: number };
  /** Only the first ANALYSIS_TEXT_CHARS characters were analysed. */
  truncated: boolean;
  provider: string;
  model: string;
  analysedAt: string;
};

const TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Collection",
  "Command and Control", "Exfiltration", "Impact",
];
const ACTOR_TYPES: AiAdversaryProfile["type"][] = ["state-sponsored", "cybercrime", "hacktivist", "insider", "unknown"];

export type AnalysisPromptInput = {
  title: string;
  url: string;
  publisher?: string;
  publishedAt?: string | null;
  text: string;
};

export const ANALYSIS_SYSTEM = `You are a senior cyber threat intelligence analyst supporting defenders (detection engineering, threat hunting and adversary emulation planning).
You read one published threat report and describe what it says. You never add facts the report does not contain, never invent indicators, techniques, actors or dates, and never write new attack commands or tooling. When the report does not say something, leave that field empty.
Answer with one JSON object only, no prose before or after it.`;

export function buildAnalysisPrompt(input: AnalysisPromptInput, wrap: (s: string) => string, notice: string): { prompt: string; truncated: boolean } {
  const text = input.text ?? "";
  const truncated = text.length > ANALYSIS_TEXT_CHARS;
  const body = text.slice(0, ANALYSIS_TEXT_CHARS);
  const prompt = `${notice}

REPORT (title, URL, publisher and text):
${wrap(`TITLE: ${input.title}\nURL: ${input.url}\nPUBLISHER: ${input.publisher ?? "unknown"}\nTEXT:\n${body}`)}

Analyse the report and return JSON with exactly these fields:
{
  "summary": "3-5 sentences: who did what, to whom, how, and why it matters to defenders. Only facts from the report.",
  "keyFindings": [{ "text": "one finding", "quote": "exact sentence copied from the report that supports it" }],
  "iocs": [{ "type": "ipv4|ipv6|domain|url|sha256|sha1|md5|email|cve|filename|registry", "value": "exactly as written in the report (defanged forms are fine)", "context": "role stated by the report, e.g. C2 server, payload hash" }],
  "attackChain": [{ "order": 1, "stage": "ATT&CK tactic name, e.g. Initial Access", "techniqueId": "T1566.001 or empty", "summary": "what happened at this stage", "quote": "exact sentence copied from the report" }],
  "adversary": { "name": "actor or group name as written, or empty", "aliases": [], "type": "state-sponsored|cybercrime|hacktivist|insider|unknown", "motivation": "as stated, or empty", "sectors": [], "regions": [], "malware": [], "tools": [], "summary": "1-2 sentences on the adversary, or empty" },
  "publishedDate": { "date": "YYYY-MM-DD the report itself was published, or empty", "quote": "the exact line of the report that states it" },
  "review": { "verdict": "useful|not_useful|unsure", "confidence": 0.0, "reasons": ["short reasons"] }
}

Rules:
- Copy every "quote" character for character from the report text. Do not paraphrase quotes.
- List indicators only when the report itself lists them. Never guess.
- Order the attack chain as the intrusion unfolded. Use only ATT&CK tactic names for "stage".
- "review": "useful" when the report is technical threat intelligence a defender can act on (attack behaviour, intrusion details, malware analysis, indicators, detection content, vulnerability exploitation in the wild). "not_useful" only when the page is clearly not threat research (empty page, navigation or listing page, marketing, job post, event or webinar notice, generic news without technical content). When in doubt, answer "unsure". "confidence" is how sure you are, from 0 to 1.
- Use empty strings and empty arrays when the report does not say.`;
  return { prompt, truncated };
}

// ── Grounding ───────────────────────────────────────────────────────────────

/** Comparable form of text: re-fanged, lower-cased, quotes and dashes unified, whitespace collapsed. */
export function normaliseForMatch(s: string): string {
  return refang(String(s ?? ""))
    .toLowerCase()
    .replace(/[‘’‚‛′]/g, "'")
    .replace(/[“”„″]/g, '"')
    .replace(/[‐-―−]/g, "-")
    .replace(/ /g, " ")
    .replace(/[*_`]+/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

const IOC_SHAPES: Record<AiIocType, RegExp> = {
  ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?$/,
  ipv6: /^[0-9a-f:]{6,39}$/i,
  domain: /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i,
  url: /^(?:https?|ftp):\/\/[^\s"'<>]{3,}$/i,
  sha256: /^[a-f0-9]{64}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  md5: /^[a-f0-9]{32}$/i,
  email: /^[^\s@]{1,64}@[a-z0-9.-]+\.[a-z]{2,}$/i,
  cve: /^CVE-\d{4}-\d{4,7}$/i,
  filename: /^[^\\/:*?"<>|\s][^\\/:*?"<>|]{0,200}\.[a-z0-9]{1,8}$/i,
  registry: /^(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\.{3,}$/i,
};

function str(v: unknown, max = 600): string {
  return typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, max) : "";
}

function strList(v: unknown, max = 20): string[] {
  return Array.isArray(v) ? v.map((x) => str(x, 120)).filter(Boolean).slice(0, max) : [];
}

/** True when the phrase appears in the text as written (case-insensitive, whitespace-insensitive). */
function inText(normText: string, phrase: string): boolean {
  const p = normaliseForMatch(phrase);
  return p.length >= 2 && normText.includes(p);
}

/** A quote is supported when it, or its longest clause of 40+ characters, appears in the text. */
function quoteInText(normText: string, quote: string): string | null {
  const q = str(quote, 500);
  if (q.length < 12) return null;
  if (inText(normText, q.replace(/^["'“”]+|["'“”.]+$/g, ""))) return q;
  // Models sometimes join two sentences or trim words at the ends: accept a long verbatim clause.
  const clauses = q.split(/(?<=[.;:!?])\s+|\s+[-–—]\s+/).map((c) => c.replace(/^["'“”]+|["'“”.]+$/g, "")).filter((c) => c.length >= 40);
  const hit = clauses.find((c) => inText(normText, c));
  return hit ?? null;
}

const SUMMARY_ARTIFACTS = [
  /\bCVE-\d{4}-\d{4,7}\b/gi,
  /\bT\d{4}(?:\.\d{3})?\b/g,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  /\b[a-f0-9]{32,64}\b/gi,
];

/** Removes summary sentences that cite an identifier or indicator the report does not contain. */
function groundSummary(summary: string, normText: string): { text: string; removed: number } {
  const sentences = summary.split(/(?<=[.!?])\s+/).filter(Boolean);
  const kept = sentences.filter((s) => SUMMARY_ARTIFACTS.every((re) => (s.match(re) ?? []).every((m) => normText.includes(m.toLowerCase()))));
  return { text: kept.join(" ").slice(0, 1500), removed: sentences.length - kept.length };
}

export type ParseOptions = {
  /** ATT&CK technique name by ID, undefined when the ID does not exist. */
  techniqueName: (id: string) => string | undefined;
  provider: string;
  model: string;
  truncated: boolean;
  now?: Date;
};

/**
 * Parses the model's JSON and keeps only what the report text supports. Throws when the answer is
 * not a JSON object at all, so the caller reports a failed analysis instead of storing nothing.
 */
export function groundReportAnalysis(parsed: unknown, sourceText: string, opts: ParseOptions): ReportAiAnalysis {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("The AI answer was not a JSON object.");
  const o = parsed as Record<string, unknown>;
  const normText = normaliseForMatch(sourceText);
  const dropped = { iocs: 0, steps: 0, findings: 0, adversaryTerms: 0, summarySentences: 0 };

  // Indicators
  const iocs: AiIoc[] = [];
  const seen = new Set<string>();
  for (const raw of Array.isArray(o.iocs) ? o.iocs.slice(0, 300) : []) {
    const r = (raw ?? {}) as Record<string, unknown>;
    const type = str(r.type, 20).toLowerCase() as AiIocType;
    const value = refang(str(r.value, 600));
    const shape = IOC_SHAPES[type];
    const key = `${type}:${value.toLowerCase()}`;
    if (!shape || !value || seen.has(key)) {
      if (value && !seen.has(key)) dropped.iocs++;
      continue;
    }
    if (!shape.test(value) || !normText.includes(normaliseForMatch(value))) {
      dropped.iocs++;
      continue;
    }
    seen.add(key);
    const context = str(r.context, 160);
    iocs.push(context ? { type, value: type === "cve" ? value.toUpperCase() : value, context } : { type, value: type === "cve" ? value.toUpperCase() : value });
  }

  // Attack chain
  const attackChain: AiChainStep[] = [];
  const rawSteps = Array.isArray(o.attackChain) ? o.attackChain.slice(0, 40) : [];
  for (const raw of rawSteps) {
    const r = (raw ?? {}) as Record<string, unknown>;
    const stage = TACTICS.find((t) => t.toLowerCase() === str(r.stage, 60).toLowerCase());
    const quote = quoteInText(normText, str(r.quote, 500));
    const summary = str(r.summary, 400);
    if (!stage || !quote || !summary) {
      dropped.steps++;
      continue;
    }
    const id = str(r.techniqueId, 12).toUpperCase();
    const name = /^T\d{4}(?:\.\d{3})?$/.test(id) ? opts.techniqueName(id) : undefined;
    attackChain.push({ order: 0, stage, ...(name ? { technique: { id, name } } : {}), summary, quote });
  }
  // Keep the model's order (the intrusion's sequence); renumber after drops.
  attackChain.forEach((s, i) => (s.order = i + 1));

  // Key findings
  const keyFindings: AiFinding[] = [];
  for (const raw of Array.isArray(o.keyFindings) ? o.keyFindings.slice(0, 12) : []) {
    const r = (raw ?? {}) as Record<string, unknown>;
    const text = str(r.text, 300);
    const quote = quoteInText(normText, str(r.quote, 500));
    if (!text || !quote) {
      dropped.findings++;
      continue;
    }
    keyFindings.push({ text, quote });
  }

  // Adversary
  let adversary: AiAdversaryProfile | null = null;
  const a = (o.adversary ?? null) as Record<string, unknown> | null;
  if (a && typeof a === "object") {
    const grounded = (list: string[]) => {
      const keep = list.filter((x) => inText(normText, x));
      dropped.adversaryTerms += list.length - keep.length;
      return keep;
    };
    const rawName = str(a.name, 120);
    const name = rawName && inText(normText, rawName) ? rawName : "";
    if (rawName && !name) dropped.adversaryTerms++;
    const malware = grounded(strList(a.malware));
    const tools = grounded(strList(a.tools));
    const profile: AiAdversaryProfile = {
      name,
      aliases: grounded(strList(a.aliases)).filter((x) => x.toLowerCase() !== name.toLowerCase()),
      type: ACTOR_TYPES.includes(str(a.type, 30) as AiAdversaryProfile["type"]) ? (str(a.type, 30) as AiAdversaryProfile["type"]) : "unknown",
      motivation: str(a.motivation, 200),
      sectors: grounded(strList(a.sectors)),
      regions: grounded(strList(a.regions)),
      malware,
      tools,
      summary: name || malware.length ? groundSummary(str(a.summary, 500), normText).text : "",
    };
    if (profile.name || profile.malware.length || profile.tools.length || profile.sectors.length) adversary = profile;
  }

  // Publication date
  let publishedDate: ReportAiAnalysis["publishedDate"] = null;
  const pd = (o.publishedDate ?? null) as Record<string, unknown> | null;
  if (pd && typeof pd === "object") {
    const date = str(pd.date, 10);
    const quote = quoteInText(normText, str(pd.quote, 200)) ?? (str(pd.quote, 200).length >= 6 && inText(normText, str(pd.quote, 200)) ? str(pd.quote, 200) : null);
    const now = opts.now ?? new Date();
    const stated = quote ? findWrittenDate(quote) : null;
    if (/^\d{4}-\d{2}-\d{2}$/.test(date) && stated === date && Number(date.slice(0, 4)) >= 1995 && Date.parse(`${date}T00:00:00Z`) <= now.getTime() + 36 * 3600_000) {
      publishedDate = { date, quote: quote as string };
    }
  }

  // Summary
  const summaryRes = groundSummary(str(o.summary, 2000), normText);
  dropped.summarySentences = summaryRes.removed;

  // Review
  const rv = (o.review ?? {}) as Record<string, unknown>;
  const verdictRaw = str(rv.verdict, 20).toLowerCase();
  const verdict: AiReviewVerdict = verdictRaw === "useful" || verdictRaw === "not_useful" ? verdictRaw : "unsure";
  const confidence = Math.max(0, Math.min(1, Number(rv.confidence) || 0));

  return {
    version: REPORT_AI_ANALYSIS_VERSION,
    summary: summaryRes.text,
    keyFindings,
    iocs,
    attackChain,
    adversary,
    publishedDate,
    review: { verdict, confidence, reasons: strList(rv.reasons, 6) },
    dropped,
    truncated: opts.truncated,
    provider: opts.provider,
    model: opts.model,
    analysedAt: (opts.now ?? new Date()).toISOString(),
  };
}
