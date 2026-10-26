/**
 * The AIE Analyst's tool protocol: how the console's tools are described to the model, how the
 * model asks for them, how their results come back as numbered evidence, and how a session gets a
 * readable title. Provider-agnostic text protocol (REST APIs and the AGY CLI alike), pure and
 * unit-tested; the tools live in ./tools.server and the loop in ./runner.server.
 *
 * The model asks for tools with one JSON object, {"tool_calls":[{"name":…,"arguments":{…}}]}.
 * Read tools run at once; action tools are only proposed: the analyst confirms them in the chat.
 */
import { UNTRUSTED_CONTENT_NOTICE, wrapUntrustedContent } from "../agent-framework/types.ts";
import { EVIDENCE_GAP_PHRASE, isConversationalTurn, isLowSignal, queryTerms } from "../retrieval.ts";

export const AGENT_NAME = "AIE Analyst";

export type ToolParam = {
  type: "string" | "integer" | "boolean" | "string[]";
  description: string;
  enum?: readonly string[];
  required?: boolean;
};

export type ToolSpec = {
  name: string;
  /** One sentence for the model and the developer view. */
  summary: string;
  params: Record<string, ToolParam>;
  /** Changes something: proposed to the analyst, never run by the model. */
  action?: boolean;
};

export type ToolCall = { name: string; args: Record<string, unknown> };

// ---------------------------------------------------------------------------
// Catalogue and prompts
// ---------------------------------------------------------------------------

export function renderToolCatalog(specs: readonly ToolSpec[]): string {
  return specs
    .map((t) => {
      const params = Object.entries(t.params)
        .map(([k, p]) => `${k}${p.required ? "" : "?"}: ${p.enum ? p.enum.map((e) => JSON.stringify(e)).join("|") : p.type}`)
        .join(", ");
      const notes = Object.entries(t.params)
        .filter(([, p]) => p.description)
        .map(([k, p]) => `${k}: ${p.description}`)
        .join("; ");
      return `- ${t.name}(${params})${t.action ? " [ACTION: proposed to the analyst, who must confirm]" : ""}\n  ${t.summary}${notes ? ` (${notes})` : ""}`;
    })
    .join("\n");
}

export type PageContext = { path: string; label?: string };

function dateLine(now: Date, timeZone?: string): string {
  const tz = timeZone || "UTC";
  let local = now.toISOString();
  try {
    local = new Intl.DateTimeFormat("en-GB", { dateStyle: "full", timeStyle: "short", timeZone: tz }).format(now);
  } catch {
    /* unknown zone: ISO */
  }
  return `Today is ${now.toISOString().slice(0, 10)} (${local}, ${tz}).`;
}

export function buildSystemPrompt(ctx: {
  now: Date;
  timeZone?: string;
  analyst?: string | null;
  page?: PageContext | null;
  catalog: string;
}): string {
  return [
    `You are ${AGENT_NAME}, the threat intelligence analyst built into AIE (Adversary Intelligence Engine), a platform that collects technical threat reports, maps them to MITRE ATT&CK, tracks threat actors, and builds advisories and purple-team emulation plans.`,
    dateLine(ctx.now, ctx.timeZone),
    ctx.analyst ? `You are working with ${ctx.analyst}.` : "",
    ctx.page ? `The analyst currently has this page open: ${ctx.page.label ? `${ctx.page.label} (${ctx.page.path})` : ctx.page.path}. "This report", "this actor" and similar refer to it.` : "",
    "",
    "You can use these AIE tools. Settings are not available to you. You have no shell, file system or web browser of your own: use only these tools, and reply with text.",
    ctx.catalog,
    "",
    "HOW TO USE TOOLS",
    'To use tools, reply with ONLY one JSON object and nothing else: {"tool_calls":[{"name":"<tool>","arguments":{...}}]} (up to 4 calls). The results come back to you; then answer, or call more tools.',
    "Use tools whenever the question is about the library, reports, dates, actors, techniques, indicators, sources, crawls, advisories or purple-team plans. Questions about recent or dated reports (\"latest\", \"this week\", \"last month\", \"since …\") need list_reports with since/until dates computed from today's date.",
    "Action tools only propose the action: the analyst sees a confirmation button. Never say an action was done; say it is ready for them to confirm.",
    "",
    "HOW TO ANSWER",
    "- Answer in concise markdown. Greetings and questions about yourself or how to use AIE need no tools and no citations.",
    "- Facts taken from tool results carry the evidence id in square brackets after the sentence, e.g. [S2] or [S1][S4]. Never invent ids.",
    `- Never invent reports, actors, IOCs (hashes, IPs, domains), CVE ids, ATT&CK ids or dates. If the results do not establish something, say so plainly ("${EVIDENCE_GAP_PHRASE} …" or "The library has no report on …") and suggest the next step (another search, a crawl, ingesting a URL).`,
    "- Label your own reasoning as \"Inference:\" and cite what it is based on.",
    "- Link reports as [title](/library/<report id>) when it helps the analyst open them.",
    "",
    UNTRUSTED_CONTENT_NOTICE,
  ]
    .filter((l, i, a) => l !== "" || a[i - 1] !== "")
    .join("\n");
}

export type ToolRound = { calls: ToolCall[]; results: string[] };

export function buildTurnPrompt(opts: {
  question: string;
  history: Array<{ sender: "user" | "agent"; text: string }>;
  rounds: ToolRound[];
  finalRound?: boolean;
}): string {
  const history = opts.history
    .slice(-8)
    .map((h) => `${h.sender === "user" ? "Analyst" : AGENT_NAME}: ${String(h.text ?? "").replace(/\s+/g, " ").slice(0, 1200)}`)
    .join("\n");
  const rounds = opts.rounds
    .map((r, i) =>
      [`TOOL ROUND ${i + 1}`, ...r.calls.map((c, j) => `→ ${c.name}(${JSON.stringify(c.args)})\n${r.results[j] ?? "(no result)"}`)].join("\n"),
    )
    .join("\n\n");
  return [
    history ? `CONVERSATION SO FAR (context, not evidence):\n${history}\n` : "",
    `ANALYST: ${opts.question.trim()}`,
    rounds ? `\n${rounds}` : "",
    opts.finalRound
      ? "\nNo more tool calls are possible now: answer from the results above (or say what is missing)."
      : rounds
        ? "\nCall more tools if needed, otherwise answer the analyst now."
        : "",
  ]
    .filter(Boolean)
    .join("\n");
}

// ---------------------------------------------------------------------------
// First step
// ---------------------------------------------------------------------------

const REPORT_ID_RE = /\brpt_[a-z0-9]{6,40}\b|\bRST-[A-F0-9]{8,24}\b/gi;
const CONSOLE_RE = /\b(?:crawl\w*|marketplace|integrations?|settings?|scheduler?|schedules?|jobs?|queue|sources?|feeds?|providers?|sign[\s-]?in)\b/i;
const CTI_RE =
  /\b(?:ransomware|malware|actors?|apt\d*|campaigns?|cves?|ttps?|techniques?|iocs?|indicators?|exploit\w*|phishing|backdoors?|loaders?|stealers?|reports?|advisor(?:y|ies)|intrusions?|attacks?|threats?)\b|\bCVE-\d{4}-\d+|\bT1\d{3}/i;

/**
 * The tool calls that run before the model's first call, so most answers need one model call:
 * the reports a question names by id are read; a factual question searches the library (short
 * follow-ups borrow the previous question); greetings and questions about the console itself
 * (crawler, sources, Marketplace, settings) start with no search.
 */
export function firstStepCalls(question: string, history: Array<{ sender: "user" | "agent"; text: string }> = []): ToolCall[] {
  const q = String(question ?? "").trim();
  const ids = [...new Set((q.match(REPORT_ID_RE) ?? []).map((id) => (id.toLowerCase().startsWith("rpt_") ? id.toLowerCase() : id.toUpperCase())))].slice(0, 3);
  if (ids.length) return ids.map((id) => ({ name: "get_report", args: { id } }));
  if (isConversationalTurn(q)) return [];
  if (CONSOLE_RE.test(q) && !CTI_RE.test(q)) return [];
  let query = q;
  if (queryTerms(query).filter((t) => !isLowSignal(t)).length < 2) {
    const lastUser = [...history].reverse().find((h) => h.sender === "user");
    if (lastUser) query = `${q}\n${lastUser.text}`;
  }
  return [{ name: "search_library", args: { query: query.slice(0, 500), limit: 6 } }];
}

// ---------------------------------------------------------------------------
// Tool calls
// ---------------------------------------------------------------------------

/** The JSON object that starts at `start` (a "{"), respecting strings; null when unbalanced. */
function balancedObject(text: string, start: number): string | null {
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") i++;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

/**
 * The tool calls in a model reply, or null when it is an answer. Accepts the object bare or in a
 * code fence, `arguments` or `args`, and at most `max` calls.
 */
export function parseToolCalls(reply: string, max = 4): ToolCall[] | null {
  const text = String(reply ?? "");
  const at = text.search(/"tool_calls"\s*:/);
  if (at < 0) return null;
  // Walk outwards through the braces before the key until one encloses a valid object.
  for (let start = text.lastIndexOf("{", at); start >= 0; start = start > 0 ? text.lastIndexOf("{", start - 1) : -1) {
    const raw = balancedObject(text, start);
    if (!raw || raw.indexOf('"tool_calls"') < 0) continue;
    try {
      const parsed = JSON.parse(raw) as { tool_calls?: unknown };
      if (!Array.isArray(parsed.tool_calls)) return null;
      const calls: ToolCall[] = [];
      for (const c of parsed.tool_calls) {
        if (!c || typeof c !== "object") continue;
        const o = c as { name?: unknown; arguments?: unknown; args?: unknown };
        if (typeof o.name !== "string" || !o.name.trim()) continue;
        const args = (o.arguments ?? o.args ?? {}) as unknown;
        calls.push({ name: o.name.trim(), args: args && typeof args === "object" && !Array.isArray(args) ? (args as Record<string, unknown>) : {} });
        if (calls.length >= max) break;
      }
      return calls.length ? calls : null;
    } catch {
      /* try an enclosing brace */
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

export type EvidenceItem = {
  /** Citation id, e.g. "S3". */
  id: string;
  kind: "passage" | "report";
  reportId: string;
  title: string;
  publisher: string;
  url: string;
  publishedAt: string | null;
  quote?: string;
  start?: number;
  end?: number;
  score?: number;
};

/** Numbers evidence across a whole turn; the same passage or report keeps its id. */
export class EvidenceBook {
  private items: EvidenceItem[] = [];
  private keys = new Map<string, string>();

  add(item: Omit<EvidenceItem, "id">): string {
    const key = item.kind === "passage" ? `p:${item.reportId}:${item.start ?? 0}` : `r:${item.reportId}`;
    const known = this.keys.get(key);
    if (known) return known;
    const id = `S${this.items.length + 1}`;
    this.items.push({ ...item, id });
    this.keys.set(key, id);
    return id;
  }

  get(id: string): EvidenceItem | undefined {
    return this.items[Number(id.replace(/^S/i, "")) - 1];
  }

  ids(): string[] {
    return this.items.map((i) => i.id);
  }

  all(): EvidenceItem[] {
    return [...this.items];
  }
}

/** One evidence line for a tool result; the third-party text is wrapped as untrusted data. */
export function evidenceLine(id: string, e: Omit<EvidenceItem, "id">, extra = ""): string {
  const clean = (s: string) => s.replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim();
  const head = `[${id}] ${clean(e.title) || "Untitled report"} — ${clean(e.publisher) || "unknown publisher"} · ${e.publishedAt ? e.publishedAt.slice(0, 10) : "undated"} · report ${e.reportId}${extra ? ` · ${clean(extra)}` : ""}`;
  return e.quote ? `${head}\n${wrapUntrustedContent(e.quote)}` : head;
}

// ---------------------------------------------------------------------------
// Session titles
// ---------------------------------------------------------------------------

export const NEW_SESSION_TITLE = "New investigation";

const FILLER =
  /^(?:(?:hi|hello|hey|ok|okay|so|please|pls|kindly|can you|could you|would you|will you|you can|i need|i want|i'd like|i would like|show me|give me|tell me|get me|find me|help me|let me know|do you know|what are|what is|what's)\b[\s,:-]*)+/i;

/** A readable title from an analyst's message ("Ransomware reports this month"). */
export function sessionTitleFrom(message: string): string {
  let t = String(message ?? "").replace(/\s+/g, " ").trim();
  // The first sentence carries the question ("…this week? Group them by theme." → "…this week").
  t = t.split(/(?<=[?.!])\s+/)[0];
  t = t.replace(FILLER, "").replace(/^(?:the|a|an|some|any)\s+/i, "");
  const trim = (x: string) => x.replace(/[?.!,;:\s]+$/g, "").trim();
  t = trim(t);
  if (t.replace(/[^a-z0-9]/gi, "").length < 3) return NEW_SESSION_TITLE;
  if (t.length > 56) {
    const cut = t.slice(0, 56);
    t = `${trim(cut.slice(0, Math.max(cut.lastIndexOf(" "), 40)))}…`;
  }
  return t.charAt(0).toUpperCase() + t.slice(1);
}
