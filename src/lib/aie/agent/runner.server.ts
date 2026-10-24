/**
 * One analyst turn: the AIE Analyst answers with the console's tools.
 *
 *   1. A factual question first searches the library (most answers then need one model call).
 *   2. The model answers, or asks for tools ({"tool_calls":[…]}); read tools run in parallel and
 *      their results come back as numbered evidence; action tools become proposals the analyst
 *      confirms in the chat. Up to MAX_TOOL_ROUNDS rounds.
 *   3. The reply's [S#] citations become the cited evidence shown under the answer.
 *
 * Works with every provider: REST APIs, and the AGY CLI in its sandbox (one worker per chat session).
 * SERVER ONLY.
 */
import { getActiveAIProvider, resolveProviderModels } from "../ai-manager";
import { getProviderAdapter } from "../providers";
import { chatAgentFor } from "../warm-agent-service";
import { AGY_AVAILABLE_MODELS } from "../agent-framework/types";
import { hasUncitedClaims, isConversationalTurn, isLowSignal, parseCitations, queryTerms } from "../retrieval";
import type { AgentActionRecord } from "../../mongodb/repository.server";
import {
  EvidenceBook,
  buildSystemPrompt,
  buildTurnPrompt,
  parseToolCalls,
  renderToolCatalog,
  type EvidenceItem,
  type PageContext,
  type ToolCall,
  type ToolRound,
} from "./protocol";
import { AGENT_TOOLS, findTool, isActionTool } from "./tools.server";

const MAX_TOOL_ROUNDS = 4;
const MODEL_TIMEOUT_MS = 90_000;

export type ActivityStep = { kind: "tool" | "model" | "info"; label: string; detail?: string; ms?: number; ok?: boolean; running?: boolean };

export type ActiveModelInfo = { providerId: string; providerName: string; model: string; modelLabel: string; isRest: boolean };

/** The provider and model the chat uses now, as configured in Settings / Marketplace. */
export async function activeModelInfo(): Promise<ActiveModelInfo> {
  const active = await getActiveAIProvider();
  const { restModel, agyModel } = resolveProviderModels(active, undefined);
  const model = active.isRest ? restModel : agyModel;
  const modelLabel = active.isRest ? model : AGY_AVAILABLE_MODELS.find((m) => m.id === model)?.name ?? model;
  return { providerId: active.providerId, providerName: active.providerName, model, modelLabel, isRest: active.isRest };
}

type ModelAnswer = { ok: boolean; text: string; error?: string; ms: number; tokens?: number };

async function callModel(system: string, prompt: string, sessionKey: string): Promise<ModelAnswer> {
  const t0 = Date.now();
  const active = await getActiveAIProvider();
  const { restModel, agyModel } = resolveProviderModels(active, undefined);
  const adapter = active.isRest && active.apiKey ? getProviderAdapter(active.providerId) : undefined;
  if (active.isRest && !adapter) {
    return { ok: false, text: "", error: `${active.providerName} has no API key configured`, ms: 0 };
  }
  if (adapter) {
    const res = await adapter.generate({
      prompt,
      systemInstruction: system,
      model: restModel,
      apiKey: active.apiKey,
      endpointUrl: active.endpointUrl,
      timeoutMs: MODEL_TIMEOUT_MS,
      temperature: 0.2,
      maxTokens: 4096,
    });
    return { ok: res.success && Boolean(res.text?.trim()), text: res.text ?? "", error: res.error || (res.success ? "the model returned no text" : undefined), ms: Date.now() - t0, tokens: res.tokens?.totalTokens };
  }
  const res = await chatAgentFor(sessionKey).executePrompt(`${system}\n\n${prompt}`, { model: agyModel, timeoutMs: MODEL_TIMEOUT_MS, priority: "high" });
  return { ok: res.success && Boolean(res.text?.trim()), text: res.text ?? "", error: res.error || (res.success ? "the agent returned no text" : undefined), ms: Date.now() - t0, tokens: res.tokens?.totalTokens };
}

export type AgentTurnResult = {
  success: boolean;
  reply: string;
  error?: string;
  /** Evidence the reply cites, in citation order. */
  sources: EvidenceItem[];
  uncitedClaims: boolean;
  actions: AgentActionRecord[];
  activity: ActivityStep[];
  model: ActiveModelInfo;
  latencyMs: number;
  tokens?: number;
  evidenceCount: number;
};

export async function runAgentTurn(opts: {
  question: string;
  history: Array<{ sender: "user" | "agent"; text: string }>;
  sessionKey: string;
  page?: PageContext | null;
  analyst?: string | null;
  timeZone?: string;
  now?: Date;
  onActivity?: (steps: ActivityStep[]) => void;
}): Promise<AgentTurnResult> {
  const t0 = Date.now();
  const now = opts.now ?? new Date();
  const model = await activeModelInfo();
  const book = new EvidenceBook();
  const activity: ActivityStep[] = [];
  const emit = () => opts.onActivity?.(activity.map((s) => ({ ...s })));
  const begin = (step: ActivityStep) => {
    activity.push({ ...step, running: true });
    emit();
    return activity.length - 1;
  };
  const finish = (i: number, patch: Partial<ActivityStep>) => {
    activity[i] = { ...activity[i], ...patch, running: false };
    emit();
  };

  const system = buildSystemPrompt({ now, timeZone: opts.timeZone, analyst: opts.analyst, page: opts.page, catalog: renderToolCatalog(AGENT_TOOLS) });
  const rounds: ToolRound[] = [];
  const actions: AgentActionRecord[] = [];
  let tokens = 0;

  const runCalls = async (calls: ToolCall[]): Promise<string[]> =>
    Promise.all(
      calls.map(async (call) => {
        const tool = findTool(call.name);
        if (!tool) return `Error: there is no tool named ${call.name}.`;
        const parsed = tool.schema.safeParse(call.args ?? {});
        if (!parsed.success) {
          const why = parsed.error.issues.map((i) => `${i.path.join(".") || "arguments"}: ${i.message}`).join("; ");
          activity.push({ kind: "tool", label: `${call.name}: invalid arguments`, detail: why, ok: false });
          emit();
          return `Error: invalid arguments for ${call.name}: ${why}`;
        }
        if (isActionTool(tool)) {
          const id = `A${actions.length + 1}`;
          const label = tool.describe(parsed.data);
          actions.push({ id, tool: tool.name, args: parsed.data as AgentActionRecord["args"], label, status: "pending" });
          activity.push({ kind: "tool", label: `Proposed: ${label}`, detail: JSON.stringify(parsed.data), ok: true });
          emit();
          return `Proposed to the analyst as action ${id} ("${label}"). It has NOT run; the analyst decides with the button under your answer.`;
        }
        const i = begin({ kind: "tool", label: toolRunningLabel(call), detail: JSON.stringify(parsed.data) });
        const s0 = Date.now();
        try {
          const out = await tool.run(parsed.data, { book, now });
          finish(i, { label: out.summary, ms: Date.now() - s0, ok: true });
          return out.text.length > 9000 ? `${out.text.slice(0, 9000)}\n…(truncated)` : out.text;
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          finish(i, { label: `${call.name} failed`, detail: msg, ms: Date.now() - s0, ok: false });
          return `Error: ${call.name} failed: ${msg.slice(0, 300)}`;
        }
      }),
    );

  // 1. Factual questions start from a library search (short follow-ups borrow the previous question).
  if (!isConversationalTurn(opts.question)) {
    let query = opts.question;
    if (queryTerms(query).filter((t) => !isLowSignal(t)).length < 2) {
      const lastUser = [...opts.history].reverse().find((h) => h.sender === "user");
      if (lastUser) query = `${opts.question}\n${lastUser.text}`.slice(0, 500);
    }
    const calls: ToolCall[] = [{ name: "search_library", args: { query: query.slice(0, 500), limit: 6 } }];
    rounds.push({ calls, results: await runCalls(calls) });
  }

  // 2. Model rounds.
  let reply = "";
  let failure: string | undefined;
  for (let round = 0; round <= MAX_TOOL_ROUNDS; round++) {
    const finalRound = round === MAX_TOOL_ROUNDS;
    const prompt = buildTurnPrompt({ question: opts.question, history: opts.history, rounds, finalRound });
    const i = begin({ kind: "model", label: round === 0 && rounds.length === 0 ? "Thinking" : "Reading the results", detail: `${model.providerName} · ${model.modelLabel}` });
    const ans = await callModel(system, prompt, opts.sessionKey);
    tokens += ans.tokens ?? 0;
    finish(i, { ms: ans.ms, ok: ans.ok, detail: `${model.providerName} · ${model.modelLabel} · ${prompt.length.toLocaleString("en-US")} chars in${ans.ok ? ` · ${ans.text.length.toLocaleString("en-US")} out` : ""}` });
    if (!ans.ok) {
      failure = ans.error ?? "the AI provider did not answer";
      break;
    }
    const calls = finalRound ? null : parseToolCalls(ans.text);
    if (!calls) {
      reply = ans.text.trim();
      break;
    }
    rounds.push({ calls, results: await runCalls(calls) });
  }

  if (failure || !reply) {
    const why = failure ?? "the model did not produce an answer";
    return {
      success: false,
      reply: `I could not answer: ${why}. Retry, or check the AI provider in the Marketplace.`,
      error: why,
      sources: [],
      uncitedClaims: false,
      actions,
      activity,
      model,
      latencyMs: Date.now() - t0,
      tokens: tokens || undefined,
      evidenceCount: book.ids().length,
    };
  }

  // 3. Cited evidence.
  const cited = parseCitations(reply, book.ids()).used;
  const sources = cited.map((id) => book.get(id)).filter((e): e is EvidenceItem => Boolean(e));
  return {
    success: true,
    reply,
    sources,
    uncitedClaims: book.ids().length > 0 && sources.length > 0 ? hasUncitedClaims(reply) : false,
    actions,
    activity,
    model,
    latencyMs: Date.now() - t0,
    tokens: tokens || undefined,
    evidenceCount: book.ids().length,
  };
}

function toolRunningLabel(call: ToolCall): string {
  const a = call.args as Record<string, unknown>;
  const q = typeof a.query === "string" ? ` “${a.query.slice(0, 50)}”` : "";
  switch (call.name) {
    case "search_library":
      return `Searching the library for${q || " passages"}`;
    case "list_reports":
      return `Listing reports${q}${a.since ? ` since ${String(a.since)}` : ""}`;
    case "get_report":
      return `Reading report ${String(a.id ?? "")}`;
    case "find_indicator":
      return `Looking up ${String(a.value ?? "")}`;
    case "list_actors":
      return "Listing threat actors";
    case "get_actor":
      return `Reading actor ${String(a.id ?? "")}`;
    case "get_technique":
      return `Reading ${String(a.id ?? "")}`;
    case "library_overview":
      return "Reading the library overview";
    case "crawler_status":
      return "Checking the crawler";
    case "list_advisories":
      return "Listing advisories";
    case "get_advisory":
      return `Reading advisory ${String(a.id ?? "")}`;
    case "plan_purple_path":
      return `Planning a purple path for ${String(a.value ?? "")}`;
    default:
      return call.name;
  }
}
