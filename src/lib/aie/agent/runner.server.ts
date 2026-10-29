/**
 * One analyst turn: the AIE Analyst answers with the console's tools.
 *
 *   1. A first step runs before the model (firstStepCalls): reports named by id are read, a factual
 *      question searches the library; greetings and console questions start without a search.
 *   2. The model answers, or asks for tools ({"tool_calls":[…]}); read tools run in parallel and
 *      their results come back as numbered evidence; action tools become proposals the analyst
 *      confirms in the chat. Up to MAX_TOOL_ROUNDS rounds.
 *   3. The reply's [S#] citations become the cited evidence shown under the answer.
 *
 * A model call that times out or answers nothing is asked once more (a fresh worker for the AGY
 * CLI). The analyst can stop a turn (AbortSignal: queued or running model calls are cancelled). A
 * failed or stopped turn returns a checkpoint of its finished tool rounds, so Retry continues from
 * there instead of starting over.
 *
 * Works with every provider: REST APIs, and the AGY CLI in its sandbox (one worker per chat session).
 * SERVER ONLY.
 */
import { getActiveAIProvider, resolveProviderModels } from "../ai-manager";
import { getProviderAdapter } from "../providers";
import { chatAgentFor } from "../warm-agent-service";
import { AGY_AVAILABLE_MODELS } from "../agent-framework/types";
import { hasUncitedClaims, parseCitations } from "../retrieval";
import type { AgentActionRecord } from "../../mongodb/repository.server";
import {
  EvidenceBook,
  buildSystemPrompt,
  buildTurnPrompt,
  firstStepCalls,
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
/** A whole turn, tools and retries included. Past it the model is asked to answer with what it has. */
const TURN_BUDGET_MS = 5 * 60_000;
/** Tool results kept in a checkpoint, per result (a resumed turn re-reads them as evidence). */
const CHECKPOINT_RESULT_CHARS = 6000;

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

type ModelAnswer = { ok: boolean; text: string; error?: string; ms: number; tokens?: number; cancelled?: boolean };

async function callModel(system: string, prompt: string, sessionKey: string, signal?: AbortSignal): Promise<ModelAnswer> {
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
      signal,
    });
    return {
      ok: res.success && Boolean(res.text?.trim()),
      text: res.text ?? "",
      error: res.error || (res.success ? "the model returned no text" : undefined),
      ms: Date.now() - t0,
      tokens: res.tokens?.totalTokens,
      cancelled: Boolean(signal?.aborted),
    };
  }
  const res = await chatAgentFor(sessionKey).executePrompt(`${system}\n\n${prompt}`, { model: agyModel, timeoutMs: MODEL_TIMEOUT_MS, priority: "high", signal });
  return {
    ok: res.success && Boolean(res.text?.trim()),
    text: res.text ?? "",
    error: res.error || (res.success ? "the agent returned no text" : undefined),
    ms: Date.now() - t0,
    tokens: res.tokens?.totalTokens,
    cancelled: Boolean(res.cancelled || signal?.aborted),
  };
}

/** Failures that asking again cannot fix (configuration, credentials, quota). */
const NOT_RETRYABLE = /api key|quota|unauthori[sz]ed|forbidden|\b40[13]\b|invalid|not configured|not signed in|sign in|subscription|billing/i;

/** The finished tool rounds of a turn, so a retry continues from them. */
export type TurnCheckpoint = { rounds: ToolRound[]; evidence: EvidenceItem[] };

export type AgentTurnResult = {
  success: boolean;
  /** The analyst stopped the turn. */
  stopped?: boolean;
  reply: string;
  error?: string;
  /** Set on a failed or stopped turn that finished at least one tool round. */
  checkpoint?: TurnCheckpoint;
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
  /** Aborted when the analyst stops the turn. */
  signal?: AbortSignal;
  /** Continue a failed or stopped turn from its checkpoint (no first step, its tool rounds reused). */
  resume?: TurnCheckpoint | null;
}): Promise<AgentTurnResult> {
  const signal = opts.signal;
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

  const checkpoint = (): TurnCheckpoint | undefined =>
    rounds.length
      ? {
          rounds: rounds.map((r) => ({ calls: r.calls, results: r.results.map((x) => (x.length > CHECKPOINT_RESULT_CHARS ? `${x.slice(0, CHECKPOINT_RESULT_CHARS)}\n…(truncated)` : x)) })),
          evidence: book.all(),
        }
      : undefined;
  const stoppedResult = (): AgentTurnResult => ({
    success: false,
    stopped: true,
    reply: "Stopped.",
    error: "stopped by the analyst",
    checkpoint: checkpoint(),
    sources: [],
    uncitedClaims: false,
    actions,
    activity,
    model,
    latencyMs: Date.now() - t0,
    tokens: tokens || undefined,
    evidenceCount: book.ids().length,
  });

  // 1. First step, or the checkpoint of the turn being continued (its evidence keeps its ids).
  if (opts.resume?.rounds?.length) {
    for (const { id: _id, ...e } of opts.resume.evidence ?? []) book.add(e);
    rounds.push(...opts.resume.rounds);
    activity.push({ kind: "info", label: `Continuing from ${opts.resume.rounds.length} finished step${opts.resume.rounds.length === 1 ? "" : "s"}`, ok: true });
    emit();
  } else {
    const calls = firstStepCalls(opts.question, opts.history);
    if (calls.length) rounds.push({ calls, results: await runCalls(calls) });
  }
  if (signal?.aborted) return stoppedResult();

  // 2. Model rounds.
  let reply = "";
  let failure: string | undefined;
  for (let round = 0; round <= MAX_TOOL_ROUNDS; round++) {
    const overBudget = Date.now() - t0 > TURN_BUDGET_MS - MODEL_TIMEOUT_MS;
    const finalRound = round === MAX_TOOL_ROUNDS || overBudget;
    const prompt = buildTurnPrompt({ question: opts.question, history: opts.history, rounds, finalRound });
    const detail = `${model.providerName} · ${model.modelLabel}`;
    let i = begin({ kind: "model", label: round === 0 && rounds.length === 0 ? "Thinking" : "Reading the results", detail });
    let ans = await callModel(system, prompt, opts.sessionKey, signal);
    tokens += ans.tokens ?? 0;
    if (ans.cancelled || signal?.aborted) {
      finish(i, { ms: ans.ms, ok: false, label: "Stopped" });
      return stoppedResult();
    }
    // One more try for a timeout or an empty answer: these are usually transient.
    if (!ans.ok && !NOT_RETRYABLE.test(ans.error ?? "") && Date.now() - t0 < TURN_BUDGET_MS - MODEL_TIMEOUT_MS / 2) {
      finish(i, { ms: ans.ms, ok: false, detail: `${detail} · ${ans.error ?? "no answer"}` });
      i = begin({ kind: "model", label: "No answer yet, asking again", detail });
      ans = await callModel(system, `${prompt}\n\nReply now: either the tool_calls JSON object or your answer as plain text.`, opts.sessionKey, signal);
      tokens += ans.tokens ?? 0;
      if (ans.cancelled || signal?.aborted) {
        finish(i, { ms: ans.ms, ok: false, label: "Stopped" });
        return stoppedResult();
      }
    }
    finish(i, { ms: ans.ms, ok: ans.ok, detail: `${detail} · ${prompt.length.toLocaleString("en-US")} chars in${ans.ok ? ` · ${ans.text.length.toLocaleString("en-US")} out` : ` · ${ans.error ?? "no answer"}`}` });
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
    if (signal?.aborted) return stoppedResult();
  }

  if (failure || !reply) {
    const why = failure ?? "the model did not produce an answer";
    return {
      success: false,
      reply: `I could not answer: ${why}.${rounds.length ? " Retry continues from the finished steps." : " Retry, or check the AI provider in the Marketplace."}`,
      error: why,
      checkpoint: checkpoint(),
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
    case "entity_context":
      return `Correlating ${String(a.ref ?? "")} across the library`;
    case "find_connection":
      return `Tracing how ${String(a.from ?? "")} connects to ${String(a.to ?? "")}`;
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
