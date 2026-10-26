/**
 * AIE Analyst chat: send a message (the agent answers with the console's tools), live activity,
 * stop, named sessions (list, open, rename, delete), retry, and the analyst's decision on proposed
 * actions.
 *
 * A turn runs on the server, not inside the request that started it: sendAgentMessage returns at
 * once and the chat polls getAgentProgress for the steps and, at the end, the saved answer. Closing
 * the chat, changing page or reloading does not lose the answer (an open session reattaches to its
 * running turn), and a long turn is never cut off by a proxy's request timeout. On serverless hosts
 * (no long-lived process) the turn runs within the request as before.
 *
 * Sessions belong to the signed-in analyst: every read and write filters on their user id.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { ForbiddenError, analystMiddleware } from "./access";
import { formatReportId } from "./ids";
import { logger } from "./logger";
import { getReport } from "./server";
import { getAdvisory } from "./server-advisories";
import { agentWorkerStatus } from "./warm-agent-service";
import { NEW_SESSION_TITLE, sessionTitleFrom, type PageContext } from "./agent/protocol";
import { activeModelInfo, runAgentTurn, type ActivityStep, type TurnCheckpoint } from "./agent/runner.server";
import { findTool, isActionTool } from "./agent/tools.server";
import {
  mongoDeleteChatMessage,
  mongoDeleteChatSession,
  mongoGetAppSettings,
  mongoGetChatMessage,
  mongoGetChatSession,
  mongoGetChatSessionMessages,
  mongoListChatSessionsDetailed,
  mongoSaveChatMessage,
  mongoSetChatAction,
  mongoUpsertChatSession,
  type AgentActionRecord,
  type AgentChatMessageRecord,
  type AgentChatMessageView,
} from "../mongodb/repository.server";

// ---------------------------------------------------------------------------
// Running turns (polled by the chat; stopped by the analyst)
// ---------------------------------------------------------------------------

/** A message as the browser sees it: the checkpoint stays on the server. */
export type PublicChatMessage = AgentChatMessageView;

type Turn = {
  requestId: string;
  userId: string;
  sessionId: string;
  userMessageId: string;
  startedAt: number;
  steps: ActivityStep[];
  done: boolean;
  /** Last change, for clean-up. */
  at: number;
  controller: AbortController;
  /** The saved answer, once done. */
  message?: PublicChatMessage;
};

const turns = new Map<string, Turn>();
/** Finished turns stay pollable this long (a chat that was closed picks its answer up later). */
const FINISHED_TURN_TTL_MS = 15 * 60_000;
/** Serverless hosts may freeze the process once a response is sent: turns run within the request there. */
const SYNC_TURNS = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY);

function pruneTurns() {
  const cutoff = Date.now() - FINISHED_TURN_TTL_MS;
  for (const [k, t] of turns) if (t.done && t.at < cutoff) turns.delete(k);
}

function liveTurnFor(userId: string, sessionId: string): Turn | undefined {
  for (const t of turns.values()) if (!t.done && t.userId === userId && t.sessionId === sessionId) return t;
  return undefined;
}

function publicMessage({ checkpoint: _checkpoint, ...m }: AgentChatMessageRecord): PublicChatMessage {
  return m;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Identity = { method: string; role?: string; username?: string | null };

function canUseDeveloperMode(identity: Identity): boolean {
  if (identity.method === "password") return identity.role === "admin";
  return identity.method === "dev" && process.env.NODE_ENV !== "production";
}

async function developerMode(identity: Identity): Promise<boolean> {
  if (!canUseDeveloperMode(identity)) return false;
  try {
    return Boolean((await mongoGetAppSettings()).debuggerMode);
  } catch {
    return false;
  }
}

const PAGE_NAMES: Array<[RegExp, string]> = [
  [/^\/$/, "Overview dashboard"],
  [/^\/library\/?$/, "Library"],
  [/^\/search/, "Search"],
  [/^\/actors\/?$/, "Threat actors"],
  [/^\/matrix/, "ATT&CK matrix"],
  [/^\/purple/, "Purple paths"],
  [/^\/advisories\/?$/, "Advisories"],
  [/^\/sources/, "Sources"],
  [/^\/ingest/, "Ingest (crawler)"],
  [/^\/marketplace/, "Marketplace"],
  [/^\/settings/, "Settings"],
];

/** What the analyst is looking at, in words the agent can use ("report “…” (RST-…)"). */
async function describePage(path: string | undefined): Promise<PageContext | null> {
  if (!path || !path.startsWith("/")) return null;
  const clean = path.split(/[?#]/)[0].slice(0, 200);
  try {
    const report = clean.match(/^\/library\/([\w-]+)/);
    if (report) {
      const r = await getReport({ data: { id: report[1] } });
      return { path: clean, label: r ? `report “${r.title}” (${formatReportId(r.id)}, id ${r.id})` : `report ${report[1]}` };
    }
    const actor = clean.match(/^\/actors\/([\w.-]+)/);
    if (actor) return { path: clean, label: `threat actor ${decodeURIComponent(actor[1])}` };
    const adv = clean.match(/^\/advisories\/([\w-]+)/);
    if (adv) {
      const a = await getAdvisory({ data: { id: adv[1] } });
      return { path: clean, label: a ? `advisory ${a.record.number} (id ${a.record.id})` : `advisory ${adv[1]}` };
    }
  } catch {
    /* context is best-effort */
  }
  const name = PAGE_NAMES.find(([re]) => re.test(clean))?.[1];
  return { path: clean, label: name ?? undefined };
}

const newSessionId = () => `ses_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
const newMessageId = (who: "user" | "agent") => `${who}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

// ---------------------------------------------------------------------------
// Server functions
// ---------------------------------------------------------------------------

/** Provider and model the chat uses (from Settings / Marketplace), and whether developer details show. */
export const getAgentInfo = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async ({ context }) => {
    const model = await activeModelInfo();
    const developer = await developerMode(context.identity);
    return { ...model, developer, canUseDeveloperMode: canUseDeveloperMode(context.identity), workers: developer ? agentWorkerStatus() : null };
  });

/** Steps of a running turn and, once it is done, its saved answer. `known: false` after a restart. */
export const getAgentProgress = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ requestId: z.string().min(8).max(80) }))
  .handler(async ({ data, context }) => {
    const t = turns.get(data.requestId);
    if (!t || t.userId !== context.userId) return { known: false, steps: [] as ActivityStep[], done: false, message: null as PublicChatMessage | null };
    return { known: true, steps: t.steps, done: t.done, message: t.done ? (t.message ?? null) : null };
  });

/** Stops a running turn: queued or running model calls are cancelled, the turn is saved as stopped. */
export const stopAgentTurn = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ requestId: z.string().min(8).max(80) }))
  .handler(async ({ data, context }) => {
    const t = turns.get(data.requestId);
    if (!t || t.userId !== context.userId) return { ok: false as const, reason: "This answer is no longer running." };
    if (!t.done) {
      t.controller.abort();
      logger.agent("CHAT", `session ${t.sessionId}: stopped by the analyst after ${Math.round((Date.now() - t.startedAt) / 1000)}s`);
    }
    return { ok: true as const };
  });

export const sendAgentMessage = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(
    z.object({
      message: z.string().trim().min(1).max(4000),
      sessionId: z.string().min(1).max(100).optional(),
      requestId: z.string().min(8).max(80),
      page: z.object({ path: z.string().max(300) }).optional(),
      timeZone: z.string().max(64).optional(),
      /** Re-ask the question of this (failed, stopped or unwanted) agent message, replacing it. */
      retryOf: z.string().max(100).optional(),
      /** Ask this user message again (it was never answered, e.g. the server restarted mid-turn). */
      askAgainOf: z.string().max(100).optional(),
    }),
  )
  .handler(async ({ data, context }) => {
    const userId = context.userId;
    const sessionId = data.sessionId || newSessionId();
    if (turns.has(data.requestId)) throw new ForbiddenError("This request was already sent.");
    if (liveTurnFor(userId, sessionId)) {
      throw new Error("An answer is still being prepared in this investigation. Wait for it, or stop it first");
    }
    // Reserved before any await, so a second tab cannot start a parallel turn in the same session.
    const turn: Turn = {
      requestId: data.requestId,
      userId,
      sessionId,
      userMessageId: "",
      startedAt: Date.now(),
      steps: [],
      done: false,
      at: Date.now(),
      controller: new AbortController(),
    };
    pruneTurns();
    turns.set(data.requestId, turn);
    try {
      return await startTurn(turn, data, context);
    } catch (err) {
      turns.delete(data.requestId);
      throw err;
    }
  });

async function startTurn(
  turn: Turn,
  data: { message: string; requestId: string; page?: { path: string }; timeZone?: string; retryOf?: string; askAgainOf?: string },
  context: { userId: string; userEmail: string | null; identity: { username?: string | null } },
) {
  const { userId, sessionId } = turn;
  let question = data.message.trim();
  let userMessageId: string | null = null;
  let resume: TurnCheckpoint | null = null;

  // Retry: the agent message is replaced; its question is asked again, not stored twice. A failed
  // or stopped turn continues from its finished tool rounds.
  if (data.retryOf) {
    const old = await mongoGetChatMessage(userId, data.retryOf);
    if (!old || old.sessionId !== sessionId || old.sender !== "agent") throw new ForbiddenError("That message cannot be retried.");
    let askedId = old.replyTo;
    if (!askedId) {
      // Answers saved before replyTo existed: the question is the user message just before it.
      const all = await mongoGetChatSessionMessages(sessionId, userId, { limit: 200 });
      const at = all.findIndex((m) => m.id === old.id);
      askedId = all.slice(0, at < 0 ? all.length : at).reverse().find((m) => m.sender === "user")?.id;
    }
    if (askedId) {
      const asked = await mongoGetChatMessage(userId, askedId);
      if (asked?.text) {
        question = asked.text;
        userMessageId = askedId;
      }
    }
    if ((old.isError || old.stopped) && old.checkpoint?.rounds?.length) resume = old.checkpoint as TurnCheckpoint;
    await mongoDeleteChatMessage(userId, data.retryOf);
  } else if (data.askAgainOf) {
    const asked = await mongoGetChatMessage(userId, data.askAgainOf);
    if (!asked || asked.sessionId !== sessionId || asked.sender !== "user") throw new ForbiddenError("That question cannot be asked again.");
    question = asked.text;
    userMessageId = asked.id;
  }

  let history: Array<{ sender: "user" | "agent"; text: string }> = [];
  try {
    const prior = await mongoGetChatSessionMessages(sessionId, userId, { limit: 16 });
    history = prior.filter((m) => m.id !== userMessageId && !m.isError && !m.stopped).map((m) => ({ sender: m.sender, text: m.text }));
  } catch {
    /* history is best-effort */
  }

  if (!userMessageId) {
    userMessageId = newMessageId("user");
    await mongoSaveChatMessage({ id: userMessageId, sessionId, userId, sender: "user", text: question, timestamp: new Date().toISOString() });
  }
  const title = sessionTitleFrom(question);
  const session = await mongoUpsertChatSession(userId, sessionId, title !== NEW_SESSION_TITLE ? { title } : {});

  turn.userMessageId = userMessageId;
  turn.startedAt = Date.now();
  const work = runTurn(turn, {
    question,
    history,
    resume,
    page: await describePage(data.page?.path),
    analyst: context.identity.username ?? context.userEmail ?? null,
    timeZone: data.timeZone,
  });
  if (SYNC_TURNS) await work;
  else void work;

  return {
    sessionId,
    title: session?.title ?? title,
    userMessageId,
    requestId: data.requestId,
    /** Set when the turn already finished (serverless hosts); otherwise poll getAgentProgress. */
    message: turn.done ? (turn.message ?? null) : null,
  };
}

/** Runs one turn to the end and saves its answer (or the error / stop) on the session. Never throws. */
async function runTurn(
  turn: Turn,
  ctx: {
    question: string;
    history: Array<{ sender: "user" | "agent"; text: string }>;
    resume: TurnCheckpoint | null;
    page: PageContext | null;
    analyst: string | null;
    timeZone?: string;
  },
): Promise<void> {
  const { userId, sessionId } = turn;
  try {
    const result = await runAgentTurn({
      question: ctx.question,
      history: ctx.history,
      sessionKey: `${userId}:${sessionId}`,
      page: ctx.page,
      analyst: ctx.analyst,
      timeZone: ctx.timeZone,
      signal: turn.controller.signal,
      resume: ctx.resume,
      onActivity: (steps) => {
        turn.steps = steps;
        turn.at = Date.now();
      },
    });
    turn.steps = result.activity;
    const sources = result.sources.map((s) => ({
      ...s,
      formattedId: formatReportId(s.reportId),
      quote: s.quote ?? "",
      start: s.start ?? 0,
      end: s.end ?? 0,
      score: s.score ?? 0,
    }));
    const agentMessage: AgentChatMessageRecord = {
      id: newMessageId("agent"),
      sessionId,
      userId,
      sender: "agent",
      text: result.reply,
      model: result.model.model,
      modelLabel: result.model.modelLabel,
      provider: result.model.providerName,
      latencyMs: result.latencyMs,
      sources,
      uncitedClaims: result.uncitedClaims,
      retrievedCount: result.evidenceCount,
      activity: result.activity.map(({ running: _running, ...s }) => s),
      actions: result.actions,
      isError: !result.success && !result.stopped,
      stopped: result.stopped || undefined,
      checkpoint: result.checkpoint,
      replyTo: turn.userMessageId,
      timestamp: new Date().toISOString(),
    };
    await mongoSaveChatMessage(agentMessage);
    turn.message = publicMessage(agentMessage);
    logger.agent("CHAT", `session ${sessionId}: ${result.success ? "answered" : result.stopped ? "stopped" : "failed"} in ${result.latencyMs} ms`, {
      provider: result.model.providerName,
      model: result.model.model,
      tools: result.activity.filter((a) => a.kind === "tool").map((a) => a.label).join(" | ").slice(0, 400),
      cited: sources.map((s) => s.id).join(","),
      actions: result.actions.map((a) => a.tool).join(","),
      resumed: ctx.resume ? ctx.resume.rounds.length : 0,
      error: result.error ?? "",
    });
  } catch (err) {
    // Unexpected failure (database, bug): the session still gets an answer the analyst can retry.
    const why = err instanceof Error ? err.message : String(err);
    logger.error("chat", `session ${sessionId}: turn failed`, err);
    const failed: AgentChatMessageRecord = {
      id: newMessageId("agent"),
      sessionId,
      userId,
      sender: "agent",
      text: `I could not answer: ${why.slice(0, 300)}.`,
      isError: true,
      replyTo: turn.userMessageId,
      activity: turn.steps.map(({ running: _running, ...s }) => s),
      timestamp: new Date().toISOString(),
    };
    try {
      await mongoSaveChatMessage(failed);
    } catch {
      /* the chat still shows it from the turn */
    }
    turn.message = publicMessage(failed);
  } finally {
    turn.done = true;
    turn.at = Date.now();
  }
}

export const listAgentSessions = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async ({ context }) => ({ sessions: await mongoListChatSessionsDetailed(context.userId, sessionTitleFrom) }));

export const getAgentSession = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ sessionId: z.string().min(1).max(100) }))
  .handler(async ({ data, context }) => {
    const [session, messages] = await Promise.all([
      mongoGetChatSession(context.userId, data.sessionId),
      mongoGetChatSessionMessages(data.sessionId, context.userId, { limit: 200 }),
    ]);
    const firstQuestion = messages.find((m) => m.sender === "user")?.text ?? "";
    const live = liveTurnFor(context.userId, data.sessionId);
    return {
      sessionId: data.sessionId,
      title: session?.title && session.title !== NEW_SESSION_TITLE ? session.title : sessionTitleFrom(firstQuestion),
      messages,
      /** A turn still running for this session (the chat reattaches to it). */
      pending: live ? { requestId: live.requestId, userMessageId: live.userMessageId, startedAt: new Date(live.startedAt).toISOString() } : null,
    };
  });

export const renameAgentSession = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ sessionId: z.string().min(1).max(100), title: z.string().trim().min(1).max(80) }))
  .handler(async ({ data, context }) => {
    const s = await mongoUpsertChatSession(context.userId, data.sessionId, { title: data.title, rename: true });
    return { title: s?.title ?? data.title };
  });

export const deleteAgentSession = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ sessionId: z.string().min(1).max(100) }))
  .handler(async ({ data, context }) => {
    await mongoDeleteChatSession(context.userId, data.sessionId);
    return { ok: true as const };
  });

/** The analyst runs or dismisses an action the agent proposed. Arguments are validated again. */
export const decideAgentAction = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ messageId: z.string().min(1).max(100), actionId: z.string().min(1).max(10), decision: z.enum(["run", "dismiss"]) }))
  .handler(async ({ data, context }): Promise<{ action: AgentActionRecord }> => {
    const msg = await mongoGetChatMessage(context.userId, data.messageId);
    const actions = msg?.actions ?? [];
    const idx = actions.findIndex((a) => a.id === data.actionId);
    if (!msg || idx < 0) throw new ForbiddenError("That action does not exist.");
    const action = actions[idx];
    if (action.status !== "pending") return { action };
    const by = context.identity.username ?? context.userEmail ?? "an analyst";
    // The current state, when another request decided this action first.
    const current = async () => ({ action: (await mongoGetChatMessage(context.userId, data.messageId))?.actions?.find((a) => a.id === action.id) ?? action });
    const decide = async (next: AgentActionRecord) => ((await mongoSetChatAction(context.userId, data.messageId, next, true)) ? { action: next } : current());
    const save = async (next: AgentActionRecord) => {
      await mongoSetChatAction(context.userId, data.messageId, next);
      return { action: next };
    };
    if (data.decision === "dismiss") return decide({ ...action, status: "dismissed", decidedAt: new Date().toISOString(), decidedBy: by });

    const tool = findTool(action.tool);
    if (!tool || !isActionTool(tool)) return decide({ ...action, status: "failed", result: "This action is no longer available." });
    const parsed = tool.schema.safeParse(action.args);
    if (!parsed.success) return decide({ ...action, status: "failed", result: "The action's arguments are not valid any more." });
    // Claim it: exactly one request moves it from pending to running and runs it.
    if (!(await mongoSetChatAction(context.userId, data.messageId, { ...action, status: "running" }, true))) return current();
    try {
      const out = await tool.execute(parsed.data);
      logger.agent("ACTION", `${by} ran ${action.tool}: ${out.ok ? "ok" : "failed"}`, { args: JSON.stringify(action.args).slice(0, 300), result: out.message });
      return save({ ...action, status: out.ok ? "done" : "failed", result: out.message, link: out.link, decidedAt: new Date().toISOString(), decidedBy: by });
    } catch (err) {
      const msgText = err instanceof Error ? err.message : String(err);
      return save({ ...action, status: "failed", result: msgText.slice(0, 300), decidedAt: new Date().toISOString(), decidedBy: by });
    }
  });
