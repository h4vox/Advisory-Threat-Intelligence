/**
 * AIE Analyst chat: send a message (the agent answers with the console's tools), live activity,
 * named sessions (list, open, rename, delete), retry, and the analyst's decision on proposed actions.
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
import { activeModelInfo, runAgentTurn, type ActivityStep } from "./agent/runner.server";
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
} from "../mongodb/repository.server";

// ---------------------------------------------------------------------------
// Live activity (polled by the chat while a turn runs)
// ---------------------------------------------------------------------------

type Progress = { userId: string; steps: ActivityStep[]; done: boolean; at: number };
const progress = new Map<string, Progress>();

function setProgress(requestId: string, userId: string, steps: ActivityStep[], done = false) {
  progress.set(requestId, { userId, steps, done, at: Date.now() });
  if (progress.size > 200) {
    const cutoff = Date.now() - 10 * 60_000;
    for (const [k, v] of progress) if (v.at < cutoff) progress.delete(k);
  }
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

export const getAgentProgress = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ requestId: z.string().min(8).max(80) }))
  .handler(async ({ data, context }) => {
    const p = progress.get(data.requestId);
    if (!p || p.userId !== context.userId) return { steps: [] as ActivityStep[], done: false };
    return { steps: p.steps, done: p.done };
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
      /** Re-ask the question of this (failed or unwanted) agent message, replacing it. */
      retryOf: z.string().max(100).optional(),
    }),
  )
  .handler(async ({ data, context }) => {
    const userId = context.userId;
    const sessionId = data.sessionId || newSessionId();
    let question = data.message.trim();
    let userMessageId: string | null = null;

    // Retry: the agent message is replaced; its question is asked again, not stored twice.
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
      await mongoDeleteChatMessage(userId, data.retryOf);
    }

    let history: Array<{ sender: "user" | "agent"; text: string }> = [];
    try {
      const prior = await mongoGetChatSessionMessages(sessionId, userId, { limit: 16 });
      history = prior.filter((m) => m.id !== userMessageId && !m.isError).map((m) => ({ sender: m.sender, text: m.text }));
    } catch {
      /* history is best-effort */
    }

    const now = new Date().toISOString();
    if (!userMessageId) {
      userMessageId = newMessageId("user");
      await mongoSaveChatMessage({ id: userMessageId, sessionId, userId, sender: "user", text: question, timestamp: now });
    }
    const title = sessionTitleFrom(question);
    const session = await mongoUpsertChatSession(userId, sessionId, title !== NEW_SESSION_TITLE ? { title } : {});

    setProgress(data.requestId, userId, []);
    const result = await runAgentTurn({
      question,
      history,
      sessionKey: `${userId}:${sessionId}`,
      page: await describePage(data.page?.path),
      analyst: context.identity.username ?? context.userEmail ?? null,
      timeZone: data.timeZone,
      onActivity: (steps) => setProgress(data.requestId, userId, steps),
    });
    setProgress(data.requestId, userId, result.activity, true);

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
      isError: !result.success,
      replyTo: userMessageId,
      timestamp: new Date().toISOString(),
    };
    await mongoSaveChatMessage(agentMessage);
    logger.agent("CHAT", `session ${sessionId}: ${result.success ? "answered" : "failed"} in ${result.latencyMs} ms`, {
      provider: result.model.providerName,
      model: result.model.model,
      tools: result.activity.filter((a) => a.kind === "tool").map((a) => a.label).join(" | ").slice(0, 400),
      cited: sources.map((s) => s.id).join(","),
      actions: result.actions.map((a) => a.tool).join(","),
      error: result.error ?? "",
    });

    return {
      sessionId,
      title: session?.title ?? title,
      userMessageId,
      message: agentMessage,
      tokens: result.tokens,
    };
  });

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
    return {
      sessionId: data.sessionId,
      title: session?.title && session.title !== NEW_SESSION_TITLE ? session.title : sessionTitleFrom(firstQuestion),
      messages,
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
