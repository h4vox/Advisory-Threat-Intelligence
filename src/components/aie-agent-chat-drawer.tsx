import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  AlertTriangle,
  Bot,
  Check,
  ChevronDown,
  CircleCheck,
  CircleX,
  Copy,
  ExternalLink,
  FileText,
  History,
  Maximize2,
  Minimize2,
  Pencil,
  Play,
  Plus,
  RotateCcw,
  Search,
  Send,
  Sparkles,
  Square,
  Trash2,
  Wrench,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "./ui/button";
import { MarkdownView } from "./ui/markdown-view";
import { ActivitySpinner } from "./ui/activity-spinner";
import { cn } from "@/lib/cn";
import { handoffPrompt, isEntityDrag, readDroppedEntity } from "./agent-handoff";
import {
  decideAgentAction,
  deleteAgentSession,
  getAgentInfo,
  getAgentProgress,
  getAgentSession,
  listAgentSessions,
  renameAgentSession,
  sendAgentMessage,
  stopAgentTurn,
} from "@/lib/aie/server-agent";

// ---------------------------------------------------------------------------
// Types (as stored by the server)
// ---------------------------------------------------------------------------

type Activity = { kind: "tool" | "model" | "info"; label: string; detail?: string; ms?: number; ok?: boolean; running?: boolean };
type Action = {
  id: string;
  tool: string;
  label: string;
  status: "pending" | "running" | "done" | "failed" | "dismissed";
  result?: string;
  link?: { label: string; href: string };
};
type Source = {
  id: string;
  kind?: "passage" | "report";
  reportId?: string;
  formattedId?: string;
  title: string;
  publisher: string;
  url: string;
  publishedAt?: string | null;
  quote?: string;
  snippet?: string;
};
type Message = {
  id: string;
  sender: "user" | "agent";
  text: string;
  timestamp: string;
  latencyMs?: number;
  model?: string;
  modelLabel?: string;
  provider?: string;
  sources?: Source[];
  uncitedClaims?: boolean;
  evidenceGap?: boolean;
  isError?: boolean;
  /** The analyst stopped this turn. */
  stopped?: boolean;
  replyTo?: string;
  activity?: Activity[];
  actions?: Action[];
  /** Client-only: sent, waiting for the answer. */
  pending?: boolean;
};

/** A turn running on the server that this chat follows. */
type Busy = { requestId: string; startedAt: number; userMessageId?: string; stopping?: boolean };

const SESSION_KEY = "aie_chat_session_id";
const WIDTH_KEY = "aie_chat_drawer_width";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readLocal(key: string): string | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeLocal(key: string, value: string | null) {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch {
    /* storage blocked */
  }
}

function clockTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function relativeTime(iso: string): string {
  const d = new Date(iso);
  const s = (Date.now() - d.getTime()) / 1000;
  if (Number.isNaN(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 172800) return "yesterday";
  return d.toLocaleDateString([], { day: "numeric", month: "short", year: d.getFullYear() === new Date().getFullYear() ? undefined : "numeric" });
}

function duration(ms?: number): string {
  if (!ms && ms !== 0) return "";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

function sourceDate(value?: string | null): string {
  if (!value) return "undated";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value.slice(0, 10) : d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

const newRequestId = () => `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;

/** Questions that fit the page the analyst is on; general ones elsewhere. */
function quickActions(path: string): Array<{ label: string; prompt: string }> {
  if (/^\/library\/[\w-]+/.test(path)) {
    return [
      { label: "Summarize this report", prompt: "Summarize this report: the actor, the attack chain step by step and the key techniques." },
      { label: "Indicators", prompt: "List the indicators of compromise in this report, grouped by type." },
      { label: "ATT&CK mapping", prompt: "Map this report to MITRE ATT&CK techniques, ordered by tactic." },
      { label: "Detection ideas", prompt: "What should we hunt for or detect, based on this report?" },
      { label: "Purple path", prompt: "Plan a purple-team emulation path from this report." },
    ];
  }
  if (/^\/actors\/[\w.-]+/.test(path)) {
    return [
      { label: "Profile this actor", prompt: "Profile this threat actor: who they target, how they operate and their main techniques." },
      { label: "Latest reports", prompt: "What are the latest library reports about this actor?" },
      { label: "Purple path", prompt: "Plan a purple-team emulation path for this actor." },
    ];
  }
  if (/^\/advisories\/[\w-]+/.test(path)) {
    return [
      { label: "Summarize this advisory", prompt: "Summarize this advisory and its recommended actions." },
      { label: "Scope", prompt: "Which techniques does this advisory cover, and what evidence supports each?" },
    ];
  }
  if (/^\/ingest/.test(path) || /^\/sources/.test(path)) {
    return [
      { label: "Crawler status", prompt: "What is the crawler doing, and how did the last runs go?" },
      { label: "Failing sources", prompt: "Which sources are failing and why?" },
      { label: "What came in today", prompt: "Which reports were added to the library today?" },
    ];
  }
  return [
    { label: "What's new this week", prompt: "What technical threat reports were published this week? Group them by theme." },
    { label: "Latest ransomware", prompt: "Show the latest ransomware reports in the library." },
    { label: "Active actors", prompt: "Which threat actors are most active in our library recently?" },
    { label: "Nation-state campaigns", prompt: "Summarize active nation-state campaigns in our library." },
    { label: "Look up an indicator", prompt: "Look up this indicator in the library: " },
  ];
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface AieAgentChatDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  /** A request handed over from elsewhere in the app (./agent-handoff), sent once. */
  ask?: { id: number; text: string } | null;
  onAskHandled?: () => void;
}

export function AieAgentChatDrawer({ isOpen, onClose, ask, onAskHandled }: AieAgentChatDrawerProps) {
  const queryClient = useQueryClient();
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [sessionId, setSessionId] = useState<string | null>(() => readLocal(SESSION_KEY));
  const [messages, setMessages] = useState<Message[]>([]);
  const [title, setTitle] = useState<string>("");
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState<Busy | null>(null);
  const [liveSteps, setLiveSteps] = useState<Activity[]>([]);
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [now, setNow] = useState(Date.now());
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const [width, setWidth] = useState<number>(() => {
    const saved = Number(readLocal(WIDTH_KEY));
    if (typeof window === "undefined") return 440;
    const max = Math.round(window.innerWidth * 0.6);
    return saved >= 340 && saved <= max ? saved : Math.max(400, Math.min(480, Math.round(window.innerWidth * 0.3)));
  });
  const [dragging, setDragging] = useState(false);

  const info = useQuery({ queryKey: ["agent-info"], queryFn: () => getAgentInfo(), enabled: isOpen, staleTime: 30_000, refetchInterval: (q) => (q.state.data?.developer ? 5000 : false) });
  const developer = Boolean(info.data?.developer);

  const sessions = useQuery({ queryKey: ["agent-sessions"], queryFn: () => listAgentSessions(), enabled: isOpen });
  const session = useQuery({
    queryKey: ["agent-session", sessionId],
    queryFn: () => getAgentSession({ data: { sessionId: sessionId! } }),
    enabled: isOpen && Boolean(sessionId),
  });

  // Take the server's copy only when a fetch brings new data, never over messages added since.
  const syncedAt = useRef(0);
  useEffect(() => {
    if (!session.data || session.dataUpdatedAt === syncedAt.current) return;
    syncedAt.current = session.dataUpdatedAt;
    setMessages(session.data.messages as Message[]);
    setTitle(session.data.title);
    // A turn still running on the server (the chat was closed, the page changed): follow it again.
    const p = session.data.pending;
    if (p) setBusy((b) => b ?? { requestId: p.requestId, startedAt: Date.parse(p.startedAt) || Date.now(), userMessageId: p.userMessageId });
  }, [session.data, session.dataUpdatedAt]);

  useEffect(() => {
    if (!sessionId) {
      setMessages([]);
      setTitle("");
    }
  }, [sessionId]);

  const busyRef = useRef<Busy | null>(null);
  busyRef.current = busy;

  /** The turn ended: its saved answer joins the conversation (once) and the cache follows. */
  const finishTurn = (answer: Message | null) => {
    setBusy(null);
    setLiveSteps([]);
    if (answer) {
      setMessages((prev) => {
        const next = [...prev.map((m) => (m.pending ? { ...m, pending: false } : m)).filter((m) => m.id !== answer.id), answer];
        if (sessionId) {
          queryClient.setQueryData(["agent-session", sessionId], (old: { sessionId: string; title: string } | undefined) => ({ ...(old ?? { sessionId, title }), messages: next, pending: null }));
          syncedAt.current = queryClient.getQueryState(["agent-session", sessionId])?.dataUpdatedAt ?? syncedAt.current;
        }
        return next;
      });
    } else if (sessionId) {
      void queryClient.invalidateQueries({ queryKey: ["agent-session", sessionId] });
    }
    void queryClient.invalidateQueries({ queryKey: ["agent-sessions"] });
    setTimeout(() => inputRef.current?.focus(), 50);
  };

  // Follow the running turn: its steps while it works, its answer when it is done. The turn runs on
  // the server, so this also picks up a turn started before the chat was closed or the page changed.
  const busyId = busy?.requestId;
  useEffect(() => {
    if (!busyId) return;
    let cancelled = false;
    let unknownSince = 0;
    const tick = setInterval(() => setNow(Date.now()), 500);
    const poll = async () => {
      try {
        const p = await getAgentProgress({ data: { requestId: busyId } });
        if (cancelled) return;
        if (p.known) {
          unknownSince = 0;
          if (p.done) return finishTurn((p.message as Message | null) ?? null);
          setLiveSteps(p.steps as Activity[]);
          return;
        }
        // Not known here (the server restarted, or another instance answered): the saved session decides.
        unknownSince ||= Date.now();
        if (sessionId) {
          const fresh = await getAgentSession({ data: { sessionId } });
          if (cancelled) return;
          const asked = busyRef.current?.userMessageId;
          const answer = asked ? (fresh.messages as Message[]).find((m) => m.sender === "agent" && m.replyTo === asked) : undefined;
          if (answer) return finishTurn(answer);
          if (fresh.pending && fresh.pending.requestId !== busyId) {
            setBusy({ requestId: fresh.pending.requestId, startedAt: Date.parse(fresh.pending.startedAt) || Date.now(), userMessageId: fresh.pending.userMessageId });
            return;
          }
        }
        // Lost for good: the question stays, with "Ask again" under it.
        if (Date.now() - unknownSince > 6000) finishTurn(null);
      } catch {
        /* next poll */
      }
    };
    void poll();
    const timer = setInterval(() => void poll(), 800);
    return () => {
      cancelled = true;
      clearInterval(tick);
      clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [busyId, sessionId]);


  useEffect(() => {
    if (isOpen) endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [isOpen, messages.length, liveSteps.length, busy]);

  // Drag to resize (340 px to 60% of the viewport).
  useEffect(() => {
    if (!dragging) return;
    const move = (e: MouseEvent) => setWidth(Math.max(340, Math.min(Math.round(window.innerWidth * 0.6), window.innerWidth - e.clientX)));
    const up = () => {
      setDragging(false);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.body.style.cursor = "ew-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
  }, [dragging]);
  useEffect(() => {
    if (!dragging) writeLocal(WIDTH_KEY, String(width));
  }, [width, dragging]);

  const wide = typeof window !== "undefined" && width >= Math.round(window.innerWidth * 0.5) - 10;
  const toggleWide = () => setWidth(wide ? Math.max(400, Math.min(480, Math.round(window.innerWidth * 0.3))) : Math.round(window.innerWidth * 0.55));

  const openSession = (id: string | null) => {
    setSessionId(id);
    writeLocal(SESSION_KEY, id);
    setSessionsOpen(false);
    setRenaming(false);
    setLiveSteps([]);
  };

  const send = async (text: string, opts: { retryOf?: string; askAgainOf?: string } = {}) => {
    const question = text.trim();
    if (!question || busy) return;
    const requestId = newRequestId();
    const nowIso = new Date().toISOString();
    if (opts.retryOf) {
      setMessages((prev) => prev.filter((m) => m.id !== opts.retryOf));
    } else if (!opts.askAgainOf) {
      setMessages((prev) => [...prev, { id: `local-${requestId}`, sender: "user", text: question, timestamp: nowIso, pending: true }]);
      setInput("");
    }
    setLiveSteps([]);
    setBusy({ requestId, startedAt: Date.now(), userMessageId: opts.askAgainOf });
    try {
      const res = await sendAgentMessage({
        data: {
          message: question,
          sessionId: sessionId ?? undefined,
          requestId,
          page: { path },
          timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          retryOf: opts.retryOf,
          askAgainOf: opts.askAgainOf,
        },
      });
      if (!res || typeof res.sessionId !== "string") throw new Error("the server sent no reply (the connection was cut); ask again");
      if (res.sessionId !== sessionId) {
        setSessionId(res.sessionId);
        writeLocal(SESSION_KEY, res.sessionId);
      }
      setTitle(res.title);
      setMessages((prev) => {
        const next = prev.map((m) => (m.id === `local-${requestId}` ? { ...m, id: res.userMessageId ?? m.id } : m));
        // Keep the cached session in step, so reopening it shows the same conversation.
        queryClient.setQueryData(["agent-session", res.sessionId], {
          sessionId: res.sessionId,
          title: res.title,
          messages: next,
          pending: res.message ? null : { requestId, userMessageId: res.userMessageId, startedAt: nowIso },
        });
        syncedAt.current = queryClient.getQueryState(["agent-session", res.sessionId])?.dataUpdatedAt ?? syncedAt.current;
        return next;
      });
      if (res.message) {
        // Serverless hosts answer within the request.
        finishTurn(res.message as Message);
      } else {
        setBusy((b) => (b && b.requestId === requestId ? { ...b, userMessageId: res.userMessageId } : b));
      }
      void queryClient.invalidateQueries({ queryKey: ["agent-sessions"] });
    } catch (err) {
      const why = err instanceof Error ? err.message : "the request did not reach the server";
      setBusy(null);
      setLiveSteps([]);
      setMessages((prev) => [
        ...prev.map((m) => (m.id === `local-${requestId}` ? { ...m, pending: false } : m)),
        { id: `local-err-${requestId}`, sender: "agent", text: `I could not answer: ${why}.`, timestamp: new Date().toISOString(), isError: true, replyTo: `local-${requestId}` },
      ]);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  };

  const stop = async () => {
    if (!busy || busy.stopping) return;
    setBusy({ ...busy, stopping: true });
    try {
      const res = await stopAgentTurn({ data: { requestId: busy.requestId } });
      if (!res.ok) finishTurn(null);
    } catch {
      toast.error("Could not stop the answer; try again");
      setBusy((b) => (b ? { ...b, stopping: false } : b));
    }
  };

  const retry = (m: Message) => {
    if (m.id.startsWith("local-err-")) {
      // Never reached the server: ask again as a new message.
      const asked = messages.find((x) => x.id === m.replyTo || x.id === m.replyTo?.replace("local-", ""));
      setMessages((prev) => prev.filter((x) => x.id !== m.id && x.id !== asked?.id));
      if (asked) void send(asked.text);
      return;
    }
    const asked = messages.find((x) => x.id === m.replyTo) ?? [...messages.slice(0, messages.indexOf(m))].reverse().find((x) => x.sender === "user");
    void send(asked?.text ?? "Please answer again.", { retryOf: m.id });
  };

  const copy = (text: string) => {
    void navigator.clipboard?.writeText(text).then(
      () => toast.success("Copied"),
      () => toast.error("Copy failed"),
    );
  };

  const decide = useMutation({
    mutationFn: (v: { messageId: string; actionId: string; decision: "run" | "dismiss" }) => decideAgentAction({ data: v }),
    onMutate: (v) => setMessages((prev) => prev.map((m) => (m.id === v.messageId ? { ...m, actions: m.actions?.map((a) => (a.id === v.actionId && v.decision === "run" ? { ...a, status: "running" } : a)) } : m))),
    onSuccess: (res, v) => {
      setMessages((prev) => {
        const next = prev.map((m) => (m.id === v.messageId ? { ...m, actions: m.actions?.map((a) => (a.id === v.actionId ? (res.action as Action) : a)) } : m));
        if (sessionId) {
          queryClient.setQueryData(["agent-session", sessionId], (old: { sessionId: string; title: string } | undefined) => (old ? { ...old, messages: next } : old));
          syncedAt.current = queryClient.getQueryState(["agent-session", sessionId])?.dataUpdatedAt ?? syncedAt.current;
        }
        return next;
      });
      if (res.action.status === "done") toast.success(res.action.result ?? "Done");
      if (res.action.status === "failed") toast.error(res.action.result ?? "The action failed");
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "The action failed"),
  });

  const rename = useMutation({
    mutationFn: (t: string) => renameAgentSession({ data: { sessionId: sessionId!, title: t } }),
    onSuccess: (res) => {
      setTitle(res.title);
      setRenaming(false);
      void queryClient.invalidateQueries({ queryKey: ["agent-sessions"] });
    },
  });

  const remove = useMutation({
    mutationFn: (id: string) => deleteAgentSession({ data: { sessionId: id } }),
    onSuccess: (_r, id) => {
      if (id === sessionId) openSession(null);
      void queryClient.invalidateQueries({ queryKey: ["agent-sessions"] });
      toast.success("Investigation deleted");
    },
  });

  const actionsHere = useMemo(() => quickActions(path), [path]);

  // The last question has no answer and nothing is running for it (the server restarted mid-turn).
  const last = messages[messages.length - 1];
  const unanswered =
    !busy && last?.sender === "user" && !last.pending && !last.id.startsWith("local-") && Boolean(session.data) && !session.data?.pending && !session.isFetching ? last : null;

  // A request handed over from the app: send it, or leave it in the box while a turn is running.
  const handledAsk = useRef<number | null>(null);
  useEffect(() => {
    if (!isOpen || !ask || handledAsk.current === ask.id) return;
    handledAsk.current = ask.id;
    if (busy) {
      setInput(ask.text);
      inputRef.current?.focus();
    } else void send(ask.text);
    onAskHandled?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once per hand-off
  }, [isOpen, ask]);

  const [dropActive, setDropActive] = useState(false);

  if (!isOpen) return null;

  const modelLine = info.data ? `${info.data.providerName} · ${info.data.modelLabel}` : "Connecting…";
  const elapsed = busy ? Math.max(0, Math.round((now - busy.startedAt) / 1000)) : 0;

  const body = (
    <div className="flex h-full min-h-0 flex-col bg-transparent text-fg">
      {/* Header */}
      <div className="drawer-section-header flex shrink-0 items-center justify-between gap-2 p-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="relative flex size-9 shrink-0 items-center justify-center rounded-lg bg-bg-subtle text-fg">
            <Bot className="size-[18px]" strokeWidth={1.75} />
            <span className={cn("absolute -right-0.5 -top-0.5 size-2 rounded-full ring-2 ring-bg-card", info.isError ? "bg-danger" : info.data ? "bg-sage" : "bg-subtle")} />
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-medium text-fg">AIE Analyst</h3>
            <Link to="/settings" title="The model is chosen in Settings → AI agent" className="block max-w-[260px] truncate text-[11px] text-subtle hover:text-fg">
              {modelLine}
            </Link>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button type="button" onClick={() => openSession(null)} title="New investigation" aria-label="New investigation" className={iconBtn}>
            <Plus className="size-4" />
          </button>
          <button type="button" onClick={() => setSessionsOpen((v) => !v)} title="Investigations" aria-label="Investigations" aria-expanded={sessionsOpen} className={cn(iconBtn, sessionsOpen && "bg-bg-subtle text-fg")}>
            <History className="size-4" />
          </button>
          <button type="button" onClick={toggleWide} title={wide ? "Narrower" : "Wider"} aria-label={wide ? "Narrower" : "Wider"} className={cn(iconBtn, "hidden sm:flex")}>
            {wide ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
          </button>
          <button type="button" onClick={onClose} aria-label="Close" className={iconBtn}>
            <X className="size-4" />
          </button>
        </div>
      </div>

      {/* Current investigation */}
      <div className="drawer-section-subbar flex shrink-0 items-center gap-2 px-3 py-2">
        {renaming && sessionId ? (
          <form
            className="flex min-w-0 flex-1 items-center gap-1.5"
            onSubmit={(e) => {
              e.preventDefault();
              const t = new FormData(e.currentTarget).get("title");
              if (typeof t === "string" && t.trim()) rename.mutate(t.trim());
            }}
          >
            <input
              name="title"
              defaultValue={title}
              autoFocus
              maxLength={80}
              aria-label="Investigation name"
              className="h-7 min-w-0 flex-1 rounded-md border border-border bg-bg-elevated px-2 text-xs text-fg focus:border-accent focus:outline-none"
              onKeyDown={(e) => e.key === "Escape" && setRenaming(false)}
            />
            <button type="submit" className={iconBtnSm} aria-label="Save name">
              <Check className="size-3.5" />
            </button>
          </form>
        ) : (
          <>
            <span className="min-w-0 flex-1 truncate text-xs font-medium text-fg" title={title || "New investigation"}>
              {title || "New investigation"}
            </span>
            {sessionId && (
              <button type="button" onClick={() => setRenaming(true)} className={iconBtnSm} title="Rename" aria-label="Rename investigation">
                <Pencil className="size-3" />
              </button>
            )}
          </>
        )}
      </div>

      {/* Investigations panel */}
      {sessionsOpen && (
        <SessionsPanel
          current={sessionId}
          loading={sessions.isLoading}
          rows={sessions.data?.sessions ?? []}
          onOpen={(id) => openSession(id)}
          onNew={() => openSession(null)}
          onDelete={(id) => remove.mutate(id)}
          onClose={() => setSessionsOpen(false)}
        />
      )}

      {/* Messages */}
      <div className={cn("min-h-0 flex-1 space-y-4 overflow-y-auto overflow-x-hidden p-3.5", sessionsOpen && "hidden")}>
        {messages.length === 0 && !busy && (
          <Welcome actions={actionsHere} onPick={(p) => (p.endsWith(": ") ? (setInput(p), inputRef.current?.focus()) : void send(p))} loading={session.isLoading && Boolean(sessionId)} />
        )}

        {messages.map((m) =>
          m.sender === "user" ? (
            <UserBubble key={m.id} m={m} onCopy={copy} />
          ) : (
            <AgentBubble
              key={m.id}
              m={m}
              developer={developer}
              busy={Boolean(busy)}
              onCopy={copy}
              onRetry={() => retry(m)}
              onAction={(actionId, decision) => decide.mutate({ messageId: m.id, actionId, decision })}
            />
          ),
        )}

        {busy && <LiveActivity steps={liveSteps} elapsed={elapsed} developer={developer} stopping={Boolean(busy.stopping)} />}
        {unanswered && (
          <div className="mr-auto flex w-full max-w-[96%] items-center justify-between gap-3 rounded-xl border border-dashed border-border px-3 py-2.5 text-xs text-muted">
            <span>This question has no answer: the answer was interrupted.</span>
            <button
              type="button"
              onClick={() => void send(unanswered.text, { askAgainOf: unanswered.id })}
              className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-fg hover:bg-bg-subtle"
            >
              <RotateCcw className="size-3" /> Ask again
            </button>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {/* Suggestions when the conversation has started */}
      {messages.length > 0 && !sessionsOpen && (
        <div className="no-scrollbar flex shrink-0 items-center gap-1.5 overflow-x-auto px-3 pb-1.5">
          {actionsHere.slice(0, 4).map((a) => (
            <button
              key={a.label}
              type="button"
              disabled={Boolean(busy)}
              onClick={() => (a.prompt.endsWith(": ") ? (setInput(a.prompt), inputRef.current?.focus()) : void send(a.prompt))}
              className="pill-liquid-glass shrink-0 whitespace-nowrap rounded-md border border-border bg-bg-elevated px-2 py-0.5 text-[11px] text-muted transition-colors hover:bg-bg-subtle hover:text-fg disabled:opacity-50"
            >
              {a.label}
            </button>
          ))}
        </div>
      )}

      {/* Composer */}
      <div className="drawer-section-footer shrink-0 p-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send(input);
          }}
          className="flex items-end gap-2"
        >
          <textarea
            ref={inputRef}
            value={input}
            rows={1}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void send(input);
              }
            }}
            placeholder="Ask the AIE Analyst…"
            aria-label="Message the AIE Analyst"
            className="max-h-40 min-h-9 w-full grow resize-none rounded-lg border border-border bg-bg-elevated px-3 py-2 text-sm leading-snug text-fg placeholder:text-subtle focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
          />
          {busy ? (
            <Button
              type="button"
              size="sm"
              variant="secondary"
              onClick={() => void stop()}
              disabled={Boolean(busy.stopping)}
              className="h-9 shrink-0 gap-1.5 rounded-lg px-3 text-sm font-medium"
              aria-label="Stop the answer"
              title="Stop the answer"
            >
              {busy.stopping ? <ActivitySpinner size="xs" /> : <Square className="size-3 fill-current" />}
              <span className="hidden sm:inline">{busy.stopping ? "Stopping" : "Stop"}</span>
            </Button>
          ) : (
            <Button type="submit" size="sm" variant="primary" disabled={!input.trim()} className="h-9 shrink-0 gap-1.5 rounded-lg px-3.5 text-sm font-medium" aria-label="Send">
              <Send className="size-3.5" />
            </Button>
          )}
        </form>
        <p className="mt-1.5 text-[10px] text-subtle">Answers cite library evidence as [S#]. Actions run only when you confirm them.</p>
        {developer && info.data?.workers && <WorkerStatus workers={info.data.workers} />}
      </div>
    </div>
  );

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="fixed inset-0 bg-black/40 backdrop-blur-xs" onClick={onClose} />
      <div
        style={{ width: `${width}px` }}
        className={cn("drawer-liquid-glass relative z-10 flex h-full max-w-[100vw] flex-col shadow-2xl animate-in slide-in-from-right duration-200", dropActive && "ring-2 ring-inset ring-primary")}
        onDragOver={(e) => {
          if (!isEntityDrag(e)) return;
          e.preventDefault();
          e.dataTransfer.dropEffect = "copy";
          setDropActive(true);
        }}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node)) setDropActive(false);
        }}
        onDrop={(e) => {
          setDropActive(false);
          const ent = readDroppedEntity(e);
          if (!ent) return;
          e.preventDefault();
          if (busy) setInput(handoffPrompt(ent));
          else void send(handoffPrompt(ent));
        }}
      >
        <div
          onMouseDown={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          className="group absolute -left-3 top-1/2 z-30 hidden h-28 w-6 -translate-y-1/2 cursor-ew-resize items-center justify-center sm:flex"
          title="Drag to resize"
        >
          <div className="h-14 w-1.5 rounded-full border border-border/40 bg-border/80 transition-all group-hover:w-2 group-hover:bg-accent" />
        </div>
        {body}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Parts
// ---------------------------------------------------------------------------

function Welcome({ actions, onPick, loading }: { actions: Array<{ label: string; prompt: string }>; onPick: (prompt: string) => void; loading: boolean }) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 p-2 text-xs text-muted">
        <ActivitySpinner size="xs" /> Loading the investigation…
      </div>
    );
  }
  return (
    <div className="card-liquid-glass space-y-3 rounded-xl border border-border bg-bg-card p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-fg">
        <Sparkles className="size-4 text-accent" strokeWidth={1.75} />
        How can I help with your investigation?
      </div>
      <p className="text-xs leading-relaxed text-muted">
        I work with the whole console: I search and read library reports, look up indicators, profile threat actors, map ATT&amp;CK techniques, check the crawler and sources, and
        plan purple-team paths. I can also start crawls, ingest a URL, hide reports or draft an advisory, each only after you confirm.
      </p>
      <div className="flex flex-wrap gap-1.5">
        {actions.map((a) => (
          <button
            key={a.label}
            type="button"
            onClick={() => onPick(a.prompt)}
            className="pill-liquid-glass rounded-md border border-border bg-bg-elevated px-2.5 py-1 text-xs text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
          >
            {a.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function UserBubble({ m, onCopy }: { m: Message; onCopy: (t: string) => void }) {
  return (
    <div className="group ml-auto flex w-full max-w-[92%] flex-col items-end">
      <div className="mb-1 flex items-center gap-1.5 px-1 text-[10px] text-subtle">
        <span className="font-medium text-muted">You</span>
        <span>{clockTime(m.timestamp)}</span>
        <button type="button" onClick={() => onCopy(m.text)} className={cn(iconBtnXs, "opacity-0 group-hover:opacity-100 focus:opacity-100")} title="Copy" aria-label="Copy message">
          <Copy className="size-3" />
        </button>
      </div>
      <div className={cn("max-w-full whitespace-pre-wrap break-words rounded-xl rounded-br-sm bg-accent px-3 py-2 text-xs leading-relaxed text-accent-fg", m.pending && "opacity-80")}>{m.text}</div>
    </div>
  );
}

function AgentBubble({
  m,
  developer,
  busy,
  onCopy,
  onRetry,
  onAction,
}: {
  m: Message;
  developer: boolean;
  busy: boolean;
  onCopy: (t: string) => void;
  onRetry: () => void;
  onAction: (actionId: string, decision: "run" | "dismiss") => void;
}) {
  const [sourcesOpen, setSourcesOpen] = useState(false);
  const [stepsOpen, setStepsOpen] = useState(false);
  const tools = (m.activity ?? []).filter((a) => a.kind === "tool");
  const sources = m.sources ?? [];
  return (
    <div className="mr-auto flex w-full max-w-[96%] min-w-0 flex-col items-start">
      <div className="mb-1 flex w-full items-center gap-1.5 px-1 text-[10px] text-subtle">
        <span className="shrink-0 whitespace-nowrap font-medium text-muted">AIE Analyst</span>
        <span className="shrink-0 whitespace-nowrap">{clockTime(m.timestamp)}</span>
        {m.latencyMs ? <span className="shrink-0 whitespace-nowrap tabular-nums">· {duration(m.latencyMs)}</span> : null}
        {developer && (m.modelLabel || m.model) && (
          <span className="min-w-0 truncate font-mono" title={`${m.provider ?? ""} ${m.model ?? ""}`}>
            · {m.provider ? `${m.provider} · ` : ""}
            {m.modelLabel ?? m.model}
          </span>
        )}
        <span className="ml-auto flex shrink-0 items-center gap-0.5">
          <button type="button" onClick={() => onCopy(m.text)} className={iconBtnXs} title="Copy answer" aria-label="Copy answer">
            <Copy className="size-3" />
          </button>
          <button type="button" onClick={onRetry} disabled={busy} className={iconBtnXs} title="Ask again" aria-label="Ask again">
            <RotateCcw className="size-3" />
          </button>
        </span>
      </div>

      {m.stopped ? (
        <div className="w-full rounded-xl rounded-bl-sm border border-dashed border-border p-3 text-xs leading-relaxed text-muted">
          <p>Stopped. {tools.length ? "The finished steps are kept: Continue picks up from them." : "Nothing was answered."}</p>
          <div className="mt-2 flex gap-1.5">
            <button type="button" onClick={onRetry} disabled={busy} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-fg hover:bg-bg-subtle disabled:opacity-50">
              <RotateCcw className="size-3" /> {tools.length ? "Continue" : "Ask again"}
            </button>
          </div>
        </div>
      ) : m.isError ? (
        <div className="w-full rounded-xl rounded-bl-sm border border-danger/40 bg-danger/10 p-3 text-xs leading-relaxed text-danger">
          <p className="break-words">{m.text}</p>
          <div className="mt-2 flex gap-1.5">
            <button type="button" onClick={onRetry} disabled={busy} className="inline-flex items-center gap-1 rounded-md border border-danger/40 px-2 py-1 text-[11px] font-medium text-danger hover:bg-danger/10 disabled:opacity-50">
              <RotateCcw className="size-3" /> Retry
            </button>
            <button type="button" onClick={() => onCopy(m.text)} className="inline-flex items-center gap-1 rounded-md border border-danger/40 px-2 py-1 text-[11px] font-medium text-danger hover:bg-danger/10">
              <Copy className="size-3" /> Copy error
            </button>
          </div>
        </div>
      ) : (
        <div className="card-liquid-glass w-full min-w-0 overflow-hidden break-words rounded-xl rounded-bl-sm border border-border bg-bg-card p-3.5 text-xs leading-relaxed text-fg">
          <MarkdownView content={m.text} />
        </div>
      )}

      {/* What the agent did */}
      {tools.length > 0 && (
        <div className="mt-1.5 w-full">
          <button type="button" onClick={() => setStepsOpen((v) => !v)} className="flex max-w-full items-center gap-1.5 px-1 text-[11px] text-subtle hover:text-fg">
            <Wrench className="size-3 shrink-0" />
            <span className="truncate">{stepsOpen ? "What I did" : tools.map((t) => t.label).join(" · ")}</span>
            <ChevronDown className={cn("size-3 shrink-0 transition-transform", stepsOpen && "rotate-180")} />
          </button>
          {stepsOpen && <Steps steps={developer ? m.activity ?? [] : tools} developer={developer} />}
        </div>
      )}

      {/* Proposed actions */}
      {(m.actions ?? []).map((a) => (
        <ActionCard key={a.id} a={a} disabled={busy} onRun={() => onAction(a.id, "run")} onDismiss={() => onAction(a.id, "dismiss")} />
      ))}

      {m.uncitedClaims && (
        <div className="mt-2 flex w-full items-start gap-2 rounded-lg border border-warn/40 bg-warn/10 px-2.5 py-1.5 text-[11px] text-warn">
          <AlertTriangle className="mt-px size-3.5 shrink-0" />
          <span>Some statements have no citation. Treat uncited sentences as unverified.</span>
        </div>
      )}

      {sources.length > 0 && (
        <div className="mt-2 w-full">
          <button
            type="button"
            onClick={() => setSourcesOpen((v) => !v)}
            className="flex w-full items-center justify-between rounded-lg border border-border bg-bg-elevated px-2.5 py-1.5 text-[11px] font-medium text-fg transition-colors hover:bg-bg-subtle"
          >
            <span className="flex items-center gap-1.5">
              <FileText className="size-3.5 text-muted" strokeWidth={1.75} />
              Evidence · {sources.length} cited
            </span>
            <ChevronDown className={cn("size-3 text-muted transition-transform", sourcesOpen && "rotate-180")} />
          </button>
          {sourcesOpen && (
            <div className="mt-1.5 space-y-1.5">
              {sources.map((s) => {
                const reportId = s.reportId || s.id;
                const quote = s.quote || s.snippet;
                return (
                  <div key={`${s.id}-${reportId}`} className="card-liquid-glass space-y-1 rounded-lg border border-border bg-bg-card p-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <Link to="/library/$reportId" params={{ reportId }} className="line-clamp-2 min-w-0 text-xs font-medium text-fg hover:text-accent">
                        {s.title}
                      </Link>
                      <span className="shrink-0 rounded-md border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted">{s.id}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 text-[10px] text-subtle">
                      <span className="min-w-0 truncate">
                        {s.publisher || "Unknown publisher"} · {sourceDate(s.publishedAt)}
                        {s.formattedId ? ` · ${s.formattedId}` : ""}
                      </span>
                      {s.url && (
                        <a href={s.url} target="_blank" rel="noreferrer noopener" title="Original publication" className="shrink-0 hover:text-accent">
                          <ExternalLink className="size-3" />
                        </a>
                      )}
                    </div>
                    {quote && <blockquote className="line-clamp-6 whitespace-pre-line break-words border-l-2 border-border pl-2 text-[11px] leading-relaxed text-muted">{quote}</blockquote>}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Steps({ steps, developer }: { steps: Activity[]; developer: boolean }) {
  return (
    <ol className="mt-1 space-y-1 rounded-lg border border-border bg-bg-elevated p-2 text-[11px]">
      {steps.map((s, i) => (
        <li key={i} className="flex items-start gap-1.5">
          {s.running ? (
            <ActivitySpinner size="xs" className="mt-0.5 shrink-0 text-accent" />
          ) : s.ok === false ? (
            <CircleX className="mt-0.5 size-3 shrink-0 text-danger" />
          ) : (
            <CircleCheck className="mt-0.5 size-3 shrink-0 text-sage" />
          )}
          <span className="min-w-0 flex-1">
            <span className={cn(s.ok === false ? "text-danger" : "text-fg")}>{s.label}</span>
            {s.ms !== undefined && !s.running && <span className="ml-1 tabular-nums text-subtle">{duration(s.ms)}</span>}
            {developer && s.detail && <span className="mt-0.5 block break-all font-mono text-[10px] text-subtle">{s.detail}</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}

function LiveActivity({ steps, elapsed, developer, stopping }: { steps: Activity[]; elapsed: number; developer: boolean; stopping: boolean }) {
  const visible = developer ? steps : steps.filter((s) => s.kind === "tool" || s.running);
  const current = [...steps].reverse().find((s) => s.running);
  const label = stopping
    ? "Stopping"
    : !current
      ? "Starting"
      : current.kind !== "model" || /asking again/i.test(current.label)
        ? current.label
        : steps.some((s) => s.kind === "tool")
          ? "Reading the results and writing the answer"
          : "Thinking";
  return (
    <div className="card-liquid-glass mr-auto w-full max-w-[96%] rounded-xl border border-border bg-bg-card p-3 text-xs" aria-live="polite">
      <div className="flex items-center gap-2 text-muted">
        <ActivitySpinner size="sm" className="shrink-0 text-accent" />
        <span className="min-w-0 flex-1 truncate">{label}…</span>
        <span className="shrink-0 tabular-nums text-subtle">{elapsed}s</span>
      </div>
      {visible.length > 0 && <Steps steps={visible} developer={developer} />}
    </div>
  );
}

function ActionCard({ a, disabled, onRun, onDismiss }: { a: Action; disabled: boolean; onRun: () => void; onDismiss: () => void }) {
  return (
    <div
      className={cn(
        "mt-2 w-full rounded-lg border p-2.5 text-xs",
        a.status === "done" ? "border-sage/40 bg-sage/10" : a.status === "failed" ? "border-danger/40 bg-danger/10" : a.status === "dismissed" ? "border-border bg-bg-subtle opacity-70" : "border-accent/40 bg-accent/5",
      )}
    >
      <div className="flex items-start gap-2">
        <Play className="mt-0.5 size-3.5 shrink-0 text-muted" />
        <div className="min-w-0 flex-1">
          <p className="font-medium text-fg">{a.label}</p>
          {a.status === "pending" && <p className="mt-0.5 text-[11px] text-muted">Proposed by the analyst agent. Nothing has run yet.</p>}
          {a.status === "running" && <div className="mt-0.5 flex items-center gap-1 text-[11px] text-muted"><ActivitySpinner size="xs" /> Running…</div>}
          {a.status === "dismissed" && <p className="mt-0.5 text-[11px] text-muted">Dismissed.</p>}
          {(a.status === "done" || a.status === "failed") && <p className={cn("mt-0.5 text-[11px]", a.status === "done" ? "text-sage" : "text-danger")}>{a.result}</p>}
          {a.link && (
            <a href={a.link.href} className="mt-1 inline-flex items-center gap-1 text-[11px] font-medium text-accent hover:underline">
              {a.link.label}
            </a>
          )}
        </div>
      </div>
      {a.status === "pending" && (
        <div className="mt-2 flex gap-1.5 pl-5">
          <Button type="button" size="sm" variant="primary" disabled={disabled} onClick={onRun} className="h-7 gap-1 px-2.5 text-[11px]">
            <Play className="size-3" /> Run
          </Button>
          <Button type="button" size="sm" variant="ghost" disabled={disabled} onClick={onDismiss} className="h-7 px-2.5 text-[11px]">
            Dismiss
          </Button>
        </div>
      )}
    </div>
  );
}

function SessionsPanel({
  current,
  rows,
  loading,
  onOpen,
  onNew,
  onDelete,
  onClose,
}: {
  current: string | null;
  rows: Array<{ sessionId: string; title: string; messageCount: number; updatedAt: string; preview: string }>;
  loading: boolean;
  onOpen: (id: string) => void;
  onNew: () => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}) {
  const [q, setQ] = useState("");
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const shown = rows.filter((r) => !q.trim() || `${r.title} ${r.preview}`.toLowerCase().includes(q.trim().toLowerCase()));
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 p-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-fg">Investigations</span>
        <button type="button" onClick={onClose} className={iconBtnSm} aria-label="Back to the conversation">
          <X className="size-3.5" />
        </button>
      </div>
      <div className="flex gap-2">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-subtle" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Find an investigation"
            aria-label="Find an investigation"
            className="h-8 w-full rounded-lg border border-border bg-bg-elevated pl-8 pr-2 text-xs text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
          />
        </div>
        <Button type="button" size="sm" variant="primary" onClick={onNew} className="h-8 gap-1 px-2.5 text-xs">
          <Plus className="size-3.5" /> New
        </Button>
      </div>
      <div className="min-h-0 flex-1 space-y-1 overflow-y-auto">
        {loading && <p className="p-3 text-center text-xs text-subtle">Loading…</p>}
        {!loading && shown.length === 0 && <p className="p-3 text-center text-xs text-subtle">{rows.length ? "No investigation matches." : "No investigations yet. Ask a question to start one."}</p>}
        {shown.map((r) => (
          <div key={r.sessionId} className={cn("group flex items-start gap-1 rounded-lg p-2 transition-colors", r.sessionId === current ? "bg-bg-subtle" : "hover:bg-bg-subtle")}>
            <button type="button" onClick={() => onOpen(r.sessionId)} className="min-w-0 flex-1 text-left">
              <div className="flex items-baseline justify-between gap-2">
                <span className="truncate text-xs font-medium text-fg">{r.title}</span>
                <span className="shrink-0 text-[10px] text-subtle">{relativeTime(r.updatedAt)}</span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-subtle">
                {r.messageCount} message{r.messageCount === 1 ? "" : "s"} · {r.preview}
              </p>
            </button>
            {confirmId === r.sessionId ? (
              <span className="flex shrink-0 items-center gap-1">
                <button type="button" onClick={() => (onDelete(r.sessionId), setConfirmId(null))} className="rounded-md bg-danger/15 px-1.5 py-0.5 text-[10px] font-medium text-danger">
                  Delete
                </button>
                <button type="button" onClick={() => setConfirmId(null)} className="rounded-md px-1.5 py-0.5 text-[10px] text-muted hover:text-fg">
                  Keep
                </button>
              </span>
            ) : (
              <button type="button" onClick={() => setConfirmId(r.sessionId)} className={cn(iconBtnXs, "opacity-0 group-hover:opacity-100 focus:opacity-100")} title="Delete" aria-label={`Delete ${r.title}`}>
                <Trash2 className="size-3" />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function WorkerStatus({ workers }: { workers: { interactive: WorkerInfo; background: WorkerInfo; chatSessions: Array<WorkerInfo & { session: string }> } }) {
  const line = (label: string, w: WorkerInfo) => (
    <span key={label} className="whitespace-nowrap">
      <span className={cn("mr-1 inline-block size-1.5 rounded-full", w.isAlive ? "bg-sage" : "bg-subtle")} />
      {label} {w.isAlive ? `pid ${w.pid ?? "?"}` : "idle"} · {w.turnCount} turns{w.queueLength ? ` · ${w.queueLength} queued` : ""}
    </span>
  );
  return (
    <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 border-t border-border pt-2 font-mono text-[10px] text-subtle" title="Developer mode: agent workers in the sandbox">
      {line("background", workers.background)}
      {workers.chatSessions.map((w) => line(`chat ${w.session.slice(-6)}`, w))}
    </div>
  );
}

type WorkerInfo = { isAlive: boolean; pid: number | null; turnCount: number; queueLength: number };

const iconBtn = "flex size-8 items-center justify-center rounded-lg text-subtle transition-colors hover:bg-bg-subtle hover:text-fg";
const iconBtnSm = "flex size-6 shrink-0 items-center justify-center rounded-md text-subtle transition-colors hover:bg-bg-subtle hover:text-fg";
const iconBtnXs = "flex size-5 items-center justify-center rounded text-subtle transition-colors hover:bg-bg-subtle hover:text-fg disabled:opacity-40";
