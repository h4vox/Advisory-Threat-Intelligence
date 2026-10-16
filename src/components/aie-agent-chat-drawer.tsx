import { useState, useRef, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  Bot,
  Send,
  X,
  RefreshCw,
  Zap,
  Trash2,
  ChevronDown,
  Copy,
  Check,
  FileText,
  ExternalLink,
  PlusCircle,
  Clock,
  Database,
  Maximize2,
  Minimize2,
  AlertTriangle,
  SearchX,
} from "lucide-react";
import { Button } from "./ui/button";
import { MarkdownView } from "./ui/markdown-view";
import { ActivitySpinner } from "./ui/activity-spinner";
import { cn } from "@/lib/cn";
import {
  chatWithAgyAgent,
  getAgentChatSessionMessages,
  clearAgentChatSession,
  listAgentChatSessions,
} from "@/lib/aie/server";
import {
  DEFAULT_AGY_MODEL,
  sanitizeAgyModel,
} from "@/lib/aie/agent-framework/types";

/**
 * A cited passage ("S1") returned by the grounded copilot. Messages saved
 * before grounded retrieval carry whole-report sources (`snippet`, no
 * `reportId` / `quote`), which still render.
 */
interface ChatSource {
  id: string;
  reportId?: string;
  formattedId: string;
  title: string;
  publisher: string;
  url: string;
  publishedAt?: string | null;
  quote?: string;
  start?: number;
  end?: number;
  score?: number;
  classification?: string;
  resourceKind?: string;
  snippet?: string;
}

function formatSourceDate(value?: string | null): string {
  if (!value) return "Undated";
  const d = new Date(value);
  return Number.isNaN(d.getTime())
    ? value.slice(0, 10)
    : d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

interface ChatMessage {
  id: string;
  sender: "user" | "agent";
  text: string;
  latencyMs?: number;
  model?: string;
  providerName?: string;
  timestamp: string;
  isError?: boolean;
  sources?: ChatSource[];
  groundedCount?: number;
  /** Reply has factual sentences without an [S#] citation. */
  uncitedClaims?: boolean;
  /** Reply is the evidence-gap message: nothing in the library matched. */
  evidenceGap?: boolean;
}

const DEFAULT_PROMPTS = [
  "Summarize active nation-state campaigns in our platform",
  "Extract MITRE TTPs and command lines for PowerShell execution",
  "What are the highest risk CVEs recorded in the local library?",
  "Audit ingestion sources and recommend high-value adversary labs",
];

const INITIAL_GREETING: ChatMessage = {
  id: "greeting",
  sender: "agent",
  text: "Autonomous Threat Intelligence Copilot online. Connected to the local platform intelligence repository and persistent warm execution daemon. How can I assist your adversary emulation or threat hunting analysis?",
  timestamp: "Ready",
};

interface AieAgentChatDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeModel?: string;
  embedded?: boolean;
}

export function AieAgentChatDrawer({
  isOpen,
  onClose,
  activeModel = DEFAULT_AGY_MODEL,
  embedded = false,
}: AieAgentChatDrawerProps) {
  const queryClient = useQueryClient();
  const [sessionId, setSessionId] = useState<string>(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("aie_chat_session_id");
      if (saved) return saved;
    }
    return "active-investigation";
  });
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_GREETING]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [expandedSources, setExpandedSources] = useState<Record<string, boolean>>({});
  const [copiedMsgId, setCopiedMsgId] = useState<string | null>(null);
  const [isSessionDropdownOpen, setIsSessionDropdownOpen] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const cleanModel = sanitizeAgyModel(activeModel);

  const [drawerWidth, setDrawerWidth] = useState<number>(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("aie_chat_drawer_width");
      if (saved) {
        const parsed = parseInt(saved, 10);
        const maxAllowed = Math.round(window.innerWidth * 0.5);
        if (!isNaN(parsed) && parsed >= 340 && parsed <= maxAllowed) {
          return parsed;
        }
      }
      return Math.max(380, Math.min(460, Math.round(window.innerWidth * 0.28)));
    }
    return 420;
  });
  const [isDragging, setIsDragging] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  // Drag-to-resize listener with 50% viewport cap
  useEffect(() => {
    if (!isDragging) return;

    const handleMouseMove = (e: MouseEvent) => {
      const newWidth = window.innerWidth - e.clientX;
      const minW = 340;
      const maxW = Math.round(window.innerWidth * 0.5);
      const clamped = Math.max(minW, Math.min(maxW, newWidth));
      setDrawerWidth(clamped);
      setIsExpanded(clamped >= maxW - 15);
    };

    const handleMouseUp = () => {
      setIsDragging(false);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };

    document.body.style.cursor = "ew-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isDragging]);

  // Persist width when not dragging
  useEffect(() => {
    if (typeof window !== "undefined" && !isDragging) {
      localStorage.setItem("aie_chat_drawer_width", String(drawerWidth));
    }
  }, [drawerWidth, isDragging]);

  const toggleExpand = () => {
    if (isExpanded) {
      setIsExpanded(false);
      const standard = Math.max(380, Math.min(460, Math.round(window.innerWidth * 0.28)));
      setDrawerWidth(standard);
    } else {
      setIsExpanded(true);
      setDrawerWidth(Math.round(window.innerWidth * 0.5));
    }
  };

  // Initialize session ID from localStorage if available
  useEffect(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("aie_chat_session_id");
      if (saved) setSessionId(saved);
    }
  }, []);

  // Fetch session history from MongoDB
  const { data: sessionData } = useQuery({
    queryKey: ["agent_chat_messages", sessionId],
    queryFn: () => getAgentChatSessionMessages({ data: { sessionId } }),
    enabled: isOpen && Boolean(sessionId),
  });

  // Fetch list of active investigations
  const { data: sessionsList } = useQuery({
    queryKey: ["agent_chat_sessions_list"],
    queryFn: () => listAgentChatSessions(),
    enabled: isOpen,
  });

  // Sync loaded history
  useEffect(() => {
    if (sessionData?.messages && sessionData.messages.length > 0) {
      const mapped: ChatMessage[] = sessionData.messages.map((m) => ({
        id: m.id,
        sender: m.sender,
        text: m.text,
        model: m.model,
        latencyMs: m.latencyMs,
        sources: m.sources,
        uncitedClaims: m.uncitedClaims,
        evidenceGap: m.evidenceGap,
        timestamp: new Date(m.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      }));
      setMessages(mapped);
    } else if (sessionData?.messages && sessionData.messages.length === 0) {
      setMessages([INITIAL_GREETING]);
    }
  }, [sessionData]);

  const toggleSource = (msgId: string) => {
    setExpandedSources((prev) => ({ ...prev, [msgId]: !prev[msgId] }));
  };

  const handleCopy = (id: string, text: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedMsgId(id);
      setTimeout(() => setCopiedMsgId(null), 2000);
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [isOpen, messages]);

  const switchSession = (newId: string) => {
    setSessionId(newId);
    if (typeof window !== "undefined") {
      localStorage.setItem("aie_chat_session_id", newId);
    }
    setIsSessionDropdownOpen(false);
  };

  const handleStartNewSession = () => {
    const newId = `investigation-${Date.now().toString(36)}`;
    switchSession(newId);
    setMessages([INITIAL_GREETING]);
  };

  const handleClearSession = async () => {
    try {
      await clearAgentChatSession({ data: { sessionId } });
      setMessages([INITIAL_GREETING]);
      queryClient.invalidateQueries({ queryKey: ["agent_chat_messages", sessionId] });
      queryClient.invalidateQueries({ queryKey: ["agent_chat_sessions_list"] });
    } catch (err) {
      console.warn("Failed to clear session:", err);
    }
  };

  const handleSend = async (promptToSend?: string) => {
    const text = (promptToSend || input).trim();
    if (!text || isLoading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: "user",
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const res = await chatWithAgyAgent({
        data: {
          message: text,
          model: cleanModel,
          sessionId,
        },
      });

      const replyText = res?.reply || (res as any)?.error || "Agent response unavailable. Please retry.";
      const agentMsg: ChatMessage = {
        id: `agent-${Date.now()}`,
        sender: "agent",
        text: replyText,
        latencyMs: res?.latencyMs,
        model: res?.model,
        providerName: "Threat Intelligence Copilot",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        isError: !res?.success,
        sources: res?.sources,
        groundedCount: res?.groundedReportCount,
        uncitedClaims: res?.uncitedClaims,
        evidenceGap: res?.evidenceGap,
      };

      setMessages((prev) => [...prev, agentMsg]);
      queryClient.invalidateQueries({ queryKey: ["agent_chat_sessions_list"] });
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        sender: "agent",
        text: `Analysis unavailable: ${err?.message || "Autonomous agent connection error"}`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        isError: true,
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  const content = (
    <div className="flex flex-col h-full bg-transparent text-fg select-text">
      {/* Copilot Header */}
      <div className="p-3.5 flex items-center justify-between shrink-0 drawer-section-header">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="relative flex size-9 shrink-0 items-center justify-center rounded-lg bg-bg-subtle text-fg">
            <Bot className="size-[18px]" strokeWidth={1.75} />
            <span className="absolute -right-0.5 -top-0.5 size-2 rounded-full bg-sage ring-2 ring-bg-card" />
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-medium text-fg">CTI analyst copilot</h3>
            <div className="flex max-w-[260px] items-center gap-1.5 truncate font-mono text-[11px] text-subtle">
              <Database className="size-3 shrink-0" />
              <span className="truncate">{cleanModel}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {/* New Investigation Thread Trigger */}
          <button
            type="button"
            onClick={handleStartNewSession}
            title="Start new investigation thread"
            aria-label="Start new investigation thread"
            className={iconBtn}
          >
            <PlusCircle className="size-3.5" />
          </button>

          {/* Active Investigations Popout Trigger */}
          <button
            type="button"
            onClick={() => setIsSessionDropdownOpen((p) => !p)}
            title="Active investigation threads"
            aria-label="Active investigation threads"
            className={cn(
              iconBtn,
              isSessionDropdownOpen && "bg-bg-subtle text-fg"
            )}
          >
            <Clock className="size-3.5" />
          </button>

          {/* Maximize / Reset Width Toggle */}
          <button
            type="button"
            onClick={toggleExpand}
            title={isExpanded ? "Restore default width (28vw)" : "Expand to 50% viewport width"}
            className={iconBtn}
          >
            {isExpanded ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
          </button>

          {/* Clear Current History */}
          <button
            type="button"
            onClick={handleClearSession}
            title="Clear current thread"
            aria-label="Clear current thread"
            className={iconBtn}
          >
            <Trash2 className="size-3.5" />
          </button>

          {!embedded && (
            <button
              type="button"
              onClick={onClose}
              aria-label="Close copilot"
              className={iconBtn}
            >
              <X className="size-4" />
            </button>
          )}
        </div>
      </div>

      {/* Suggested Threat Hunting Queries (Frosted Pill Chips) */}
      <div className="px-3 py-2 drawer-section-subbar overflow-x-auto shrink-0 flex items-center gap-1.5 no-scrollbar">
        <span className="flex shrink-0 items-center gap-1 text-xs text-muted">
          <Zap className="size-3.5" strokeWidth={1.75} />
          Try
        </span>
        {DEFAULT_PROMPTS.map((prompt, i) => (
          <button
            key={i}
            type="button"
            disabled={isLoading}
            onClick={() => handleSend(prompt)}
            className="pill-liquid-glass shrink-0 cursor-pointer whitespace-nowrap rounded-md border border-border bg-bg-elevated px-2.5 py-1 text-xs text-muted transition-colors hover:bg-bg-subtle hover:text-fg disabled:opacity-50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden p-3.5 space-y-4">
        {messages.map((msg) => {
          const hasSources = Boolean(msg.sources && msg.sources.length > 0);
          const isSourceOpen = expandedSources[msg.id] !== false; // Default expanded

          return (
            <div
              key={msg.id}
              className={cn(
                "flex flex-col max-w-[94%] w-full min-w-0 overflow-x-hidden",
                msg.sender === "user" ? "ml-auto items-end" : "mr-auto items-start"
              )}
            >
              {/* Message Header */}
              <div className="flex items-center gap-1.5 mb-1 px-1">
                <span className="text-[11px] font-medium text-muted">
                  {msg.sender === "user" ? "Analyst" : "Copilot"}
                </span>
                {msg.model && msg.sender !== "user" && (
                  <span className="max-w-[140px] truncate font-mono text-[10px] text-subtle" title={msg.model}>
                    ({msg.model})
                  </span>
                )}
                <span className="text-[10px] text-subtle">·</span>
                <span className="text-[10px] text-subtle">{msg.timestamp}</span>
                {msg.latencyMs && (
                  <span className="text-[10px] text-subtle tabular-nums">
                    · {msg.latencyMs < 1000 ? `${msg.latencyMs} ms` : `${(msg.latencyMs / 1000).toFixed(1)} s`}
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => handleCopy(msg.id, msg.text)}
                  className="text-subtle hover:text-fg p-0.5 rounded cursor-pointer transition-colors"
                  title="Copy response"
                >
                  {copiedMsgId === msg.id ? (
                    <Check className="size-3 text-sage" />
                  ) : (
                    <Copy className="size-3" />
                  )}
                </button>
              </div>

              {/* Message Bubble */}
              {msg.sender === "user" ? (
                <div className="max-w-full select-text overflow-hidden break-words rounded-xl rounded-br-sm bg-accent p-3 text-xs leading-relaxed text-accent-fg">
                  {msg.text}
                </div>
              ) : msg.isError ? (
                <div className="max-w-full select-text overflow-hidden break-words rounded-xl rounded-bl-sm border border-danger/50 bg-danger/10 p-3.5 text-xs leading-relaxed text-danger">
                  {msg.text}
                </div>
              ) : (
                <div className="card-liquid-glass w-full max-w-full select-text overflow-hidden break-words rounded-xl rounded-bl-sm border border-border bg-bg-card p-3.5 text-xs leading-relaxed text-fg">
                  <MarkdownView content={msg.text} />
                </div>
              )}

              {/* Grounding notices */}
              {msg.sender === "agent" && msg.evidenceGap && (
                <div className="mt-2 flex w-full items-start gap-2 rounded-lg border border-border bg-bg-subtle px-2.5 py-2 text-[11px] text-muted">
                  <SearchX className="size-3.5 shrink-0 mt-px" />
                  <span>No library passage matched this question closely enough to cite, so no answer was generated from model knowledge.</span>
                </div>
              )}
              {msg.sender === "agent" && msg.uncitedClaims && (
                <div className="mt-2 flex w-full items-start gap-2 rounded-lg border border-warn/40 bg-warn/10 px-2.5 py-2 text-[11px] text-warn">
                  <AlertTriangle className="size-3.5 shrink-0 mt-px" />
                  <span>Some statements are not backed by a cited passage. Treat uncited sentences as unverified.</span>
                </div>
              )}

              {/* Cited evidence (only passages the reply actually cites) */}
              {hasSources && (
                <div className="mt-2 w-full space-y-1.5">
                  <button
                    type="button"
                    onClick={() => toggleSource(msg.id)}
                    className="flex w-full cursor-pointer items-center justify-between rounded-lg border border-border bg-bg-elevated px-2.5 py-1.5 text-[11px] font-medium text-fg transition-colors hover:bg-bg-subtle"
                  >
                    <div className="flex items-center gap-1.5">
                      <FileText className="size-3.5 text-muted" strokeWidth={1.75} />
                      <span>
                        Cited evidence ({msg.sources?.length} passage{msg.sources?.length === 1 ? "" : "s"})
                      </span>
                    </div>
                    <div className="flex items-center gap-1 text-[11px] text-muted">
                      <span>{isSourceOpen ? "Collapse" : "Expand"}</span>
                      <ChevronDown
                        className={cn(
                          "size-3 transition-transform duration-200",
                          isSourceOpen && "rotate-180"
                        )}
                      />
                    </div>
                  </button>

                  {isSourceOpen && (
                    <div className="space-y-1.5 pt-0.5">
                      {msg.sources?.map((s) => {
                        const reportId = s.reportId || s.id;
                        const quote = s.quote || s.snippet;
                        const isPassage = Boolean(s.reportId);
                        return (
                          <div
                            key={`${s.id}-${reportId}`}
                            className="card-liquid-glass space-y-1.5 rounded-lg border border-border bg-bg-card p-2.5"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <Link
                                to="/library/$reportId"
                                params={{ reportId }}
                                className="line-clamp-2 min-w-0 text-xs font-medium text-fg transition-colors hover:text-accent"
                              >
                                {s.title}
                              </Link>
                              <span className="shrink-0 rounded-md border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted">
                                {isPassage ? s.id : s.formattedId || reportId.slice(0, 10)}
                              </span>
                            </div>
                            <div className="flex items-center justify-between gap-2 text-[10px] text-subtle">
                              <span className="truncate min-w-0">
                                {s.publisher}
                                {isPassage ? ` · ${formatSourceDate(s.publishedAt)}` : s.classification ? ` · ${s.classification}` : ""}
                                {s.formattedId ? ` · ${s.formattedId}` : ""}
                              </span>
                              <div className="flex items-center gap-2 shrink-0">
                                <Link
                                  to="/library/$reportId"
                                  params={{ reportId }}
                                  className="text-accent flex items-center gap-1 hover:underline font-medium"
                                >
                                  <span>Open report</span>
                                </Link>
                                {s.url && (
                                  <a
                                    href={s.url}
                                    target="_blank"
                                    rel="noreferrer noopener"
                                    title="Original publication"
                                    className="text-subtle hover:text-accent"
                                  >
                                    <ExternalLink className="size-3" />
                                  </a>
                                )}
                              </div>
                            </div>
                            {quote && (
                              <blockquote className="whitespace-pre-line break-words border-l-2 border-border pl-2 text-[11px] leading-relaxed text-muted">
                                {quote}
                              </blockquote>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {isLoading && (
          <div className="card-liquid-glass mr-auto flex max-w-[85%] items-center gap-2.5 rounded-xl border border-border bg-bg-card p-3 text-xs text-muted">
            <ActivitySpinner size="sm" className="text-accent shrink-0" />
            <span>Analyzing threat data & formulating a response…</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Form */}
      <div className="p-3 drawer-section-footer">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <div className="relative grow">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about threats, TTPs, CVEs, or campaigns…"
              disabled={isLoading}
              className="h-9 w-full rounded-lg border border-border bg-bg-elevated px-3 pr-9 text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
            />
            {input && (
              <button
                type="button"
                onClick={() => setInput("")}
                aria-label="Clear input"
                className="absolute right-3 top-1/2 -translate-y-1/2 text-subtle hover:text-fg p-0.5 cursor-pointer"
              >
                <X className="size-3" />
              </button>
            )}
          </div>

          <Button
            type="submit"
            size="sm"
            variant="primary"
            disabled={!input.trim() || isLoading}
            className="h-9 shrink-0 cursor-pointer gap-1.5 rounded-lg px-3.5 text-sm font-medium"
          >
            {isLoading ? (
              <ActivitySpinner size="xs" />
            ) : (
              <>
                <Send className="size-3.5" />
                <span className="hidden sm:inline">Send</span>
              </>
            )}
          </Button>
        </form>

        {/* Structured Session & Sandbox Status Footer */}
        <div className="mt-2.5 flex select-none items-center justify-between gap-2 border-t border-border pt-2 text-[11px]">
          <div className="flex items-center gap-1.5 min-w-0 flex-1">
            <span className="shrink-0 text-subtle">Session</span>
            <span className="truncate font-mono text-muted" title={sessionId}>
              {sessionId ? (sessionId.length > 20 ? `${sessionId.slice(0, 10)}…${sessionId.slice(-6)}` : sessionId) : "New thread"}
            </span>
          </div>
          <div className="flex items-center gap-1.5 shrink-0 pl-1.5">
            <span className="size-1.5 shrink-0 rounded-full bg-sage" />
            <span className="whitespace-nowrap text-muted">Daemon active</span>
          </div>
        </div>
      </div>
    </div>
  );

  if (embedded) {
    return <div className="card-liquid-glass flex h-96 flex-col overflow-hidden rounded-xl border border-border">{content}</div>;
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />

      {/* Slide-over Drawer with Left Anchored Dock and Resizer Handle */}
      <div
        style={{ width: `${drawerWidth}px` }}
        className="relative z-10 max-w-[92vw] h-full shadow-2xl drawer-liquid-glass animate-in slide-in-from-right duration-200 flex flex-col"
      >
        {/* Expansion Handle / Drag affordance on center-left edge with vertical 3-dot affordance */}
        <div
          onMouseDown={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onClick={() => {
            if (!isDragging) {
              toggleExpand();
            }
          }}
          className="absolute -left-3 top-1/2 -translate-y-1/2 w-6 h-28 flex items-center justify-center cursor-ew-resize group z-30 select-none"
          title="Click to toggle 50% expansion, or drag to resize"
        >
          <div className="w-1.5 h-14 rounded-full bg-border/80 group-hover:bg-accent group-hover:w-2 transition-all flex flex-col items-center justify-center gap-1 shadow-md border border-border/40 backdrop-blur-md">
            <span className="size-1 rounded-full bg-fg/70 group-hover:bg-accent-fg transition-colors" />
            <span className="size-1 rounded-full bg-fg/70 group-hover:bg-accent-fg transition-colors" />
            <span className="size-1 rounded-full bg-fg/70 group-hover:bg-accent-fg transition-colors" />
          </div>
        </div>

        {/* Session Switcher Pop-out Panel (Anchored to Left of Drawer) */}
        {isSessionDropdownOpen && (
          <div className="dropdown-liquid-glass absolute right-full top-3 z-40 mr-2 w-80 space-y-2.5 rounded-xl border border-border bg-bg-card p-3.5 shadow-2xl animate-in fade-in-0 slide-in-from-right-2 duration-150">
            <div className="flex items-center justify-between px-1 pb-2 border-b border-border/60">
              <div className="flex items-center gap-1.5">
                <Clock className="size-4 text-muted" strokeWidth={1.75} />
                <span className="text-sm font-medium text-fg">Active investigations</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted tabular-nums">{sessionsList?.sessions?.length || 0} threads</span>
                <button
                  type="button"
                  onClick={() => setIsSessionDropdownOpen(false)}
                  className="p-1 rounded-lg text-subtle hover:text-fg hover:bg-bg-subtle cursor-pointer"
                >
                  <X className="size-3" />
                </button>
              </div>
            </div>

            {/* Quick Start New Thread Button inside popout */}
            <button
              type="button"
              onClick={handleStartNewSession}
              className="flex h-9 w-full cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle"
            >
              <PlusCircle className="size-3.5" />
              <span>Start new investigation thread</span>
            </button>

            {/* Threads List */}
            <div className="max-h-72 overflow-y-auto space-y-1.5 pr-0.5">
              {(sessionsList?.sessions || []).map((s) => (
                <button
                  key={s.sessionId}
                  type="button"
                  onClick={() => switchSession(s.sessionId)}
                  className={cn(
                    "flex w-full cursor-pointer flex-col gap-1 rounded-lg p-2.5 text-left text-xs transition-colors",
                    s.sessionId === sessionId ? "bg-bg-subtle text-fg" : "text-muted hover:bg-bg-subtle hover:text-fg"
                  )}
                >
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-mono truncate">{s.sessionId}</span>
                    <span className="shrink-0 text-[10px] text-subtle tabular-nums">
                      {s.messageCount} messages
                    </span>
                  </div>
                  <p className="text-[10px] text-subtle truncate">{s.lastMessage || "Empty thread"}</p>
                </button>
              ))}
              {(!sessionsList?.sessions || sessionsList.sessions.length === 0) && (
                <p className="text-xs text-subtle p-3 text-center">No prior investigations saved.</p>
              )}
            </div>
          </div>
        )}

        {content}
      </div>
    </div>
  );
}

const iconBtn =
  "flex size-8 cursor-pointer items-center justify-center rounded-lg text-subtle transition-colors hover:bg-bg-subtle hover:text-fg";
