import { useState, useRef, useEffect } from "react";
import {
  Bot,
  Send,
  X,
  Sparkles,
  RefreshCw,
  Terminal,
  Zap,
  Trash2,
  CheckCircle2,
  AlertCircle,
  CornerDownLeft,
  ChevronRight,
  ChevronDown,
  Copy,
  Check,
  Code2,
} from "lucide-react";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { cn } from "@/lib/cn";
import { chatWithAgyAgent } from "@/lib/aie/server";

interface ChatMessage {
  id: string;
  sender: "user" | "agent";
  text: string;
  latencyMs?: number;
  model?: string;
  providerName?: string;
  timestamp: string;
  isError?: boolean;
  trace?: {
    id: string;
    command: string;
    args: string[];
    fullCommandStr: string;
    runtime: string;
    containerName: string;
    pid?: number;
    latencyMs: number;
    exitCode: number | null;
    stdoutBytes: number;
    stderrBytes: number;
    status: string;
    stepLogs: string[];
  };
  logs?: string[];
  sources?: Array<{
    id: string;
    formattedId: string;
    title: string;
    publisher: string;
    url: string;
    classification: string;
    resourceKind: string;
    snippet?: string;
  }>;
}

const DEFAULT_PROMPTS = [
  "Verify agent IPC status",
  "Analyze MITRE T1059.001 (PowerShell)",
  "What are standard ransomware kill-chain stages?",
  "Test procedural extraction pipeline",
];

interface AieAgentChatDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeModel?: string;
  embedded?: boolean;
}

export function AieAgentChatDrawer({
  isOpen,
  onClose,
  activeModel = "gemini-3.8-flash-low",
  embedded = false,
}: AieAgentChatDrawerProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "init",
      sender: "agent",
      text: "Antigravity AGY Agent online. IPC protocol operational via `agy --dangerously-skip-permissions`. Ready for autonomous adversary TTP extraction, kill-chain reconstruction, or threat research queries.",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [expandedTraceIds, setExpandedTraceIds] = useState<Record<string, boolean>>({});
  const [copiedMsgId, setCopiedMsgId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const toggleTrace = (id: string) => {
    setExpandedTraceIds((prev) => ({ ...prev, [id]: !prev[id] }));
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
          model: activeModel,
        },
      });

      const agentMsg: ChatMessage = {
        id: `agent-${Date.now()}`,
        sender: "agent",
        text: res.reply,
        latencyMs: res.latencyMs,
        model: res.model,
        providerName: (res as any).providerName,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        isError: !res.success,
        trace: res.trace as any,
        logs: res.logs,
        sources: (res as any).sources,
      };

      setMessages((prev) => [...prev, agentMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        sender: "agent",
        text: `Communication error: ${err?.message || "Could not reach Antigravity CLI agent"}`,
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
    <div className="flex flex-col h-full bg-bg-elevated text-fg select-text">
      {/* Drawer Header */}
      <div className="p-3.5 border-b border-border flex items-center justify-between shrink-0 bg-bg/85 backdrop-blur-md">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="relative p-2 rounded-xl bg-accent/10 border border-accent/20 text-accent shrink-0">
            <Bot className="size-4.5" />
            <span className="absolute -top-0.5 -right-0.5 flex size-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
            </span>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-fg">AIE Cognitive Agent</h3>
              <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-[9px] px-1.5 py-0.2">
                Live
              </Badge>
            </div>
            <p className="text-[11px] text-subtle font-mono truncate max-w-[200px]">
              Antigravity AGY · {activeModel}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={() =>
              setMessages([
                {
                  id: "init",
                  sender: "agent",
                  text: "Console reset. Ready for new queries.",
                  timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
                },
              ])
            }
            title="Clear Chat History"
            className="p-1.5 rounded-lg text-subtle hover:text-fg hover:bg-bg-subtle transition-colors cursor-pointer"
          >
            <Trash2 className="size-3.5" />
          </button>
          {!embedded && (
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-subtle hover:text-fg hover:bg-bg-subtle transition-colors cursor-pointer"
            >
              <X className="size-4" />
            </button>
          )}
        </div>
      </div>

      {/* Suggested Quick Queries */}
      <div className="px-3 py-2 border-b border-border/60 bg-bg-subtle/40 overflow-x-auto shrink-0 flex items-center gap-1.5 no-scrollbar">
        <span className="text-[10px] uppercase font-mono text-subtle shrink-0 flex items-center gap-1">
          <Zap className="size-2.5 text-accent" />
          Quick:
        </span>
        {DEFAULT_PROMPTS.map((prompt, i) => (
          <button
            key={i}
            type="button"
            disabled={isLoading}
            onClick={() => handleSend(prompt)}
            className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-border bg-bg-elevated hover:border-accent/40 text-muted hover:text-fg transition-colors whitespace-nowrap cursor-pointer shrink-0"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-3.5">
        {messages.map((msg) => {
          const isTraceOpen = Boolean(expandedTraceIds[msg.id]);
          const hasTrace = Boolean(msg.trace || (msg.logs && msg.logs.length > 0));

          return (
            <div
              key={msg.id}
              className={cn(
                "flex flex-col max-w-[94%]",
                msg.sender === "user" ? "ml-auto items-end" : "mr-auto items-start"
              )}
            >
              <div className="flex items-center gap-1.5 mb-1 px-1">
                <span className="text-[10px] font-mono text-subtle font-medium">
                  {msg.sender === "user" ? "You" : msg.providerName || "AIE Agent"}
                </span>
                {msg.model && msg.sender !== "user" && (
                  <span className="text-[9px] font-mono text-subtle/70 max-w-[140px] truncate" title={msg.model}>
                    ({msg.model})
                  </span>
                )}
                <span className="text-[9px] text-subtle/70">·</span>
                <span className="text-[9px] text-subtle/70">{msg.timestamp}</span>
                {msg.latencyMs && (
                  <Badge className="text-[9px] font-mono border border-emerald-500/30 text-emerald-400 px-1 py-0 ml-1">
                    {msg.latencyMs}ms
                  </Badge>
                )}
                <button
                  type="button"
                  onClick={() => handleCopy(msg.id, msg.text)}
                  className="text-subtle hover:text-fg p-0.5 rounded cursor-pointer transition-colors"
                  title="Copy message"
                >
                  {copiedMsgId === msg.id ? (
                    <Check className="size-2.5 text-emerald-400" />
                  ) : (
                    <Copy className="size-2.5" />
                  )}
                </button>
              </div>

              <div
                className={cn(
                  "p-3 rounded-xl text-xs leading-relaxed transition-all shadow-xs select-text w-full",
                  msg.sender === "user"
                    ? "bg-accent text-white rounded-br-xs font-sans"
                    : msg.isError
                    ? "bg-red-500/10 border border-red-500/30 text-red-300 rounded-bl-xs font-mono"
                    : "bg-bg-subtle border border-border/80 text-fg rounded-bl-xs whitespace-pre-wrap font-mono text-[11.5px]"
                )}
              >
                {msg.text}

                {/* Grounded Threat Intelligence Sources */}
                {msg.sources && msg.sources.length > 0 && (
                  <div className="mt-3 pt-2.5 border-t border-border/50 font-sans">
                    <div className="flex items-center gap-1.5 text-[10px] font-semibold text-emerald-400 uppercase tracking-wider mb-2">
                      <Sparkles className="size-3 text-emerald-400" />
                      <span>Grounded in {msg.sources.length} Local Intelligence Reports</span>
                    </div>
                    <div className="grid grid-cols-1 gap-1.5">
                      {msg.sources.map((src) => (
                        <a
                          key={src.id}
                          href={`/library?highlight=${encodeURIComponent(src.id)}`}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center justify-between p-2 rounded-lg bg-bg-surface/80 hover:bg-bg-surface border border-border/60 hover:border-emerald-500/40 text-[11px] transition-all group no-underline"
                        >
                          <div className="flex items-center gap-2 min-w-0 pr-2">
                            <span className="font-mono text-[9.5px] px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 font-semibold shrink-0">
                              {src.formattedId}
                            </span>
                            <span className="truncate font-medium text-fg group-hover:text-emerald-400 transition-colors">
                              {src.title}
                            </span>
                          </div>
                          <span className="text-[9.5px] text-muted shrink-0 font-mono">
                            {src.publisher}
                          </span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Execution Trace & Detailed Telemetry Accordion */}
              {hasTrace && msg.sender === "agent" && (
                <div className="mt-1 w-full border border-border/60 rounded-lg overflow-hidden bg-black/60">
                  <button
                    type="button"
                    onClick={() => toggleTrace(msg.id)}
                    className="w-full flex items-center justify-between px-2.5 py-1.5 text-[10px] font-mono text-subtle hover:text-fg hover:bg-white/5 transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-1.5">
                      <Terminal className="size-3 text-cyan-400" />
                      <span>Execution Trace & Stdio Telemetry</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-[9px] text-emerald-400 font-bold">
                        {msg.trace?.runtime ? `[${msg.trace.runtime.toUpperCase()}]` : "[LOGS]"}
                      </span>
                      {isTraceOpen ? (
                        <ChevronDown className="size-3" />
                      ) : (
                        <ChevronRight className="size-3" />
                      )}
                    </div>
                  </button>

                  {isTraceOpen && (
                    <div className="p-2.5 pt-0 border-t border-white/10 font-mono text-[10px] space-y-1.5 text-muted bg-[#080b10]">
                      {msg.trace?.fullCommandStr && (
                        <div>
                          <div className="text-[9px] uppercase tracking-wider text-subtle pt-1.5">Command Dispatched:</div>
                          <div className="p-1 rounded bg-black/80 border border-white/10 text-cyan-300 break-all select-all">
                            {msg.trace.fullCommandStr}
                          </div>
                        </div>
                      )}

                      <div className="grid grid-cols-2 gap-1.5 text-[9.5px] pt-1">
                        <div>
                          <span className="text-subtle">Exit Code:</span>{" "}
                          <span className={msg.trace?.exitCode === 0 ? "text-emerald-400 font-bold" : "text-rose-400"}>
                            {msg.trace?.exitCode ?? 0}
                          </span>
                        </div>
                        <div>
                          <span className="text-subtle">Process Latency:</span>{" "}
                          <span className="text-fg">{msg.latencyMs || msg.trace?.latencyMs}ms</span>
                        </div>
                        <div>
                          <span className="text-subtle">Output Bytes:</span>{" "}
                          <span className="text-fg">{msg.trace?.stdoutBytes ?? msg.text.length} B</span>
                        </div>
                        <div>
                          <span className="text-subtle">Sandbox Target:</span>{" "}
                          <span className="text-accent">{msg.trace?.containerName || "aie-agent-sandbox"}</span>
                        </div>
                      </div>

                      {/* Step-by-Step Logs */}
                      {msg.trace?.stepLogs && msg.trace.stepLogs.length > 0 && (
                        <div className="pt-1.5 border-t border-white/5">
                          <div className="text-[9px] uppercase tracking-wider text-subtle mb-1">Process Lifecycle Logs:</div>
                          <div className="space-y-0.5 max-h-32 overflow-y-auto p-1.5 rounded bg-black/90 border border-white/5 text-[9px]">
                            {msg.trace.stepLogs.map((logLine, lIdx) => (
                              <div key={lIdx} className="leading-tight text-emerald-400/90 break-all">
                                {logLine}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {isLoading && (
          <div className="mr-auto items-start max-w-[90%]">
            <div className="flex items-center gap-1.5 mb-1 px-1">
              <span className="text-[10px] font-mono text-accent font-medium flex items-center gap-1">
                <RefreshCw className="size-2.5 animate-spin" />
                Antigravity Agent Processing...
              </span>
            </div>
            <div className="p-3 rounded-xl bg-bg-subtle border border-border/80 text-subtle text-xs flex items-center gap-2 rounded-bl-xs font-mono text-[11px]">
              <span className="size-1.5 rounded-full bg-accent animate-ping" />
              <span>Executing in sandbox: `agy --dangerously-skip-permissions`</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Drawer Input Footer */}
      <div className="p-3 border-t border-border bg-bg/90 backdrop-blur-md shrink-0 space-y-1.5">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Message Antigravity Agent..."
            disabled={isLoading}
            className="flex-1 rounded-xl border border-border bg-bg-subtle px-3 py-2 text-xs text-fg focus:border-accent focus:outline-none placeholder:text-subtle font-sans transition-colors"
          />
          <Button
            type="submit"
            size="sm"
            variant="primary"
            disabled={!input.trim() || isLoading}
            className="h-8 w-8 p-0 bg-accent hover:bg-accent/90 text-white rounded-xl shrink-0 cursor-pointer shadow-xs"
          >
            <Send className="size-3.5" />
          </Button>
        </form>

        <div className="flex items-center justify-between text-[10px] font-mono text-subtle/80 px-1">
          <span className="flex items-center gap-1 truncate">
            <Terminal className="size-2.5 text-accent" />
            <span>`agy --dangerously-skip-permissions`</span>
          </span>
          <span className="shrink-0">Enter to send</span>
        </div>
      </div>
    </div>
  );

  if (embedded) {
    return <div className="h-96 border border-border/80 rounded-xl overflow-hidden">{content}</div>;
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />

      {/* Slide-over Drawer: EXACTLY 1/4 screen width */}
      <div className="relative z-10 w-full sm:w-80 md:w-96 lg:w-[25vw] min-w-[320px] max-w-[400px] h-full shadow-2xl border-l border-border animate-in slide-in-from-right duration-200">
        {content}
      </div>
    </div>
  );
}
