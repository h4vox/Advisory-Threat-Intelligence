import { useState, useRef, useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Code2,
  Cpu,
  Download,
  ExternalLink,
  Filter,
  Flame,
  Globe,
  Key,
  Layers,
  Loader2,
  Play,
  Plug,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  Sparkles,
  Terminal,
  Trash2,
  X,
  Zap,
  Copy,
  FileText,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { AieAgentChatDrawer } from "@/components/aie-agent-chat-drawer";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/cn";
import {
  OFFICIAL_AGY_OAUTH_URL,
  generateAgyOAuthSession,
  generateAgyOAuthUrl,
  type AgyOAuthSession,
} from "@/lib/aie/marketplace-registry";
import {
  getMarketplaceData,
  installMarketplaceIntegration,
  uninstallMarketplaceIntegration,
  configureMarketplaceIntegration,
  setActiveAgentProvider,
  testIntegrationConnection,
  executeRealIntegrationInstall,
  detectLocalAgentSession,
  getAgentSandboxStatus,
  restartAgentSandbox,
  getAgentSandboxLogs,
  clearAgentSandboxLogs,
  getContainerDetailedMetrics,
  executeDiagnosticsCommand,
  type ContainerDetailedMetrics,
} from "@/lib/aie/server";
import type {
  CuratedResourceCatalogItem,
  IntegrationCategory,
  IntegrationItem,
  PlaybookBlockItem,
  PowerupItem,
} from "@/lib/aie/marketplace-types";

export const Route = createFileRoute("/marketplace")({
  component: MarketplacePage,
});

type TabType = "home" | "curated" | "response" | "powerups" | "playbooks";

function MarketplacePage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>("response");

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("All");
  const [statusFilter, setStatusFilter] = useState<string>("All");

  // Selected item for 1/4 width right details drawer ("half of the half")
  const [selectedIntegration, setSelectedIntegration] = useState<IntegrationItem | null>(null);

  // Drawer collapsible sections
  const [actionsExpanded, setActionsExpanded] = useState(true);
  const [connectorsExpanded, setConnectorsExpanded] = useState(true);
  const [modelsExpanded, setModelsExpanded] = useState(false);

  // Install / Configure Modal state
  const [configModalItem, setConfigModalItem] = useState<IntegrationItem | null>(null);
  const [isReconfigMode, setIsReconfigMode] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [authTokenInput, setAuthTokenInput] = useState("");
  const [selectedModelInput, setSelectedModelInput] = useState("");
  const [modalFeedback, setModalFeedback] = useState<string | null>(null);
  const [agyOAuthSession, setAgyOAuthSession] = useState<AgyOAuthSession | null>(null);

  // Live execution logs state
  const [realInstallLogs, setRealInstallLogs] = useState<string[]>([]);
  const [isLogsExpanded, setIsLogsExpanded] = useState(false);
  const [logFilter, setLogFilter] = useState<"ALL" | "INFO" | "EXEC" | "AUTH" | "STDOUT" | "ERRORS">("ALL");
  const [logSearchQuery, setLogSearchQuery] = useState("");
  const [isCopiedLogs, setIsCopiedLogs] = useState(false);
  const [autoScrollLogs, setAutoScrollLogs] = useState(true);
  const [drawerDiagnosticsExpanded, setDrawerDiagnosticsExpanded] = useState(false);
  const terminalBottomRef = useRef<HTMLDivElement>(null);

  // Uninstall confirmation modal
  const [uninstallConfirmItem, setUninstallConfirmItem] = useState<IntegrationItem | null>(null);

  // Test connection feedback
  const [testResult, setTestResult] = useState<{
    id: string;
    message: string;
    latencyMs?: number;
    success: boolean;
  } | null>(null);

  // Modal-specific connection test result
  const [modalTestResult, setModalTestResult] = useState<{
    message: string;
    latencyMs?: number;
    success: boolean;
  } | null>(null);

  // Query marketplace state
  const { data: marketplaceState, isLoading, refetch } = useQuery({
    queryKey: ["marketplace_state"],
    queryFn: () => getMarketplaceData(),
  });

  // Query local shell OAuth token session if available on host
  const { data: detectedLocalSession } = useQuery({
    queryKey: ["detected_local_agent_session"],
    queryFn: () => detectLocalAgentSession(),
  });

  // Query isolated agent sandbox runtime status
  const { data: sandboxStatus, refetch: refetchSandbox } = useQuery({
    queryKey: ["agent_sandbox_status"],
    queryFn: () => getAgentSandboxStatus(),
    refetchInterval: 12000,
  });

  // Query global live sandbox diagnostics logs
  const { data: sandboxLogsData, refetch: refetchLogs } = useQuery({
    queryKey: ["agent_sandbox_logs"],
    queryFn: () => getAgentSandboxLogs(),
    refetchInterval: 3000,
  });

  // Query live detailed container metrics & host telemetry
  const { data: containerMetrics, refetch: refetchMetrics } = useQuery({
    queryKey: ["container_detailed_metrics"],
    queryFn: () => getContainerDetailedMetrics(),
    refetchInterval: 4000,
  });

  // Clear sandbox logs mutation
  const clearLogsMutation = useMutation({
    mutationFn: () => clearAgentSandboxLogs(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent_sandbox_logs"] });
      setRealInstallLogs([]);
    },
  });

  // Interactive diagnostics probe command mutation
  const diagnosticsCommandMutation = useMutation({
    mutationFn: (command: "version" | "models" | "help" | "stats" | "token" | "ping") =>
      executeDiagnosticsCommand({ data: { command } }),
    onSuccess: (res) => {
      if (res.logs && res.logs.length > 0) {
        setRealInstallLogs((prev) => [...prev, ...res.logs]);
        setIsLogsExpanded(true);
      }
      queryClient.invalidateQueries({ queryKey: ["agent_sandbox_logs"] });
      queryClient.invalidateQueries({ queryKey: ["container_detailed_metrics"] });
    },
  });

  const integrations = marketplaceState?.integrations || [];
  const activeProviderId = marketplaceState?.activeProviderId || "agy_agent";
  const activeModel = marketplaceState?.activeModel || "AGY: gemini-3.8-flash-low";

  // Real installation mutation (executes real script, rm for reconfig, captures stdout/stderr)
  const realInstallMutation = useMutation({
    mutationFn: (data: {
      id: string;
      reconfig?: boolean;
      authToken?: string;
      apiKey?: string;
      selectedModel?: string;
    }) => executeRealIntegrationInstall({ data }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
      queryClient.invalidateQueries({ queryKey: ["detected_local_agent_session"] });
      if (res.logs && res.logs.length > 0) {
        setRealInstallLogs(res.logs);
        setIsLogsExpanded(true);
      }
      if (selectedIntegration?.id === res.id) {
        setSelectedIntegration(res.integration);
      }
      setModalFeedback(
        res.reconfigured
          ? "Re-configuration and fresh installation executed successfully!"
          : "Host installation executed and verified!"
      );
      setTimeout(() => setModalFeedback(null), 4000);
    },
    onError: (err) => {
      const errMsg = err instanceof Error ? err.message : String(err);
      setRealInstallLogs((prev) => [...prev, `[FATAL ERROR] ${errMsg}`]);
      setIsLogsExpanded(true);
      setModalFeedback(`Installation failed: ${errMsg}`);
    },
  });

  // Save / Update configuration mutation
  const configureMutation = useMutation({
    mutationFn: (data: { id: string; config: Record<string, any> }) =>
      configureMarketplaceIntegration({ data }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
      setConfigModalItem(null);
      if (selectedIntegration?.id === res.integration.id) {
        setSelectedIntegration(res.integration);
      }
      setModalFeedback("Configuration updated!");
      setTimeout(() => setModalFeedback(null), 3000);
    },
  });

  // Uninstall mutation
  const uninstallMutation = useMutation({
    mutationFn: (id: string) => uninstallMarketplaceIntegration({ data: { id } }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
      setUninstallConfirmItem(null);
      if (selectedIntegration?.id === res.id) {
        setSelectedIntegration((prev) =>
          prev ? { ...prev, status: "not_installed", config: undefined } : null
        );
      }
    },
  });

  // Set active agent mutation
  const setActiveMutation = useMutation({
    mutationFn: (data: { id: string; model: string }) =>
      setActiveAgentProvider({ data }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
    },
  });

  // Test connection mutation (for drawer)
  const testConnectionMutation = useMutation({
    mutationFn: (id: string) => testIntegrationConnection({ data: { id } }),
    onSuccess: (res) => {
      setTestResult(res);
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["agent_sandbox_logs"] });
      setTimeout(() => setTestResult(null), 6000);
    },
  });

  // Test connection mutation (for modal)
  const modalTestConnectionMutation = useMutation({
    mutationFn: (id: string) => testIntegrationConnection({ data: { id } }),
    onSuccess: (res) => {
      setModalTestResult(res);
      if (res.logs && res.logs.length > 0) {
        setRealInstallLogs(res.logs);
        setIsLogsExpanded(true);
      }
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["agent_sandbox_logs"] });
      setTimeout(() => setModalTestResult(null), 6000);
    },
  });

  // Restart agent sandbox mutation
  const restartSandboxMutation = useMutation({
    mutationFn: () => restartAgentSandbox(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent_sandbox_status"] });
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["agent_sandbox_logs"] });
    },
  });

  // Open Install / Configure / Re-Config modal
  const handleOpenConfigModal = (item: IntegrationItem, reconfig: boolean = false) => {
    setConfigModalItem(item);
    setIsReconfigMode(reconfig);
    setApiKeyInput(item.config?.apiKey || "");
    setAuthTokenInput(item.config?.authToken || "");
    setSelectedModelInput(item.config?.selectedModel || item.supportedModels[0] || "");
    setRealInstallLogs(item.config?.logs || []);
    setIsLogsExpanded(true);
    setModalFeedback(null);
    setModalTestResult(null);
    if (item.id === "agy_agent") {
      setAgyOAuthSession(generateAgyOAuthSession());
    }
  };

  // Filter active logs for the terminal viewer
  const displayedInstallLogs = realInstallLogs.filter((line) => {
    if (logSearchQuery.trim() !== "") {
      if (!line.toLowerCase().includes(logSearchQuery.toLowerCase())) {
        return false;
      }
    }
    if (logFilter === "ALL") return true;
    if (logFilter === "ERRORS") {
      return (
        line.includes("[ERROR]") ||
        line.includes("[STDERR]") ||
        line.toLowerCase().includes("fail") ||
        line.toLowerCase().includes("error")
      );
    }
    return line.includes(`[${logFilter}]`);
  });

  const handleCopyLogs = (logsToCopy: string[]) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(logsToCopy.join("\n"));
      setIsCopiedLogs(true);
      setTimeout(() => setIsCopiedLogs(false), 2000);
    }
  };

  const handleDownloadLogs = (logsToDownload: string[], filename = "aie-install-debug.log") => {
    const blob = new Blob([logsToDownload.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const isPendingOperation =
    realInstallMutation.isPending ||
    modalTestConnectionMutation.isPending ||
    testConnectionMutation.isPending;

  useEffect(() => {
    if (isPendingOperation && sandboxLogsData?.logs && configModalItem) {
      const recentFormatted = sandboxLogsData.logs
        .slice(-25)
        .map((l) => `${l.formattedTime} [${l.level.padEnd(5)}] [${l.category.toUpperCase()}] ${l.message}`);
      setRealInstallLogs((prev) => {
        const existingSet = new Set(prev);
        const next = [...prev];
        for (const line of recentFormatted) {
          if (!existingSet.has(line)) {
            next.push(line);
            existingSet.add(line);
          }
        }
        return next;
      });
      setIsLogsExpanded(true);
    }
  }, [isPendingOperation, sandboxLogsData, configModalItem]);

  const handleExportDiagnosticBundle = () => {
    const bundle = {
      exportedAt: new Date().toISOString(),
      containerMetrics: containerMetrics || null,
      sandboxStatus: sandboxStatus || null,
      activeProvider: {
        id: activeProviderId,
        model: activeModel,
      },
      integrations: integrations.map((i) => ({
        id: i.id,
        name: i.name,
        status: i.status,
        version: i.version,
        config: i.config,
      })),
      recentLogs: sandboxLogsData?.logs || [],
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aie-diagnostic-bundle-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  useEffect(() => {
    if (autoScrollLogs && isLogsExpanded && configModalItem) {
      terminalBottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [displayedInstallLogs, autoScrollLogs, isLogsExpanded, configModalItem]);

  // Filtered integrations for Response Integration tab
  const filteredIntegrations = integrations.filter((item) => {
    const matchesSearch =
      searchQuery === "" ||
      item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.provider.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesCategory =
      categoryFilter === "All" || item.category === categoryFilter;

    const matchesStatus =
      statusFilter === "All" ||
      (statusFilter === "Installed" && item.status === "installed") ||
      (statusFilter === "Available" && item.status !== "installed");

    return matchesSearch && matchesCategory && matchesStatus;
  });

  // Check if mandatory token is missing for install or re-config
  const isMandatoryAuthMissing =
    (isReconfigMode || configModalItem?.status !== "installed") &&
    authTokenInput.trim() === "" &&
    (configModalItem?.type === "cli_agent" || configModalItem?.id === "agy_agent");

  return (
    <AppShell flush>
      <div className="h-full flex flex-col overflow-hidden bg-bg text-fg">
        {/* ========================================================================= */}
        {/* 1. 100% STATIC TOP HEADER & NAVIGATION TABS (NEVER SCROLLS)               */}
        {/* ========================================================================= */}
        <header className="shrink-0 border-b border-border bg-bg/85 backdrop-blur-xl px-6 pt-5 pb-0 z-20">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-accent/10 border border-accent/20 text-accent">
                  <Cpu className="size-5" />
                </div>
                <h1 className="text-xl font-semibold tracking-tight">Marketplace & External Integrations</h1>
                <Badge className="text-xs bg-bg-subtle text-muted border border-border">
                  Ecosystem Hub
                </Badge>
              </div>
              <p className="text-xs text-subtle mt-1 max-w-2xl">
                Install, configure, and manage external AI agents, direct API endpoints, curated adversary feeds,
                and execution blocks for threat intelligence and purple-team simulation.
              </p>
            </div>

            <div className="flex items-center gap-3 flex-wrap">
              {/* Agent Sandbox Environment Indicator */}
              <div className="flex items-center gap-3 bg-bg-elevated/90 backdrop-blur-sm border border-border px-3.5 py-2 rounded-xl shadow-xs shrink-0">
                <div className="relative flex items-center justify-center">
                  <div
                    className={cn(
                      "size-2.5 rounded-full",
                      sandboxStatus?.runtime === "docker" && sandboxStatus?.containerRunning
                        ? "bg-cyan-400 animate-pulse"
                        : sandboxStatus?.isReady
                          ? "bg-emerald-500"
                          : "bg-amber-500"
                    )}
                  />
                  <div
                    className={cn(
                      "absolute size-4 rounded-full",
                      sandboxStatus?.runtime === "docker" && sandboxStatus?.containerRunning
                        ? "bg-cyan-400/25"
                        : sandboxStatus?.isReady
                          ? "bg-emerald-500/20"
                          : "bg-amber-500/20"
                    )}
                  />
                </div>
                <div className="text-xs">
                  <div className="text-[10px] uppercase font-mono text-subtle tracking-wider flex items-center gap-1.5">
                    <span>Execution Sandbox</span>
                    {sandboxStatus?.runtime === "docker" && (
                      <span className="text-[9px] px-1 py-0.2 rounded bg-cyan-500/15 text-cyan-400 font-bold border border-cyan-500/20">
                        ISOLATED
                      </span>
                    )}
                  </div>
                  <div className="font-medium text-fg flex items-center gap-1.5">
                    <span className="font-mono text-[11px] text-accent">
                      {sandboxStatus?.runtime === "docker"
                        ? `${sandboxStatus.containerName} (Active)`
                        : sandboxStatus?.runtime === "wsl"
                          ? "WSL Linux Bridge"
                          : sandboxStatus?.runtime === "native"
                            ? "Host Native Runtime"
                            : "Sandbox Standby"}
                    </span>
                    <button
                      type="button"
                      onClick={() => restartSandboxMutation.mutate()}
                      disabled={restartSandboxMutation.isPending}
                      title="Restart Agent Sandbox Container"
                      className="p-1 rounded hover:bg-bg-subtle text-subtle hover:text-fg transition-colors cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw
                        className={cn("size-3", restartSandboxMutation.isPending && "animate-spin text-accent")}
                      />
                    </button>
                  </div>
                </div>
              </div>

              {/* Active AI Agent Indicator Badge */}
              <div className="flex items-center gap-3 bg-bg-elevated/90 backdrop-blur-sm border border-border px-3.5 py-2 rounded-xl shadow-xs shrink-0">
                <div className="relative flex items-center justify-center">
                  <div className="size-2.5 rounded-full bg-emerald-500 animate-pulse" />
                  <div className="absolute size-4 rounded-full bg-emerald-500/20" />
                </div>
                <div className="text-xs">
                  <div className="text-[10px] uppercase font-mono text-subtle tracking-wider">Active AI Agent</div>
                  <div className="font-medium text-fg flex items-center gap-1.5">
                    <span>{integrations.find((x) => x.id === activeProviderId)?.name || "Antigravity AGY Agent"}</span>
                    <span className="font-mono text-[11px] text-accent">({activeModel})</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Navigation Columns / Tabs - "Core AI" badge removed from Response Integration */}
          <div className="flex items-center gap-1 border-b border-border/60 -mb-px overflow-x-auto select-none">
            <button
              onClick={() => setActiveTab("home")}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap",
                activeTab === "home"
                  ? "border-accent text-accent bg-accent/5 rounded-t-md"
                  : "border-transparent text-muted hover:text-fg hover:bg-bg-subtle"
              )}
            >
              <Activity className="size-3.5" />
              Home
            </button>

            <button
              onClick={() => setActiveTab("curated")}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap",
                activeTab === "curated"
                  ? "border-accent text-accent bg-accent/5 rounded-t-md"
                  : "border-transparent text-muted hover:text-fg hover:bg-bg-subtle"
              )}
            >
              <Globe className="size-3.5" />
              Curated Resources
              <Badge className="text-[10px] py-0 px-1.5 ml-1 border border-border">
                {marketplaceState?.curatedResources?.length || 4}
              </Badge>
            </button>

            {/* RESPONSE INTEGRATION TAB - CLEAN TITLE WITHOUT CORE AI BADGE */}
            <button
              onClick={() => setActiveTab("response")}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap",
                activeTab === "response"
                  ? "border-accent text-accent bg-accent/5 rounded-t-md"
                  : "border-transparent text-muted hover:text-fg hover:bg-bg-subtle"
              )}
            >
              <Bot className="size-3.5" />
              Response Integration
            </button>

            <button
              onClick={() => setActiveTab("powerups")}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap",
                activeTab === "powerups"
                  ? "border-accent text-accent bg-accent/5 rounded-t-md"
                  : "border-transparent text-muted hover:text-fg hover:bg-bg-subtle"
              )}
            >
              <Zap className="size-3.5" />
              Powerups & Exporters
            </button>

            <button
              onClick={() => setActiveTab("playbooks")}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap",
                activeTab === "playbooks"
                  ? "border-accent text-accent bg-accent/5 rounded-t-md"
                  : "border-transparent text-muted hover:text-fg hover:bg-bg-subtle"
              )}
            >
              <Layers className="size-3.5" />
              Playbook Blocks
            </button>
          </div>
        </header>

        {/* ========================================================================= */}
        {/* TAB 1: RESPONSE INTEGRATION (STATIC TOOLBAR + SCROLLABLE CARDS GRID)       */}
        {/* ========================================================================= */}
        {activeTab === "response" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* 100% STATIC CATEGORIES & SEARCH TOOLBAR WITH TRANSLUCENT BACKDROP */}
            <div className="shrink-0 z-10 bg-bg/80 backdrop-blur-lg border-b border-border/60 px-6 py-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                {/* Category Filter Pills */}
                <div className="flex items-center gap-1.5 overflow-x-auto">
                  <span className="text-[11px] font-medium text-subtle mr-1 flex items-center gap-1 shrink-0">
                    <Filter className="size-3" /> Category:
                  </span>
                  {["All", "Intelligence", "Analysis", "Automation"].map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setCategoryFilter(cat)}
                      className={cn(
                        "text-xs px-3 py-1 rounded-lg transition-all cursor-pointer font-medium whitespace-nowrap",
                        categoryFilter === cat
                          ? "bg-accent text-white shadow-xs"
                          : "bg-bg-subtle text-muted hover:text-fg hover:bg-border/60"
                      )}
                    >
                      {cat}
                    </button>
                  ))}
                </div>

                {/* Status & Search Input */}
                <div className="flex items-center gap-2.5 shrink-0">
                  <div className="flex items-center gap-1 bg-bg-subtle p-0.5 rounded-lg border border-border">
                    {["All", "Installed", "Available"].map((st) => (
                      <button
                        key={st}
                        onClick={() => setStatusFilter(st)}
                        className={cn(
                          "text-[11px] px-2.5 py-1 rounded-md transition-all cursor-pointer",
                          statusFilter === st
                            ? "bg-bg-elevated text-fg font-medium shadow-xs"
                            : "text-subtle hover:text-fg"
                        )}
                      >
                        {st}
                      </button>
                    ))}
                  </div>

                  <div className="relative w-full sm:w-60">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-subtle" />
                    <Input
                      placeholder="Filter integrations..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-8 h-8 text-xs bg-bg-subtle"
                    />
                    {searchQuery && (
                      <button
                        onClick={() => setSearchQuery("")}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-subtle hover:text-fg"
                      >
                        <X className="size-3" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* SCROLLABLE CARDS GRID CONTAINER: ONLY THIS AREA SCROLLS */}
            <div className="flex-1 overflow-y-auto px-6 py-5 pb-24 md:pb-8">
              {/* Feedback Alert if tested */}
              {testResult && (
                <div
                  className={cn(
                    "mb-4 p-3.5 rounded-xl border text-xs flex items-center justify-between transition-all",
                    testResult.success
                      ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                      : "bg-red-500/10 border-red-500/30 text-red-400"
                  )}
                >
                  <div className="flex items-center gap-2">
                    {testResult.success ? (
                      <CheckCircle2 className="size-4 shrink-0 text-emerald-400" />
                    ) : (
                      <AlertCircle className="size-4 shrink-0 text-red-400" />
                    )}
                    <span>{testResult.message}</span>
                  </div>
                  {testResult.latencyMs && (
                    <Badge className="text-[10px] font-mono border border-emerald-500/30 text-emerald-400">
                      Latency: {testResult.latencyMs}ms
                    </Badge>
                  )}
                </div>
              )}

              {/* 4 IN A ROW CONTAINER GRID */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {filteredIntegrations.map((item) => {
                  const isInstalled = item.status === "installed";
                  const isActive = activeProviderId === item.id;

                  return (
                    <div
                      key={item.id}
                      className={cn(
                        "group relative flex flex-col justify-between rounded-xl border bg-bg-elevated p-4.5 transition-all duration-200 hover:shadow-md hover:border-accent/40",
                        isActive
                          ? "border-emerald-500/50 shadow-xs ring-1 ring-emerald-500/20 bg-emerald-500/[0.02]"
                          : isInstalled
                          ? "border-border"
                          : "border-border/70 opacity-90"
                      )}
                    >
                      {/* Card Header: Category & Top-Right Status Badge */}
                      <div>
                        <div className="flex items-start justify-between gap-2 mb-3">
                          <span className="text-[10px] font-mono uppercase tracking-wider text-accent font-medium px-2 py-0.5 rounded-md bg-accent/10">
                            {item.category}
                          </span>

                          {/* Top-Right Status Badge */}
                          <div className="flex items-center gap-1">
                            {isActive ? (
                              <Badge className="bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] px-2 py-0.5 font-medium flex items-center gap-1">
                                <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
                                Active
                              </Badge>
                            ) : isInstalled ? (
                              <Badge className="bg-blue-500/15 text-blue-400 border border-blue-500/30 text-[10px] px-2 py-0.5 font-medium flex items-center gap-1">
                                <Check className="size-3" />
                                Installed
                              </Badge>
                            ) : (
                              <Badge className="text-subtle text-[10px] px-2 py-0.5 border border-border">
                                Available
                              </Badge>
                            )}
                          </div>
                        </div>

                        {/* Title, Icon & Version */}
                        <div className="flex items-center gap-2.5 mb-2">
                          <div className="p-2 rounded-lg bg-bg-subtle border border-border text-fg group-hover:text-accent transition-colors shrink-0">
                            {item.type === "cli_agent" ? (
                              <Terminal className="size-4" />
                            ) : (
                              <Sparkles className="size-4" />
                            )}
                          </div>
                          <div className="min-w-0">
                            <h3 className="text-sm font-semibold text-fg truncate group-hover:text-accent transition-colors">
                              {item.name}
                            </h3>
                            <div className="flex items-center gap-1.5 text-[11px] text-subtle">
                              <span>{item.provider}</span>
                              <span>·</span>
                              <span className="font-mono text-[10px]">{item.version}</span>
                            </div>
                          </div>
                        </div>

                        {/* Description */}
                        <p className="text-xs text-muted line-clamp-3 leading-relaxed mb-3">
                          {item.description}
                        </p>

                        {/* Tags */}
                        <div className="flex flex-wrap gap-1 mb-4">
                          {item.tags.slice(0, 3).map((tag) => (
                            <span
                              key={tag}
                              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg-subtle text-subtle border border-border/50"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Card Bottom: EXACTLY TWO BUTTONS AT BOTTOM RIGHT */}
                      <div className="pt-3 border-t border-border/60 flex items-center justify-end gap-2">
                        {/* Button 1: Details (opens 1/4 screen drawer) */}
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => setSelectedIntegration(item)}
                          className="text-xs h-7.5 px-3 gap-1.5"
                        >
                          Details
                        </Button>

                        {/* Button 2: Install (if not installed) OR Configure (if already installed) */}
                        {isInstalled ? (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => handleOpenConfigModal(item, false)}
                            className="text-xs h-7.5 px-3 gap-1.5 font-medium border-accent/30 hover:border-accent"
                          >
                            <Settings2 className="size-3 text-accent" />
                            Configure
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            variant="primary"
                            onClick={() => handleOpenConfigModal(item, false)}
                            className="text-xs h-7.5 px-3 gap-1.5 font-medium bg-accent hover:bg-accent/90 text-white shadow-xs"
                          >
                            <Download className="size-3" />
                            Install
                          </Button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {filteredIntegrations.length === 0 && (
                <div className="text-center py-16 border border-dashed border-border rounded-xl">
                  <Cpu className="size-8 text-subtle mx-auto mb-2 opacity-50" />
                  <div className="text-sm font-medium text-fg">No integrations match your filters</div>
                  <div className="text-xs text-subtle mt-1">Try resetting the category or search query.</div>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => {
                      setCategoryFilter("All");
                      setStatusFilter("All");
                      setSearchQuery("");
                    }}
                    className="mt-3 text-xs"
                  >
                    Reset Filters
                  </Button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: CURATED RESOURCES (STATIC TOOLBAR + SCROLLABLE CONTENT)             */}
        {/* ========================================================================= */}
        {activeTab === "curated" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="shrink-0 z-10 bg-bg/80 backdrop-blur-lg border-b border-border/60 px-6 py-3.5 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-fg">Curated Threat Intelligence Feeds</h2>
                <p className="text-xs text-subtle mt-0.5">
                  Pre-vetted, high-fidelity security research blogs, incident timelines, and regulatory advisory feeds.
                </p>
              </div>
              <Badge className="text-xs border border-border">
                {marketplaceState?.curatedResources?.length || 4} Feeds Configured
              </Badge>
            </div>

            <div className="flex-1 overflow-y-auto px-6 py-5 pb-24 md:pb-8">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(marketplaceState?.curatedResources || []).map((res) => (
                  <div
                    key={res.id}
                    className="border border-border rounded-xl bg-bg-elevated p-4.5 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-mono uppercase text-accent bg-accent/10 px-2 py-0.5 rounded">
                          {res.category}
                        </span>
                        <Badge className="text-[10px] border border-emerald-500/30 text-emerald-400">
                          Trust Score: {res.trustScore}%
                        </Badge>
                      </div>
                      <h3 className="text-sm font-medium text-fg">{res.name}</h3>
                      <div className="text-[11px] text-subtle mb-2">Provider: {res.provider} · Format: {res.format}</div>
                      <p className="text-xs text-muted leading-relaxed mb-3">{res.description}</p>
                      <div className="font-mono text-[11px] text-accent/80 bg-bg-subtle p-2 rounded border border-border truncate mb-3">
                        {res.endpointUrl}
                      </div>
                    </div>
                    <div className="flex items-center justify-between pt-3 border-t border-border/60">
                      <div className="flex gap-1">
                        {res.tags.map((t) => (
                          <span key={t} className="text-[10px] font-mono px-1.5 py-0.5 bg-bg-subtle text-subtle rounded">
                            {t}
                          </span>
                        ))}
                      </div>
                      <Badge className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px]">
                        Active Ingest
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 3: POWERUPS & EXPORTERS (STATIC TOOLBAR + SCROLLABLE CONTENT)          */}
        {/* ========================================================================= */}
        {activeTab === "powerups" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="shrink-0 z-10 bg-bg/80 backdrop-blur-lg border-b border-border/60 px-6 py-3.5 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-fg">Automation Powerups & Exporters</h2>
                <p className="text-xs text-subtle mt-0.5">
                  Extend AIE capabilities with custom rule generators, incident response webhooks, and bundle serializers.
                </p>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto px-6 py-5 pb-24 md:pb-8">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {(marketplaceState?.powerups || []).map((pwr) => (
                  <div
                    key={pwr.id}
                    className="border border-border rounded-xl bg-bg-elevated p-4.5 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-mono uppercase text-accent bg-accent/10 px-2 py-0.5 rounded">
                          {pwr.category}
                        </span>
                        <Badge
                          className={cn(
                            "text-[10px]",
                            pwr.status === "installed"
                              ? "bg-blue-500/15 text-blue-400 border-blue-500/30"
                              : "bg-bg-subtle text-subtle"
                          )}
                        >
                          {pwr.status === "installed" ? "Installed" : "Available"}
                        </Badge>
                      </div>
                      <h3 className="text-sm font-medium text-fg">{pwr.name}</h3>
                      <div className="text-[11px] text-subtle mb-2">Author: {pwr.author} · {pwr.version}</div>
                      <p className="text-xs text-muted leading-relaxed mb-3">{pwr.description}</p>
                    </div>
                    <div className="pt-3 border-t border-border/60 flex items-center justify-between">
                      <div className="flex gap-1">
                        {pwr.tags.map((t) => (
                          <span key={t} className="text-[10px] font-mono px-1.5 py-0.5 bg-bg-subtle text-subtle rounded">
                            {t}
                          </span>
                        ))}
                      </div>
                      <Button size="sm" variant="secondary" className="text-xs h-7">
                        {pwr.status === "installed" ? "Configure" : "Enable"}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 4: PLAYBOOK BLOCKS (STATIC TOOLBAR + SCROLLABLE CONTENT)               */}
        {/* ========================================================================= */}
        {activeTab === "playbooks" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="shrink-0 z-10 bg-bg/80 backdrop-blur-lg border-b border-border/60 px-6 py-3.5 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-fg">Adversary Emulation Playbook Blocks</h2>
                <p className="text-xs text-subtle mt-0.5">
                  Modular purple-team scenario components, automated attack chain runners, and defense verification blocks.
                </p>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto px-6 py-5 pb-24 md:pb-8">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {(marketplaceState?.playbooks || []).map((pb) => (
                  <div
                    key={pb.id}
                    className="border border-border rounded-xl bg-bg-elevated p-4.5 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-mono uppercase text-accent bg-accent/10 px-2 py-0.5 rounded">
                          {pb.framework}
                        </span>
                        <Badge
                          className={cn(
                            "text-[10px]",
                            pb.difficulty === "Advanced"
                              ? "text-red-400 border-red-500/30"
                              : "text-amber-400 border-amber-500/30"
                          )}
                        >
                          {pb.difficulty}
                        </Badge>
                      </div>
                      <h3 className="text-sm font-medium text-fg">{pb.name}</h3>
                      <div className="text-[11px] text-subtle mb-2">
                        Steps: {pb.stepsCount} · Tactics: {pb.tactics.join(", ")}
                      </div>
                      <p className="text-xs text-muted leading-relaxed mb-3">{pb.description}</p>
                      <div className="flex flex-wrap gap-1 mb-3">
                        {pb.techniques.map((t) => (
                          <span key={t} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent/10 text-accent">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="pt-3 border-t border-border/60 flex items-center justify-end">
                      <Button size="sm" variant="secondary" className="text-xs h-7 gap-1">
                        <Play className="size-3 text-accent" /> Run Block
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 5: HOME TAB                                                           */}
        {/* ========================================================================= */}
        {activeTab === "home" && (
          <div className="flex-1 overflow-y-auto px-6 py-6 pb-24 md:pb-8 space-y-6">
            <div className="rounded-2xl border border-border bg-gradient-to-br from-bg-elevated to-bg-subtle p-6">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div>
                  <Badge tone="accent" className="mb-2 text-white">
                    Ecosystem Architecture
                  </Badge>
                  <h2 className="text-lg font-semibold text-fg">Modular AI Agent & Emulation Ecosystem</h2>
                  <p className="text-xs text-subtle mt-1 max-w-xl">
                    AIE is designed from the ground up to support interchangeable AI agents, automated discovery
                    connectors, and modular attack-flow playbooks without hard vendor lock-in.
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => setActiveTab("response")}
                  className="gap-2 bg-accent text-white"
                >
                  <Bot className="size-3.5" /> Manage AI Integrations
                </Button>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-border/60">
                <div className="p-3 bg-bg/50 rounded-xl border border-border">
                  <div className="text-[10px] text-subtle uppercase font-mono">Installed Agents</div>
                  <div className="text-lg font-bold text-fg mt-1">
                    {integrations.filter((x) => x.status === "installed").length} / {integrations.length}
                  </div>
                </div>
                <div className="p-3 bg-bg/50 rounded-xl border border-border">
                  <div className="text-[10px] text-subtle uppercase font-mono">Active Provider</div>
                  <div className="text-sm font-semibold text-accent mt-1 truncate">
                    {integrations.find((x) => x.id === activeProviderId)?.name || "Antigravity AGY Agent"}
                  </div>
                </div>
                <div className="p-3 bg-bg/50 rounded-xl border border-border">
                  <div className="text-[10px] text-subtle uppercase font-mono">Curated Feeds</div>
                  <div className="text-lg font-bold text-fg mt-1">
                    {marketplaceState?.curatedResources?.length || 4} Active
                  </div>
                </div>
                <div className="p-3 bg-bg/50 rounded-xl border border-border">
                  <div className="text-[10px] text-subtle uppercase font-mono">Playbook Blocks</div>
                  <div className="text-lg font-bold text-fg mt-1">
                    {marketplaceState?.playbooks?.length || 3} Ready
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* RIGHT DETAILS DRAWER: 1/4 SCREEN WIDTH ("HALF OF THE HALF")               */}
        {/* ========================================================================= */}
        {selectedIntegration && (
          <div className="fixed inset-0 z-50 flex justify-end">
            {/* Subtle Backdrop */}
            <div
              className="fixed inset-0 bg-black/50 backdrop-blur-xs transition-opacity"
              onClick={() => setSelectedIntegration(null)}
            />

            {/* Drawer Container: EXACTLY 1/4 SCREEN WIDTH (w-full sm:w-80 md:w-96 lg:w-[25vw] min-w-[320px] max-w-[400px]) */}
            <div className="relative w-full sm:w-80 md:w-96 lg:w-[25vw] min-w-[320px] max-w-[400px] h-full bg-bg-elevated/95 backdrop-blur-2xl border-l border-border/80 shadow-2xl flex flex-col z-10 animate-in slide-in-from-right duration-200">
              {/* Drawer Header */}
              <div className="p-4 border-b border-border flex items-start justify-between gap-3 bg-bg/60 shrink-0">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="p-2 rounded-lg bg-bg-subtle border border-border text-accent shrink-0">
                    {selectedIntegration.type === "cli_agent" ? (
                      <Terminal className="size-4" />
                    ) : (
                      <Sparkles className="size-4" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <h2 className="text-sm font-semibold text-fg truncate">{selectedIntegration.name}</h2>
                    <div className="flex items-center gap-1.5 text-[11px] text-subtle mt-0.5">
                      <span>{selectedIntegration.provider}</span>
                      <span>·</span>
                      <span className="font-mono text-[10px] text-accent">{selectedIntegration.version}</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => setSelectedIntegration(null)}
                  className="p-1.5 rounded-lg text-subtle hover:text-fg hover:bg-bg-subtle transition-colors cursor-pointer shrink-0"
                >
                  <X className="size-4" />
                </button>
              </div>

              {/* Drawer Body (Scrollable inside drawer) */}
              <div className="flex-1 p-4 overflow-y-auto space-y-4 text-xs">
                {/* Status Bar */}
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-bg-subtle border border-border/70">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] text-subtle">Status:</span>
                    {selectedIntegration.status === "installed" ? (
                      <Badge className="bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px]">
                        Installed
                      </Badge>
                    ) : (
                      <Badge className="text-subtle text-[10px] border border-border">
                        Available
                      </Badge>
                    )}
                  </div>
                  {activeProviderId === selectedIntegration.id ? (
                    <Badge className="bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] flex items-center gap-1">
                      <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      Active Provider
                    </Badge>
                  ) : null}
                </div>

                {/* Sandbox Execution Architecture (For CLI & Automated Agents) */}
                {selectedIntegration.type === "cli_agent" && (
                  <div className="p-3 rounded-lg bg-bg-elevated border border-border space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="font-semibold text-fg flex items-center gap-1.5 text-xs">
                        <Terminal className="size-3.5 text-accent" />
                        <span>Execution Sandbox</span>
                      </div>
                      <Badge className="text-[9px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        {sandboxStatus?.runtime === "docker"
                          ? "ISOLATED DOCKER"
                          : sandboxStatus?.runtime === "wsl"
                            ? "WSL BRIDGE"
                            : "HOST NATIVE"}
                      </Badge>
                    </div>

                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex items-center justify-between text-subtle">
                        <span>Runtime Target:</span>
                        <span className="font-mono text-fg">
                          {sandboxStatus?.containerName || "aie-agent-sandbox"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-subtle">
                        <span>Binary Path:</span>
                        <span className="font-mono text-fg text-[10px]">
                          {sandboxStatus?.binaryPath || "/usr/local/bin/agy"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-subtle">
                        <span>Container Status:</span>
                        <span className="font-medium text-emerald-400 flex items-center gap-1">
                          <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
                          {sandboxStatus?.containerRunning ? "Running (Healthy)" : "Standby / Ready"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-subtle">
                        <span>Persistence Vault:</span>
                        <span className="font-mono text-fg text-[10px]">
                          aie-agent-vault (Isolated)
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Collapsible: Live Diagnostics & Sandbox Logs */}
                {selectedIntegration.type === "cli_agent" && (
                  <div className="border border-border/80 rounded-lg bg-bg-subtle/40 overflow-hidden">
                    <button
                      type="button"
                      onClick={() => setDrawerDiagnosticsExpanded(!drawerDiagnosticsExpanded)}
                      className="w-full flex items-center justify-between p-2.5 text-xs font-semibold text-fg hover:bg-bg-subtle transition-colors cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-1.5">
                        <Terminal className="size-3.5 text-cyan-400" />
                        <span>Live Sandbox Diagnostics ({sandboxLogsData?.count || 0})</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-subtle font-mono">
                          {sandboxStatus?.runtime === "docker" ? "Docker Daemon" : "Host Runtime"}
                        </span>
                        {drawerDiagnosticsExpanded ? (
                          <ChevronDown className="size-3.5 text-subtle" />
                        ) : (
                          <ChevronRight className="size-3.5 text-subtle" />
                        )}
                      </div>
                    </button>

                    {drawerDiagnosticsExpanded && (
                      <div className="p-3 pt-0 border-t border-border/50 space-y-2 bg-[#0c1017]">
                        <div className="flex items-center justify-between text-[10px] pt-2 text-subtle font-mono border-b border-white/5 pb-1.5">
                          <span className="flex items-center gap-1.5">
                            <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
                            Live Telemetry Stream
                          </span>
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => {
                                if (sandboxLogsData?.logs) {
                                  const text = sandboxLogsData.logs
                                    .map(
                                      (l) =>
                                        `${l.formattedTime} [${l.level.padEnd(5)}] [${l.category.toUpperCase()}] ${l.message}`
                                    )
                                    .join("\n");
                                  handleCopyLogs([text]);
                                }
                              }}
                              className="text-cyan-400 hover:underline cursor-pointer flex items-center gap-1"
                              title="Copy live telemetry to clipboard"
                            >
                              <Copy className="size-2.5" />
                              Copy
                            </button>
                            <span>·</span>
                            <button
                              type="button"
                              onClick={() => refetchLogs()}
                              className="text-accent hover:underline cursor-pointer flex items-center gap-1"
                            >
                              <RefreshCw className="size-2.5" />
                              Refresh
                            </button>
                            <span>·</span>
                            <button
                              type="button"
                              onClick={() => clearLogsMutation.mutate()}
                              className="text-rose-400 hover:underline cursor-pointer"
                            >
                              Clear
                            </button>
                          </div>
                        </div>
                        <div className="font-mono text-[10px] space-y-1 max-h-48 overflow-y-auto pr-1">
                          {sandboxLogsData?.logs && sandboxLogsData.logs.length > 0 ? (
                            sandboxLogsData.logs.slice(-40).map((log) => (
                              <div key={log.id} className="leading-snug break-all flex items-start gap-1.5 text-muted hover:text-fg">
                                <span className="text-subtle/70 shrink-0 select-none">{log.formattedTime.slice(12, 23)}</span>
                                <span
                                  className={cn(
                                    "px-1 py-0.2 rounded text-[8.5px] shrink-0 font-bold uppercase",
                                    log.level === "EXEC" && "bg-purple-500/20 text-purple-300 border border-purple-500/30",
                                    log.level === "AUTH" && "bg-amber-500/20 text-amber-300 border border-amber-500/30",
                                    log.level === "INFO" && "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30",
                                    log.level === "STDOUT" && "bg-green-500/20 text-green-300 border border-green-500/30",
                                    (log.level === "ERROR" || log.level === "STDERR") && "bg-rose-500/20 text-rose-300 border border-rose-500/30",
                                    log.level === "DEBUG" && "bg-blue-500/20 text-blue-300 border border-blue-500/30",
                                    log.level === "WARN" && "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30"
                                  )}
                                >
                                  {log.level}
                                </span>
                                <span className="text-fg/90">{log.message}</span>
                              </div>
                            ))
                          ) : (
                            <div className="text-subtle py-3 text-center text-xs">No live telemetry captured yet.</div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Overview */}
                <div>
                  <h4 className="text-[10px] uppercase font-mono tracking-wider text-subtle mb-1 font-semibold">
                    Overview
                  </h4>
                  <p className="text-xs text-muted leading-relaxed">
                    {selectedIntegration.overview || selectedIntegration.description}
                  </p>
                </div>

                {/* Collapsible: Supported Actions */}
                <div className="border border-border/80 rounded-lg bg-bg-subtle/40 overflow-hidden">
                  <button
                    onClick={() => setActionsExpanded(!actionsExpanded)}
                    className="w-full flex items-center justify-between p-2.5 text-xs font-semibold text-fg hover:bg-bg-subtle transition-colors cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-1.5">
                      <Zap className="size-3.5 text-accent" />
                      <span>Actions ({selectedIntegration.actions.length})</span>
                    </div>
                    {actionsExpanded ? <ChevronDown className="size-3.5 text-subtle" /> : <ChevronRight className="size-3.5 text-subtle" />}
                  </button>

                  {actionsExpanded && (
                    <div className="p-2.5 pt-0 space-y-1.5 border-t border-border/50">
                      {selectedIntegration.actions.map((act) => (
                        <div key={act.id} className="p-2 rounded-md bg-bg-elevated border border-border/60">
                          <div className="font-medium text-fg text-xs flex items-center gap-1.5">
                            <span className="size-1.5 rounded-full bg-accent" />
                            {act.name}
                          </div>
                          <div className="text-[11px] text-subtle mt-0.5 pl-3 leading-snug">
                            {act.description}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Collapsible: Connectors & Protocols */}
                <div className="border border-border/80 rounded-lg bg-bg-subtle/40 overflow-hidden">
                  <button
                    onClick={() => setConnectorsExpanded(!connectorsExpanded)}
                    className="w-full flex items-center justify-between p-2.5 text-xs font-semibold text-fg hover:bg-bg-subtle transition-colors cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-1.5">
                      <Plug className="size-3.5 text-accent" />
                      <span>Connectors & Auth Protocol</span>
                    </div>
                    {connectorsExpanded ? <ChevronDown className="size-3.5 text-subtle" /> : <ChevronRight className="size-3.5 text-subtle" />}
                  </button>

                  {connectorsExpanded && (
                    <div className="p-2.5 pt-0 space-y-1.5 border-t border-border/50">
                      {selectedIntegration.connectors.map((conn, i) => (
                        <div key={i} className="p-2 rounded-md bg-bg-elevated border border-border/60">
                          <div className="font-medium text-fg text-xs flex items-center justify-between">
                            <span>{conn.label}</span>
                            <Badge className="text-[10px] font-mono border border-border">
                              {conn.type}
                            </Badge>
                          </div>
                          <div className="text-[11px] text-subtle mt-1 leading-snug">
                            {conn.description}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Collapsible: Supported Models */}
                <div className="border border-border/80 rounded-lg bg-bg-subtle/40 overflow-hidden">
                  <button
                    onClick={() => setModelsExpanded(!modelsExpanded)}
                    className="w-full flex items-center justify-between p-2.5 text-xs font-semibold text-fg hover:bg-bg-subtle transition-colors cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-1.5">
                      <Cpu className="size-3.5 text-accent" />
                      <span>Supported Models ({selectedIntegration.supportedModels.length})</span>
                    </div>
                    {modelsExpanded ? <ChevronDown className="size-3.5 text-subtle" /> : <ChevronRight className="size-3.5 text-subtle" />}
                  </button>

                  {modelsExpanded && (
                    <div className="p-2.5 pt-0 space-y-1 border-t border-border/50">
                      {selectedIntegration.supportedModels.map((m) => (
                        <div
                          key={m}
                          className="font-mono text-[11px] p-1.5 rounded-md bg-bg-elevated border border-border/60 text-fg flex items-center justify-between"
                        >
                          <span className="truncate">{m}</span>
                          {selectedIntegration.config?.selectedModel === m && (
                            <Badge className="bg-emerald-500/10 text-emerald-400 text-[9px]">Default</Badge>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Tags */}
                <div>
                  <h4 className="text-[10px] uppercase font-mono tracking-wider text-subtle mb-1 font-semibold">
                    Security Tags
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {selectedIntegration.tags.map((t) => (
                      <span
                        key={t}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-bg-subtle border border-border text-muted"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Configuration Timestamp Info */}
                {selectedIntegration.config?.installedAt && (
                  <div className="text-[10px] text-subtle font-mono pt-2 border-t border-border/60">
                    <div>Installed: {new Date(selectedIntegration.config.installedAt).toLocaleString()}</div>
                    {selectedIntegration.config.lastReconfiguredAt && (
                      <div className="text-accent">
                        Reconfigured: {new Date(selectedIntegration.config.lastReconfiguredAt).toLocaleString()}
                      </div>
                    )}
                  </div>
                )}

                {/* Agent Interactive Test & Prompt Debug Section (Very bottom of details) */}
                {selectedIntegration.id === "agy_agent" && selectedIntegration.status === "installed" && (
                  <div className="border border-accent/30 rounded-xl bg-bg-subtle/40 overflow-hidden space-y-2 p-3">
                    <div className="flex items-center justify-between">
                      <div className="font-semibold text-fg flex items-center gap-1.5 text-xs">
                        <Terminal className="size-3.5 text-accent" />
                        <span>Interactive Agent Test Console</span>
                      </div>
                      <Badge className="text-[9px] border border-emerald-500/30 text-emerald-400 font-mono">
                        --dangerously-skip-permissions
                      </Badge>
                    </div>
                    <p className="text-[11px] text-muted leading-relaxed">
                      Test real-time IPC communication and cognitive responses with the local Antigravity CLI agent.
                    </p>

                    <div className="pt-1">
                      <AieAgentChatDrawer
                        isOpen={true}
                        onClose={() => {}}
                        activeModel={selectedIntegration.config?.selectedModel || selectedIntegration.supportedModels[0]}
                        embedded={true}
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Drawer Footer: Actions & Re-Config */}
              <div className="p-3.5 border-t border-border bg-bg/70 space-y-2 shrink-0">
                {selectedIntegration.status === "installed" ? (
                  <>
                    <div className="grid grid-cols-2 gap-2">
                      {/* Set as Active Provider */}
                      <Button
                        size="sm"
                        variant={activeProviderId === selectedIntegration.id ? "secondary" : "primary"}
                        disabled={activeProviderId === selectedIntegration.id || setActiveMutation.isPending}
                        onClick={() =>
                          setActiveMutation.mutate({
                            id: selectedIntegration.id,
                            model: selectedIntegration.supportedModels[0],
                          })
                        }
                        className="text-xs h-7.5 gap-1 font-medium truncate"
                      >
                        <Bot className="size-3 text-accent shrink-0" />
                        <span className="truncate">
                          {activeProviderId === selectedIntegration.id ? "Active Provider" : "Set as Active"}
                        </span>
                      </Button>

                      {/* Test Connection */}
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={testConnectionMutation.isPending}
                        onClick={() => testConnectionMutation.mutate(selectedIntegration.id)}
                        className="text-xs h-7.5 gap-1 truncate"
                      >
                        <RefreshCw
                          className={cn("size-3 text-accent shrink-0", testConnectionMutation.isPending && "animate-spin")}
                        />
                        <span>{testConnectionMutation.isPending ? "Testing..." : "Test Connection"}</span>
                      </Button>
                    </div>

                    <div className="grid grid-cols-3 gap-1.5 pt-1.5 border-t border-border/60">
                      {/* RE-CONFIG BUTTON: Uninstalls first then reruns install */}
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleOpenConfigModal(selectedIntegration, true)}
                        className="text-xs h-7.5 gap-1 border-accent/40 text-accent hover:bg-accent/10"
                        title="Performs clean uninstall and runs fresh installation"
                      >
                        <RefreshCw className="size-3" />
                        Re-Config
                      </Button>

                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleOpenConfigModal(selectedIntegration, false)}
                        className="text-xs h-7.5 gap-1"
                      >
                        <Settings2 className="size-3" />
                        Configure
                      </Button>

                      {/* UNINSTALL BUTTON (ONLY IF INSTALLED) */}
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => setUninstallConfirmItem(selectedIntegration)}
                        className="text-xs h-7.5 gap-1 text-red-400 hover:text-red-300 hover:bg-red-500/10 border-red-500/30"
                      >
                        <Trash2 className="size-3" />
                        Uninstall
                      </Button>
                    </div>
                  </>
                ) : (
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() => handleOpenConfigModal(selectedIntegration, false)}
                      className="flex-1 text-xs h-8 gap-1.5 bg-accent text-white font-medium"
                    >
                      <Download className="size-3.5" />
                      Install Integration
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => testConnectionMutation.mutate(selectedIntegration.id)}
                      disabled={testConnectionMutation.isPending}
                      className="text-xs h-8 px-2.5"
                      title="Test if already present in environment"
                    >
                      <RefreshCw
                        className={cn("size-3 text-accent", testConnectionMutation.isPending && "animate-spin")}
                      />
                    </Button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* INSTALL / RE-CONFIG MODAL (NO STATIC COMMAND, MANDATORY TOKEN, LOGS, TEST) */}
        {/* ========================================================================= */}
        {configModalItem && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/60 backdrop-blur-xs" onClick={() => setConfigModalItem(null)} />

            <div className="relative w-full max-w-lg bg-bg-elevated border border-border rounded-2xl shadow-2xl p-6 z-10 animate-in zoom-in-95 duration-150 max-h-[90vh] overflow-y-auto">
              {/* Modal Header */}
              <div className="flex items-start justify-between gap-3 mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-accent/10 border border-accent/20 text-accent">
                    {configModalItem.type === "cli_agent" ? <Terminal className="size-5" /> : <Key className="size-5" />}
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-fg">
                      {isReconfigMode
                        ? `Re-Configure & Reinstall ${configModalItem.name}`
                        : configModalItem.status === "installed"
                        ? `Configure ${configModalItem.name}`
                        : `Install ${configModalItem.name}`}
                    </h3>
                    <p className="text-xs text-subtle">
                      Provider: {configModalItem.provider} · Version: {configModalItem.version}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setConfigModalItem(null)}
                  className="p-1 rounded-lg text-subtle hover:text-fg hover:bg-bg-subtle cursor-pointer"
                >
                  <X className="size-4" />
                </button>
              </div>

              {/* Feedback Alert if present */}
              {modalFeedback && (
                <div className="mb-4 p-3 rounded-xl bg-accent/10 border border-accent/20 text-xs text-accent flex items-center gap-2">
                  <CheckCircle2 className="size-4 shrink-0" />
                  <span>{modalFeedback}</span>
                </div>
              )}

              {/* Modal Connection Test Feedback */}
              {modalTestResult && (
                <div
                  className={cn(
                    "mb-4 p-3 rounded-xl border text-xs flex items-center justify-between transition-all",
                    modalTestResult.success
                      ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                      : "bg-red-500/10 border-red-500/30 text-red-400"
                  )}
                >
                  <div className="flex items-center gap-2">
                    {modalTestResult.success ? (
                      <CheckCircle2 className="size-4 shrink-0 text-emerald-400" />
                    ) : (
                      <AlertCircle className="size-4 shrink-0 text-red-400" />
                    )}
                    <span>{modalTestResult.message}</span>
                  </div>
                  {modalTestResult.latencyMs && (
                    <Badge className="text-[10px] font-mono border border-emerald-500/30 text-emerald-400">
                      {modalTestResult.latencyMs}ms
                    </Badge>
                  )}
                </div>
              )}

              {/* CLI Agent Installation & Re-Config Engine */}
              {configModalItem.type === "cli_agent" && (
                <div className="space-y-4 text-xs">
                  {/* Step 1: Real Host & Sandbox Installation Execution */}
                  <div className="p-3.5 rounded-xl border border-border bg-bg-subtle/50 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="font-semibold text-fg flex items-center gap-1.5">
                        <Terminal className="size-3.5 text-accent" />
                        <span>Host & Sandbox Installation</span>
                      </div>
                      <Badge className="text-[10px] border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 font-mono">
                        {sandboxStatus?.runtime === "docker" ? "DOCKER CONTAINER" : isReconfigMode ? "Clean Re-Install" : "Automated Script"}
                      </Badge>
                    </div>

                    <p className="text-xs text-muted leading-relaxed">
                      {isReconfigMode
                        ? "Re-configuration cycles the execution environment, verifies container credentials, and synchronizes isolated tokens in aie-agent-sandbox."
                        : "Installs and verifies the official Antigravity CLI binary inside the isolated aie-agent-sandbox container with full host process protection."}
                    </p>

                    {sandboxStatus && (
                      <div className="flex items-center justify-between p-2 rounded-lg bg-bg-elevated border border-border/70 text-[11px] font-mono">
                        <span className="text-subtle">Target Environment:</span>
                        <span className="text-accent font-semibold">
                          {sandboxStatus.runtime === "docker" ? "aie-agent-sandbox (Running)" : `${sandboxStatus.runtime.toUpperCase()} Runtime`}
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-2 pt-1">
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={realInstallMutation.isPending}
                        onClick={() =>
                          realInstallMutation.mutate({
                            id: configModalItem.id,
                            reconfig: isReconfigMode,
                            authToken: authTokenInput || undefined,
                            selectedModel: selectedModelInput || configModalItem.supportedModels[0],
                          })
                        }
                        className="text-xs h-8 gap-1.5 bg-accent text-white font-medium"
                      >
                        {realInstallMutation.isPending ? (
                          <>
                            <Loader2 className="size-3.5 animate-spin" />
                            <span>Running Installation...</span>
                          </>
                        ) : (
                          <>
                            <Download className="size-3.5" />
                            <span>{isReconfigMode ? "Execute Fresh Re-Install" : "Run Sandbox Installation"}</span>
                          </>
                        )}
                      </Button>

                      {/* Modal Test Connection Button */}
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={modalTestConnectionMutation.isPending}
                        onClick={() => modalTestConnectionMutation.mutate(configModalItem.id)}
                        className="text-xs h-8 gap-1.5"
                      >
                        <RefreshCw
                          className={cn("size-3 text-accent", modalTestConnectionMutation.isPending && "animate-spin")}
                        />
                        <span>{modalTestConnectionMutation.isPending ? "Testing..." : "Test Connection"}</span>
                      </Button>
                    </div>
                  </div>

                  {/* Step 2: Advanced Real-Time Terminal & Execution Logs */}
                  <div className="border border-border/80 rounded-xl bg-[#0d1117] overflow-hidden shadow-inner">
                    {/* Header */}
                    <div className="p-2.5 bg-black/60 border-b border-white/10 flex items-center justify-between gap-2">
                      <button
                        type="button"
                        onClick={() => setIsLogsExpanded(!isLogsExpanded)}
                        className="flex items-center gap-2 font-mono text-[11px] text-muted hover:text-fg transition-colors cursor-pointer select-none"
                      >
                        <Terminal className="size-3.5 text-emerald-400" />
                        <span className="font-semibold text-fg">Sandbox Execution & Installation Logs</span>
                        <Badge className="text-[9px] font-mono px-1.5 py-0.2 bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                          {displayedInstallLogs.length} events
                        </Badge>
                        {isLogsExpanded ? <ChevronDown className="size-3.5 text-subtle" /> : <ChevronRight className="size-3.5 text-subtle" />}
                      </button>

                      {/* Right Log Controls: Copy, Download, Clear */}
                      {isLogsExpanded && (
                        <div className="flex items-center gap-1.5">
                          <Button
                            type="button"
                            size="sm"
                            variant="secondary"
                            onClick={() => handleCopyLogs(realInstallLogs)}
                            className="text-[10px] h-6 px-2 gap-1 border-white/10 hover:bg-white/10 cursor-pointer"
                            title="Copy entire log output to clipboard"
                          >
                            {isCopiedLogs ? (
                              <>
                                <Check className="size-3 text-emerald-400" />
                                <span className="text-emerald-400 font-mono">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="size-3 text-subtle" />
                                <span className="font-mono text-subtle">Copy</span>
                              </>
                            )}
                          </Button>

                          <Button
                            type="button"
                            size="sm"
                            variant="secondary"
                            onClick={() => handleDownloadLogs(realInstallLogs, `aie-${configModalItem.id}-install.log`)}
                            className="text-[10px] h-6 px-2 gap-1 border-white/10 hover:bg-white/10 cursor-pointer"
                            title="Download raw log file"
                          >
                            <Download className="size-3 text-subtle" />
                            <span className="font-mono text-subtle">Export .log</span>
                          </Button>

                          <Button
                            type="button"
                            size="sm"
                            variant="secondary"
                            onClick={handleExportDiagnosticBundle}
                            className="text-[10px] h-6 px-2 gap-1 border-accent/30 text-accent hover:bg-accent/10 cursor-pointer"
                            title="Download complete diagnostic telemetry bundle (.json)"
                          >
                            <FileText className="size-3 text-accent" />
                            <span className="font-mono text-accent">Bundle .json</span>
                          </Button>

                          <Button
                            type="button"
                            size="sm"
                            variant="secondary"
                            onClick={() => setRealInstallLogs([])}
                            className="text-[10px] h-6 px-2 text-subtle hover:text-rose-400 hover:bg-white/10 cursor-pointer"
                            title="Clear console output"
                          >
                            <Trash2 className="size-3" />
                          </Button>
                        </div>
                      )}
                    </div>

                    {isLogsExpanded && (
                      <div className="p-2.5 space-y-2.5 border-b border-white/5 bg-black/40">
                        {/* Live Container Telemetry Strip */}
                        {containerMetrics && (
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 p-2 rounded-lg bg-black/70 border border-white/10 text-[10px] font-mono">
                            <div className="flex flex-col">
                              <span className="text-subtle text-[9px] uppercase">Container State</span>
                              <span className={cn("font-bold flex items-center gap-1", containerMetrics.containerRunning ? "text-emerald-400" : "text-amber-400")}>
                                <span className={cn("size-1.5 rounded-full", containerMetrics.containerRunning ? "bg-emerald-400 animate-pulse" : "bg-amber-400")} />
                                {containerMetrics.status.toUpperCase()}
                              </span>
                            </div>
                            <div className="flex flex-col">
                              <span className="text-subtle text-[9px] uppercase">CPU Load</span>
                              <span className="text-cyan-300 font-semibold">{containerMetrics.cpuPercent}</span>
                            </div>
                            <div className="flex flex-col">
                              <span className="text-subtle text-[9px] uppercase">Memory / Vault</span>
                              <span className="text-purple-300 font-semibold truncate" title={containerMetrics.memoryUsage || "Active"}>
                                {containerMetrics.memoryUsage ? containerMetrics.memoryUsage.split("/")[0]?.trim() : "1.0 MiB"}
                              </span>
                            </div>
                            <div className="flex flex-col">
                              <span className="text-subtle text-[9px] uppercase">PIDs / Network</span>
                              <span className="text-emerald-300 font-semibold">
                                {containerMetrics.pids ?? 1} tasks · {containerMetrics.netIO ? containerMetrics.netIO.split("/")[0]?.trim() : "OK"}
                              </span>
                            </div>
                          </div>
                        )}

                        {/* Interactive Diagnostics Probes Toolbar */}
                        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 no-scrollbar text-[10px] font-mono">
                          <span className="text-subtle text-[9px] uppercase tracking-wider shrink-0 flex items-center gap-1">
                            <Sparkles className="size-2.5 text-accent" />
                            Diagnostic Probes:
                          </span>
                          <button
                            type="button"
                            disabled={diagnosticsCommandMutation.isPending}
                            onClick={() => diagnosticsCommandMutation.mutate("version")}
                            className="px-2 py-0.5 rounded border border-white/10 bg-white/5 hover:bg-accent/20 hover:border-accent/40 text-muted hover:text-fg transition-colors whitespace-nowrap cursor-pointer"
                            title="Probe CLI version in container"
                          >
                            agy --version
                          </button>
                          <button
                            type="button"
                            disabled={diagnosticsCommandMutation.isPending}
                            onClick={() => diagnosticsCommandMutation.mutate("models")}
                            className="px-2 py-0.5 rounded border border-white/10 bg-white/5 hover:bg-accent/20 hover:border-accent/40 text-muted hover:text-fg transition-colors whitespace-nowrap cursor-pointer"
                            title="List engine models"
                          >
                            agy models
                          </button>
                          <button
                            type="button"
                            disabled={diagnosticsCommandMutation.isPending}
                            onClick={() => diagnosticsCommandMutation.mutate("stats")}
                            className="px-2 py-0.5 rounded border border-white/10 bg-white/5 hover:bg-accent/20 hover:border-accent/40 text-muted hover:text-fg transition-colors whitespace-nowrap cursor-pointer"
                            title="Inspect live container stats"
                          >
                            docker stats
                          </button>
                          <button
                            type="button"
                            disabled={diagnosticsCommandMutation.isPending}
                            onClick={() => diagnosticsCommandMutation.mutate("token")}
                            className="px-2 py-0.5 rounded border border-white/10 bg-white/5 hover:bg-accent/20 hover:border-accent/40 text-muted hover:text-fg transition-colors whitespace-nowrap cursor-pointer"
                            title="Audit OAuth token in vault"
                          >
                            Audit Vault Token
                          </button>
                          <button
                            type="button"
                            disabled={diagnosticsCommandMutation.isPending}
                            onClick={() => diagnosticsCommandMutation.mutate("ping")}
                            className="px-2 py-0.5 rounded border border-white/10 bg-white/5 hover:bg-accent/20 hover:border-accent/40 text-muted hover:text-fg transition-colors whitespace-nowrap cursor-pointer"
                            title="Run loopback ping benchmark"
                          >
                            Benchmark Ping
                          </button>
                        </div>
                        {/* Filter Bar */}
                        <div className="flex items-center justify-between gap-2 flex-wrap text-[10px]">
                          <div className="flex items-center gap-1 flex-wrap">
                            {(["ALL", "INFO", "EXEC", "AUTH", "STDOUT", "ERRORS"] as const).map((lvl) => (
                              <button
                                key={lvl}
                                type="button"
                                onClick={() => setLogFilter(lvl)}
                                className={cn(
                                  "px-2 py-0.5 rounded font-mono text-[9px] uppercase font-semibold transition-all cursor-pointer",
                                  logFilter === lvl
                                    ? "bg-accent text-white"
                                    : "bg-white/5 text-subtle hover:text-fg hover:bg-white/10"
                                )}
                              >
                                {lvl}
                              </button>
                            ))}
                          </div>

                          <div className="relative w-44">
                            <Search className="size-3 absolute left-2 top-1/2 -translate-y-1/2 text-subtle" />
                            <Input
                              value={logSearchQuery}
                              onChange={(e) => setLogSearchQuery(e.target.value)}
                              placeholder="Filter logs..."
                              className="text-[10px] h-6 pl-6 py-0 font-mono bg-black/60 border-white/15 text-fg"
                            />
                          </div>
                        </div>

                        {/* Terminal Body */}
                        <div className="font-mono text-[10.5px] max-h-56 overflow-y-auto space-y-1 select-all p-2 rounded bg-black/90 border border-white/5">
                          {displayedInstallLogs.length > 0 ? (
                            displayedInstallLogs.map((logLine, idx) => {
                              const isExec = logLine.includes("[EXEC]");
                              const isAuth = logLine.includes("[AUTH]");
                              const isInfo = logLine.includes("[INFO]");
                              const isDebug = logLine.includes("[DEBUG]");
                              const isWarn = logLine.includes("[WARN]");
                              const isError =
                                logLine.includes("[ERROR]") ||
                                logLine.includes("[STDERR]") ||
                                logLine.includes("fail") ||
                                logLine.includes("Error");
                              const isStdout = logLine.includes("[STDOUT]");

                              return (
                                <div
                                  key={idx}
                                  className="leading-snug break-all flex items-start gap-2 hover:bg-white/5 p-0.5 rounded"
                                >
                                  <span className="text-subtle/50 select-none w-5 text-right shrink-0 text-[9px]">
                                    {idx + 1}
                                  </span>
                                  <span
                                    className={cn(
                                      "grow font-mono",
                                      isError && "text-rose-400 font-semibold",
                                      isExec && "text-purple-300 font-medium",
                                      isAuth && "text-amber-300 font-medium",
                                      isStdout && "text-green-300",
                                      isWarn && "text-yellow-300",
                                      isDebug && "text-subtle/90",
                                      isInfo && "text-emerald-300",
                                      !isError &&
                                        !isExec &&
                                        !isAuth &&
                                        !isStdout &&
                                        !isWarn &&
                                        !isDebug &&
                                        !isInfo &&
                                        "text-fg/90"
                                    )}
                                  >
                                    {logLine}
                                  </span>
                                </div>
                              );
                            })
                          ) : (
                            <div className="text-subtle text-[11px] py-3 text-center">
                              {realInstallLogs.length === 0
                                ? 'Click "Run Sandbox Installation" or "Execute Fresh Re-Install" to start the diagnostic stream...'
                                : "No logs match the selected filter."}
                            </div>
                          )}
                          <div ref={terminalBottomRef} />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Local Active Session Detection */}
                  {configModalItem.id === "agy_agent" && detectedLocalSession?.available && (
                    <div className="p-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 flex items-center justify-between">
                      <div>
                        <div className="font-semibold text-emerald-400 text-xs flex items-center gap-1.5">
                          <CheckCircle2 className="size-3.5" />
                          Active Shell OAuth Session Detected
                        </div>
                        <div className="text-[11px] text-subtle mt-0.5 font-mono">
                          Token: {detectedLocalSession.tokenPreview} (Host Verified)
                        </div>
                      </div>
                      <Button
                        size="sm"
                        type="button"
                        variant="secondary"
                        onClick={() => {
                          if (detectedLocalSession.fullToken) {
                            setAuthTokenInput(detectedLocalSession.fullToken);
                          }
                        }}
                        className="text-xs h-7 text-emerald-400 border-emerald-500/40 hover:bg-emerald-500/20 font-medium cursor-pointer"
                      >
                        Auto-Fill Token
                      </Button>
                    </div>
                  )}

                  {/* Step 3: Google OAuth Dynamic PKCE Authentication Portal */}
                  <div className="p-3.5 rounded-xl border border-accent/20 bg-accent/5 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="font-semibold text-fg flex items-center gap-1.5 text-xs">
                        <Shield className="size-3.5 text-accent" />
                        Google OAuth Authorization Portal (PKCE Flow)
                      </div>
                      <div className="flex items-center gap-1.5">
                        <Badge className="text-[10px] border border-emerald-500/30 text-emerald-400 font-mono">
                          Dynamic S256 PKCE
                        </Badge>
                        <button
                          type="button"
                          onClick={() => setAgyOAuthSession(generateAgyOAuthSession())}
                          className="p-1 rounded hover:bg-accent/10 text-accent text-[10px] flex items-center gap-1 cursor-pointer transition-colors"
                          title="Generate fresh PKCE code challenge and session state"
                        >
                          <RefreshCw className="size-3" />
                          <span>Refresh</span>
                        </button>
                      </div>
                    </div>
                    <p className="text-xs text-muted leading-relaxed">
                      Authenticate with your Google account via the official dynamic authorization portal to generate your access token:
                    </p>

                    <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2 pt-0.5">
                      <a
                        href={
                          configModalItem.id === "agy_agent"
                            ? (agyOAuthSession?.authUrl || generateAgyOAuthUrl())
                            : configModalItem.authUrl || generateAgyOAuthUrl()
                        }
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent text-white font-medium text-xs hover:bg-accent/90 transition-colors shadow-xs cursor-pointer"
                      >
                        <ExternalLink className="size-3" />
                        Open Google OAuth Authorization Portal
                      </a>
                      {agyOAuthSession?.state && (
                        <span className="text-[10px] font-mono text-subtle truncate max-w-[200px]" title={`Dynamic Session State: ${agyOAuthSession.state}`}>
                          state: {agyOAuthSession.state.slice(0, 10)}...
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Step 4: Mandatory Authorization Code / Token */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-subtle font-medium flex items-center gap-1">
                        <span>Authorization Code / Token</span>
                        <span className="text-red-400 font-bold">*</span>
                      </label>
                      <span className="text-[10px] text-accent font-mono">
                        {isReconfigMode || configModalItem.status !== "installed" ? "Mandatory for Installation" : "Configured"}
                      </span>
                    </div>
                    <Input
                      placeholder="Paste authorization token or code from OAuth portal..."
                      value={authTokenInput}
                      onChange={(e) => setAuthTokenInput(e.target.value)}
                      className={cn(
                        "font-mono text-xs bg-bg-subtle",
                        isMandatoryAuthMissing && "border-amber-500/60 focus:border-amber-500"
                      )}
                    />
                    {isMandatoryAuthMissing && (
                      <p className="text-[11px] text-amber-400 mt-1 flex items-center gap-1">
                        <AlertCircle className="size-3 shrink-0" />
                        Authorization code is required to finalize installation or re-config.
                      </p>
                    )}
                  </div>

                  {/* Target Model Selection */}
                  <div>
                    <label className="block text-subtle font-medium mb-1">Default Model</label>
                    <select
                      value={selectedModelInput || configModalItem.supportedModels[0]}
                      onChange={(e) => setSelectedModelInput(e.target.value)}
                      className="w-full rounded-md border border-border bg-bg-subtle px-3 py-2 text-xs text-fg focus:border-accent focus:outline-none"
                    >
                      {configModalItem.supportedModels.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              )}

              {/* Direct API Provider Configuration */}
              {configModalItem.type === "api_provider" && (
                <div className="space-y-4 text-xs">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-subtle font-medium flex items-center gap-1">
                        <span>API Key</span>
                        <span className="text-red-400 font-bold">*</span>
                      </label>
                      <a
                        href={configModalItem.authUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-accent hover:underline flex items-center gap-1"
                      >
                        Get Key <ExternalLink className="size-2.5" />
                      </a>
                    </div>
                    <Input
                      type="password"
                      placeholder="sk-... or AIzaSy..."
                      value={apiKeyInput}
                      onChange={(e) => setApiKeyInput(e.target.value)}
                      className="font-mono text-xs bg-bg-subtle"
                    />
                  </div>

                  <div>
                    <label className="block text-subtle font-medium mb-1">Target Model</label>
                    <select
                      value={selectedModelInput || configModalItem.supportedModels[0]}
                      onChange={(e) => setSelectedModelInput(e.target.value)}
                      className="w-full rounded-md border border-border bg-bg-subtle px-3 py-2 text-xs text-fg focus:border-accent focus:outline-none"
                    >
                      {configModalItem.supportedModels.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="pt-1">
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={modalTestConnectionMutation.isPending}
                      onClick={() => modalTestConnectionMutation.mutate(configModalItem.id)}
                      className="text-xs h-8 gap-1.5"
                    >
                      <RefreshCw
                        className={cn("size-3 text-accent", modalTestConnectionMutation.isPending && "animate-spin")}
                      />
                      <span>{modalTestConnectionMutation.isPending ? "Testing..." : "Test Connection"}</span>
                    </Button>
                  </div>
                </div>
              )}

              {/* Modal Footer */}
              <div className="mt-6 pt-4 border-t border-border flex items-center justify-end gap-2">
                <Button size="sm" variant="secondary" onClick={() => setConfigModalItem(null)} className="text-xs">
                  Cancel
                </Button>
                <Button
                  size="sm"
                  variant="primary"
                  disabled={
                    configureMutation.isPending ||
                    realInstallMutation.isPending ||
                    (configModalItem.type === "cli_agent" && isMandatoryAuthMissing)
                  }
                  onClick={() => {
                    const configPayload = {
                      apiKey: apiKeyInput || undefined,
                      authToken: authTokenInput || undefined,
                      selectedModel: selectedModelInput || configModalItem.supportedModels[0],
                      lastReconfiguredAt: isReconfigMode ? new Date().toISOString() : undefined,
                    };

                    // Save configuration or complete installation
                    configureMutation.mutate({
                      id: configModalItem.id,
                      config: configPayload,
                    });
                  }}
                  className={cn(
                    "text-xs bg-accent text-white font-medium",
                    isMandatoryAuthMissing && "opacity-50 cursor-not-allowed"
                  )}
                >
                  {isReconfigMode
                    ? "Complete Re-Configuration"
                    : configModalItem.status === "installed"
                    ? "Save Configuration"
                    : "Complete & Install"}
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* UNINSTALL CONFIRMATION MODAL                                              */}
        {/* ========================================================================= */}
        {uninstallConfirmItem && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/60 backdrop-blur-xs" onClick={() => setUninstallConfirmItem(null)} />

            <div className="relative w-full max-w-md bg-bg-elevated border border-red-500/30 rounded-2xl shadow-2xl p-6 z-10 animate-in zoom-in-95 duration-150">
              <div className="flex items-center gap-3 text-red-400 mb-3">
                <AlertCircle className="size-6" />
                <h3 className="text-base font-semibold text-fg">Uninstall {uninstallConfirmItem.name}?</h3>
              </div>
              <p className="text-xs text-subtle leading-relaxed mb-6">
                This will remove the configuration and credentials for {uninstallConfirmItem.name}. If this was the
                active AI provider, AIE will automatically revert back to Antigravity AGY Agent.
              </p>
              <div className="flex items-center justify-end gap-2">
                <Button size="sm" variant="secondary" onClick={() => setUninstallConfirmItem(null)} className="text-xs">
                  Cancel
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  disabled={uninstallMutation.isPending}
                  onClick={() => uninstallMutation.mutate(uninstallConfirmItem.id)}
                  className="text-xs bg-red-500/20 text-red-300 border border-red-500/40 hover:bg-red-500/30"
                >
                  Confirm Uninstall
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
