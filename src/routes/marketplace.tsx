import { useState, useRef, useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  Bot,
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
import { ActionButton, PageHeader, SegmentedTabs, Toolbar } from "@/components/layout/page";
import { EmptyState, StatusChip, StatusDot } from "@/components/ui/primitives";
import { AieAgentChatDrawer } from "@/components/aie-agent-chat-drawer";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { cn } from "@/lib/cn";
import { AgentOnboardingStepper } from "@/components/agent-onboarding-stepper";
import { sanitizeAgyModel, DEFAULT_AGY_MODEL } from "@/lib/aie/agent-framework/types";
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
  // OAuth (PKCE) is generated server-side; the client only ever sees the server's authUrl.
  const [serverAuthUrl, setServerAuthUrl] = useState<string | null>(null);

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

  // Query isolated agent sandbox runtime status (adaptive: 10s when modal open, 45s idle)
  const { data: sandboxStatus, refetch: refetchSandbox } = useQuery({
    queryKey: ["agent_sandbox_status"],
    queryFn: () => getAgentSandboxStatus(),
    refetchInterval: configModalItem ? 10000 : 45000,
    staleTime: 10000,
  });

  // Query global live sandbox diagnostics logs (only poll when logs drawer is expanded)
  const { data: sandboxLogsData, refetch: refetchLogs } = useQuery({
    queryKey: ["agent_sandbox_logs"],
    queryFn: () => getAgentSandboxLogs(),
    refetchInterval: isLogsExpanded ? 3000 : false,
    staleTime: 3000,
  });

  // Query live detailed container metrics & host telemetry (only poll when telemetry strip is open)
  const { data: containerMetrics, refetch: refetchMetrics } = useQuery({
    queryKey: ["container_detailed_metrics"],
    queryFn: () => getContainerDetailedMetrics(),
    refetchInterval: isLogsExpanded ? 4000 : false,
    staleTime: 4000,
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
  const activeModel = sanitizeAgyModel(marketplaceState?.activeModel);

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
      const returnedAuthUrl =
        (res as { authUrl?: unknown }).authUrl ??
        (res as { integration?: { config?: { authUrl?: unknown } } }).integration?.config?.authUrl;
      if (typeof returnedAuthUrl === "string" && returnedAuthUrl) {
        setServerAuthUrl(returnedAuthUrl);
      }
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
    // Never prefill stored secrets; the server only reports whether one exists.
    setApiKeyInput("");
    setAuthTokenInput("");
    setSelectedModelInput(item.config?.selectedModel || item.supportedModels[0] || "");
    setRealInstallLogs(item.config?.logs || []);
    setIsLogsExpanded(true);
    setModalFeedback(null);
    setModalTestResult(null);
    setServerAuthUrl(typeof item.config?.authUrl === "string" ? item.config.authUrl : null);
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
      const modalIntegrationId = configModalItem.id;
      const recentFormatted = sandboxLogsData.logs
        .filter((l) => {
          const owner = (l as { meta?: Record<string, unknown> }).meta?.integrationId;
          return typeof owner !== "string" || owner === modalIntegrationId;
        })
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
    // Strip anything secret-shaped (keys, tokens, client secrets) before export.
    const isSecretKey = (k: string) => {
      const lower = k.toLowerCase();
      if (lower === "hasapikey" || lower === "apikeyhint") return false;
      return /secret|token|key|password|verifier/.test(lower);
    };
    const stripSecrets = (value: unknown, depth = 0): unknown => {
      if (depth > 6 || value === null || typeof value !== "object") return value;
      if (Array.isArray(value)) return value.map((v) => stripSecrets(v, depth + 1));
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (isSecretKey(k)) continue;
        out[k] = stripSecrets(v, depth + 1);
      }
      return out;
    };
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
        config: i.config ? stripSecrets(i.config) : undefined,
      })),
      recentLogs: stripSecrets(sandboxLogsData?.logs || []),
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
        {/* Static header + section tabs (never scrolls) */}
        <header className="z-20 shrink-0 border-b border-border bg-bg px-4 pb-4 pt-6 md:px-10 md:pt-8">
          <PageHeader
            className="mb-0 md:mb-0"
            title="Marketplace"
            description="Install, configure, and manage external AI agents, API endpoints, curated adversary feeds, and execution blocks."
            actions={
              <div className="flex min-w-0 max-w-full flex-col gap-1.5 rounded-lg border border-border bg-bg-card px-3 py-2 text-xs">
                {/* Agent sandbox environment indicator */}
                <div className="flex items-center gap-2">
                  <StatusDot
                    tone={
                      (sandboxStatus?.runtime === "docker" && sandboxStatus?.containerRunning) || sandboxStatus?.isReady
                        ? "success"
                        : "warning"
                    }
                  >
                    <span className="text-muted">Sandbox</span>
                  </StatusDot>
                  <span className="font-medium text-fg">
                    {sandboxStatus?.runtime === "docker"
                      ? `${sandboxStatus.containerName} (active)`
                      : sandboxStatus?.runtime === "wsl"
                        ? "WSL Linux bridge"
                        : sandboxStatus?.runtime === "native"
                          ? "Host native runtime"
                          : "Standby"}
                  </span>
                  {sandboxStatus?.runtime === "docker" && <span className="text-subtle">· Isolated</span>}
                  <button
                    type="button"
                    onClick={() => restartSandboxMutation.mutate()}
                    disabled={restartSandboxMutation.isPending}
                    title="Restart agent sandbox container"
                    aria-label="Restart agent sandbox container"
                    className="rounded-md p-1 text-subtle transition-colors hover:bg-bg-subtle hover:text-fg disabled:opacity-50"
                  >
                    {restartSandboxMutation.isPending ? (
                      <ActivitySpinner size="xs" className="text-accent" />
                    ) : (
                      <RefreshCw className="size-3.5" strokeWidth={1.75} />
                    )}
                  </button>
                </div>

                {/* Active AI agent indicator */}
                <div className="flex min-w-0 items-center gap-2">
                  <StatusDot tone="success">
                    <span className="text-muted">Agent</span>
                  </StatusDot>
                  <span className="truncate font-medium text-fg">
                    {integrations.find((x) => x.id === activeProviderId)?.name || "Autonomous Threat Intelligence Agent"}
                  </span>
                  <span className="shrink-0 font-mono text-[11px] text-muted">{activeModel}</span>
                </div>
              </div>
            }
            tabs={
              <SegmentedTabs
                ariaLabel="Marketplace sections"
                value={activeTab}
                onChange={setActiveTab}
                items={[
                  { value: "home", label: "Home", icon: Activity },
                  {
                    value: "curated",
                    label: "Curated resources",
                    icon: Globe,
                    count: marketplaceState?.curatedResources?.length || 4,
                  },
                  { value: "response", label: "Response integration", icon: Bot, count: integrations.length },
                  { value: "powerups", label: "Powerups & exporters", icon: Zap },
                  { value: "playbooks", label: "Playbook blocks", icon: Layers },
                ]}
              />
            }
          />
        </header>

        {/* Response integration tab */}
        {activeTab === "response" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="z-10 shrink-0 border-b border-border bg-bg px-4 py-3 md:px-10">
              <Toolbar
                className="mb-0"
                left={
                  <>
                    <span className="flex shrink-0 items-center gap-1.5 text-sm text-muted">
                      <Filter className="size-4" strokeWidth={1.75} /> Category
                    </span>
                    <SegmentedTabs
                      size="sm"
                      ariaLabel="Integration category"
                      value={categoryFilter}
                      onChange={setCategoryFilter}
                      items={["All", "Intelligence", "Analysis", "Automation"].map((cat) => ({ value: cat, label: cat }))}
                    />
                  </>
                }
                right={
                  <>
                    <SegmentedTabs
                      size="sm"
                      ariaLabel="Install status"
                      value={statusFilter}
                      onChange={setStatusFilter}
                      items={["All", "Installed", "Available"].map((st) => ({ value: st, label: st }))}
                    />
                    <div className="relative w-full sm:w-60">
                      <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" strokeWidth={1.75} />
                      <Input
                        placeholder="Filter integrations…"
                        aria-label="Filter integrations"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="h-9 rounded-lg border-border bg-bg-elevated pl-9 text-sm"
                      />
                      {searchQuery && (
                        <button
                          onClick={() => setSearchQuery("")}
                          aria-label="Clear filter"
                          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-subtle hover:text-fg"
                        >
                          <X className="size-3.5" />
                        </button>
                      )}
                    </div>
                  </>
                }
              />
            </div>

            {/* Scrollable cards grid */}
            <div className="flex-1 overflow-y-auto px-4 py-6 pb-24 md:px-10 md:pb-8">
              {testResult && (
                <div
                  className={cn(
                    "mb-4 flex items-center justify-between gap-3 rounded-xl border bg-bg-card p-3.5 text-sm",
                    testResult.success ? "border-sage/40 text-sage" : "border-danger/50 text-danger",
                  )}
                >
                  <div className="flex items-center gap-2">
                    {testResult.success ? (
                      <CheckCircle2 className="size-4 shrink-0" />
                    ) : (
                      <AlertCircle className="size-4 shrink-0" />
                    )}
                    <span>{testResult.message}</span>
                  </div>
                  {testResult.latencyMs && <StatusChip tone="success">Latency {testResult.latencyMs} ms</StatusChip>}
                </div>
              )}

              {isLoading ? (
                <div className="flex flex-col items-center justify-center py-20 text-muted">
                  <ActivitySpinner size="lg" className="mb-2 text-accent" />
                  <p className="text-sm">Loading integration framework & marketplace…</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
                  {filteredIntegrations.map((item) => {
                    const isInstalled = item.status === "installed";
                    const isActive = activeProviderId === item.id;
                    return (
                      <IntegrationCard
                        key={item.id}
                        icon={item.type === "cli_agent" ? Terminal : Sparkles}
                        name={item.name}
                        meta={
                          <>
                            {item.category} · {item.provider} · <span className="font-mono">{item.version}</span>
                          </>
                        }
                        description={item.description}
                        onOpen={() => setSelectedIntegration(item)}
                        status={
                          isActive ? (
                            <StatusChip tone="success" dot>
                              Active
                            </StatusChip>
                          ) : isInstalled ? (
                            <StatusChip tone="info">Installed</StatusChip>
                          ) : (
                            <StatusChip>Not installed</StatusChip>
                          )
                        }
                        action={
                          <ActionButton
                            variant={isInstalled ? "outline" : "primary"}
                            icon={isInstalled ? Settings2 : Download}
                            onClick={() => handleOpenConfigModal(item, false)}
                          >
                            {isInstalled ? "Configure" : "Install"}
                          </ActionButton>
                        }
                      />
                    );
                  })}
                </div>
              )}

              {!isLoading && filteredIntegrations.length === 0 && (
                <EmptyState
                  icon={Cpu}
                  title="No integrations match your filters"
                  description="Try resetting the category or search query."
                  action={
                    <ActionButton
                      onClick={() => {
                        setCategoryFilter("All");
                        setStatusFilter("All");
                        setSearchQuery("");
                      }}
                    >
                      Reset filters
                    </ActionButton>
                  }
                />
              )}
            </div>
          </div>
        )}

        {/* Curated resources tab */}
        {activeTab === "curated" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex-1 overflow-y-auto px-4 py-6 pb-24 md:px-10 md:pb-8">
              <TabIntro
                title="Curated threat intelligence feeds"
                description="Pre-vetted, high-fidelity security research blogs, incident timelines, and regulatory advisory feeds."
                aside={<span className="text-sm text-muted">{marketplaceState?.curatedResources?.length || 4} feeds configured</span>}
              />
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                {(marketplaceState?.curatedResources || []).map((res) => (
                  <IntegrationCard
                    key={res.id}
                    icon={Globe}
                    name={res.name}
                    meta={`${res.category} · ${res.provider} · ${res.format} · Trust ${res.trustScore}%`}
                    description={res.description}
                    footnote={<span className="block truncate font-mono text-xs text-subtle">{res.endpointUrl}</span>}
                    status={
                      <StatusChip tone="success" dot>
                        Active ingest
                      </StatusChip>
                    }
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Powerups & exporters tab */}
        {activeTab === "powerups" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex-1 overflow-y-auto px-4 py-6 pb-24 md:px-10 md:pb-8">
              <TabIntro
                title="Automation powerups & exporters"
                description="Extend AIE capabilities with custom rule generators, incident response webhooks, and bundle serializers."
              />
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                {(marketplaceState?.powerups || []).map((pwr) => (
                  <IntegrationCard
                    key={pwr.id}
                    icon={Plug}
                    name={pwr.name}
                    meta={
                      <>
                        {pwr.category} · {pwr.author} · <span className="font-mono">{pwr.version}</span>
                      </>
                    }
                    description={pwr.description}
                    status={
                      pwr.status === "installed" ? (
                        <StatusChip tone="info">Installed</StatusChip>
                      ) : (
                        <StatusChip>Not installed</StatusChip>
                      )
                    }
                    action={<ActionButton>{pwr.status === "installed" ? "Configure" : "Enable"}</ActionButton>}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Playbook blocks tab */}
        {activeTab === "playbooks" && (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex-1 overflow-y-auto px-4 py-6 pb-24 md:px-10 md:pb-8">
              <TabIntro
                title="Adversary emulation playbook blocks"
                description="Modular purple-team scenario components, automated attack chain runners, and defense verification blocks."
              />
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                {(marketplaceState?.playbooks || []).map((pb) => (
                  <IntegrationCard
                    key={pb.id}
                    icon={Layers}
                    name={pb.name}
                    meta={`${pb.framework} · ${pb.stepsCount} steps · ${pb.tactics.join(", ")}`}
                    description={pb.description}
                    footnote={
                      <span className="block truncate font-mono text-xs text-subtle" title={pb.techniques.join(", ")}>
                        {pb.techniques.join("  ")}
                      </span>
                    }
                    status={
                      <StatusChip tone={pb.difficulty === "Advanced" ? "danger" : "warning"}>{pb.difficulty}</StatusChip>
                    }
                    action={<ActionButton icon={Play}>Run block</ActionButton>}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Home tab */}
        {activeTab === "home" && (
          <div className="flex-1 space-y-6 overflow-y-auto px-4 py-6 pb-24 md:px-10 md:pb-8">
            <section className="rounded-xl border border-border bg-bg-card p-5">
              <div className="flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
                <div>
                  <h2 className="text-base font-medium text-fg">Modular AI agent & emulation ecosystem</h2>
                  <p className="mt-1 max-w-xl text-sm text-muted">
                    AIE is designed from the ground up to support interchangeable AI agents, automated discovery
                    connectors, and modular attack-flow playbooks without hard vendor lock-in.
                  </p>
                </div>
                <ActionButton variant="primary" icon={Bot} onClick={() => setActiveTab("response")}>
                  Manage AI integrations
                </ActionButton>
              </div>

              <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 border-t border-border pt-5 md:grid-cols-4">
                <div className="min-w-0">
                  <dt className="text-sm text-muted">Installed agents</dt>
                  <dd className="mt-1 text-2xl font-semibold text-fg tabular-nums">
                    {integrations.filter((x) => x.status === "installed").length} / {integrations.length}
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-sm text-muted">Active provider</dt>
                  <dd className="mt-1 truncate text-base font-medium text-fg">
                    {integrations.find((x) => x.id === activeProviderId)?.name || "Autonomous Threat Intelligence Agent"}
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-sm text-muted">Curated feeds</dt>
                  <dd className="mt-1 text-2xl font-semibold text-fg tabular-nums">
                    {marketplaceState?.curatedResources?.length || 4}
                    <span className="ml-1.5 text-sm font-normal text-muted">active</span>
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-sm text-muted">Playbook blocks</dt>
                  <dd className="mt-1 text-2xl font-semibold text-fg tabular-nums">
                    {marketplaceState?.playbooks?.length || 3}
                    <span className="ml-1.5 text-sm font-normal text-muted">ready</span>
                  </dd>
                </div>
              </dl>
            </section>
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
            <div className="relative w-full sm:w-80 md:w-96 lg:w-[25vw] min-w-[320px] max-w-[400px] h-full drawer-liquid-glass shadow-2xl flex flex-col z-10 animate-in slide-in-from-right duration-200">
              {/* Drawer Header */}
              <div className="p-4 flex items-start justify-between gap-3 drawer-section-header shrink-0">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-bg-subtle text-fg">
                    {selectedIntegration.type === "cli_agent" ? (
                      <Terminal className="size-4" />
                    ) : (
                      <Sparkles className="size-4" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <h2 className="truncate text-base font-medium text-fg">{selectedIntegration.name}</h2>
                    <div className="flex items-center gap-1.5 text-[11px] text-subtle mt-0.5">
                      <span>{selectedIntegration.provider}</span>
                      <span>·</span>
                      <span className="font-mono text-[11px]">{selectedIntegration.version}</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => setSelectedIntegration(null)}
                  aria-label="Close details"
                  className="shrink-0 rounded-lg p-1.5 text-subtle transition-colors hover:bg-bg-subtle hover:text-fg"
                >
                  <X className="size-4" />
                </button>
              </div>

              {/* Drawer Body (Scrollable inside drawer) */}
              <div className="flex-1 p-4 overflow-y-auto space-y-4 text-xs">
                {/* Status Bar */}
                <div className="flex items-center justify-between p-3 rounded-xl card-liquid-glass">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs text-muted">Status</span>
                    {selectedIntegration.status === "installed" ? (
                      <StatusChip tone="success">
                        Installed
                      </StatusChip>
                    ) : (
                      <StatusChip>
                        Available
                      </StatusChip>
                    )}
                  </div>
                  {activeProviderId === selectedIntegration.id ? (
                    <StatusDot tone="success">Active provider</StatusDot>
                  ) : null}
                </div>

                {/* Agent Engine Status Overview */}
                {selectedIntegration.type === "cli_agent" && (
                  <div className="p-3.5 rounded-xl card-liquid-glass space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="font-semibold text-fg flex items-center gap-1.5 text-xs">
                        <Terminal className="size-3.5 text-accent" />
                        <span>Agent engine status</span>
                      </div>
                      <StatusChip tone={selectedIntegration.status === "installed" ? "success" : "warning"}>
                        {selectedIntegration.status === "installed" ? "Online & ready" : "Onboarding required"}
                      </StatusChip>
                    </div>

                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex items-center justify-between text-subtle">
                        <span>Architecture</span>
                        <span className="font-medium text-fg">Isolated container sandbox</span>
                      </div>
                      <div className="flex items-center justify-between text-subtle">
                        <span>Authentication</span>
                        <span className="font-medium text-fg">Google OAuth 2.0 / Vertex API</span>
                      </div>
                      <div className="flex items-center justify-between text-subtle">
                        <span>Active model</span>
                        <span className="font-mono text-accent">
                          {selectedIntegration.config?.selectedModel || selectedIntegration.supportedModels[0]}
                        </span>
                      </div>
                      {selectedIntegration.config?.lastLatencyMs && (
                        <div className="flex items-center justify-between text-subtle">
                          <span>Verified latency</span>
                          <span className="font-mono text-sage">{selectedIntegration.config.lastLatencyMs}ms</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Overview */}
                <div>
                  <h4 className="mb-2 text-sm font-medium text-fg">
                    Overview
                  </h4>
                  <p className="text-xs text-muted leading-relaxed">
                    {selectedIntegration.overview || selectedIntegration.description}
                  </p>
                </div>

                {/* Collapsible: Supported Actions */}
                <div className="overflow-hidden rounded-lg border border-border">
                  <button
                    onClick={() => setActionsExpanded(!actionsExpanded)}
                    className="flex w-full select-none items-center justify-between p-2.5 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle"
                  >
                    <div className="flex items-center gap-1.5">
                      <Zap className="size-3.5 text-accent" />
                      <span>Actions ({selectedIntegration.actions.length})</span>
                    </div>
                    {actionsExpanded ? <ChevronDown className="size-3.5 text-subtle" /> : <ChevronRight className="size-3.5 text-subtle" />}
                  </button>

                  {actionsExpanded && (
                    <div className="divide-y divide-border border-t border-border">
                      {selectedIntegration.actions.map((act) => (
                        <div key={act.id} className="px-3 py-2">
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
                <div className="overflow-hidden rounded-lg border border-border">
                  <button
                    onClick={() => setConnectorsExpanded(!connectorsExpanded)}
                    className="flex w-full select-none items-center justify-between p-2.5 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle"
                  >
                    <div className="flex items-center gap-1.5">
                      <Plug className="size-3.5 text-accent" />
                      <span>Connectors & auth protocol</span>
                    </div>
                    {connectorsExpanded ? <ChevronDown className="size-3.5 text-subtle" /> : <ChevronRight className="size-3.5 text-subtle" />}
                  </button>

                  {connectorsExpanded && (
                    <div className="divide-y divide-border border-t border-border">
                      {selectedIntegration.connectors.map((conn, i) => (
                        <div key={i} className="px-3 py-2">
                          <div className="font-medium text-fg text-xs flex items-center justify-between">
                            <span>{conn.label}</span>
                            <StatusChip>
                              {conn.type}
                            </StatusChip>
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
                <div className="overflow-hidden rounded-lg border border-border">
                  <button
                    onClick={() => setModelsExpanded(!modelsExpanded)}
                    className="flex w-full select-none items-center justify-between p-2.5 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle"
                  >
                    <div className="flex items-center gap-1.5">
                      <Cpu className="size-3.5 text-accent" />
                      <span>Supported models ({selectedIntegration.supportedModels.length})</span>
                    </div>
                    {modelsExpanded ? <ChevronDown className="size-3.5 text-subtle" /> : <ChevronRight className="size-3.5 text-subtle" />}
                  </button>

                  {modelsExpanded && (
                    <div className="divide-y divide-border border-t border-border">
                      {selectedIntegration.supportedModels.map((m) => (
                        <div
                          key={m}
                          className="flex items-center justify-between px-3 py-1.5 font-mono text-[11px] text-fg"
                        >
                          <span className="truncate">{m}</span>
                          {selectedIntegration.config?.selectedModel === m && (
                            <StatusChip tone="success">Default</StatusChip>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Tags */}
                <div>
                  <h4 className="mb-2 text-sm font-medium text-fg">
                    Tags
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {selectedIntegration.tags.map((t) => (
                      <span
                        key={t}
                        className="rounded-md bg-bg-subtle px-2 py-0.5 text-[11px] text-muted"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Configuration Timestamp Info */}
                {selectedIntegration.config?.installedAt && (
                  <div className="border-t border-border pt-3 text-[11px] text-subtle">
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
                  <div className="rounded-xl card-liquid-glass overflow-hidden space-y-2.5 p-3.5 shadow-sm">
                    <div className="flex items-center justify-between">
                      <div className="font-semibold text-fg flex items-center gap-1.5 text-xs">
                        <Terminal className="size-3.5 text-accent" />
                        <span>Interactive agent test console</span>
                      </div>
                      <StatusChip tone="success">
                        print-only · sandboxed
                      </StatusChip>
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
              <div className="p-3.5 drawer-section-footer space-y-2 shrink-0">
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
                          {activeProviderId === selectedIntegration.id ? "Active provider" : "Set as active"}
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
                        {testConnectionMutation.isPending ? (
                          <ActivitySpinner size="xs" className="text-accent shrink-0" />
                        ) : (
                          <RefreshCw className="size-3 text-accent shrink-0" />
                        )}
                        <span>{testConnectionMutation.isPending ? "Testing…" : "Test connection"}</span>
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
                        Reconfigure
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
                        className="text-xs h-7.5 gap-1"
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
                      className="flex-1 text-xs h-8 gap-1.5 font-medium"
                    >
                      <Download className="size-3.5" />
                      Install integration
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => testConnectionMutation.mutate(selectedIntegration.id)}
                      disabled={testConnectionMutation.isPending}
                      className="text-xs h-8 px-2.5"
                      title="Test if already present in environment"
                    >
                      {testConnectionMutation.isPending ? (
                        <ActivitySpinner size="xs" className="text-accent" />
                      ) : (
                        <RefreshCw className="size-3 text-accent" />
                      )}
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

            <div className="relative w-full max-w-lg bg-bg-card border border-border rounded-xl shadow-2xl p-6 z-10 animate-in zoom-in-95 duration-150 max-h-[90vh] overflow-y-auto">
              {/* Modal Header */}
              <div className="flex items-start justify-between gap-3 mb-4">
                <div className="flex items-center gap-3">
                  <div className="flex size-10 items-center justify-center rounded-lg bg-bg-subtle text-fg">
                    {configModalItem.type === "cli_agent" ? <Terminal className="size-5" /> : <Key className="size-5" />}
                  </div>
                  <div>
                    <h3 className="text-base font-medium text-fg">
                      {isReconfigMode
                        ? `Reconfigure & reinstall ${configModalItem.name}`
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
                  aria-label="Close"
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
                      ? "bg-sage/10 border-sage/40 text-sage"
                      : "bg-danger/10 border-danger/50 text-danger"
                  )}
                >
                  <div className="flex items-center gap-2">
                    {modalTestResult.success ? (
                      <CheckCircle2 className="size-4 shrink-0 text-sage" />
                    ) : (
                      <AlertCircle className="size-4 shrink-0 text-danger" />
                    )}
                    <span>{modalTestResult.message}</span>
                  </div>
                  {modalTestResult.latencyMs && (
                    <StatusChip tone="success">
                      {modalTestResult.latencyMs}ms
                    </StatusChip>
                  )}
                </div>
              )}

              {/* Server-issued OAuth sign-in (PKCE verifier never leaves the server) */}
              {configModalItem.id === "agy_agent" && (
                <div className="mb-4 flex items-center justify-between gap-3 rounded-xl border border-border bg-bg-subtle p-3 text-xs">
                  <span className="text-subtle">Google sign-in for {configModalItem.name}</span>
                  {serverAuthUrl ? (
                    <a
                      href={serverAuthUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 font-medium text-accent hover:underline"
                    >
                      Open sign-in <ExternalLink className="size-3" />
                    </a>
                  ) : (
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={realInstallMutation.isPending}
                      onClick={() => realInstallMutation.mutate({ id: configModalItem.id })}
                      className="h-7 text-xs"
                    >
                      {realInstallMutation.isPending ? "Starting…" : "Start sign-in"}
                    </Button>
                  )}
                </div>
              )}

              {/* Autonomous Agent Onboarding Pipeline (10-Step Extensible Flow) */}
              {configModalItem.type === "cli_agent" && (
                <AgentOnboardingStepper
                  agentId={configModalItem.id}
                  onCompleted={() => {
                    queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
                    queryClient.invalidateQueries({ queryKey: ["app_settings"] });
                  }}
                />
              )}

              {/* Direct API Provider Configuration */}
              {configModalItem.type === "api_provider" && (
                <div className="space-y-4 text-xs">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-subtle font-medium flex items-center gap-1">
                        <span>API key</span>
                        <span className="text-danger font-bold">*</span>
                      </label>
                      <a
                        href={configModalItem.authUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-accent hover:underline flex items-center gap-1"
                      >
                        Get key <ExternalLink className="size-2.5" />
                      </a>
                    </div>
                    <Input
                      type="password"
                      autoComplete="off"
                      placeholder={
                        configModalItem.config?.hasApiKey
                          ? `•••• saved${configModalItem.config?.apiKeyHint ? ` (…${configModalItem.config.apiKeyHint})` : ""} — enter a new key to replace`
                          : "sk-... or AIzaSy..."
                      }
                      value={apiKeyInput}
                      onChange={(e) => setApiKeyInput(e.target.value)}
                      className="font-mono text-xs bg-bg-subtle"
                    />
                  </div>

                  <div>
                    <label className="block text-subtle font-medium mb-1">Target model</label>
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
                      {modalTestConnectionMutation.isPending ? (
                        <ActivitySpinner size="xs" className="text-accent" />
                      ) : (
                        <RefreshCw className="size-3 text-accent" />
                      )}
                      <span>{modalTestConnectionMutation.isPending ? "Testing…" : "Test connection"}</span>
                    </Button>
                  </div>
                </div>
              )}

              {/* Modal Footer */}
              <div className="mt-6 pt-4 border-t border-border flex items-center justify-end gap-2">
                <Button size="sm" variant="secondary" onClick={() => setConfigModalItem(null)} className="text-xs">
                  {configModalItem.type === "cli_agent" ? "Close" : "Cancel"}
                </Button>
                {configModalItem.type === "api_provider" && (
                  <Button
                    size="sm"
                    variant="primary"
                    disabled={
                      configureMutation.isPending ||
                      (!apiKeyInput.trim() && !configModalItem.config?.hasApiKey)
                    }
                    onClick={() => {
                      const newKey = apiKeyInput.trim();
                      // Only send apiKey when the user typed a new one; otherwise keep the stored key.
                      const configPayload: Record<string, unknown> = {
                        selectedModel: selectedModelInput || configModalItem.supportedModels[0],
                      };
                      if (newKey) configPayload.apiKey = newKey;
                      configureMutation.mutate({
                        id: configModalItem.id,
                        config: configPayload,
                      });
                    }}
                    className="text-xs bg-accent text-white font-medium"
                  >
                    {configModalItem.status === "installed" ? "Save configuration" : "Save & activate"}
                  </Button>
                )}
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

            <div className="relative w-full max-w-md bg-bg-card border border-border rounded-xl shadow-2xl p-6 z-10 animate-in zoom-in-95 duration-150">
              <div className="flex items-center gap-3 text-danger mb-3">
                <AlertCircle className="size-6" />
                <h3 className="text-base font-semibold text-fg">Uninstall {uninstallConfirmItem.name}?</h3>
              </div>
              <p className="text-xs text-subtle leading-relaxed mb-6">
                This will remove the configuration and credentials for {uninstallConfirmItem.name}. If this was the
                active AI provider, AIE will automatically revert back to the Autonomous Threat Intelligence Agent.
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
                  className="text-xs bg-danger/15 text-danger border border-danger/40 hover:bg-danger/25"
                >
                  Confirm uninstall
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}

type IconType = typeof Globe;

/** Hadrian-style integration card: icon + name, one-line description, one status chip, one action. */
function IntegrationCard({
  icon: Icon,
  name,
  meta,
  description,
  footnote,
  status,
  action,
  onOpen,
}: {
  icon: IconType;
  name: React.ReactNode;
  meta?: React.ReactNode;
  description: React.ReactNode;
  footnote?: React.ReactNode;
  status?: React.ReactNode;
  action?: React.ReactNode;
  onOpen?: () => void;
}) {
  const head = (
    <>
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-bg-subtle text-fg">
        <Icon className="size-[18px]" strokeWidth={1.75} />
      </span>
      <span className="min-w-0">
        <span className="block truncate text-base font-medium text-fg group-hover/head:text-accent">{name}</span>
        {meta && <span className="block truncate text-xs text-subtle">{meta}</span>}
      </span>
    </>
  );
  return (
    <div className="flex flex-col rounded-xl border border-border bg-bg-card p-5">
      {onOpen ? (
        <button type="button" onClick={onOpen} className="group/head flex min-w-0 items-center gap-3 text-left" title="View details">
          {head}
        </button>
      ) : (
        <div className="flex min-w-0 items-center gap-3">{head}</div>
      )}
      <p className="mt-3 line-clamp-2 text-sm leading-relaxed text-muted">{description}</p>
      {footnote && <div className="mt-2">{footnote}</div>}
      <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-5">
        <div>{status}</div>
        {action}
      </div>
    </div>
  );
}

function TabIntro({ title, description, aside }: { title: string; description: string; aside?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 className="text-lg font-medium text-fg">{title}</h2>
        <p className="mt-1 text-sm text-muted">{description}</p>
      </div>
      {aside}
    </div>
  );
}
