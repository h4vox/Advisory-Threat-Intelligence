import { useState } from "react";
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
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/cn";
import {
  getMarketplaceData,
  installMarketplaceIntegration,
  uninstallMarketplaceIntegration,
  configureMarketplaceIntegration,
  setActiveAgentProvider,
  testIntegrationConnection,
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

  // Selected item for 1/4 width right details drawer
  const [selectedIntegration, setSelectedIntegration] = useState<IntegrationItem | null>(null);

  // Drawer collapsible sections
  const [actionsExpanded, setActionsExpanded] = useState(true);
  const [connectorsExpanded, setConnectorsExpanded] = useState(true);

  // Install / Configure Modal state
  const [configModalItem, setConfigModalItem] = useState<IntegrationItem | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [authTokenInput, setAuthTokenInput] = useState("");
  const [selectedModelInput, setSelectedModelInput] = useState("");
  const [oauthStep, setOauthStep] = useState<"ready" | "authorizing" | "completed">("ready");
  const [modalFeedback, setModalFeedback] = useState<string | null>(null);

  // Uninstall confirmation modal
  const [uninstallConfirmItem, setUninstallConfirmItem] = useState<IntegrationItem | null>(null);

  // Test connection feedback
  const [testResult, setTestResult] = useState<{
    id: string;
    message: string;
    latencyMs?: number;
    success: boolean;
  } | null>(null);

  // Query marketplace state
  const { data: marketplaceState, isLoading, refetch } = useQuery({
    queryKey: ["marketplace_state"],
    queryFn: () => getMarketplaceData(),
  });

  const integrations = marketplaceState?.integrations || [];
  const activeProviderId = marketplaceState?.activeProviderId || "agy_agent";
  const activeModel = marketplaceState?.activeModel || "AGY: gemini-3.8-flash-low";

  // Mutations
  const installMutation = useMutation({
    mutationFn: (data: { id: string; config?: Record<string, any> }) =>
      installMarketplaceIntegration({ data }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
      if (configModalItem?.id === res.integration.id) {
        setConfigModalItem(null);
      }
      if (selectedIntegration?.id === res.integration.id) {
        setSelectedIntegration(res.integration);
      }
      setModalFeedback("Integration installed and configured successfully!");
      setTimeout(() => setModalFeedback(null), 3000);
    },
  });

  const uninstallMutation = useMutation({
    mutationFn: (id: string) => uninstallMarketplaceIntegration({ data: { id } }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
      setUninstallConfirmItem(null);
      if (selectedIntegration?.id === res.id) {
        setSelectedIntegration((prev) => (prev ? { ...prev, status: "not_installed", config: undefined } : null));
      }
    },
  });

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

  const setActiveMutation = useMutation({
    mutationFn: (data: { id: string; model?: string }) =>
      setActiveAgentProvider({ data }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
    },
  });

  const testConnectionMutation = useMutation({
    mutationFn: (id: string) => testIntegrationConnection({ data: { id } }),
    onSuccess: (res) => {
      setTestResult({
        id: res.id,
        message: res.message,
        latencyMs: res.latencyMs,
        success: true,
      });
      setTimeout(() => setTestResult(null), 6000);
    },
    onError: (err) => {
      setTestResult({
        id: selectedIntegration?.id || "",
        message: err instanceof Error ? err.message : "Connection probe failed",
        success: false,
      });
      setTimeout(() => setTestResult(null), 6000);
    },
  });

  // Open Install/Configure modal
  const handleOpenConfigModal = (item: IntegrationItem) => {
    setConfigModalItem(item);
    setApiKeyInput(item.config?.apiKey || "");
    setAuthTokenInput(item.config?.authToken || "");
    setSelectedModelInput(item.config?.selectedModel || item.supportedModels[0] || "");
    setOauthStep(item.status === "installed" ? "completed" : "ready");
    setModalFeedback(null);
  };

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

  return (
    <AppShell>
      <div className="relative flex flex-col h-full overflow-y-auto">
        {/* Top Header */}
        <div className="border-b border-border bg-bg/80 backdrop-blur-md px-6 py-5 sticky top-0 z-20">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
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

            {/* Active AI Agent Indicator Badge */}
            <div className="flex items-center gap-3 bg-bg-elevated border border-border px-3.5 py-2 rounded-xl shadow-xs">
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

          {/* Navigation Columns / Tabs */}
          <div className="flex items-center gap-1 mt-6 border-b border-border/60 -mb-5 pb-px overflow-x-auto select-none">
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
              <Badge tone="accent" className="text-[10px] py-0 px-1.5 ml-1 text-white">
                Core AI
              </Badge>
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
              Powerups
              <Badge className="text-[10px] py-0 px-1.5 ml-1 border border-border">
                {marketplaceState?.powerups?.length || 3}
              </Badge>
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
              <Flame className="size-3.5" />
              Playbooks & Blocks (Emulation/Simulation)
              <Badge className="text-[10px] py-0 px-1.5 ml-1 border border-border">
                {marketplaceState?.playbooks?.length || 3}
              </Badge>
            </button>
          </div>
        </div>

        {/* Tab Content Body */}
        <div className="flex-1 p-6 pb-20">
          {/* ========================================================================= */}
          {/* RESPONSE INTEGRATION TAB (PRIMARY FUNCTIONAL FOCUS)                       */}
          {/* ========================================================================= */}
          {activeTab === "response" && (
            <div className="space-y-6">
              {/* Category Filter & Search Toolbar */}
              <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-bg-elevated/70 border border-border p-3 rounded-xl">
                {/* Category Pills */}
                <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
                  <span className="text-[11px] font-medium text-subtle mr-1 flex items-center gap-1">
                    <Filter className="size-3" /> Category:
                  </span>
                  {["All", "Intelligence", "Analysis", "Automation"].map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setCategoryFilter(cat)}
                      className={cn(
                        "text-xs px-3 py-1 rounded-lg transition-all cursor-pointer font-medium",
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
                <div className="flex items-center gap-2.5">
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

                  <div className="relative w-full sm:w-64">
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

              {/* Feedback Alert if tested */}
              {testResult && (
                <div
                  className={cn(
                    "p-3.5 rounded-xl border text-xs flex items-center justify-between transition-all",
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
                        {/* Button 1: Details (opens right drawer ~1/4 size) */}
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
                            onClick={() => handleOpenConfigModal(item)}
                            className="text-xs h-7.5 px-3 gap-1.5 font-medium border-accent/30 hover:border-accent"
                          >
                            <Settings2 className="size-3 text-accent" />
                            Configure
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            variant="primary"
                            onClick={() => handleOpenConfigModal(item)}
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
          )}

          {/* ========================================================================= */}
          {/* CURATED RESOURCES TAB                                                     */}
          {/* ========================================================================= */}
          {activeTab === "curated" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
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
          )}

          {/* ========================================================================= */}
          {/* POWERUPS TAB                                                              */}
          {/* ========================================================================= */}
          {activeTab === "powerups" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-fg">Automation Powerups & Exporters</h2>
                  <p className="text-xs text-subtle mt-0.5">
                    Extend AIE capabilities with custom rule generators, incident response webhooks, and bundle serializers.
                  </p>
                </div>
              </div>

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
          )}

          {/* ========================================================================= */}
          {/* PLAYBOOKS & BLOCKS TAB                                                    */}
          {/* ========================================================================= */}
          {activeTab === "playbooks" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-fg">Adversary Emulation & Simulation Playbooks</h2>
                  <p className="text-xs text-subtle mt-0.5">
                    Pre-compiled executable attack sequences, Atomic Red Team blocks, and multi-stage adversary campaigns.
                  </p>
                </div>
              </div>

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
                            "text-[10px] border",
                            pb.difficulty === "Beginner"
                              ? "border-emerald-500/30 text-emerald-400"
                              : pb.difficulty === "Intermediate"
                              ? "border-amber-500/30 text-amber-400"
                              : "border-red-500/30 text-red-400"
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
          )}

          {/* ========================================================================= */}
          {/* HOME TAB                                                                  */}
          {/* ========================================================================= */}
          {activeTab === "home" && (
            <div className="space-y-6">
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
        </div>

        {/* ========================================================================= */}
        {/* RIGHT DETAILS DRAWER: 1/4 WIDTH OF SCREEN                                 */}
        {/* ========================================================================= */}
        {selectedIntegration && (
          <div className="fixed inset-y-0 right-0 z-50 flex">
            {/* Backdrop */}
            <div
              className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity"
              onClick={() => setSelectedIntegration(null)}
            />

            {/* Drawer Container: 1/4 screen size (w-full sm:w-96 md:w-[28rem] lg:w-[26vw] min-w-[340px]) */}
            <div className="relative w-full sm:w-96 md:w-[28rem] lg:w-[26vw] min-w-[340px] max-w-full h-full bg-bg-elevated border-l border-border shadow-2xl flex flex-col z-10 animate-in slide-in-from-right duration-200">
              {/* Drawer Header */}
              <div className="p-5 border-b border-border flex items-start justify-between gap-3 bg-bg/50">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-bg-subtle border border-border text-accent">
                    {selectedIntegration.type === "cli_agent" ? (
                      <Terminal className="size-5" />
                    ) : (
                      <Sparkles className="size-5" />
                    )}
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-fg">{selectedIntegration.name}</h2>
                    <div className="flex items-center gap-1.5 text-xs text-subtle mt-0.5">
                      <span>{selectedIntegration.provider}</span>
                      <span>·</span>
                      <span className="font-mono text-[11px] text-accent">{selectedIntegration.version}</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => setSelectedIntegration(null)}
                  className="p-1.5 rounded-lg text-subtle hover:text-fg hover:bg-bg-subtle transition-colors cursor-pointer"
                >
                  <X className="size-4" />
                </button>
              </div>

              {/* Drawer Body (Scrollable) */}
              <div className="flex-1 p-5 overflow-y-auto space-y-5 text-xs">
                {/* Status & Active Banner */}
                <div className="flex items-center justify-between p-3 rounded-xl bg-bg-subtle border border-border">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-subtle">Deployment Status:</span>
                    {selectedIntegration.status === "installed" ? (
                      <Badge className="bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px]">
                        Installed & Verified
                      </Badge>
                    ) : (
                      <Badge className="text-subtle text-[10px] border border-border">
                        Not Installed
                      </Badge>
                    )}
                  </div>
                  {activeProviderId === selectedIntegration.id && (
                    <Badge className="bg-accent/15 text-accent border border-accent/30 text-[10px]">
                      Active Provider
                    </Badge>
                  )}
                </div>

                {/* Overview Section */}
                <div>
                  <h4 className="text-[11px] uppercase font-mono tracking-wider text-subtle mb-1.5 font-semibold">
                    Overview
                  </h4>
                  <p className="text-xs text-muted leading-relaxed">
                    {selectedIntegration.overview || selectedIntegration.description}
                  </p>
                </div>

                {/* DROPDOWN / COLLAPSIBLE: ACTIONS */}
                <div className="border border-border rounded-xl bg-bg-subtle/50 overflow-hidden">
                  <button
                    onClick={() => setActionsExpanded(!actionsExpanded)}
                    className="w-full flex items-center justify-between p-3 text-xs font-semibold text-fg hover:bg-bg-subtle transition-colors cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2">
                      <Zap className="size-3.5 text-accent" />
                      <span>Supported Actions ({selectedIntegration.actions.length})</span>
                    </div>
                    {actionsExpanded ? <ChevronDown className="size-4 text-subtle" /> : <ChevronRight className="size-4 text-subtle" />}
                  </button>

                  {actionsExpanded && (
                    <div className="p-3 pt-0 space-y-2 border-t border-border/50">
                      {selectedIntegration.actions.map((act) => (
                        <div key={act.id} className="p-2.5 rounded-lg bg-bg-elevated border border-border/60">
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

                {/* DROPDOWN / COLLAPSIBLE: CONNECTORS */}
                <div className="border border-border rounded-xl bg-bg-subtle/50 overflow-hidden">
                  <button
                    onClick={() => setConnectorsExpanded(!connectorsExpanded)}
                    className="w-full flex items-center justify-between p-3 text-xs font-semibold text-fg hover:bg-bg-subtle transition-colors cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2">
                      <Plug className="size-3.5 text-accent" />
                      <span>Connectors & Auth Protocol</span>
                    </div>
                    {connectorsExpanded ? <ChevronDown className="size-4 text-subtle" /> : <ChevronRight className="size-4 text-subtle" />}
                  </button>

                  {connectorsExpanded && (
                    <div className="p-3 pt-0 space-y-2 border-t border-border/50">
                      {selectedIntegration.connectors.map((conn, i) => (
                        <div key={i} className="p-2.5 rounded-lg bg-bg-elevated border border-border/60">
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

                {/* Supported Models */}
                <div>
                  <h4 className="text-[11px] uppercase font-mono tracking-wider text-subtle mb-1.5 font-semibold">
                    Supported Models
                  </h4>
                  <div className="space-y-1">
                    {selectedIntegration.supportedModels.map((m) => (
                      <div
                        key={m}
                        className="font-mono text-[11px] p-2 rounded-lg bg-bg-subtle border border-border text-fg flex items-center justify-between"
                      >
                        <span>{m}</span>
                        {selectedIntegration.config?.selectedModel === m && (
                          <Badge className="bg-emerald-500/10 text-emerald-400 text-[9px]">Default</Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Tags */}
                <div>
                  <h4 className="text-[11px] uppercase font-mono tracking-wider text-subtle mb-1.5 font-semibold">
                    Security & Emulation Tags
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedIntegration.tags.map((t) => (
                      <span
                        key={t}
                        className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-bg-subtle border border-border text-muted"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Drawer Footer: Actions & Uninstall */}
              <div className="p-4 border-t border-border bg-bg/50 space-y-2">
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
                        className="text-xs h-8 gap-1.5 font-medium"
                      >
                        <Bot className="size-3 text-accent" />
                        {activeProviderId === selectedIntegration.id ? "Active Provider" : "Set as Active"}
                      </Button>

                      {/* Test Connection */}
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={testConnectionMutation.isPending}
                        onClick={() => testConnectionMutation.mutate(selectedIntegration.id)}
                        className="text-xs h-8 gap-1.5"
                      >
                        <RefreshCw
                          className={cn("size-3 text-accent", testConnectionMutation.isPending && "animate-spin")}
                        />
                        <span>{testConnectionMutation.isPending ? "Testing..." : "Test Connection"}</span>
                      </Button>
                    </div>

                    <div className="flex items-center justify-between gap-2 pt-2 border-t border-border/60">
                      {/* UNINSTALL OPTION INSIDE DETAILS DRAWER (AS REQUESTED) */}
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => setUninstallConfirmItem(selectedIntegration)}
                        className="text-xs h-8 gap-1.5 text-red-400 hover:text-red-300 hover:bg-red-500/10 border-red-500/30"
                      >
                        <Trash2 className="size-3" />
                        Uninstall
                      </Button>

                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleOpenConfigModal(selectedIntegration)}
                        className="text-xs h-8 gap-1.5"
                      >
                        <Settings2 className="size-3" />
                        Configure
                      </Button>
                    </div>
                  </>
                ) : (
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() => handleOpenConfigModal(selectedIntegration)}
                    className="w-full text-xs h-8 gap-2 bg-accent text-white font-medium"
                  >
                    <Download className="size-3.5" />
                    Install Integration
                  </Button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* INSTALL / CONFIGURE MODAL DIALOG                                          */}
        {/* ========================================================================= */}
        {configModalItem && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/60 backdrop-blur-xs" onClick={() => setConfigModalItem(null)} />

            <div className="relative w-full max-w-lg bg-bg-elevated border border-border rounded-2xl shadow-2xl p-6 z-10 animate-in zoom-in-95 duration-150">
              <div className="flex items-start justify-between gap-3 mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-accent/10 border border-accent/20 text-accent">
                    {configModalItem.type === "cli_agent" ? <Terminal className="size-5" /> : <Key className="size-5" />}
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-fg">
                      {configModalItem.status === "installed" ? "Configure" : "Install"} {configModalItem.name}
                    </h3>
                    <p className="text-xs text-subtle">
                      Provider: {configModalItem.provider} · Version: {configModalItem.version}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setConfigModalItem(null)}
                  className="p-1 rounded-lg text-subtle hover:text-fg hover:bg-bg-subtle"
                >
                  <X className="size-4" />
                </button>
              </div>

              {/* CLI Agent Installation & OAuth Flow */}
              {configModalItem.type === "cli_agent" && (
                <div className="space-y-4 text-xs">
                  <div>
                    <label className="block text-subtle font-medium mb-1">Installation Command</label>
                    <div className="flex items-center gap-2 p-2.5 rounded-lg bg-bg-subtle border border-border font-mono text-[11px] text-accent break-all select-all">
                      <span>{configModalItem.installCommand}</span>
                    </div>
                  </div>

                  {/* OAuth Flow Integration */}
                  <div className="p-4 rounded-xl border border-accent/20 bg-accent/5 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="font-semibold text-fg flex items-center gap-1.5">
                        <Shield className="size-3.5 text-accent" />
                        OAuth Authentication Redirect
                      </div>
                      <Badge className="text-[10px] border border-accent/30 text-accent">
                        Required
                      </Badge>
                    </div>
                    <p className="text-xs text-muted leading-relaxed">
                      This agent requires authentication via its official provider portal. Click below to open the
                      authorization URL directly:
                    </p>

                    <div className="flex items-center gap-2">
                      <a
                        href={configModalItem.authUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent text-white font-medium text-xs hover:bg-accent/90 transition-colors shadow-xs"
                      >
                        <ExternalLink className="size-3" />
                        Open Authorization URL
                      </a>

                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => setOauthStep("authorizing")}
                        className="text-xs h-7.5"
                      >
                        Enter Auth Token
                      </Button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-subtle font-medium mb-1">
                      Authorization Code / Token (Optional for Pre-authenticated CLI)
                    </label>
                    <Input
                      placeholder="Paste authorization token or leave blank if authenticated via shell..."
                      value={authTokenInput}
                      onChange={(e) => setAuthTokenInput(e.target.value)}
                      className="font-mono text-xs bg-bg-subtle"
                    />
                  </div>

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
                      <label className="text-subtle font-medium">API Key</label>
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
                  disabled={installMutation.isPending || configureMutation.isPending}
                  onClick={() => {
                    const configPayload = {
                      apiKey: apiKeyInput || undefined,
                      authToken: authTokenInput || undefined,
                      selectedModel: selectedModelInput || configModalItem.supportedModels[0],
                    };

                    if (configModalItem.status === "installed") {
                      configureMutation.mutate({
                        id: configModalItem.id,
                        config: configPayload,
                      });
                    } else {
                      installMutation.mutate({
                        id: configModalItem.id,
                        config: configPayload,
                      });
                    }
                  }}
                  className="text-xs bg-accent text-white font-medium"
                >
                  {configModalItem.status === "installed" ? "Save Configuration" : "Complete & Install"}
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
