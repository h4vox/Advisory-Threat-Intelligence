import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  CheckCircle2,
  Clock,
  Compass,
  Database,
  Eye,
  FileCode,
  Filter,
  HardDrive,
  Layers,
  Moon,
  Play,
  RefreshCw,
  RotateCcw,
  Save,
  Shield,
  ShieldAlert,
  Sliders,
  Sparkles,
  Sun,
  Trash2,
  UsersRound,
  Zap,
  Code2,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { UsersPanel } from "@/components/settings/users-panel";
import { DataSourceNotice } from "@/components/layout/data-source-notice";
import { ActionButton, PageHeader, SegmentedTabs } from "@/components/layout/page";
import { StatusChip } from "@/components/ui/primitives";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { Select } from "@/components/ui/select";
import {
  checkCrawlerSchedule,
  getAppSettings,
  getCrawlConfig,
  getStorageStats,
  purgeServerCaches,
  updateAppSettings,
  updateCrawlerConfig,
  getAgentStatus,
  getMarketplaceData,
  setActiveAgentProvider,
  setDebuggerMode,
} from "@/lib/aie/server";
import { getAgentInfo } from "@/lib/aie/server-agent";
import { AGY_AVAILABLE_MODELS } from "@/lib/aie/agent-framework/types";
import { z } from "zod";
import { cn } from "@/lib/cn";
import type { AppSettings, CrawlConfig, ResourceKind } from "@/lib/aie/types";
import { RESEARCH_CATEGORIES, normalizeResearchDiscovery, type ResearchDiscoveryConfig } from "@/lib/aie/research-taxonomy";

const settingsSearchSchema = z.object({
  tab: z.enum(["crawler", "policy", "storage", "display", "agent", "users"]).optional(),
});

export const Route = createFileRoute("/settings")({
  validateSearch: (search) => settingsSearchSchema.parse(search),
  component: SettingsPage,
});

const SETTINGS_SECTIONS = [
  { id: "crawler", label: "Crawler & ingestion", icon: Bot, badge: "Engine" },
  { id: "policy", label: "Intelligence policies", icon: Shield, badge: "SOC" },
  { id: "storage", label: "Database & storage", icon: Database, badge: "Storage" },
  { id: "display", label: "Display & preferences", icon: Sliders, badge: "UI" },
  { id: "agent", label: "AI agent", icon: Sparkles, badge: "AGY" },
  { id: "users", label: "Users & access", icon: UsersRound, badge: "Admin" },
] as const;

// Minimum is 15m to match the server validator (frequencyMinutes >= 15); the 5m "Test" preset was
// removed because saving it failed validation. 15m is the shortest production cadence.
const INTERVAL_PRESETS = [
  { label: "5m", mins: 5, tag: "Min" },
  { label: "15m", mins: 15 },
  { label: "30m", mins: 30 },
  { label: "1h", mins: 60 },
  { label: "2h", mins: 120 },
  { label: "6h", mins: 360, tag: "Std" },
  { label: "12h", mins: 720 },
  { label: "24h", mins: 1440, tag: "Daily" },
];

function formatCrawlInterval(mins: number): string {
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

type SettingsSectionId = (typeof SETTINGS_SECTIONS)[number]["id"];

function SettingsPage() {
  const search = Route.useSearch();
  const qc = useQueryClient();
  const [activeSection, setActiveSection] = useState<SettingsSectionId>(
    search.tab ?? "crawler"
  );
  // Deep links (e.g. Profile → Manage users) can switch sections while the page is open.
  useEffect(() => {
    if (search.tab) setActiveSection(search.tab);
  }, [search.tab]);

  // Fetch Configurations from Database
  const configQuery = useQuery({
    queryKey: ["crawler-config"],
    queryFn: () => getCrawlConfig(),
    staleTime: 60000,
  });

  const appSettingsQuery = useQuery({
    queryKey: ["app-settings"],
    queryFn: () => getAppSettings(),
    staleTime: 60000,
  });

  // Where the library is read from (shared with the app shell's nav counts).
  const dataSourceQuery = useQuery({
    queryKey: ["nav-counts"],
    queryFn: () => getStorageStats(),
    staleTime: 5 * 60_000,
  });
  const dataSource = (() => {
    const st = dataSourceQuery.data;
    if (!st) return { label: "Checking…", chip: "Checking…", dot: "bg-subtle", text: "text-subtle", engine: undefined };
    if (st.engine === "mongodb" && !st.error) return { label: `MongoDB · ${st.databaseName}`, chip: "Connected", dot: "bg-sage", text: "text-sage", engine: "mongodb" as const };
    if (st.engine === "mongodb") return { label: "MongoDB not reachable", chip: "Not reachable", dot: "bg-danger", text: "text-danger", engine: "mongodb" as const };
    return { label: "Local database (MONGODB_URI not set)", chip: "MONGODB_URI not set", dot: "bg-warn", text: "text-warn", engine: "local" as const };
  })();

  const storageStatsQuery = useQuery({
    queryKey: ["storage-stats"],
    queryFn: () => getStorageStats(),
    enabled: activeSection === "storage",
    staleTime: 30000,
    placeholderData: (previousData) => previousData,
    refetchInterval: () => (activeSection === "storage" ? 25000 : false),
  });

  const agentStatusQuery = useQuery({
    queryKey: ["agent-status"],
    queryFn: () => getAgentStatus(),
    enabled: activeSection === "agent",
    staleTime: 60000,
    placeholderData: (previousData) => previousData,
  });

  const marketplaceQuery = useQuery({
    queryKey: ["marketplace_state"],
    queryFn: () => getMarketplaceData(),
    staleTime: 30000,
  });

  // Local Form States for instantaneous 0ms responsive UI
  const [crawlForm, setCrawlForm] = useState<Partial<CrawlConfig>>({});
  const [appForm, setAppForm] = useState<Partial<AppSettings>>({});
  const [isDirty, setIsDirty] = useState(false);

  // Central AI provider/model picker (Settings → AI agent). null = follow the saved active selection.
  const [aiProviderPick, setAiProviderPick] = useState<string | null>(null);
  const [aiModelPick, setAiModelPick] = useState<string | null>(null);
  const stripModelLabel = (m?: string | null) => {
    if (!m) return "";
    const i = m.indexOf(":");
    return (i >= 0 ? m.slice(i + 1) : m).trim();
  };

  // Visual Theme & UI Preferences
  const [uiStyle, setUiStyle] = useState<"default" | "liquid-glass">(() => {
    if (typeof window !== "undefined") {
      return (localStorage.getItem("aie_ui_style") as "default" | "liquid-glass") || "default";
    }
    return "default";
  });

  const [colorTheme, setColorTheme] = useState<"dark" | "light">(() => {
    if (typeof window !== "undefined") {
      return (localStorage.getItem("aie_theme") as "dark" | "light") || "dark";
    }
    return "dark";
  });

  const [spinnerVariant, setSpinnerVariant] = useState<"radial" | "ring" | "dots">(() => {
    if (typeof window !== "undefined") {
      const saved = (localStorage.getItem("aie_spinner_variant") as string | null) || "radial";
      return saved === "ios" ? "radial" : (saved as "radial" | "ring" | "dots");
    }
    return "radial";
  });

  const [previewSpinnerSize, setPreviewSpinnerSize] = useState<"xs" | "sm" | "md" | "lg">("md");

  const [glassRatio, setGlassRatio] = useState<number>(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("aie_glass_blur_ratio");
      if (saved) {
        const parsed = parseInt(saved, 10);
        if (!isNaN(parsed) && parsed >= 5 && parsed <= 110) return parsed;
      }
    }
    return 70;
  });

  const applyGlassRatioTokens = (val: number) => {
    if (typeof document === "undefined") return;
    const blurPx = Math.round(6 + (val / 100) * 36.0);
    const opacityDark = (0.05 + (val / 100) * 0.16).toFixed(3);
    const opacityLight = (0.50 + (val / 100) * 0.28).toFixed(3);
    const specular = (0.22 + (val / 100) * 0.38).toFixed(3);
    document.documentElement.style.setProperty("--glass-blur-ratio", `${val}%`);
    document.documentElement.style.setProperty("--glass-blur", `${blurPx}px`);
    document.documentElement.style.setProperty("--glass-opacity-dark", `${opacityDark}`);
    document.documentElement.style.setProperty("--glass-opacity-light", `${opacityLight}`);
    document.documentElement.style.setProperty("--glass-specular-opacity", `${specular}`);
  };

  const handleGlassRatioChange = (val: number) => {
    setGlassRatio(val);
    localStorage.setItem("aie_glass_blur_ratio", String(val));
    applyGlassRatioTokens(val);
    window.dispatchEvent(new Event("aie-glass-ratio-changed"));
  };

  // Keep settings synchronized across tabs and components
  useEffect(() => {
    const handleStyleSync = () => {
      const saved = (localStorage.getItem("aie_ui_style") as "default" | "liquid-glass") || "default";
      setUiStyle(saved);
    };
    const handleThemeSync = () => {
      const savedTheme = (localStorage.getItem("aie_theme") as "dark" | "light") || "dark";
      setColorTheme(savedTheme);
    };
    const handleSpinnerSync = () => {
      const saved = (localStorage.getItem("aie_spinner_variant") as string | null) || "radial";
      setSpinnerVariant(saved === "ios" ? "radial" : (saved as "radial" | "ring" | "dots"));
    };
    const handleGlassRatioSync = () => {
      const saved = localStorage.getItem("aie_glass_blur_ratio");
      if (saved) {
        const parsed = parseInt(saved, 10);
        if (!isNaN(parsed)) {
          setGlassRatio(parsed);
          applyGlassRatioTokens(parsed);
        }
      }
    };

    window.addEventListener("aie-style-changed", handleStyleSync);
    window.addEventListener("aie-theme-changed", handleThemeSync);
    window.addEventListener("aie-spinner-changed", handleSpinnerSync);
    window.addEventListener("aie-glass-ratio-changed", handleGlassRatioSync);
    return () => {
      window.removeEventListener("aie-style-changed", handleStyleSync);
      window.removeEventListener("aie-theme-changed", handleThemeSync);
      window.removeEventListener("aie-spinner-changed", handleSpinnerSync);
      window.removeEventListener("aie-glass-ratio-changed", handleGlassRatioSync);
    };
  }, []);

  const handleUiStyleChange = (nextStyle: "default" | "liquid-glass") => {
    setUiStyle(nextStyle);
    localStorage.setItem("aie_ui_style", nextStyle);
    document.documentElement.setAttribute("data-style", nextStyle);
    if (nextStyle === "liquid-glass") {
      document.documentElement.classList.add("theme-liquid-glass");
      applyGlassRatioTokens(glassRatio);
    } else {
      document.documentElement.classList.remove("theme-liquid-glass");
    }
    window.dispatchEvent(new Event("aie-style-changed"));
    toast.success(
      nextStyle === "liquid-glass"
        ? "Liquid Glass mode activated"
        : "Tactical Slate (Default) activated"
    );
  };

  const handleColorThemeChange = (nextTheme: "dark" | "light") => {
    setColorTheme(nextTheme);
    localStorage.setItem("aie_theme", nextTheme);
    document.documentElement.setAttribute("data-theme", nextTheme);
    if (nextTheme === "light") {
      document.documentElement.classList.add("light");
    } else {
      document.documentElement.classList.remove("light");
    }
    window.dispatchEvent(new Event("aie-theme-changed"));
    toast.success(
      nextTheme === "dark"
        ? "Dark mode enabled"
        : "Light mode enabled"
    );
  };

  const handleSpinnerVariantChange = (nextVariant: "radial" | "ring" | "dots") => {
    setSpinnerVariant(nextVariant);
    localStorage.setItem("aie_spinner_variant", nextVariant);
    window.dispatchEvent(new Event("aie-spinner-changed"));
    toast.success(`Activity indicator set to ${nextVariant === "radial" ? "Radial Blade" : nextVariant === "ring" ? "Activity Ring" : "Pulse Dots"}`);
  };

  // Sync initial server values to local form state
  useEffect(() => {
    if (configQuery.data) {
      setCrawlForm(configQuery.data);
    }
  }, [configQuery.data]);

  useEffect(() => {
    if (appSettingsQuery.data) {
      setAppForm(appSettingsQuery.data);
    }
  }, [appSettingsQuery.data]);

  const updateCrawlField = <K extends keyof CrawlConfig>(key: K, val: CrawlConfig[K]) => {
    setCrawlForm((prev) => ({ ...prev, [key]: val }));
    setIsDirty(true);
  };

  const updateAppField = <K extends keyof AppSettings>(key: K, val: AppSettings[K]) => {
    setAppForm((prev) => ({ ...prev, [key]: val }));
    setIsDirty(true);
  };

  // Mutation to save changes atomically to DB
  const saveMutation = useMutation({
    mutationFn: async () => {
      const p1 = updateCrawlerConfig({ data: crawlForm as any });
      const p2 = updateAppSettings({ data: appForm as any });
      return await Promise.all([p1, p2]);
    },
    onSuccess: () => {
      setIsDirty(false);
      void qc.invalidateQueries({ queryKey: ["crawler-config"] });
      void qc.invalidateQueries({ queryKey: ["app-settings"] });
      void qc.invalidateQueries({ queryKey: ["crawlerState"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
      toast.success("Settings saved successfully to Database");
    },
    onError: (err: Error) => {
      toast.error(`Failed to save settings: ${err.message}`);
    },
  });

  // Apply the central AI provider/model selection. Uses the REST-aware server fn so an API
  // provider's model (e.g. gpt-4o) is persisted on the integration, not AGY-normalised.
  const applyActiveAIMutation = useMutation({
    mutationFn: (vars: { id: string; model: string }) => setActiveAgentProvider({ data: vars }),
    onSuccess: (res) => {
      setAiProviderPick(null);
      setAiModelPick(null);
      void qc.invalidateQueries({ queryKey: ["marketplace_state"] });
      void qc.invalidateQueries({ queryKey: ["app-settings"] });
      toast.success(`Active AI set to ${res.activeModel}`);
    },
    onError: (err: Error) => {
      toast.error(`Could not set active AI: ${err.message}`);
    },
  });

  // Mutation to purge in-memory cache
  const purgeMutation = useMutation({
    mutationFn: () => purgeServerCaches(),
    onSuccess: () => {
      void qc.invalidateQueries();
      toast.success("All in-memory server caches flushed (0ms fresh state)");
    },
    onError: (err: Error) => {
      toast.error(`Cache flush failed: ${err.message}`);
    },
  });

  // Mutation to manually trigger/test scheduled scan evaluation
  const checkScheduleMutation = useMutation({
    mutationFn: () => checkCrawlerSchedule(),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["crawler-config"] });
      void qc.invalidateQueries({ queryKey: ["crawlerState"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
      if (res.triggered) {
        toast.success(`Autonomous scheduled scan dispatched`, {
          description: `Job ID: ${res.jobId?.slice(0, 16)} · Next run at ${res.nextRunAt ? new Date(res.nextRunAt).toLocaleTimeString() : "scheduled interval"}`,
        });
      } else {
        toast.info(`Scheduler status: ${res.reason}`, {
          description: res.nextRunAt
            ? `Next autonomous scan scheduled for: ${new Date(res.nextRunAt).toLocaleTimeString()}`
            : undefined,
        });
      }
    },
    onError: (err: Error) => {
      toast.error(`Scheduler check failed: ${err.message}`);
    },
  });

  const handleReset = () => {
    if (configQuery.data) setCrawlForm(configQuery.data);
    if (appSettingsQuery.data) setAppForm(appSettingsQuery.data);
    setIsDirty(false);
    toast.info("Reverted local changes to current database state");
  };

  const currentCrawl = { ...configQuery.data, ...crawlForm };
  const currentApp = { ...appSettingsQuery.data, ...appForm };

  // Central AI selection, derived from the saved marketplace state + the local picks. Installed
  // providers are listed first; the model list follows the chosen provider.
  const aiIntegrations = marketplaceQuery.data?.integrations ?? [];
  const aiSavedProvider = marketplaceQuery.data?.activeProviderId ?? "agy_agent";
  const aiSavedModel = marketplaceQuery.data?.activeModel ?? "";
  const aiEffProvider = aiProviderPick ?? aiSavedProvider;
  const aiEffProviderItem = aiIntegrations.find((x) => x.id === aiEffProvider);
  const aiEffModels = aiEffProviderItem?.supportedModels ?? [];
  const aiDefaultModel =
    aiEffProvider === aiSavedProvider
      ? aiEffModels.find((m) => stripModelLabel(m) === stripModelLabel(aiSavedModel)) ?? aiEffModels[0] ?? aiSavedModel
      : aiEffModels[0] ?? "";
  const aiEffModel = aiModelPick ?? aiDefaultModel;
  const aiProvidersSorted = [...aiIntegrations].sort(
    (a, b) => (a.status === "installed" ? 0 : 1) - (b.status === "installed" ? 0 : 1),
  );
  const aiSelectionChanged =
    aiEffProvider !== aiSavedProvider || stripModelLabel(aiEffModel) !== stripModelLabel(aiSavedModel);

  return (
    <AppShell>
      <div className="mx-auto max-w-6xl pb-12">
        <PageHeader
          title="Settings"
          description={
            <span className="flex flex-col gap-1.5">
              <span>
                Configure acquisition pipelines, qualification thresholds, retention policies, and database telemetry.
              </span>
              <span className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                {isDirty ? (
                  <span className="flex items-center gap-1.5 text-warn">
                    <span className="size-2 rounded-full bg-warn " />
                    Unsaved changes
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-subtle">
                    <CheckCircle2 className="size-3.5 text-sage" />
                    All configurations synced to database
                  </span>
                )}
                <span className="flex items-center gap-1.5 text-subtle">
                  <span className={cn("size-1.5 rounded-full", dataSource.dot)} />
                  Primary storage: <span className="text-fg">{dataSource.label}</span>
                </span>
              </span>
            </span>
          }
          actions={
            <>
              <ActionButton
                icon={RefreshCw}
                disabled={purgeMutation.isPending}
                onClick={() => purgeMutation.mutate()}
                title="Flush in-memory caches to force fresh retrieval from Database"
              >
                {purgeMutation.isPending ? "Purging…" : "Purge cache"}
              </ActionButton>
              {isDirty && (
                <ActionButton icon={RotateCcw} onClick={handleReset}>
                  Discard
                </ActionButton>
              )}
              <ActionButton
                variant="primary"
                icon={Save}
                disabled={!isDirty || saveMutation.isPending}
                onClick={() => saveMutation.mutate()}
              >
                {saveMutation.isPending ? "Saving to DB…" : "Save changes"}
              </ActionButton>
            </>
          }
        />

        {/* Sticky unsaved-changes bar: keeps Save/Discard reachable while scrolling long forms */}
        {isDirty && (
          <div
            className={cn(
              "sticky top-2 z-20 mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl px-4 py-3 transition-all",
              uiStyle === "liquid-glass"
                ? "sticky-liquid-glass"
                : "border border-border bg-bg/95 backdrop-blur-md ",
            )}
          >
            <span className="flex items-center gap-1.5 text-sm text-warn">
              <span className="size-2 rounded-full bg-warn " />
              Unsaved changes
            </span>
            <div className="flex items-center gap-2">
              <ActionButton icon={RotateCcw} onClick={handleReset}>
                Discard
              </ActionButton>
              <ActionButton
                variant="primary"
                icon={Save}
                disabled={saveMutation.isPending}
                onClick={() => saveMutation.mutate()}
              >
                {saveMutation.isPending ? "Saving to DB…" : "Save changes"}
              </ActionButton>
            </div>
          </div>
        )}

        <DeveloperModeCard />

        <div className="grid grid-cols-[minmax(0,1fr)] gap-6 lg:grid-cols-[256px_minmax(0,1fr)] lg:items-start">
        {/* ========================================================================= */}
        {/* SECTION NAVIGATION: tabs on mobile, left rail on desktop                  */}
        {/* ========================================================================= */}
        <div className="lg:hidden">
          <SegmentedTabs
            ariaLabel="Settings sections"
            value={activeSection}
            onChange={setActiveSection}
            items={SETTINGS_SECTIONS.map((sec) => ({ value: sec.id, label: sec.label, icon: sec.icon }))}
          />
        </div>
        <nav aria-label="Settings sections" className="hidden lg:sticky lg:top-2 lg:block">
          <ul className="space-y-0.5">
            {SETTINGS_SECTIONS.map((sec) => {
              const active = activeSection === sec.id;
              return (
                <li key={sec.id}>
                  <button
                    type="button"
                    onClick={() => setActiveSection(sec.id)}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "relative flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm font-medium transition-colors select-none",
                      active ? "bg-bg-subtle text-fg" : "text-muted hover:bg-bg-elevated hover:text-fg",
                    )}
                  >
                    {active && <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-accent" />}
                    <sec.icon className={cn("size-4 shrink-0", active ? "text-accent" : "text-muted")} />
                    <span className="min-w-0 flex-1 truncate">{sec.label}</span>
                    <span className="text-[11px] text-subtle">
                      {sec.badge}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="min-w-0 space-y-6">

        {/* ========================================================================= */}
        {/* TAB 1: CRAWLER & INGESTION ENGINE CONTROLS                                */}
        {/* ========================================================================= */}
        {activeSection === "crawler" && (
          <div className="space-y-6">
            {/* Section 1.1: Autonomous Schedule & Execution Limits */}
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <div className="flex flex-col gap-3 border-b border-border pb-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h3 className="flex items-center gap-2 text-base font-medium text-fg">
                    <Activity className="size-4 text-muted" strokeWidth={1.75} />
                    Autonomous acquisition & schedule engine
                  </h3>
                  <p className="text-xs text-muted">
                    Control the autonomous crawler scheduler, concurrency limit, and traversal depth.
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <label className="flex cursor-pointer items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={currentCrawl.enabled ?? true}
                      onChange={(e) => updateCrawlField("enabled", e.target.checked)}
                      className={switchCls}
                    />
                    <span>Master scheduler enabled</span>
                  </label>
                  <label className="flex cursor-pointer items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={currentCrawl.paused ?? false}
                      onChange={(e) => updateCrawlField("paused", e.target.checked)}
                      className={switchCls}
                    />
                    <span className={currentCrawl.paused ? "text-warn" : "text-muted"}>Pause jobs</span>
                  </label>
                </div>
              </div>

              {/* Live Autonomous Scheduler Telemetry & Trigger Card */}
              <div className="flex flex-col justify-between gap-3 rounded-lg bg-bg-subtle/60 p-3.5 md:flex-row md:items-center">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        "size-2 rounded-full",
                        !currentCrawl.enabled ? "bg-muted" : currentCrawl.paused ? "bg-warn" : "bg-sage "
                      )}
                    />
                    <span className="text-sm font-medium text-fg">
                      {!currentCrawl.enabled
                        ? "Autonomous daemon: disabled"
                        : currentCrawl.paused
                          ? "Autonomous daemon: paused"
                          : `Autonomous daemon: active (every ${formatCrawlInterval(currentCrawl.frequencyMinutes ?? 360)})`}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
                    <span>
                      Last run:{" "}
                      <span className="text-fg">
                        {currentCrawl.lastRunAt ? new Date(currentCrawl.lastRunAt).toLocaleString() : "Never run"}
                      </span>
                    </span>
                    <span>
                      Next scheduled run:{" "}
                      <span className="font-medium text-fg">
                        {currentCrawl.nextRunAt ? new Date(currentCrawl.nextRunAt).toLocaleString() : "Pending schedule"}
                      </span>
                    </span>
                  </div>
                </div>
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => checkScheduleMutation.mutate()}
                  disabled={checkScheduleMutation.isPending}
                  className="text-xs shrink-0 gap-1.5"
                >
                  <Play className="size-3 text-accent" />
                  <span>{checkScheduleMutation.isPending ? "Evaluating schedule…" : "Evaluate / test schedule"}</span>
                </Button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Crawl interval</label>
                    <span className="font-medium text-fg tabular-nums">
                      {formatCrawlInterval(currentCrawl.frequencyMinutes ?? 360)}
                    </span>
                  </div>
                  <input
                    type="range"
                    min="5"
                    max="1440"
                    step="5"
                    value={currentCrawl.frequencyMinutes ?? 360}
                    onChange={(e) => updateCrawlField("frequencyMinutes", Math.max(5, parseInt(e.target.value, 10) || 5))}
                    className="w-full accent-accent"
                  />
                  <div className="flex flex-wrap items-center gap-1 pt-1">
                    {INTERVAL_PRESETS.map((p) => {
                      const isSelected = (currentCrawl.frequencyMinutes ?? 360) === p.mins;
                      return (
                        <button
                          key={p.mins}
                          type="button"
                          onClick={() => updateCrawlField("frequencyMinutes", p.mins)}
                          className={cn(
                            "cursor-pointer rounded-md border px-2 py-0.5 text-[11px] transition-colors",
                            isSelected
                              ? "border-accent bg-accent/15 text-accent font-semibold"
                              : "border-border bg-bg-subtle/30 text-muted hover:border-border-hover hover:text-fg"
                          )}
                        >
                          {p.label}
                          {p.tag ? <span className="ml-0.5 opacity-70">({p.tag})</span> : null}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Parallel fetch workers</label>
                    <span className="text-muted tabular-nums">{currentCrawl.concurrency ?? 4} workers</span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="8"
                    step="1"
                    value={currentCrawl.concurrency ?? 4}
                    onChange={(e) => updateCrawlField("concurrency", parseInt(e.target.value, 10))}
                    className="w-full accent-accent cursor-pointer"
                  />
                  <div className="flex justify-between text-[11px] text-subtle">
                    <span>1 (sequential)</span>
                    <span>4 (recommended)</span>
                    <span>8 (high-throughput)</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Polite per-domain delay</label>
                    <span className="text-muted tabular-nums">{currentCrawl.rateLimitMs ?? 150}ms</span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="500"
                    step="25"
                    value={currentCrawl.rateLimitMs ?? 150}
                    onChange={(e) => updateCrawlField("rateLimitMs", parseInt(e.target.value, 10))}
                    className="w-full accent-accent cursor-pointer"
                  />
                  <div className="flex justify-between text-[11px] text-subtle">
                    <span>50ms (ultra-fast)</span>
                    <span>150ms (optimal)</span>
                    <span>500ms (polite)</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-3 border-t border-border">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Max resources per run</label>
                    <span className="text-muted tabular-nums">
                      {currentCrawl.maxResourcesPerJob ?? currentCrawl.maxResourcesPerRun ?? 35} URLs
                    </span>
                  </div>
                  <input
                    type="range"
                    min="15"
                    max="150"
                    step="5"
                    value={currentCrawl.maxResourcesPerJob ?? currentCrawl.maxResourcesPerRun ?? 35}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      updateCrawlField("maxResourcesPerJob", val);
                      updateCrawlField("maxResourcesPerRun", val);
                    }}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[11px] text-subtle">
                    <span>15 min</span>
                    <span>35 default</span>
                    <span>150 max</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium flex items-center gap-1.5">
                      <Clock className="size-3.5 text-accent" />
                      <span>Crawl job time limit</span>
                    </label>
                    <span className="text-muted tabular-nums">
                      {currentCrawl.maxRunTimeMinutes ?? 5} min
                    </span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="20"
                    step="1"
                    value={currentCrawl.maxRunTimeMinutes ?? 5}
                    onChange={(e) => updateCrawlField("maxRunTimeMinutes", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[11px] text-subtle">
                    <span>1m (quick)</span>
                    <span>5m (balanced)</span>
                    <span>20m (deep)</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Per-domain cap</label>
                    <span className="text-muted tabular-nums">{currentCrawl.maxResourcesPerDomain ?? 8} max</span>
                  </div>
                  <input
                    type="range"
                    min="2"
                    max="25"
                    step="1"
                    value={currentCrawl.maxResourcesPerDomain ?? 8}
                    onChange={(e) => updateCrawlField("maxResourcesPerDomain", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[11px] text-subtle">
                    <span>2 min</span>
                    <span>8 default</span>
                    <span>25 max</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Max graph depth</label>
                    <span className="text-muted tabular-nums">{currentCrawl.maxDepth ?? 3} hops</span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="5"
                    step="1"
                    value={currentCrawl.maxDepth ?? 3}
                    onChange={(e) => updateCrawlField("maxDepth", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[11px] text-subtle">
                    <span>1 shallow</span>
                    <span>3 default</span>
                    <span>5 deep</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 1.2: Discovery Channels & Spidering Protocols */}
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <h3 className="flex items-center gap-2 border-b border-border pb-3 text-base font-medium text-fg">
                <Compass className="size-4 text-muted" strokeWidth={1.75} />
                Discovery channels & spidering protocols
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="flex items-center justify-between rounded-lg bg-bg-subtle/60 p-3">
                  <div>
                    <label className="text-xs font-medium block">Continuous RSS & Atom feeds</label>
                    <span className="text-[11px] text-muted">Real-time CTI feed polling from monitored sources</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={currentCrawl.rssDiscovery !== false}
                    onChange={(e) => updateCrawlField("rssDiscovery", e.target.checked)}
                    className={switchCls}
                  />
                </div>

                <div className="flex items-center justify-between rounded-lg bg-bg-subtle/60 p-3">
                  <div>
                    <label className="text-xs font-medium block">Homepage permalink scraping</label>
                    <span className="text-[11px] text-muted">Extract new technical reports from source landing pages</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={currentCrawl.htmlDiscovery !== false}
                    onChange={(e) => updateCrawlField("htmlDiscovery", e.target.checked)}
                    className={switchCls}
                  />
                </div>

                <div className="flex items-center justify-between rounded-lg bg-bg-subtle/60 p-3">
                  <div>
                    <label className="text-xs font-medium block">Search-driven discovery vectors</label>
                    <span className="text-[11px] text-muted">Generate dynamic search queries for emerging campaigns</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={currentCrawl.searchDiscovery !== false}
                    onChange={(e) => updateCrawlField("searchDiscovery", e.target.checked)}
                    className={switchCls}
                  />
                </div>

                <div className="flex items-center justify-between rounded-lg bg-bg-subtle/60 p-3">
                  <div>
                    <label className="text-xs font-medium block">Recursive outlink deep spidering</label>
                    <span className="text-[11px] text-muted">Traverse technical citations and links referenced in reports</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={currentCrawl.recursiveDiscovery !== false}
                    onChange={(e) => updateCrawlField("recursiveDiscovery", e.target.checked)}
                    className={switchCls}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-border">
                <div className="space-y-1.5">
                  <label htmlFor="crawl-discovery-breadth" className="text-xs font-medium block">Discovery breadth</label>
                  <Select
                    id="crawl-discovery-breadth"
                    value={currentCrawl.discoveryBreadth || "balanced"}
                    onValueChange={(v) => updateCrawlField("discoveryBreadth", v as any)}
                    className="w-full"
                  >
                    <option value="focused">Focused (seeds + 1-hop citations only)</option>
                    <option value="balanced">Balanced (recommended 2-hop graph expansion)</option>
                    <option value="wide">Wide (aggressive multi-hop graph traversal)</option>
                  </Select>
                </div>

                <div className="flex items-center pt-4">
                  <label className="flex items-center gap-2 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={currentCrawl.allowExternalDomains !== false}
                      onChange={(e) => updateCrawlField("allowExternalDomains", e.target.checked)}
                      className={switchCls}
                    />
                    <div>
                      <span className="font-medium block">Allow external domains</span>
                      <span className="text-[10px] text-muted block">
                        Expand outside initial seed list to discover new threat publishers
                      </span>
                    </div>
                  </label>
                </div>
              </div>
            </div>

            {/* Section 1.3: Target Intelligence Resource Types */}
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-3">
              <div className="border-b border-border pb-3">
                <h3 className="flex items-center gap-2 text-base font-medium text-fg">
                  <Filter className="size-4 text-muted" strokeWidth={1.75} />
                  Target intelligence resource types
                </h3>
                <p className="text-xs text-muted">
                  Specify the technical artifacts the qualification engine should extract, categorize, and index.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                {[
                  { id: "FULL_ATTACK_CHAIN", label: "Full intrusion attack chains", desc: "Multi-stage lifecycle (Initial Access -> Lateral -> Impact)" },
                  { id: "CAMPAIGN_INTEL", label: "Adversary campaign tracking", desc: "Geopolitical threat activity & multi-incident tracking" },
                  { id: "PROCEDURE_DEEPDIVE", label: "Procedure execution & TTPs", desc: "Command-line scripts, binary executions, and atomic tests" },
                  { id: "MALWARE_ANALYSIS", label: "Malware & C2 analysis", desc: "Reverse-engineering teardowns, beacons, payloads, loaders" },
                  { id: "DETECTION_GUIDANCE", label: "Detection engineering & Sigma", desc: "Sigma rules, YARA signatures, hunting queries, mitigations" },
                  { id: "VULNERABILITY_ADVISORY", label: "CVE exploits & zero-days", desc: "Vulnerability weaponization and technical advisories" },
                  { id: "THREAT_ACTOR_DOSSIER", label: "Threat actor dossiers", desc: "Adversary group profiles, infrastructure, and attribution" },
                ].map((item) => {
                  const isChecked = (currentCrawl.targetResourceTypes || []).includes(item.id as ResourceKind);
                  return (
                    <label
                      key={item.id}
                      className={cn(
                        "flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors",
                        isChecked ? "border-accent/40 bg-bg-subtle" : "border-transparent bg-bg-subtle/60 hover:bg-bg-subtle",
                      )}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => {
                          const curr = currentCrawl.targetResourceTypes || [];
                          const updated = e.target.checked
                            ? [...curr, item.id as ResourceKind]
                            : curr.filter((k: string) => k !== item.id);
                          updateCrawlField("targetResourceTypes", updated);
                        }}
                        className={cn("mt-0.5", switchCls)}
                      />
                      <div>
                        <span className="text-xs font-medium block">{item.label}</span>
                        <span className="text-[11px] text-muted block leading-tight">{item.desc}</span>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Section 1.4: Heuristic Qualification & Strictness Gate */}
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <h3 className="flex items-center gap-2 border-b border-border pb-3 text-base font-medium text-fg">
                <ShieldAlert className="size-4 text-muted" strokeWidth={1.75} />
                Heuristic qualification & quality gate
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label htmlFor="crawl-strictness-mode" className="font-medium text-fg">Strictness mode</label>
                    <span className="capitalize text-muted">{currentCrawl.strictnessMode || "balanced"}</span>
                  </div>
                  <Select
                    id="crawl-strictness-mode"
                    value={currentCrawl.strictnessMode || "balanced"}
                    onValueChange={(v) => updateCrawlField("strictnessMode", v as any)}
                    className="w-full"
                  >
                    <option value="permissive">Permissive (Include brief advisories)</option>
                    <option value="balanced">Balanced (Recommended standard)</option>
                    <option value="strict">Strict (High TTP & IOC density required)</option>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Min quality score</label>
                    <span className="text-muted tabular-nums">
                      {Math.round((currentCrawl.minQualityScore ?? 0.35) * 100)}%
                    </span>
                  </div>
                  <input
                    type="range"
                    min="0.15"
                    max="0.80"
                    step="0.05"
                    value={currentCrawl.minQualityScore ?? 0.35}
                    onChange={(e) => updateCrawlField("minQualityScore", parseFloat(e.target.value))}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[11px] text-subtle">
                    <span>15% (broad)</span>
                    <span>35%</span>
                    <span>80% (strict)</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Min word count</label>
                    <span className="text-muted tabular-nums">{currentCrawl.minWordCount ?? 100} words</span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="500"
                    step="10"
                    value={currentCrawl.minWordCount ?? 100}
                    onChange={(e) => updateCrawlField("minWordCount", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[11px] text-subtle">
                    <span>50w</span>
                    <span>250w</span>
                    <span>500w</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-border">
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentCrawl.requireIocs ?? false}
                    onChange={(e) => updateCrawlField("requireIocs", e.target.checked)}
                    className={switchCls}
                  />
                  <div>
                    <span className="font-medium block">Require verified IOCs</span>
                    <span className="text-[10px] text-muted block">Must have IPs, Hashes, or CVEs</span>
                  </div>
                </label>

                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentCrawl.requireAttck ?? false}
                    onChange={(e) => updateCrawlField("requireAttck", e.target.checked)}
                    className={switchCls}
                  />
                  <div>
                    <span className="font-medium block">Require MITRE ATT&CK</span>
                    <span className="text-[10px] text-muted block">Must contain technique identifiers</span>
                  </div>
                </label>

                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentCrawl.rejectMarketingNoise ?? true}
                    onChange={(e) => updateCrawlField("rejectMarketingNoise", e.target.checked)}
                    className={switchCls}
                  />
                  <div>
                    <span className="font-medium block">Reject marketing & PR</span>
                    <span className="text-[10px] text-muted block">Exclude webinars, pricing, announcements</span>
                  </div>
                </label>
              </div>

              <div className="pt-2 border-t border-border">
                <label className="text-xs font-medium block">Noise / PR keyword blacklist</label>
                <p className="text-[11px] text-muted">Pages with high density of these terms are filtered as vendor noise.</p>
                <Input
                  value={currentCrawl.noiseKeywords || ""}
                  onChange={(e) => updateCrawlField("noiseKeywords", e.target.value)}
                  placeholder="webinar, discount, pricing, subscribe..."
                  className="mt-1.5 h-9 rounded-lg border-border bg-bg-elevated font-mono text-xs"
                />
              </div>
            </div>

            {/* Section 1.5: Deduplication, PDF & Keywords */}
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <h3 className="flex items-center gap-2 border-b border-border pb-3 text-base font-medium text-fg">
                <HardDrive className="size-4 text-muted" strokeWidth={1.75} />
                Deduplication strategy & document preservation
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <label htmlFor="crawl-dedup-method" className="text-xs font-medium block">Deduplication method</label>
                  <Select
                    id="crawl-dedup-method"
                    value={currentCrawl.dedupMethod || "smart_hybrid"}
                    onValueChange={(v) => updateCrawlField("dedupMethod", v as any)}
                    className="w-full"
                  >
                    <option value="smart_hybrid">Smart hybrid (normalized URL + 64-bit SimHash)</option>
                    <option value="both">Both (strict URL & exact content hash)</option>
                    <option value="canonical_url">Canonical URL Only</option>
                    <option value="content_hash">Content hash only</option>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Max PDF preservation cap</label>
                    <span className="text-muted tabular-nums">{currentCrawl.maxPdfDownloads ?? 10} PDFs</span>
                  </div>
                  <input
                    type="range"
                    min="2"
                    max="50"
                    step="2"
                    value={currentCrawl.maxPdfDownloads ?? 10}
                    onChange={(e) => updateCrawlField("maxPdfDownloads", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                </div>

                <div className="flex items-center pt-4">
                  <label className="flex items-center gap-2 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={currentCrawl.generatePdf !== false}
                      onChange={(e) => updateCrawlField("generatePdf", e.target.checked)}
                      className={switchCls}
                    />
                    <div>
                      <span className="font-medium block">High-fidelity PDF generation</span>
                      <span className="text-[10px] text-muted block">Preserve visual report layout</span>
                    </div>
                  </label>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-border">
                <label className="flex items-start gap-2.5 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentCrawl.autoIngest ?? true}
                    onChange={(e) => updateCrawlField("autoIngest", e.target.checked)}
                    className={cn("mt-0.5", switchCls)}
                  />
                  <div>
                    <span className="font-medium block">Auto-ingest qualified reports</span>
                    <span className="text-[10px] text-muted block">Direct save vs manual review approval queue</span>
                    {!(currentCrawl.autoIngest ?? true) && Boolean(currentCrawl.agentAutoIngestEnabled) && (
                      <span className="mt-1 inline-flex items-center gap-1 text-[10px] text-warn font-medium bg-warn/10 border border-warn/40 rounded px-1.5 py-0.5">
                        <AlertTriangle className="size-2.5" />
                        Pauses AI Agent autonomous ingestion until enabled
                      </span>
                    )}
                  </div>
                </label>

                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentCrawl.autoAnalyze ?? true}
                    onChange={(e) => updateCrawlField("autoAnalyze", e.target.checked)}
                    className={switchCls}
                  />
                  <div>
                    <span className="font-medium block">Auto ATT&CK & TTP extraction</span>
                    <span className="text-[10px] text-muted block">Reconstruct multi-stage attack chains</span>
                  </div>
                </label>
              </div>

              <div className="pt-2 border-t border-border">
                <label className="text-xs font-medium block">Targeted threat keywords & query patterns</label>
                <p className="text-[11px] text-muted">
                  Comma-separated phrases. Each run searches two of them, rotating, on top of the research coverage searches below.
                </p>
                <Textarea
                  rows={3}
                  value={currentCrawl.keywords || ""}
                  onChange={(e) => updateCrawlField("keywords", e.target.value)}
                  className="mt-1.5 rounded-lg border-border bg-bg-elevated font-mono text-xs"
                />
              </div>

              <ResearchDiscoverySettings
                value={normalizeResearchDiscovery(currentCrawl.researchDiscovery)}
                onChange={(v) => updateCrawlField("researchDiscovery", v)}
                searchEnabled={currentCrawl.searchDiscovery !== false}
              />
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: INTELLIGENCE & SOC POLICIES                                        */}
        {/* ========================================================================= */}
        {activeSection === "policy" && (
          <div className="space-y-6">
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <h3 className="flex items-center gap-2 border-b border-border pb-3 text-base font-medium text-fg">
                <Shield className="size-4 text-muted" strokeWidth={1.75} />
                Organizational node & ingestion identity
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium block">SOC node / unit name</label>
                  <p className="text-[11px] text-muted">Identifies the reporting entity in exported STIX bundles.</p>
                  <Input
                    value={currentApp.organizationName || ""}
                    onChange={(e) => updateAppField("organizationName", e.target.value)}
                    className="mt-1.5 h-9 rounded-lg border-border bg-bg-elevated text-sm"
                  />
                </div>

                <div>
                  <label className="text-xs font-medium block">Sensor / engine identifier</label>
                  <p className="text-[11px] text-muted">Node signature tagged to cryptographic SHA-256 hashes.</p>
                  <Input
                    value={currentApp.nodeId || ""}
                    onChange={(e) => updateAppField("nodeId", e.target.value)}
                    className="mt-1.5 h-9 rounded-lg border-border bg-bg-elevated font-mono text-xs"
                  />
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <h3 className="flex items-center gap-2 border-b border-border pb-3 text-base font-medium text-fg">
                <FileCode className="size-4 text-muted" strokeWidth={1.75} />
                CTI classification & retention standards
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <label htmlFor="app-default-classification" className="text-xs font-medium block">Default classification</label>
                  <Select
                    id="app-default-classification"
                    value={currentApp.defaultClassification || "INTRUSION_REPORT"}
                    onValueChange={(v) => updateAppField("defaultClassification", v)}
                    className="w-full"
                  >
                    <option value="INTRUSION_REPORT">Intrusion report</option>
                    <option value="CAMPAIGN_INTEL">Campaign intelligence</option>
                    <option value="PROCEDURE_DEEPDIVE">Procedure deep-dive</option>
                    <option value="MALWARE_ANALYSIS">Malware analysis</option>
                    <option value="THREAT_REPORT">General threat report</option>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-muted">Min IOC Confidence</label>
                    <span className="text-muted tabular-nums">{currentApp.iocConfidenceThreshold ?? 75}%</span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="95"
                    step="5"
                    disabled
                    aria-disabled="true"
                    title="Not active yet: IOC harvesting does not filter by confidence"
                    value={currentApp.iocConfidenceThreshold ?? 75}
                    onChange={(e) => updateAppField("iocConfidenceThreshold", parseInt(e.target.value, 10))}
                    className="w-full accent-accent opacity-50 cursor-not-allowed"
                  />
                  <p className="text-[11px] text-subtle">Not active yet · saved, but no pipeline step applies it</p>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="app-evidence-retention" className="text-xs font-medium block text-muted">Evidence retention period</label>
                  <Select
                    id="app-evidence-retention"
                    disabled
                    title="Not active yet: evidence is never purged automatically"
                    value={String(currentApp.evidenceRetentionDays ?? 365)}
                    onValueChange={(v) => updateAppField("evidenceRetentionDays", parseInt(v, 10))}
                    className="w-full"
                  >
                    <option value="90">90 days (quarterly audit)</option>
                    <option value="180">180 Days (Semi-Annual)</option>
                    <option value="365">365 days (1 year standard)</option>
                    <option value="0">Indefinite (never auto-purge)</option>
                  </Select>
                  <p className="text-[11px] text-subtle">Not active yet · saved, but no pipeline step applies it</p>
                </div>
              </div>

              <div className="pt-3 border-t border-border">
                <div className="space-y-1.5 max-w-sm">
                  <label htmlFor="app-default-export" className="text-xs font-medium block text-muted">Default export standard</label>
                  <Select
                    id="app-default-export"
                    disabled
                    title="Not active yet: exports do not read this default"
                    value={currentApp.defaultExportFormat || "stix21"}
                    onValueChange={(v) => updateAppField("defaultExportFormat", v as any)}
                    className="w-full"
                  >
                    <option value="stix21">STIX 2.1 JSON Bundle (OASIS Standard)</option>
                    <option value="json">Raw engine JSON (evidence-preserving)</option>
                    <option value="csv">CSV IOC Table (Firewall / SIEM Ingest)</option>
                    <option value="pdf">Structured PDF Dossier</option>
                  </Select>
                  <p className="text-[11px] text-subtle">Not active yet · saved, but no pipeline step applies it</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 3: DATABASE & STORAGE TELEMETRY                                       */}
        {/* ========================================================================= */}
        {activeSection === "storage" && (
          <div className="space-y-6">
            <DataSourceNotice />
            {/* Storage Architecture Overview */}
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <div className="flex flex-col gap-3 border-b border-border pb-3 sm:flex-row sm:items-center sm:justify-between">
                <h3 className="flex items-center gap-2 text-base font-medium text-fg">
                  <Database className="size-4 text-muted" strokeWidth={1.75} />
                  {dataSource.engine === "local" ? "Local database telemetry" : "MongoDB telemetry"}
                </h3>
                <span className={cn("flex items-center gap-1.5 text-xs", dataSource.text)}>
                  <span className={cn("size-2 rounded-full", dataSource.dot)} />
                  {dataSource.chip}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-lg bg-bg-subtle/60 p-3">
                  <span className="block text-xs text-muted">Database</span>
                  <span className="mt-1 block font-mono text-sm text-fg">{dataSourceQuery.data?.databaseName ?? "—"}</span>
                </div>
                <div className="rounded-lg bg-bg-subtle/60 p-3">
                  <span className="block text-xs text-muted">Collection</span>
                  <span className="mt-1 block font-mono text-sm text-fg">{dataSourceQuery.data?.collectionName ?? "—"}</span>
                </div>
                <div className="rounded-lg bg-bg-subtle/60 p-3">
                  <span className="block text-xs text-muted">Stored reports</span>
                  <span className="mt-1 block text-lg font-semibold text-fg tabular-nums">
                    {storageStatsQuery.data?.totalReports ?? "—"}
                  </span>
                </div>
                <div className="rounded-lg bg-bg-subtle/60 p-3">
                  <span className="block text-xs text-muted">Active sources</span>
                  <span className="mt-1 block text-lg font-semibold text-fg tabular-nums">
                    {storageStatsQuery.data?.totalSources ?? "—"}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-2">
                <div className="rounded-lg bg-bg-subtle/60 p-3">
                  <span className="block text-xs text-muted">Discovered candidates</span>
                  <span className="mt-1 block text-lg font-semibold text-fg tabular-nums">
                    {storageStatsQuery.data?.totalDiscovered ?? "—"}
                  </span>
                </div>
                <div className="rounded-lg bg-bg-subtle/60 p-3">
                  <span className="block text-xs text-muted">Executed crawl jobs</span>
                  <span className="mt-1 block text-lg font-semibold text-fg tabular-nums">
                    {storageStatsQuery.data?.totalJobs ?? "—"}
                  </span>
                </div>
                <div className="rounded-lg bg-bg-subtle/60 p-3">
                  <span className="block text-xs text-muted">Pipeline audit events</span>
                  <span className="mt-1 block text-lg font-semibold text-fg tabular-nums">
                    {storageStatsQuery.data?.totalEvents ?? "—"}
                  </span>
                </div>
              </div>
            </div>

            {/* In-Memory Cache Acceleration & Invalidation */}
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <div className="flex flex-col gap-3 border-b border-border pb-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h3 className="flex items-center gap-2 text-base font-medium text-fg">
                    <Zap className="size-4 text-muted" strokeWidth={1.75} />
                    High-speed in-memory cache acceleration
                  </h3>
                  <p className="text-xs text-muted">
                    Serves intelligence library and telemetry in &lt;1ms while maintaining instant invalidation on write.
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => purgeMutation.mutate()}
                  disabled={purgeMutation.isPending}
                  className="gap-1.5 text-xs"
                >
                  <Trash2 className="size-3.5 text-danger" />
                  <span>Flush all caches</span>
                </Button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Library query cache TTL</label>
                    <span className="text-muted tabular-nums">{currentApp.cacheTtlSeconds ?? 60} seconds</span>
                  </div>
                  <input
                    type="range"
                    min="15"
                    max="300"
                    step="15"
                    value={currentApp.cacheTtlSeconds ?? 60}
                    onChange={(e) => updateAppField("cacheTtlSeconds", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <span className="text-[10px] text-muted block">
                    Cached in memory; automatically evicted when new reports are ingested or deleted.
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-sm">
                    <label className="font-medium text-fg">Dashboard aggregation TTL</label>
                    <span className="text-muted tabular-nums">{currentApp.dashboardCacheTtlSeconds ?? 15} seconds</span>
                  </div>
                  <input
                    type="range"
                    min="5"
                    max="60"
                    step="5"
                    value={currentApp.dashboardCacheTtlSeconds ?? 15}
                    onChange={(e) => updateAppField("dashboardCacheTtlSeconds", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <span className="text-[10px] text-muted block">
                    Caches 11-way aggregation pipeline for instant 0ms dashboard renders.
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 4: DISPLAY & USER INTERFACE PREFERENCES                              */}
        {/* ========================================================================= */}
        {activeSection === "display" && (
          <div className="space-y-6">
            {/* Visual Interface Theme & Aesthetic Engine */}
            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-6 ">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-border gap-2">
                <div>
                  <h3 className="flex items-center gap-2 text-base font-medium text-fg">
                    <Sparkles className="size-4 text-muted" strokeWidth={1.75} />
                    Appearance & visual interface theme
                  </h3>
                  <p className="text-xs text-subtle mt-0.5">
                    Select your visual presentation aesthetic, glassmorphism translucency, and refined micro-interactions.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <StatusChip>
                    Theme engine v2.5
                  </StatusChip>
                  <span className={cn(
                    "rounded-md border px-2 py-0.5 text-[11px]",
                    uiStyle === "liquid-glass"
                      ? "border-accent/40 bg-accent/15 text-accent"
                      : "border-border bg-bg-subtle text-muted"
                  )}>
                    {uiStyle === "liquid-glass" ? "Liquid Glass" : "Tactical Slate"}
                  </span>
                </div>
              </div>

              {/* Theme Presets: 2 Rich Cards */}
              <div className="space-y-2.5">
                <label className="text-xs font-medium text-fg block">
                  Interface theme preset
                </label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Preset 1: Default (Tactical Slate) */}
                  <div
                    onClick={() => handleUiStyleChange("default")}
                    className={cn(
                      "group relative p-4 rounded-xl border transition-all cursor-pointer space-y-3",
                      uiStyle === "default"
                        ? "border-accent ring-2 ring-accent/30 bg-bg-card shadow-sm"
                        : "border-border bg-bg-subtle/40 hover:border-border-strong hover:bg-bg-subtle/80"
                    )}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2.5">
                        <div className="size-9 rounded-lg bg-bg-subtle border border-border flex items-center justify-center text-fg">
                          <Layers className="size-4.5 text-accent" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-fg">Tactical Slate</span>
                            <StatusChip>Default</StatusChip>
                          </div>
                          <span className="text-[11px] text-subtle block">Standard SOC opaque architecture</span>
                        </div>
                      </div>
                      <div className={cn(
                        "size-5 rounded-full border flex items-center justify-center transition-colors",
                        uiStyle === "default"
                          ? "border-accent bg-accent text-accent-fg"
                          : "border-border text-transparent"
                      )}>
                        <Check className="size-3 stroke-[3]" />
                      </div>
                    </div>

                    {/* Mini Specimen Visualizer (Default Slate) */}
                    <div className="p-2.5 rounded-lg border border-border bg-bg-subtle space-y-1.5 pointer-events-none select-none">
                      <div className="flex items-center justify-between text-[10px] text-muted">
                        <span>Retrieval matrix</span>
                        <span className="inline-block size-1.5 rounded-full bg-sage" />
                      </div>
                      <div className="h-5 rounded-md bg-bg-card border border-border flex items-center px-2 text-[10px] text-muted font-medium">
                        Solid high-contrast surface
                      </div>
                    </div>

                    <p className="text-xs text-subtle leading-relaxed">
                      Solid, opaque surfaces engineered for high data density, zero visual distraction, and long operational SOC shifts. Crisp text rendering across all monitors.
                    </p>
                  </div>

                  {/* Preset 2: Liquid Glass */}
                  <div
                    onClick={() => handleUiStyleChange("liquid-glass")}
                    className={cn(
                      "group relative p-4 rounded-xl border transition-all cursor-pointer space-y-3",
                      uiStyle === "liquid-glass"
                        ? "border-accent ring-2 ring-accent/30 bg-bg-card shadow-sm"
                        : "border-border bg-bg-subtle/40 hover:border-border-strong hover:bg-bg-subtle/80"
                    )}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2.5">
                        <div className="size-9 rounded-lg bg-accent/15 border border-accent/30 flex items-center justify-center text-accent  backdrop-blur-md">
                          <Sparkles className="size-4.5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-fg">Liquid Glass</span>
                            <StatusChip>Glassmorphism</StatusChip>
                          </div>
                          <span className="text-[11px] text-subtle block">Refractive frosted glassmorphism</span>
                        </div>
                      </div>
                      <div className={cn(
                        "size-5 rounded-full border flex items-center justify-center transition-colors",
                        uiStyle === "liquid-glass"
                          ? "border-accent bg-accent text-accent-fg"
                          : "border-border text-transparent"
                      )}>
                        <Check className="size-3 stroke-[3]" />
                      </div>
                    </div>

                    {/* Mini Specimen Visualizer (Liquid Glass) */}
                    <div className="p-2.5 rounded-lg border border-border/80 card-liquid-glass space-y-1.5 pointer-events-none select-none relative overflow-hidden">
                      <div className="flex items-center justify-between text-[10px] text-accent font-semibold">
                        <span>Frosted cognitive capsule</span>
                        <ActivitySpinner size="xs" variant={spinnerVariant} className="text-accent" />
                      </div>
                      <div className="h-6 rounded-lg pill-liquid-glass flex items-center justify-between px-2.5 text-[10px] font-medium text-fg">
                        <span>{Math.round(8 + (glassRatio / 100) * 32.4)}px diffusion blur · specular glare</span>
                        <span className="text-muted tabular-nums">{glassRatio}% ratio</span>
                      </div>
                    </div>

                    <p className="text-xs text-subtle leading-relaxed">
                      Frosted liquid glass with dynamic ambient luminance, specular rim highlights, and deep diffusion blur. Targeted to floating drawers, session lists, badges, and interactive cards.
                    </p>

                    {/* Liquid Glass Blur & Translucency Ratio Control (Inside Liquid Glass Selection) */}
                    {uiStyle === "liquid-glass" && (
                      <div
                        onClick={(e) => e.stopPropagation()}
                        className="pt-3 border-t border-accent/25 space-y-3 cursor-default"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-fg">
                              Blur liquid ratio & translucency
                            </span>
                            <StatusChip>
                              {glassRatio}% · {Math.round(8 + (glassRatio / 100) * 32.4)}px blur
                            </StatusChip>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleGlassRatioChange(70)}
                            className="cursor-pointer text-[11px] text-muted underline hover:text-fg"
                          >
                            Reset (70%)
                          </button>
                        </div>

                        {/* Interactive Slider */}
                        <div className="space-y-1">
                          <input
                            type="range"
                            min="5"
                            max="110"
                            step="5"
                            value={glassRatio}
                            onChange={(e) => handleGlassRatioChange(Number(e.target.value))}
                            className="w-full accent-accent h-1.5 bg-bg-subtle rounded-lg cursor-pointer"
                          />
                          <div className="flex justify-between text-[11px] text-subtle">
                            <span>5% (Pure Glass)</span>
                            <span>35% (Crystal)</span>
                            <span>70% (Balanced)</span>
                            <span>110% (Ultra Frost)</span>
                          </div>
                        </div>

                        {/* Presets */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 pt-0.5">
                          {[
                            { label: "Pure Glass", ratio: 5, desc: "Ultra clear, glassy refraction" },
                            { label: "Crystal Clear", ratio: 35, desc: "Crisp reflection with depth" },
                            { label: "Balanced Velvet", ratio: 70, desc: "Default optimal frosted look" },
                            { label: "Ultra Frost", ratio: 110, desc: "Maximum diffusion (46px)" },
                          ].map((preset) => {
                            const isSelected = glassRatio === preset.ratio;
                            return (
                              <button
                                key={preset.ratio}
                                type="button"
                                onClick={() => handleGlassRatioChange(preset.ratio)}
                                className={cn(
                                  "p-2 rounded-lg border text-left transition-all cursor-pointer flex flex-col gap-0.5",
                                  isSelected
                                    ? "border-accent bg-accent/20 text-fg "
                                    : "border-border/60 hover:border-border pill-liquid-glass text-muted hover:text-fg"
                                )}
                              >
                                <div className="flex items-center justify-between">
                                  <span className="text-[10px] font-medium">{preset.label}</span>
                                  <span className="text-[10px] opacity-80 tabular-nums">{preset.ratio}%</span>
                                </div>
                                <span className="text-[9px] text-subtle">{preset.desc}</span>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Color Mode & Appearance */}
              <div className="pt-4 border-t border-border space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium text-fg block">
                      Color mode (dark / light)
                    </label>
                    <span className="text-[11px] text-subtle">
                      Adaptive high-contrast color scheme for tactical operations
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => handleColorThemeChange("dark")}
                    className={cn(
                      "flex items-center justify-between p-3 rounded-xl border text-xs font-medium transition-all cursor-pointer",
                      colorTheme === "dark"
                        ? "border-accent bg-accent/10 text-fg ring-1 ring-accent/30"
                        : "border-border bg-bg-subtle/40 text-muted hover:border-border-strong hover:text-fg"
                    )}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="size-7 rounded-lg bg-bg-subtle border border-border flex items-center justify-center text-accent">
                        <Moon className="size-3.5" />
                      </div>
                      <div className="text-left">
                        <span className="block font-medium">Dark mode (OLED / midnight)</span>
                        <span className="text-[10px] text-subtle block">Low-light SOC tactical monitoring</span>
                      </div>
                    </div>
                    {colorTheme === "dark" && <Check className="size-4 text-accent" />}
                  </button>

                  <button
                    type="button"
                    onClick={() => handleColorThemeChange("light")}
                    className={cn(
                      "flex items-center justify-between p-3 rounded-xl border text-xs font-medium transition-all cursor-pointer",
                      colorTheme === "light"
                        ? "border-accent bg-accent/10 text-fg ring-1 ring-accent/30"
                        : "border-border bg-bg-subtle/40 text-muted hover:border-border-strong hover:text-fg"
                    )}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="size-7 rounded-lg bg-bg-subtle border border-border flex items-center justify-center text-accent">
                        <Sun className="size-3.5" />
                      </div>
                      <div className="text-left">
                        <span className="block font-medium">Light mode (daylight)</span>
                        <span className="text-[10px] text-subtle block">High-key daylight documentation</span>
                      </div>
                    </div>
                    {colorTheme === "light" && <Check className="size-4 text-accent" />}
                  </button>
                </div>
              </div>

              {/* Activity Indicator (Spinner) Style */}
              <div className="pt-4 border-t border-border space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <div>
                    <label className="text-xs font-medium text-fg block">
                      Activity indicator & progress animations
                    </label>
                    <span className="text-[11px] text-subtle">
                      Real-time animated indicators for AI generation, sandbox probes, and retrieval streams
                    </span>
                  </div>
                  <div className="flex items-center gap-1 bg-bg-subtle p-1 rounded-lg border border-border">
                    <span className="text-[11px] text-subtle px-1.5">Size:</span>
                    {(["xs", "sm", "md", "lg"] as const).map((sz) => (
                      <button
                        key={sz}
                        type="button"
                        onClick={() => setPreviewSpinnerSize(sz)}
                        className={cn(
                          "cursor-pointer rounded-md px-2 py-0.5 text-[11px] transition-colors",
                          previewSpinnerSize === sz
                            ? "bg-accent text-accent-fg font-semibold "
                            : "text-subtle hover:text-fg"
                        )}
                      >
                        {sz.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {/* Option 1: Radial Blade */}
                  <button
                    type="button"
                    onClick={() => handleSpinnerVariantChange("radial")}
                    className={cn(
                      "p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between gap-3",
                      spinnerVariant === "radial"
                        ? "border-accent ring-1 ring-accent/30 bg-accent/5 "
                        : "border-border bg-bg-subtle/30 hover:border-border-strong hover:bg-bg-subtle/60"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <ActivitySpinner size={previewSpinnerSize} variant="radial" className="text-accent" />
                      {spinnerVariant === "radial" && <Check className="size-3.5 text-accent" />}
                    </div>
                    <div>
                      <span className="text-xs font-medium text-fg block">Radial Blade</span>
                      <span className="text-[10px] text-subtle leading-tight block mt-0.5">
                        Stepped rotation & graduated blade opacity
                      </span>
                    </div>
                  </button>

                  {/* Option 2: Activity Ring */}
                  <button
                    type="button"
                    onClick={() => handleSpinnerVariantChange("ring")}
                    className={cn(
                      "p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between gap-3",
                      spinnerVariant === "ring"
                        ? "border-accent ring-1 ring-accent/30 bg-accent/5 "
                        : "border-border bg-bg-subtle/30 hover:border-border-strong hover:bg-bg-subtle/60"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <ActivitySpinner size={previewSpinnerSize} variant="ring" className="text-accent" />
                      {spinnerVariant === "ring" && <Check className="size-3.5 text-accent" />}
                    </div>
                    <div>
                      <span className="text-xs font-medium text-fg block">Activity Ring</span>
                      <span className="text-[10px] text-subtle leading-tight block mt-0.5">
                        Continuous rotating gradient activity ring
                      </span>
                    </div>
                  </button>

                  {/* Option 3: Pulse Dots */}
                  <button
                    type="button"
                    onClick={() => handleSpinnerVariantChange("dots")}
                    className={cn(
                      "p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between gap-3",
                      spinnerVariant === "dots"
                        ? "border-accent ring-1 ring-accent/30 bg-accent/5 "
                        : "border-border bg-bg-subtle/30 hover:border-border-strong hover:bg-bg-subtle/60"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <ActivitySpinner size={previewSpinnerSize} variant="dots" className="text-accent" />
                      {spinnerVariant === "dots" && <Check className="size-3.5 text-accent" />}
                    </div>
                    <div>
                      <span className="text-xs font-medium text-fg block">Pulse Dots</span>
                      <span className="text-[10px] text-subtle leading-tight block mt-0.5">
                        Smooth bouncing triple-dot indicator
                      </span>
                    </div>
                  </button>
                </div>
              </div>

              {/* Interactive Live Glass Specimen Playground */}
              <div className="pt-4 border-t border-border space-y-3">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-fg flex items-center gap-1.5">
                    <Eye className="size-3.5 text-accent" />
                    Live interface component specimen
                  </label>
                  <span className="text-[11px] text-subtle">
                    Real-time CSS rendering test
                  </span>
                </div>

                <div className={cn(
                  "p-4 rounded-xl border transition-all space-y-3",
                  uiStyle === "liquid-glass"
                    ? "card-liquid-glass"
                    : "border-border bg-bg-card"
                )}>
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-fg">AI agent interaction capsule</span>
                      <StatusChip>
                        Live specimen
                      </StatusChip>
                    </div>
                    <div className="flex items-center gap-2">
                      <ActivitySpinner size="sm" variant={spinnerVariant} className="text-accent" />
                      <span className="text-[11px] text-subtle">Streaming active</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
                    <div className={cn(
                      "p-3 rounded-lg text-xs space-y-1 transition-all",
                      uiStyle === "liquid-glass" ? "pill-liquid-glass" : "bg-bg-subtle border border-border"
                    )}>
                      <span className="font-semibold block text-fg">Session switcher</span>
                      <p className="text-[10px] text-subtle">Frosted glass backdrop with zero transparency leakage.</p>
                    </div>

                    <div className={cn(
                      "p-3 rounded-lg text-xs space-y-1 transition-all",
                      uiStyle === "liquid-glass" ? "pill-liquid-glass" : "bg-bg-subtle border border-border"
                    )}>
                      <span className="font-semibold block text-fg">Grounded CTI cards</span>
                      <p className="text-[10px] text-subtle">Frosted links with hover glow & direct report modal jumps.</p>
                    </div>

                    <div className={cn(
                      "p-3 rounded-lg text-xs space-y-1 transition-all",
                      uiStyle === "liquid-glass" ? "pill-liquid-glass" : "bg-bg-subtle border border-border"
                    )}>
                      <span className="font-semibold block text-fg">Micro-interactions</span>
                      <p className="text-[10px] text-subtle">Specular top edge lighting with graduated blade spinners.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-bg-card p-5 space-y-4">
              <h3 className="flex items-center gap-2 border-b border-border pb-3 text-base font-medium text-fg">
                <Sliders className="size-4 text-muted" strokeWidth={1.75} />
                MITRE ATT&CK matrix & telemetry presentation
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label htmlFor="app-matrix-layout" className="text-xs font-medium block">Default ATT&CK matrix column width</label>
                  <Select
                    id="app-matrix-layout"
                    value={currentApp.defaultMatrixLayout || "standard"}
                    onValueChange={(v) => updateAppField("defaultMatrixLayout", v as any)}
                    className="w-full"
                  >
                    <option value="standard">Standard (224px columns — full name & counts)</option>
                    <option value="compact">Compact (176px columns — high viewport density)</option>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="app-polling-interval" className="text-xs font-medium block">Live dashboard refresh interval</label>
                  <Select
                    id="app-polling-interval"
                    value={String(currentApp.pollingIntervalSeconds ?? 12)}
                    onValueChange={(v) => updateAppField("pollingIntervalSeconds", parseInt(v, 10))}
                    className="w-full"
                  >
                    <option value="8">8 seconds (high frequency SOC stream)</option>
                    <option value="12">12 seconds (recommended standard)</option>
                    <option value="30">30 seconds (low bandwidth)</option>
                    <option value="60">60 Seconds (Manual / Background)</option>
                  </Select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-3 border-t border-border">
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentApp.matrixSubtechniqueAutoExpand ?? false}
                    onChange={(e) => updateAppField("matrixSubtechniqueAutoExpand", e.target.checked)}
                    className={switchCls}
                  />
                  <div>
                    <span className="font-medium block">Auto-expand sub-techniques</span>
                    <span className="text-[10px] text-muted block">Show expandable (=) items by default</span>
                  </div>
                </label>

                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentApp.enableLiveTelemetryStream ?? true}
                    onChange={(e) => updateAppField("enableLiveTelemetryStream", e.target.checked)}
                    className={switchCls}
                  />
                  <div>
                    <span className="font-medium block">Live terminal telemetry log stream</span>
                    <span className="text-[10px] text-muted block">Print HTTP & query metrics to terminal</span>
                  </div>
                </label>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 5: AI AGENT                                                           */}
        {/* ========================================================================= */}
        {activeSection === "agent" && (
          <div className="space-y-6">
            {/* Agent Status Banner */}
            <div className="rounded-xl border border-border bg-bg-card p-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={cn(
                    "flex size-10 items-center justify-center rounded-lg border",
                    agentStatusQuery.data?.available ? "bg-sage/10 border-sage/40" : "bg-danger/10 border-danger/50"
                  )}>
                    <Bot className={cn("size-5", agentStatusQuery.data?.available ? "text-sage" : "text-danger")} />
                  </div>
                  <div>
                    <h3 className="text-base font-medium text-fg">AGY agent status</h3>
                    <p className="text-xs text-muted">
                      {agentStatusQuery.data?.available
                        ? `v${agentStatusQuery.data.version} · ${agentStatusQuery.data.platform} · Ready`
                        : "Agent unavailable — crawler operates with rule-based fallback"}
                    </p>
                  </div>
                </div>
                <div className={cn(
                  "flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium border",
                  agentStatusQuery.data?.available
                    ? "bg-sage/15 text-sage border-sage/40"
                    : "bg-danger/15 text-danger border-danger/50"
                )}>
                  <div className={cn("size-2 rounded-full", agentStatusQuery.data?.available ? "bg-sage" : "bg-danger")} />
                  {agentStatusQuery.data?.available ? "Online" : "Offline"}
                </div>
              </div>
            </div>

            {/* Agent Feature Toggles */}
            <div className="rounded-xl border border-border bg-bg-card p-5">
              <h3 className="flex items-center gap-2 text-base font-medium text-fg">
                <Sparkles className="size-4 text-muted" strokeWidth={1.75} />
                Intelligence enhancement layer
              </h3>
              <p className="mt-1 text-xs text-muted">
                Control which AI agent capabilities are active. The crawler engine remains the core system regardless of these settings.
              </p>
              <div className="mt-4 space-y-4">
                {[
                  {
                    key: "agentDiscoveryEnabled" as const,
                    label: "Source discovery",
                    desc: "Agent autonomously discovers new high-value CTI sources and root domains",
                  },
                  {
                    key: "agentTaggingEnabled" as const,
                    label: "Intelligent tagging & analysis",
                    desc: "Agent evaluates resources and enriches classification, threat actors, malware families, and MITRE techniques",
                  },
                  {
                    key: "agentLibraryAuditEnabled" as const,
                    label: "AI library quality audit",
                    desc: "Continuously audit and evaluate library resources, verify technical threat intelligence, and assign enriched tags",
                  },
                  {
                    key: "agentAutoPruneJunkEnabled" as const,
                    label: "AI auto-prune non-threat intel pages",
                    desc: "Carefully purge confirmed non-threat content (e.g. homepages, contact pages, error pages, zero-IOC marketing) from the library. High-value threat intelligence is protected by strict safety guardrails.",
                  },
                  {
                    key: "agentApprovalEnabled" as const,
                    label: "Approval recommendations",
                    desc: "Agent provides pass scores and ingestion recommendations for qualified resources",
                  },
                  {
                    key: "agentAutoIngestEnabled" as const,
                    label: "Auto-ingest agent approved",
                    desc: "Automatically ingest resources the agent approves with score ≥ 65 (requires auto-ingest ON)",
                  },
                  {
                    key: "agentCrawlSourcesEnabled" as const,
                    label: "Crawl discovered sources",
                    desc: "Include agent-discovered and crawler-discovered sources in crawl jobs",
                  },
                  {
                    key: "translateNonEnglish" as const,
                    label: "Translate non-English reports",
                    desc: "Reports in other languages are translated into English with the active AI provider before they are evaluated, unless the publisher has an English edition. Indicators and identifiers are checked against the original, which is kept with the report. Off: they wait until this is turned on.",
                    defaultOn: true,
                  },
                ].map((toggle) => {
                  const isChecked = Boolean(currentCrawl[toggle.key] ?? ("defaultOn" in toggle && toggle.defaultOn));
                  return (
                    <div
                      key={toggle.key}
                      className="rounded-lg border border-border bg-bg-subtle p-3.5"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="text-sm font-medium text-fg">{toggle.label}</div>
                          <div className="text-xs text-muted mt-0.5">{toggle.desc}</div>
                        </div>
                        <button
                          type="button"
                          role="switch"
                          aria-checked={isChecked}
                          onClick={() => {
                            const next = !isChecked;
                            updateCrawlField(toggle.key, next);
                            updateAppField(toggle.key as any, next);
                          }}
                          className={cn(
                            "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center p-0.5 rounded-full transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-accent/50 ",
                            isChecked
                              ? "bg-sage"
                              : "bg-neutral-800 border border-neutral-700",
                          )}
                        >
                          <span
                            className={cn(
                              "pointer-events-none inline-block size-5 transform rounded-full bg-white shadow-sm ring-0 transition-transform duration-200 ease-in-out",
                              isChecked ? "translate-x-5" : "translate-x-0",
                            )}
                          />
                        </button>
                      </div>

                      {/* Safety Guardrail banner for Auto-Prune */}
                      {toggle.key === "agentAutoPruneJunkEnabled" && isChecked && (
                        <div className="mt-2.5 flex items-center gap-2 text-[11px] text-sage bg-sage/10 border border-sage/40 rounded-md px-2.5 py-1.5 font-medium">
                          <CheckCircle2 className="size-3.5 shrink-0" />
                          <span>Strict safety guardrails active: legitimate threat reports with IOCs, CVEs, or ATT&CK techniques are strictly protected and will never be pruned.</span>
                        </div>
                      )}

                      {/* Warning Alert when Auto-Ingest Agent Approved is enabled while Auto-Ingest Qualified Reports is disabled */}
                      {toggle.key === "agentAutoIngestEnabled" && isChecked && !(currentCrawl.autoIngest ?? true) && (
                        <div className="mt-3 flex items-start gap-2.5 rounded-lg border border-warn/40 bg-warn/10 p-3 text-xs">
                          <AlertTriangle className="size-4 shrink-0 mt-0.5 text-warn" />
                          <div className="flex-1 space-y-1">
                            <div className="font-semibold text-warn">
                              Prerequisite setting disabled: "Auto-ingest qualified reports" is off
                            </div>
                            <p className="text-[11px] leading-relaxed text-muted">
                              Autonomous ingestion requires <strong>BOTH</strong> settings enabled. While <em>Auto-ingest qualified reports</em> (under Crawler & ingestion) is paused, newly discovered reports approved by the agent will be placed in the manual review approval queue instead of being directly ingested.
                            </p>
                            <button
                              type="button"
                              onClick={() => {
                                updateCrawlField("autoIngest", true);
                                toast.success('Enabled "Auto-ingest qualified reports"');
                              }}
                              className="mt-1.5 inline-flex items-center gap-1.5 rounded-md border border-warn/50 bg-warn/15 px-2.5 py-1 text-[11px] font-medium text-warn hover:bg-warn/25 transition-colors cursor-pointer"
                            >
                              <CheckCircle2 className="size-3.5 text-warn" />
                              Enable "Auto-ingest qualified reports" now
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Direct Save Button for AI Agent Settings */}
              <div className="mt-5 flex items-center justify-between border-t border-border pt-4">
                <div className="text-xs text-muted">
                  {isDirty ? (
                    <span className="flex items-center gap-1.5 text-warn">
                      <span className="size-2 rounded-full bg-warn " />
                      Unsaved AI Agent settings
                    </span>
                  ) : (
                    <span className="flex items-center gap-1.5 text-sage">
                      <CheckCircle2 className="size-3.5 text-sage" />
                      All AI agent settings saved
                    </span>
                  )}
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  className="gap-1.5"
                  disabled={saveMutation.isPending}
                  onClick={() => saveMutation.mutate()}
                >
                  <Save className="size-3.5" />
                  <span>{saveMutation.isPending ? "Saving…" : "Save AI agent settings"}</span>
                </Button>
              </div>
            </div>

            {/* Agent Model & Timeout */}
            <div className="rounded-xl border border-border bg-bg-card p-5">
              <div className="flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-base font-medium text-fg">
                  <Zap className="size-4 text-muted" strokeWidth={1.75} />
                  Model & performance
                </h3>
                <Link
                  to="/marketplace"
                  className="text-xs text-accent hover:underline flex items-center gap-1 font-medium"
                >
                  <span>Manage in Marketplace</span>
                  <Bot className="size-3" />
                </Link>
              </div>

              <p className="mt-1 text-xs text-muted">
                Choose which AI powers AIE and the exact model it runs. Applies to every AI feature —
                crawling, tagging, library audit and the agent console. Set it here or in the Marketplace.
              </p>

              {/* Current active selection */}
              <div className="mt-3 p-3 rounded-lg bg-bg-subtle border border-border flex items-center justify-between gap-3 text-xs">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="text-subtle shrink-0">Active:</span>
                  <span className="font-semibold text-fg truncate">
                    {aiIntegrations.find((x) => x.id === aiSavedProvider)?.name || "Autonomous AI Agent Engine"}
                  </span>
                  <span className="shrink-0 font-mono text-[11px] text-accent">{stripModelLabel(aiSavedModel) || "—"}</span>
                </div>
                <StatusChip tone="success">Active</StatusChip>
              </div>

              {/* Provider + model picker */}
              <div className="mt-4 grid gap-4 md:grid-cols-2">
                <div>
                  <label htmlFor="ai-provider" className="block text-xs font-medium text-muted mb-1.5">AI provider</label>
                  <Select
                    id="ai-provider"
                    value={aiEffProvider}
                    onValueChange={(v) => {
                      setAiProviderPick(v);
                      setAiModelPick(null);
                    }}
                    className="w-full"
                  >
                    {aiProvidersSorted.map((integration) => (
                      <option key={integration.id} value={integration.id}>
                        {integration.name} {integration.status === "installed" ? "· Installed" : "· Not installed"}
                      </option>
                    ))}
                  </Select>
                </div>
                <div>
                  <label htmlFor="ai-model" className="block text-xs font-medium text-muted mb-1.5">Model</label>
                  <Select
                    id="ai-model"
                    value={aiEffModel}
                    onValueChange={(v) => setAiModelPick(v)}
                    disabled={aiEffModels.length === 0}
                    className="w-full"
                  >
                    {aiEffModels.length > 0 ? (
                      aiEffModels.map((m) => (
                        <option key={m} value={m}>
                          {AGY_AVAILABLE_MODELS.find((x) => x.id === stripModelLabel(m))?.name ?? stripModelLabel(m)}
                        </option>
                      ))
                    ) : (
                      <option value="">No models — configure this provider first</option>
                    )}
                  </Select>
                </div>
              </div>

              {/* Not-installed hint + apply */}
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
                <div className="text-xs">
                  {aiEffProviderItem && aiEffProviderItem.status !== "installed" ? (
                    <span className="flex items-center gap-1.5 text-warn">
                      <AlertTriangle className="size-3.5 shrink-0" />
                      Not configured yet — add its API key in the{" "}
                      <Link to="/marketplace" className="font-medium text-accent hover:underline">
                        Marketplace
                      </Link>{" "}
                      so it can run.
                    </span>
                  ) : aiSelectionChanged ? (
                    <span className="flex items-center gap-1.5 text-warn">
                      <span className="size-2 rounded-full bg-warn" />
                      Unapplied AI selection
                    </span>
                  ) : (
                    <span className="flex items-center gap-1.5 text-sage">
                      <CheckCircle2 className="size-3.5" />
                      This AI is active
                    </span>
                  )}
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  className="gap-1.5"
                  disabled={!aiSelectionChanged || !aiEffModel || applyActiveAIMutation.isPending}
                  onClick={() => applyActiveAIMutation.mutate({ id: aiEffProvider, model: aiEffModel })}
                >
                  <Zap className="size-3.5" />
                  <span>{applyActiveAIMutation.isPending ? "Applying…" : "Set as active AI"}</span>
                </Button>
              </div>

              {/* Agent timeout (applies to the AGY sandbox agent path) */}
              <div className="mt-4 border-t border-border pt-4">
                <label className="block text-xs font-medium text-muted mb-1.5">
                  Agent timeout (seconds): {crawlForm.agentTimeoutSeconds || 45}s
                </label>
                <input
                  type="range"
                  min={10}
                  max={120}
                  step={5}
                  value={crawlForm.agentTimeoutSeconds || 45}
                  onChange={(e) => {
                    setCrawlForm((prev) => ({ ...prev, agentTimeoutSeconds: Number(e.target.value) }));
                    setIsDirty(true);
                  }}
                  className="w-full accent-accent"
                />
                <div className="flex justify-between text-[10px] text-subtle mt-1">
                  <span>10s (fast)</span>
                  <span>120s (thorough)</span>
                </div>
                {isDirty && (
                  <div className="mt-2 text-[11px] text-warn">Timeout change is saved with "Save AI agent settings" above.</div>
                )}
              </div>
            </div>

            {/* Fail-Safe Notice */}
            <div className="rounded-lg border border-warn/40 bg-warn/10 p-4">
              <div className="flex items-start gap-3">
                <ShieldAlert className="size-5 text-warn shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-warn">Zero point of failure design</p>
                  <p className="mt-1 text-xs text-muted ">
                    If the AGY agent is unavailable, times out, or returns an error, the crawler automatically
                    falls back to rule-based heuristic qualification and standard ingestion — zero disruption to
                    the core pipeline.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 6: USERS & ACCESS                                                     */}
        {/* ========================================================================= */}
        {activeSection === "users" && <UsersPanel />}
        </div>
        </div>
      </div>
    </AppShell>
  );
}

/** Native checkbox styled as a switch (keeps the checkbox semantics and handlers). */
const switchCls =
  "peer relative h-5 w-9 shrink-0 cursor-pointer appearance-none rounded-full border border-border bg-bg-subtle transition-colors before:absolute before:left-0.5 before:top-0.5 before:size-3.5 before:rounded-full before:bg-muted before:transition-transform before:content-[''] checked:border-accent checked:bg-accent checked:before:translate-x-4 checked:before:bg-accent-fg disabled:cursor-not-allowed disabled:opacity-50";

/**
 * Developer mode, for administrators: shows the technical details behind the console (agent workers
 * and CLI output, the tools the AIE Analyst called with their arguments and timings, the provider and
 * model on each answer, Marketplace diagnostics). Off, analysts see only what they need.
 */
/** Taxonomy discovery: which research categories the crawler searches for, and how many searches a run makes. */
function ResearchDiscoverySettings({
  value,
  onChange,
  searchEnabled,
}: {
  value: ResearchDiscoveryConfig;
  onChange: (v: ResearchDiscoveryConfig) => void;
  searchEnabled: boolean;
}) {
  const core = RESEARCH_CATEGORIES.filter((c) => c.scope === "core");
  const bas = RESEARCH_CATEGORIES.filter((c) => c.scope === "bas");
  const off = !searchEnabled || !value.enabled;
  return (
    <div className="space-y-3 border-t border-border pt-3" aria-labelledby="research-discovery-title">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <span id="research-discovery-title" className="block text-xs font-medium">
            Research coverage searches
          </span>
          <p className="text-[11px] text-muted">
            Each run searches the web across the research taxonomy, the categories with the fewest reports first, so every kind of attack research
            is looked for over time. What is found still has to pass the technical quality gate.
          </p>
          {!searchEnabled && <p className="mt-1 text-[11px] text-warn">Turn on search-driven discovery above to use these searches.</p>}
        </div>
        <input
          type="checkbox"
          role="switch"
          aria-label="Research coverage searches"
          checked={value.enabled}
          disabled={!searchEnabled}
          onChange={(e) => onChange({ ...value, enabled: e.target.checked })}
          className={switchCls}
        />
      </div>

      <div className={cn("space-y-3", off && "opacity-60")}>
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="research-queries-per-run" className="text-xs text-muted">
            Searches per run
          </label>
          <Select
            id="research-queries-per-run"
            size="sm"
            value={String(value.queriesPerRun)}
            onValueChange={(v) => onChange({ ...value, queriesPerRun: Number(v) })}
            disabled={off}
            className="w-20"
          >
            {[2, 4, 6, 8, 10, 12].map((n) => (
              <option key={n} value={String(n)}>
                {n}
              </option>
            ))}
          </Select>
        </div>

        <div>
          <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-wide text-subtle">Always searched</span>
          <div className="flex flex-wrap gap-1.5">
            {core.map((c) => (
              <span key={c.id} title={`${c.label}: ${c.types.join(", ")}`} className="rounded-md border border-border bg-bg-subtle/60 px-2 py-0.5 text-[11px] text-muted">
                {c.short}
              </span>
            ))}
          </div>
        </div>

        <div>
          <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-wide text-subtle">Optional: detection and emulation (BAS)</span>
          <div className="grid gap-2 sm:grid-cols-3">
            {bas.map((c) => {
              const on = value.bas.includes(c.id);
              return (
                <label key={c.id} className={cn("flex cursor-pointer items-start gap-2 rounded-lg border p-2.5 text-xs", on ? "border-accent/50 bg-accent/5" : "border-border bg-bg-subtle/40")}>
                  <input
                    type="checkbox"
                    checked={on}
                    disabled={off}
                    onChange={(e) => onChange({ ...value, bas: e.target.checked ? [...value.bas, c.id] : value.bas.filter((x) => x !== c.id) })}
                    className="mt-0.5 accent-[var(--color-primary)]"
                  />
                  <span className="min-w-0">
                    <span className="block font-medium text-fg">{c.short}</span>
                    <span className="block text-[11px] text-muted">{c.purpose}</span>
                  </span>
                </label>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

function DeveloperModeCard() {
  const qc = useQueryClient();
  const info = useQuery({ queryKey: ["agent-info"], queryFn: () => getAgentInfo(), staleTime: 30_000 });
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => setDebuggerMode({ data: { enabled } }),
    onSuccess: (res) => {
      toast.success(res.debuggerMode ? "Developer mode on" : "Developer mode off");
      for (const key of [["agent-info"], ["app-settings"], ["app_settings"], ["marketplace_state"]]) void qc.invalidateQueries({ queryKey: key });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Could not change Developer mode"),
  });
  if (!info.data?.canUseDeveloperMode) return null;
  const on = Boolean(info.data.developer);
  return (
    <div className="card-liquid-glass mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-bg-card px-4 py-3">
      <div className="flex min-w-0 items-start gap-3">
        <Code2 className="mt-0.5 size-4 shrink-0 text-muted" strokeWidth={1.75} />
        <div className="min-w-0">
          <p className="text-sm font-medium text-fg">Developer mode</p>
          <p className="mt-0.5 text-xs text-muted">
            Shows technical details: agent workers and CLI output, the tools the AIE Analyst used with their arguments and timings, the provider and model on each answer, and
            Marketplace diagnostics. Only administrators see this switch.
          </p>
        </div>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={on}
        aria-label="Developer mode"
        disabled={toggle.isPending}
        onClick={() => toggle.mutate(!on)}
        className={cn(
          "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full p-0.5 transition-colors focus:outline-none focus:ring-2 focus:ring-accent/50 disabled:opacity-60",
          on ? "bg-sage" : "border border-neutral-700 bg-neutral-800",
        )}
      >
        <span className={cn("inline-block size-5 rounded-full bg-white shadow-sm transition-transform", on ? "translate-x-5" : "translate-x-0")} />
      </button>
    </div>
  );
}
