import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  Clock,
  Compass,
  Database,
  Download,
  FileCode,
  FileText,
  Filter,
  HardDrive,
  Layers,
  Moon,
  Network,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  Sliders,
  Sparkles,
  Sun,
  Trash2,
  Upload,
  Zap,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import {
  getAppSettings,
  getCrawlConfig,
  getStorageStats,
  purgeServerCaches,
  updateAppSettings,
  updateCrawlerConfig,
} from "@/lib/aie/server";
import { z } from "zod";
import { cn } from "@/lib/cn";
import type { AppSettings, CrawlConfig, ResourceKind } from "@/lib/aie/types";

const settingsSearchSchema = z.object({
  tab: z.enum(["crawler", "policy", "storage", "display"]).optional(),
});

export const Route = createFileRoute("/settings")({
  validateSearch: (search) => settingsSearchSchema.parse(search),
  component: SettingsPage,
});

const SETTINGS_SECTIONS = [
  { id: "crawler", label: "Crawler & Ingestion", icon: Bot, badge: "Engine" },
  { id: "policy", label: "Intelligence Policies", icon: Shield, badge: "SOC" },
  { id: "storage", label: "Database & Storage", icon: Database, badge: "Atlas" },
  { id: "display", label: "Display & Preferences", icon: Sliders, badge: "UI" },
] as const;

type SettingsSectionId = (typeof SETTINGS_SECTIONS)[number]["id"];

function SettingsPage() {
  const search = Route.useSearch();
  const qc = useQueryClient();
  const [activeSection, setActiveSection] = useState<SettingsSectionId>(
    search.tab ?? "crawler"
  );

  // Fetch Configurations from MongoDB Atlas
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

  const storageStatsQuery = useQuery({
    queryKey: ["storage-stats"],
    queryFn: () => getStorageStats(),
    staleTime: 15000,
    refetchInterval: 20000,
  });

  // Local Form States for instantaneous 0ms responsive UI
  const [crawlForm, setCrawlForm] = useState<Partial<CrawlConfig>>({});
  const [appForm, setAppForm] = useState<Partial<AppSettings>>({});
  const [isDirty, setIsDirty] = useState(false);

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
      toast.success("Settings saved successfully to MongoDB Atlas");
    },
    onError: (err: Error) => {
      toast.error(`Failed to save settings: ${err.message}`);
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

  const handleReset = () => {
    if (configQuery.data) setCrawlForm(configQuery.data);
    if (appSettingsQuery.data) setAppForm(appSettingsQuery.data);
    setIsDirty(false);
    toast.info("Reverted local changes to current database state");
  };

  const currentCrawl = { ...configQuery.data, ...crawlForm };
  const currentApp = { ...appSettingsQuery.data, ...appForm };

  return (
    <AppShell>
      <div className="space-y-6 max-w-6xl mx-auto pb-12">
        {/* ========================================================================= */}
        {/* SETTINGS HEADER & PERSISTENCE BANNER                                      */}
        {/* ========================================================================= */}
        <div className="flex flex-col justify-between gap-4 border-b border-border pb-6 sm:flex-row sm:items-center">
          <div>
            <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">
              <span className="size-2 rounded-full bg-accent animate-pulse" />
              <span>System Administration · Configuration Hub</span>
            </div>
            <h1 className="mt-1 text-2xl font-bold tracking-tight text-fg sm:text-3xl">
              Centralized Settings
            </h1>
            <p className="mt-1.5 text-xs text-muted max-w-2xl leading-relaxed">
              Configure autonomous acquisition pipelines, heuristic qualification thresholds, intelligence retention policies, and database telemetry.
            </p>
          </div>

          {/* PERSISTENCE BACKBONE BADGE */}
          <div className="flex items-center gap-3">
            <div className="rounded-lg border border-border bg-bg-elevated px-3 py-2 text-right hidden md:block">
              <div className="font-mono text-[10px] uppercase text-subtle">Primary Storage</div>
              <div className="font-mono text-xs text-accent font-medium flex items-center gap-1.5 justify-end">
                <span className="size-1.5 rounded-full bg-emerald-500" />
                MongoDB Atlas Cluster
              </div>
            </div>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* TOP ACTION BAR: UNSAVED STATUS, SAVE, DISCARD, PURGE CACHE                */}
        {/* ========================================================================= */}
        <div className="sticky top-14 z-20 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-bg/95 backdrop-blur-md px-4 py-3 shadow-xs">
          <div className="flex items-center gap-2.5">
            {isDirty ? (
              <span className="flex items-center gap-1.5 font-mono text-xs text-warn">
                <span className="size-2 rounded-full bg-warn animate-pulse" />
                Unsaved modifications pending
              </span>
            ) : (
              <span className="flex items-center gap-1.5 font-mono text-xs text-subtle">
                <CheckCircle2 className="size-3.5 text-emerald-500" />
                All configurations synced to MongoDB
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              disabled={purgeMutation.isPending}
              onClick={() => purgeMutation.mutate()}
              className="gap-1.5 text-xs font-mono"
              title="Flush in-memory caches to force fresh retrieval from MongoDB"
            >
              <RefreshCw className={cn("size-3.5", purgeMutation.isPending && "animate-spin")} />
              <span>Purge Cache</span>
            </Button>

            {isDirty && (
              <Button
                variant="secondary"
                size="sm"
                onClick={handleReset}
                className="gap-1.5 text-xs font-mono text-muted hover:text-fg"
              >
                <RotateCcw className="size-3.5" />
                <span>Discard</span>
              </Button>
            )}

            <Button
              variant="primary"
              size="sm"
              disabled={!isDirty || saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
              className={cn(
                "gap-1.5 text-xs font-mono",
                isDirty ? "bg-accent text-bg hover:opacity-90" : "opacity-60",
              )}
            >
              <Save className="size-3.5" />
              <span>{saveMutation.isPending ? "Saving to DB..." : "Save Changes"}</span>
            </Button>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* TAB NAVIGATION: CRAWLER, POLICY, STORAGE, DISPLAY                         */}
        {/* ========================================================================= */}
        <div className="flex flex-wrap gap-2 border-b border-border pb-3">
          {SETTINGS_SECTIONS.map((sec) => {
            const active = activeSection === sec.id;
            return (
              <button
                key={sec.id}
                type="button"
                onClick={() => setActiveSection(sec.id)}
                className={cn(
                  "flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-colors select-none",
                  active
                    ? "bg-bg-subtle text-fg border border-border"
                    : "text-muted hover:bg-bg-elevated hover:text-fg border border-transparent",
                )}
              >
                <sec.icon className={cn("size-4", active ? "text-accent" : "text-muted")} />
                <span>{sec.label}</span>
                <span className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-subtle">
                  {sec.badge}
                </span>
              </button>
            );
          })}
        </div>

        {/* ========================================================================= */}
        {/* TAB 1: CRAWLER & INGESTION ENGINE CONTROLS                                */}
        {/* ========================================================================= */}
        {activeSection === "crawler" && (
          <div className="space-y-6">
            {/* Section 1.1: Autonomous Schedule & Execution Limits */}
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <div>
                  <h3 className="text-sm font-medium flex items-center gap-2">
                    <Activity className="size-4 text-accent" />
                    Autonomous Acquisition & Schedule Engine
                  </h3>
                  <p className="text-xs text-muted">
                    Control the autonomous crawler scheduler, concurrency limit, and traversal depth.
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <label className="flex items-center gap-2 text-xs font-mono cursor-pointer">
                    <input
                      type="checkbox"
                      checked={currentCrawl.enabled ?? true}
                      onChange={(e) => updateCrawlField("enabled", e.target.checked)}
                      className="size-4 accent-accent"
                    />
                    <span>Master Scheduler Enabled</span>
                  </label>
                  <label className="flex items-center gap-2 text-xs font-mono cursor-pointer">
                    <input
                      type="checkbox"
                      checked={currentCrawl.paused ?? false}
                      onChange={(e) => updateCrawlField("paused", e.target.checked)}
                      className="size-4 accent-warn"
                    />
                    <span className={currentCrawl.paused ? "text-warn" : "text-muted"}>Pause Jobs</span>
                  </label>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Crawl Interval</label>
                    <span className="font-mono text-accent">
                      {Math.floor((currentCrawl.frequencyMinutes ?? 360) / 60)}h{" "}
                      {(currentCrawl.frequencyMinutes ?? 360) % 60 > 0
                        ? `${(currentCrawl.frequencyMinutes ?? 360) % 60}m`
                        : ""}
                    </span>
                  </div>
                  <input
                    type="range"
                    min="30"
                    max="1440"
                    step="30"
                    value={currentCrawl.frequencyMinutes ?? 360}
                    onChange={(e) => updateCrawlField("frequencyMinutes", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[10px] font-mono text-subtle">
                    <span>30m</span>
                    <span>6h</span>
                    <span>12h</span>
                    <span>24h</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Concurrency Workers</label>
                    <span className="font-mono text-accent">{currentCrawl.concurrency ?? 2} workers</span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="6"
                    step="1"
                    value={currentCrawl.concurrency ?? 2}
                    onChange={(e) => updateCrawlField("concurrency", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[10px] font-mono text-subtle">
                    <span>1 worker</span>
                    <span>3 workers</span>
                    <span>6 workers</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Polite Rate Limit</label>
                    <span className="font-mono text-accent">{currentCrawl.rateLimitMs ?? 150}ms</span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="1000"
                    step="50"
                    value={currentCrawl.rateLimitMs ?? 150}
                    onChange={(e) => updateCrawlField("rateLimitMs", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                  <div className="flex justify-between text-[10px] font-mono text-subtle">
                    <span>50ms (fast)</span>
                    <span>250ms</span>
                    <span>1s (polite)</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-3 border-t border-border">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Max Resources Per Run</label>
                    <span className="font-mono text-accent">
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
                  <div className="flex justify-between text-[10px] text-subtle font-mono">
                    <span>15 min</span>
                    <span>35 default</span>
                    <span>150 max</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium flex items-center gap-1.5">
                      <Clock className="size-3.5 text-accent" />
                      <span>Crawl Job Time Limit</span>
                    </label>
                    <span className="font-mono text-accent">
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
                  <div className="flex justify-between text-[10px] text-subtle font-mono">
                    <span>1m (quick)</span>
                    <span>5m (balanced)</span>
                    <span>20m (deep)</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Per-Domain Cap</label>
                    <span className="font-mono text-accent">{currentCrawl.maxResourcesPerDomain ?? 8} max</span>
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
                  <div className="flex justify-between text-[10px] text-subtle font-mono">
                    <span>2 min</span>
                    <span>8 default</span>
                    <span>25 max</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Max Graph Depth</label>
                    <span className="font-mono text-accent">{currentCrawl.maxDepth ?? 3} hops</span>
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
                  <div className="flex justify-between text-[10px] text-subtle font-mono">
                    <span>1 shallow</span>
                    <span>3 default</span>
                    <span>5 deep</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 1.2: Discovery Channels & Spidering Protocols */}
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <h3 className="text-sm font-medium border-b border-border pb-3 flex items-center gap-2">
                <Compass className="size-4 text-accent" />
                Discovery Channels & Spidering Protocols
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg-subtle/20">
                  <div>
                    <label className="text-xs font-medium block">Continuous RSS & Atom Feeds</label>
                    <span className="text-[11px] text-muted">Real-time CTI feed polling from monitored sources</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={currentCrawl.rssDiscovery !== false}
                    onChange={(e) => updateCrawlField("rssDiscovery", e.target.checked)}
                    className="size-4 accent-accent"
                  />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg-subtle/20">
                  <div>
                    <label className="text-xs font-medium block">Homepage Permalink Scraping</label>
                    <span className="text-[11px] text-muted">Extract new technical reports from source landing pages</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={currentCrawl.htmlDiscovery !== false}
                    onChange={(e) => updateCrawlField("htmlDiscovery", e.target.checked)}
                    className="size-4 accent-accent"
                  />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg-subtle/20">
                  <div>
                    <label className="text-xs font-medium block">Search-Driven Discovery Vectors</label>
                    <span className="text-[11px] text-muted">Generate dynamic search queries for emerging campaigns</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={currentCrawl.searchDiscovery !== false}
                    onChange={(e) => updateCrawlField("searchDiscovery", e.target.checked)}
                    className="size-4 accent-accent"
                  />
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg-subtle/20">
                  <div>
                    <label className="text-xs font-medium block">Recursive Outlink Deep Spidering</label>
                    <span className="text-[11px] text-muted">Traverse technical citations and links referenced in reports</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={currentCrawl.recursiveDiscovery !== false}
                    onChange={(e) => updateCrawlField("recursiveDiscovery", e.target.checked)}
                    className="size-4 accent-accent"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-border">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium block">Discovery Breadth</label>
                  <select
                    value={currentCrawl.discoveryBreadth || "balanced"}
                    onChange={(e) => updateCrawlField("discoveryBreadth", e.target.value as any)}
                    className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                  >
                    <option value="focused">Focused (Seeds + 1-Hop Citations Only)</option>
                    <option value="balanced">Balanced (Recommended 2-Hop Graph Expansion)</option>
                    <option value="wide">Wide (Aggressive Multi-Hop Graph Traversal)</option>
                  </select>
                </div>

                <div className="flex items-center pt-4">
                  <label className="flex items-center gap-2 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={currentCrawl.allowExternalDomains !== false}
                      onChange={(e) => updateCrawlField("allowExternalDomains", e.target.checked)}
                      className="size-4 accent-accent"
                    />
                    <div>
                      <span className="font-medium block">Allow External Domains</span>
                      <span className="text-[10px] text-muted block">
                        Expand outside initial seed list to discover new threat publishers
                      </span>
                    </div>
                  </label>
                </div>
              </div>
            </div>

            {/* Section 1.3: Target Intelligence Resource Types */}
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-3">
              <div className="border-b border-border pb-3">
                <h3 className="text-sm font-medium flex items-center gap-2">
                  <Filter className="size-4 text-accent" />
                  Target Intelligence Resource Types
                </h3>
                <p className="text-xs text-muted">
                  Specify the technical artifacts the qualification engine should extract, categorize, and index.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                {[
                  { id: "FULL_ATTACK_CHAIN", label: "Full Intrusion Attack Chains", desc: "Multi-stage lifecycle (Initial Access -> Lateral -> Impact)" },
                  { id: "CAMPAIGN_INTEL", label: "Adversary Campaign Tracking", desc: "Geopolitical threat activity & multi-incident tracking" },
                  { id: "PROCEDURE_DEEPDIVE", label: "Procedure Execution & TTPs", desc: "Command-line scripts, binary executions, and atomic tests" },
                  { id: "MALWARE_ANALYSIS", label: "Malware & C2 Analysis", desc: "Reverse-engineering teardowns, beacons, payloads, loaders" },
                  { id: "DETECTION_GUIDANCE", label: "Detection Engineering & Sigma", desc: "Sigma rules, YARA signatures, hunting queries, mitigations" },
                  { id: "VULNERABILITY_ADVISORY", label: "CVE Exploits & Zero-Days", desc: "Vulnerability weaponization and technical advisories" },
                  { id: "THREAT_ACTOR_DOSSIER", label: "Threat Actor Dossiers", desc: "Adversary group profiles, infrastructure, and attribution" },
                ].map((item) => {
                  const isChecked = (currentCrawl.targetResourceTypes || []).includes(item.id as ResourceKind);
                  return (
                    <label
                      key={item.id}
                      className={cn(
                        "flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors",
                        isChecked ? "border-accent/40 bg-accent/5" : "border-border bg-bg-subtle/30 hover:border-border/80",
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
                        className="mt-0.5 size-4 accent-accent"
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
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <h3 className="text-sm font-medium border-b border-border pb-3 flex items-center gap-2">
                <ShieldAlert className="size-4 text-accent" />
                Heuristic Qualification & Quality Gate
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Strictness Mode</label>
                    <span className="font-mono text-accent capitalize">{currentCrawl.strictnessMode || "balanced"}</span>
                  </div>
                  <select
                    value={currentCrawl.strictnessMode || "balanced"}
                    onChange={(e) => updateCrawlField("strictnessMode", e.target.value as any)}
                    className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                  >
                    <option value="permissive">Permissive (Include brief advisories)</option>
                    <option value="balanced">Balanced (Recommended standard)</option>
                    <option value="strict">Strict (High TTP & IOC density required)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Min Quality Score</label>
                    <span className="font-mono text-accent">
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
                  <div className="flex justify-between text-[10px] font-mono text-subtle">
                    <span>15% (broad)</span>
                    <span>35%</span>
                    <span>80% (strict)</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Min Word Count</label>
                    <span className="font-mono text-accent">{currentCrawl.minWordCount ?? 100} words</span>
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
                  <div className="flex justify-between text-[10px] font-mono text-subtle">
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
                    className="size-4 accent-accent"
                  />
                  <div>
                    <span className="font-medium block">Require Verified IOCs</span>
                    <span className="text-[10px] text-muted block">Must have IPs, Hashes, or CVEs</span>
                  </div>
                </label>

                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentCrawl.requireAttck ?? false}
                    onChange={(e) => updateCrawlField("requireAttck", e.target.checked)}
                    className="size-4 accent-accent"
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
                    className="size-4 accent-accent"
                  />
                  <div>
                    <span className="font-medium block">Reject Marketing & PR</span>
                    <span className="text-[10px] text-muted block">Exclude webinars, pricing, announcements</span>
                  </div>
                </label>
              </div>

              <div className="pt-2 border-t border-border">
                <label className="text-xs font-medium block">Noise / PR Keyword Blacklist</label>
                <p className="text-[11px] text-muted">Pages with high density of these terms are filtered as vendor noise.</p>
                <Input
                  value={currentCrawl.noiseKeywords || ""}
                  onChange={(e) => updateCrawlField("noiseKeywords", e.target.value)}
                  placeholder="webinar, discount, pricing, subscribe..."
                  className="mt-1.5 text-xs font-mono"
                />
              </div>
            </div>

            {/* Section 1.5: Deduplication, PDF & Keywords */}
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <h3 className="text-sm font-medium border-b border-border pb-3 flex items-center gap-2">
                <HardDrive className="size-4 text-accent" />
                Deduplication Strategy & Document Preservation
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium block">Deduplication Method</label>
                  <select
                    value={currentCrawl.dedupMethod || "smart_hybrid"}
                    onChange={(e) => updateCrawlField("dedupMethod", e.target.value as any)}
                    className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                  >
                    <option value="smart_hybrid">Smart Hybrid (Normalized URL + 64-bit SimHash)</option>
                    <option value="both">Both (Strict URL & Exact Content Hash)</option>
                    <option value="canonical_url">Canonical URL Only</option>
                    <option value="content_hash">Content Hash Only</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Max PDF Preservation Cap</label>
                    <span className="font-mono text-accent">{currentCrawl.maxPdfDownloads ?? 10} PDFs</span>
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
                      className="size-4 accent-accent"
                    />
                    <div>
                      <span className="font-medium block">High-Fidelity PDF Generation</span>
                      <span className="text-[10px] text-muted block">Preserve visual report layout</span>
                    </div>
                  </label>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-border">
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentCrawl.autoIngest ?? true}
                    onChange={(e) => updateCrawlField("autoIngest", e.target.checked)}
                    className="size-4 accent-accent"
                  />
                  <div>
                    <span className="font-medium block">Auto-Ingest Qualified Reports</span>
                    <span className="text-[10px] text-muted block">Direct save vs manual review approval queue</span>
                  </div>
                </label>

                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentCrawl.autoAnalyze ?? true}
                    onChange={(e) => updateCrawlField("autoAnalyze", e.target.checked)}
                    className="size-4 accent-accent"
                  />
                  <div>
                    <span className="font-medium block">Auto-ATT&CK & TTP Extraction</span>
                    <span className="text-[10px] text-muted block">Reconstruct multi-stage attack chains</span>
                  </div>
                </label>
              </div>

              <div className="pt-2 border-t border-border">
                <label className="text-xs font-medium block">Targeted Threat Keywords & Query Patterns</label>
                <p className="text-[11px] text-muted">Comma-separated terms used to seed search discovery vectors.</p>
                <Textarea
                  rows={3}
                  value={currentCrawl.keywords || ""}
                  onChange={(e) => updateCrawlField("keywords", e.target.value)}
                  className="mt-1.5 text-xs font-mono"
                />
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: INTELLIGENCE & SOC POLICIES                                        */}
        {/* ========================================================================= */}
        {activeSection === "policy" && (
          <div className="space-y-6">
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <h3 className="text-sm font-medium border-b border-border pb-3 flex items-center gap-2">
                <Shield className="size-4 text-accent" />
                Organizational Node & Ingestion Identity
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium block">SOC Node / Unit Name</label>
                  <p className="text-[11px] text-muted">Identifies the reporting entity in exported STIX bundles.</p>
                  <Input
                    value={currentApp.organizationName || ""}
                    onChange={(e) => updateAppField("organizationName", e.target.value)}
                    className="mt-1.5 text-xs"
                  />
                </div>

                <div>
                  <label className="text-xs font-medium block">Sensor / Engine Identifier</label>
                  <p className="text-[11px] text-muted">Node signature tagged to cryptographic SHA-256 hashes.</p>
                  <Input
                    value={currentApp.nodeId || ""}
                    onChange={(e) => updateAppField("nodeId", e.target.value)}
                    className="mt-1.5 text-xs font-mono"
                  />
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <h3 className="text-sm font-medium border-b border-border pb-3 flex items-center gap-2">
                <FileCode className="size-4 text-accent" />
                CTI Classification & Retention Standards
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium block">Default Classification</label>
                  <select
                    value={currentApp.defaultClassification || "INTRUSION_REPORT"}
                    onChange={(e) => updateAppField("defaultClassification", e.target.value)}
                    className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                  >
                    <option value="INTRUSION_REPORT">Intrusion Report</option>
                    <option value="CAMPAIGN_INTEL">Campaign Intelligence</option>
                    <option value="PROCEDURE_DEEPDIVE">Procedure Deep-Dive</option>
                    <option value="MALWARE_ANALYSIS">Malware Analysis</option>
                    <option value="THREAT_REPORT">General Threat Report</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Min IOC Confidence</label>
                    <span className="font-mono text-accent">{currentApp.iocConfidenceThreshold ?? 75}%</span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="95"
                    step="5"
                    value={currentApp.iocConfidenceThreshold ?? 75}
                    onChange={(e) => updateAppField("iocConfidenceThreshold", parseInt(e.target.value, 10))}
                    className="w-full accent-accent"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium block">Evidence Retention Period</label>
                  <select
                    value={String(currentApp.evidenceRetentionDays ?? 365)}
                    onChange={(e) => updateAppField("evidenceRetentionDays", parseInt(e.target.value, 10))}
                    className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                  >
                    <option value="90">90 Days (Quarterly Audit)</option>
                    <option value="180">180 Days (Semi-Annual)</option>
                    <option value="365">365 Days (1 Year Standard)</option>
                    <option value="0">Indefinite (Never Auto-Purge)</option>
                  </select>
                </div>
              </div>

              <div className="pt-3 border-t border-border">
                <div className="space-y-1.5 max-w-sm">
                  <label className="text-xs font-medium block">Default Export Standard</label>
                  <select
                    value={currentApp.defaultExportFormat || "stix21"}
                    onChange={(e) => updateAppField("defaultExportFormat", e.target.value as any)}
                    className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                  >
                    <option value="stix21">STIX 2.1 JSON Bundle (OASIS Standard)</option>
                    <option value="json">Raw Engine JSON (Evidence-Preserving)</option>
                    <option value="csv">CSV IOC Table (Firewall / SIEM Ingest)</option>
                    <option value="pdf">Structured PDF Dossier</option>
                  </select>
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
            {/* Storage Architecture Overview */}
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <h3 className="text-sm font-medium flex items-center gap-2">
                  <Database className="size-4 text-accent" />
                  MongoDB Atlas Cluster Telemetry
                </h3>
                <span className="flex items-center gap-1.5 font-mono text-xs text-emerald-400">
                  <span className="size-2 rounded-full bg-emerald-500 animate-pulse" />
                  Cluster0 Connected
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-lg border border-border bg-bg p-3">
                  <span className="text-[11px] text-muted block">Database</span>
                  <span className="font-mono text-sm font-semibold text-fg">threat-intel-DB</span>
                </div>
                <div className="rounded-lg border border-border bg-bg p-3">
                  <span className="text-[11px] text-muted block">Collection</span>
                  <span className="font-mono text-sm font-semibold text-fg">threat-intel</span>
                </div>
                <div className="rounded-lg border border-border bg-bg p-3">
                  <span className="text-[11px] text-muted block">Stored Reports</span>
                  <span className="font-mono text-sm font-semibold text-accent">
                    {storageStatsQuery.data?.totalReports ?? "—"}
                  </span>
                </div>
                <div className="rounded-lg border border-border bg-bg p-3">
                  <span className="text-[11px] text-muted block">Active Sources</span>
                  <span className="font-mono text-sm font-semibold text-fg">
                    {storageStatsQuery.data?.totalSources ?? "—"}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-2">
                <div className="rounded-lg border border-border bg-bg p-3">
                  <span className="text-[11px] text-muted block">Discovered Candidates</span>
                  <span className="font-mono text-sm font-semibold text-fg">
                    {storageStatsQuery.data?.totalDiscovered ?? "—"}
                  </span>
                </div>
                <div className="rounded-lg border border-border bg-bg p-3">
                  <span className="text-[11px] text-muted block">Executed Crawl Jobs</span>
                  <span className="font-mono text-sm font-semibold text-fg">
                    {storageStatsQuery.data?.totalJobs ?? "—"}
                  </span>
                </div>
                <div className="rounded-lg border border-border bg-bg p-3">
                  <span className="text-[11px] text-muted block">Pipeline Audit Events</span>
                  <span className="font-mono text-sm font-semibold text-fg">
                    {storageStatsQuery.data?.totalEvents ?? "—"}
                  </span>
                </div>
              </div>
            </div>

            {/* In-Memory Cache Acceleration & Invalidation */}
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <div>
                  <h3 className="text-sm font-medium flex items-center gap-2">
                    <Zap className="size-4 text-accent" />
                    High-Speed In-Memory Cache Acceleration
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
                  className="text-xs font-mono gap-1.5"
                >
                  <Trash2 className="size-3.5 text-danger" />
                  <span>Flush All Caches</span>
                </Button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Library Query Cache TTL</label>
                    <span className="font-mono text-accent">{currentApp.cacheTtlSeconds ?? 60} seconds</span>
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
                  <div className="flex justify-between text-xs">
                    <label className="font-medium">Dashboard Aggregation TTL</label>
                    <span className="font-mono text-accent">{currentApp.dashboardCacheTtlSeconds ?? 15} seconds</span>
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
            <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
              <h3 className="text-sm font-medium border-b border-border pb-3 flex items-center gap-2">
                <Sliders className="size-4 text-accent" />
                MITRE ATT&CK Matrix & Telemetry Presentation
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium block">Default ATT&CK Matrix Column Width</label>
                  <select
                    value={currentApp.defaultMatrixLayout || "standard"}
                    onChange={(e) => updateAppField("defaultMatrixLayout", e.target.value as any)}
                    className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                  >
                    <option value="standard">Standard (224px Columns — Full Name & Counts)</option>
                    <option value="compact">Compact (176px Columns — High Viewport Density)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium block">Live Dashboard Refresh Interval</label>
                  <select
                    value={String(currentApp.pollingIntervalSeconds ?? 12)}
                    onChange={(e) => updateAppField("pollingIntervalSeconds", parseInt(e.target.value, 10))}
                    className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                  >
                    <option value="8">8 Seconds (High Frequency SOC Stream)</option>
                    <option value="12">12 Seconds (Recommended Standard)</option>
                    <option value="30">30 Seconds (Low Bandwidth)</option>
                    <option value="60">60 Seconds (Manual / Background)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-3 border-t border-border">
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentApp.matrixSubtechniqueAutoExpand ?? false}
                    onChange={(e) => updateAppField("matrixSubtechniqueAutoExpand", e.target.checked)}
                    className="size-4 accent-accent"
                  />
                  <div>
                    <span className="font-medium block">Auto-Expand Sub-techniques</span>
                    <span className="text-[10px] text-muted block">Show expandable (=) items by default</span>
                  </div>
                </label>

                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={currentApp.enableLiveTelemetryStream ?? true}
                    onChange={(e) => updateAppField("enableLiveTelemetryStream", e.target.checked)}
                    className="size-4 accent-accent"
                  />
                  <div>
                    <span className="font-medium block">Live Terminal Telemetry Log Stream</span>
                    <span className="text-[10px] text-muted block">Print HTTP & query metrics to terminal</span>
                  </div>
                </label>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
