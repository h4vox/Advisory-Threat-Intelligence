import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import {
  Activity,
  ArrowRight,
  Bot,
  CheckCircle2,
  Clock,
  Compass,
  Crosshair,
  Database,
  Download,
  ExternalLink,
  FileText,
  Filter,
  GitBranch,
  Globe,
  Layers,
  ListFilter,
  Network,
  Play,
  RefreshCw,
  Rss,
  Search,
  Settings,
  Share2,
  Shield,
  ShieldAlert,
  Sparkles,
  Upload,
  XCircle,
  Zap,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import {
  cancelCrawlJob,
  exportSTIXBundle,
  getCrawlerState,
  ingestDiscoveredUrl,
  ingestUrl,
  listCatalog,
  triggerCrawlJob,
  updateCrawlerConfig,
} from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";
import type { CrawlConfig, ResourceKind } from "@/lib/aie/types";

export const Route = createFileRoute("/ingest")({ component: IngestPage });

const VIEWS = [
  { id: "crawler", label: "Autonomous Crawler", icon: Bot },
  { id: "queue", label: "Discovery Queue", icon: Compass },
  { id: "graph", label: "Discovery Graph & Sources", icon: Network },
  { id: "audit", label: "Pipeline Audit Log", icon: Activity },
  { id: "settings", label: "Crawler Controls", icon: Settings },
  { id: "manual", label: "Manual Ingest", icon: Upload },
  { id: "catalog", label: "Curated Catalog", icon: Database },
] as const;

const DEFAULT_CRAWL_CONFIG: CrawlConfig = {
  id: "cfg_default",
  enabled: true,
  paused: false,
  frequencyMinutes: 360,
  startHour: "09:00",
  maxResourcesPerRun: 60,
  maxResourcesPerJob: 60,
  maxResourcesPerDomain: 8,
  maxDepth: 3,
  discoveryBreadth: "balanced",
  allowExternalDomains: true,
  domainAllowlist: [],
  domainBlocklist: [],
  rateLimitMs: 150,
  concurrency: 2,
  maxPdfDownloads: 10,
  autoIngest: true,
  autoAnalyze: true,
  generatePdf: true,
  rssDiscovery: true,
  htmlDiscovery: true,
  searchDiscovery: true,
  recursiveDiscovery: true,
  keywords: 'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"',
  noiseKeywords: "webinar, discount, pricing, subscribe, careers, terms of service, privacy policy",
  minQualityScore: 0.35,
  minWordCount: 100,
  strictnessMode: "balanced",
  requireIocs: false,
  requireAttck: false,
  rejectMarketingNoise: true,
  dedupMethod: "smart_hybrid",
  activeSources: [],
  targetResourceTypes: [
    "FULL_ATTACK_CHAIN",
    "CAMPAIGN_INTEL",
    "PROCEDURE_DEEPDIVE",
    "MALWARE_ANALYSIS",
    "DETECTION_GUIDANCE",
    "VULNERABILITY_ADVISORY",
    "THREAT_ACTOR_DOSSIER",
  ],
  dateRangeDays: null,
  lastRunAt: null,
  nextRunAt: null,
};

function IngestPage() {
  const qc = useQueryClient();
  const [activeView, setActiveView] = useState<(typeof VIEWS)[number]["id"]>("crawler");

  // Targeted Hunt Query State
  const [targetedTopic, setTargetedTopic] = useState("");

  // Manual Ingest State
  const [url, setUrl] = useState("");
  const [pasted, setPasted] = useState("");

  // Queue Filter State
  const [queueFilter, setQueueFilter] = useState<string>("all");
  const [queueSearch, setQueueSearch] = useState<string>("");

  // Queries
  const crawlerState = useQuery({
    queryKey: ["crawlerState"],
    queryFn: () => getCrawlerState(),
    refetchInterval: 3500,
  });

  const catalog = useQuery({
    queryKey: ["catalog"],
    queryFn: () => listCatalog(),
  });

  // Targeted Crawl Mutation
  const targetedCrawl = useMutation({
    mutationFn: (topic: string) =>
      triggerCrawlJob({ data: { triggerType: "SEARCH", customQuery: topic } }),
    onSuccess: () => {
      toast.success("Targeted Threat Hunt Dispatched", {
        description: `Autonomous crawler is hunting intelligence for '${targetedTopic}' and expanding citation graphs.`,
      });
      void qc.invalidateQueries({ queryKey: ["crawlerState"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
      setTargetedTopic("");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // Manual Ingest Mutation
  const manualIngest = useMutation({
    mutationFn: (input: { url?: string; pastedText?: string }) =>
      ingestUrl({ data: { url: input.url, pastedText: input.pastedText } }),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["reports"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
      void qc.invalidateQueries({ queryKey: ["catalog"] });
      if (res.duplicate) {
        toast.message("Already in the store", { description: res.title });
      } else {
        toast.success("Acquired & Ingested", {
          description: `${res.title} · quality ${Math.round(res.qualityScore * 100)}% · PDF generated`,
        });
      }
      setUrl("");
      setPasted("");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // Trigger Crawl Mutation
  const runCrawl = useMutation({
    mutationFn: (triggerType?: "MANUAL" | "SCHEDULED" | "SEARCH") =>
      triggerCrawlJob({ data: { triggerType: triggerType ?? "MANUAL" } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["crawlerState"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
      toast.success("Autonomous Discovery Engine Dispatched", {
        description: "Frontier queue initiated: exploring seeds, citations, repositories, and new CTI domains...",
      });
    },
    onError: (e: Error) => toast.error(`Crawler failed to start: ${e.message}`),
  });

  // Cancel Crawl Mutation
  const cancelCrawl = useMutation({
    mutationFn: (jobId: string) => cancelCrawlJob({ data: { jobId } }),
    onSuccess: () => {
      void qc.invalidateQueries();
      toast.info("Crawl job cancelled");
    },
  });

  // Ingest Discovered Item Mutation
  const ingestQueueItem = useMutation({
    mutationFn: (discoveredId: string) => ingestDiscoveredUrl({ data: { discoveredId } }),
    onSuccess: (res) => {
      void qc.invalidateQueries();
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
      toast.success("Resource Ingested", {
        description: `${res.title} · PDF document available in library`,
      });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // Update Config Mutation
  const saveConfig = useMutation({
    mutationFn: (cfg: Parameters<typeof updateCrawlerConfig>[0]["data"]) =>
      updateCrawlerConfig({ data: cfg }),
    onSuccess: () => {
      void qc.invalidateQueries();
      toast.success("Crawler configuration applied to runtime engine");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const exportStix = async () => {
    try {
      toast.info("Generating STIX 2.1 Threat Intel Bundle...");
      const bundle = await exportSTIXBundle();
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const dlUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = dlUrl;
      a.download = `cti_stix21_bundle_${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(dlUrl);
      toast.success("STIX 2.1 Bundle Downloaded successfully");
    } catch {
      toast.error("Failed to export STIX bundle");
    }
  };

  const state = crawlerState.data;
  const config = state?.config ?? DEFAULT_CRAWL_CONFIG;
  const activeJob = state?.activeJob;
  const jobs = state?.jobs ?? [];
  const discovered = state?.discovered ?? [];
  const items = state?.items ?? [];
  const discoveredSources = state?.discoveredSources ?? [];
  const graphEdges = state?.graphEdges ?? [];

  // Filtered Queue Items
  const filteredDiscovered = discovered.filter((item) => {
    if (queueFilter === "qualified" && item.status !== "qualified" && item.status !== "awaiting_approval") return false;
    if (queueFilter === "ingested" && item.status !== "ingested") return false;
    if (queueFilter === "rejected" && item.status !== "rejected") return false;
    if (queueSearch.trim()) {
      const q = queueSearch.toLowerCase();
      return (
        item.title.toLowerCase().includes(q) ||
        item.url.toLowerCase().includes(q) ||
        item.publisher.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <AppShell>
      {/* Header Section */}
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">
              Autonomous Intelligence Engine
            </p>
            <Badge tone="sage" className="gap-1 font-mono text-[10px]">
              <Network className="size-2.5" /> Discovery Graph Active
            </Badge>
            <Badge tone="accent" className="gap-1 font-mono text-[10px]">
              <Globe className="size-2.5" /> Source Expansion ON
            </Badge>
          </div>
          <h1 className="mt-1 text-3xl font-medium tracking-tight">Threat Discovery & Ingestion Engine</h1>
          <p className="mt-1 text-xs text-muted">
            Frontier crawler expanding from seeds to discover new sources, citation graphs, research papers, and pristine PDF evidence.
          </p>
        </div>

        {/* Global Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={exportStix}
            className="gap-1.5 text-xs"
          >
            <Download className="size-3.5" />
            <span>Export STIX 2.1</span>
          </Button>

          {activeJob ? (
            <Button
              variant="danger"
              size="sm"
              onClick={() => cancelCrawl.mutate(activeJob.id)}
              disabled={cancelCrawl.isPending}
              className="gap-1.5 text-xs"
            >
              <XCircle className="size-3.5" />
              <span>Cancel Scan ({activeJob.id.slice(0, 8)})</span>
            </Button>
          ) : (
            <Button
              size="sm"
              onClick={() => runCrawl.mutate("MANUAL")}
              disabled={runCrawl.isPending}
              className="gap-1.5 text-xs"
            >
              <Play className="size-3.5" />
              <span>Launch Discovery Crawl</span>
            </Button>
          )}
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="mt-6 flex flex-wrap gap-1 border-b border-border pb-px">
        {VIEWS.map((v) => {
          const Icon = v.icon;
          const isActive = activeView === v.id;
          return (
            <button
              key={v.id}
              type="button"
              onClick={() => setActiveView(v.id)}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-xs font-medium transition-colors",
                isActive
                  ? "border-b-2 border-accent text-fg font-semibold"
                  : "text-muted hover:text-fg",
              )}
            >
              <Icon className="size-3.5" />
              <span>{v.label}</span>
              {v.id === "queue" && discovered.length > 0 && (
                <span className="rounded-full bg-bg-subtle px-1.5 py-0.2 font-mono text-[10px] text-muted">
                  {discovered.length}
                </span>
              )}
              {v.id === "graph" && discoveredSources.length > 0 && (
                <span className="rounded-full bg-accent/20 text-accent px-1.5 py-0.2 font-mono text-[10px]">
                  +{discoveredSources.length}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* VIEW 1: AUTONOMOUS CRAWLER CONSOLE */}
      {activeView === "crawler" && (
        <div className="space-y-6">
          {/* Active Job Alert / Live Status */}
          {activeJob && (
            <div className="flex flex-col items-start justify-between gap-4 rounded-xl border border-accent/40 bg-accent/5 p-4 sm:flex-row sm:items-center">
              <div className="flex items-center gap-3">
                <RefreshCw className="size-5 animate-spin text-accent" />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-fg">
                      Autonomous Intelligence Discovery Active
                    </span>
                    <Badge tone="accent">{activeJob.triggerType}</Badge>
                    <Badge tone="sage">Stage: {activeJob.currentStage || "evaluated"}</Badge>
                  </div>
                  <p className="mt-0.5 text-xs text-muted truncate max-w-xl">
                    Current Frontier URL: <span className="font-mono text-fg">{activeJob.currentUrl || "Extracting citations & outlinks..."}</span>
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-4 font-mono text-xs text-muted">
                <span>Discovered: <strong className="text-fg">{activeJob.discoveredCount}</strong></span>
                <span>Evaluated: <strong className="text-fg">{activeJob.evaluatedCount || 0}</strong></span>
                <span>Qualified: <strong className="text-sage">{activeJob.qualifiedCount}</strong></span>
                <span>Ingested: <strong className="text-accent">{activeJob.ingestedCount}</strong></span>
                <span>Duplicates: <strong className="text-warn">{activeJob.duplicateCount}</strong></span>
              </div>
            </div>
          )}

          {/* Targeted Threat Hunt Bar */}
          <div className="rounded-xl border border-border bg-bg-elevated p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Crosshair className="size-4 text-accent" />
                  <h2 className="text-sm font-medium">Targeted Threat & Adversary Emulation Hunt</h2>
                </div>
                <p className="mt-0.5 text-xs text-muted">
                  Input an adversary group, CVE, or malware family to initiate an outlink-expanding intelligence crawl.
                </p>
              </div>

              <div className="flex items-center gap-2 w-full sm:w-auto">
                <Input
                  value={targetedTopic}
                  onChange={(e) => setTargetedTopic(e.target.value)}
                  placeholder="e.g. Akira Ransomware, Volt Typhoon, MOVEit CVE-2023-34362..."
                  className="w-full sm:w-80 text-xs"
                />
                <Button
                  size="sm"
                  onClick={() => targetedCrawl.mutate(targetedTopic)}
                  disabled={targetedCrawl.isPending || !targetedTopic.trim()}
                  className="shrink-0 text-xs"
                >
                  Hunt Intel
                </Button>
              </div>
            </div>
          </div>

          {/* Engine Architecture & Crawl Scheduling Cards */}
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="flex flex-col justify-between rounded-xl border border-border bg-bg-elevated p-5 lg:col-span-2">
              <div>
                <h2 className="text-base font-medium">Iterative Discovery Pipeline</h2>
                <p className="mt-1 text-xs text-muted">
                  How the autonomous engine expands outward from seed sources to discover unmapped CTI resources.
                </p>
              </div>

              <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-5">
                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">01 · SEED SOURCES</div>
                  <div className="mt-1 text-sm font-medium">Trusted Entry</div>
                  <p className="mt-1 text-xs text-muted">
                    Continuous RSS feeds & permalinks from verified CTI partners.
                  </p>
                </div>

                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">02 · GRAPH EXPANSION</div>
                  <div className="mt-1 text-sm font-medium">Outlink Citations</div>
                  <p className="mt-1 text-xs text-muted">
                    Follows external references, technical whitepapers, and GitHub repos.
                  </p>
                </div>

                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">03 · SOURCE DISCOVERY</div>
                  <div className="mt-1 text-sm font-medium">New CTI Domains</div>
                  <p className="mt-1 text-xs text-muted">
                    Evaluates domain trust scores and registers newly discovered sources.
                  </p>
                </div>

                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">04 · QUALIFICATION</div>
                  <div className="mt-1 text-sm font-medium">Deep TTP Scoring</div>
                  <p className="mt-1 text-xs text-muted">
                    Verifies attack chains, IOC density, and MITRE ATT&CK techniques.
                  </p>
                </div>

                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">05 · PRESERVATION</div>
                  <div className="mt-1 text-sm font-medium">PDF & Knowledge Base</div>
                  <p className="mt-1 text-xs text-muted">
                    Pristine vector document generation and MongoDB Atlas persistence.
                  </p>
                </div>
              </div>

              {/* Source Performance Stats */}
              <div className="mt-8 border-t border-border pt-5">
                <h3 className="text-sm font-medium">Source Ingestion Performance</h3>
                <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {state?.sourceStats?.map((s) => (
                    <div key={s.sourceName} className="rounded-lg border border-border bg-bg-subtle px-3 py-2">
                      <div className="truncate text-xs font-medium">{s.sourceName}</div>
                      <div className="mt-1 flex items-baseline gap-1.5 font-mono text-xs text-muted">
                        <span className="text-fg font-medium">{s.ingested}</span>
                        <span>ingested</span>
                        <span className="text-subtle">({s.found} found)</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Quick Run & Scheduler Controls */}
            <div className="flex flex-col justify-between rounded-xl border border-border bg-bg-elevated p-5">
              <div>
                <h2 className="text-base font-medium">Engine Control Plane</h2>
                <p className="mt-1 text-xs text-muted">Live parameters applied to the frontier crawler.</p>

                <dl className="mt-5 space-y-3 font-mono text-xs">
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Max Resources / Job</dt>
                    <dd className="text-accent font-semibold">{config.maxResourcesPerJob || config.maxResourcesPerRun || 60} URLs</dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Per-Domain Cap</dt>
                    <dd className="text-fg">{config.maxResourcesPerDomain ?? 8} per host</dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Max Traversal Depth</dt>
                    <dd className="text-fg">Depth {config.maxDepth ?? 3}</dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">External Domain Expansion</dt>
                    <dd className={config.allowExternalDomains !== false ? "text-sage" : "text-muted"}>
                      {config.allowExternalDomains !== false ? "ENABLED" : "DISABLED"}
                    </dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Deduplication Method</dt>
                    <dd className="text-fg uppercase">{config.dedupMethod || "smart_hybrid"}</dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Auto-Ingestion</dt>
                    <dd className={config.autoIngest ? "text-sage" : "text-warn"}>
                      {config.autoIngest ? "AUTO-PERSIST" : "APPROVAL QUEUE"}
                    </dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Strictness Mode</dt>
                    <dd className="text-fg capitalize">{config.strictnessMode || "balanced"}</dd>
                  </div>
                  <div className="flex justify-between pb-2">
                    <dt className="text-subtle">Last Discovery Run</dt>
                    <dd className="text-fg">{formatDateTime(config.lastRunAt, "Never")}</dd>
                  </div>
                </dl>
              </div>

              <div className="mt-6 flex flex-col gap-2">
                <Button
                  onClick={() => runCrawl.mutate("MANUAL")}
                  disabled={runCrawl.isPending || !!activeJob}
                  className="w-full gap-2"
                >
                  <Play className="size-4" />
                  <span>Execute Discovery Scan</span>
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => setActiveView("settings")}
                  className="w-full text-xs"
                >
                  Configure Granular Controls
                </Button>
              </div>
            </div>
          </div>

          {/* Recent Crawl Job Runs History */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-base font-medium">Recent Crawl Jobs History</h2>
                <p className="text-xs text-muted">Complete audit trail of automated and targeted graph discovery jobs.</p>
              </div>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setActiveView("audit")}
                className="text-xs"
              >
                Detailed Pipeline Audit
              </Button>
            </div>

            {jobs.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted">No crawl jobs executed yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[850px] text-left text-xs">
                  <thead className="border-b border-border font-mono text-[10px] uppercase text-subtle">
                    <tr>
                      <th className="py-2">Job ID</th>
                      <th className="py-2">Trigger</th>
                      <th className="py-2">Status</th>
                      <th className="py-2">Discovered</th>
                      <th className="py-2">Evaluated</th>
                      <th className="py-2">Qualified</th>
                      <th className="py-2">Ingested</th>
                      <th className="py-2">New Sources</th>
                      <th className="py-2">Duplicates</th>
                      <th className="py-2">Rejected</th>
                      <th className="py-2">Completed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {jobs.map((j) => (
                      <tr key={j.id} className="hover:bg-bg-subtle/40">
                        <td className="py-2.5 font-mono text-fg">{j.id.slice(0, 12)}</td>
                        <td className="py-2.5 font-mono text-subtle">{j.triggerType}</td>
                        <td className="py-2.5">
                          <Badge
                            tone={
                              j.status === "completed"
                                ? "sage"
                                : j.status === "running"
                                  ? "accent"
                                  : "danger"
                            }
                          >
                            {j.status}
                          </Badge>
                        </td>
                        <td className="py-2.5 font-mono">{j.discoveredCount}</td>
                        <td className="py-2.5 font-mono text-muted">{j.evaluatedCount || j.discoveredCount}</td>
                        <td className="py-2.5 font-mono text-sage">{j.qualifiedCount}</td>
                        <td className="py-2.5 font-mono font-medium text-accent">{j.ingestedCount}</td>
                        <td className="py-2.5 font-mono text-sage">{j.newSourcesCount ? `+${j.newSourcesCount}` : "0"}</td>
                        <td className="py-2.5 font-mono text-warn">{j.duplicateCount}</td>
                        <td className="py-2.5 font-mono text-muted">{j.rejectedCount}</td>
                        <td className="py-2.5 font-mono text-subtle">{formatDateTime(j.completedAt, "Running...")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* VIEW 2: DISCOVERY QUEUE */}
      {activeView === "queue" && (
        <div className="space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-medium">Candidate Discovery Queue</h2>
              <p className="text-xs text-muted">
                Candidate resources discovered across seeds, citations, and outlink graphs.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Input
                value={queueSearch}
                onChange={(e) => setQueueSearch(e.target.value)}
                placeholder="Search candidate queue…"
                className="w-48 text-xs sm:w-64"
              />
              <div className="flex rounded-lg border border-border bg-bg-elevated p-0.5">
                {(["all", "qualified", "ingested", "rejected"] as const).map((filter) => (
                  <button
                    key={filter}
                    type="button"
                    onClick={() => setQueueFilter(filter)}
                    className={cn(
                      "rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors",
                      queueFilter === filter ? "bg-fg text-bg" : "text-muted hover:text-fg",
                    )}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {filteredDiscovered.length === 0 ? (
            <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
              No discovered resources in this category. Run an autonomous crawl job to populate.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border bg-bg-elevated">
              <table className="w-full min-w-[800px] text-left text-xs">
                <thead className="border-b border-border bg-bg-subtle font-mono text-[10px] uppercase text-subtle">
                  <tr>
                    <th className="p-3">Status</th>
                    <th className="p-3">Resource Kind</th>
                    <th className="p-3">Title / Canonical URL</th>
                    <th className="p-3">Source Domain</th>
                    <th className="p-3">Method</th>
                    <th className="p-3">Score</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredDiscovered.map((res) => (
                    <tr key={res.canonicalUrl} className="hover:bg-bg-subtle/30">
                      <td className="p-3">
                        <Badge
                          tone={
                            res.status === "ingested"
                              ? "sage"
                              : res.status === "qualified" || res.status === "awaiting_approval"
                                ? "accent"
                                : "neutral"
                          }
                        >
                          {res.status.replace(/_/g, " ")}
                        </Badge>
                      </td>
                      <td className="p-3 font-mono text-[11px] text-muted">
                        {res.resourceKind || res.classification}
                      </td>
                      <td className="max-w-[280px] p-3">
                        <div className="truncate font-medium text-fg">{res.title}</div>
                        <a
                          href={res.canonicalUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="truncate font-mono text-[10px] text-subtle hover:text-accent flex items-center gap-1"
                        >
                          <span className="truncate">{res.canonicalUrl}</span>
                          <ExternalLink className="size-2.5 shrink-0" />
                        </a>
                      </td>
                      <td className="p-3 text-muted">{res.sourceDomain}</td>
                      <td className="p-3 font-mono text-[10px] text-subtle">
                        {res.discoveryMethod.replace(/_/g, " ")}
                      </td>
                      <td className="p-3 font-mono">
                        {res.qualityScore !== null ? `${Math.round(res.qualityScore * 100)}%` : "—"}
                      </td>
                      <td className="p-3 text-right">
                        {res.status === "ingested" ? (
                          <Link
                            to="/library/$reportId"
                            params={{ reportId: res.reportId || "" }}
                            className="inline-flex items-center gap-1 text-accent hover:underline text-xs"
                          >
                            View in Library
                          </Link>
                        ) : (
                          <Button
                            size="sm"
                            variant="secondary"
                            className="h-7 text-xs"
                            disabled={ingestQueueItem.isPending}
                            onClick={() => ingestQueueItem.mutate(res.id)}
                          >
                            Acquire & Ingest
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* VIEW 3: DISCOVERY GRAPH & EXPANDED SOURCES */}
      {activeView === "graph" && (
        <div className="space-y-6">
          <div>
            <h2 className="text-lg font-medium">Discovered Sources & Citation Graph</h2>
            <p className="text-xs text-muted">
              Domains and technical references discovered autonomously through citation extraction.
            </p>
          </div>

          {/* Discovered Sources Table */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="text-sm font-medium">Autonomously Discovered CTI Sources</h3>
                <p className="text-xs text-muted">External domains identified via hyperlinks, citations, and research papers.</p>
              </div>
              <Badge tone="accent">Total Discovered: {discoveredSources.length}</Badge>
            </div>

            {discoveredSources.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted">
                No external sources discovered yet. Run a discovery scan with depth $\ge 2$ to explore citations.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[700px] text-left text-xs">
                  <thead className="border-b border-border font-mono text-[10px] uppercase text-subtle">
                    <tr>
                      <th className="py-2">Domain</th>
                      <th className="py-2">Status</th>
                      <th className="py-2">Trust Score</th>
                      <th className="py-2">Resources</th>
                      <th className="py-2">Referrer / Parent</th>
                      <th className="py-2">Discovered Date</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {discoveredSources.map((src) => (
                      <tr key={src.domain} className="hover:bg-bg-subtle/40">
                        <td className="py-2.5 font-mono text-fg font-medium">
                          <a href={src.homepageUrl} target="_blank" rel="noreferrer" className="hover:text-accent flex items-center gap-1">
                            {src.domain}
                            <ExternalLink className="size-2.5 text-subtle" />
                          </a>
                        </td>
                        <td className="py-2.5">
                          <Badge tone={src.status === "approved" ? "sage" : "neutral"}>
                            {src.status}
                          </Badge>
                        </td>
                        <td className="py-2.5 font-mono text-accent">
                          {Math.round(src.trustScore * 100)}%
                        </td>
                        <td className="py-2.5 font-mono">{src.resourceCount}</td>
                        <td className="py-2.5 text-muted font-mono text-[11px]">{src.parentSource || "Seed"}</td>
                        <td className="py-2.5 font-mono text-subtle text-[10px]">{formatDateTime(src.firstDiscoveredAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Citation Graph Edges */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="text-sm font-medium">Recent Citation & Outlink Graph Edges</h3>
                <p className="text-xs text-muted">Relationship links established between documents, repositories, and PDFs.</p>
              </div>
              <Badge tone="neutral">Edges: {graphEdges.length}</Badge>
            </div>

            {graphEdges.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted">No graph edges recorded yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[750px] text-left text-xs">
                  <thead className="border-b border-border font-mono text-[10px] uppercase text-subtle">
                    <tr>
                      <th className="py-2">Source Origin</th>
                      <th className="py-2">Relationship</th>
                      <th className="py-2">Target Reference</th>
                      <th className="py-2">Label / Context</th>
                      <th className="py-2">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {graphEdges.slice(0, 30).map((edge) => (
                      <tr key={edge.id} className="hover:bg-bg-subtle/40">
                        <td className="max-w-[200px] py-2.5 truncate font-mono text-[11px] text-muted">
                          {edge.from}
                        </td>
                        <td className="py-2.5">
                          <Badge
                            tone={
                              edge.relationship === "DOWNLOADS_PDF"
                                ? "sage"
                                : edge.relationship === "REFERENCES_REPO"
                                  ? "accent"
                                  : "neutral"
                            }
                          >
                            {edge.relationship.replace(/_/g, " ")}
                          </Badge>
                        </td>
                        <td className="max-w-[260px] py-2.5 truncate font-mono text-[11px] text-fg">
                          <a href={edge.to} target="_blank" rel="noreferrer" className="hover:text-accent">
                            {edge.to}
                          </a>
                        </td>
                        <td className="max-w-[180px] py-2.5 truncate text-muted text-[11px]">
                          {edge.label}
                        </td>
                        <td className="py-2.5 font-mono text-[10px] text-subtle">
                          {formatDateTime(edge.createdAt)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* VIEW 4: PIPELINE AUDIT LOG */}
      {activeView === "audit" && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-medium">Pipeline Progression Audit Log</h2>
            <p className="text-xs text-muted">
              Complete visibility into every evaluated URL across the 7 pipeline stages.
            </p>
          </div>

          {items.length === 0 ? (
            <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
              No audit items recorded yet. Run a discovery scan to populate logs.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border bg-bg-elevated">
              <table className="w-full min-w-[850px] text-left text-xs">
                <thead className="border-b border-border bg-bg-subtle font-mono text-[10px] uppercase text-subtle">
                  <tr>
                    <th className="p-3">Decision</th>
                    <th className="p-3">Pipeline Stage</th>
                    <th className="p-3">Title / Canonical URL</th>
                    <th className="p-3">Depth</th>
                    <th className="p-3">Publisher</th>
                    <th className="p-3">Diagnostic Reason</th>
                    <th className="p-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {items.map((itm) => (
                    <tr key={itm.id} className="hover:bg-bg-subtle/30">
                      <td className="p-3">
                        <Badge
                          tone={
                            itm.decision === "INGESTED"
                              ? "sage"
                              : itm.decision === "AWAITING_APPROVAL"
                                ? "accent"
                                : itm.decision === "DUPLICATE"
                                  ? "warn"
                                  : itm.decision === "REJECTED"
                                    ? "neutral"
                                    : "danger"
                          }
                        >
                          {itm.decision.replace(/_/g, " ")}
                        </Badge>
                      </td>
                      <td className="p-3 font-mono text-[11px]">
                        <span className="capitalize text-muted">{itm.stage || itm.decision.toLowerCase()}</span>
                      </td>
                      <td className="max-w-[240px] p-3">
                        <div className="truncate font-medium text-fg">{itm.title || itm.canonicalUrl}</div>
                        <div className="truncate font-mono text-[10px] text-subtle">{itm.canonicalUrl}</div>
                      </td>
                      <td className="p-3 font-mono text-muted">
                        Depth {itm.depth}
                      </td>
                      <td className="p-3 text-muted">{itm.publisher}</td>
                      <td className="max-w-[300px] p-3 text-muted">
                        <p className="line-clamp-2 text-[11px] leading-relaxed">{itm.reason}</p>
                      </td>
                      <td className="p-3 font-mono text-[10px] text-subtle">
                        {formatDateTime(itm.createdAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* VIEW 5: CRAWL SETTINGS - GRANULAR ENGINE CONTROLS */}
      {activeView === "settings" && (
        <div className="max-w-4xl space-y-6">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-xl font-medium tracking-tight">Granular Autonomous Crawler Controls</h2>
              <p className="text-xs text-muted">
                Configure source expansion, crawl depth, domain caps, qualification thresholds, and PDF preservation.
              </p>
            </div>
            <div className="flex items-center gap-2 pt-2 sm:pt-0">
              <span className="font-mono text-[11px] text-muted">
                Persistence Backbone: <strong className="text-accent">MongoDB Atlas (threat-intel-DB)</strong>
              </span>
            </div>
          </div>

          {/* SECTION 1: TARGET INTELLIGENCE RESOURCE TYPES */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="text-sm font-medium">Target Intelligence Resource Types</h3>
                <p className="text-xs text-muted">Select specific intelligence resources the engine should identify, decompose, and preserve.</p>
              </div>
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
                const isChecked = (config.targetResourceTypes || []).includes(item.id as any);
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
                        const current = config.targetResourceTypes || [];
                        const updated = e.target.checked
                          ? [...current, item.id]
                          : current.filter((k: string) => k !== item.id);
                        saveConfig.mutate({ targetResourceTypes: updated });
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

          {/* SECTION 2: DISCOVERY CHANNELS & SPIDERING */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
            <h3 className="text-sm font-medium border-b border-border pb-3">Discovery Channels & Spidering Protocols</h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg-subtle/20">
                <div>
                  <label className="text-xs font-medium block">Continuous RSS & Atom Feeds</label>
                  <span className="text-[11px] text-muted">Real-time CTI feed monitoring</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.rssDiscovery !== false}
                  onChange={(e) => saveConfig.mutate({ rssDiscovery: e.target.checked })}
                  className="size-4 accent-accent"
                />
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg-subtle/20">
                <div>
                  <label className="text-xs font-medium block">Homepage Permalink Scraping</label>
                  <span className="text-[11px] text-muted">Extract links from source homepages</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.htmlDiscovery !== false}
                  onChange={(e) => saveConfig.mutate({ htmlDiscovery: e.target.checked })}
                  className="size-4 accent-accent"
                />
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg-subtle/20">
                <div>
                  <label className="text-xs font-medium block">Search-Driven Discovery Vectors</label>
                  <span className="text-[11px] text-muted">Generate queries from keywords</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.searchDiscovery !== false}
                  onChange={(e) => saveConfig.mutate({ searchDiscovery: e.target.checked })}
                  className="size-4 accent-accent"
                />
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg-subtle/20">
                <div>
                  <label className="text-xs font-medium block">Recursive Outlink Deep Spidering</label>
                  <span className="text-[11px] text-muted">Follow links referenced inside reports</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.recursiveDiscovery !== false}
                  onChange={(e) => saveConfig.mutate({ recursiveDiscovery: e.target.checked })}
                  className="size-4 accent-accent"
                />
              </div>
            </div>
          </div>

          {/* SECTION 3: QUALIFICATION HEURISTICS & REJECTION RULES */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
            <h3 className="text-sm font-medium border-b border-border pb-3">Heuristic Qualification & Quality Rejection Rules</h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <label className="font-medium">Strictness Mode</label>
                  <span className="font-mono text-accent capitalize">{config.strictnessMode || "balanced"}</span>
                </div>
                <select
                  value={config.strictnessMode || "balanced"}
                  onChange={(e) => saveConfig.mutate({ strictnessMode: e.target.value as any })}
                  className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                >
                  <option value="permissive">Permissive (Include concise advisories)</option>
                  <option value="balanced">Balanced (Recommended standard)</option>
                  <option value="strict">Strict (High TTP threshold only)</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <label className="font-medium">Min Quality Score</label>
                  <span className="font-mono text-accent">{Math.round((config.minQualityScore ?? 0.35) * 100)}%</span>
                </div>
                <input
                  type="range"
                  min="0.15"
                  max="0.8"
                  step="0.05"
                  value={config.minQualityScore ?? 0.35}
                  onChange={(e) => saveConfig.mutate({ minQualityScore: parseFloat(e.target.value) })}
                  className="w-full accent-accent"
                />
              </div>

              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <label className="font-medium">Min Word Count</label>
                  <span className="font-mono text-accent">{config.minWordCount ?? 100} words</span>
                </div>
                <input
                  type="range"
                  min="50"
                  max="500"
                  step="10"
                  value={config.minWordCount ?? 100}
                  onChange={(e) => saveConfig.mutate({ minWordCount: parseInt(e.target.value, 10) })}
                  className="w-full accent-accent"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-border">
              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.requireIocs ?? false}
                  onChange={(e) => saveConfig.mutate({ requireIocs: e.target.checked })}
                  className="size-4 accent-accent"
                />
                <span>Require verified IOCs</span>
              </label>

              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.requireAttck ?? false}
                  onChange={(e) => saveConfig.mutate({ requireAttck: e.target.checked })}
                  className="size-4 accent-accent"
                />
                <span>Require MITRE ATT&CK IDs</span>
              </label>

              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.rejectMarketingNoise ?? true}
                  onChange={(e) => saveConfig.mutate({ rejectMarketingNoise: e.target.checked })}
                  className="size-4 accent-accent"
                />
                <span>Reject Marketing & PR noise</span>
              </label>
            </div>

            <div className="pt-2 border-t border-border">
              <label className="text-xs font-medium block">Marketing / Noise Filter Blacklist</label>
              <p className="text-[11px] text-muted">Pages containing clusters of these terms are filtered as noise.</p>
              <Input
                defaultValue={config.noiseKeywords || "webinar, discount, pricing, subscribe, careers, terms of service, privacy policy"}
                onBlur={(e) => saveConfig.mutate({ noiseKeywords: e.target.value })}
                className="mt-1.5 text-xs font-mono"
              />
            </div>
          </div>

          {/* SECTION 4: LIMITS, DEDUPLICATION & EXPANSION */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
            <h3 className="text-sm font-medium border-b border-border pb-3">Execution Limits, Deduplication & Frontier Expansion</h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <label className="font-medium">Max Resources per Job</label>
                  <span className="font-mono text-accent">{config.maxResourcesPerJob || config.maxResourcesPerRun || 60} URLs</span>
                </div>
                <input
                  type="range"
                  min="20"
                  max="300"
                  step="10"
                  value={config.maxResourcesPerJob || config.maxResourcesPerRun || 60}
                  onChange={(e) => {
                    const val = parseInt(e.target.value, 10);
                    saveConfig.mutate({ maxResourcesPerJob: val, maxResourcesPerRun: val });
                  }}
                  className="w-full accent-accent"
                />
              </div>

              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <label className="font-medium">Per-Domain Cap</label>
                  <span className="font-mono text-accent">{config.maxResourcesPerDomain ?? 8} per host</span>
                </div>
                <input
                  type="range"
                  min="2"
                  max="25"
                  step="1"
                  value={config.maxResourcesPerDomain ?? 8}
                  onChange={(e) => saveConfig.mutate({ maxResourcesPerDomain: parseInt(e.target.value, 10) })}
                  className="w-full accent-accent"
                />
              </div>

              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <label className="font-medium">Max Traversal Depth</label>
                  <span className="font-mono text-accent">Depth {config.maxDepth ?? 3}</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="5"
                  step="1"
                  value={config.maxDepth ?? 3}
                  onChange={(e) => saveConfig.mutate({ maxDepth: parseInt(e.target.value, 10) })}
                  className="w-full accent-accent"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-border">
              <div className="space-y-1.5">
                <label className="text-xs font-medium block">Deduplication Strategy</label>
                <select
                  value={config.dedupMethod || "smart_hybrid"}
                  onChange={(e) => saveConfig.mutate({ dedupMethod: e.target.value as any })}
                  className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                >
                  <option value="smart_hybrid">Smart Hybrid (Normalized URL + Content Hash)</option>
                  <option value="both">Both (Strict URL & Hash)</option>
                  <option value="canonical_url">Canonical URL Only</option>
                  <option value="content_hash">Content Hash Only</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium block">Discovery Breadth</label>
                <select
                  value={config.discoveryBreadth || "balanced"}
                  onChange={(e) => saveConfig.mutate({ discoveryBreadth: e.target.value as any })}
                  className="w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
                >
                  <option value="focused">Focused (Seeds + 1-Hop Citations)</option>
                  <option value="balanced">Balanced (2-Hop Graph Expansion)</option>
                  <option value="wide">Wide (Aggressive Multi-Hop Discovery)</option>
                </select>
              </div>

              <div className="flex items-center pt-4">
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.allowExternalDomains !== false}
                    onChange={(e) => saveConfig.mutate({ allowExternalDomains: e.target.checked })}
                    className="size-4 accent-accent"
                  />
                  <div>
                    <span className="font-medium block">Allow External Domains</span>
                    <span className="text-[10px] text-muted block">Expand outside seed list to discover new sources</span>
                  </div>
                </label>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-border">
              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.autoIngest ?? true}
                  onChange={(e) => saveConfig.mutate({ autoIngest: e.target.checked })}
                  className="size-4 accent-accent"
                />
                <div>
                  <span className="font-medium block">Auto-Ingest Qualified</span>
                  <span className="text-[10px] text-muted block">Direct save vs manual review queue</span>
                </div>
              </label>

              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.autoAnalyze ?? true}
                  onChange={(e) => saveConfig.mutate({ autoAnalyze: e.target.checked })}
                  className="size-4 accent-accent"
                />
                <div>
                  <span className="font-medium block">Auto-ATT&CK & TTP Extraction</span>
                  <span className="text-[10px] text-muted block">Reconstruct attack progression</span>
                </div>
              </label>

              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.generatePdf !== false}
                  onChange={(e) => saveConfig.mutate({ generatePdf: e.target.checked })}
                  className="size-4 accent-accent"
                />
                <div>
                  <span className="font-medium block">High-Fidelity PDF Generation</span>
                  <span className="text-[10px] text-muted block">Preserve original look & print PDF</span>
                </div>
              </label>
            </div>
          </div>

          {/* SECTION 5: DISCOVERY KEYWORDS */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-3">
            <h3 className="text-sm font-medium border-b border-border pb-3">Targeted Threat Keywords & Query Patterns</h3>
            <p className="text-xs text-muted">Comma-separated keywords and search terms used to hunt candidate intelligence.</p>
            <Textarea
              rows={3}
              defaultValue={config.keywords}
              onBlur={(e) => saveConfig.mutate({ keywords: e.target.value })}
              className="mt-1 text-xs font-mono"
            />
          </div>
        </div>
      )}

      {/* VIEW 6: MANUAL INGEST */}
      {activeView === "manual" && (
        <div className="max-w-2xl space-y-6">
          <div>
            <h2 className="text-lg font-medium">Manual Report Acquisition</h2>
            <p className="text-xs text-muted">Directly acquire and parse permalinks or paste raw incident telemetry.</p>
          </div>

          <div className="space-y-4 rounded-xl border border-border bg-bg-elevated p-5">
            <div>
              <label className="text-xs font-medium">Report Permalink URL</label>
              <div className="mt-1.5 flex gap-2">
                <Input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://..."
                  className="text-xs"
                />
                <Button
                  size="sm"
                  disabled={manualIngest.isPending || !url.trim()}
                  onClick={() => manualIngest.mutate({ url })}
                  className="shrink-0 text-xs"
                >
                  Acquire & PDF
                </Button>
              </div>
            </div>

            <div className="relative border-t border-border pt-4">
              <div className="absolute inset-x-0 -top-2 flex justify-center">
                <span className="bg-bg-elevated px-2 font-mono text-[10px] uppercase text-subtle">OR</span>
              </div>
              <label className="text-xs font-medium">Paste Technical CTI Text / Advisory</label>
              <Textarea
                rows={6}
                value={pasted}
                onChange={(e) => setPasted(e.target.value)}
                placeholder="Paste report text, malware analysis, or incident notes…"
                className="mt-1.5 text-xs font-mono"
              />
              <div className="mt-3 flex justify-end">
                <Button
                  size="sm"
                  disabled={manualIngest.isPending || !pasted.trim()}
                  onClick={() => manualIngest.mutate({ pastedText: pasted })}
                  className="text-xs"
                >
                  Ingest Pasted Text
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 7: CURATED CATALOG */}
      {activeView === "catalog" && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-medium">Curated Golden CTI Reports Catalog</h2>
            <p className="text-xs text-muted">
              Pre-validated high-signal intrusion reports from DFIR, Mandiant, Unit 42, and CISA.
            </p>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            {catalog.data?.map((c) => (
              <div
                key={c.url}
                className="flex flex-col justify-between rounded-xl border border-border bg-bg-elevated p-5"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <Badge tone="neutral">{c.sourceName}</Badge>
                    {c.alreadyIngested ? (
                      <Badge tone="sage">Ingested & PDF Ready</Badge>
                    ) : (
                      <Badge tone="accent">Ready to Acquire</Badge>
                    )}
                  </div>
                  <h3 className="mt-3 text-base font-medium">{c.title}</h3>
                  <p className="mt-2 text-xs text-muted leading-relaxed">{c.why}</p>
                  <a
                    href={c.url}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-3 flex items-center gap-1 font-mono text-[11px] text-subtle hover:text-fg"
                  >
                    <span className="truncate">{c.url}</span>
                    <ExternalLink className="size-3 shrink-0" />
                  </a>
                </div>

                <div className="mt-4 border-t border-border pt-3">
                  <Button
                    size="sm"
                    variant={c.alreadyIngested ? "secondary" : "default"}
                    disabled={manualIngest.isPending || c.alreadyIngested}
                    onClick={() => manualIngest.mutate({ url: c.url })}
                    className="w-full text-xs"
                  >
                    {c.alreadyIngested ? "Stored in Knowledge Base" : "One-Click Ingest & PDF"}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </AppShell>
  );
}
