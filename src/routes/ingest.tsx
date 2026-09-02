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
  Globe,
  Layers,
  ListFilter,
  Play,
  RefreshCw,
  Rss,
  Search,
  Settings,
  Shield,
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

export const Route = createFileRoute("/ingest")({ component: IngestPage });

const VIEWS = [
  { id: "crawler", label: "Autonomous Crawler", icon: Bot },
  { id: "queue", label: "Discovery Queue", icon: Compass },
  { id: "manual", label: "Manual Ingest", icon: Upload },
  { id: "catalog", label: "Curated Catalog", icon: Database },
  { id: "audit", label: "Crawl Audit Log", icon: Activity },
  { id: "settings", label: "Crawl Settings", icon: Settings },
] as const;

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
    refetchInterval: 4000,
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
        description: `Autonomous crawler is hunting intelligence for '${targetedTopic}' and generating PDF evidence.`,
      });
      void qc.invalidateQueries({ queryKey: ["crawlerState"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
      setTargetedTopic("");
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to run hunt");
    },
  });

  // Manual Ingest Mutation
  const manualIngest = useMutation({
    mutationFn: (input: { url: string; pasted?: string }) => ingestUrl({ data: input }),
    onSuccess: (res) => {
      void qc.invalidateQueries();
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
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
      toast.success("Autonomous Crawler Triggered", {
        description: "Scanning trusted sources, continuous RSS feeds & search vectors...",
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
      toast.success("Crawler schedule and discovery settings saved");
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
  const config = state?.config;
  const activeJob = state?.activeJob;
  const jobs = state?.jobs ?? [];
  const discovered = state?.discovered ?? [];
  const items = state?.items ?? [];

  // Filtered Queue Items
  const filteredDiscovered = discovered.filter((item) => {
    if (queueFilter === "qualified" && item.status !== "qualified") return false;
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
              <Rss className="size-2.5" /> Feeds Active
            </Badge>
            <Badge tone="accent" className="gap-1 font-mono text-[10px]">
              <FileText className="size-2.5" /> PDF Extraction Ready
            </Badge>
          </div>
          <h1 className="mt-1 text-3xl font-medium tracking-tight">Threat Ingestion Console</h1>
          <p className="mt-1 text-xs text-muted">
            Continuous threat harvesting, permalink discrimination, attack-chain reconstruction, and high-fidelity PDF extraction.
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
              <span>Launch Crawl Job</span>
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
                  ? "border-b-2 border-accent text-fg"
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
                      Autonomous Threat Harvest Active
                    </span>
                    <Badge tone="accent">{activeJob.triggerType}</Badge>
                  </div>
                  <p className="mt-0.5 text-xs text-muted">
                    Inspecting sources, parsing RSS feeds, and qualifying threat reports...
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="font-mono text-xs text-subtle">
                  Started: {formatDateTime(activeJob.startedAt)}
                </div>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => cancelCrawl.mutate(activeJob.id)}
                  disabled={cancelCrawl.isPending}
                >
                  Stop Job
                </Button>
              </div>
            </div>
          )}

          {/* TARGETED THREAT ACTOR & CVE HUNTER BAR */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Crosshair className="size-4 text-accent" />
                  <h2 className="text-base font-medium">Targeted Threat Actor & CVE Deep Hunter</h2>
                </div>
                <p className="mt-0.5 text-xs text-muted">
                  Direct the autonomous engine to execute search vectors for a specific adversary, malware family, or CVE exploit.
                </p>
              </div>
              <Badge tone="sage" className="self-start sm:self-auto text-xs">
                Auto-ATT&CK & PDF Ready
              </Badge>
            </div>

            <div className="mt-4 flex flex-col gap-2 sm:flex-row">
              <Input
                value={targetedTopic}
                onChange={(e) => setTargetedTopic(e.target.value)}
                placeholder="e.g. Akira Ransomware, Volt Typhoon, CVE-2024-3400, AdaptixC2, Scattered Spider Okta..."
                className="flex-1 text-xs"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && targetedTopic.trim()) {
                    targetedCrawl.mutate(targetedTopic.trim());
                  }
                }}
              />
              <Button
                onClick={() => targetedCrawl.mutate(targetedTopic.trim())}
                disabled={targetedCrawl.isPending || !targetedTopic.trim() || !!activeJob}
                className="gap-1.5 text-xs whitespace-nowrap"
              >
                <Zap className="size-3.5" />
                <span>Deep Hunt & Ingest</span>
              </Button>
            </div>
          </div>

          {/* High-Level Crawl Metrics */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="rounded-xl border border-border bg-bg-elevated p-4">
              <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Discovered URLs</div>
              <div className="mt-1 text-2xl font-medium text-fg">
                {jobs.reduce((acc, j) => acc + j.discoveredCount, 0)}
              </div>
              <div className="mt-1 text-[11px] text-muted">From feeds & sources</div>
            </div>

            <div className="rounded-xl border border-border bg-bg-elevated p-4">
              <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Auto-Ingested</div>
              <div className="mt-1 text-2xl font-medium text-fg">
                {jobs.reduce((acc, j) => acc + j.ingestedCount, 0)}
              </div>
              <div className="mt-1 text-[11px] text-muted">With PDF representation</div>
            </div>

            <div className="rounded-xl border border-border bg-bg-elevated p-4">
              <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Deduplicated</div>
              <div className="mt-1 text-2xl font-medium text-warn">
                {jobs.reduce((acc, j) => acc + j.duplicateCount, 0)}
              </div>
              <div className="mt-1 text-[11px] text-muted">Skipped existing</div>
            </div>

            <div className="rounded-xl border border-border bg-bg-elevated p-4">
              <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Rejected / Noise</div>
              <div className="mt-1 text-2xl font-medium text-danger">
                {jobs.reduce((acc, j) => acc + j.rejectedCount, 0)}
              </div>
              <div className="mt-1 text-[11px] text-muted">Index / Marketing</div>
            </div>
          </div>

          {/* Autonomous Crawler Pipeline Diagram & Live Controls */}
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="rounded-xl border border-border bg-bg-elevated p-5 lg:col-span-2">
              <h2 className="text-base font-medium">Autonomous Intelligence Pipeline</h2>
              <p className="mt-1 text-xs text-muted">
                How the autonomous crawler searches, qualifies individual permalinks, reconstructs attack chains, and formats exact PDFs.
              </p>

              <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-5">
                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">01 · SOURCE DISCOVERY</div>
                  <div className="mt-1 text-sm font-medium">Feed & Search Crawl</div>
                  <p className="mt-1 text-xs text-muted">
                    Continuous RSS/Atom feeds, search queries, and source seeds.
                  </p>
                </div>

                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">02 · DISCRIMINATION</div>
                  <div className="mt-1 text-sm font-medium">Permalinks Only</div>
                  <p className="mt-1 text-xs text-muted">
                    Rejects index, tag, and category pages. Selects individual articles.
                  </p>
                </div>

                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">03 · QUALIFICATION</div>
                  <div className="mt-1 text-sm font-medium">Heuristic Gate</div>
                  <p className="mt-1 text-xs text-muted">
                    Filters out low-density marketing; verifies adversary TTPs.
                  </p>
                </div>

                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">04 · PDF EXTRACTION</div>
                  <div className="mt-1 text-sm font-medium">Pristine Document</div>
                  <p className="mt-1 text-xs text-muted">
                    Extracts exact article layout, tables, code blocks, and print CSS.
                  </p>
                </div>

                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">05 · ATT&CK MAPPING</div>
                  <div className="mt-1 text-sm font-medium">Attack Chains</div>
                  <p className="mt-1 text-xs text-muted">
                    Reconstructs multi-stage kill chains & adversary emulation plans.
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
                <h2 className="text-base font-medium">Crawler Schedule</h2>
                <p className="mt-1 text-xs text-muted">Automated continuous threat collection settings.</p>

                <dl className="mt-5 space-y-3 font-mono text-xs">
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Schedule State</dt>
                    <dd className={config?.enabled ? "text-sage" : "text-muted"}>
                      {config?.enabled ? "Enabled" : "Disabled"}
                    </dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Frequency</dt>
                    <dd className="text-fg">Every {config ? config.frequencyMinutes / 60 : 6} Hours</dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Max Depth</dt>
                    <dd className="text-fg">Depth {config?.maxDepth ?? 2}</dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Auto-Ingest</dt>
                    <dd className={config?.autoIngest ? "text-sage" : "text-muted"}>
                      {config?.autoIngest ? "ON" : "OFF"}
                    </dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">PDF & HTML Extraction</dt>
                    <dd className="text-sage">ALWAYS ON</dd>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Last Run</dt>
                    <dd className="text-fg">{formatDateTime(config?.lastRunAt, "Never")}</dd>
                  </div>
                  <div className="flex justify-between pb-2">
                    <dt className="text-subtle">Next Run</dt>
                    <dd className="text-fg">{formatDateTime(config?.nextRunAt, "Scheduled")}</dd>
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
                  <span>Run Discovery Scan</span>
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => setActiveView("settings")}
                  className="w-full text-xs"
                >
                  Adjust Crawler Settings
                </Button>
              </div>
            </div>
          </div>

          {/* Recent Crawl Job Runs History */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-base font-medium">Recent Crawl Jobs</h2>
                <p className="text-xs text-muted">Audit trail of automated and manual intelligence runs.</p>
              </div>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setActiveView("audit")}
                className="text-xs"
              >
                Full Audit Log
              </Button>
            </div>

            {jobs.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted">No crawl jobs executed yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[700px] text-left text-xs">
                  <thead className="border-b border-border font-mono text-[10px] uppercase text-subtle">
                    <tr>
                      <th className="py-2">Job ID</th>
                      <th className="py-2">Trigger</th>
                      <th className="py-2">Status</th>
                      <th className="py-2">Discovered</th>
                      <th className="py-2">Qualified</th>
                      <th className="py-2">Ingested</th>
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
                        <td className="py-2.5 font-mono text-sage">{j.qualifiedCount}</td>
                        <td className="py-2.5 font-mono font-medium text-fg">{j.ingestedCount}</td>
                        <td className="py-2.5 font-mono text-warn">{j.duplicateCount}</td>
                        <td className="py-2.5 font-mono text-muted">{j.rejectedCount}</td>
                        <td className="py-2.5 font-mono text-subtle">
                          {formatDateTime(j.completedAt, "Running...")}
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

      {/* VIEW 2: DISCOVERY QUEUE */}
      {activeView === "queue" && (
        <div className="space-y-4">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
            <div>
              <h2 className="text-lg font-medium">Discovered Threat Resources Queue</h2>
              <p className="text-xs text-muted">
                Candidate intelligence items discovered across sources, classified and qualified by heuristic gate.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Input
                placeholder="Search candidate title, publisher, URL..."
                value={queueSearch}
                onChange={(e) => setQueueSearch(e.target.value)}
                className="h-9 w-64 text-xs"
              />
            </div>
          </div>

          {/* Quick Filter Badges */}
          <div className="flex flex-wrap gap-1.5 border-b border-border pb-3">
            {[
              { id: "all", label: "All Items" },
              { id: "qualified", label: "Qualified Only" },
              { id: "ingested", label: "Ingested in Knowledge Base" },
              { id: "rejected", label: "Rejected (Low Depth / News)" },
            ].map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setQueueFilter(f.id)}
                className={cn(
                  "rounded-full px-3 py-1 text-xs font-medium transition-colors",
                  queueFilter === f.id
                    ? "bg-fg text-bg"
                    : "bg-bg-elevated text-muted hover:text-fg border border-border",
                )}
              >
                {f.label}
              </button>
            ))}
          </div>

          {filteredDiscovered.length === 0 ? (
            <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
              No discovered resources match your filter criteria. Run the crawler to discover new items.
            </div>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {filteredDiscovered.map((item) => (
                <div
                  key={item.id}
                  className="flex flex-col justify-between rounded-xl border border-border bg-bg-elevated p-4 transition-colors hover:border-border/80"
                >
                  <div>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap gap-1.5">
                        <Badge tone="neutral">{item.publisher || item.sourceDomain}</Badge>
                        <Badge tone="accent">{item.classification}</Badge>
                      </div>
                      <Badge
                        tone={
                          item.status === "ingested"
                            ? "sage"
                            : item.status === "qualified"
                              ? "sage"
                              : "danger"
                        }
                      >
                        {item.status === "ingested"
                          ? "In Knowledge Base"
                          : item.status === "qualified"
                            ? "Qualified"
                            : "Rejected"}
                      </Badge>
                    </div>

                    <h3 className="mt-3 text-sm font-medium leading-snug">{item.title}</h3>
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noreferrer"
                      className="mt-1 flex items-center gap-1 font-mono text-[11px] text-subtle hover:text-fg"
                    >
                      <span className="truncate">{item.url}</span>
                      <ExternalLink className="size-3 shrink-0" />
                    </a>

                    {item.rejectReason && (
                      <p className="mt-2.5 rounded-md border border-danger/20 bg-danger/5 px-2.5 py-1.5 text-[11px] text-danger">
                        {item.rejectReason}
                      </p>
                    )}
                  </div>

                  <div className="mt-4 flex items-center justify-between border-t border-border pt-3">
                    <div className="font-mono text-[11px] text-subtle">
                      {item.qualityScore ? `Score: ${Math.round(item.qualityScore * 100)}%` : "Score: —"} · via {item.discoveryMethod}
                    </div>

                    <div className="flex items-center gap-2">
                      {item.reportId ? (
                        <Link
                          to="/library/$reportId"
                          params={{ reportId: item.reportId }}
                          className="inline-flex h-8 items-center gap-1 rounded-md bg-bg-subtle px-2.5 text-xs text-muted hover:text-fg"
                        >
                          <FileText className="size-3" />
                          <span>View & PDF</span>
                          <ArrowRight className="size-3" />
                        </Link>
                      ) : (
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => ingestQueueItem.mutate(item.id)}
                          disabled={ingestQueueItem.isPending}
                          className="h-8 text-xs gap-1"
                        >
                          <Zap className="size-3" />
                          <span>Ingest & PDF</span>
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* VIEW 3: MANUAL INGEST */}
      {activeView === "manual" && (
        <div className="space-y-6">
          <div className="max-w-2xl">
            <h2 className="text-lg font-medium">Manual Report Acquisition</h2>
            <p className="mt-1 text-sm text-muted">
              Manually supply a threat intelligence report URL or paste the raw HTML/text payload.
              The engine automatically extracts IOCs, reconstructs attack chains, and formats the document into a high-fidelity PDF.
            </p>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Direct URL Fetch */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!url.trim()) return;
                manualIngest.mutate({ url: url.trim() });
              }}
              className="rounded-xl border border-border bg-bg-elevated p-5"
            >
              <h3 className="text-base font-medium">Fetch Live URL</h3>
              <p className="mt-1 text-xs text-muted">
                Fetches raw article HTML, strips nav/ads, normalizes text, generates PDF, and hashes evidence.
              </p>

              <div className="mt-4 flex flex-col gap-2 sm:flex-row">
                <Input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://thedfirreport.com/2024/04/..."
                  className="flex-1 font-mono text-xs"
                />
                <Button type="submit" disabled={manualIngest.isPending || !url.trim()} className="gap-2">
                  <Play className="size-3.5" />
                  <span>{manualIngest.isPending ? "Ingesting…" : "Acquire"}</span>
                </Button>
              </div>
            </form>

            {/* Direct Paste */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!pasted.trim()) return;
                manualIngest.mutate({
                  url: url.trim() || `https://manual-paste.internal/${crypto.randomUUID().slice(0, 8)}`,
                  pasted: pasted.trim(),
                });
              }}
              className="rounded-xl border border-border bg-bg-elevated p-5"
            >
              <h3 className="text-base font-medium">Paste HTML / Text Payload</h3>
              <p className="mt-1 text-xs text-muted">
                Bypasses Cloudflare anti-bot blocks if a live source is unreachable.
              </p>

              <div className="mt-4 space-y-3">
                <Input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="Optional Source URL (for provenance attribution)"
                  className="font-mono text-xs"
                />
                <Textarea
                  rows={6}
                  value={pasted}
                  onChange={(e) => setPasted(e.target.value)}
                  placeholder="Paste article HTML, incident writeup, or TTP report text…"
                  className="font-mono text-xs"
                />
                <Button
                  type="submit"
                  disabled={manualIngest.isPending || !pasted.trim()}
                  className="w-full gap-2"
                >
                  <Upload className="size-3.5" />
                  <span>{manualIngest.isPending ? "Ingesting…" : "Ingest Pasted Content & Build PDF"}</span>
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* VIEW 4: CURATED CATALOG */}
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
                  <p className="mt-2 text-xs text-muted leading-relaxed">{c.notes}</p>
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

      {/* VIEW 5: CRAWL AUDIT LOG */}
      {activeView === "audit" && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-medium">Crawl Item Audit Log</h2>
            <p className="text-xs text-muted">
              Detailed breakdown of decisions (INGESTED, REJECTED, DUPLICATE, FAILED) made by the engine.
            </p>
          </div>

          {items.length === 0 ? (
            <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
              No audit items recorded yet. Run a discovery scan to populate logs.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border bg-bg-elevated">
              <table className="w-full min-w-[800px] text-left text-xs">
                <thead className="border-b border-border bg-bg-subtle font-mono text-[10px] uppercase text-subtle">
                  <tr>
                    <th className="p-3">Decision</th>
                    <th className="p-3">Classification</th>
                    <th className="p-3">Title / URL</th>
                    <th className="p-3">Publisher</th>
                    <th className="p-3">Reason / Details</th>
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
                              : itm.decision === "DUPLICATE"
                                ? "warn"
                                : itm.decision === "REJECTED"
                                  ? "neutral"
                                  : "danger"
                          }
                        >
                          {itm.decision}
                        </Badge>
                      </td>
                      <td className="p-3 font-mono text-[11px] text-muted">{itm.classification}</td>
                      <td className="max-w-[240px] p-3">
                        <div className="truncate font-medium text-fg">{itm.title || itm.canonicalUrl}</div>
                        <div className="truncate font-mono text-[10px] text-subtle">{itm.canonicalUrl}</div>
                      </td>
                      <td className="p-3 text-muted">{itm.publisher}</td>
                      <td className="max-w-[280px] p-3 text-muted">
                        <p className="line-clamp-2 text-[11px]">{itm.reason}</p>
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

      {/* VIEW 6: CRAWL SETTINGS */}
      {activeView === "settings" && config && (
        <div className="max-w-2xl space-y-6">
          <div>
            <h2 className="text-lg font-medium">Crawler Configuration & Schedules</h2>
            <p className="text-xs text-muted">
              Configure crawl depth, frequency, automatic qualification thresholds, and targeted keywords.
            </p>
          </div>

          <div className="space-y-4 rounded-xl border border-border bg-bg-elevated p-5">
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Automatic Ingestion</label>
                <p className="text-xs text-muted">Automatically acquire qualified permalinks and build PDF documents.</p>
              </div>
              <input
                type="checkbox"
                checked={config.autoIngest}
                onChange={(e) => saveConfig.mutate({ autoIngest: e.target.checked })}
                className="size-4 accent-accent"
              />
            </div>

            <div className="flex items-center justify-between border-t border-border pt-4">
              <div>
                <label className="text-sm font-medium">Auto-ATT&CK & Attack Chain Analysis</label>
                <p className="text-xs text-muted">Reconstruct TTP progression & adversary emulation commands.</p>
              </div>
              <input
                type="checkbox"
                checked={config.autoAnalyze}
                onChange={(e) => saveConfig.mutate({ autoAnalyze: e.target.checked })}
                className="size-4 accent-accent"
              />
            </div>

            <div className="flex items-center justify-between border-t border-border pt-4">
              <div>
                <label className="text-sm font-medium">Search-Driven Discovery Vectors</label>
                <p className="text-xs text-muted">Execute dynamic search queries against CTI databases.</p>
              </div>
              <input
                type="checkbox"
                checked={config.searchDiscovery}
                onChange={(e) => saveConfig.mutate({ searchDiscovery: e.target.checked })}
                className="size-4 accent-accent"
              />
            </div>

            <div className="flex items-center justify-between border-t border-border pt-4">
              <div>
                <label className="text-sm font-medium">Recursive Outlink Discovery (Depth 2)</label>
                <p className="text-xs text-muted">Spider external references linked within ingested reports.</p>
              </div>
              <input
                type="checkbox"
                checked={config.recursiveDiscovery}
                onChange={(e) => saveConfig.mutate({ recursiveDiscovery: e.target.checked })}
                className="size-4 accent-accent"
              />
            </div>

            <div className="border-t border-border pt-4">
              <label className="text-sm font-medium">Discovery Keywords & Attack Vector Patterns</label>
              <p className="text-xs text-muted">Comma-separated terms used to seed discovery search vectors.</p>
              <Textarea
                rows={3}
                defaultValue={config.keywords}
                onBlur={(e) => saveConfig.mutate({ keywords: e.target.value })}
                className="mt-2 text-xs font-mono"
              />
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
