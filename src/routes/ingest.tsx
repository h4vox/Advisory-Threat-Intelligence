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
  Database,
  ExternalLink,
  Filter,
  Globe,
  Layers,
  ListFilter,
  Play,
  RefreshCw,
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
  getCrawlerState,
  ingestDiscoveredUrl,
  ingestUrl,
  listCatalog,
  triggerCrawlJob,
  updateCrawlerConfig,
} from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/extract";
import { cn } from "@/lib/cn";

export const Route = createFileRoute("/ingest")({ component: IngestPage });

const VIEWS = [
  { id: "crawler", label: "Autonomous Crawler", icon: Bot },
  { id: "queue", label: "Discovery Queue", icon: Compass },
  { id: "manual", label: "Manual Ingest", icon: Upload },
  { id: "catalog", label: "Curated Catalog", icon: Layers },
  { id: "audit", label: "Crawl Audit Log", icon: Activity },
  { id: "settings", label: "Crawl Settings", icon: Settings },
] as const;

export function IngestPage() {
  const qc = useQueryClient();
  const [activeView, setActiveView] = useState<(typeof VIEWS)[number]["id"]>("crawler");

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

  // Manual Ingest Mutation
  const manualIngest = useMutation({
    mutationFn: (input: { url: string; pasted?: string }) => ingestUrl({ data: input }),
    onSuccess: (res) => {
      void qc.invalidateQueries();
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
      if (res.duplicate) toast.message("Already in the store", { description: res.title });
      else toast.success("Acquired & Ingested", { description: `${res.title} · quality ${Math.round(res.qualityScore * 100)}%` });
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
        description: "Scanning trusted sources & searching threat intel feeds...",
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
      toast.success("Resource Ingested", { description: res.title });
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

  const state = crawlerState.data;
  const config = state?.config;
  const activeJob = state?.activeJob;
  const jobs = state?.jobs ?? [];
  const discovered = state?.discovered ?? [];
  const auditItems = state?.items ?? [];

  // Filter queue items
  const filteredDiscovered = discovered.filter((d) => {
    const matchesFilter =
      queueFilter === "all"
        ? true
        : queueFilter === "qualified"
          ? d.status === "qualified" || d.status === "ingested"
          : d.status === queueFilter;
    const matchesSearch =
      !queueSearch.trim() ||
      `${d.title} ${d.publisher} ${d.url} ${d.classification}`.toLowerCase().includes(queueSearch.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <AppShell>
      {/* Top Header */}
      <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-center">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">
            Adversary Intelligence Engine · Acquisition
          </p>
          <h1 className="mt-1 text-3xl font-medium tracking-tight">Threat Ingestion & Crawler</h1>
          <p className="mt-1 text-sm text-muted">
            Autonomous adversary intelligence discovery, qualification gate, and structured attack-chain extraction.
          </p>
        </div>

        {/* Global Action Button */}
        <div className="flex items-center gap-2">
          {activeJob ? (
            <Button
              variant="secondary"
              className="gap-2 border-warn/30 bg-warn/10 text-warn hover:bg-warn/20"
              onClick={() => cancelCrawl.mutate(activeJob.id)}
              disabled={cancelCrawl.isPending}
            >
              <RefreshCw className="size-4 animate-spin" />
              <span>Scanning... Stop</span>
            </Button>
          ) : (
            <Button
              className="gap-2 shadow-sm"
              onClick={() => runCrawl.mutate("MANUAL")}
              disabled={runCrawl.isPending}
            >
              <Zap className="size-4" />
              <span>Run Discovery Now</span>
            </Button>
          )}
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="mb-6 flex flex-wrap gap-1 border-b border-border">
        {VIEWS.map((v) => {
          const Icon = v.icon;
          const isActive = activeView === v.id;
          return (
            <button
              key={v.id}
              type="button"
              onClick={() => setActiveView(v.id)}
              className={cn(
                "flex h-11 items-center gap-2 px-4 text-sm font-medium transition-colors duration-150",
                isActive
                  ? "border-b-2 border-accent text-fg"
                  : "text-muted hover:text-fg hover:bg-bg-subtle/50",
              )}
            >
              <Icon className={cn("size-4", isActive ? "text-accent" : "text-subtle")} />
              {v.label}
              {v.id === "queue" && discovered.length > 0 && (
                <span className="ml-1 rounded-full bg-bg-elevated px-2 py-0.5 font-mono text-[10px] text-muted border border-border">
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
          {/* Active Job Alert Banner */}
          {activeJob && (
            <div className="flex items-center justify-between rounded-xl border border-accent/40 bg-accent/5 p-4">
              <div className="flex items-center gap-3">
                <RefreshCw className="size-5 animate-spin text-accent" />
                <div>
                  <div className="text-sm font-medium">Autonomous Discovery In Progress</div>
                  <div className="text-xs text-muted">
                    Inspecting feeds, discovering permalinks, running heuristic qualification & attack-chain mapping...
                  </div>
                </div>
              </div>
              <Badge tone="accent">Running</Badge>
            </div>
          )}

          {/* Crawler Live Metrics Cards */}
          <div className="grid gap-3 xs:grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
            <div className="rounded-xl border border-border bg-bg-elevated p-4">
              <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Engine Status</div>
              <div className="mt-1 flex items-center gap-2">
                <span className={cn("size-2 rounded-full", activeJob ? "bg-accent animate-pulse" : config?.enabled ? "bg-sage" : "bg-muted")} />
                <span className="text-lg font-medium capitalize">
                  {activeJob ? "Crawling" : config?.paused ? "Paused" : config?.enabled ? "Scheduled" : "Idle"}
                </span>
              </div>
              <div className="mt-1 text-[11px] text-muted">
                Freq: {config ? `${config.frequencyMinutes / 60}h` : "6h"}
              </div>
            </div>

            <div className="rounded-xl border border-border bg-bg-elevated p-4">
              <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Discovered</div>
              <div className="mt-1 text-2xl font-medium">
                {jobs.reduce((acc, j) => acc + j.discoveredCount, 0)}
              </div>
              <div className="mt-1 text-[11px] text-muted">Total candidates found</div>
            </div>

            <div className="rounded-xl border border-border bg-bg-elevated p-4">
              <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Qualified</div>
              <div className="mt-1 text-2xl font-medium text-sage">
                {jobs.reduce((acc, j) => acc + j.qualifiedCount, 0)}
              </div>
              <div className="mt-1 text-[11px] text-muted">Passed threat gate</div>
            </div>

            <div className="rounded-xl border border-border bg-bg-elevated p-4">
              <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Auto-Ingested</div>
              <div className="mt-1 text-2xl font-medium text-fg">
                {jobs.reduce((acc, j) => acc + j.ingestedCount, 0)}
              </div>
              <div className="mt-1 text-[11px] text-muted">In knowledge base</div>
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
                How the autonomous crawler searches, qualifies individual permalinks, and converts raw intelligence into attack chains.
              </p>

              <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-5">
                <div className="flex flex-col rounded-lg border border-border bg-bg-subtle p-3">
                  <div className="font-mono text-[10px] text-subtle">01 · SOURCE DISCOVERY</div>
                  <div className="mt-1 text-sm font-medium">Feed & Search Crawl</div>
                  <p className="mt-1 text-xs text-muted">
                    Scans DFIR, Mandiant, SentinelLABS, CISA, Unit 42 & query vectors.
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
                  <div className="font-mono text-[10px] text-subtle">04 · ACQUISITION</div>
                  <div className="mt-1 text-sm font-medium">Hash & Ingest</div>
                  <p className="mt-1 text-xs text-muted">
                    Stores SHA-256 evidence, raw text, and extracts regex IOCs.
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
                    <dt className="text-subtle">Auto-ATT&CK Analysis</dt>
                    <dd className={config?.autoAnalyze ? "text-sage" : "text-muted"}>
                      {config?.autoAnalyze ? "ON" : "OFF"}
                    </dd>
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
                View Detailed Item Audit
              </Button>
            </div>

            {jobs.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted">No crawl jobs executed yet. Click &quot;Run Discovery Now&quot; above.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[650px] text-left text-xs">
                  <thead className="border-b border-border font-mono text-[10px] uppercase text-subtle">
                    <tr>
                      <th className="pb-2">Job ID</th>
                      <th className="pb-2">Trigger</th>
                      <th className="pb-2">Status</th>
                      <th className="pb-2">Discovered</th>
                      <th className="pb-2">Qualified</th>
                      <th className="pb-2">Ingested</th>
                      <th className="pb-2">Duplicates</th>
                      <th className="pb-2">Rejected</th>
                      <th className="pb-2">Completed At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {jobs.map((j) => (
                      <tr key={j.id} className="hover:bg-bg-subtle">
                        <td className="py-2.5 font-mono text-muted">{j.id}</td>
                        <td className="py-2.5">
                          <Badge tone="neutral">{j.triggerType}</Badge>
                        </td>
                        <td className="py-2.5">
                          <Badge
                            tone={
                              j.status === "completed"
                                ? "sage"
                                : j.status === "running"
                                  ? "accent"
                                  : j.status === "failed"
                                    ? "danger"
                                    : "warn"
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
                          View Report <ArrowRight className="size-3" />
                        </Link>
                      ) : (
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => ingestQueueItem.mutate(item.id)}
                          disabled={ingestQueueItem.isPending}
                          className="h-8 text-xs"
                        >
                          Ingest Now
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

      {/* VIEW 3: MANUAL INGEST (PRESERVED & ENHANCED) */}
      {activeView === "manual" && (
        <div className="space-y-6">
          <div className="max-w-2xl">
            <h2 className="text-lg font-medium">Manual Report Acquisition</h2>
            <p className="mt-1 text-sm text-muted">
              Manually supply a threat intelligence report URL or paste the raw HTML/text payload.
              The pipeline hashes original bytes, cleans content, scores quality, extracts regex IOCs, and reconstructs attack chains.
            </p>
          </div>

          <form
            className="max-w-2xl space-y-4 rounded-xl border border-border bg-bg-elevated p-5"
            onSubmit={(e) => {
              e.preventDefault();
              manualIngest.mutate({ url, pasted: pasted.trim() ? pasted : undefined });
            }}
          >
            <div>
              <label className="block text-xs uppercase tracking-wider text-subtle">Report URL</label>
              <Input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://thedfirreport.com/2026/04/22/bissa-scanner-exposed…"
                type="url"
                required
                className="mt-1.5"
              />
            </div>

            <div>
              <label className="block text-xs uppercase tracking-wider text-subtle">
                Optional Paste Payload (HTML or Clean Text)
              </label>
              <p className="mt-0.5 text-[11px] text-muted">
                Useful when cloud firewalls or paywalls block live automated web requests.
              </p>
              <Textarea
                value={pasted}
                onChange={(e) => setPasted(e.target.value)}
                placeholder="Paste threat analysis report text here when direct fetching is restricted…"
                className="mt-1.5 min-h-[140px]"
              />
            </div>

            <Button type="submit" disabled={manualIngest.isPending} className="mt-2 w-full sm:w-auto">
              {manualIngest.isPending ? "Retrieving & Analyzing…" : "Retrieve, Hash and Ingest"}
            </Button>
          </form>
        </div>
      )}

      {/* VIEW 4: CURATED DISCOVERY CATALOG (PRESERVED) */}
      {activeView === "catalog" && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-medium">Curated Golden-Set Catalog</h2>
            <p className="text-sm text-muted">
              Pre-validated high-value adversary reports representing key intrusion archetypes. One-click ingest routes through the live acquisition pipeline.
            </p>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            {catalog.data?.map((c) => (
              <article key={c.id} className="flex flex-col rounded-xl border border-border bg-bg-elevated p-5">
                <div className="flex flex-wrap gap-2">
                  <Badge>{c.sourceName}</Badge>
                  <Badge tone="neutral">{c.published}</Badge>
                  {c.alreadyIngested ? <Badge tone="sage">In Knowledge Base</Badge> : null}
                </div>
                <h3 className="mt-3 text-sm font-medium leading-snug">{c.title}</h3>
                <p className="mt-2 flex-1 text-sm text-muted">{c.why}</p>
                <div className="mt-4 flex flex-wrap gap-2 border-t border-border pt-3">
                  <Button
                    type="button"
                    size="sm"
                    variant={c.alreadyIngested ? "secondary" : "primary"}
                    disabled={manualIngest.isPending}
                    onClick={() => {
                      setUrl(c.url);
                      manualIngest.mutate({ url: c.url });
                    }}
                  >
                    {c.alreadyIngested ? "Re-ingest" : "Ingest Report"}
                  </Button>
                  <a
                    href={c.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex h-9 items-center gap-1 rounded-md px-3 text-sm text-muted hover:text-fg"
                  >
                    Open Source <ExternalLink className="size-3" />
                  </a>
                </div>
              </article>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 5: CRAWL AUDIT LOG */}
      {activeView === "audit" && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-medium">Crawler Item Decision Audit</h2>
            <p className="text-xs text-muted">
              Per-URL qualification logs showing why candidate resources were accepted or rejected by the crawler.
            </p>
          </div>

          {auditItems.length === 0 ? (
            <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
              No crawl decision records available yet. Run a discovery scan to see audit items.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border bg-bg-elevated">
              <table className="w-full min-w-[700px] text-left text-xs">
                <thead className="border-b border-border bg-bg-subtle font-mono text-[10px] uppercase text-subtle">
                  <tr>
                    <th className="p-3">Decision</th>
                    <th className="p-3">Classification</th>
                    <th className="p-3">Candidate Resource</th>
                    <th className="p-3">Publisher</th>
                    <th className="p-3">Reason / Qualification Rationale</th>
                    <th className="p-3">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {auditItems.map((itm) => (
                    <tr key={itm.id} className="hover:bg-bg-subtle/50">
                      <td className="p-3">
                        <Badge
                          tone={
                            itm.decision === "INGESTED"
                              ? "sage"
                              : itm.decision === "QUALIFIED"
                                ? "sage"
                                : itm.decision === "DUPLICATE"
                                  ? "warn"
                                  : itm.decision === "REJECTED"
                                    ? "danger"
                                    : "neutral"
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
            <h2 className="text-lg font-medium">Crawler Configuration & Scheduler</h2>
            <p className="text-xs text-muted">
              Configure automatic discovery frequency, crawl depth, keyword filters, and ingestion gates.
            </p>
          </div>

          <div className="space-y-4 rounded-xl border border-border bg-bg-elevated p-5">
            {/* Auto Schedule Toggle */}
            <div className="flex items-center justify-between border-b border-border pb-4">
              <div>
                <div className="text-sm font-medium">Automated Crawling</div>
                <div className="text-xs text-muted">Run autonomous discovery on a continuous recurring timer.</div>
              </div>
              <Button
                variant={config.enabled ? "primary" : "secondary"}
                size="sm"
                onClick={() => saveConfig.mutate({ enabled: !config.enabled })}
              >
                {config.enabled ? "Enabled" : "Disabled"}
              </Button>
            </div>

            {/* Frequency Selection */}
            <div>
              <label className="block text-xs uppercase tracking-wider text-subtle">Run Frequency</label>
              <select
                value={config.frequencyMinutes}
                onChange={(e) => saveConfig.mutate({ frequencyMinutes: Number(e.target.value) })}
                className="mt-1.5 w-full rounded-md border border-border bg-bg-subtle px-3 py-2 text-sm text-fg"
              >
                <option value={15}>Every 15 Minutes</option>
                <option value={30}>Every 30 Minutes</option>
                <option value={60}>Every 1 Hour</option>
                <option value={360}>Every 6 Hours (Recommended)</option>
                <option value={720}>Every 12 Hours</option>
                <option value={1440}>Every 24 Hours (Daily)</option>
              </select>
            </div>

            {/* Crawl Depth Selection */}
            <div>
              <label className="block text-xs uppercase tracking-wider text-subtle">Maximum Crawl Depth</label>
              <select
                value={config.maxDepth}
                onChange={(e) => saveConfig.mutate({ maxDepth: Number(e.target.value) })}
                className="mt-1.5 w-full rounded-md border border-border bg-bg-subtle px-3 py-2 text-sm text-fg"
              >
                <option value={1}>Depth 1 · Direct Article Permalinks</option>
                <option value={2}>Depth 2 · Recursive Referenced Reports (Recommended)</option>
                <option value={3}>Depth 3 · New Discovered Threat Publishers</option>
              </select>
            </div>

            {/* Max Resources Per Run */}
            <div>
              <label className="block text-xs uppercase tracking-wider text-subtle">
                Maximum Candidates Per Run
              </label>
              <Input
                type="number"
                value={config.maxResourcesPerRun}
                onChange={(e) => saveConfig.mutate({ maxResourcesPerRun: Number(e.target.value) })}
                min={5}
                max={100}
                className="mt-1.5"
              />
            </div>

            {/* Ingestion & Analysis Toggles */}
            <div className="space-y-3 border-t border-border pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium">Automatic Ingestion to Knowledge Base</div>
                  <div className="text-xs text-muted">
                    Automatically ingest qualified reports without waiting in queue.
                  </div>
                </div>
                <Button
                  variant={config.autoIngest ? "primary" : "secondary"}
                  size="sm"
                  onClick={() => saveConfig.mutate({ autoIngest: !config.autoIngest })}
                >
                  {config.autoIngest ? "ON" : "OFF"}
                </Button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium">Automatic ATT&CK & Attack-Chain Reconstruction</div>
                  <div className="text-xs text-muted">
                    Extract multi-stage kill chains and adversary emulation profiles upon ingest.
                  </div>
                </div>
                <Button
                  variant={config.autoAnalyze ? "primary" : "secondary"}
                  size="sm"
                  onClick={() => saveConfig.mutate({ autoAnalyze: !config.autoAnalyze })}
                >
                  {config.autoAnalyze ? "ON" : "OFF"}
                </Button>
              </div>
            </div>

            {/* Discovery Keywords */}
            <div className="border-t border-border pt-4">
              <label className="block text-xs uppercase tracking-wider text-subtle">
                Search-Driven Discovery Keywords
              </label>
              <p className="mt-0.5 text-[11px] text-muted">
                Comma-separated queries used for continuous search and topic discovery.
              </p>
              <Textarea
                value={config.keywords}
                onChange={(e) => saveConfig.mutate({ keywords: e.target.value })}
                className="mt-1.5 text-xs"
              />
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
