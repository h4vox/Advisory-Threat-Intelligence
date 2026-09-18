import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import {
  ExternalLink,
  Globe,
  Bot,
  Shield,
  Eye,
  EyeOff,
  Trash2,
  CheckCircle2,
  Plus,
  Sparkles,
  Search,
  AlertTriangle,
  RefreshCw,
  Zap,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { IdBadge } from "@/components/id-badge";
import { formatDomainId, formatSourceId } from "@/lib/aie/ids";
import { cn } from "@/lib/cn";
import {
  listSources,
  toggleSource,
  listDiscoveredSources,
  toggleDiscoveredSource,
  revokeDiscoveredSource,
  deleteDiscoveredSource,
  validateDiscoveredSource,
  addDiscoveredSource,
  triggerAgentSourceDiscovery,
  getAgentStatus,
  probeSourceFeeds,
} from "@/lib/aie/server";
import type { DiscoveredSourceRecord, SourceProbeResult, SourceRecord } from "@/lib/aie/types";

export const Route = createFileRoute("/sources")({ component: SourcesPage });

function SourcesPage() {
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<"curated" | "discovered">("curated");
  const [showAddModal, setShowAddModal] = useState(false);
  const [addDomain, setAddDomain] = useState("");
  const [addCrawlPattern, setAddCrawlPattern] = useState("");
  const [addName, setAddName] = useState("");
  const [addNotes, setAddNotes] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [probeResults, setProbeResults] = useState<Record<string, SourceProbeResult>>({});

  // Curated sources query
  const { data: sources } = useQuery({
    queryKey: ["sources"],
    queryFn: () => listSources(),
    staleTime: 60_000,
    placeholderData: (previousData) => previousData,
  });

  // Discovered sources query
  const { data: discoveredSources, isLoading: discoveredLoading } = useQuery({
    queryKey: ["discovered-sources"],
    queryFn: () => listDiscoveredSources(),
    staleTime: 60_000,
    placeholderData: (previousData) => previousData,
  });

  // Agent status
  const { data: agentStatus } = useQuery({
    queryKey: ["agent-status"],
    queryFn: () => getAgentStatus(),
    staleTime: 60_000,
    placeholderData: (previousData) => previousData,
  });

  // Concurrent Feed Health Probing Mutation (Architecture Improvement)
  const probeMut = useMutation({
    mutationFn: (sourceIds?: string[]) =>
      probeSourceFeeds({ data: { sourceIds, concurrency: 6 } }),
    onSuccess: (data) => {
      const map: Record<string, SourceProbeResult> = {};
      for (const p of data.probes) {
        map[p.sourceId] = p;
      }
      setProbeResults((prev) => ({ ...prev, ...map }));
      toast.success("Concurrent Health Probe Completed", {
        description: `Checked ${data.summary.total} sources in parallel: ${data.summary.healthy} online, ${data.summary.degraded} degraded/offline.`,
      });
    },
    onError: (err: Error) => toast.error(`Health probe failed: ${err.message}`),
  });

  // 0ms Optimistic Mutations
  const toggleMut = useMutation({
    mutationFn: (input: { id: string; enabled: boolean }) => toggleSource({ data: input }),
    onMutate: async ({ id, enabled }) => {
      await qc.cancelQueries({ queryKey: ["sources"] });
      const previousSources = qc.getQueryData<SourceRecord[]>(["sources"]);
      qc.setQueryData<SourceRecord[]>(["sources"], (old) =>
        old?.map((s) => (s.id === id ? { ...s, enabled } : s)),
      );
      return { previousSources };
    },
    onError: (_err, _vars, context) => {
      if (context?.previousSources) {
        qc.setQueryData(["sources"], context.previousSources);
      }
      toast.error("Failed to toggle source");
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ["sources"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  const toggleDiscoveredMut = useMutation({
    mutationFn: (input: { id: string; enabled: boolean }) => toggleDiscoveredSource({ data: input }),
    onMutate: async ({ id, enabled }) => {
      await qc.cancelQueries({ queryKey: ["discovered-sources"] });
      const previous = qc.getQueryData<DiscoveredSourceRecord[]>(["discovered-sources"]);
      qc.setQueryData<DiscoveredSourceRecord[]>(["discovered-sources"], (old) =>
        old?.map((s) => (s.id === id ? { ...s, enabled } : s)),
      );
      return { previous };
    },
    onError: (_err, _vars, context) => {
      if (context?.previous) {
        qc.setQueryData(["discovered-sources"], context.previous);
      }
      toast.error("Failed to toggle discovered source");
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ["discovered-sources"] });
      toast.success("Source status updated");
    },
  });

  const revokeMut = useMutation({
    mutationFn: (id: string) => revokeDiscoveredSource({ data: { id } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["discovered-sources"] });
      toast.success("Source revoked");
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteDiscoveredSource({ data: { id } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["discovered-sources"] });
      toast.success("Source permanently deleted");
    },
  });

  const validateMut = useMutation({
    mutationFn: (id: string) => validateDiscoveredSource({ data: { id, status: "verified" } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["discovered-sources"] });
      toast.success("Source validated");
    },
  });

  const addSourceMut = useMutation({
    mutationFn: (input: { domain: string; name: string; notes: string; crawlPattern?: string }) =>
      addDiscoveredSource({ data: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["discovered-sources"] });
      setShowAddModal(false);
      setAddDomain("");
      setAddCrawlPattern("");
      setAddName("");
      setAddNotes("");
      toast.success("Source added");
    },
  });

  const discoverMut = useMutation({
    mutationFn: () => triggerAgentSourceDiscovery({ data: {} }),
    onSuccess: (result) => {
      void qc.invalidateQueries({ queryKey: ["discovered-sources"] });
      toast.success(`Agent discovered ${result?.discoveredCount ?? 0} new sources`);
    },
    onError: () => {
      toast.error("Agent source discovery failed");
    },
  });

  // Filter helpers
  const filteredSources = (sources ?? []).filter((s) =>
    searchQuery
      ? s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.homepageUrl.toLowerCase().includes(searchQuery.toLowerCase())
      : true,
  );

  const filteredDiscovered = (discoveredSources ?? []).filter((s: DiscoveredSourceRecord) =>
    searchQuery
      ? s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        s.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (s.notes || "").toLowerCase().includes(searchQuery.toLowerCase())
      : true,
  );

  const originBadge = (origin?: string) => {
    switch (origin) {
      case "agent_discovery":
        return <Badge tone="accent"><Bot className="size-3 mr-0.5" />Agent</Badge>;
      case "crawler_outlink":
        return <Badge tone="neutral"><Globe className="size-3 mr-0.5" />Crawler</Badge>;
      case "manual":
        return <Badge><Plus className="size-3 mr-0.5" />Manual</Badge>;
      case "citation_expansion":
        return <Badge tone="sage"><Search className="size-3 mr-0.5" />Citation</Badge>;
      default:
        return <Badge tone="neutral">{origin || "Unknown"}</Badge>;
    }
  };

  const statusBadge = (status: string) => {
    switch (status) {
      case "verified":
      case "approved":
        return <span className="inline-flex items-center gap-1 rounded-full bg-emerald-950/40 px-2 py-0.5 text-[10px] font-semibold text-emerald-400"><CheckCircle2 className="size-3" />{status}</span>;
      case "discovered":
      case "evaluated":
        return <span className="inline-flex items-center gap-1 rounded-full bg-blue-950/40 px-2 py-0.5 text-[10px] font-semibold text-blue-400">{status}</span>;
      case "ignored":
      case "rejected":
        return <span className="inline-flex items-center gap-1 rounded-full bg-red-950/40 px-2 py-0.5 text-[10px] font-semibold text-red-400"><AlertTriangle className="size-3" />{status}</span>;
      default:
        return <span className="inline-flex rounded-full bg-zinc-800 px-2 py-0.5 text-[10px] font-semibold text-zinc-400">{status}</span>;
    }
  };

  return (
    <AppShell>
      <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">Registry</p>
      <h1 className="mt-1 text-3xl font-medium tracking-tight">Sources</h1>
      <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted">
        Curated sources are protected baseline intelligence publishers. Discovered sources are
        found by the crawler engine or AI agent and can be reviewed, toggled, or revoked.
      </p>

      {/* Tab Navigation */}
      <div className="mt-6 flex items-center gap-4 border-b border-border">
        <button
          type="button"
          onClick={() => setActiveTab("curated")}
          className={cn(
            "pb-2.5 text-sm font-medium transition-colors border-b-2",
            activeTab === "curated"
              ? "border-accent text-fg"
              : "border-transparent text-muted hover:text-fg",
          )}
        >
          <Shield className="inline size-4 mr-1.5 -mt-0.5" />
          Curated Sources ({filteredSources.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("discovered")}
          className={cn(
            "pb-2.5 text-sm font-medium transition-colors border-b-2",
            activeTab === "discovered"
              ? "border-accent text-fg"
              : "border-transparent text-muted hover:text-fg",
          )}
        >
          <Globe className="inline size-4 mr-1.5 -mt-0.5" />
          Discovered Sources ({filteredDiscovered.length})
        </button>
      </div>

      {/* Search Bar & Actions Toolbar */}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="absolute left-3 top-2.5 size-4 text-subtle" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search sources..."
            className="w-full rounded-lg border border-border bg-bg-elevated pl-9 pr-4 py-2 text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Concurrent Health Probe Button */}
          <Button
            size="sm"
            variant="secondary"
            disabled={probeMut.isPending}
            onClick={() => {
              const currentList = activeTab === "curated" ? filteredSources : filteredDiscovered;
              const ids = currentList.map((s) => s.id);
              probeMut.mutate(ids.length > 0 ? ids : undefined);
            }}
            className="gap-1.5 whitespace-nowrap"
            title="Concurrently probe HTTP latency and reachability across feeds using 6 parallel workers"
          >
            {probeMut.isPending ? (
              <>
                <RefreshCw className="size-3.5 animate-spin text-accent" />
                <span>Probing Feeds...</span>
              </>
            ) : (
              <>
                <Zap className="size-3.5 text-accent" />
                <span>Probe Feeds</span>
              </>
            )}
          </Button>

          {activeTab === "discovered" && (
            <>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setShowAddModal(true)}
                className="gap-1.5"
              >
                <Plus className="size-3.5" />
                Add Source
              </Button>
              <Button
                size="sm"
                variant="primary"
                disabled={discoverMut.isPending || !agentStatus?.available}
                onClick={() => discoverMut.mutate()}
                className="gap-1.5"
              >
                <Sparkles className="size-3.5" />
                {discoverMut.isPending ? "Discovering..." : "AI Discover"}
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Agent Status Indicator */}
      {activeTab === "discovered" && agentStatus && (
        <div className="mt-3 flex items-center gap-2 text-xs text-muted">
          <div className={cn("size-2 rounded-full", agentStatus.available ? "bg-emerald-500" : "bg-red-500")} />
          <span>AGY Agent: {agentStatus.available ? `v${agentStatus.version} · Available` : "Unavailable"}</span>
          {agentStatus.available && (
            <span className="text-subtle">({agentStatus.platform})</span>
          )}
        </div>
      )}

      {/* Curated Sources Tab */}
      {activeTab === "curated" && (
        <div className="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredSources.map((s) => (
            <article
              key={s.id}
              className={cn(
                "flex flex-col justify-between rounded-xl border p-3.5 transition-colors",
                s.enabled
                  ? "border-border bg-bg-elevated hover:border-border/80"
                  : "border-border/40 bg-bg-subtle/50 opacity-60",
              )}
            >
              <div>
                {/* Header: ID, Badges */}
                <div className="flex flex-wrap items-center gap-1.5 mb-1.5">
                  <IdBadge id={formatSourceId(s.id, s.slug)} category="source" size="xs" prefixLabel="SRC" />
                  <Badge tone="sage"><Shield className="size-2.5 mr-0.5" />Curated</Badge>
                  <Badge tone="accent">P{s.priority}</Badge>
                  <Badge tone={s.trustLevel === "official" ? "sage" : "neutral"}>{s.trustLevel}</Badge>

                  {/* Concurrent Health Probe Status Badge */}
                  {probeResults[s.id] && (
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono font-medium",
                        probeResults[s.id].reachable
                          ? "bg-emerald-950/50 text-emerald-400 border border-emerald-800/40"
                          : "bg-rose-950/50 text-rose-400 border border-rose-800/40",
                      )}
                      title={probeResults[s.id].reachable ? `HTTP ${probeResults[s.id].statusCode} in ${probeResults[s.id].latencyMs}ms` : (probeResults[s.id].error || "Unreachable")}
                    >
                      <span className={cn("size-1.5 rounded-full", probeResults[s.id].reachable ? "bg-emerald-400 animate-pulse" : "bg-rose-400")} />
                      {probeResults[s.id].reachable ? `${probeResults[s.id].latencyMs}ms · ${probeResults[s.id].statusCode}` : "Offline"}
                    </span>
                  )}
                </div>

                {/* Title & Category */}
                <div className="flex items-start justify-between gap-2">
                  <h2 className="text-sm font-semibold tracking-tight text-fg line-clamp-1">{s.name}</h2>
                  <span className="shrink-0 text-[10px] font-medium uppercase tracking-wider text-subtle">
                    {s.category.replaceAll("_", " ")}
                  </span>
                </div>

                {/* Resource Count Badge */}
                <div className="mt-2 flex items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-xs font-medium text-fg">
                    <span className="size-1.5 rounded-full bg-accent" />
                    <strong>{s.resourceCount ?? 0}</strong> reports collected
                  </span>
                </div>

                {/* Notes */}
                <p className="mt-1.5 text-xs leading-relaxed text-muted line-clamp-2">{s.notes}</p>

                {/* Scoped Endpoint Pattern */}
                {s.crawlPattern && (
                  <div className="mt-2 rounded border border-border/80 bg-bg-subtle px-2 py-1.5">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-subtle mb-0.5">
                      Endpoint Pattern:
                    </div>
                    <code className="break-all font-mono text-[11px] text-accent font-medium">
                      {s.crawlPattern}
                    </code>
                  </div>
                )}
              </div>

              {/* Card Footer: Homepage Link & Dark Gray Neutral Toggle Button */}
              <div className="mt-3 flex items-center justify-between border-t border-border/60 pt-2.5">
                <a
                  href={s.homepageUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 font-mono text-xs text-subtle hover:text-fg transition-colors"
                >
                  <span className="truncate max-w-[130px]">{s.homepageUrl.replace(/^https?:\/\//, "").replace(/\/+$/, "")}</span>
                  <ExternalLink className="size-3 shrink-0" />
                </a>

                <button
                  type="button"
                  onClick={() => toggleMut.mutate({ id: s.id, enabled: !s.enabled })}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors shadow-xs cursor-pointer",
                    s.enabled
                      ? "border-zinc-700 bg-zinc-800 text-zinc-200 hover:bg-zinc-700 hover:text-white"
                      : "border-border/60 bg-transparent text-muted hover:bg-bg-subtle hover:text-fg",
                  )}
                >
                  {s.enabled ? (
                    <>
                      <Eye className="size-3 text-zinc-400" />
                      <span>Active</span>
                    </>
                  ) : (
                    <>
                      <EyeOff className="size-3 text-zinc-500" />
                      <span>Paused</span>
                    </>
                  )}
                </button>
              </div>
            </article>
          ))}
          {filteredSources.length === 0 && (
            <div className="col-span-full py-12 text-center text-sm text-muted">
              No curated sources matching search criteria.
            </div>
          )}
        </div>
      )}

      {/* Discovered Sources Tab */}
      {activeTab === "discovered" && (
        <div className="mt-6">
          {discoveredLoading && (
            <p className="py-12 text-center text-sm text-muted">Loading discovered sources...</p>
          )}
          {!discoveredLoading && filteredDiscovered.length === 0 && (
            <div className="py-12 text-center">
              <Globe className="mx-auto size-8 text-subtle" />
              <p className="mt-3 text-sm text-muted">
                No discovered sources yet. Run a crawl job or use AI Discover to find new sources.
              </p>
            </div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredDiscovered.map((ds: DiscoveredSourceRecord) => (
              <article
                key={ds.id}
                className={cn(
                  "flex flex-col justify-between rounded-xl border p-3.5 transition-colors",
                  ds.enabled !== false
                    ? "border-border bg-bg-elevated hover:border-border/80"
                    : "border-border/40 bg-bg-subtle/50 opacity-60",
                )}
              >
                <div>
                  {/* Header: ID, Badges */}
                  <div className="flex flex-wrap items-center gap-1.5 mb-1.5">
                    <IdBadge id={ds.domain} category="domain" size="xs" />
                    {originBadge(ds.origin)}
                    {statusBadge(ds.status)}
                    <span className="rounded bg-bg-subtle border border-border px-1.5 py-0.5 text-[10px] font-mono text-muted">
                      Trust: {Math.round(ds.trustScore * 100 > 100 ? ds.trustScore : ds.trustScore * 100)}%
                    </span>
                    {probeResults[ds.id] && (
                      <span
                        className={cn(
                          "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono font-medium",
                          probeResults[ds.id].reachable
                            ? "bg-emerald-950/50 text-emerald-400 border border-emerald-800/40"
                            : "bg-rose-950/50 text-rose-400 border border-rose-800/40",
                        )}
                        title={probeResults[ds.id].reachable ? `HTTP ${probeResults[ds.id].statusCode} in ${probeResults[ds.id].latencyMs}ms` : (probeResults[ds.id].error || "Unreachable")}
                      >
                        <span className={cn("size-1.5 rounded-full", probeResults[ds.id].reachable ? "bg-emerald-400 animate-pulse" : "bg-rose-400")} />
                        {probeResults[ds.id].reachable ? `${probeResults[ds.id].latencyMs}ms · ${probeResults[ds.id].statusCode}` : "Offline"}
                      </span>
                    )}
                  </div>

                  {/* Title */}
                  <h2 className="text-sm font-semibold tracking-tight text-fg line-clamp-1">{ds.name}</h2>

                  {/* Resource Count Badge */}
                  <div className="mt-2 flex items-center gap-2">
                    <span className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-xs font-medium text-fg">
                      <span className="size-1.5 rounded-full bg-blue-400" />
                      <strong>{ds.resourceCount}</strong> reports in library
                    </span>
                  </div>

                  {/* Notes / Why Crawl */}
                  {ds.notes && (
                    <p className="mt-1.5 text-xs leading-relaxed text-muted line-clamp-2">{ds.notes}</p>
                  )}
                  {ds.whyCrawl && ds.whyCrawl !== ds.notes && (
                    <p className="mt-1 text-[11px] text-subtle italic line-clamp-1">{ds.whyCrawl}</p>
                  )}

                  {/* Endpoint Pattern */}
                  <div className="mt-2 rounded border border-border/80 bg-bg-subtle px-2 py-1.5">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-subtle mb-0.5">
                      Endpoint Pattern:
                    </div>
                    <code className="break-all font-mono text-[11px] text-accent font-medium">
                      {ds.crawlPattern || `https://${ds.domain}/*`}
                    </code>
                  </div>
                </div>

                {/* Footer: Link on Left, Single Row Action Buttons on Right */}
                <div className="mt-3 flex items-center justify-between gap-2 border-t border-border/60 pt-2.5">
                  <a
                    href={ds.homepageUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-xs text-subtle hover:text-fg transition-colors truncate max-w-[120px]"
                    title={ds.homepageUrl}
                  >
                    <span className="truncate">{ds.homepageUrl.replace(/^https?:\/\//, "").replace(/\/+$/, "")}</span>
                    <ExternalLink className="size-3 shrink-0" />
                  </a>

                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      onClick={() => toggleDiscoveredMut.mutate({ id: ds.id, enabled: ds.enabled === false })}
                      className={cn(
                        "inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition-colors cursor-pointer",
                        ds.enabled !== false
                          ? "border-zinc-700 bg-zinc-800 text-zinc-200 hover:bg-zinc-700 hover:text-white"
                          : "border-border/60 bg-transparent text-muted hover:bg-bg-subtle hover:text-fg",
                      )}
                      title={ds.enabled !== false ? "Click to Pause" : "Click to Activate"}
                    >
                      {ds.enabled !== false ? (
                        <>
                          <Eye className="size-3 text-zinc-400" />
                          <span>Active</span>
                        </>
                      ) : (
                        <>
                          <EyeOff className="size-3 text-zinc-500" />
                          <span>Paused</span>
                        </>
                      )}
                    </button>

                    {ds.status !== "verified" && ds.status !== "approved" && (
                      <button
                        type="button"
                        onClick={() => validateMut.mutate(ds.id)}
                        disabled={validateMut.isPending}
                        className="inline-flex items-center gap-1 rounded-md border border-emerald-900/50 bg-emerald-950/30 px-1.5 py-1 text-[11px] font-medium text-emerald-300 hover:bg-emerald-950/60 transition-colors cursor-pointer"
                        title="Verify Source"
                      >
                        <CheckCircle2 className="size-3 text-emerald-400" />
                        <span className="hidden sm:inline">Verify</span>
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => {
                        if (confirm(`Revoke source "${ds.name}"? This will pause it and mark it as rejected.`)) {
                          revokeMut.mutate(ds.id);
                        }
                      }}
                      disabled={revokeMut.isPending}
                      className="inline-flex items-center justify-center rounded-md border border-amber-900/50 bg-amber-950/20 p-1 text-amber-400 hover:bg-amber-950/40 transition-colors cursor-pointer"
                      title="Revoke Source"
                    >
                      <AlertTriangle className="size-3" />
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        if (confirm(`Permanently delete source "${ds.name}"? This cannot be undone.`)) {
                          deleteMut.mutate(ds.id);
                        }
                      }}
                      disabled={deleteMut.isPending}
                      className="inline-flex items-center justify-center rounded-md border border-red-900/50 bg-red-950/20 p-1 text-red-400 hover:bg-red-950/40 transition-colors cursor-pointer"
                      title="Delete Source"
                    >
                      <Trash2 className="size-3" />
                    </button>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </div>
      )}

      {/* Add Discovered Source Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-md rounded-xl border border-border bg-bg-elevated p-6 shadow-2xl">
            <h3 className="text-lg font-medium">Add Discovered Source</h3>
            <p className="mt-1 text-sm text-muted">Manually register a new intelligence source for crawling.</p>
            <div className="mt-4 space-y-3">
              <div>
                <label className="block text-xs font-medium text-muted mb-1">Domain *</label>
                <input
                  type="text"
                  value={addDomain}
                  onChange={(e) => {
                    const val = e.target.value;
                    setAddDomain(val);
                    if (!addCrawlPattern || addCrawlPattern.startsWith("https://") && addCrawlPattern.endsWith("/*")) {
                      const clean = val.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
                      setAddCrawlPattern(clean ? `https://${clean}/*` : "");
                    }
                  }}
                  placeholder="e.g. www.sentinelone.com or thedfirreport.com"
                  className="w-full rounded-md border border-border bg-bg-subtle px-3 py-2 text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted mb-1">
                  Scoped Endpoint Pattern * <span className="text-accent text-[11px]">(e.g. www.sentinelone.com/labs/*)</span>
                </label>
                <input
                  type="text"
                  value={addCrawlPattern}
                  onChange={(e) => setAddCrawlPattern(e.target.value)}
                  placeholder="e.g. https://www.sentinelone.com/labs/* or thedfirreport.com/reports/*"
                  className="w-full rounded-md border border-border bg-bg-subtle px-3 py-2 font-mono text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
                />
                <p className="mt-1 text-[11px] text-subtle">
                  Restricts crawling strictly to this research endpoint to avoid collecting marketing, pricing, or false data.
                </p>
              </div>
              <div>
                <label className="block text-xs font-medium text-muted mb-1">Name</label>
                <input
                  type="text"
                  value={addName}
                  onChange={(e) => setAddName(e.target.value)}
                  placeholder="e.g. SentinelLABS or The DFIR Report"
                  className="w-full rounded-md border border-border bg-bg-subtle px-3 py-2 text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted mb-1">Notes</label>
                <textarea
                  value={addNotes}
                  onChange={(e) => setAddNotes(e.target.value)}
                  placeholder="Why should this research endpoint be crawled?"
                  rows={3}
                  className="w-full rounded-md border border-border bg-bg-subtle px-3 py-2 text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none resize-none"
                />
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => setShowAddModal(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={!addDomain.trim() || addSourceMut.isPending}
                onClick={() => {
                  const rawDomain = addDomain.trim().replace(/^https?:\/\//, "").replace(/\/+.*$/, "");
                  let pattern = (addCrawlPattern.trim() || `https://${rawDomain}/*`);
                  if (!pattern.startsWith("http://") && !pattern.startsWith("https://")) {
                    pattern = `https://${pattern}`;
                  }
                  if (!pattern.endsWith("/*")) {
                    pattern = `${pattern.replace(/\/+$/, "")}/*`;
                  }

                  addSourceMut.mutate({
                    domain: rawDomain,
                    name: addName.trim() || rawDomain,
                    crawlPattern: pattern,
                    notes: addNotes.trim(),
                  });
                }}
              >
                {addSourceMut.isPending ? "Adding..." : "Add Source"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
