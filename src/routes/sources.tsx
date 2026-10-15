import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Ban,
  Bot,
  CheckCircle2,
  ExternalLink,
  Eye,
  EyeOff,
  Globe,
  Plus,
  Search,
  Shield,
  Sparkles,
  Trash2,
  Zap,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { ActionButton, PageHeader, SegmentedTabs, StatCard, Toolbar } from "@/components/layout/page";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState, Meter, StatusChip, StatusDot, type Tone } from "@/components/ui/primitives";
import { RowMenu, SourceMark, Switch } from "@/components/sources/row-menu";
import { SearchField } from "@/components/ingest/controls";
import { humanize, shortDate } from "@/components/ingest/format";
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
      toast.success("Feed probe complete", {
        description: `Checked ${data.summary.total} sources: ${data.summary.healthy} online, ${data.summary.degraded} degraded or offline.`,
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

  const originLabel = (origin?: string) => {
    switch (origin) {
      case "agent_discovery":
        return { label: "AI agent", icon: Bot };
      case "crawler_outlink":
        return { label: "Crawler", icon: Globe };
      case "manual":
        return { label: "Manual", icon: Plus };
      case "citation_expansion":
        return { label: "Citation", icon: Search };
      default:
        return { label: origin ? origin.replace(/_/g, " ") : "Unknown", icon: Globe };
    }
  };

  const statusTone = (status: string): Tone => {
    switch (status) {
      case "verified":
      case "approved":
        return "success";
      case "discovered":
      case "evaluated":
        return "info";
      case "ignored":
      case "rejected":
        return "danger";
      default:
        return "neutral";
    }
  };

  const healthCell = (id: string, enabled: boolean) => {
    const probe = probeResults[id];
    if (probe) {
      return (
        <span title={probe.reachable ? `HTTP ${probe.statusCode} in ${probe.latencyMs}ms` : probe.error || "Unreachable"}>
          <StatusDot tone={probe.reachable ? "success" : "danger"}>
            {probe.reachable ? `${probe.latencyMs} ms · ${probe.statusCode}` : "Offline"}
          </StatusDot>
        </span>
      );
    }
    return <StatusDot tone={enabled ? "success" : "neutral"}>{enabled ? "Active" : "Paused"}</StatusDot>;
  };

  const hostOf = (url: string) => url.replace(/^https?:\/\//, "").replace(/\/+$/, "");

  const curatedColumns: ColumnDef<SourceRecord, any>[] = [
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ row }) => {
        const s = row.original;
        return (
          <div className="flex min-w-0 items-center gap-3">
            <SourceMark name={s.name} />
            <div className="min-w-0">
              <div className="max-w-[170px] truncate font-medium text-fg sm:max-w-none" title={s.notes || s.name}>{s.name}</div>
              <a
                href={s.homepageUrl}
                target="_blank"
                rel="noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex max-w-[170px] items-center gap-1 text-xs text-subtle hover:text-fg sm:max-w-[260px]"
              >
                <span className="truncate">{hostOf(s.homepageUrl)}</span>
                <ExternalLink className="size-3 shrink-0" />
              </a>
            </div>
          </div>
        );
      },
      meta: { className: "max-w-[320px]" },
    },
    {
      accessorKey: "category",
      header: "Category",
      cell: ({ getValue }) => <span className="text-muted">{humanize(getValue() as string)}</span>,
      meta: { hideBelow: "md" },
    },
    {
      id: "feed",
      header: "Feed",
      accessorFn: (s) => (s.feedUrl ? "RSS" : "HTML"),
      cell: ({ row, getValue }) => (
        <span className="text-muted" title={row.original.feedUrl || row.original.crawlPattern || row.original.homepageUrl}>
          {getValue() as string}
        </span>
      ),
      meta: { hideBelow: "lg" },
    },
    {
      id: "reports",
      header: "Reports",
      accessorFn: (s) => s.resourceCount ?? 0,
      cell: ({ getValue }) => <span className="tabular-nums">{(getValue() as number).toLocaleString()}</span>,
      meta: { align: "right", hideBelow: "sm" },
    },
    {
      accessorKey: "lastIngestAt",
      header: "Last crawl",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted tabular-nums">{shortDate(getValue() as string | null)}</span>,
      meta: { hideBelow: "lg" },
    },
    {
      id: "status",
      header: "Status",
      accessorFn: (s) => (probeResults[s.id] ? (probeResults[s.id].reachable ? 1 : 0) : s.enabled ? 1 : 0),
      cell: ({ row }) => healthCell(row.original.id, row.original.enabled),
      meta: { hideBelow: "md" },
    },
    {
      accessorKey: "enabled",
      header: "Enabled",
      cell: ({ row }) => (
        <Switch
          checked={row.original.enabled}
          label={row.original.enabled ? `Pause ${row.original.name}` : `Enable ${row.original.name}`}
          onChange={(enabled) => toggleMut.mutate({ id: row.original.id, enabled })}
        />
      ),
      meta: { align: "right", className: "w-20" },
    },
  ];

  const discoveredColumns: ColumnDef<DiscoveredSourceRecord, any>[] = [
    {
      accessorKey: "domain",
      header: "Domain",
      cell: ({ row }) => {
        const ds = row.original;
        return (
          <div className="flex min-w-0 items-center gap-3">
            <SourceMark name={ds.domain} />
            <div className="min-w-0">
              <a
                href={ds.homepageUrl}
                target="_blank"
                rel="noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex max-w-[240px] items-center gap-1 font-mono text-[13px] text-fg hover:text-accent"
                title={ds.crawlPattern || `https://${ds.domain}/*`}
              >
                <span className="truncate">{ds.domain}</span>
                <ExternalLink className="size-3 shrink-0 text-subtle" />
              </a>
              <div className="truncate text-xs text-subtle sm:hidden">{ds.name}</div>
            </div>
          </div>
        );
      },
      meta: { className: "max-w-[300px]" },
    },
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ row }) => (
        <div className="min-w-0 max-w-[260px]">
          <div className="truncate text-fg">{row.original.name}</div>
          {(row.original.notes || row.original.whyCrawl) && (
            <div className="truncate text-xs text-subtle" title={row.original.notes || row.original.whyCrawl}>
              {row.original.notes || row.original.whyCrawl}
            </div>
          )}
        </div>
      ),
      meta: { hideBelow: "sm" },
    },
    {
      id: "origin",
      header: "Origin",
      accessorFn: (ds) => originLabel(ds.origin).label,
      cell: ({ row }) => {
        const o = originLabel(row.original.origin);
        const Icon = o.icon;
        return (
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-muted">
            <Icon className="size-3.5" strokeWidth={1.75} />
            {o.label}
          </span>
        );
      },
      meta: { hideBelow: "lg" },
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => (
        <StatusChip tone={row.original.enabled === false ? "neutral" : statusTone(row.original.status)} dot>
          {row.original.enabled === false ? "Paused" : humanize(row.original.status)}
        </StatusChip>
      ),
    },
    {
      id: "quality",
      header: "Quality",
      accessorFn: (ds) => (ds.trustScore > 1 ? ds.trustScore / 100 : ds.trustScore),
      cell: ({ getValue }) => {
        const v = getValue() as number;
        return (
          <div className="flex w-28 items-center gap-2">
            <Meter value={v} tone={v >= 0.8 ? "success" : v >= 0.5 ? "info" : "warning"} label="Trust score" />
            <span className="w-9 shrink-0 text-right text-xs tabular-nums text-muted">{Math.round(v * 100)}%</span>
          </div>
        );
      },
      meta: { hideBelow: "md" },
    },
    {
      id: "health",
      header: "Health",
      accessorFn: (ds) => (probeResults[ds.id]?.reachable ? 1 : 0),
      cell: ({ row }) => healthCell(row.original.id, row.original.enabled !== false),
      meta: { hideBelow: "xl" },
    },
    {
      accessorKey: "firstDiscoveredAt",
      header: "Discovered",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted tabular-nums">{shortDate(getValue() as string)}</span>,
      meta: { hideBelow: "lg" },
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      enableSorting: false,
      cell: ({ row }) => {
        const ds = row.original;
        const verified = ds.status === "verified" || ds.status === "approved";
        const enabled = ds.enabled !== false;
        return (
          <RowMenu
            label={`Actions for ${ds.domain}`}
            items={[
              {
                label: "Validate",
                icon: CheckCircle2,
                hidden: verified,
                disabled: validateMut.isPending,
                onSelect: () => validateMut.mutate(ds.id),
              },
              {
                label: "Revoke",
                icon: Ban,
                disabled: revokeMut.isPending,
                onSelect: () => {
                  if (confirm(`Revoke source "${ds.name}"? This will pause it and mark it as rejected.`)) {
                    revokeMut.mutate(ds.id);
                  }
                },
              },
              {
                label: enabled ? "Disable" : "Enable",
                icon: enabled ? EyeOff : Eye,
                onSelect: () => toggleDiscoveredMut.mutate({ id: ds.id, enabled: !enabled }),
              },
              {
                label: "Open homepage",
                icon: ExternalLink,
                onSelect: () => window.open(ds.homepageUrl, "_blank", "noopener,noreferrer"),
              },
              {
                label: "Delete",
                icon: Trash2,
                danger: true,
                separated: true,
                disabled: deleteMut.isPending,
                onSelect: () => {
                  if (confirm(`Permanently delete source "${ds.name}"? This cannot be undone.`)) {
                    deleteMut.mutate(ds.id);
                  }
                },
              },
            ]}
          />
        );
      },
      meta: { align: "right", className: "w-12" },
    },
  ];

  const curatedActive = (sources ?? []).filter((s) => s.enabled).length;
  const reportsCollected = (sources ?? []).reduce((sum, s) => sum + (s.resourceCount ?? 0), 0);
  const probeList = Object.values(probeResults);
  const probeOnline = probeList.filter((p) => p.reachable).length;

  return (
    <AppShell>
      <PageHeader
        title="Sources"
        description="Curated sources are the protected baseline publishers. Discovered sources come from the crawler or the AI agent and can be reviewed, toggled or revoked."
        actions={
          <div className="flex flex-wrap items-center gap-2 md:flex-nowrap [&>*]:whitespace-nowrap">
            <ActionButton
              icon={probeMut.isPending ? undefined : Zap}
              disabled={probeMut.isPending}
              onClick={() => {
                const currentList = activeTab === "curated" ? filteredSources : filteredDiscovered;
                const ids = currentList.map((s) => s.id);
                probeMut.mutate(ids.length > 0 ? ids : undefined);
              }}
              title="Probe HTTP latency and reachability across feeds with 6 parallel workers"
            >
              {probeMut.isPending ? (
                <>
                  <ActivitySpinner size="xs" className="text-accent" />
                  <span>Probing feeds…</span>
                </>
              ) : (
                "Probe feeds"
              )}
            </ActionButton>
            {activeTab === "discovered" && (
              <>
                <ActionButton icon={Plus} onClick={() => setShowAddModal(true)}>
                  Add source
                </ActionButton>
                <ActionButton
                  variant="primary"
                  icon={Sparkles}
                  disabled={discoverMut.isPending || !agentStatus?.available}
                  onClick={() => discoverMut.mutate()}
                >
                  {discoverMut.isPending ? "Discovering…" : "AI discover"}
                </ActionButton>
              </>
            )}
          </div>
        }
        tabs={
          <SegmentedTabs
            ariaLabel="Source registry"
            value={activeTab}
            onChange={setActiveTab}
            items={[
              { value: "curated", label: "Curated", icon: Shield, count: filteredSources.length },
              { value: "discovered", label: "Discovered", icon: Globe, count: filteredDiscovered.length },
            ]}
          />
        }
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Shield} label="Curated sources" value={(sources ?? []).length} />
        <StatCard icon={Eye} label="Active curated" value={curatedActive} />
        <StatCard icon={Globe} label="Discovered sources" value={(discoveredSources ?? []).length} />
        <StatCard icon={CheckCircle2} label="Reports collected" value={reportsCollected.toLocaleString()} />
      </div>

      <Toolbar
        left={
          <SearchField
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search sources…"
            label="Search sources"
            className="sm:w-80"
          />
        }
        right={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
            {probeList.length > 0 && (
              <span className="tabular-nums">
                Probe: {probeOnline} online · {probeList.length - probeOnline} offline
              </span>
            )}
            {activeTab === "discovered" && agentStatus && (
              <StatusDot tone={agentStatus.available ? "success" : "danger"}>
                AI agent {agentStatus.available ? `v${agentStatus.version} available` : "unavailable"}
                {agentStatus.available && agentStatus.platform ? ` · ${agentStatus.platform}` : ""}
              </StatusDot>
            )}
          </div>
        }
      />

      {activeTab === "curated" && (
        <DataTable
          data={filteredSources}
          columns={curatedColumns}
          getRowId={(s) => s.id}
          caption="Curated sources"
          empty={
            <EmptyState
              icon={Shield}
              title="No curated sources match"
              description={searchQuery ? "Try a different search." : "Curated sources will appear here once seeded."}
            />
          }
        />
      )}

      {activeTab === "discovered" &&
        (discoveredLoading && !discoveredSources ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-bg-card py-16 text-muted">
            <ActivitySpinner size="lg" className="mb-2 text-accent" />
            <p className="text-sm">Loading discovered sources…</p>
          </div>
        ) : (
          <DataTable
            data={filteredDiscovered}
            columns={discoveredColumns}
            getRowId={(ds) => ds.id}
            caption="Discovered sources"
            empty={
              <EmptyState
                icon={Globe}
                title="No discovered sources yet"
                description="Run a crawl job or use AI discover to find new sources."
              />
            }
          />
        ))}

      {/* Add Discovered Source Modal */}
      {showAddModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onKeyDown={(e) => {
            if (e.key === "Escape") setShowAddModal(false);
          }}
        >
          <div role="dialog" aria-modal="true" aria-labelledby="add-source-title" className="w-full max-w-md rounded-xl border border-border bg-bg-elevated p-6 shadow-2xl">
            <h3 id="add-source-title" className="text-lg font-medium">Add discovered source</h3>
            <p className="mt-1 text-sm text-muted">Register a new intelligence source for crawling.</p>
            <div className="mt-4 space-y-3">
              <div>
                <label htmlFor="add-domain" className="mb-1 block text-sm text-muted">Domain</label>
                <input
                  id="add-domain"
                  type="text"
                  autoFocus
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
                  className={INPUT_CLS}
                />
              </div>
              <div>
                <label htmlFor="add-pattern" className="mb-1 block text-sm text-muted">Scoped endpoint pattern</label>
                <input
                  id="add-pattern"
                  type="text"
                  value={addCrawlPattern}
                  onChange={(e) => setAddCrawlPattern(e.target.value)}
                  placeholder="e.g. https://www.sentinelone.com/labs/*"
                  className={cn(INPUT_CLS, "font-mono")}
                />
                <p className="mt-1 text-xs text-subtle">
                  Crawling stays inside this research endpoint, so marketing and pricing pages are skipped.
                </p>
              </div>
              <div>
                <label htmlFor="add-name" className="mb-1 block text-sm text-muted">Name</label>
                <input
                  id="add-name"
                  type="text"
                  value={addName}
                  onChange={(e) => setAddName(e.target.value)}
                  placeholder="e.g. SentinelLABS or The DFIR Report"
                  className={INPUT_CLS}
                />
              </div>
              <div>
                <label htmlFor="add-notes" className="mb-1 block text-sm text-muted">Notes</label>
                <textarea
                  id="add-notes"
                  value={addNotes}
                  onChange={(e) => setAddNotes(e.target.value)}
                  placeholder="Why should this research endpoint be crawled?"
                  rows={3}
                  className={cn(INPUT_CLS, "h-auto resize-none py-2")}
                />
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <ActionButton variant="ghost" onClick={() => setShowAddModal(false)}>
                Cancel
              </ActionButton>
              <ActionButton
                variant="primary"
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
                {addSourceMut.isPending ? "Adding…" : "Add source"}
              </ActionButton>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}

const INPUT_CLS =
  "h-9 w-full rounded-lg border border-border bg-bg-subtle px-3 text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none";
