import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Ban,
  Bot,
  Braces,
  CheckCircle2,
  Database,
  ExternalLink,
  Eye,
  EyeOff,
  FlaskConical,
  GitBranch,
  Globe,
  Info,
  Layers,
  Library,
  Plus,
  Radar,
  RefreshCw,
  Rss,
  Search,
  Shield,
  Sparkles,
  Trash2,
  Zap,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { ActionButton, PageHeader, SectionCard, SegmentedTabs, StatCard, Toolbar } from "@/components/layout/page";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState, Meter, StatusChip, StatusDot, type Tone } from "@/components/ui/primitives";
import { RowMenu, SourceMark, Switch } from "@/components/sources/row-menu";
import { SearchField } from "@/components/ingest/controls";
import { humanize, shortDate } from "@/components/ingest/format";
import { cn } from "@/lib/cn";
import { DocTypeBadge, EntityIcon, entityMeta, type EntityKind } from "@/components/ui/entity";
import {
  getIntelCoverage,
  getSourceRegistry,
  syncStructuredSource,
  classifyLibraryDocTypes,
  type RegistrySourceView,
  type SourceRegistryResponse,
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
import type { ConnectorType, DiscoveredSourceRecord, SourceProbeResult, SourceRecord, SourceTier } from "@/lib/aie/types";
import { getCollectorOverview, startSourceBackfill, type CollectorSourceRow } from "@/lib/aie/server-collector";
import { CollectionHealthView, RegistryHealthLine } from "@/components/collector/collector-ui";

export const Route = createFileRoute("/sources")({ component: SourcesPage });

function SourcesPage() {
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<"registry" | "health" | "curated" | "discovered">("registry");
  const [backfillingId, setBackfillingId] = useState<string | null>(null);
  const [tierFilter, setTierFilter] = useState<"all" | "1" | "2" | "3" | "4">("all");
  const [syncingIds, setSyncingIds] = useState<string[]>([]);
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

  // Tiered registry (seed definitions + live enabled / crawl / sync state)
  const { data: registry, isLoading: registryLoading } = useQuery({
    queryKey: ["source-registry"],
    queryFn: () => getSourceRegistry(),
    staleTime: 30_000,
    placeholderData: (previousData) => previousData,
  });

  // Per-source collection health, yield and schedule (collector)
  const { data: collector, isLoading: collectorLoading } = useQuery({
    queryKey: ["collector-overview"],
    queryFn: () => getCollectorOverview(),
    staleTime: 20_000,
    refetchInterval: 60_000,
    placeholderData: (previousData) => previousData,
  });
  const healthBySource = new Map<string, CollectorSourceRow>((collector?.sources ?? []).map((r) => [r.sourceId, r]));

  const backfillMut = useMutation({
    mutationFn: (input: { sourceId: string; months: 6 | 12 | 24 }) => startSourceBackfill({ data: input }),
    onMutate: (input) => setBackfillingId(input.sourceId),
    onSuccess: (res, input) => {
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
      const name = healthBySource.get(input.sourceId)?.name ?? input.sourceId;
      toast.success(`Backfill started for ${name}`, {
        description: `Since ${res.plan.sinceIso.slice(0, 10)} · up to ${res.plan.maxArticles} articles and ${res.plan.maxListingPages} listing pages · ${(res.plan.hostSpacingMs / 1000).toFixed(1)} s between requests. Follow it on the Ingest page.`,
      });
      void qc.invalidateQueries({ queryKey: ["crawlerState"] });
    },
    onError: (err: Error) => toast.error(`Backfill failed to start: ${err.message}`),
    onSettled: () => {
      setBackfillingId(null);
      void qc.invalidateQueries({ queryKey: ["collector-overview"] });
    },
  });

  const { data: coverage } = useQuery({
    queryKey: ["intel-coverage"],
    queryFn: () => getIntelCoverage(),
    staleTime: 60_000,
    placeholderData: (previousData) => previousData,
  });

  const syncMut = useMutation({
    mutationFn: (sourceId: string) => syncStructuredSource({ data: { sourceId } }),
    onMutate: (sourceId) => setSyncingIds((ids) => [...ids, sourceId]),
    onSuccess: (res) => {
      if (res.ok) {
        toast.success(res.message, {
          description: res.warnings?.length ? `${res.warnings.length} warning${res.warnings.length === 1 ? "" : "s"}: ${res.warnings[0]}` : undefined,
        });
      } else if (res.requiresMongo) {
        toast.warning("Requires MongoDB", { description: res.message });
      } else {
        toast.error(res.message);
      }
    },
    onError: (err: Error) => toast.error(`Sync failed: ${err.message}`),
    onSettled: (_res, _err, sourceId) => {
      setSyncingIds((ids) => ids.filter((id) => id !== sourceId));
      void qc.invalidateQueries({ queryKey: ["source-registry"] });
      void qc.invalidateQueries({ queryKey: ["intel-coverage"] });
      void qc.invalidateQueries({ queryKey: ["reports"] });
    },
  });

  const classifyMut = useMutation({
    mutationFn: () => classifyLibraryDocTypes({ data: { limit: 500 } }),
    onSuccess: (res) => {
      if (!res.ok) toast.warning("Requires MongoDB", { description: res.message });
      else toast.success(res.message, { description: res.remaining ? `${res.remaining} still to classify — run again.` : "All stored reports carry document types." });
      void qc.invalidateQueries({ queryKey: ["intel-coverage"] });
    },
    onError: (err: Error) => toast.error(`Classification failed: ${err.message}`),
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
      void qc.invalidateQueries({ queryKey: ["source-registry"] });
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
      header: () => <span className="relative"><span className="sr-only">Actions</span></span>,
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
        description="A tiered intelligence registry: authoritative structured data (ATT&CK, KEV, CERT advisories), adversary-emulation content, research publishers and community sources — each with its connector, the document types it yields and a confidence class."
        actions={
          <div className="flex flex-wrap items-center gap-2 md:flex-nowrap [&>*]:whitespace-nowrap">
            {activeTab === "registry" && registry?.persistence === "mongodb" && (coverage?.unclassified ?? 0) > 0 && (
              <ActionButton
                icon={Layers}
                disabled={classifyMut.isPending}
                onClick={() => classifyMut.mutate()}
                title="Assign document types, source tier and confidence to reports stored before classification existed"
              >
                {classifyMut.isPending ? "Classifying…" : `Classify ${coverage?.unclassified.toLocaleString()} reports`}
              </ActionButton>
            )}
            <ActionButton
              icon={probeMut.isPending ? undefined : Zap}
              disabled={probeMut.isPending}
              onClick={() => {
                const currentList = activeTab === "discovered" ? filteredDiscovered : filteredSources;
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
              { value: "registry", label: "Registry", icon: Library, count: registry?.sources.length },
              { value: "health", label: "Health", icon: Radar, count: collector?.failing || undefined },
              { value: "curated", label: "Curated", icon: Shield, count: filteredSources.length },
              { value: "discovered", label: "Discovered", icon: Globe, count: filteredDiscovered.length },
            ]}
          />
        }
      />

      {activeTab === "registry" ? (
        <RegistryStats registry={registry} coverage={coverage} />
      ) : activeTab === "health" ? null : (
        <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard icon={Shield} label="Curated sources" value={(sources ?? []).length} />
          <StatCard icon={Eye} label="Active curated" value={curatedActive} />
          <StatCard icon={Globe} label="Discovered sources" value={(discoveredSources ?? []).length} />
          <StatCard icon={CheckCircle2} label="Reports collected" value={reportsCollected.toLocaleString()} />
        </div>
      )}

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
            {activeTab === "registry" && (
              <SegmentedTabs
                size="sm"
                ariaLabel="Filter by tier"
                value={tierFilter}
                onChange={setTierFilter}
                items={[
                  { value: "all", label: "All tiers" },
                  { value: "1", label: "Tier 1" },
                  { value: "2", label: "Tier 2" },
                  { value: "3", label: "Tier 3" },
                  { value: "4", label: "Tier 4" },
                ]}
              />
            )}
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

      {activeTab === "registry" && (
        <RegistryView
          registry={registry}
          loading={registryLoading && !registry}
          query={searchQuery}
          tier={tierFilter}
          discoveredCount={(discoveredSources ?? []).length}
          syncingIds={syncingIds}
          probeResults={probeResults}
          onSync={(id) => syncMut.mutate(id)}
          onToggle={(id, enabled) => toggleMut.mutate({ id, enabled })}
          onShowDiscovered={() => setActiveTab("discovered")}
          health={healthBySource}
        />
      )}

      {activeTab === "health" && (
        <CollectionHealthView
          overview={collector}
          loading={collectorLoading}
          query={searchQuery}
          backfillingId={backfillingId}
          onBackfill={(sourceId, months) => backfillMut.mutate({ sourceId, months })}
        />
      )}

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

// ---------------------------------------------------------------------------
// Tiered registry
// ---------------------------------------------------------------------------

type IntelCoverageView = Awaited<ReturnType<typeof getIntelCoverage>>;

const TIER_KIND: Record<SourceTier, EntityKind> = { 1: "advisory", 2: "emulation", 3: "technique", 4: "source" };
const TIER_ICON: Record<SourceTier, typeof Shield> = { 1: Shield, 2: FlaskConical, 3: Search, 4: Globe };

const CONNECTOR_META: Record<ConnectorType, { label: string; icon: typeof Rss; hint: string }> = {
  stix_bundle: { label: "STIX bundle", icon: Database, hint: "Official STIX 2.1 bundle, parsed into structured records" },
  github_repo: { label: "GitHub repo", icon: GitBranch, hint: "Repository files via the GitHub tree API and raw content" },
  json_feed: { label: "JSON feed", icon: Braces, hint: "Machine-readable JSON feed" },
  rss: { label: "RSS feed", icon: Rss, hint: "Feed polled by the crawler" },
  html: { label: "HTML archive", icon: Globe, hint: "Research archive pages crawled within the endpoint pattern" },
  search: { label: "Search", icon: Search, hint: "Search-driven discovery" },
};

function TierBadge({ tier }: { tier: SourceTier }) {
  const color = entityMeta(TIER_KIND[tier]).color;
  return (
    <span
      className="inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[11px] font-semibold tabular-nums"
      style={{ color, backgroundColor: `color-mix(in oklab, ${color} 16%, transparent)` }}
    >
      T{tier}
    </span>
  );
}

function ConnectorChip({ connector }: { connector: ConnectorType }) {
  const meta = CONNECTOR_META[connector] ?? CONNECTOR_META.html;
  const Icon = meta.icon;
  return (
    <span
      title={meta.hint}
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-xs text-muted"
    >
      <Icon className="size-3.5" strokeWidth={1.75} />
      {meta.label}
    </span>
  );
}

function ConfidenceMeter({ value, cls }: { value: number; cls: string }) {
  return (
    <div className="flex w-full items-center gap-2" title={`${humanize(cls)} · confidence weight ${value.toFixed(2)}`}>
      <Meter value={value} tone={value >= 0.95 ? "success" : value >= 0.85 ? "info" : value >= 0.7 ? "warning" : "danger"} label="Source confidence" />
      <span className="w-8 shrink-0 text-right text-xs tabular-nums text-muted">{value.toFixed(2)}</span>
    </div>
  );
}

function SyncStatus({ s }: { s: RegistrySourceView }) {
  if (s.structured) {
    if (s.lastSyncError) {
      return (
        <span title={s.lastSyncError}>
          <StatusChip tone="danger" dot>
            Sync failed
          </StatusChip>
        </span>
      );
    }
    if (s.lastSyncAt) {
      const warn = s.lastSyncWarnings?.length ?? 0;
      return (
        <div className="flex flex-col items-start gap-0.5">
          <StatusChip tone={warn ? "warning" : "success"} dot>
            {(s.lastSyncCount ?? 0).toLocaleString()} records
          </StatusChip>
          <span className="text-xs text-subtle tabular-nums" title={warn ? s.lastSyncWarnings?.join("\n") : undefined}>
            Synced {shortDate(s.lastSyncAt)}
            {warn ? ` · ${warn} warning${warn === 1 ? "" : "s"}` : ""}
          </span>
        </div>
      );
    }
    return <StatusChip tone="neutral">Not synced</StatusChip>;
  }
  if (!s.enabled) {
    const unverified = /unverified|until/i.test(s.notes);
    return (
      <span title={s.notes}>
        <StatusChip tone={unverified ? "warning" : "neutral"}>{unverified ? "Needs review" : "Paused"}</StatusChip>
      </span>
    );
  }
  return (
    <div className="flex flex-col items-start gap-0.5">
      <StatusChip tone={(s.resourceCount ?? 0) > 0 ? "success" : "neutral"} dot>
        {(s.resourceCount ?? 0).toLocaleString()} reports
      </StatusChip>
      <span className="text-xs text-subtle tabular-nums">{s.lastIngestAt ? `Crawled ${shortDate(s.lastIngestAt)}` : "Awaiting first crawl"}</span>
    </div>
  );
}

function RegistryRow({
  s,
  syncing,
  probe,
  onSync,
  onToggle,
  health,
}: {
  health?: CollectorSourceRow;
  s: RegistrySourceView;
  syncing: boolean;
  probe?: SourceProbeResult;
  onSync: () => void;
  onToggle: (enabled: boolean) => void;
}) {
  const host = s.homepageUrl.replace(/^https?:\/\//, "").replace(/\/+$/, "");
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-4 gap-y-3 px-5 py-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1.4fr)_9rem_9.5rem_auto] lg:items-center">
      <div className="flex min-w-0 items-start gap-3">
        <TierBadge tier={s.tier} />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-medium text-fg">{s.name}</span>
            <ConnectorChip connector={s.connector ?? "html"} />
          </div>
          <a
            href={s.homepageUrl}
            target="_blank"
            rel="noreferrer"
            className="mt-0.5 inline-flex max-w-full items-center gap-1 text-xs text-subtle hover:text-fg"
          >
            <span className="truncate">{host}</span>
            <ExternalLink className="size-3 shrink-0" />
          </a>
          <p className="mt-1 line-clamp-2 text-xs text-muted" title={s.notes}>
            {s.notes}
          </p>
          {probe && (
            <div className="mt-1">
              <StatusDot tone={probe.reachable ? "success" : "danger"}>
                {probe.reachable ? `Feed online · ${probe.latencyMs} ms` : `Feed offline${probe.error ? ` · ${probe.error}` : ""}`}
              </StatusDot>
            </div>
          )}
        </div>
      </div>

      <div className="order-last col-span-2 flex flex-wrap gap-1.5 lg:order-none lg:col-span-1">
        {(s.yields ?? []).map((t) => (
          <DocTypeBadge key={t} type={t} />
        ))}
      </div>

      <div className="col-span-2 flex items-center gap-3 lg:col-span-1 lg:block">
        <span className="text-xs text-subtle lg:hidden">Confidence</span>
        <ConfidenceMeter value={s.confidence} cls={s.confidenceClass} />
        <div className="hidden truncate text-[11px] text-subtle lg:mt-1 lg:block">
          {humanize(s.confidenceClass)} · {s.schedule}
        </div>
      </div>

      <div className="col-span-2 lg:col-span-1">
        <SyncStatus s={s} />
        {!s.structured && s.enabled && <RegistryHealthLine row={health} />}
      </div>

      <div className="row-start-1 col-start-2 flex items-center justify-end gap-2 lg:row-auto lg:col-auto">
        {s.structured ? (
          <ActionButton icon={syncing ? undefined : RefreshCw} disabled={syncing} onClick={onSync} title={`Run the ${s.name} connector now`}>
            {syncing ? (
              <>
                <ActivitySpinner size="xs" className="text-accent" />
                <span>Syncing…</span>
              </>
            ) : (
              "Sync now"
            )}
          </ActionButton>
        ) : (
          <Switch checked={s.enabled} label={s.enabled ? `Pause ${s.name}` : `Enable ${s.name}`} onChange={onToggle} />
        )}
      </div>
    </li>
  );
}

function RegistryStats({ registry, coverage }: { registry?: SourceRegistryResponse; coverage?: IntelCoverageView }) {
  const list = registry?.sources ?? [];
  const structured = list.filter((s) => s.structured);
  const synced = structured.filter((s) => s.lastSyncAt && !s.lastSyncError).length;
  const tierCounts = ([1, 2, 3, 4] as SourceTier[]).map((t) => list.filter((s) => s.tier === t).length);
  const emulationTechniques = coverage?.emulationTechniques ?? 0;
  return (
    <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        icon={Library}
        kind="source"
        label="Registry sources"
        value={list.length || "—"}
        hint={list.length ? `T1 ${tierCounts[0]} · T2 ${tierCounts[1]} · T3 ${tierCounts[2]} · T4 ${tierCounts[3]}` : undefined}
      />
      <StatCard
        icon={Database}
        kind="advisory"
        label="Structured connectors"
        value={structured.length || "—"}
        hint={registry?.structuredSyncAvailable ? `${synced} of ${structured.length} synced` : "Sync requires MongoDB"}
      />
      <StatCard
        icon={FlaskConical}
        kind="emulation"
        label="Emulation coverage"
        value={emulationTechniques ? emulationTechniques.toLocaleString() : "—"}
        hint={emulationTechniques ? `techniques with atomic tests, CALDERA, CTID or flow procedures` : "Sync Tier 2 sources to index emulation options"}
      />
      <StatCard
        icon={Layers}
        kind="technique"
        label="Library documents"
        value={coverage ? coverage.total.toLocaleString() : "—"}
        hint={
          coverage
            ? `${Object.keys(coverage.byDocType).length} document types${coverage.structured ? ` · ${coverage.structured.toLocaleString()} structured` : ""}`
            : undefined
        }
      />
    </div>
  );
}

function RegistryView({
  registry,
  loading,
  query,
  tier,
  discoveredCount,
  syncingIds,
  probeResults,
  onSync,
  onToggle,
  onShowDiscovered,
  health,
}: {
  health?: Map<string, CollectorSourceRow>;
  registry?: SourceRegistryResponse;
  loading: boolean;
  query: string;
  tier: "all" | "1" | "2" | "3" | "4";
  discoveredCount: number;
  syncingIds: string[];
  probeResults: Record<string, SourceProbeResult>;
  onSync: (id: string) => void;
  onToggle: (id: string, enabled: boolean) => void;
  onShowDiscovered: () => void;
}) {
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-bg-card py-16 text-muted">
        <ActivitySpinner size="lg" className="mb-2 text-accent" />
        <p className="text-sm">Loading source registry…</p>
      </div>
    );
  }
  if (!registry) {
    return <EmptyState icon={Library} title="Registry unavailable" description="The source registry could not be loaded. Try again shortly." />;
  }
  const q = query.trim().toLowerCase();
  const matches = (s: RegistrySourceView) =>
    !q ||
    s.name.toLowerCase().includes(q) ||
    s.homepageUrl.toLowerCase().includes(q) ||
    (s.yields ?? []).some((y) => y.toLowerCase().includes(q.replace(/\s+/g, "_"))) ||
    (s.connector ?? "").includes(q);
  const tiers = ([1, 2, 3, 4] as SourceTier[]).filter((t) => tier === "all" || String(t) === tier);

  return (
    <div className="space-y-5">
      {!registry.structuredSyncAvailable && (
        <div
          role="note"
          className="flex items-start gap-3 rounded-xl border px-4 py-3 text-sm"
          style={{
            borderColor: "color-mix(in oklab, var(--color-info) 35%, transparent)",
            backgroundColor: "color-mix(in oklab, var(--color-info) 8%, transparent)",
          }}
        >
          <Info className="mt-0.5 size-4 shrink-0" style={{ color: "var(--color-info)" }} />
          <div>
            <div className="font-medium text-fg">Structured sync requires MongoDB</div>
            <p className="mt-0.5 text-muted">
              This workspace is using local storage. ATT&CK, emulation-plan, attack-flow and KEV connectors store their records and
              emulation indexes in MongoDB — configure it to enable “Sync now”. Feed sources below still crawl normally.
            </p>
          </div>
        </div>
      )}

      {tiers.map((t) => {
        const meta = registry.tiers[t];
        const rows = registry.sources.filter((s) => s.tier === t && matches(s));
        const all = registry.sources.filter((s) => s.tier === t);
        const TierIcon = TIER_ICON[t];
        if (q && rows.length === 0) return null;
        return (
          <SectionCard
            key={t}
            icon={TierIcon}
            iconKind={TIER_KIND[t]}
            title={
              <span className="flex flex-wrap items-center gap-2">
                {meta.label}
                <span className="rounded bg-bg-subtle px-1.5 py-px font-mono text-[10px] text-subtle tabular-nums">{all.length}</span>
              </span>
            }
            actions={<span className="hidden text-xs text-subtle md:inline">{meta.description}</span>}
            bodyClassName="p-0 pt-3"
          >
            <p className="px-5 pb-2 text-xs text-subtle md:hidden">{meta.description}</p>
            <div className="hidden border-y border-border bg-bg-subtle/40 px-5 py-2 text-[11px] font-medium uppercase tracking-wide text-subtle lg:grid lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1.4fr)_9rem_9.5rem_auto] lg:gap-x-4">
              <span>Source · connector</span>
              <span>Yields</span>
              <span>Confidence</span>
              <span>Status</span>
              <span className="w-24 text-right">Action</span>
            </div>
            {rows.length > 0 && (
              <ul className="divide-y divide-border">
                {rows.map((s) => (
                  <RegistryRow
                    key={s.id}
                    s={s}
                    syncing={syncingIds.includes(s.id)}
                    probe={probeResults[s.id]}
                    onSync={() => onSync(s.id)}
                    onToggle={(enabled) => onToggle(s.id, enabled)}
                    health={health?.get(s.id)}
                  />
                ))}
              </ul>
            )}
            {t === 4 ? (
              <div className="flex flex-col items-start gap-3 border-t border-border px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                  <EntityIcon kind="source" />
                  <p className="text-sm text-muted">
                    {discoveredCount
                      ? `${discoveredCount} community sources found by the crawler and AI agent join this tier at a lower confidence.`
                      : "Community sources discovered by the crawler or AI agent join this tier at a lower confidence."}
                  </p>
                </div>
                <ActionButton icon={Globe} onClick={onShowDiscovered}>
                  Review discovered
                </ActionButton>
              </div>
            ) : (
              rows.length === 0 && <p className="px-5 py-5 text-sm text-muted">No sources in this tier.</p>
            )}
          </SectionCard>
        );
      })}
    </div>
  );
}
