import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import { useState } from "react";
import { toast } from "sonner";
import {
  Activity,
  Bot,
  CheckCircle2,
  Compass,
  Crosshair,
  Database,
  Download,
  ExternalLink,
  FileText,
  Flame,
  GitBranch,
  Globe,
  Layers,
  Library,
  Network,
  Play,
  Settings,
  Square,
  Upload,
  X,
  XCircle,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { ActionButton, PageHeader, SectionCard, SegmentedTabs, StatCard, Toolbar } from "@/components/layout/page";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState, Meter, PropertyList, StatusChip, StatusDot, type Tone } from "@/components/ui/primitives";
import { Input, Textarea } from "@/components/ui/input";
import { RowMenu } from "@/components/sources/row-menu";
import { FilterSelect, PaginationControls, SearchField, SectionHeading } from "@/components/ingest/controls";
import { humanize, paginateList, shortDate } from "@/components/ingest/format";
import {
  formatAuditId,
  formatDomainId,
  formatEdgeId,
  formatJobId,
  formatOutcomeId,
  formatSourceId,
  formatSystemId,
} from "@/lib/aie/ids";
import {
  batchIngestDiscoveredUrls,
  batchRejectDiscoveredUrls,
  cancelCrawlJob,
  exportSTIXBundle,
  getCrawlerState,
  ingestDiscoveredUrl,
  ingestUrl,
  listCatalog,
  triggerCrawlJob,
} from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";
import type { CrawlConfig } from "@/lib/aie/types";

export const Route = createFileRoute("/ingest")({ component: IngestPage });

const VIEWS = [
  { id: "crawler", label: "Crawler", icon: Bot },
  { id: "queue", label: "Discovery queue", icon: Compass },
  { id: "graph", label: "Sources & graph", icon: Network },
  { id: "audit", label: "Audit log", icon: Activity },
  { id: "manual", label: "Manual ingest", icon: Upload },
  { id: "catalog", label: "Curated catalog", icon: Database },
] as const;

const DEFAULT_CRAWL_CONFIG: CrawlConfig = {
  id: "cfg_default",
  enabled: true,
  paused: false,
  frequencyMinutes: 360,
  startHour: "09:00",
  maxResourcesPerRun: 35,
  maxResourcesPerJob: 35,
  maxRunTimeMinutes: 5,
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

function isItemAwaitingApproval(status?: string | null, decision?: string | null): boolean {
  const s = (status || decision || "").toLowerCase().trim();
  return (
    s === "awaiting_approval" ||
    s === "awaiting approval" ||
    s === "pending_approval" ||
    s === "pending approval"
  );
}

function formatResourceKind(kind?: string): { label: string; tone: "accent" | "warn" | "sage" | "neutral" } {
  const k = (kind || "").toUpperCase().trim();
  if (k.includes("ATTACK_CHAIN") || k.includes("INTRUSION")) {
    return { label: "Attack Chains", tone: "accent" };
  }
  if (k.includes("MALWARE")) {
    return { label: "Malware Analysis", tone: "warn" };
  }
  if (k.includes("EMULATION") || k.includes("PROCEDURE") || k.includes("PURPLE")) {
    return { label: "Procedures & TTPs", tone: "accent" };
  }
  if (k.includes("DETECTION") || k.includes("SIGMA")) {
    return { label: "Detections & Sigma", tone: "sage" };
  }
  if (k.includes("VULNERABILITY") || k.includes("CVE")) {
    return { label: "Vulnerability Advisories", tone: "warn" };
  }
  if (k.includes("THREAT_ACTOR")) {
    return { label: "Threat Actor Dossiers", tone: "neutral" };
  }
  return { label: "Campaigns", tone: "neutral" };
}

function IngestPage() {
  const qc = useQueryClient();
  const [activeView, setActiveView] = useState<(typeof VIEWS)[number]["id"]>("crawler");

  // Targeted Hunt Query State
  const [targetedTopic, setTargetedTopic] = useState("");

  // Manual Ingest State
  const [url, setUrl] = useState("");
  const [pasted, setPasted] = useState("");

  // Queue Filter & Pagination State (default 25 per page)
  const [queuePage, setQueuePage] = useState(1);
  const [queuePageSize, setQueuePageSize] = useState<number | "all">(25);
  const [queueFilter, setQueueFilter] = useState<string>("all");
  const [queueSearch, setQueueSearch] = useState<string>("");
  const [queueKind, setQueueKind] = useState<string>("all");
  const [queueMinScore, setQueueMinScore] = useState<number>(0);
  const [queueNovelOnly, setQueueNovelOnly] = useState(false);
  const [queueDomain, setQueueDomain] = useState<string>("all");
  const [queueSort, setQueueSort] = useState<"newest" | "oldest" | "score_desc" | "title_asc" | "domain_asc">("newest");
  const [ingestingId, setIngestingId] = useState<string | null>(null);
  const [selectedCandidates, setSelectedCandidates] = useState<Set<string>>(new Set());
  // Bumped to remount the queue DataTable, which clears its internal checkbox state.
  const [selectionEpoch, setSelectionEpoch] = useState(0);
  const clearSelection = () => {
    setSelectedCandidates(new Set());
    setSelectionEpoch((n) => n + 1);
  };
  const navigate = useNavigate();

  // Pipeline Audit Log State (default 25 per page)
  const [auditPage, setAuditPage] = useState(1);
  const [auditPageSize, setAuditPageSize] = useState<number | "all">(25);
  const [auditDecision, setAuditDecision] = useState<string>("all");
  const [auditDepth, setAuditDepth] = useState<string>("all");
  const [auditStage, setAuditStage] = useState<string>("all");
  const [auditPublisher, setAuditPublisher] = useState<string>("all");
  const [auditSearch, setAuditSearch] = useState("");
  const [auditSort, setAuditSort] = useState<"newest" | "oldest">("newest");

  // Discovered Sources State (default 25 per page)
  const [sourcesPage, setSourcesPage] = useState(1);
  const [sourcesPageSize, setSourcesPageSize] = useState<number | "all">(25);
  const [sourcesSearch, setSourcesSearch] = useState("");
  const [sourcesTrust, setSourcesTrust] = useState<"all" | "high" | "medium">("all");
  const [sourcesSort, setSourcesSort] = useState<"trust_desc" | "resources_desc" | "domain_asc" | "newest">("trust_desc");

  // Citation Graph Edges State (default 25 per page)
  const [edgesPage, setEdgesPage] = useState(1);
  const [edgesPageSize, setEdgesPageSize] = useState<number | "all">(25);
  const [edgesRelationship, setEdgesRelationship] = useState<string>("all");
  const [edgesSearch, setEdgesSearch] = useState("");
  const [edgesSort, setEdgesSort] = useState<"newest" | "oldest">("newest");

  // Crawl Jobs History State (default 25 per page)
  const [jobsPage, setJobsPage] = useState(1);
  const [jobsPageSize, setJobsPageSize] = useState<number | "all">(25);
  const [jobsStatus, setJobsStatus] = useState<string>("all");
  const [jobsTrigger, setJobsTrigger] = useState<string>("all");
  const [jobsSearch, setJobsSearch] = useState("");
  const [jobsSort, setJobsSort] = useState<"newest" | "oldest">("newest");

  // Queries
  const crawlerState = useQuery({
    queryKey: ["crawlerState"],
    queryFn: () => getCrawlerState(),
    staleTime: 6000,
    placeholderData: (previousData) => previousData,
    refetchInterval: (query) => (query.state.data?.activeJob ? 1200 : 25000),
  });

  const isCrawlerLoading = crawlerState.isLoading || (!crawlerState.data && !crawlerState.isError);

  const catalog = useQuery({
    queryKey: ["catalog"],
    queryFn: () => listCatalog(),
    staleTime: 60_000,
  });

  // Targeted Crawl Mutation
  const targetedCrawl = useMutation({
    mutationFn: (topic: string) =>
      triggerCrawlJob({ data: { triggerType: "SEARCH", customQuery: topic } }),
    onSuccess: (res) => {
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
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
      ingestUrl({ data: { url: input.url || "", pasted: input.pastedText } }),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["reports"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
      void qc.invalidateQueries({ queryKey: ["catalog"] });
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
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["crawlerState"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
      toast.success("Autonomous Discovery Engine Dispatched", {
        description: "Frontier queue initiated: exploring seeds, citations, repositories, and new CTI domains...",
      });
    },
    onError: (e: Error) => toast.error(`Crawler failed to start: ${e.message}`),
  });

  // Cancel Crawl Mutation
  const cancelCrawl = useMutation({
    mutationFn: (jobId: string) => cancelCrawlJob({ data: { jobId } }),
    onSuccess: (res) => {
      void qc.invalidateQueries();
      if (!res.ok) {
        toast.message("Crawl job is no longer running");
        return;
      }
      toast.info("Crawl job cancelled");
    },
  });

  // Ingest Discovered Item Mutation
  const ingestQueueItem = useMutation({
    mutationFn: async (discoveredId: string) => {
      setIngestingId(discoveredId);
      return await ingestDiscoveredUrl({ data: { discoveredId } });
    },
    onSettled: () => {
      setIngestingId(null);
    },
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

  // Batch Ingest Discovered Items (Concurrent Workers)
  const batchIngestMutation = useMutation({
    mutationFn: (discoveredIds: string[]) =>
      batchIngestDiscoveredUrls({ data: { discoveredIds, concurrency: 4 } }),
    onSuccess: (res) => {
      void qc.invalidateQueries();
      clearSelection();
      toast.success("Batch Ingestion Complete", {
        description: `Ingested: ${res.succeeded} / ${res.total} · Failed: ${res.failed}${res.durationMs ? ` (${res.durationMs}ms)` : ""}`,
      });
    },
    onError: (e: Error) => toast.error(`Batch ingest failed: ${e.message}`),
  });

  // Batch Reject Discovered Items
  const batchRejectMutation = useMutation({
    mutationFn: (discoveredIds: string[]) =>
      batchRejectDiscoveredUrls({ data: { discoveredIds } }),
    onSuccess: (res) => {
      void qc.invalidateQueries();
      clearSelection();
      toast.info("Batch Reject Complete", {
        description: `${res.count} candidate resources marked as rejected.`,
      });
    },
    onError: (e: Error) => toast.error(`Batch reject failed: ${e.message}`),
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

  // Discovery Queue computations
  const queueDomains = Array.from(new Set(discovered.map((d) => d.sourceDomain).filter(Boolean))).sort();
  const queueKinds = Array.from(new Set(discovered.map((d) => d.resourceKind || d.classification).filter(Boolean))).sort();

  const filteredDiscovered = discovered.filter((item) => {
    if (queueFilter === "awaiting_approval" && !isItemAwaitingApproval(item.status)) return false;
    if (queueFilter === "qualified" && item.status !== "qualified" && !isItemAwaitingApproval(item.status)) return false;
    if (queueFilter === "ingested" && item.status !== "ingested") return false;
    if (queueFilter === "rejected" && item.status !== "rejected") return false;
    if (queueKind !== "all" && item.resourceKind !== queueKind && item.classification !== queueKind) return false;
    if (queueDomain !== "all" && item.sourceDomain !== queueDomain) return false;
    if (queueMinScore > 0 && (item.qualityScore ?? 0) < queueMinScore) return false;
    if (queueNovelOnly && !item.isEmergingTechnique) return false;
    if (queueSearch.trim()) {
      const q = queueSearch.toLowerCase();
      const discId = formatSystemId("discovered", item.id, item.canonicalUrl).toLowerCase();
      const outcome = formatOutcomeId(item.status, item.reportId || item.id, item.canonicalUrl).id.toLowerCase();
      const domId = formatDomainId(item.sourceDomain).toLowerCase();
      return (
        (item.title || "").toLowerCase().includes(q) ||
        (item.url || "").toLowerCase().includes(q) ||
        (item.canonicalUrl || "").toLowerCase().includes(q) ||
        (item.publisher || "").toLowerCase().includes(q) ||
        (item.sourceDomain || "").toLowerCase().includes(q) ||
        (item.noveltyRationale || "").toLowerCase().includes(q) ||
        (item.rejectReason || "").toLowerCase().includes(q) ||
        (item.id || "").toLowerCase().includes(q) ||
        (item.reportId || "").toLowerCase().includes(q) ||
        discId.includes(q) ||
        outcome.includes(q) ||
        domId.includes(q)
      );
    }
    return true;
  });

  const sortedDiscovered = [...filteredDiscovered].sort((a, b) => {
    // 1. PIN AWAITING APPROVAL TO TOP ROWS:
    // Any candidate item requiring operator review/approval is pinned at the top
    const aPending = isItemAwaitingApproval(a.status);
    const bPending = isItemAwaitingApproval(b.status);
    if (aPending && !bPending) return -1;
    if (!aPending && bPending) return 1;

    // 2. Secondary sort according to chosen criteria
    if (queueSort === "oldest") return (a.createdAt || "").localeCompare(b.createdAt || "");
    if (queueSort === "score_desc") return (b.qualityScore ?? 0) - (a.qualityScore ?? 0);
    if (queueSort === "title_asc") return (a.title || "").localeCompare(b.title || "");
    if (queueSort === "domain_asc") return (a.sourceDomain || "").localeCompare(b.sourceDomain || "");
    return (b.createdAt || "").localeCompare(a.createdAt || "");
  });

  const pagedDiscovered = paginateList(sortedDiscovered, queuePage, queuePageSize);

  // Pipeline Audit Log computations
  const auditStages = (Array.from(new Set(items.map((i) => i.stage).filter(Boolean))) as string[]).sort();
  const auditPublishers = (Array.from(new Set(items.map((i) => i.publisher).filter(Boolean))) as string[]).sort();

  const filteredAuditItems = items.filter((itm) => {
    if (auditDecision !== "all") {
      if (auditDecision === "AWAITING_APPROVAL") {
        if (!isItemAwaitingApproval(itm.stage, itm.decision)) return false;
      } else if (itm.decision !== auditDecision) {
        return false;
      }
    }
    if (auditDepth === "0" && itm.depth !== 0) return false;
    if (auditDepth === "1" && itm.depth !== 1) return false;
    if (auditDepth === "2+" && itm.depth < 2) return false;
    if (auditStage !== "all" && itm.stage !== auditStage) return false;
    if (auditPublisher !== "all" && itm.publisher !== auditPublisher) return false;
    if (auditSearch.trim()) {
      const q = auditSearch.toLowerCase();
      const audId = formatAuditId(itm.id).toLowerCase();
      const outcome = formatOutcomeId(itm.decision, itm.id, itm.url).id.toLowerCase();
      const domId = formatDomainId(itm.canonicalUrl).toLowerCase();
      return (
        (itm.title || "").toLowerCase().includes(q) ||
        (itm.canonicalUrl || "").toLowerCase().includes(q) ||
        (itm.url || "").toLowerCase().includes(q) ||
        (itm.reason || "").toLowerCase().includes(q) ||
        (itm.publisher || "").toLowerCase().includes(q) ||
        (itm.id || "").toLowerCase().includes(q) ||
        audId.includes(q) ||
        outcome.includes(q) ||
        domId.includes(q)
      );
    }
    return true;
  });

  const sortedAuditItems = [...filteredAuditItems].sort((a, b) => {
    if (auditSort === "oldest") return (a.createdAt || "").localeCompare(b.createdAt || "");
    return (b.createdAt || "").localeCompare(a.createdAt || "");
  });

  const pagedAuditItems = paginateList(sortedAuditItems, auditPage, auditPageSize);

  // Discovered Sources computations
  const filteredSources = discoveredSources.filter((src) => {
    if (sourcesTrust === "high" && src.trustScore < 0.90) return false;
    if (sourcesTrust === "medium" && src.trustScore < 0.80) return false;
    if (sourcesSearch.trim()) {
      const q = sourcesSearch.toLowerCase();
      const srcId = formatSourceId(src.id, src.domain).toLowerCase();
      const domId = formatDomainId(src.domain).toLowerCase();
      return (
        (src.domain || "").toLowerCase().includes(q) ||
        (src.name || "").toLowerCase().includes(q) ||
        (src.parentSource || "").toLowerCase().includes(q) ||
        (src.id || "").toLowerCase().includes(q) ||
        srcId.includes(q) ||
        domId.includes(q)
      );
    }
    return true;
  });

  const sortedSources = [...filteredSources].sort((a, b) => {
    if (sourcesSort === "resources_desc") return b.resourceCount - a.resourceCount;
    if (sourcesSort === "domain_asc") return a.domain.localeCompare(b.domain);
    if (sourcesSort === "newest") return (b.firstDiscoveredAt || "").localeCompare(a.firstDiscoveredAt || "");
    if (b.trustScore !== a.trustScore) return b.trustScore - a.trustScore;
    return b.resourceCount - a.resourceCount;
  });

  const pagedSources = paginateList(sortedSources, sourcesPage, sourcesPageSize);

  // Citation Graph Edges computations
  const edgeRelationships = (Array.from(new Set(graphEdges.map((e) => e.relationship).filter(Boolean))) as string[]).sort();

  const filteredEdges = graphEdges.filter((edge) => {
    if (edgesRelationship !== "all" && edge.relationship !== edgesRelationship) return false;
    if (edgesSearch.trim()) {
      const q = edgesSearch.toLowerCase();
      const edgId = formatEdgeId(edge.id, `${edge.from}->${edge.to}`).toLowerCase();
      const srcDomId = formatDomainId(edge.sourceDomain || edge.from).toLowerCase();
      const tgtDomId = formatDomainId(edge.targetDomain || edge.to).toLowerCase();
      return (
        (edge.from || "").toLowerCase().includes(q) ||
        (edge.to || "").toLowerCase().includes(q) ||
        (edge.label || "").toLowerCase().includes(q) ||
        (edge.id || "").toLowerCase().includes(q) ||
        edgId.includes(q) ||
        srcDomId.includes(q) ||
        tgtDomId.includes(q)
      );
    }
    return true;
  });

  const sortedEdges = [...filteredEdges].sort((a, b) => {
    if (edgesSort === "oldest") return (a.createdAt || "").localeCompare(b.createdAt || "");
    return (b.createdAt || "").localeCompare(a.createdAt || "");
  });

  const pagedEdges = paginateList(sortedEdges, edgesPage, edgesPageSize);

  // Crawl Jobs History computations
  const filteredJobs = jobs.filter((j) => {
    if (jobsStatus !== "all" && j.status !== jobsStatus) return false;
    if (jobsTrigger !== "all" && j.triggerType !== jobsTrigger) return false;
    if (jobsSearch.trim()) {
      const q = jobsSearch.toLowerCase();
      const jobId = formatJobId(j.id, j.triggerType).toLowerCase();
      return (
        (j.id || "").toLowerCase().includes(q) ||
        (j.errorSummary || "").toLowerCase().includes(q) ||
        (j.triggerType || "").toLowerCase().includes(q) ||
        jobId.includes(q)
      );
    }
    return true;
  });

  const sortedJobs = [...filteredJobs].sort((a, b) => {
    if (jobsSort === "oldest") return (a.completedAt || a.startedAt || "").localeCompare(b.completedAt || b.startedAt || "");
    return (b.completedAt || b.startedAt || "").localeCompare(a.completedAt || a.startedAt || "");
  });

  const pagedJobs = paginateList(sortedJobs, jobsPage, jobsPageSize);

  const kpiSkeleton = <span className="inline-block h-8 w-20 animate-pulse rounded bg-border/40 align-middle" />;

  const progressDone = activeJob ? activeJob.evaluatedCount || activeJob.ingestedCount || 0 : 0;
  const progressMax = activeJob ? activeJob.maxResourcesPerRun || config.maxResourcesPerRun || 35 : 1;
  const progressPct = Math.min(100, Math.round((progressDone / progressMax) * 100));
  const lastJob = activeJob ?? sortedJobsByRecency(jobs)[0];
  const freq = Number(config.frequencyMinutes);
  const cadence = !config.enabled
    ? "Disabled"
    : config.paused
      ? "Paused"
      : !Number.isFinite(freq) || freq <= 0
        ? "Scheduled"
        : `Every ${freq < 60 ? `${freq}m` : `${Math.floor(freq / 60)}h ${freq % 60 > 0 ? `${freq % 60}m` : ""}`.trim()}`;

  const queueFiltersActive =
    Boolean(queueSearch) || queueKind !== "all" || queueMinScore > 0 || queueNovelOnly || queueDomain !== "all" || queueFilter !== "all";
  const auditFiltersActive =
    Boolean(auditSearch) || auditDecision !== "all" || auditDepth !== "all" || auditStage !== "all" || auditPublisher !== "all";
  const selectedIngestable = Array.from(selectedCandidates).filter(
    (id) => discovered.find((d) => d.id === id)?.status !== "ingested",
  );

  // ----- Column definitions -----
  type Discovered = (typeof discovered)[number];
  type AuditItem = (typeof items)[number];
  type Job = (typeof jobs)[number];
  type DiscSource = (typeof discoveredSources)[number];
  type Edge = (typeof graphEdges)[number];

  const queueColumns: ColumnDef<Discovered, any>[] = [
    {
      accessorKey: "title",
      header: "Title",
      cell: ({ row }) => {
        const res = row.original;
        return (
          <div className="min-w-0 max-w-[420px]">
            <div className="truncate font-medium text-fg" title={res.title}>{res.title || res.canonicalUrl}</div>
            <a
              href={res.canonicalUrl}
              target="_blank"
              rel="noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="flex items-center gap-1 text-xs text-subtle hover:text-fg"
            >
              <span className="truncate">{res.canonicalUrl}</span>
              <ExternalLink className="size-3 shrink-0" />
            </a>
            {res.rejectReason && (
              <div className="mt-0.5 truncate text-xs text-danger/80" title={res.rejectReason}>
                {res.rejectReason}
              </div>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "sourceDomain",
      header: "Domain",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted">{getValue() as string}</span>,
      meta: { hideBelow: "md" },
    },
    {
      id: "type",
      header: "Type",
      accessorFn: (r) => formatResourceKind(r.resourceKind || r.classification).label,
      cell: ({ row, getValue }) => (
        <span className="whitespace-nowrap text-muted" title={humanize(row.original.discoveryMethod)}>
          {getValue() as string}
        </span>
      ),
      meta: { hideBelow: "xl" },
    },
    {
      id: "score",
      header: "Score",
      accessorFn: (r) => r.qualityScore ?? -1,
      cell: ({ row }) => {
        const res = row.original;
        const q = res.qualityScore;
        return (
          <div className="w-28" title={res.agentRationale || undefined}>
            {q !== null && q !== undefined ? (
              <div className="flex items-center gap-2">
                <Meter value={q} tone={q >= 0.8 ? "success" : q >= 0.5 ? "info" : "warning"} label="Quality score" />
                <span className="w-9 shrink-0 text-right text-xs tabular-nums text-muted">{Math.round(q * 100)}%</span>
              </div>
            ) : (
              <span className="text-subtle">—</span>
            )}
            {res.agentScore !== undefined && res.agentScore > 0 && (
              <div className="mt-1 text-xs text-subtle tabular-nums">
                AI {res.agentScore}%{res.agentApproved ? " · approved" : ""}
                {res.simulationScore ? ` · sim ${Math.round(res.simulationScore * 100)}%` : ""}
              </div>
            )}
          </div>
        );
      },
      meta: { hideBelow: "sm" },
    },
    {
      id: "novelty",
      header: "Novelty",
      accessorFn: (r) => (r.isEmergingTechnique ? 1 : 0),
      cell: ({ row }) =>
        row.original.isEmergingTechnique ? (
          <span className="inline-flex items-center gap-1 whitespace-nowrap text-warn" title={row.original.noveltyRationale || "Novel unmapped procedure"}>
            <Flame className="size-3.5" strokeWidth={1.75} />
            Novel
          </span>
        ) : (
          <span className="text-subtle">—</span>
        ),
      meta: { hideBelow: "lg" },
    },
    {
      accessorKey: "createdAt",
      header: "Discovered",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted tabular-nums">{shortDate(getValue() as string)}</span>,
      meta: { hideBelow: "lg" },
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => {
        const st = row.original.status;
        const pending = isItemAwaitingApproval(st);
        return (
          <StatusChip tone={pending ? "warning" : queueTone(st)} dot>
            {ingestQueueItem.isPending && ingestingId === row.original.id ? "Ingesting…" : humanize(st)}
          </StatusChip>
        );
      },
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      enableSorting: false,
      cell: ({ row }) => {
        const res = row.original;
        const ingested = res.status === "ingested";
        return (
          <RowMenu
            label={`Actions for ${res.title}`}
            items={[
              {
                label: "Ingest",
                icon: Download,
                hidden: ingested,
                disabled: ingestQueueItem.isPending,
                onSelect: () => ingestQueueItem.mutate(res.id),
              },
              {
                label: "View in library",
                icon: Library,
                hidden: !ingested,
                onSelect: () =>
                  void navigate({ to: "/library", search: { selected: res.reportId || res.canonicalUrl || res.title } as never }),
              },
              {
                label: "Open source page",
                icon: ExternalLink,
                onSelect: () => window.open(res.canonicalUrl, "_blank", "noopener,noreferrer"),
              },
              {
                label: "Reject",
                icon: XCircle,
                danger: true,
                separated: true,
                hidden: ingested || res.status === "rejected",
                disabled: batchRejectMutation.isPending,
                onSelect: () => batchRejectMutation.mutate([res.id]),
              },
            ]}
          />
        );
      },
      meta: { align: "right", className: "w-12" },
    },
  ];

  const auditColumns: ColumnDef<AuditItem, any>[] = [
    {
      accessorKey: "createdAt",
      header: "Time",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted tabular-nums">{formatDateTime(getValue())}</span>,
      meta: { hideBelow: "sm" },
    },
    {
      accessorKey: "title",
      header: "URL",
      cell: ({ row }) => {
        const itm = row.original;
        return (
          <div className="min-w-0 max-w-[380px]">
            <div className="truncate font-medium text-fg">
              {itm.decision === "INGESTED" ? (
                <Link
                  to="/library"
                  search={{ selected: itm.canonicalUrl || itm.title } as never}
                  className="hover:text-accent hover:underline"
                  title="View in library"
                >
                  {itm.title || itm.canonicalUrl}
                </Link>
              ) : (
                itm.title || itm.canonicalUrl
              )}
            </div>
            <div className="truncate text-xs text-subtle">{itm.canonicalUrl}</div>
          </div>
        );
      },
    },
    {
      accessorKey: "decision",
      header: "Outcome",
      cell: ({ row }) => {
        const itm = row.original;
        const pending = isItemAwaitingApproval(itm.stage, itm.decision);
        return (
          <StatusChip tone={pending ? "warning" : queueTone(itm.decision)} dot>
            {humanize(pending ? "awaiting_approval" : itm.decision)}
          </StatusChip>
        );
      },
    },
    {
      id: "stage",
      header: "Stage",
      accessorFn: (i) => i.stage || "",
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-muted">
          {humanize(row.original.stage || row.original.decision)} · depth {row.original.depth}
        </span>
      ),
      meta: { hideBelow: "xl" },
    },
    {
      accessorKey: "publisher",
      header: "Publisher",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted">{(getValue() as string) || "—"}</span>,
      meta: { hideBelow: "lg" },
    },
    {
      accessorKey: "reason",
      header: "Detail",
      enableSorting: false,
      cell: ({ getValue }) => (
        <p className="line-clamp-2 max-w-[360px] text-xs leading-relaxed text-muted" title={getValue() as string}>
          {getValue() as string}
        </p>
      ),
      meta: { hideBelow: "md" },
    },
  ];

  const jobColumns: ColumnDef<Job, any>[] = [
    {
      id: "job",
      header: "Job",
      accessorFn: (j) => formatJobId(j.id, j.triggerType),
      cell: ({ row, getValue }) => (
        <div className="min-w-0">
          <div className="whitespace-nowrap font-mono text-[13px] text-fg">{getValue() as string}</div>
          {row.original.errorSummary && (
            <div className="max-w-[260px] truncate text-xs text-danger/80" title={row.original.errorSummary}>
              {row.original.errorSummary}
            </div>
          )}
        </div>
      ),
    },
    {
      accessorKey: "triggerType",
      header: "Trigger",
      cell: ({ getValue }) => <span className="text-muted">{humanize(getValue() as string)}</span>,
      meta: { hideBelow: "sm" },
    },
    {
      accessorKey: "startedAt",
      header: "Started",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted tabular-nums">{formatDateTime(getValue())}</span>,
      meta: { hideBelow: "md" },
    },
    {
      id: "duration",
      header: "Duration",
      accessorFn: (j) => durationMs(j.startedAt, j.completedAt) ?? -1,
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-muted tabular-nums">
          {formatDuration(durationMs(row.original.startedAt, row.original.completedAt), row.original.status)}
        </span>
      ),
      meta: { hideBelow: "lg" },
    },
    {
      id: "items",
      header: "Items",
      accessorFn: (j) => j.ingestedCount,
      cell: ({ row }) => {
        const j = row.original;
        return (
          <span
            className="whitespace-nowrap text-muted tabular-nums"
            title={`Discovered ${j.discoveredCount} · evaluated ${j.evaluatedCount || j.discoveredCount} · qualified ${j.qualifiedCount} · duplicates ${j.duplicateCount} · rejected ${j.rejectedCount} · new sources ${j.newSourcesCount || 0}`}
          >
            <span className="text-fg">{j.ingestedCount}</span> ingested · {j.discoveredCount} found
            {j.newSourcesCount ? ` · +${j.newSourcesCount} sources` : ""}
          </span>
        );
      },
      meta: { hideBelow: "sm" },
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ getValue }) => {
        const st = getValue() as string;
        return (
          <StatusChip tone={st === "completed" ? "success" : st === "running" ? "info" : st === "failed" ? "danger" : "neutral"} dot>
            {humanize(st)}
          </StatusChip>
        );
      },
      meta: { align: "right" },
    },
  ];

  const sourceColumns: ColumnDef<DiscSource, any>[] = [
    {
      accessorKey: "domain",
      header: "Domain",
      cell: ({ row }) => (
        <div className="min-w-0 max-w-[320px]">
          <a
            href={row.original.homepageUrl}
            target="_blank"
            rel="noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="inline-flex max-w-full items-center gap-1 font-mono text-[13px] text-fg hover:text-accent"
          >
            <span className="truncate">{row.original.domain}</span>
            <ExternalLink className="size-3 shrink-0 text-subtle" />
          </a>
          <div className="truncate text-xs text-subtle">{row.original.name}</div>
        </div>
      ),
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ getValue }) => {
        const st = getValue() as string;
        return (
          <StatusChip tone={st === "approved" || st === "verified" ? "success" : st === "rejected" || st === "ignored" ? "danger" : "neutral"} dot>
            {humanize(st)}
          </StatusChip>
        );
      },
    },
    {
      accessorKey: "trustScore",
      header: "Trust",
      cell: ({ getValue }) => {
        const v = getValue() as number;
        return (
          <div className="flex w-28 items-center gap-2">
            <Meter value={v} tone={v >= 0.9 ? "success" : v >= 0.8 ? "info" : "warning"} label="Trust score" />
            <span className="w-9 shrink-0 text-right text-xs tabular-nums text-muted">{Math.round(v * 100)}%</span>
          </div>
        );
      },
      meta: { hideBelow: "sm" },
    },
    {
      accessorKey: "resourceCount",
      header: "Resources",
      meta: { align: "right", hideBelow: "md" },
    },
    {
      accessorKey: "parentSource",
      header: "Referrer",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted">{(getValue() as string) || "Seed"}</span>,
      meta: { hideBelow: "lg" },
    },
    {
      accessorKey: "firstDiscoveredAt",
      header: "Discovered",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted tabular-nums">{shortDate(getValue() as string)}</span>,
      meta: { hideBelow: "lg" },
    },
  ];

  const edgeColumns: ColumnDef<Edge, any>[] = [
    {
      accessorKey: "from",
      header: "From",
      cell: ({ getValue }) => <div className="max-w-[260px] truncate text-muted" title={getValue() as string}>{getValue() as string}</div>,
      meta: { hideBelow: "md" },
    },
    {
      accessorKey: "relationship",
      header: "Relationship",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-fg">{humanize(getValue() as string)}</span>,
    },
    {
      accessorKey: "to",
      header: "To",
      cell: ({ getValue }) => (
        <a
          href={getValue() as string}
          target="_blank"
          rel="noreferrer"
          className="flex max-w-[300px] items-center gap-1 text-fg hover:text-accent"
        >
          <span className="truncate">{getValue() as string}</span>
          <ExternalLink className="size-3 shrink-0 text-subtle" />
        </a>
      ),
    },
    {
      accessorKey: "label",
      header: "Context",
      cell: ({ getValue }) => <div className="max-w-[220px] truncate text-muted">{getValue() as string}</div>,
      meta: { hideBelow: "xl" },
    },
    {
      accessorKey: "createdAt",
      header: "Time",
      cell: ({ getValue }) => <span className="whitespace-nowrap text-muted tabular-nums">{formatDateTime(getValue())}</span>,
      meta: { hideBelow: "lg" },
    },
  ];

  const loadingBlock = (label: string) => (
    <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-bg-card py-14 text-center">
      <ActivitySpinner size="md" className="mb-2 text-accent" />
      <p className="text-sm text-muted">{label}</p>
    </div>
  );

  return (
    <AppShell>
      <PageHeader
        title="Ingest"
        description="The frontier crawler expands from seed sources to discover new sources, citations and research, and preserves each report as PDF evidence."
        actions={
          <>
            <ActionButton icon={Download} onClick={exportStix}>
              Export STIX 2.1
            </ActionButton>
            {activeJob ? (
              <ActionButton
                icon={cancelCrawl.isPending ? undefined : Square}
                onClick={() => cancelCrawl.mutate(activeJob.id)}
                disabled={cancelCrawl.isPending}
                title={`Cancel job ${activeJob.id}`}
              >
                {cancelCrawl.isPending ? <ActivitySpinner size="xs" /> : null}
                Cancel crawl
              </ActionButton>
            ) : (
              <ActionButton
                variant="primary"
                icon={Play}
                onClick={() => runCrawl.mutate("MANUAL")}
                disabled={runCrawl.isPending}
              >
                {runCrawl.isPending ? "Launching…" : "Launch crawl"}
              </ActionButton>
            )}
          </>
        }
        tabs={
          <SegmentedTabs
            ariaLabel="Ingest views"
            value={activeView}
            onChange={setActiveView}
            items={VIEWS.map((v) => ({
              value: v.id,
              label: v.label,
              icon: v.icon,
              count:
                v.id === "queue" && !isCrawlerLoading && discovered.length > 0
                  ? discovered.length
                  : v.id === "graph" && !isCrawlerLoading && (discoveredSources.length > 0 || graphEdges.length > 0)
                    ? discoveredSources.length || graphEdges.length
                    : v.id === "audit" && !isCrawlerLoading && items.length > 0
                      ? items.length
                      : v.id === "catalog" && (catalog.data?.length ?? 0) > 0
                        ? catalog.data?.length
                        : undefined,
            }))}
          />
        }
      />

      {crawlerState.isError && (
        <div className="mb-6 flex items-center justify-between gap-3 rounded-xl border border-danger/40 bg-bg-card p-4 text-sm text-danger">
          <div className="flex items-center gap-2">
            <XCircle className="size-4 shrink-0" />
            <span>Couldn't sync crawler telemetry: {crawlerState.error?.message}</span>
          </div>
          <ActionButton onClick={() => void crawlerState.refetch()}>Retry</ActionButton>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Compass}
          label="Discovered candidates"
          value={
            isCrawlerLoading
              ? kpiSkeleton
              : (state?.totalCounts?.discovered ?? discovered.length).toLocaleString()
          }
          hint="URLs in the store"
        />
        <StatCard
          icon={Network}
          label="Monitored sources"
          value={
            isCrawlerLoading
              ? kpiSkeleton
              : (state?.totalCounts?.sources ?? discoveredSources.length).toLocaleString()
          }
          hint="Active domains"
        />
        <StatCard
          icon={Bot}
          label="Crawl jobs"
          value={isCrawlerLoading ? kpiSkeleton : (state?.totalCounts?.jobs ?? jobs.length).toLocaleString()}
          hint="Executed runs"
        />
        <StatCard
          icon={GitBranch}
          label="Citation edges"
          value={
            isCrawlerLoading
              ? kpiSkeleton
              : (state?.totalCounts?.graphEdges ?? graphEdges.length).toLocaleString()
          }
          hint="Mapped links"
        />
      </div>

      {/* VIEW 1: CRAWLER */}
      {activeView === "crawler" && (
        <div className="mt-6 space-y-6">
          <SectionCard
            title="Crawler"
            actions={
              activeJob ? (
                <StatusDot tone="info">Running</StatusDot>
              ) : (
                <StatusDot tone={!config.enabled ? "neutral" : config.paused ? "warning" : "success"}>
                  {!config.enabled ? "Schedule disabled" : config.paused ? "Schedule paused" : "Idle · scheduled"}
                </StatusDot>
              )
            }
          >
            {activeJob ? (
              <div className="space-y-4">
                <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_auto] md:items-start">
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                      <ActivitySpinner size="xs" className="text-accent" />
                      <span className="font-mono text-[13px] text-fg">{formatJobId(activeJob.id, activeJob.triggerType)}</span>
                      <span className="text-muted">
                        · {humanize(activeJob.triggerType)} · stage {humanize(activeJob.currentStage || "evaluated").toLowerCase()}
                      </span>
                    </div>
                    <p className="truncate text-sm text-muted">
                      Current URL: <span className="font-mono text-xs text-fg">{activeJob.currentUrl || "Extracting citations and outlinks…"}</span>
                    </p>
                    <p className="text-xs text-subtle">
                      {activeJob.activeWorkers ?? (config.concurrency || 4)} parallel workers ·{" "}
                      {activeJob.throughputDocsPerSec ? activeJob.throughputDocsPerSec.toFixed(1) : "0.0"} docs/sec
                      {activeJob.activeDomains && activeJob.activeDomains.length > 0
                        ? ` · hosts: ${activeJob.activeDomains.join(", ")}`
                        : ""}
                    </p>
                  </div>
                  <div className="text-sm text-muted md:text-right">
                    <div className="text-[28px] font-semibold leading-none text-fg tabular-nums">{progressPct}%</div>
                    <div className="mt-1 tabular-nums">
                      {progressDone} / {progressMax} items
                    </div>
                  </div>
                </div>
                <Meter value={progressPct / 100} tone="info" label="Job progress" />
              </div>
            ) : (
              <div className="grid gap-4 text-sm sm:grid-cols-3">
                <div>
                  <div className="text-muted">Last run</div>
                  <div className="mt-1 text-fg tabular-nums">{formatDateTime(config.lastRunAt, "Never")}</div>
                </div>
                <div>
                  <div className="text-muted">Next run</div>
                  <div className="mt-1 text-fg tabular-nums">
                    {config.enabled && !config.paused ? formatDateTime(config.nextRunAt, "Scheduled soon") : "Inactive"}
                  </div>
                </div>
                <div>
                  <div className="text-muted">Cadence</div>
                  <div className="mt-1 text-fg">{cadence}</div>
                </div>
              </div>
            )}
          </SectionCard>

          {lastJob && (
            <div>
              <p className="mb-3 text-sm text-muted">
                {activeJob ? "Current job" : "Last job"} ·{" "}
                <span className="font-mono text-xs">{formatJobId(lastJob.id, lastJob.triggerType)}</span>
              </p>
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <StatCard icon={Compass} label="Discovered" value={lastJob.discoveredCount} hint={`${lastJob.evaluatedCount || 0} evaluated`} />
                <StatCard icon={CheckCircle2} label="Qualified" value={lastJob.qualifiedCount} hint={`${lastJob.rejectedCount || 0} rejected`} />
                <StatCard icon={Upload} label="Ingested" value={lastJob.ingestedCount} hint={`${lastJob.newSourcesCount || 0} new sources`} />
                <StatCard
                  icon={Layers}
                  label="Duplicates"
                  value={lastJob.duplicateCount}
                  hint={lastJob.failedCount ? `${lastJob.failedCount} failed or timed out` : "No failures"}
                />
              </div>
            </div>
          )}

          <SectionCard title="Targeted hunt" info="Runs a search-triggered crawl that expands outlinks and citations for one topic.">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <p className="text-sm text-muted">Enter an adversary group, CVE or malware family to start a focused crawl.</p>
              <form
                className="flex w-full items-center gap-2 md:w-auto"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (targetedTopic.trim()) targetedCrawl.mutate(targetedTopic);
                }}
              >
                <Input
                  value={targetedTopic}
                  onChange={(e) => setTargetedTopic(e.target.value)}
                  placeholder="e.g. Akira ransomware, Volt Typhoon, CVE-2023-34362"
                  aria-label="Hunt topic"
                  className="h-9 w-full text-sm md:w-80"
                />
                <ActionButton type="submit" icon={Crosshair} disabled={targetedCrawl.isPending || !targetedTopic.trim()}>
                  Hunt
                </ActionButton>
              </form>
            </div>
          </SectionCard>

          <div className="grid gap-6 lg:grid-cols-3">
            <SectionCard title="Discovery pipeline" className="lg:col-span-2">
              <ol className="grid gap-4 sm:grid-cols-5">
                {PIPELINE_STEPS.map((step, i) => (
                  <li key={step.title}>
                    <span className="flex size-6 items-center justify-center rounded-md bg-bg-subtle text-xs font-medium text-muted tabular-nums">
                      {i + 1}
                    </span>
                    <div className="mt-2 text-sm font-medium text-fg">{step.title}</div>
                    <p className="mt-1 text-xs leading-relaxed text-muted">{step.body}</p>
                  </li>
                ))}
              </ol>

              <div className="mt-6 border-t border-border pt-5">
                <h3 className="mb-2 text-sm font-medium text-fg">Source performance</h3>
                {crawlerState.isLoading ? (
                  <div className="h-20 animate-pulse rounded-lg bg-bg-subtle/50" />
                ) : state?.sourceStats && state.sourceStats.length > 0 ? (
                  <ul className="grid gap-x-8 sm:grid-cols-2">
                    {state.sourceStats.map((s) => (
                      <li key={s.sourceName} className="flex items-center justify-between gap-3 border-b border-border py-2 text-sm last:border-b-0 sm:[&:nth-last-child(2)]:border-b-0">
                        <span className="truncate text-fg">{s.sourceName}</span>
                        <span className="shrink-0 text-muted tabular-nums">
                          <span className="text-fg">{s.ingested}</span> ingested · {s.found} found
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted">No source telemetry recorded yet.</p>
                )}
              </div>
            </SectionCard>

            <SectionCard
              title="Engine configuration"
              actions={
                <ActionButton variant="ghost" icon={Settings} onClick={() => void navigate({ to: "/settings", search: { tab: "crawler" } as never })}>
                  Configure
                </ActionButton>
              }
            >
              {isCrawlerLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3, 4, 5, 6].map((i) => (
                    <div key={i} className="h-4 animate-pulse rounded bg-border/40" />
                  ))}
                </div>
              ) : (
                <PropertyList
                  title={null}
                  items={[
                    { label: "Resources per job", value: `${config.maxResourcesPerJob || config.maxResourcesPerRun || 35} URLs` },
                    { label: "Time limit", value: `${config.maxRunTimeMinutes ?? 5} min` },
                    { label: "Per-domain cap", value: `${config.maxResourcesPerDomain ?? 8} per host` },
                    { label: "Max depth", value: `Depth ${config.maxDepth ?? 3}` },
                    { label: "External domains", value: config.allowExternalDomains !== false ? "Enabled" : "Disabled" },
                    { label: "Deduplication", value: humanize(config.dedupMethod || "smart_hybrid") },
                    { label: "Ingestion", value: config.autoIngest ? "Automatic" : "Approval queue" },
                    { label: "Strictness", value: humanize(config.strictnessMode || "balanced") },
                    { label: "Workers", value: `${config.concurrency || 4} parallel` },
                    { label: "Host spacing", value: `${config.rateLimitMs || 150} ms` },
                    { label: "Cadence", value: cadence },
                  ]}
                />
              )}
            </SectionCard>
          </div>

          <section>
            <SectionHeading
              title="Job history"
              description="Every automated and targeted crawl job."
              actions={
                <ActionButton variant="ghost" icon={Activity} onClick={() => setActiveView("audit")}>
                  Pipeline audit log
                </ActionButton>
              }
            />
            <Toolbar
              left={
                <>
                  <SearchField
                    value={jobsSearch}
                    onChange={(v) => {
                      setJobsSearch(v);
                      setJobsPage(1);
                    }}
                    placeholder="Search job ID or error…"
                  />
                  <FilterSelect
                    label="Job status"
                    value={jobsStatus}
                    onChange={(v) => {
                      setJobsStatus(v);
                      setJobsPage(1);
                    }}
                  >
                    <option value="all">All statuses ({jobs.length})</option>
                    <option value="completed">Completed ({jobs.filter((j) => j.status === "completed").length})</option>
                    <option value="running">Running ({jobs.filter((j) => j.status === "running").length})</option>
                    <option value="failed">Failed ({jobs.filter((j) => j.status === "failed").length})</option>
                  </FilterSelect>
                  <FilterSelect
                    label="Trigger"
                    value={jobsTrigger}
                    onChange={(v) => {
                      setJobsTrigger(v);
                      setJobsPage(1);
                    }}
                  >
                    <option value="all">All triggers</option>
                    <option value="MANUAL">Manual</option>
                    <option value="SCHEDULED">Scheduled</option>
                    <option value="SEARCH">Search</option>
                  </FilterSelect>
                </>
              }
              right={
                <FilterSelect label="Sort jobs" value={jobsSort} onChange={(v) => setJobsSort(v as typeof jobsSort)}>
                  <option value="newest">Newest first</option>
                  <option value="oldest">Oldest first</option>
                </FilterSelect>
              }
            />
            {isCrawlerLoading ? (
              loadingBlock("Loading crawl job history…")
            ) : (
              <>
                <DataTable
                  data={pagedJobs}
                  columns={jobColumns}
                  getRowId={(j) => j.id}
                  caption="Crawl job history"
                  empty={<EmptyState icon={Bot} title="No crawl jobs" description={jobs.length ? "No jobs match these filters." : "Launch a crawl to see its history here."} />}
                />
                {filteredJobs.length > 0 && (
                  <PaginationControls
                    currentPage={jobsPage}
                    pageSize={jobsPageSize}
                    totalItems={filteredJobs.length}
                    onPageChange={setJobsPage}
                    onPageSizeChange={setJobsPageSize}
                    itemLabel="jobs"
                  />
                )}
              </>
            )}
          </section>
        </div>
      )}

      {/* VIEW 2: DISCOVERY QUEUE */}
      {activeView === "queue" && (
        <section className="mt-6">
          <SectionHeading
            title="Discovery queue"
            description="Candidate reports found across seeds, citations and outlinks. Items awaiting approval are pinned to the top."
          />
          <div className="mb-4">
            <SegmentedTabs
              size="sm"
              ariaLabel="Queue status"
              value={queueFilter}
              onChange={(v) => {
                setQueueFilter(v);
                setQueuePage(1);
              }}
              items={[
                { value: "all", label: "All", count: isCrawlerLoading ? undefined : discovered.length },
                {
                  value: "awaiting_approval",
                  label: "Awaiting approval",
                  count: isCrawlerLoading ? undefined : discovered.filter((d) => isItemAwaitingApproval(d.status)).length,
                },
                { value: "qualified", label: "Qualified", count: isCrawlerLoading ? undefined : discovered.filter((d) => d.status === "qualified").length },
                { value: "ingested", label: "Ingested", count: isCrawlerLoading ? undefined : discovered.filter((d) => d.status === "ingested").length },
                { value: "rejected", label: "Rejected", count: isCrawlerLoading ? undefined : discovered.filter((d) => d.status === "rejected").length },
              ]}
            />
          </div>

          <Toolbar
            left={
              <>
                <SearchField
                  value={queueSearch}
                  onChange={(v) => {
                    setQueueSearch(v);
                    setQueuePage(1);
                  }}
                  placeholder="Search title, URL, publisher, domain…"
                />
                <FilterSelect
                  label="Resource type"
                  value={queueKind}
                  onChange={(v) => {
                    setQueueKind(v);
                    setQueuePage(1);
                  }}
                >
                  <option value="all">All types ({queueKinds.length})</option>
                  {queueKinds.map((k) => (
                    <option key={k} value={k}>
                      {humanize(k)}
                    </option>
                  ))}
                </FilterSelect>
                <FilterSelect
                  label="Minimum quality score"
                  value={queueMinScore}
                  onChange={(v) => {
                    setQueueMinScore(Number(v));
                    setQueuePage(1);
                  }}
                >
                  <option value={0}>Any score</option>
                  <option value={0.8}>Score ≥ 80%</option>
                  <option value={0.6}>Score ≥ 60%</option>
                  <option value={0.4}>Score ≥ 40%</option>
                </FilterSelect>
                <FilterSelect
                  label="Source domain"
                  value={queueDomain}
                  onChange={(v) => {
                    setQueueDomain(v);
                    setQueuePage(1);
                  }}
                >
                  <option value="all">All domains ({queueDomains.length})</option>
                  {queueDomains.map((dm) => (
                    <option key={dm} value={dm}>
                      {dm}
                    </option>
                  ))}
                </FilterSelect>
                <button
                  type="button"
                  aria-pressed={queueNovelOnly}
                  onClick={() => {
                    setQueueNovelOnly(!queueNovelOnly);
                    setQueuePage(1);
                  }}
                  className={cn(
                    "inline-flex h-9 items-center gap-1.5 rounded-lg border px-3 text-sm transition-colors",
                    queueNovelOnly ? "border-warn/50 bg-bg-subtle text-warn" : "border-border bg-bg-elevated text-muted hover:text-fg",
                  )}
                >
                  <Flame className="size-4" strokeWidth={1.75} />
                  Novel only ({discovered.filter((d) => d.isEmergingTechnique).length})
                </button>
                {queueFiltersActive && (
                  <ActionButton
                    variant="ghost"
                    icon={X}
                    onClick={() => {
                      setQueueSearch("");
                      setQueueKind("all");
                      setQueueMinScore(0);
                      setQueueNovelOnly(false);
                      setQueueDomain("all");
                      setQueueFilter("all");
                      setQueuePage(1);
                    }}
                  >
                    Reset
                  </ActionButton>
                )}
              </>
            }
            right={
              selectedCandidates.size > 0 ? (
                <>
                  <span className="text-sm text-muted tabular-nums">{selectedCandidates.size} selected</span>
                  <ActionButton
                    variant="primary"
                    icon={batchIngestMutation.isPending ? undefined : Play}
                    disabled={batchIngestMutation.isPending || batchRejectMutation.isPending || selectedIngestable.length === 0}
                    onClick={() => batchIngestMutation.mutate(selectedIngestable)}
                    title="Ingest selected candidates across 4 parallel workers"
                  >
                    {batchIngestMutation.isPending ? "Ingesting…" : "Ingest selected"}
                  </ActionButton>
                  <ActionButton
                    icon={XCircle}
                    disabled={batchIngestMutation.isPending || batchRejectMutation.isPending}
                    onClick={() => batchRejectMutation.mutate(Array.from(selectedCandidates))}
                  >
                    {batchRejectMutation.isPending ? "Rejecting…" : "Reject"}
                  </ActionButton>
                  <ActionButton variant="ghost" onClick={clearSelection}>
                    Clear
                  </ActionButton>
                </>
              ) : (
                <FilterSelect label="Sort candidates" value={queueSort} onChange={(v) => setQueueSort(v as typeof queueSort)}>
                  <option value="newest">Latest discovered</option>
                  <option value="oldest">Oldest discovered</option>
                  <option value="score_desc">Highest score</option>
                  <option value="title_asc">Title (A–Z)</option>
                  <option value="domain_asc">Domain (A–Z)</option>
                </FilterSelect>
              )
            }
          />

          {isCrawlerLoading ? (
            loadingBlock("Loading the discovery queue…")
          ) : (
            <>
              <DataTable
                key={selectionEpoch}
                data={pagedDiscovered}
                columns={queueColumns}
                getRowId={(r) => r.id}
                selectable
                onSelectionChange={(ids) => setSelectedCandidates(new Set(ids))}
                isRowActive={(r) => isItemAwaitingApproval(r.status)}
                caption="Discovery queue"
                empty={
                  <EmptyState
                    icon={Compass}
                    title={discovered.length ? "No candidates match these filters" : "The queue is empty"}
                    description={discovered.length ? "Adjust or reset the filters." : "Launch a crawl to discover candidate reports."}
                  />
                }
              />
              {filteredDiscovered.length > 0 && (
                <PaginationControls
                  currentPage={queuePage}
                  pageSize={queuePageSize}
                  totalItems={filteredDiscovered.length}
                  onPageChange={setQueuePage}
                  onPageSizeChange={setQueuePageSize}
                  itemLabel="candidates"
                />
              )}
            </>
          )}
        </section>
      )}

      {/* VIEW 3: SOURCES & GRAPH */}
      {activeView === "graph" && (
        <div className="mt-6 space-y-8">
          <section>
            <SectionHeading
              title="Discovered sources"
              description="External domains found through links, citations and research papers."
            />
            <Toolbar
              left={
                <>
                  <SearchField
                    value={sourcesSearch}
                    onChange={(v) => {
                      setSourcesSearch(v);
                      setSourcesPage(1);
                    }}
                    placeholder="Search domain or publisher…"
                  />
                  <FilterSelect
                    label="Trust level"
                    value={sourcesTrust}
                    onChange={(v) => {
                      setSourcesTrust(v as typeof sourcesTrust);
                      setSourcesPage(1);
                    }}
                  >
                    <option value="all">All trust levels</option>
                    <option value="high">High trust (≥ 90%)</option>
                    <option value="medium">Medium trust (≥ 80%)</option>
                  </FilterSelect>
                </>
              }
              right={
                <FilterSelect label="Sort sources" value={sourcesSort} onChange={(v) => setSourcesSort(v as typeof sourcesSort)}>
                  <option value="trust_desc">Highest trust</option>
                  <option value="resources_desc">Most resources</option>
                  <option value="domain_asc">Domain (A–Z)</option>
                  <option value="newest">Recently discovered</option>
                </FilterSelect>
              }
            />
            {isCrawlerLoading ? (
              loadingBlock("Loading discovered sources…")
            ) : (
              <>
                <DataTable
                  data={pagedSources}
                  columns={sourceColumns}
                  getRowId={(src) => src.id || src.domain}
                  caption="Discovered sources"
                  empty={<EmptyState icon={Globe} title="No discovered sources" description={discoveredSources.length ? "No sources match these filters." : "Sources appear here as the crawler follows citations."} />}
                />
                {filteredSources.length > 0 && (
                  <PaginationControls
                    currentPage={sourcesPage}
                    pageSize={sourcesPageSize}
                    totalItems={filteredSources.length}
                    onPageChange={setSourcesPage}
                    onPageSizeChange={setSourcesPageSize}
                    itemLabel="sources"
                  />
                )}
              </>
            )}
          </section>

          <section>
            <SectionHeading
              title="Citation graph"
              description="Links between documents, repositories and PDFs found during crawling."
            />
            <Toolbar
              left={
                <>
                  <SearchField
                    value={edgesSearch}
                    onChange={(v) => {
                      setEdgesSearch(v);
                      setEdgesPage(1);
                    }}
                    placeholder="Search origin, target or context…"
                  />
                  <FilterSelect
                    label="Relationship"
                    value={edgesRelationship}
                    onChange={(v) => {
                      setEdgesRelationship(v);
                      setEdgesPage(1);
                    }}
                  >
                    <option value="all">All relationships ({edgeRelationships.length})</option>
                    {edgeRelationships.map((rel) => (
                      <option key={rel} value={rel}>
                        {humanize(rel)}
                      </option>
                    ))}
                  </FilterSelect>
                </>
              }
              right={
                <FilterSelect label="Sort edges" value={edgesSort} onChange={(v) => setEdgesSort(v as typeof edgesSort)}>
                  <option value="newest">Newest first</option>
                  <option value="oldest">Oldest first</option>
                </FilterSelect>
              }
            />
            {isCrawlerLoading ? (
              loadingBlock("Mapping citation relationships…")
            ) : (
              <>
                <DataTable
                  data={pagedEdges}
                  columns={edgeColumns}
                  getRowId={(e) => e.id}
                  caption="Citation graph edges"
                  empty={<EmptyState icon={GitBranch} title="No graph edges" description={graphEdges.length ? "No edges match these filters." : "Edges appear as the crawler follows links."} />}
                />
                {filteredEdges.length > 0 && (
                  <PaginationControls
                    currentPage={edgesPage}
                    pageSize={edgesPageSize}
                    totalItems={filteredEdges.length}
                    onPageChange={setEdgesPage}
                    onPageSizeChange={setEdgesPageSize}
                    itemLabel="edges"
                  />
                )}
              </>
            )}
          </section>
        </div>
      )}

      {/* VIEW 4: PIPELINE AUDIT LOG */}
      {activeView === "audit" && (
        <section className="mt-6">
          <SectionHeading
            title="Pipeline audit log"
            description="Every evaluated URL across the seven pipeline stages, with its outcome and reason."
          />
          <Toolbar
            left={
              <>
                <SearchField
                  value={auditSearch}
                  onChange={(v) => {
                    setAuditSearch(v);
                    setAuditPage(1);
                  }}
                  placeholder="Search URL, title, publisher, reason…"
                />
                <FilterSelect
                  label="Outcome"
                  value={auditDecision}
                  onChange={(v) => {
                    setAuditDecision(v);
                    setAuditPage(1);
                  }}
                >
                  <option value="all">All outcomes</option>
                  <option value="INGESTED">Ingested</option>
                  <option value="AWAITING_APPROVAL">Awaiting approval</option>
                  <option value="QUALIFIED">Qualified</option>
                  <option value="DUPLICATE">Duplicate</option>
                  <option value="REJECTED">Rejected</option>
                  <option value="FAILED">Failed</option>
                </FilterSelect>
                <FilterSelect
                  label="Depth"
                  value={auditDepth}
                  onChange={(v) => {
                    setAuditDepth(v);
                    setAuditPage(1);
                  }}
                >
                  <option value="all">All depths</option>
                  <option value="0">Depth 0 (seeds)</option>
                  <option value="1">Depth 1 (citations)</option>
                  <option value="2+">Depth 2+ (outlinks)</option>
                </FilterSelect>
                <FilterSelect
                  label="Stage"
                  value={auditStage}
                  onChange={(v) => {
                    setAuditStage(v);
                    setAuditPage(1);
                  }}
                >
                  <option value="all">All stages ({auditStages.length})</option>
                  {auditStages.map((st) => (
                    <option key={st} value={st}>
                      {humanize(st)}
                    </option>
                  ))}
                </FilterSelect>
                <FilterSelect
                  label="Publisher"
                  value={auditPublisher}
                  onChange={(v) => {
                    setAuditPublisher(v);
                    setAuditPage(1);
                  }}
                >
                  <option value="all">All publishers ({auditPublishers.length})</option>
                  {auditPublishers.map((pub) => (
                    <option key={pub} value={pub}>
                      {pub}
                    </option>
                  ))}
                </FilterSelect>
                {auditFiltersActive && (
                  <ActionButton
                    variant="ghost"
                    icon={X}
                    onClick={() => {
                      setAuditSearch("");
                      setAuditDecision("all");
                      setAuditDepth("all");
                      setAuditStage("all");
                      setAuditPublisher("all");
                      setAuditPage(1);
                    }}
                  >
                    Reset
                  </ActionButton>
                )}
              </>
            }
            right={
              <FilterSelect label="Sort audit log" value={auditSort} onChange={(v) => setAuditSort(v as typeof auditSort)}>
                <option value="newest">Newest first</option>
                <option value="oldest">Oldest first</option>
              </FilterSelect>
            }
          />
          {isCrawlerLoading ? (
            loadingBlock("Loading the pipeline audit trail…")
          ) : (
            <>
              <DataTable
                data={pagedAuditItems}
                columns={auditColumns}
                getRowId={(i) => i.id}
                isRowActive={(i) => isItemAwaitingApproval(i.stage, i.decision)}
                caption="Pipeline audit log"
                empty={<EmptyState icon={Activity} title="No audit entries" description={items.length ? "No entries match these filters." : "Entries appear once a crawl evaluates URLs."} />}
              />
              {filteredAuditItems.length > 0 && (
                <PaginationControls
                  currentPage={auditPage}
                  pageSize={auditPageSize}
                  totalItems={filteredAuditItems.length}
                  onPageChange={setAuditPage}
                  onPageSizeChange={setAuditPageSize}
                  itemLabel="entries"
                />
              )}
            </>
          )}
        </section>
      )}

      {/* VIEW 5: MANUAL INGEST */}
      {activeView === "manual" && (
        <div className="mt-6 grid max-w-3xl gap-6">
          <SectionCard title="Ingest by URL" info="Fetches the page, extracts the report and generates a PDF copy.">
            <form
              className="flex flex-col gap-2 sm:flex-row"
              onSubmit={(e) => {
                e.preventDefault();
                if (url.trim()) manualIngest.mutate({ url });
              }}
            >
              <label htmlFor="ingest-url" className="sr-only">Report URL</label>
              <Input
                id="ingest-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://…"
                className="h-9 text-sm"
              />
              <ActionButton type="submit" variant="primary" icon={Upload} disabled={manualIngest.isPending || !url.trim()}>
                {manualIngest.isPending ? "Ingesting…" : "Ingest URL"}
              </ActionButton>
            </form>
          </SectionCard>

          <SectionCard title="Ingest pasted text">
            <label htmlFor="ingest-text" className="mb-1.5 block text-sm text-muted">
              Report text, malware analysis or incident notes
            </label>
            <Textarea
              id="ingest-text"
              rows={7}
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              placeholder="Paste the advisory or report text…"
              className="font-mono text-xs"
            />
            <div className="mt-3 flex justify-end">
              <ActionButton
                disabled={manualIngest.isPending || !pasted.trim()}
                onClick={() => manualIngest.mutate({ pastedText: pasted })}
                icon={FileText}
              >
                Ingest text
              </ActionButton>
            </div>
          </SectionCard>
        </div>
      )}

      {/* VIEW 6: CURATED CATALOG */}
      {activeView === "catalog" && (
        <SectionCard
          className="mt-6"
          title="Curated catalog"
          info="Pre-validated, high-signal intrusion reports from DFIR, Mandiant, Unit 42 and CISA."
          bodyClassName="px-5 pb-2 pt-3"
        >
          {catalog.isLoading ? (
            <div className="py-8 text-center text-sm text-muted">Loading catalog…</div>
          ) : !catalog.data?.length ? (
            <EmptyState icon={Database} title="The catalog is empty" />
          ) : (
            <ul className="divide-y divide-border">
              {catalog.data.map((c) => (
                <li key={c.url} className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <div className="font-medium text-fg">{c.title}</div>
                    <p className="mt-0.5 text-sm text-muted">
                      {c.sourceName} · {c.why}
                    </p>
                    <a
                      href={c.url}
                      target="_blank"
                      rel="noreferrer"
                      className="mt-1 flex items-center gap-1 text-xs text-subtle hover:text-fg"
                    >
                      <span className="truncate">{c.url}</span>
                      <ExternalLink className="size-3 shrink-0" />
                    </a>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    {c.alreadyIngested ? (
                      <StatusChip tone="success" dot>Ingested</StatusChip>
                    ) : (
                      <ActionButton
                        icon={Download}
                        disabled={manualIngest.isPending}
                        onClick={() => manualIngest.mutate({ url: c.url })}
                      >
                        Ingest
                      </ActionButton>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>
      )}
    </AppShell>
  );
}

const PIPELINE_STEPS = [
  { title: "Seed sources", body: "RSS feeds and permalinks from verified CTI publishers." },
  { title: "Graph expansion", body: "Follows citations, whitepapers and GitHub repositories." },
  { title: "Source discovery", body: "Scores domain trust and registers new sources." },
  { title: "Qualification", body: "Checks attack chains, IOC density and ATT&CK coverage." },
  { title: "Preservation", body: "Generates the PDF copy and stores the report." },
];

function queueTone(status?: string | null): Tone {
  const s = (status || "").toLowerCase();
  if (s === "ingested") return "success";
  if (s === "qualified") return "info";
  if (s === "duplicate") return "warning";
  if (s === "rejected" || s === "failed") return "danger";
  return "neutral";
}

function durationMs(start?: string | null, end?: string | null): number | null {
  if (!start || !end) return null;
  const ms = new Date(end).getTime() - new Date(start).getTime();
  return Number.isFinite(ms) && ms >= 0 ? ms : null;
}

function formatDuration(ms: number | null, status?: string): string {
  if (ms === null) return status === "running" ? "Running" : "—";
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ${sec % 60}s`;
  return `${Math.floor(min / 60)}h ${min % 60}m`;
}

function sortedJobsByRecency<T extends { startedAt: string | null; completedAt: string | null }>(list: T[]): T[] {
  return [...list].sort((a, b) => (b.completedAt || b.startedAt || "").localeCompare(a.completedAt || a.startedAt || ""));
}
