import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import {
  Activity,
  ArrowRight,
  ArrowUpDown,
  Bot,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Clock,
  Compass,
  Crosshair,
  Database,
  Download,
  ExternalLink,
  FileText,
  Filter,
  Flame,
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
  SlidersHorizontal,
  Sparkles,
  Upload,
  X,
  XCircle,
  Zap,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { IdBadge } from "@/components/id-badge";
import {
  formatAuditId,
  formatDomainId,
  formatEdgeId,
  formatJobId,
  formatOriginId,
  formatOutcomeId,
  formatReportId,
  formatSourceId,
  formatSystemId,
} from "@/lib/aie/ids";
import {
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
import type { CrawlConfig, ResourceKind } from "@/lib/aie/types";

export const Route = createFileRoute("/ingest")({ component: IngestPage });

const VIEWS = [
  { id: "crawler", label: "Autonomous Crawler", icon: Bot },
  { id: "queue", label: "Discovery Queue", icon: Compass },
  { id: "graph", label: "Discovery Graph & Sources", icon: Network },
  { id: "audit", label: "Pipeline Audit Log", icon: Activity },
  { id: "manual", label: "Manual Ingest", icon: Upload },
  { id: "catalog", label: "Curated Catalog", icon: Database },
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

function paginateList<T>(list: T[], page: number, pageSize: number | "all"): T[] {
  if (pageSize === "all") return list;
  const start = (page - 1) * pageSize;
  return list.slice(start, start + pageSize);
}

function PaginationControls({
  currentPage,
  pageSize,
  totalItems,
  onPageChange,
  onPageSizeChange,
  itemLabel = "items",
}: {
  currentPage: number;
  pageSize: number | "all";
  totalItems: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number | "all") => void;
  itemLabel?: string;
}) {
  const numericSize = pageSize === "all" ? Math.max(1, totalItems) : pageSize;
  const totalPages = pageSize === "all" ? 1 : Math.max(1, Math.ceil(totalItems / numericSize));
  const safePage = Math.min(Math.max(1, currentPage), totalPages);

  const startItem = totalItems === 0 ? 0 : (safePage - 1) * numericSize + 1;
  const endItem = pageSize === "all" ? totalItems : Math.min(totalItems, safePage * numericSize);

  const pages: (number | "...")[] = [];
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pages.push(i);
  } else {
    pages.push(1);
    if (safePage > 3) pages.push("...");
    const start = Math.max(2, safePage - 1);
    const end = Math.min(totalPages - 1, safePage + 1);
    for (let i = start; i <= end; i++) pages.push(i);
    if (safePage < totalPages - 2) pages.push("...");
    pages.push(totalPages);
  }

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-t border-border/60 pt-3 text-xs">
      <div className="flex flex-wrap items-center gap-3 text-muted">
        <span>
          Showing <span className="font-mono text-fg font-medium">{startItem}–{endItem}</span> of{" "}
          <span className="font-mono text-fg font-medium">{totalItems}</span> {itemLabel}
        </span>
        <div className="flex items-center gap-1.5 pl-2 border-l border-border/80">
          <span className="text-[11px] text-subtle">Per page:</span>
          <div className="flex rounded-md border border-border bg-bg-elevated p-0.5">
            {([10, 25, 50, 100, "all"] as const).map((sz) => (
              <button
                key={sz}
                type="button"
                onClick={() => {
                  onPageSizeChange(sz);
                  onPageChange(1);
                }}
                className={cn(
                  "rounded px-2 py-0.5 text-[11px] font-mono transition-colors",
                  pageSize === sz ? "bg-accent/20 text-accent font-semibold" : "text-subtle hover:text-fg",
                )}
              >
                {sz === "all" ? "All" : sz}
              </button>
            ))}
          </div>
        </div>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center gap-1">
          <button
            type="button"
            disabled={safePage <= 1}
            onClick={() => onPageChange(1)}
            className="flex h-7 w-7 items-center justify-center rounded border border-border/60 bg-bg-elevated text-subtle hover:text-fg hover:bg-bg-subtle disabled:opacity-40 disabled:pointer-events-none"
            title="First page"
          >
            <ChevronsLeft className="size-3.5" />
          </button>
          <button
            type="button"
            disabled={safePage <= 1}
            onClick={() => onPageChange(safePage - 1)}
            className="flex h-7 w-7 items-center justify-center rounded border border-border/60 bg-bg-elevated text-subtle hover:text-fg hover:bg-bg-subtle disabled:opacity-40 disabled:pointer-events-none"
            title="Previous page"
          >
            <ChevronLeft className="size-3.5" />
          </button>

          <div className="flex items-center gap-1">
            {pages.map((p, idx) =>
              p === "..." ? (
                <span key={`ell-${idx}`} className="px-1 text-subtle font-mono text-xs">…</span>
              ) : (
                <button
                  key={p}
                  type="button"
                  onClick={() => onPageChange(p)}
                  className={cn(
                    "h-7 min-w-[28px] rounded px-1.5 font-mono text-xs transition-colors",
                    safePage === p
                      ? "bg-accent text-bg font-semibold"
                      : "text-muted hover:bg-bg-subtle hover:text-fg border border-border/50",
                  )}
                >
                  {p}
                </button>
              ),
            )}
          </div>

          <button
            type="button"
            disabled={safePage >= totalPages}
            onClick={() => onPageChange(safePage + 1)}
            className="flex h-7 w-7 items-center justify-center rounded border border-border/60 bg-bg-elevated text-subtle hover:text-fg hover:bg-bg-subtle disabled:opacity-40 disabled:pointer-events-none"
            title="Next page"
          >
            <ChevronRight className="size-3.5" />
          </button>
          <button
            type="button"
            disabled={safePage >= totalPages}
            onClick={() => onPageChange(totalPages)}
            className="flex h-7 w-7 items-center justify-center rounded border border-border/60 bg-bg-elevated text-subtle hover:text-fg hover:bg-bg-subtle disabled:opacity-40 disabled:pointer-events-none"
            title="Last page"
          >
            <ChevronsRight className="size-3.5" />
          </button>
        </div>
      )}
    </div>
  );
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
    refetchInterval: (query) => (query.state.data?.activeJob ? 3000 : 25000),
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
    if (queueFilter === "qualified" && item.status !== "qualified" && item.status !== "awaiting_approval") return false;
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
    if (auditDecision !== "all" && itm.decision !== auditDecision) return false;
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

      {/* Live Telemetry Error Alert */}
      {crawlerState.isError && (
        <div className="mt-4 flex items-center justify-between rounded-xl border border-danger/40 bg-danger/10 p-4 text-xs text-danger">
          <div className="flex items-center gap-2">
            <XCircle className="size-4 shrink-0" />
            <span>Failed to sync live telemetry from MongoDB Atlas: {crawlerState.error?.message}</span>
          </div>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => crawlerState.refetch()}
            className="text-xs shrink-0"
          >
            Retry Connection
          </Button>
        </div>
      )}

      {/* Top Metrics Telemetry Row */}
      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-border bg-bg-elevated p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted">Discovered Candidates</span>
            <Compass className="size-4 text-accent" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            {isCrawlerLoading ? (
              <div className="h-8 w-20 rounded bg-border/40 animate-pulse my-0.5" />
            ) : (
              <span className="font-mono text-2xl font-bold text-fg">
                {state?.totalCounts?.discovered !== undefined
                  ? state.totalCounts.discovered.toLocaleString()
                  : discovered.length.toLocaleString()}
              </span>
            )}
            <span className="font-mono text-[11px] text-muted">URLs in store</span>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted">Monitored CTI Sources</span>
            <Network className="size-4 text-sage" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            {isCrawlerLoading ? (
              <div className="h-8 w-16 rounded bg-border/40 animate-pulse my-0.5" />
            ) : (
              <span className="font-mono text-2xl font-bold text-fg">
                {state?.totalCounts?.sources !== undefined
                  ? state.totalCounts.sources.toLocaleString()
                  : discoveredSources.length.toLocaleString()}
              </span>
            )}
            <span className="font-mono text-[11px] text-muted">active domains</span>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted">Crawl Job Runs</span>
            <Bot className="size-4 text-accent" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            {isCrawlerLoading ? (
              <div className="h-8 w-16 rounded bg-border/40 animate-pulse my-0.5" />
            ) : (
              <span className="font-mono text-2xl font-bold text-fg">
                {state?.totalCounts?.jobs !== undefined
                  ? state.totalCounts.jobs.toLocaleString()
                  : jobs.length.toLocaleString()}
              </span>
            )}
            <span className="font-mono text-[11px] text-muted">executed jobs</span>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted">Citation Graph Edges</span>
            <GitBranch className="size-4 text-subtle" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            {isCrawlerLoading ? (
              <div className="h-8 w-20 rounded bg-border/40 animate-pulse my-0.5" />
            ) : (
              <span className="font-mono text-2xl font-bold text-fg">
                {state?.totalCounts?.graphEdges !== undefined
                  ? state.totalCounts.graphEdges.toLocaleString()
                  : graphEdges.length.toLocaleString()}
              </span>
            )}
            <span className="font-mono text-[11px] text-muted">mapped links</span>
          </div>
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
              {v.id === "queue" && !isCrawlerLoading && discovered.length > 0 && (
                <span className="rounded-full bg-bg-subtle px-1.5 py-0.2 font-mono text-[10px] text-muted">
                  {discovered.length}
                </span>
              )}
              {v.id === "graph" && !isCrawlerLoading && (discoveredSources.length > 0 || graphEdges.length > 0) && (
                <span className="rounded-full bg-accent/20 text-accent px-1.5 py-0.2 font-mono text-[10px]">
                  +{discoveredSources.length || graphEdges.length}
                </span>
              )}
              {v.id === "audit" && !isCrawlerLoading && items.length > 0 && (
                <span className="rounded-full bg-bg-subtle px-1.5 py-0.2 font-mono text-[10px] text-muted">
                  {items.length}
                </span>
              )}
              {v.id === "catalog" && (catalog.data?.length ?? 0) > 0 && (
                <span className="rounded-full bg-bg-subtle px-1.5 py-0.2 font-mono text-[10px] text-muted">
                  {catalog.data?.length}
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
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-medium">Source Ingestion Performance</h3>
                  <span className="font-mono text-[11px] text-subtle">Atlas Live Feed</span>
                </div>
                {crawlerState.isLoading ? (
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 animate-pulse">
                    {[1, 2, 3, 4].map((i) => (
                      <div key={i} className="h-14 rounded-lg border border-border bg-bg-subtle/50" />
                    ))}
                  </div>
                ) : (state?.sourceStats && state.sourceStats.length > 0) ? (
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                    {state.sourceStats.map((s) => (
                      <div key={s.sourceName} className="rounded-lg border border-border bg-bg-subtle px-3 py-2 hover:border-border/80 transition-colors">
                        <div className="truncate text-xs font-medium text-fg">{s.sourceName}</div>
                        <div className="mt-1 flex items-baseline gap-1.5 font-mono text-xs text-muted">
                          <span className="text-fg font-medium">{s.ingested}</span>
                          <span>ingested</span>
                          <span className="text-subtle text-[11px]">({s.found} found)</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted">No source telemetry recorded yet.</p>
                )}
              </div>
            </div>

            {/* Quick Run & Scheduler Controls */}
            <div className="flex flex-col justify-between rounded-xl border border-border bg-bg-elevated p-5">
              <div>
                <h2 className="text-base font-medium">Engine Control Plane</h2>
                <p className="mt-1 text-xs text-muted">Live parameters applied to the frontier crawler.</p>

                {isCrawlerLoading ? (
                  <div className="mt-5 space-y-3 animate-pulse">
                    {[1, 2, 3, 4, 5, 6].map((i) => (
                      <div key={i} className="flex justify-between border-b border-border pb-2">
                        <div className="h-4 w-28 bg-border/40 rounded" />
                        <div className="h-4 w-20 bg-border/40 rounded" />
                      </div>
                    ))}
                  </div>
                ) : (
                  <dl className="mt-5 space-y-3 font-mono text-xs">
                    <div className="flex justify-between border-b border-border pb-2">
                      <dt className="text-subtle">Max Resources / Job</dt>
                      <dd className="text-accent font-semibold">{config.maxResourcesPerJob || config.maxResourcesPerRun || 35} URLs</dd>
                    </div>
                    <div className="flex justify-between border-b border-border pb-2">
                      <dt className="text-subtle">Execution Time Limit</dt>
                      <dd className="text-accent font-semibold">{config.maxRunTimeMinutes ?? 5} min cap</dd>
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
                )}
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
                <Link to="/settings" search={{ tab: "crawler" }}>
                  <Button
                    variant="secondary"
                    className="w-full text-xs gap-1.5"
                  >
                    <Settings className="size-3.5 text-muted" />
                    <span>Configure Granular Controls in Settings</span>
                    <ArrowRight className="size-3 text-muted ml-auto" />
                  </Button>
                </Link>
              </div>
            </div>
          </div>

          {/* Recent Crawl Job Runs History */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-3">
              <div>
                <h2 className="text-base font-medium">Recent Crawl Jobs History</h2>
                <p className="text-xs text-muted">Complete audit trail of automated and targeted graph discovery jobs.</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge tone="neutral" className="font-mono text-[10px]">
                  Total: {jobs.length} Runs
                </Badge>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setActiveView("audit")}
                  className="text-xs"
                >
                  Detailed Pipeline Audit
                </Button>
              </div>
            </div>

            {/* Filter Controls Row */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="relative flex-1 min-w-[200px] max-w-xs">
                <Search className="absolute left-2.5 top-2 size-3.5 text-subtle" />
                <input
                  type="text"
                  value={jobsSearch}
                  onChange={(e) => {
                    setJobsSearch(e.target.value);
                    setJobsPage(1);
                  }}
                  placeholder="Search Job ID or error details..."
                  className="w-full rounded-md border border-border bg-bg-subtle pl-8 pr-7 py-1.5 text-xs text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
                />
                {jobsSearch && (
                  <button
                    type="button"
                    onClick={() => setJobsSearch("")}
                    className="absolute right-2 top-2 text-subtle hover:text-fg"
                  >
                    <X className="size-3" />
                  </button>
                )}
              </div>

              {/* Status Filter */}
              <select
                value={jobsStatus}
                onChange={(e) => {
                  setJobsStatus(e.target.value);
                  setJobsPage(1);
                }}
                className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
              >
                <option value="all">All Statuses ({jobs.length})</option>
                <option value="completed">Completed ({jobs.filter((j) => j.status === "completed").length})</option>
                <option value="running">Running ({jobs.filter((j) => j.status === "running").length})</option>
                <option value="failed">Failed ({jobs.filter((j) => j.status === "failed").length})</option>
              </select>

              {/* Trigger Filter */}
              <select
                value={jobsTrigger}
                onChange={(e) => {
                  setJobsTrigger(e.target.value);
                  setJobsPage(1);
                }}
                className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
              >
                <option value="all">All Triggers</option>
                <option value="MANUAL">MANUAL</option>
                <option value="SCHEDULED">SCHEDULED</option>
                <option value="SEARCH">SEARCH</option>
              </select>

              {/* Sort Order */}
              <select
                value={jobsSort}
                onChange={(e) => setJobsSort(e.target.value as any)}
                className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
              </select>
            </div>

            {isCrawlerLoading ? (
              <div className="py-10 text-center">
                <RefreshCw className="size-5 text-accent animate-spin mx-auto mb-2" />
                <p className="text-xs text-muted">Retrieving crawl jobs execution history from database...</p>
              </div>
            ) : filteredJobs.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted">No crawl jobs match the selected filters.</p>
            ) : (
              <div className="space-y-4">
                <div className="overflow-x-auto rounded-lg border border-border">
                  <table className="w-full min-w-[850px] text-left text-xs">
                    <thead className="border-b border-border bg-bg-subtle/70 font-mono text-[10px] uppercase text-subtle">
                      <tr>
                        <th className="py-2.5 px-3">Job ID</th>
                        <th className="py-2.5 px-3">Trigger</th>
                        <th className="py-2.5 px-3">Status</th>
                        <th className="py-2.5 px-3">Discovered</th>
                        <th className="py-2.5 px-3">Evaluated</th>
                        <th className="py-2.5 px-3">Qualified</th>
                        <th className="py-2.5 px-3">Ingested</th>
                        <th className="py-2.5 px-3">New Sources</th>
                        <th className="py-2.5 px-3">Duplicates</th>
                        <th className="py-2.5 px-3">Rejected</th>
                        <th className="py-2.5 px-3">Completed</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {pagedJobs.map((j) => (
                        <tr key={j.id} className="hover:bg-bg-subtle/40">
                          <td className="py-2.5 px-3">
                            <IdBadge
                              id={formatJobId(j.id, j.triggerType)}
                              category="job"
                              tone={j.status === "completed" ? "sage" : j.status === "running" ? "accent" : "danger"}
                              size="xs"
                            />
                          </td>
                          <td className="py-2.5 px-3 font-mono text-subtle">{j.triggerType}</td>
                          <td className="py-2.5 px-3">
                            <div className="flex flex-col gap-0.5">
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
                              {j.errorSummary ? (
                                <span className="text-[10px] text-danger font-mono max-w-[150px] truncate" title={j.errorSummary}>
                                  {j.errorSummary}
                                </span>
                              ) : null}
                            </div>
                          </td>
                          <td className="py-2.5 px-3 font-mono">{j.discoveredCount}</td>
                          <td className="py-2.5 px-3 font-mono text-muted">{j.evaluatedCount || j.discoveredCount}</td>
                          <td className="py-2.5 px-3 font-mono text-sage">{j.qualifiedCount}</td>
                          <td className="py-2.5 px-3 font-mono font-medium text-accent">{j.ingestedCount}</td>
                          <td className="py-2.5 px-3 font-mono text-sage">{j.newSourcesCount ? `+${j.newSourcesCount}` : "0"}</td>
                          <td className="py-2.5 px-3 font-mono text-warn">{j.duplicateCount}</td>
                          <td className="py-2.5 px-3 font-mono text-muted">{j.rejectedCount}</td>
                          <td className="py-2.5 px-3 font-mono text-subtle">{formatDateTime(j.completedAt || j.startedAt, "Running...")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <PaginationControls
                  currentPage={jobsPage}
                  pageSize={jobsPageSize}
                  totalItems={filteredJobs.length}
                  onPageChange={setJobsPage}
                  onPageSizeChange={setJobsPageSize}
                  itemLabel="crawl jobs"
                />
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
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-medium">Candidate Discovery Queue</h2>
                <Badge tone="accent" className="font-mono text-[10px]">
                  {isCrawlerLoading ? "…" : `${discovered.length} Total`}
                </Badge>
                {!isCrawlerLoading && filteredDiscovered.length !== discovered.length && (
                  <Badge tone="neutral" className="font-mono text-[10px]">
                    {filteredDiscovered.length} Filtered
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted">
                Candidate resources discovered across seeds, citations, and outlink graphs. Default view: 25 items per page.
              </p>
            </div>

            {/* Status Pills */}
            <div className="flex rounded-lg border border-border bg-bg-elevated p-0.5">
              {(
                [
                  { id: "all", label: `All (${isCrawlerLoading ? "…" : discovered.length})` },
                  {
                    id: "qualified",
                    label: `Qualified (${isCrawlerLoading ? "…" : discovered.filter((d) => d.status === "qualified" || d.status === "awaiting_approval").length})`,
                  },
                  {
                    id: "ingested",
                    label: `Ingested (${isCrawlerLoading ? "…" : discovered.filter((d) => d.status === "ingested").length})`,
                  },
                  {
                    id: "rejected",
                    label: `Rejected (${isCrawlerLoading ? "…" : discovered.filter((d) => d.status === "rejected").length})`,
                  },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => {
                    setQueueFilter(tab.id);
                    setQueuePage(1);
                  }}
                  className={cn(
                    "rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                    queueFilter === tab.id ? "bg-fg text-bg" : "text-muted hover:text-fg",
                  )}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Rich Filter & Search Toolbar */}
          <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border bg-bg-elevated p-3 text-xs">
            {/* Search Input */}
            <div className="relative flex-1 min-w-[220px] max-w-sm">
              <Search className="absolute left-2.5 top-2 size-3.5 text-subtle" />
              <input
                type="text"
                value={queueSearch}
                onChange={(e) => {
                  setQueueSearch(e.target.value);
                  setQueuePage(1);
                }}
                placeholder="Search candidates (title, URL, publisher, domain)..."
                className="w-full rounded-md border border-border bg-bg-subtle pl-8 pr-7 py-1.5 text-xs text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
              />
              {queueSearch && (
                <button
                  type="button"
                  onClick={() => {
                    setQueueSearch("");
                    setQueuePage(1);
                  }}
                  className="absolute right-2 top-2 text-subtle hover:text-fg"
                >
                  <X className="size-3" />
                </button>
              )}
            </div>

            {/* Resource Kind Dropdown */}
            <select
              value={queueKind}
              onChange={(e) => {
                setQueueKind(e.target.value);
                setQueuePage(1);
              }}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
            >
              <option value="all">All Resource Types ({queueKinds.length})</option>
              {queueKinds.map((k) => (
                <option key={k} value={k}>
                  {k.replace(/_/g, " ")}
                </option>
              ))}
            </select>

            {/* Quality Threshold Dropdown */}
            <select
              value={queueMinScore}
              onChange={(e) => {
                setQueueMinScore(Number(e.target.value));
                setQueuePage(1);
              }}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
            >
              <option value={0}>Any Quality Score</option>
              <option value={0.8}>≥ 80% High Quality</option>
              <option value={0.6}>≥ 60% Moderate</option>
              <option value={0.4}>≥ 40% Minimal</option>
            </select>

            {/* Source Domain Dropdown */}
            <select
              value={queueDomain}
              onChange={(e) => {
                setQueueDomain(e.target.value);
                setQueuePage(1);
              }}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none max-w-[170px] truncate"
            >
              <option value="all">All Source Domains ({queueDomains.length})</option>
              {queueDomains.map((dm) => (
                <option key={dm} value={dm}>
                  {dm}
                </option>
              ))}
            </select>

            {/* Novel TTP Toggle */}
            <button
              type="button"
              onClick={() => {
                setQueueNovelOnly(!queueNovelOnly);
                setQueuePage(1);
              }}
              className={cn(
                "flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors",
                queueNovelOnly
                  ? "border-danger/60 bg-danger/15 text-danger font-semibold"
                  : "border-border bg-bg-subtle text-muted hover:text-fg",
              )}
            >
              <Flame className="size-3.5" />
              <span>Novel TTPs ({discovered.filter((d) => d.isEmergingTechnique).length})</span>
            </button>

            {/* Sort Order Dropdown */}
            <select
              value={queueSort}
              onChange={(e) => setQueueSort(e.target.value as any)}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
            >
              <option value="newest">Latest Discovered</option>
              <option value="oldest">Oldest Discovered</option>
              <option value="score_desc">Highest Quality Score</option>
              <option value="title_asc">Title (A–Z)</option>
              <option value="domain_asc">Domain (A–Z)</option>
            </select>

            {/* Reset Filter Button */}
            {(queueSearch || queueKind !== "all" || queueMinScore > 0 || queueNovelOnly || queueDomain !== "all" || queueFilter !== "all") && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setQueueSearch("");
                  setQueueKind("all");
                  setQueueMinScore(0);
                  setQueueNovelOnly(false);
                  setQueueDomain("all");
                  setQueueFilter("all");
                  setQueuePage(1);
                }}
                className="h-7 px-2 text-xs text-subtle hover:text-fg"
              >
                <X className="size-3 mr-1" />
                Reset
              </Button>
            )}
          </div>

          {isCrawlerLoading ? (
            <div className="rounded-xl border border-border bg-bg-elevated p-12 text-center">
              <RefreshCw className="size-6 text-accent animate-spin mx-auto mb-3" />
              <p className="text-sm font-medium text-fg">Synchronizing Discovery Queue...</p>
              <p className="mt-1 text-xs text-muted">Retrieving candidate URLs, qualification scores, and triage status from MongoDB Atlas.</p>
            </div>
          ) : filteredDiscovered.length === 0 ? (
            <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
              No discovered resources match the selected filters.
            </div>
          ) : (
            <div className="space-y-4">
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
                    {pagedDiscovered.map((res) => {
                      const outcomeMeta = formatOutcomeId(res.status, res.reportId || res.id, res.canonicalUrl);
                      const prefix =
                        res.status === "ingested"
                          ? "ING"
                          : res.status === "duplicate"
                            ? "DUP"
                            : res.status === "rejected"
                              ? "REJ"
                              : res.status === "failed"
                                ? "FAIL"
                                : "DISC";

                      return (
                        <tr key={res.id || res.canonicalUrl} className="hover:bg-bg-subtle/30">
                          <td className="p-3">
                            <div className="flex flex-col items-start gap-1">
                              <IdBadge
                                id={outcomeMeta.id}
                                category={outcomeMeta.category}
                                tone={outcomeMeta.tone}
                                size="xs"
                                prefixLabel={prefix}
                              />
                              <span
                                className={cn(
                                  "font-mono text-[9px] uppercase tracking-wider px-1 py-0.2 rounded font-semibold",
                                  res.status === "ingested"
                                    ? "text-emerald-400 bg-emerald-950/40"
                                    : res.status === "duplicate"
                                      ? "text-amber-400 bg-amber-950/40"
                                      : res.status === "rejected"
                                        ? "text-rose-400 bg-rose-950/40"
                                        : res.status === "failed"
                                          ? "text-red-400 bg-red-950/40"
                                          : "text-cyan-400 bg-cyan-950/40",
                                )}
                              >
                                {res.status.replace(/_/g, " ")}
                              </span>
                            </div>
                          </td>
                          <td className="p-3 font-mono text-[11px] text-muted">
                            {res.resourceKind || res.classification}
                          </td>
                          <td className="max-w-[280px] p-3">
                            {res.reportId && (
                              <div className="mb-1">
                                <IdBadge id={formatReportId(res.reportId)} category="report" size="xs" prefixLabel="RPT" />
                              </div>
                            )}
                            <div className="flex items-center gap-1.5 truncate">
                              <span className="truncate font-medium text-fg">{res.title}</span>
                              {res.isEmergingTechnique && (
                                <span className="shrink-0 rounded bg-danger/15 px-1 py-0.2 text-[9px] font-bold text-danger font-mono" title={res.noveltyRationale || "Novel unmapped procedure"}>
                                  NOVEL
                                </span>
                              )}
                            </div>
                            <a
                              href={res.canonicalUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="truncate font-mono text-[10px] text-subtle hover:text-accent flex items-center gap-1"
                            >
                              <span className="truncate">{res.canonicalUrl}</span>
                              <ExternalLink className="size-2.5 shrink-0" />
                            </a>
                            {res.rejectReason && (
                              <div className="mt-0.5 truncate font-mono text-[10px] text-danger/80" title={res.rejectReason}>
                                {res.rejectReason}
                              </div>
                            )}
                          </td>
                          <td className="p-3">
                            <div className="flex flex-col items-start gap-1">
                              <span className="text-muted text-xs">{res.sourceDomain}</span>
                              <IdBadge id={formatDomainId(res.sourceDomain)} category="domain" size="xs" />
                            </div>
                          </td>
                          <td className="p-3 font-mono text-[10px] text-subtle">
                            {res.discoveryMethod.replace(/_/g, " ")}
                          </td>
                        <td className="p-3 font-mono">
                          <div>{res.qualityScore !== null ? `${Math.round(res.qualityScore * 100)}%` : "—"}</div>
                          {res.simulationScore !== undefined && res.simulationScore > 0 && (
                            <div className="text-[10px] font-mono text-accent">
                              SIM {Math.round(res.simulationScore * 100)}%
                            </div>
                          )}
                        </td>
                        <td className="p-3 text-right">
                          {res.status === "ingested" ? (
                            res.reportId ? (
                              <Link
                                to="/library/$reportId"
                                params={{ reportId: res.reportId }}
                                className="inline-flex items-center gap-1 text-accent hover:underline text-xs font-medium"
                              >
                                View in Library
                              </Link>
                            ) : (
                              <Link
                                to="/library"
                                search={{ q: res.title }}
                                className="inline-flex items-center gap-1 text-accent hover:underline text-xs font-medium"
                              >
                                View in Library
                              </Link>
                            )
                          ) : (
                            <Button
                              size="sm"
                              variant="secondary"
                              className="h-7 text-xs gap-1.5"
                              disabled={ingestQueueItem.isPending}
                              onClick={() => ingestQueueItem.mutate(res.id)}
                            >
                              {ingestQueueItem.isPending && ingestingId === res.id ? (
                                <>
                                  <RefreshCw className="size-3 animate-spin text-accent" />
                                  <span>Acquiring…</span>
                                </>
                              ) : (
                                <>
                                  <Download className="size-3 text-muted" />
                                  <span>Acquire & Ingest</span>
                                </>
                              )}
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                  </tbody>
                </table>
              </div>

              <PaginationControls
                currentPage={queuePage}
                pageSize={queuePageSize}
                totalItems={filteredDiscovered.length}
                onPageChange={setQueuePage}
                onPageSizeChange={setQueuePageSize}
                itemLabel="candidate resources"
              />
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
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-3">
              <div>
                <h3 className="text-sm font-medium">Autonomously Discovered CTI Sources</h3>
                <p className="text-xs text-muted">External domains identified via hyperlinks, citations, and research papers.</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge tone="accent">
                  {isCrawlerLoading ? "…" : `Total: ${discoveredSources.length} Domains`}
                </Badge>
                {!isCrawlerLoading && filteredSources.length !== discoveredSources.length && (
                  <Badge tone="neutral">{filteredSources.length} Filtered</Badge>
                )}
              </div>
            </div>

            {/* Discovered Sources Filter Toolbar */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="relative flex-1 min-w-[200px] max-w-xs">
                <Search className="absolute left-2.5 top-2 size-3.5 text-subtle" />
                <input
                  type="text"
                  value={sourcesSearch}
                  onChange={(e) => {
                    setSourcesSearch(e.target.value);
                    setSourcesPage(1);
                  }}
                  placeholder="Search discovered domain or publisher..."
                  className="w-full rounded-md border border-border bg-bg-subtle pl-8 pr-7 py-1.5 text-xs text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
                />
                {sourcesSearch && (
                  <button
                    type="button"
                    onClick={() => {
                      setSourcesSearch("");
                      setSourcesPage(1);
                    }}
                    className="absolute right-2 top-2 text-subtle hover:text-fg"
                  >
                    <X className="size-3" />
                  </button>
                )}
              </div>

              <select
                value={sourcesTrust}
                onChange={(e) => {
                  setSourcesTrust(e.target.value as any);
                  setSourcesPage(1);
                }}
                className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
              >
                <option value="all">All Trust Levels</option>
                <option value="high">High Trust (≥ 90%)</option>
                <option value="medium">Medium Trust (≥ 80%)</option>
              </select>

              <select
                value={sourcesSort}
                onChange={(e) => setSourcesSort(e.target.value as any)}
                className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
              >
                <option value="trust_desc">Highest Trust Score</option>
                <option value="resources_desc">Most Discovered Resources</option>
                <option value="domain_asc">Domain (A–Z)</option>
                <option value="newest">Recently Discovered</option>
              </select>
            </div>

            {isCrawlerLoading ? (
              <div className="rounded-xl border border-border/60 bg-bg p-8 text-center">
                <RefreshCw className="size-5 text-accent animate-spin mx-auto mb-2" />
                <p className="text-xs text-muted">Analyzing outlink graph and discovered CTI domain authorities...</p>
              </div>
            ) : filteredSources.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted">
                No external sources match the current filter criteria.
              </p>
            ) : (
              <div className="space-y-4">
                <div className="overflow-x-auto rounded-lg border border-border">
                  <table className="w-full min-w-[700px] text-left text-xs">
                    <thead className="border-b border-border bg-bg-subtle/70 font-mono text-[10px] uppercase text-subtle">
                      <tr>
                        <th className="py-2.5 px-3">Domain</th>
                        <th className="py-2.5 px-3">Status</th>
                        <th className="py-2.5 px-3">Trust Score</th>
                        <th className="py-2.5 px-3">Resources</th>
                        <th className="py-2.5 px-3">Referrer / Parent</th>
                        <th className="py-2.5 px-3">Discovered Date</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {pagedSources.map((src) => (
                        <tr key={src.domain} className="hover:bg-bg-subtle/40">
                          <td className="py-2.5 px-3">
                            <div className="flex flex-wrap items-center gap-1.5 mb-1">
                              <IdBadge id={formatSourceId(src.id, src.domain)} category="source" size="xs" prefixLabel="SRC" />
                              <IdBadge id={formatDomainId(src.domain)} category="domain" size="xs" />
                            </div>
                            <a href={src.homepageUrl} target="_blank" rel="noreferrer" className="hover:text-accent font-mono text-fg font-medium flex items-center gap-1.5">
                              <span>{src.domain}</span>
                              <ExternalLink className="size-2.5 text-subtle" />
                            </a>
                            <div className="text-[10px] text-subtle font-sans">{src.name}</div>
                          </td>
                          <td className="py-2.5 px-3">
                            <Badge tone={src.status === "approved" ? "sage" : "neutral"}>
                              {src.status}
                            </Badge>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-accent font-medium">
                            {Math.round(src.trustScore * 100)}%
                          </td>
                          <td className="py-2.5 px-3 font-mono">{src.resourceCount}</td>
                          <td className="py-2.5 px-3">
                            <div className="flex flex-col items-start gap-1">
                              <span className="text-muted font-mono text-[11px]">{src.parentSource || "Seed"}</span>
                              <IdBadge id={formatOriginId(src.parentSource)} category="origin" size="xs" />
                            </div>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-subtle text-[10px]">{formatDateTime(src.firstDiscoveredAt)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <PaginationControls
                  currentPage={sourcesPage}
                  pageSize={sourcesPageSize}
                  totalItems={filteredSources.length}
                  onPageChange={setSourcesPage}
                  onPageSizeChange={setSourcesPageSize}
                  itemLabel="discovered sources"
                />
              </div>
            )}
          </div>

          {/* Citation Graph Edges */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-3">
              <div>
                <h3 className="text-sm font-medium">Recent Citation & Outlink Graph Edges</h3>
                <p className="text-xs text-muted">Relationship links established between documents, repositories, and PDFs.</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge tone="neutral">
                  {isCrawlerLoading ? "…" : `Total: ${graphEdges.length} Edges`}
                </Badge>
                {!isCrawlerLoading && filteredEdges.length !== graphEdges.length && (
                  <Badge tone="accent">{filteredEdges.length} Filtered</Badge>
                )}
              </div>
            </div>

            {/* Graph Edges Filter Toolbar */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="relative flex-1 min-w-[200px] max-w-xs">
                <Search className="absolute left-2.5 top-2 size-3.5 text-subtle" />
                <input
                  type="text"
                  value={edgesSearch}
                  onChange={(e) => {
                    setEdgesSearch(e.target.value);
                    setEdgesPage(1);
                  }}
                  placeholder="Search source origin, target, or context..."
                  className="w-full rounded-md border border-border bg-bg-subtle pl-8 pr-7 py-1.5 text-xs text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
                />
                {edgesSearch && (
                  <button
                    type="button"
                    onClick={() => {
                      setEdgesSearch("");
                      setEdgesPage(1);
                    }}
                    className="absolute right-2 top-2 text-subtle hover:text-fg"
                  >
                    <X className="size-3" />
                  </button>
                )}
              </div>

              <select
                value={edgesRelationship}
                onChange={(e) => {
                  setEdgesRelationship(e.target.value);
                  setEdgesPage(1);
                }}
                className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
              >
                <option value="all">All Relationships ({edgeRelationships.length})</option>
                {edgeRelationships.map((rel) => (
                  <option key={rel} value={rel}>
                    {rel.replace(/_/g, " ")}
                  </option>
                ))}
              </select>

              <select
                value={edgesSort}
                onChange={(e) => setEdgesSort(e.target.value as any)}
                className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
              </select>
            </div>

            {isCrawlerLoading ? (
              <div className="rounded-xl border border-border/60 bg-bg p-8 text-center">
                <RefreshCw className="size-5 text-accent animate-spin mx-auto mb-2" />
                <p className="text-xs text-muted">Mapping citation relationships and threat intelligence links...</p>
              </div>
            ) : filteredEdges.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted">No graph edges match the current filters.</p>
            ) : (
              <div className="space-y-4">
                <div className="overflow-x-auto rounded-lg border border-border">
                  <table className="w-full min-w-[750px] text-left text-xs">
                    <thead className="border-b border-border bg-bg-subtle/70 font-mono text-[10px] uppercase text-subtle">
                      <tr>
                        <th className="py-2.5 px-3">Source Origin</th>
                        <th className="py-2.5 px-3">Relationship</th>
                        <th className="py-2.5 px-3">Target Reference</th>
                        <th className="py-2.5 px-3">Label / Context</th>
                        <th className="py-2.5 px-3">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {pagedEdges.map((edge) => (
                        <tr key={edge.id} className="hover:bg-bg-subtle/40">
                          <td className="max-w-[220px] py-2.5 px-3">
                            <div className="flex flex-wrap items-center gap-1 mb-1">
                              <IdBadge id={formatEdgeId(edge.id, `${edge.from}->${edge.to}`)} category="edge" size="xs" prefixLabel="EDGE" />
                              <IdBadge id={formatDomainId(edge.sourceDomain || edge.from)} category="domain" size="xs" />
                            </div>
                            <div className="truncate font-mono text-[11px] text-muted">{edge.from}</div>
                          </td>
                          <td className="py-2.5 px-3">
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
                          <td className="max-w-[260px] py-2.5 px-3">
                            <div className="mb-1">
                              <IdBadge id={formatDomainId(edge.targetDomain || edge.to)} category="domain" size="xs" />
                            </div>
                            <a href={edge.to} target="_blank" rel="noreferrer" className="hover:text-accent font-mono text-[11px] text-fg flex items-center gap-1 truncate">
                              <span className="truncate">{edge.to}</span>
                              <ExternalLink className="size-2.5 shrink-0 text-subtle" />
                            </a>
                          </td>
                          <td className="max-w-[180px] py-2.5 px-3 truncate text-muted text-[11px]">
                            {edge.label}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[10px] text-subtle">
                            {formatDateTime(edge.createdAt)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <PaginationControls
                  currentPage={edgesPage}
                  pageSize={edgesPageSize}
                  totalItems={filteredEdges.length}
                  onPageChange={setEdgesPage}
                  onPageSizeChange={setEdgesPageSize}
                  itemLabel="graph edges"
                />
              </div>
            )}
          </div>
        </div>
      )}

      {/* VIEW 4: PIPELINE AUDIT LOG */}
      {activeView === "audit" && (
        <div className="space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-medium">Pipeline Progression Audit Log</h2>
                <Badge tone="accent" className="font-mono text-[10px]">
                  {isCrawlerLoading ? "…" : `${items.length} Total`}
                </Badge>
                {!isCrawlerLoading && filteredAuditItems.length !== items.length && (
                  <Badge tone="neutral" className="font-mono text-[10px]">
                    {filteredAuditItems.length} Filtered
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted">
                Complete visibility into every evaluated URL across the 7 pipeline stages. Default view: 25 items per page.
              </p>
            </div>
          </div>

          {/* Audit Filter Toolbar */}
          <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border bg-bg-elevated p-3 text-xs">
            {/* Search Input */}
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="absolute left-2.5 top-2 size-3.5 text-subtle" />
              <input
                type="text"
                value={auditSearch}
                onChange={(e) => {
                  setAuditSearch(e.target.value);
                  setAuditPage(1);
                }}
                placeholder="Search URL, title, publisher, reason..."
                className="w-full rounded-md border border-border bg-bg-subtle pl-8 pr-7 py-1.5 text-xs text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
              />
              {auditSearch && (
                <button
                  type="button"
                  onClick={() => {
                    setAuditSearch("");
                    setAuditPage(1);
                  }}
                  className="absolute right-2 top-2 text-subtle hover:text-fg"
                >
                  <X className="size-3" />
                </button>
              )}
            </div>

            {/* Decision Filter */}
            <select
              value={auditDecision}
              onChange={(e) => {
                setAuditDecision(e.target.value);
                setAuditPage(1);
              }}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
            >
              <option value="all">All Decisions</option>
              <option value="INGESTED">INGESTED</option>
              <option value="AWAITING_APPROVAL">AWAITING APPROVAL</option>
              <option value="QUALIFIED">QUALIFIED</option>
              <option value="DUPLICATE">DUPLICATE</option>
              <option value="REJECTED">REJECTED</option>
              <option value="FAILED">FAILED</option>
            </select>

            {/* Depth Filter */}
            <select
              value={auditDepth}
              onChange={(e) => {
                setAuditDepth(e.target.value);
                setAuditPage(1);
              }}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
            >
              <option value="all">All Depths</option>
              <option value="0">Depth 0 (Seeds)</option>
              <option value="1">Depth 1 (Citations)</option>
              <option value="2+">Depth 2+ (Graph Outlinks)</option>
            </select>

            {/* Stage Filter */}
            <select
              value={auditStage}
              onChange={(e) => {
                setAuditStage(e.target.value);
                setAuditPage(1);
              }}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none max-w-[150px] truncate"
            >
              <option value="all">All Stages ({auditStages.length})</option>
              {auditStages.map((st) => (
                <option key={st} value={st}>
                  {st.replace(/_/g, " ")}
                </option>
              ))}
            </select>

            {/* Publisher Filter */}
            <select
              value={auditPublisher}
              onChange={(e) => {
                setAuditPublisher(e.target.value);
                setAuditPage(1);
              }}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none max-w-[160px] truncate"
            >
              <option value="all">All Publishers ({auditPublishers.length})</option>
              {auditPublishers.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>

            {/* Sort Order */}
            <select
              value={auditSort}
              onChange={(e) => setAuditSort(e.target.value as any)}
              className="rounded-md border border-border bg-bg-subtle px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
            >
              <option value="newest">Newest First</option>
              <option value="oldest">Oldest First</option>
            </select>

            {/* Reset Filters */}
            {(auditSearch || auditDecision !== "all" || auditDepth !== "all" || auditStage !== "all" || auditPublisher !== "all") && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setAuditSearch("");
                  setAuditDecision("all");
                  setAuditDepth("all");
                  setAuditStage("all");
                  setAuditPublisher("all");
                  setAuditPage(1);
                }}
                className="h-7 px-2 text-xs text-subtle hover:text-fg"
              >
                <X className="size-3 mr-1" />
                Reset
              </Button>
            )}
          </div>

          {isCrawlerLoading ? (
            <div className="rounded-xl border border-border bg-bg-elevated p-12 text-center">
              <RefreshCw className="size-6 text-accent animate-spin mx-auto mb-3" />
              <p className="text-sm font-medium text-fg">Loading Pipeline Audit Trail...</p>
              <p className="mt-1 text-xs text-muted">Fetching multi-stage URL evaluations, content extractions, and ingestion verdicts from MongoDB Atlas.</p>
            </div>
          ) : filteredAuditItems.length === 0 ? (
            <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
              No audit log items match the selected filters.
            </div>
          ) : (
            <div className="space-y-4">
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
                    {pagedAuditItems.map((itm) => {
                      const outcomeMeta = formatOutcomeId(itm.decision, itm.id, itm.url);
                      const prefix =
                        itm.decision === "INGESTED"
                          ? "ING"
                          : itm.decision === "DUPLICATE"
                            ? "DUP"
                            : itm.decision === "REJECTED"
                              ? "REJ"
                              : itm.decision === "FAILED"
                                ? "FAIL"
                                : "DISC";

                      return (
                        <tr key={itm.id} className="hover:bg-bg-subtle/30">
                          <td className="p-3">
                            <div className="flex flex-col items-start gap-1">
                              <IdBadge
                                id={formatAuditId(itm.id)}
                                category="audit"
                                size="xs"
                                prefixLabel="AUD"
                              />
                              <IdBadge
                                id={outcomeMeta.id}
                                category={outcomeMeta.category}
                                tone={outcomeMeta.tone}
                                size="xs"
                                label={itm.decision}
                                prefixLabel={prefix}
                              />
                            </div>
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
                          <td className="p-3">
                            <div className="flex flex-col items-start gap-1">
                              <span className="text-muted text-xs">{itm.publisher}</span>
                              <IdBadge id={formatDomainId(itm.canonicalUrl)} category="domain" size="xs" />
                            </div>
                          </td>
                          <td className="max-w-[300px] p-3 text-muted">
                            <p className="line-clamp-2 text-[11px] leading-relaxed">{itm.reason}</p>
                          </td>
                          <td className="p-3 font-mono text-[10px] text-subtle">
                            {formatDateTime(itm.createdAt)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <PaginationControls
                currentPage={auditPage}
                pageSize={auditPageSize}
                totalItems={filteredAuditItems.length}
                onPageChange={setAuditPage}
                onPageSizeChange={setAuditPageSize}
                itemLabel="audit log entries"
              />
            </div>
          )}
        </div>
      )}

      {/* VIEW 5: MANUAL INGEST */}
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

      {/* VIEW 6: CURATED CATALOG */}
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
                    variant={c.alreadyIngested ? "secondary" : "primary"}
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
