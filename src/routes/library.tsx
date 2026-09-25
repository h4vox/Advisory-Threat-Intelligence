import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState, useEffect } from "react";
import { z } from "zod";
import {
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Download,
  Eye,
  FileText,
  Filter,
  Flame,
  Printer,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Tag,
  Workflow,
  X,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { IdBadge } from "@/components/id-badge";
import { formatDomainId, formatReportId } from "@/lib/aie/ids";
import { getReportPdf, listReports, auditLibraryWithAi, evaluateReportWithAi } from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";
import type { ReportListItem, ResourceKind } from "@/lib/aie/types";

const librarySearchSchema = z.object({
  q: z.string().optional(),
  selected: z.string().optional(),
  highlight: z.string().optional(),
  pdf: z.string().optional(),
  tag: z.string().optional(),
  sort: z.enum(["newest", "quality", "iocs", "words", "rejected"]).optional(),
});

export const Route = createFileRoute("/library")({
  validateSearch: (search) => librarySearchSchema.parse(search),
  component: LibraryPage,
});

const RESOURCE_KINDS: { id: string; label: string }[] = [
  { id: "ALL", label: "All Intelligence" },
  { id: "FULL_ATTACK_CHAIN", label: "Attack Chains" },
  { id: "CAMPAIGN_INTEL", label: "Campaigns" },
  { id: "PROCEDURE_DEEPDIVE", label: "Procedures & TTPs" },
  { id: "MALWARE_ANALYSIS", label: "Malware Analysis" },
  { id: "DETECTION_GUIDANCE", label: "Detections & Sigma" },
  { id: "VULNERABILITY_ADVISORY", label: "Vulnerability Advisories" },
  { id: "THREAT_ACTOR_DOSSIER", label: "Threat Actor Dossiers" },
];

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
  itemLabel = "intelligence records",
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
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-t border-border/60 pt-4 text-xs">
      <div className="flex flex-wrap items-center gap-3 text-muted">
        <span>
          Showing <span className="font-mono text-fg font-medium">{startItem}–{endItem}</span> of{" "}
          <span className="font-mono text-fg font-medium">{totalItems}</span> {itemLabel}
        </span>
        <div className="flex items-center gap-1.5 pl-2 border-l border-border/80">
          <span className="text-[11px] text-subtle">Per page:</span>
          <div className="flex rounded-md border border-border bg-bg-elevated p-0.5">
            {([20, 40, 60, 100, "all"] as const).map((sz) => (
              <button
                key={sz}
                type="button"
                onClick={() => {
                  onPageSizeChange(sz);
                  onPageChange(1);
                }}
                className={cn(
                  "rounded px-2 py-0.5 text-[11px] font-mono transition-colors cursor-pointer",
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
            className="flex h-7 w-7 items-center justify-center rounded border border-border/60 bg-bg-elevated text-subtle hover:text-fg hover:bg-bg-subtle disabled:opacity-40 disabled:pointer-events-none cursor-pointer"
            title="First page"
          >
            <ChevronsLeft className="size-3.5" />
          </button>
          <button
            type="button"
            disabled={safePage <= 1}
            onClick={() => onPageChange(safePage - 1)}
            className="flex h-7 w-7 items-center justify-center rounded border border-border/60 bg-bg-elevated text-subtle hover:text-fg hover:bg-bg-subtle disabled:opacity-40 disabled:pointer-events-none cursor-pointer"
            title="Previous page"
          >
            <ChevronLeft className="size-3.5" />
          </button>

          <div className="flex items-center gap-1 px-1">
            {pages.map((p, idx) =>
              p === "..." ? (
                <span key={`ellipsis-${idx}`} className="px-1 text-muted text-xs">…</span>
              ) : (
                <button
                  key={p}
                  type="button"
                  onClick={() => onPageChange(p)}
                  className={cn(
                    "flex h-7 min-w-[28px] items-center justify-center rounded px-1.5 text-xs font-mono transition-colors cursor-pointer",
                    safePage === p
                      ? "bg-accent text-bg font-semibold shadow-xs"
                      : "border border-border/60 bg-bg-elevated text-muted hover:text-fg hover:bg-bg-subtle",
                  )}
                >
                  {p}
                </button>
              )
            )}
          </div>

          <button
            type="button"
            disabled={safePage >= totalPages}
            onClick={() => onPageChange(safePage + 1)}
            className="flex h-7 w-7 items-center justify-center rounded border border-border/60 bg-bg-elevated text-subtle hover:text-fg hover:bg-bg-subtle disabled:opacity-40 disabled:pointer-events-none cursor-pointer"
            title="Next page"
          >
            <ChevronRight className="size-3.5" />
          </button>
          <button
            type="button"
            disabled={safePage >= totalPages}
            onClick={() => onPageChange(totalPages)}
            className="flex h-7 w-7 items-center justify-center rounded border border-border/60 bg-bg-elevated text-subtle hover:text-fg hover:bg-bg-subtle disabled:opacity-40 disabled:pointer-events-none cursor-pointer"
            title="Last page"
          >
            <ChevronsRight className="size-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}

function LibraryPage() {
  const qc = useQueryClient();
  const searchParams = Route.useSearch();
  const navigate = Route.useNavigate();

  const [q, setQ] = useState(searchParams.q || "");
  const [selectedKind, setSelectedKind] = useState("ALL");
  const [selectedTag, setSelectedTag] = useState(searchParams.tag || "ALL");
  const [selectedActor, setSelectedActor] = useState("ALL");
  const [selectedMalware, setSelectedMalware] = useState("ALL");
  const [selectedTactic, setSelectedTactic] = useState("ALL");
  const [selectedPublisher, setSelectedPublisher] = useState("ALL");
  const [minQuality, setMinQuality] = useState<number>(0);
  const [onlyWithIocs, setOnlyWithIocs] = useState(false);
  const [sortBy, setSortBy] = useState<"newest" | "quality" | "iocs" | "words" | "rejected">(
    searchParams.sort || "newest",
  );
  const [showFilters, setShowFilters] = useState(Boolean(searchParams.tag || searchParams.sort));
  const [previewReportId, setPreviewReportId] = useState<string | null>(searchParams.pdf || null);
  const [auditModalReport, setAuditModalReport] = useState<ReportListItem | null>(null);

  // High-performance client-side pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState<number | "all">(20);

  const targetHighlightId = searchParams.selected || searchParams.highlight;

  // Sync URL if pdf parameter arrives or changes
  useEffect(() => {
    if (searchParams.pdf && searchParams.pdf !== previewReportId) {
      setPreviewReportId(searchParams.pdf);
    }
  }, [searchParams.pdf]);

  const openPdfModal = (id: string) => {
    setPreviewReportId(id);
    void navigate({
      search: (prev) => ({ ...prev, pdf: id }),
      replace: true,
    });
  };

  const closePdfModal = () => {
    setPreviewReportId(null);
    void navigate({
      search: (prev) => {
        const next = { ...prev };
        delete next.pdf;
        return next;
      },
      replace: true,
    });
  };

  const queryClient = useQueryClient();
  const [isAuditing, setIsAuditing] = useState(false);

  // Debounce search query to trigger server-side full content search
  const [debouncedQ, setDebouncedQ] = useState(q);
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQ(q.trim());
    }, 280);
    return () => clearTimeout(timer);
  }, [q]);

  const isDeepSearchActive = debouncedQ.length >= 2;

  // Server-side deep content search: searches full 5,000-word extractedText in MongoDB!
  const { data: searchResults, isLoading: isSearchLoading } = useQuery({
    queryKey: ["reports-search", debouncedQ],
    queryFn: () => listReports({ data: { q: debouncedQ } }),
    enabled: isDeepSearchActive,
    staleTime: 30_000,
  });

  // Fetch all reports to enable rich interactive filtering and instant counts
  const { data: rawReports, isLoading: isBaseLoading } = useQuery({
    queryKey: ["reports-all"],
    queryFn: () => listReports({ data: {} }),
    staleTime: 60_000,
    placeholderData: (previousData) => previousData,
  });

  const isLoading = isDeepSearchActive ? isSearchLoading : isBaseLoading;

  const allReports = useMemo(() => rawReports || [], [rawReports]);
  const activeReportsPool = useMemo(() => {
    if (isDeepSearchActive && searchResults) {
      return searchResults;
    }
    return allReports;
  }, [isDeepSearchActive, searchResults, allReports]);

  const [isEvaluatingSingle, setIsEvaluatingSingle] = useState(false);

  const handleRunAiAudit = async () => {
    setIsAuditing(true);
    toast.info("AI Quality Gate active. Auditing reports with Antigravity Agent...");
    try {
      const res = await auditLibraryWithAi({ data: { limit: 10 } });
      toast.success(res.message || `AI Audit Complete: ${res.verifiedCount} verified, ${res.prunedCount} flagged/pruned (${res.aiEvaluatedCount ?? 0} deep AI evaluations).`);
      void queryClient.invalidateQueries({ queryKey: ["reports-all"] });
      void queryClient.invalidateQueries({ queryKey: ["reports-search"] });
    } catch (err: any) {
      toast.error(`AI Audit failed: ${err?.message || "Unknown error"}`);
    } finally {
      setIsAuditing(false);
    }
  };

  const handleEvaluateSingle = async (reportId: string) => {
    setIsEvaluatingSingle(true);
    toast.info("Running authentic 5-dimensional rubric evaluation via containerized AGY agent...");
    try {
      const res = await evaluateReportWithAi({ data: { id: reportId } });
      if (res.success && res.result) {
        if (res.isApproved) {
          toast.success(`Report Approved by AI Agent (${res.result.passScore}/100)!`);
        } else {
          toast.warning(`Report Rejected by AI Agent (${res.result.passScore}/100): ${res.result.rationale}`);
        }
        setAuditModalReport((prev) => {
          if (!prev || prev.id !== reportId) return prev;
          return {
            ...prev,
            aiVerified: res.isApproved,
            aiQualityScore: res.result.passScore,
            aiAuditReason: res.isApproved
              ? `AI Cognitive Approval (${res.result.passScore}/100): ${res.result.rationale}`
              : `Rejected by AI Cognitive Gate (${res.result.passScore}/100): ${res.result.rationale}`,
            scoreBreakdown: res.result.scoreBreakdown,
            status: res.isApproved ? "acquired" : "rejected",
            classification: res.result.classification || prev.classification,
            resourceKind: res.result.resourceKind || prev.resourceKind,
          };
        });
        void queryClient.invalidateQueries({ queryKey: ["reports-all"] });
        void queryClient.invalidateQueries({ queryKey: ["reports-search"] });
      } else {
        toast.error(`Evaluation failed: ${res.error || "Unknown error"}`);
      }
    } catch (err: any) {
      toast.error(`Agent evaluation failed: ${err?.message || "Unknown error"}`);
    } finally {
      setIsEvaluatingSingle(false);
    }
  };

  // Compute category counts
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {
      ALL: allReports.length,
      FULL_ATTACK_CHAIN: 0,
      CAMPAIGN_INTEL: 0,
      PROCEDURE_DEEPDIVE: 0,
      MALWARE_ANALYSIS: 0,
      DETECTION_GUIDANCE: 0,
      VULNERABILITY_ADVISORY: 0,
      THREAT_ACTOR_DOSSIER: 0,
    };

    for (const r of allReports) {
      const k = r.resourceKind || "CAMPAIGN_INTEL";
      if (counts[k] !== undefined) {
        counts[k]++;
      }
    }
    return counts;
  }, [allReports]);

  // Extract distinct tag options from current library dataset
  const filterOptions = useMemo(() => {
    const actorsSet = new Set<string>();
    const malwareSet = new Set<string>();
    const tacticsSet = new Set<string>();
    const publishersSet = new Set<string>();
    const tagsSet = new Set<string>();

    for (const r of allReports) {
      if (r.publisher) publishersSet.add(r.publisher);
      if (r.sourceName) publishersSet.add(r.sourceName);

      if (Array.isArray(r.tags)) {
        for (const t of r.tags) if (t) tagsSet.add(t);
      }

      if (r.analysis?.threatActors) {
        for (const a of r.analysis.threatActors) if (a && a !== "None Identified") actorsSet.add(a);
      }
      if (r.extractedEntities?.threatActors) {
        for (const a of r.extractedEntities.threatActors) if (a) actorsSet.add(a);
      }

      if (r.analysis?.malware) {
        for (const m of r.analysis.malware) if (m && m !== "None Identified") malwareSet.add(m);
      }
      if (r.extractedEntities?.malwareFamilies) {
        for (const m of r.extractedEntities.malwareFamilies) if (m) malwareSet.add(m);
      }

      if (r.analysis?.attackChain) {
        for (const step of r.analysis.attackChain) if (step.tactic) tacticsSet.add(step.tactic);
      }
      if (r.extractedEntities?.tactics) {
        for (const t of r.extractedEntities.tactics) if (t) tacticsSet.add(t);
      }
    }

    return {
      actors: Array.from(actorsSet).sort(),
      malware: Array.from(malwareSet).sort(),
      tactics: Array.from(tacticsSet).sort(),
      publishers: Array.from(publishersSet).sort(),
      tags: Array.from(tagsSet).sort(),
    };
  }, [allReports]);

  const rejectedCount = useMemo(
    () => allReports.filter((r) => r.status === "rejected").length,
    [allReports],
  );

  // Robust target report resolution: matches by ID, formatted ID, URL, canonical URL, or title
  const targetReport = useMemo(() => {
    if (!targetHighlightId || allReports.length === 0) return null;
    const rawTarget = targetHighlightId.trim();
    const lower = rawTarget.toLowerCase();
    const cleanTarget = lower.replace(/^(rpt_|rst[-_]|report[-_])/i, "");

    // 1. Exact ID match (raw mongo id, custom id, or formatted id)
    const byId = allReports.find((r) => {
      const rIdLower = r.id.toLowerCase();
      const cleanR = rIdLower.replace(/^(rpt_|rst[-_]|report[-_])/i, "");
      return (
        r.id === rawTarget ||
        rIdLower === lower ||
        formatReportId(r.id).toLowerCase() === lower ||
        cleanR === cleanTarget ||
        (cleanTarget.length >= 8 && cleanR.includes(cleanTarget)) ||
        (cleanR.length >= 8 && cleanTarget.includes(cleanR))
      );
    });
    if (byId) return byId;

    // 2. Exact URL or canonicalUrl match
    const byUrl = allReports.find(
      (r) =>
        (r.canonicalUrl && (r.canonicalUrl === rawTarget || r.canonicalUrl.toLowerCase() === lower)) ||
        (r.url && (r.url === rawTarget || r.url.toLowerCase() === lower)),
    );
    if (byUrl) return byUrl;

    // 3. Normalized URL match (ignoring protocol, www., and trailing slashes)
    const normalizeUrl = (u: string) =>
      u.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/$/, "");
    const normTarget = normalizeUrl(rawTarget);
    if (normTarget.length > 5) {
      const byNormUrl = allReports.find((r) => {
        const cNorm = r.canonicalUrl ? normalizeUrl(r.canonicalUrl) : "";
        const uNorm = r.url ? normalizeUrl(r.url) : "";
        return (
          cNorm === normTarget ||
          uNorm === normTarget ||
          (cNorm.length > 8 && cNorm.includes(normTarget)) ||
          (normTarget.length > 8 && normTarget.includes(cNorm))
        );
      });
      if (byNormUrl) return byNormUrl;
    }

    // 4. Exact Title match
    const byExactTitle = allReports.find(
      (r) => r.title && r.title.trim().toLowerCase() === lower,
    );
    if (byExactTitle) return byExactTitle;

    // 5. Partial Title substring match (at least 3 characters)
    if (lower.length >= 3) {
      const byTitle = allReports.find(
        (r) =>
          r.title &&
          (r.title.toLowerCase().includes(lower) || lower.includes(r.title.toLowerCase())),
      );
      if (byTitle) return byTitle;
    }

    return null;
  }, [targetHighlightId, allReports]);

  // Jump and highlight tracking effect with retry polling until rendered in DOM
  useEffect(() => {
    if (!targetHighlightId) return;

    let cancelled = false;
    let attempts = 0;
    const maxAttempts = 40;

    const tryScroll = () => {
      if (cancelled) return;
      attempts++;

      const matchedId = targetReport?.id || targetHighlightId;
      const cleanTarget = targetHighlightId.toLowerCase().replace(/^(rpt_|rst[-_]|report[-_])/i, "");

      const el =
        (targetReport ? document.getElementById(`report-${targetReport.id}`) : null) ||
        document.getElementById(`report-${matchedId}`) ||
        document.getElementById(`report-${targetHighlightId}`) ||
        document.querySelector(`[data-report-id="${matchedId}"]`) ||
        document.querySelector(`[data-report-id="${targetHighlightId}"]`) ||
        document.querySelector(`[data-clean-id="${cleanTarget}"]`);

      if (el) {
        const scrollToElement = () => {
          const mainContainer = el.closest("main");
          if (mainContainer) {
            const containerRect = mainContainer.getBoundingClientRect();
            const elRect = el.getBoundingClientRect();
            const relativeTop = elRect.top - containerRect.top + mainContainer.scrollTop;
            const targetScrollTop = relativeTop - mainContainer.clientHeight / 2 + elRect.height / 2;
            mainContainer.scrollTo({
              top: Math.max(0, targetScrollTop),
              behavior: "smooth",
            });
          }
          try {
            el.scrollIntoView({ behavior: "smooth", block: "center" });
          } catch {
            // ignore
          }
        };

        scrollToElement();
        setTimeout(scrollToElement, 300);
      } else if (attempts < maxAttempts) {
        setTimeout(tryScroll, 80);
      }
    };

    const timer = setTimeout(tryScroll, 100);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [targetHighlightId, targetReport]);

  // Filter and sort reports
  const filteredReports = useMemo(() => {
    const query = q.trim().toLowerCase();

    const list = activeReportsPool
      .filter((r) => {
        // Targeted Jump: Always show the target item being tracked from /ingest or matrix
        if (targetReport && r.id === targetReport.id) {
          return true;
        }

        // If viewing rejected, show ONLY records flagged/rejected by AI quality audit
        if (sortBy === "rejected") {
          if (r.status !== "rejected") return false;
        } else {
          // Standard view: hide rejected non-threat pages
          if (r.status === "rejected") return false;
        }

        if (selectedKind !== "ALL") {
          const kind = r.resourceKind || "CAMPAIGN_INTEL";
          if (kind !== selectedKind) return false;
        }

        if (selectedActor !== "ALL") {
          const hasActor =
            r.analysis?.threatActors?.some((a) => a.toLowerCase() === selectedActor.toLowerCase()) ||
            r.extractedEntities?.threatActors?.some((a) => a.toLowerCase() === selectedActor.toLowerCase());
          if (!hasActor) return false;
        }

        if (selectedMalware !== "ALL") {
          const hasMalware =
            r.analysis?.malware?.some((m) => m.toLowerCase() === selectedMalware.toLowerCase()) ||
            r.extractedEntities?.malwareFamilies?.some((m) => m.toLowerCase() === selectedMalware.toLowerCase());
          if (!hasMalware) return false;
        }

        if (selectedTactic !== "ALL") {
          const hasTactic =
            r.analysis?.attackChain?.some((s) => s.tactic.toLowerCase() === selectedTactic.toLowerCase()) ||
            r.extractedEntities?.tactics?.some((t) => t.toLowerCase() === selectedTactic.toLowerCase());
          if (!hasTactic) return false;
        }

        if (selectedPublisher !== "ALL") {
          const pub = (r.publisher || r.sourceName || "").toLowerCase();
          if (pub !== selectedPublisher.toLowerCase()) return false;
        }

        if (selectedTag !== "ALL") {
          const hasTag = r.tags && r.tags.some((t) => t.toLowerCase() === selectedTag.toLowerCase());
          if (!hasTag) return false;
        }

        if (minQuality > 0 && r.qualityScore < minQuality) {
          return false;
        }

        if (onlyWithIocs && (r.iocCount || 0) === 0) {
          return false;
        }

        // For single-character or instant client typing before debounce
        if (query && !isDeepSearchActive) {
          const repId = formatReportId(r.id);
          const domId = formatDomainId(r.sourceDomain || r.url);
          const tagsStr = r.tags?.join(" ") || "";
          const searchable = `${r.title} ${r.sourceName} ${r.publisher} ${r.url} ${r.canonicalUrl} ${r.id} ${repId} ${r.sourceId} ${r.ingestOrigin || ""} ${domId} ${r.excerpt} ${r.classification} ${r.resourceKind || ""} ${tagsStr} ${
            r.analysis?.threatActors?.join(" ") || ""
          } ${r.analysis?.malware?.join(" ") || ""} ${r.extractedEntities?.cves?.join(" ") || ""} ${
            r.iocs?.map((i) => i.value).join(" ") || ""
          }`.toLowerCase();

          if (!searchable.includes(query)) return false;
        }

        return true;
      })
      .sort((a, b) => {
        if (sortBy === "rejected") return new Date(b.ingestedAt).getTime() - new Date(a.ingestedAt).getTime();
        if (sortBy === "quality") return b.qualityScore - a.qualityScore;
        if (sortBy === "iocs") return (b.iocCount || 0) - (a.iocCount || 0);
        if (sortBy === "words") return (b.wordCount || 0) - (a.wordCount || 0);
        return new Date(b.ingestedAt).getTime() - new Date(a.ingestedAt).getTime();
      });

    // Ensure targetReport is in the list even if current active filters would have excluded it
    if (targetReport && !list.some((r) => r.id === targetReport.id)) {
      const merged = [...list, targetReport];
      return merged.sort((a, b) => {
        if (sortBy === "rejected") return new Date(b.ingestedAt).getTime() - new Date(a.ingestedAt).getTime();
        if (sortBy === "quality") return b.qualityScore - a.qualityScore;
        if (sortBy === "iocs") return (b.iocCount || 0) - (a.iocCount || 0);
        if (sortBy === "words") return (b.wordCount || 0) - (a.wordCount || 0);
        return new Date(b.ingestedAt).getTime() - new Date(a.ingestedAt).getTime();
      });
    }

    return list;
  }, [
    activeReportsPool,
    isDeepSearchActive,
    targetReport,
    targetHighlightId,
    q,
    sortBy,
    selectedKind,
    selectedActor,
    selectedMalware,
    selectedTactic,
    selectedPublisher,
    selectedTag,
    minQuality,
    onlyWithIocs,
  ]);

  const activeFiltersCount = useMemo(() => {
    let count = 0;
    if (selectedTag !== "ALL") count++;
    if (selectedActor !== "ALL") count++;
    if (selectedMalware !== "ALL") count++;
    if (selectedTactic !== "ALL") count++;
    if (selectedPublisher !== "ALL") count++;
    if (minQuality > 0) count++;
    if (onlyWithIocs) count++;
    return count;
  }, [selectedTag, selectedActor, selectedMalware, selectedTactic, selectedPublisher, minQuality, onlyWithIocs]);

  // Reset pagination to page 1 on filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [
    q,
    selectedKind,
    selectedTag,
    selectedActor,
    selectedMalware,
    selectedTactic,
    selectedPublisher,
    minQuality,
    onlyWithIocs,
    sortBy,
  ]);

  // Automatically navigate to page containing targetReport or targetHighlightId
  useEffect(() => {
    if (!targetHighlightId || filteredReports.length === 0 || pageSize === "all") return;
    const cleanTarget = targetHighlightId.toLowerCase().replace(/^(rpt_|rst[-_]|report[-_])/i, "");
    const targetIdx = filteredReports.findIndex(
      (r) =>
        r.id === targetHighlightId ||
        r.id.toLowerCase() === targetHighlightId.toLowerCase() ||
        formatReportId(r.id).toLowerCase() === targetHighlightId.toLowerCase() ||
        (cleanTarget.length >= 8 && r.id.toLowerCase().includes(cleanTarget)) ||
        (targetReport && r.id === targetReport.id),
    );
    if (targetIdx !== -1) {
      const targetPage = Math.floor(targetIdx / pageSize) + 1;
      if (currentPage !== targetPage) {
        setCurrentPage(targetPage);
      }
    }
  }, [targetHighlightId, targetReport, filteredReports, pageSize, currentPage]);

  const pagedReports = useMemo(
    () => paginateList(filteredReports, currentPage, pageSize),
    [filteredReports, currentPage, pageSize],
  );

  const handlePageChange = (newPage: number) => {
    setCurrentPage(newPage);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const resetFilters = () => {
    setSelectedTag("ALL");
    setSelectedActor("ALL");
    setSelectedMalware("ALL");
    setSelectedTactic("ALL");
    setSelectedPublisher("ALL");
    setMinQuality(0);
    setOnlyWithIocs(false);
    setQ("");
  };

  const { data: previewData, isLoading: isPreviewLoading, isError: isPreviewError, refetch: refetchPreview } = useQuery({
    queryKey: ["report-pdf", previewReportId],
    queryFn: () => (previewReportId ? getReportPdf({ data: { id: previewReportId } }) : null),
    enabled: Boolean(previewReportId),
    staleTime: 60_000,
  });

  const handleDownloadPdf = (r: ReportListItem, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();

    // Fetch full report if not in previewData
    void (async () => {
      try {
        toast.info("Preparing PDF Document for download...");
        const rep = await getReportPdf({ data: { id: r.id } });
        if (!rep.ok || !rep.rawHtml) {
          toast.error("PDF representation not available for this report");
          return;
        }

        const blob = new Blob([rep.rawHtml], { type: "text/html;charset=utf-8" });
        const dlUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = dlUrl;
        const slug = (rep.title || "threat_report")
          .toLowerCase()
          .replace(/[^a-z0-9_-]/g, "_")
          .slice(0, 50);
        a.download = `${slug}_intel_report.html`;
        a.click();
        URL.revokeObjectURL(dlUrl);
        toast.success("Document Downloaded", {
          description: "High-fidelity PDF document saved. Open and select Print → Save as PDF for vector rendering.",
        });
      } catch (err) {
        toast.error("Failed downloading document");
      }
    })();
  };

  const handlePrintDocument = (html: string) => {
    const printWindow = window.open("", "_blank");
    if (printWindow) {
      printWindow.document.write(html);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 400);
    } else {
      toast.info("Pop-up blocked. Please allow pop-ups to print to PDF directly.");
    }
  };

  const getKindTone = (kind?: ResourceKind): "accent" | "warn" | "sage" | "neutral" => {
    switch (kind) {
      case "FULL_ATTACK_CHAIN":
        return "accent";
      case "MALWARE_ANALYSIS":
        return "warn";
      case "DETECTION_GUIDANCE":
        return "sage";
      case "VULNERABILITY_ADVISORY":
        return "warn";
      case "PROCEDURE_DEEPDIVE":
        return "accent";
      default:
        return "neutral";
    }
  };

  return (
    <AppShell>
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">Central Intelligence Store</p>
          <h1 className="mt-1 text-3xl font-medium tracking-tight">Intelligence Library</h1>
          <p className="mt-1 text-xs text-muted">
            Acquired adversary intelligence, normalized evidence, IOCs, and reconstructed attack chains.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full sm:w-80">
            <Search className="absolute left-3 top-2.5 size-3.5 text-muted" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search CVE, actor, malware, procedure, or hash…"
              className="w-full pl-8 pr-8 text-xs"
            />
            {q && (
              <button
                type="button"
                onClick={() => setQ("")}
                className="absolute right-2.5 top-2.5 text-muted hover:text-fg"
              >
                <X className="size-3.5" />
              </button>
            )}
          </div>
          <Button
            size="sm"
            variant={showFilters || activeFiltersCount > 0 ? "secondary" : "ghost"}
            className={cn("h-9 gap-1.5 text-xs", activeFiltersCount > 0 && "border-accent text-accent")}
            onClick={() => setShowFilters(!showFilters)}
          >
            <SlidersHorizontal className="size-3.5" />
            <span>Filters</span>
            {activeFiltersCount > 0 && (
              <span className="rounded-full bg-accent px-1.5 py-0.2 font-mono text-[10px] text-white">
                {activeFiltersCount}
              </span>
            )}
          </Button>

          <Button
            size="sm"
            variant="secondary"
            disabled={isAuditing}
            onClick={handleRunAiAudit}
            className="h-9 gap-1.5 text-xs bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
            title="Trigger intelligent AGY evaluation & verification across acquired intelligence reports"
          >
            <Sparkles className={cn("size-3.5", isAuditing && "animate-spin text-emerald-400")} />
            <span>{isAuditing ? "Auditing with AI..." : "Audit with AI"}</span>
          </Button>
        </div>
      </div>

      {/* Category Pills with Active Counts */}
      <div className="mt-6 flex flex-wrap gap-1.5 border-b border-border pb-3">
        {RESOURCE_KINDS.map((c) => {
          const count = categoryCounts[c.id] ?? 0;
          return (
            <button
              key={c.id}
              type="button"
              onClick={() => setSelectedKind(c.id)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors",
                selectedKind === c.id
                  ? "bg-fg text-bg font-semibold shadow-sm"
                  : "bg-bg-elevated text-muted hover:text-fg border border-border",
              )}
            >
              <span>{c.label}</span>
              <span
                className={cn(
                  "rounded-full px-1.5 py-0.2 font-mono text-[10px]",
                  selectedKind === c.id ? "bg-bg text-fg font-bold" : "bg-bg-subtle text-subtle",
                )}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Advanced Tag Filter Drawer / Controls */}
      {showFilters && (
        <div className="mt-4 rounded-xl border border-border bg-bg-elevated p-4 animate-in fade-in slide-in-from-top-2 duration-150">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <Filter className="size-4 text-accent" />
              <span className="text-xs font-semibold uppercase tracking-wider text-fg">
                Advanced Intelligence Filters
              </span>
            </div>
            {activeFiltersCount > 0 && (
              <button
                type="button"
                onClick={resetFilters}
                className="text-xs text-accent hover:underline font-mono"
              >
                Reset All Filters
              </button>
            )}
          </div>

          <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {/* Filter 0: Intelligence Tag */}
            <div className="space-y-1">
              <label className="text-[11px] font-medium text-muted">Intelligence Tag</label>
              <select
                value={selectedTag}
                onChange={(e) => setSelectedTag(e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Tags ({filterOptions.tags.length})</option>
                {filterOptions.tags.map((tag) => (
                  <option key={tag} value={tag}>
                    {tag}
                  </option>
                ))}
              </select>
            </div>

            {/* Filter 1: Threat Actor */}
            <div className="space-y-1">
              <label className="text-[11px] font-medium text-muted">Threat Actor / Adversary</label>
              <select
                value={selectedActor}
                onChange={(e) => setSelectedActor(e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Adversary Groups ({filterOptions.actors.length})</option>
                {filterOptions.actors.map((actor) => (
                  <option key={actor} value={actor}>
                    {actor}
                  </option>
                ))}
              </select>
            </div>

            {/* Filter 2: Malware Family */}
            <div className="space-y-1">
              <label className="text-[11px] font-medium text-muted">Malware Family & Toolset</label>
              <select
                value={selectedMalware}
                onChange={(e) => setSelectedMalware(e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Malware Families ({filterOptions.malware.length})</option>
                {filterOptions.malware.map((mal) => (
                  <option key={mal} value={mal}>
                    {mal}
                  </option>
                ))}
              </select>
            </div>

            {/* Filter 3: ATT&CK Tactic */}
            <div className="space-y-1">
              <label className="text-[11px] font-medium text-muted">MITRE ATT&CK Tactic</label>
              <select
                value={selectedTactic}
                onChange={(e) => setSelectedTactic(e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Tactics ({filterOptions.tactics.length})</option>
                {filterOptions.tactics.map((tactic) => (
                  <option key={tactic} value={tactic}>
                    {tactic}
                  </option>
                ))}
              </select>
            </div>

            {/* Filter 4: Publisher */}
            <div className="space-y-1">
              <label className="text-[11px] font-medium text-muted">Publisher / Threat Origin</label>
              <select
                value={selectedPublisher}
                onChange={(e) => setSelectedPublisher(e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Publishers ({filterOptions.publishers.length})</option>
                {filterOptions.publishers.map((pub) => (
                  <option key={pub} value={pub}>
                    {pub}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="mt-3 pt-3 border-t border-border flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-4 text-xs">
              {/* Quality Score threshold */}
              <div className="flex items-center gap-2">
                <span className="text-muted text-[11px]">Quality Threshold:</span>
                <select
                  value={minQuality}
                  onChange={(e) => setMinQuality(parseFloat(e.target.value))}
                  className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-fg"
                >
                  <option value={0}>Any Score</option>
                  <option value={0.6}>≥ 60% Verified</option>
                  <option value={0.8}>≥ 80% Pristine</option>
                </select>
              </div>

              {/* Only with IOCs */}
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={onlyWithIocs}
                  onChange={(e) => setOnlyWithIocs(e.target.checked)}
                  className="size-3.5 accent-accent"
                />
                <span className="text-muted text-[11px]">Only reports with verified IOCs</span>
              </label>
            </div>

            {/* Sort Dropdown */}
            <div className="flex items-center gap-2 text-xs">
              <span className="text-muted text-[11px]">Sort:</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-fg"
              >
                <option value="newest">Newest Ingested</option>
                <option value="quality">Quality Score (High to Low)</option>
                <option value="iocs">Most IOCs</option>
                <option value="words">Longest Analysis</option>
                <option value="rejected">AI Rejected / Pruned ({rejectedCount})</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Active Filter Badges Bar */}
      {activeFiltersCount > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-mono text-muted mr-1">Active filters:</span>
          {selectedTag !== "ALL" && (
            <span className="inline-flex items-center gap-1 rounded-md bg-accent/10 text-accent border border-accent/20 px-2 py-0.5 text-xs font-mono">
              Tag: {selectedTag}
              <button type="button" onClick={() => setSelectedTag("ALL")} className="hover:opacity-75">
                <X className="size-3" />
              </button>
            </span>
          )}
          {selectedActor !== "ALL" && (
            <span className="inline-flex items-center gap-1 rounded-md bg-danger/10 text-danger border border-danger/20 px-2 py-0.5 text-xs font-mono">
              Actor: {selectedActor}
              <button type="button" onClick={() => setSelectedActor("ALL")} className="hover:opacity-75">
                <X className="size-3" />
              </button>
            </span>
          )}
          {selectedMalware !== "ALL" && (
            <span className="inline-flex items-center gap-1 rounded-md bg-warn/10 text-warn border border-warn/20 px-2 py-0.5 text-xs font-mono">
              Malware: {selectedMalware}
              <button type="button" onClick={() => setSelectedMalware("ALL")} className="hover:opacity-75">
                <X className="size-3" />
              </button>
            </span>
          )}
          {selectedTactic !== "ALL" && (
            <span className="inline-flex items-center gap-1 rounded-md bg-accent/10 text-accent border border-accent/20 px-2 py-0.5 text-xs font-mono">
              Tactic: {selectedTactic}
              <button type="button" onClick={() => setSelectedTactic("ALL")} className="hover:opacity-75">
                <X className="size-3" />
              </button>
            </span>
          )}
          {selectedPublisher !== "ALL" && (
            <span className="inline-flex items-center gap-1 rounded-md bg-bg-subtle text-fg border border-border px-2 py-0.5 text-xs font-mono">
              Publisher: {selectedPublisher}
              <button type="button" onClick={() => setSelectedPublisher("ALL")} className="hover:opacity-75">
                <X className="size-3" />
              </button>
            </span>
          )}
          {minQuality > 0 && (
            <span className="inline-flex items-center gap-1 rounded-md bg-sage/10 text-sage border border-sage/20 px-2 py-0.5 text-xs font-mono">
              Score ≥ {Math.round(minQuality * 100)}%
              <button type="button" onClick={() => setMinQuality(0)} className="hover:opacity-75">
                <X className="size-3" />
              </button>
            </span>
          )}
          {onlyWithIocs && (
            <span className="inline-flex items-center gap-1 rounded-md bg-sage/10 text-sage border border-sage/20 px-2 py-0.5 text-xs font-mono">
              Has IOCs
              <button type="button" onClick={() => setOnlyWithIocs(false)} className="hover:opacity-75">
                <X className="size-3" />
              </button>
            </span>
          )}
          <button
            type="button"
            onClick={resetFilters}
            className="text-[11px] text-subtle hover:text-fg underline ml-2"
          >
            Clear all
          </button>
        </div>
      )}

      {/* Result Counter */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
        <div className="flex items-center gap-2">
          <span>
            Showing{" "}
            <strong className="text-fg">
              {filteredReports.length === 0
                ? 0
                : `${(currentPage - 1) * (pageSize === "all" ? filteredReports.length : pageSize) + 1}–${pageSize === "all" ? filteredReports.length : Math.min(filteredReports.length, currentPage * pageSize)}`}
            </strong>{" "}
            of <strong className="text-fg">{filteredReports.length}</strong> filtered records
            {filteredReports.length !== allReports.length && (
              <span className="text-subtle"> ({allReports.length} total in store)</span>
            )}
          </span>
          {pageSize !== "all" && filteredReports.length > pageSize && (
            <span className="rounded bg-bg-elevated border border-border px-1.5 py-0.5 font-mono text-[10px] text-accent">
              Page {currentPage} of {Math.max(1, Math.ceil(filteredReports.length / pageSize))}
            </span>
          )}
        </div>
        {selectedKind !== "ALL" && (
          <span className="font-mono text-[11px] text-subtle">
            Category: {RESOURCE_KINDS.find((k) => k.id === selectedKind)?.label}
          </span>
        )}
      </div>

      {/* Reports Grid */}
      <div className="mt-4 grid gap-3">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted">
            <RefreshCw className="size-6 animate-spin text-accent mb-2" />
            <p className="text-sm">Querying Central Intelligence Store…</p>
          </div>
        ) : null}

        {!isLoading && filteredReports.length === 0 ? (
          <div className="rounded-xl border border-border bg-bg-elevated py-16 text-center text-sm text-muted">
            <ShieldAlert className="size-8 mx-auto text-muted mb-2 opacity-50" />
            <p className="font-medium text-fg">No threat intelligence reports match your filter.</p>
            <p className="mt-1 text-xs text-muted">Try relaxing search terms or click "Reset All Filters".</p>
            {activeFiltersCount > 0 && (
              <Button size="sm" variant="secondary" onClick={resetFilters} className="mt-4 text-xs">
                Reset All Filters
              </Button>
            )}
          </div>
        ) : null}

        {pagedReports.map((r) => {
          const actors = r.analysis?.threatActors || r.extractedEntities?.threatActors || [];
          const malware = r.analysis?.malware || r.extractedEntities?.malwareFamilies || [];
          const cves = r.extractedEntities?.cves || [];
          const cleanId = r.id.toLowerCase().replace(/^(rpt_|rst[-_]|report[-_])/i, "");
          const isHighlighted = Boolean(
            (targetReport && targetReport.id === r.id) ||
            (targetHighlightId && (
              r.id === targetHighlightId ||
              r.id.toLowerCase() === targetHighlightId.toLowerCase() ||
              formatReportId(r.id).toLowerCase() === targetHighlightId.toLowerCase() ||
              (targetHighlightId.length >= 8 && cleanId.includes(targetHighlightId.toLowerCase().replace(/^(rpt_|rst[-_]|report[-_])/i, "")))
            ))
          );

          return (
            <div
              key={r.id}
              id={`report-${r.id}`}
              data-report-id={r.id}
              data-clean-id={cleanId}
              className={cn(
                "group relative rounded-xl border bg-bg-elevated p-5",
                isHighlighted
                  ? "target-card-blink border-accent bg-accent/[0.03]"
                  : "border-border hover:border-border/80 hover:bg-bg-subtle/40 transition-all duration-300",
                r.status === "rejected" && "border-danger/40 bg-danger/[0.03]",
              )}
            >
              {/* AI Pruned / Rejected Banner */}
              {r.status === "rejected" && (
                <div className="mb-3 flex items-start gap-2.5 rounded-lg border border-danger/40 bg-danger/10 p-2.5 text-xs text-danger">
                  <AlertTriangle className="size-4 shrink-0 mt-0.5 text-danger" />
                  <div>
                    <div className="font-semibold uppercase tracking-wider font-mono text-[10px]">
                      Pruned / Rejected by AI Quality Gate
                    </div>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-danger/90">
                      {r.aiAuditReason || "Identified as sub-threshold stub, generic index query, or non-threat marketing."}
                    </p>
                  </div>
                </div>
              )}

              {/* Standardized AIE ID Bar: RST and DOM with AI Verification Badge on Very Top Right */}
              <div className="flex flex-wrap items-center justify-between gap-1.5 mb-2.5 pb-2 border-b border-border/50">
                <div className="flex flex-wrap items-center gap-1.5">
                  <IdBadge id={formatReportId(r.id)} category="report" size="xs" />
                  {(r.sourceDomain || r.url) && (
                    <IdBadge id={formatDomainId(r.sourceDomain || r.url)} category="domain" size="xs" />
                  )}
                </div>

                {/* AI Verification status badge on very top right */}
                {r.aiVerified ? (
                  <button
                    type="button"
                    onClick={() => setAuditModalReport(r)}
                    className="inline-flex items-center gap-1 rounded-full bg-sage/15 hover:bg-sage/25 text-sage border border-sage/30 px-2 py-0.5 text-[10px] font-mono font-medium transition-colors cursor-pointer"
                    title="Click to view AI Quality Gate Audit Details"
                  >
                    <CheckCircle2 className="size-2.5 text-sage" />
                    AI Verified {r.aiQualityScore ? `· ${r.aiQualityScore}%` : ""}
                  </button>
                ) : r.status === "rejected" ? (
                  <button
                    type="button"
                    onClick={() => setAuditModalReport(r)}
                    className="inline-flex items-center gap-1 rounded-full bg-red-500/15 hover:bg-red-500/25 text-red-400 border border-red-500/30 px-2 py-0.5 text-[10px] font-mono font-medium transition-colors cursor-pointer"
                    title="Click to view AI Rejection Details"
                  >
                    <XCircle className="size-2.5 text-red-400" />
                    Rejected by AI
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => setAuditModalReport(r)}
                    className="inline-flex items-center gap-1 rounded-full bg-muted/10 hover:bg-muted/20 text-muted border border-border px-2 py-0.5 text-[10px] font-mono transition-colors cursor-pointer"
                    title="Click to view Crawler & AI Audit Details"
                  >
                    Pending AI Audit
                  </button>
                )}
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="neutral">{r.sourceName || r.publisher}</Badge>
                  {r.resourceKind && (
                    <Badge tone={getKindTone(r.resourceKind)} className="font-semibold">
                      {r.resourceKind.replace(/_/g, " ")}
                    </Badge>
                  )}
                  <Badge tone="neutral">{r.classification}</Badge>
                  <Badge tone={r.status === "acquired" ? "sage" : "warn"}>{r.status}</Badge>
                  {r.simulationScore !== undefined && r.simulationScore > 0 && (
                    <Badge tone="accent" className="font-mono font-semibold">
                      SIM {Math.round(r.simulationScore * 100)}%
                    </Badge>
                  )}
                  {r.isEmergingTechnique && (
                    <Badge tone="danger" className="font-semibold" title={r.noveltyRationale || "Novel unmapped adversary procedure"}>
                      NOVEL TTP
                    </Badge>
                  )}
                  <Badge tone="sage" className="gap-1">
                    <FileText className="size-2.5" /> High-Fidelity PDF
                  </Badge>
                </div>

                <span className="font-mono text-[11px] text-subtle tabular-nums">
                  {Math.round(r.qualityScore * 100)}% quality · {r.wordCount} words · {r.iocCount} IOCs
                </span>
              </div>

              <div className="mt-3 flex items-start justify-between gap-4">
                <button
                  type="button"
                  onClick={() => openPdfModal(r.id)}
                  className="flex-1 text-left cursor-pointer group/title"
                  title="Open high-fidelity document representation"
                >
                  <h2 className="text-base font-medium leading-snug group-hover/title:text-accent transition-colors">
                    {r.title}
                  </h2>
                  <p className="mt-1.5 line-clamp-2 text-xs text-muted leading-relaxed">{r.excerpt}</p>
                  {r.matchedSnippet && (
                    <div className="mt-2.5 p-2 rounded-lg bg-black/40 border border-accent/40 text-[11px] font-mono">
                      <div className="flex items-center gap-1.5 text-[9.5px] uppercase font-semibold text-accent mb-1">
                        <Sparkles className="size-3 text-accent" />
                        <span>Deep Content Match:</span>
                      </div>
                      <div className="text-fg/90 select-text whitespace-pre-wrap leading-relaxed">
                        "{r.matchedSnippet}"
                      </div>
                    </div>
                  )}
                </button>

                <div className="flex shrink-0 items-center gap-2 pt-1">
                  <Link
                    to="/library/$reportId"
                    params={{ reportId: r.id }}
                    className="h-8 gap-1.5 text-xs inline-flex items-center justify-center rounded-lg border border-border bg-bg-elevated hover:bg-bg px-2.5 font-medium text-fg hover:text-accent transition-colors shadow-xs"
                    title="Open Full Threat Intel Dossier (Attack Chains, Emulation, Detections)"
                  >
                    <Workflow className="size-3.5 text-accent" />
                    <span className="hidden sm:inline">Dossier</span>
                  </Link>

                  <Button
                    size="sm"
                    variant="secondary"
                    className="h-8 gap-1.5 text-xs"
                    onClick={() => openPdfModal(r.id)}
                    title="View PDF Document Representation"
                  >
                    <Eye className="size-3.5" />
                    <span className="hidden sm:inline">View PDF</span>
                  </Button>

                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-8 gap-1.5 text-xs text-muted hover:text-fg"
                    onClick={(e) => handleDownloadPdf(r, e)}
                    title="Download Document"
                  >
                    <Download className="size-3.5" />
                    <span className="hidden sm:inline">Download</span>
                  </Button>

                  <a
                    href={r.canonicalUrl || r.url}
                    target="_blank"
                    rel="noreferrer"
                    className="p-1 text-subtle hover:text-accent transition-colors"
                    title={`Open source article: ${r.canonicalUrl || r.url}`}
                    onClick={(e) => e.stopPropagation()}
                  >
                    <ArrowUpRight className="size-4" />
                  </a>
                </div>
              </div>

              {/* Tag Highlights on Report Card */}
              {(actors.length > 0 || malware.length > 0 || cves.length > 0) && (
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  {actors.slice(0, 3).map((a) => (
                    <button
                      key={a}
                      type="button"
                      onClick={() => {
                        setSelectedActor(a);
                        setShowFilters(true);
                      }}
                      className="inline-flex items-center gap-1 rounded bg-danger/10 hover:bg-danger/20 text-danger border border-danger/20 px-1.5 py-0.2 font-mono text-[10px]"
                    >
                      <ShieldAlert className="size-2.5" />
                      {a}
                    </button>
                  ))}
                  {malware.slice(0, 3).map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => {
                        setSelectedMalware(m);
                        setShowFilters(true);
                      }}
                      className="inline-flex items-center gap-1 rounded bg-warn/10 hover:bg-warn/20 text-warn border border-warn/20 px-1.5 py-0.2 font-mono text-[10px]"
                    >
                      <Flame className="size-2.5" />
                      {m}
                    </button>
                  ))}
                  {cves.slice(0, 3).map((cve) => (
                    <span
                      key={cve}
                      className="rounded bg-bg-subtle text-muted border border-border px-1.5 py-0.2 font-mono text-[10px]"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              )}

              {/* High-Value Intelligence Tags (e.g. FULL ATTACK CHAIN, INTRUSION_REPORT, Publisher, Techniques) */}
              {r.tags && r.tags.length > 0 && (
                <div className="mt-2.5 flex flex-wrap items-center gap-1">
                  <span className="text-[10px] font-mono text-muted mr-1 flex items-center gap-1">
                    <Tag className="size-2.5" /> Tags:
                  </span>
                  {r.tags.slice(0, 8).map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => {
                        setSelectedTag(t);
                        setShowFilters(true);
                      }}
                      className="inline-flex items-center rounded bg-bg-subtle hover:bg-bg border border-border px-1.5 py-0.5 text-[10px] font-mono text-fg hover:text-accent hover:border-accent/40 transition-colors"
                      title={`Filter by tag: ${t}`}
                    >
                      {t}
                    </button>
                  ))}
                  {r.tags.length > 8 && (
                    <span className="text-[10px] font-mono text-muted">+{r.tags.length - 8} more</span>
                  )}
                </div>
              )}

              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2.5 font-mono text-[10px] text-subtle">
                <span>Domain: {r.sourceDomain || "Verified source"}</span>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => openPdfModal(r.id)}
                    className="text-accent hover:underline flex items-center gap-1"
                  >
                    <FileText className="size-3" /> Preview Document & Evidence
                  </button>
                  <Link
                    to="/library/$reportId"
                    params={{ reportId: r.id }}
                    className="text-accent hover:underline flex items-center gap-1 font-semibold"
                  >
                    <Workflow className="size-3" /> Full Intel Dossier
                  </Link>
                  <span>Ingested: {formatDateTime(r.ingestedAt)}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* High-Performance Pagination Toolbar */}
      {filteredReports.length > 0 && (
        <div className="mt-4 mb-2">
          <PaginationControls
            currentPage={currentPage}
            pageSize={pageSize}
            totalItems={filteredReports.length}
            onPageChange={handlePageChange}
            onPageSizeChange={(sz) => {
              setPageSize(sz);
              setCurrentPage(1);
            }}
            itemLabel="intelligence records"
          />
        </div>
      )}

      {/* PDF / DOCUMENT VIEW MODAL */}
      {previewReportId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="flex h-[90vh] w-full max-w-5xl flex-col rounded-2xl border border-border bg-bg-elevated shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-border bg-bg px-6 py-4">
              <div className="flex items-center gap-3 overflow-hidden">
                <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-elevated">
                  <FileText className="size-4 text-accent" />
                </div>
                <div className="overflow-hidden">
                  <div className="flex items-center gap-2 mb-1">
                    {previewReportId && (
                      <IdBadge id={formatReportId(previewReportId)} category="report" size="xs" />
                    )}
                    {previewData?.url && (
                      <IdBadge id={formatDomainId(previewData.url)} category="domain" size="xs" />
                    )}
                  </div>
                  <h3 className="truncate text-sm font-medium">
                    {previewData?.title || "High-Fidelity PDF Representation"}
                  </h3>
                  <p className="truncate text-xs text-muted font-mono">
                    {previewData?.canonicalUrl || previewData?.url}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {previewData?.rawHtml && (
                  <>
                    <Button
                      size="sm"
                      variant="secondary"
                      className="h-8 gap-1.5 text-xs"
                      onClick={() => handlePrintDocument(previewData.rawHtml)}
                    >
                      <Printer className="size-3.5" />
                      <span>Print to PDF</span>
                    </Button>

                    <Button
                      size="sm"
                      variant="secondary"
                      className="h-8 gap-1.5 text-xs"
                      onClick={() => {
                        const blob = new Blob([previewData.rawHtml], { type: "text/html;charset=utf-8" });
                        const dlUrl = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = dlUrl;
                        a.download = `${previewData.title.slice(0, 40).replace(/[^a-z0-9_-]/gi, "_")}_report.html`;
                        a.click();
                        URL.revokeObjectURL(dlUrl);
                        toast.success("Document downloaded");
                      }}
                    >
                      <Download className="size-3.5" />
                      <span>Download File</span>
                    </Button>
                  </>
                )}

                <button
                  type="button"
                  onClick={() => {
                    const id = previewReportId;
                    closePdfModal();
                    if (id) {
                      void navigate({
                        search: (prev) => ({ ...prev, selected: id }),
                        replace: true,
                      });
                    }
                  }}
                  className="rounded-lg border border-border bg-bg-elevated px-3 py-1.5 text-xs text-muted hover:text-fg transition-colors"
                >
                  View in Gallery
                </button>

                <button
                  type="button"
                  onClick={() => closePdfModal()}
                  className="flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg transition-colors"
                >
                  <X className="size-4" />
                </button>
              </div>
            </div>

            {/* Modal Body / Document Preview */}
            <div className="flex-1 overflow-hidden bg-neutral-900">
              {isPreviewLoading ? (
                <div className="flex h-full items-center justify-center text-muted text-sm">
                  Loading high-fidelity PDF document representation...
                </div>
              ) : isPreviewError || (previewData && !previewData.ok) ? (
                <div className="flex h-full flex-col items-center justify-center p-8 text-center text-muted">
                  <AlertTriangle className="size-8 text-warn mb-2.5" />
                  <p className="text-sm font-medium text-fg">Unable to load document representation</p>
                  <p className="mt-1 text-xs text-muted max-w-sm">
                    {previewData && !previewData.ok && previewData.error
                      ? previewData.error
                      : "A network error occurred or the server connection was interrupted."}
                  </p>
                  <Button
                    size="sm"
                    variant="secondary"
                    className="mt-4 text-xs gap-1.5"
                    onClick={() => refetchPreview()}
                  >
                    <RefreshCw className="size-3" />
                    <span>Retry Loading</span>
                  </Button>
                </div>
              ) : previewData?.rawHtml ? (
                <iframe
                  title="Document PDF Preview"
                  srcDoc={previewData.rawHtml}
                  className="size-full border-0 bg-white"
                  sandbox="allow-scripts allow-popups"
                />
              ) : (
                <div className="flex h-full flex-col items-center justify-center p-8 text-center text-muted">
                  <p className="text-sm">Raw document HTML not available for this record.</p>
                  <p className="mt-1 text-xs">You can re-ingest or crawl to regenerate pristine document layouts.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* AI QUALITY GATE AUDIT DETAILS MODAL */}
      {auditModalReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="flex w-full max-w-lg flex-col rounded-2xl border border-border bg-bg-elevated shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-border bg-bg px-5 py-3.5">
              <div className="flex items-center gap-2">
                <Sparkles className="size-4 text-accent" />
                <h3 className="text-sm font-semibold text-fg">AI Threat Intel Audit Verification</h3>
              </div>
              <button
                type="button"
                onClick={() => setAuditModalReport(null)}
                className="text-muted hover:text-fg p-1 rounded-md"
              >
                <X className="size-4" />
              </button>
            </div>

            <div className="p-5 space-y-4 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-muted">Verification Status:</span>
                {auditModalReport.aiVerified ? (
                  <span className="inline-flex items-center gap-1 rounded-full bg-sage/15 text-sage border border-sage/30 px-2.5 py-0.5 font-mono font-medium">
                    <CheckCircle2 className="size-3 text-sage" /> AI Quality Gate Verified
                  </span>
                ) : auditModalReport.status === "rejected" ? (
                  <span className="inline-flex items-center gap-1 rounded-full bg-red-500/15 text-red-400 border border-red-500/30 px-2.5 py-0.5 font-mono font-medium">
                    <XCircle className="size-3 text-red-400" /> Rejected by Cognitive Gate
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 rounded-full bg-muted/15 text-muted border border-border px-2.5 py-0.5 font-mono">
                    Pending Cognitive AI Turn
                  </span>
                )}
              </div>

              <div className="rounded-lg border border-border bg-bg p-3 space-y-2">
                <div className="flex justify-between items-center text-[11px] font-mono">
                  <span className="text-muted">Quality Score:</span>
                  <span className="text-fg font-semibold">{Math.round(auditModalReport.qualityScore * 100)}%</span>
                </div>
                <div className="flex justify-between items-center text-[11px] font-mono">
                  <span className="text-muted">IOC Count:</span>
                  <span className="text-fg font-semibold">{auditModalReport.iocCount || 0} indicators</span>
                </div>
                <div className="flex justify-between items-center text-[11px] font-mono">
                  <span className="text-muted">Word Count:</span>
                  <span className="text-fg font-semibold">{auditModalReport.wordCount || 0} words</span>
                </div>
                <div className="flex justify-between items-center text-[11px] font-mono">
                  <span className="text-muted">Category:</span>
                  <span className="text-accent font-semibold">
                    {auditModalReport.resourceKind?.replace(/_/g, " ") || "CAMPAIGN INTEL"}
                  </span>
                </div>
              </div>

              {/* 5-DIMENSIONAL VALIDATION SCORECARD */}
              <div className="rounded-lg border border-border bg-bg p-3.5 space-y-2.5">
                <div className="flex justify-between items-center text-[11px] font-mono">
                  <span className="text-muted font-semibold uppercase tracking-wider">5D Validation Scorecard:</span>
                  <span className="text-accent font-bold text-xs">
                    {auditModalReport.scoreBreakdown?.totalScore ?? Math.round(auditModalReport.qualityScore * 100)} / 100
                  </span>
                </div>

                {/* Dimension 1: Procedural Depth (0-30) */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] font-mono text-muted">
                    <span>Procedural Depth (Commands/LOLBins)</span>
                    <span className="text-fg font-semibold">
                      {auditModalReport.scoreBreakdown?.proceduralDepth ?? Math.round(auditModalReport.qualityScore * 30)} / 30
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-bg-subtle overflow-hidden">
                    <div
                      className="h-full rounded-full bg-blue-500 transition-all duration-300"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(
                            8,
                            (((auditModalReport.scoreBreakdown?.proceduralDepth ?? Math.round(auditModalReport.qualityScore * 30))) / 30) * 100,
                          ),
                        )}%`,
                      }}
                    />
                  </div>
                </div>

                {/* Dimension 2: Attack Progression (0-25) */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] font-mono text-muted">
                    <span>Attack Progression (Multi-Stage Flow)</span>
                    <span className="text-fg font-semibold">
                      {auditModalReport.scoreBreakdown?.attackProgression ?? Math.round(auditModalReport.qualityScore * 25)} / 25
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-bg-subtle overflow-hidden">
                    <div
                      className="h-full rounded-full bg-indigo-500 transition-all duration-300"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(
                            8,
                            (((auditModalReport.scoreBreakdown?.attackProgression ?? Math.round(auditModalReport.qualityScore * 25))) / 25) * 100,
                          ),
                        )}%`,
                      }}
                    />
                  </div>
                </div>

                {/* Dimension 3: Attribution & Context (0-15) */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] font-mono text-muted">
                    <span>Attribution & Threat Context</span>
                    <span className="text-fg font-semibold">
                      {auditModalReport.scoreBreakdown?.attributionContext ?? Math.round(auditModalReport.qualityScore * 15)} / 15
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-bg-subtle overflow-hidden">
                    <div
                      className="h-full rounded-full bg-amber-500 transition-all duration-300"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(
                            8,
                            (((auditModalReport.scoreBreakdown?.attributionContext ?? Math.round(auditModalReport.qualityScore * 15))) / 15) * 100,
                          ),
                        )}%`,
                      }}
                    />
                  </div>
                </div>

                {/* Dimension 4: Emulation Utility (0-20) */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] font-mono text-muted">
                    <span>Emulation & Detection Utility</span>
                    <span className="text-fg font-semibold">
                      {auditModalReport.scoreBreakdown?.emulationUtility ?? Math.round(auditModalReport.qualityScore * 20)} / 20
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-bg-subtle overflow-hidden">
                    <div
                      className="h-full rounded-full bg-emerald-500 transition-all duration-300"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(
                            8,
                            (((auditModalReport.scoreBreakdown?.emulationUtility ?? Math.round(auditModalReport.qualityScore * 20))) / 20) * 100,
                          ),
                        )}%`,
                      }}
                    />
                  </div>
                </div>

                {/* Dimension 5: IOC Verifiability (0-10) */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] font-mono text-muted">
                    <span>IOC & Telemetry Verifiability</span>
                    <span className="text-fg font-semibold">
                      {auditModalReport.scoreBreakdown?.iocVerifiability ?? Math.round(auditModalReport.qualityScore * 10)} / 10
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-bg-subtle overflow-hidden">
                    <div
                      className="h-full rounded-full bg-cyan-500 transition-all duration-300"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(
                            8,
                            (((auditModalReport.scoreBreakdown?.iocVerifiability ?? Math.round(auditModalReport.qualityScore * 10))) / 10) * 100,
                          ),
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              </div>

              <div>
                <span className="text-[11px] font-medium text-muted uppercase tracking-wider block mb-1">
                  AI Audit Assessment
                </span>
                <p className="rounded-lg border border-border bg-bg-subtle p-3 text-fg text-xs leading-relaxed font-sans">
                  {auditModalReport.aiAuditReason ||
                    "Report verified through automated threat intelligence pipeline. Contains substantive technical adversary indicators, procedures, or vulnerability disclosures."}
                </p>
              </div>

              {auditModalReport.tags && auditModalReport.tags.length > 0 && (
                <div>
                  <span className="text-[11px] font-medium text-muted uppercase tracking-wider block mb-1.5">
                    Extracted Intelligence Tags ({auditModalReport.tags.length})
                  </span>
                  <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto p-1">
                    {auditModalReport.tags.map((t) => (
                      <span
                        key={t}
                        className="rounded bg-bg border border-border px-2 py-0.5 text-[10px] font-mono text-fg"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="pt-2 flex flex-wrap items-center justify-between gap-2 border-t border-border">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={isEvaluatingSingle}
                  onClick={() => handleEvaluateSingle(auditModalReport.id)}
                  className="text-xs border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 gap-1.5"
                >
                  <Sparkles className={cn("size-3.5", isEvaluatingSingle && "animate-spin text-emerald-400")} />
                  <span>
                    {isEvaluatingSingle
                      ? "Evaluating with Agent..."
                      : auditModalReport.aiVerified
                        ? "Re-evaluate with AI Agent"
                        : "Evaluate with AI Agent"}
                  </span>
                </Button>

                <div className="flex items-center gap-2">
                  <Link
                    to="/library/$reportId"
                    params={{ reportId: auditModalReport.id }}
                    onClick={() => setAuditModalReport(null)}
                    className="h-8 gap-1.5 text-xs inline-flex items-center justify-center rounded-lg border border-accent/40 bg-accent/10 hover:bg-accent/20 px-3 font-medium text-accent transition-colors"
                  >
                    <Workflow className="size-3.5" /> Full Dossier
                  </Link>

                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => {
                      const r = auditModalReport;
                      setAuditModalReport(null);
                      openPdfModal(r.id);
                    }}
                    className="text-xs"
                  >
                    <Eye className="size-3.5 mr-1" /> View High-Fidelity PDF
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setAuditModalReport(null)}
                    className="text-xs"
                  >
                    Close
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
