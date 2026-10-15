import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { z } from "zod";
import { ArrowUpRight, FileText, Search, SearchX, Shield, SlidersHorizontal, Sparkles, X } from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { EmptyState } from "@/components/ui/primitives";
import { formatDomainId, formatReportId } from "@/lib/aie/ids";
import { getReportPdf, listReports, auditLibraryWithAi } from "@/lib/aie/server";
import { cn } from "@/lib/cn";
import type { ReportListItem } from "@/lib/aie/types";
import { ReportEvidenceDialog } from "@/components/evidence/report-evidence-dialog";
import { ActionButton, SegmentedTabs, Toolbar } from "@/components/layout/page";
import { ListPageTemplate, Pagination } from "@/components/templates/page-templates";
import { ReportTable } from "@/components/library/report-table";
import { ReportPdfDialog } from "@/components/library/report-pdf-dialog";
import { AiReviewDialog } from "@/components/library/ai-review-dialog";
import { compareReports, downloadHtml, type ReportSort, type ReportSortKey } from "@/components/library/report-utils";

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
  { id: "ALL", label: "All" },
  { id: "FULL_ATTACK_CHAIN", label: "Attack chains" },
  { id: "CAMPAIGN_INTEL", label: "Campaigns" },
  { id: "PROCEDURE_DEEPDIVE", label: "Procedures" },
  { id: "MALWARE_ANALYSIS", label: "Malware" },
  { id: "DETECTION_GUIDANCE", label: "Detections" },
  { id: "VULNERABILITY_ADVISORY", label: "Vulnerabilities" },
  { id: "THREAT_ACTOR_DOSSIER", label: "Actor dossiers" },
];

const PAGE_SIZES = [20, 40, 60, 100, "all"] as const;
type PageSize = (typeof PAGE_SIZES)[number];

const TEXT_SORTS: ReportSortKey[] = ["title", "publisher", "type"];

const selectCls =
  "h-9 w-full rounded-lg border border-border bg-bg-elevated px-2.5 text-sm text-fg focus:outline-none focus:ring-1 focus:ring-accent";

function FilterSelect({
  label,
  value,
  onChange,
  allLabel,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  allLabel: string;
  options: string[];
}) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs text-muted">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className={selectCls}>
        <option value="ALL">
          {allLabel} ({options.length})
        </option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function FilterChip({ children, onRemove }: { children: React.ReactNode; onRemove: () => void }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-border bg-bg-elevated py-0.5 pl-2 pr-1 text-xs text-fg">
      <span className="truncate">{children}</span>
      <button
        type="button"
        onClick={onRemove}
        aria-label="Remove filter"
        className="flex size-4 items-center justify-center rounded text-muted hover:bg-bg-subtle hover:text-fg"
      >
        <X className="size-3" />
      </button>
    </span>
  );
}

function LibraryPage() {
  const queryClient = useQueryClient();
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
  const [colSort, setColSort] = useState<ReportSort>(null);
  const [showFilters, setShowFilters] = useState(Boolean(searchParams.tag || searchParams.sort));
  const [previewReportId, setPreviewReportId] = useState<string | null>(searchParams.pdf || null);
  const [auditModalReport, setAuditModalReport] = useState<ReportListItem | null>(null);
  const [evidenceReport, setEvidenceReport] = useState<ReportListItem | null>(null);
  const [isAuditing, setIsAuditing] = useState(false);

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState<PageSize>(20);

  const targetHighlightId = searchParams.selected || searchParams.highlight;

  const openReport = useCallback(
    (id: string) => void navigate({ to: "/library/$reportId", params: { reportId: id } }),
    [navigate],
  );

  const openPdfModal = useCallback(
    (id: string) => {
      setPreviewReportId(id);
      void navigate({ search: (prev) => ({ ...prev, pdf: id }), replace: true });
    },
    [navigate],
  );

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

  const clearSelection = () => {
    void navigate({
      search: (prev) => {
        const next = { ...prev };
        delete next.selected;
        delete next.highlight;
        delete next.pdf;
        return next;
      },
      replace: true,
    });
  };

  // Debounce search query to trigger server-side full content search
  const [debouncedQ, setDebouncedQ] = useState(q);
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQ(q.trim()), 280);
    return () => clearTimeout(timer);
  }, [q]);

  const isDeepSearchActive = debouncedQ.length >= 2;

  // Server-side deep content search over the full extracted text
  const { data: searchResults, isLoading: isSearchLoading } = useQuery({
    queryKey: ["reports-search", debouncedQ],
    queryFn: () => listReports({ data: { q: debouncedQ, limit: 200 } }),
    enabled: isDeepSearchActive,
    staleTime: 30_000,
  });

  // Fetch all reports to enable rich interactive filtering and instant counts
  const { data: rawReports, isLoading: isBaseLoading } = useQuery({
    queryKey: ["reports-all"],
    queryFn: () => listReports({ data: { limit: 500 } }),
    staleTime: 60_000,
    placeholderData: (previousData) => previousData,
  });

  const isLoading = isDeepSearchActive ? isSearchLoading : isBaseLoading;

  const allReports = useMemo(() => rawReports || [], [rawReports]);
  const activeReportsPool = useMemo(() => {
    if (isDeepSearchActive && searchResults) return searchResults;
    return allReports;
  }, [isDeepSearchActive, searchResults, allReports]);

  const handleRunAiAudit = async () => {
    setIsAuditing(true);
    toast.info("AI quality gate running across the library…");
    try {
      const res = await auditLibraryWithAi({ data: { limit: 10 } });
      toast.success(
        res.message ||
          `AI audit complete: ${res.verifiedCount} verified, ${res.prunedCount} flagged (${res.aiEvaluatedCount ?? 0} deep evaluations).`,
      );
      void queryClient.invalidateQueries({ queryKey: ["reports-all"] });
      void queryClient.invalidateQueries({ queryKey: ["reports-search"] });
    } catch (err: any) {
      toast.error(`AI audit failed: ${err?.message || "Unknown error"}`);
    } finally {
      setIsAuditing(false);
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

  // Open the document preview once per ?pdf= / ?selected= value (not again after the user closes it).
  const pdfOpenedRef = useRef<string | null>(null);
  const selOpenedRef = useRef<string | null>(null);
  useEffect(() => {
    if (searchParams.selected) {
      // A ?selected= link auto-opens the preview at most once; an explicit ?pdf= also counts.
      if (selOpenedRef.current !== searchParams.selected && (searchParams.pdf || targetReport)) {
        selOpenedRef.current = searchParams.selected;
        if (!searchParams.pdf && targetReport) setPreviewReportId(targetReport.id);
      }
    }
    if (searchParams.pdf && pdfOpenedRef.current !== searchParams.pdf) {
      pdfOpenedRef.current = searchParams.pdf;
      setPreviewReportId(searchParams.pdf);
    }
    if (!searchParams.pdf) pdfOpenedRef.current = null;
  }, [searchParams.pdf, searchParams.selected, targetReport]);

  const isHighlighted = useCallback(
    (r: ReportListItem) => {
      if (!targetHighlightId) return false;
      if (targetReport) return targetReport.id === r.id;
      const t = targetHighlightId.toLowerCase();
      const cleanT = t.replace(/^(rpt_|rst[-_]|report[-_])/i, "");
      const cleanR = r.id.toLowerCase().replace(/^(rpt_|rst[-_]|report[-_])/i, "");
      return r.id.toLowerCase() === t || formatReportId(r.id).toLowerCase() === t || (cleanT.length >= 8 && cleanR.includes(cleanT));
    },
    [targetHighlightId, targetReport],
  );

  // Filter and sort reports
  const filteredReports = useMemo(() => {
    // Direct Item Selector: If a specific resource is requested via ?selected=..., isolate directly to only that exact resource
    if (searchParams.selected) {
      return targetReport ? [targetReport] : [];
    }

    const query = q.trim().toLowerCase();

    const list = activeReportsPool
      .filter((r) => {

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
    searchParams.selected,
    isDeepSearchActive,
    targetReport,
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

  const sortedReports = useMemo(() => {
    if (!colSort) return filteredReports;
    const cmp = compareReports(colSort.key);
    const list = [...filteredReports].sort(cmp);
    return colSort.desc ? list.reverse() : list;
  }, [filteredReports, colSort]);

  const onSort = useCallback((key: ReportSortKey) => {
    setColSort((prev) =>
      prev?.key === key ? { key, desc: !prev.desc } : { key, desc: !TEXT_SORTS.includes(key) },
    );
  }, []);

  const activeFiltersCount =
    (selectedTag !== "ALL" ? 1 : 0) +
    (selectedActor !== "ALL" ? 1 : 0) +
    (selectedMalware !== "ALL" ? 1 : 0) +
    (selectedTactic !== "ALL" ? 1 : 0) +
    (selectedPublisher !== "ALL" ? 1 : 0) +
    (minQuality > 0 ? 1 : 0) +
    (onlyWithIocs ? 1 : 0) +
    (sortBy === "rejected" ? 1 : 0);

  // Reset pagination to page 1 on filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [q, selectedKind, selectedTag, selectedActor, selectedMalware, selectedTactic, selectedPublisher, minQuality, onlyWithIocs, sortBy, colSort]);

  const numericPageSize = pageSize === "all" ? Math.max(1, sortedReports.length) : pageSize;
  const pageCount = Math.max(1, Math.ceil(sortedReports.length / numericPageSize));

  // Jump to the page containing the highlighted report, then scroll it into view.
  useEffect(() => {
    if (!targetHighlightId || sortedReports.length === 0) return;
    const idx = sortedReports.findIndex(isHighlighted);
    if (idx === -1) return;
    const targetPage = Math.floor(idx / numericPageSize) + 1;
    if (targetPage !== currentPage) setCurrentPage(targetPage);
    // only re-run when the target or list changes, not on manual paging
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetHighlightId, targetReport, sortedReports, numericPageSize, isHighlighted]);

  useEffect(() => {
    if (!targetHighlightId) return;
    let cancelled = false;
    let attempts = 0;
    const tryScroll = () => {
      if (cancelled) return;
      attempts++;
      const id = targetReport?.id || targetHighlightId;
      const el =
        document.getElementById(`report-${id}`) || document.querySelector(`[data-report-id="${CSS.escape(id)}"]`);
      if (el) {
        el.closest("tr")?.scrollIntoView({ behavior: "smooth", block: "center" });
      } else if (attempts < 40) {
        setTimeout(tryScroll, 80);
      }
    };
    const timer = setTimeout(tryScroll, 120);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [targetHighlightId, targetReport, currentPage]);

  const pagedReports = useMemo(
    () => sortedReports.slice((currentPage - 1) * numericPageSize, currentPage * numericPageSize),
    [sortedReports, currentPage, numericPageSize],
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
    if (sortBy === "rejected") setSortBy("newest");
    setQ("");
    if (searchParams.selected || searchParams.highlight) clearSelection();
  };

  const handleDownload = useCallback((r: ReportListItem) => {
    void (async () => {
      try {
        toast.info("Preparing the document for download…");
        const rep = await getReportPdf({ data: { id: r.id } });
        if (!rep.ok || !rep.rawHtml) {
          toast.error("No document representation is available for this report");
          return;
        }
        downloadHtml(rep.rawHtml, rep.title || r.title);
        toast.success("Document downloaded", {
          description: "Open it and choose Print → Save as PDF for a vector PDF.",
        });
      } catch {
        toast.error("Failed to download the document");
      }
    })();
  }, []);

  const rowActions = useMemo(
    () => ({
      open: (r: ReportListItem) => openReport(r.id),
      viewPdf: (r: ReportListItem) => openPdfModal(r.id),
      download: handleDownload,
      evidence: (r: ReportListItem) => setEvidenceReport(r),
      aiReview: (r: ReportListItem) => setAuditModalReport(r),
    }),
    [openReport, openPdfModal, handleDownload],
  );

  const filterChips: Array<{ label: string; clear: () => void }> = [
    selectedTag !== "ALL" && { label: `Tag: ${selectedTag}`, clear: () => setSelectedTag("ALL") },
    selectedActor !== "ALL" && { label: `Actor: ${selectedActor}`, clear: () => setSelectedActor("ALL") },
    selectedMalware !== "ALL" && { label: `Malware: ${selectedMalware}`, clear: () => setSelectedMalware("ALL") },
    selectedTactic !== "ALL" && { label: `Tactic: ${selectedTactic}`, clear: () => setSelectedTactic("ALL") },
    selectedPublisher !== "ALL" && { label: `Publisher: ${selectedPublisher}`, clear: () => setSelectedPublisher("ALL") },
    minQuality > 0 && { label: `Quality ≥ ${Math.round(minQuality * 100)}%`, clear: () => setMinQuality(0) },
    onlyWithIocs && { label: "Has IOCs", clear: () => setOnlyWithIocs(false) },
    sortBy === "rejected" && { label: `Rejected by AI (${rejectedCount})`, clear: () => setSortBy("newest") },
  ].filter(Boolean) as Array<{ label: string; clear: () => void }>;

  return (
    <AppShell>
      <ListPageTemplate
        header={{
          title: "Library",
          description: "Acquired threat intelligence with normalized evidence, IOCs and reconstructed attack chains.",
          actions: (
            <ActionButton
              variant="primary"
              icon={Sparkles}
              disabled={isAuditing}
              onClick={handleRunAiAudit}
              title="Run the AI quality gate across acquired reports"
            >
              {isAuditing ? "Auditing…" : "Audit with AI"}
            </ActionButton>
          ),
          tabs: (
            <SegmentedTabs
              ariaLabel="Report category"
              items={RESOURCE_KINDS.map((c) => ({ value: c.id, label: c.label, count: categoryCounts[c.id] ?? 0 }))}
              value={selectedKind}
              onChange={setSelectedKind}
            />
          ),
        }}
        toolbar={
          <div className="mb-4 flex flex-col gap-3">
            <Toolbar
              className="mb-0"
              left={
                <>
                  <div className="relative w-full sm:w-80">
                    <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" />
                    <input
                      value={q}
                      onChange={(e) => setQ(e.target.value)}
                      placeholder="Search title, CVE, actor, malware, hash…"
                      aria-label="Search library"
                      className="h-9 w-full rounded-lg border border-border bg-bg-elevated pl-9 pr-8 text-sm text-fg placeholder:text-subtle focus:outline-none focus:ring-1 focus:ring-accent"
                    />
                    {q && (
                      <button
                        type="button"
                        onClick={() => setQ("")}
                        aria-label="Clear search"
                        className="absolute right-2 top-1/2 flex size-5 -translate-y-1/2 items-center justify-center rounded text-muted hover:text-fg"
                      >
                        <X className="size-3.5" />
                      </button>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => setShowFilters(!showFilters)}
                    aria-expanded={showFilters}
                    className={cn(
                      "inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle",
                      showFilters && "bg-bg-subtle",
                    )}
                  >
                    <SlidersHorizontal className="size-4" strokeWidth={1.75} />
                    Filters
                    {activeFiltersCount > 0 && (
                      <span className="rounded bg-accent px-1.5 text-[11px] font-medium text-accent-fg tabular-nums">
                        {activeFiltersCount}
                      </span>
                    )}
                  </button>
                </>
              }
              right={
                <span className="text-sm text-muted">
                  <span className="tabular-nums text-fg">{sortedReports.length}</span>{" "}
                  {sortedReports.length === 1 ? "report" : "reports"}
                  {sortedReports.length !== allReports.length && (
                    <span className="text-subtle"> of {allReports.length}</span>
                  )}
                  {isDeepSearchActive && <span className="text-subtle"> · full-text search</span>}
                </span>
              }
            />

            {showFilters && (
              <div className="rounded-xl border border-border bg-bg-card p-5">
                <div className="mb-4 flex items-center justify-between gap-3">
                  <h2 className="text-base font-medium text-fg">Filters</h2>
                  {activeFiltersCount > 0 && (
                    <button type="button" onClick={resetFilters} className="text-sm text-muted hover:text-fg">
                      Reset all
                    </button>
                  )}
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
                  <FilterSelect label="Tag" value={selectedTag} onChange={setSelectedTag} allLabel="All tags" options={filterOptions.tags} />
                  <FilterSelect label="Threat actor" value={selectedActor} onChange={setSelectedActor} allLabel="All actors" options={filterOptions.actors} />
                  <FilterSelect label="Malware family" value={selectedMalware} onChange={setSelectedMalware} allLabel="All malware" options={filterOptions.malware} />
                  <FilterSelect label="ATT&CK tactic" value={selectedTactic} onChange={setSelectedTactic} allLabel="All tactics" options={filterOptions.tactics} />
                  <FilterSelect label="Publisher" value={selectedPublisher} onChange={setSelectedPublisher} allLabel="All publishers" options={filterOptions.publishers} />
                </div>
                <div className="mt-4 flex flex-wrap items-end gap-4 border-t border-border pt-4">
                  <label className="block w-full space-y-1.5 sm:w-48">
                    <span className="text-xs text-muted">Minimum quality</span>
                    <select value={minQuality} onChange={(e) => setMinQuality(parseFloat(e.target.value))} className={selectCls}>
                      <option value={0}>Any score</option>
                      <option value={0.6}>60% or higher</option>
                      <option value={0.8}>80% or higher</option>
                    </select>
                  </label>
                  <label className="block w-full space-y-1.5 sm:w-56">
                    <span className="text-xs text-muted">Order</span>
                    <select
                      value={sortBy}
                      onChange={(e) => {
                        setSortBy(e.target.value as typeof sortBy);
                        setColSort(null);
                      }}
                      className={selectCls}
                    >
                      <option value="newest">Newest ingested</option>
                      <option value="quality">Quality score</option>
                      <option value="iocs">Most IOCs</option>
                      <option value="words">Longest analysis</option>
                      <option value="rejected">Rejected by AI only ({rejectedCount})</option>
                    </select>
                  </label>
                  <label className="flex h-9 cursor-pointer items-center gap-2 text-sm text-muted">
                    <input
                      type="checkbox"
                      checked={onlyWithIocs}
                      onChange={(e) => setOnlyWithIocs(e.target.checked)}
                      className="size-4 accent-[var(--color-accent)]"
                    />
                    Only reports with IOCs
                  </label>
                </div>
              </div>
            )}

            {filterChips.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-muted">Filtered by</span>
                {filterChips.map((c) => (
                  <FilterChip key={c.label} onRemove={c.clear}>
                    {c.label}
                  </FilterChip>
                ))}
                <button type="button" onClick={resetFilters} className="text-xs text-muted underline-offset-2 hover:text-fg hover:underline">
                  Clear all
                </button>
              </div>
            )}

            {searchParams.selected && (
              <div className="flex flex-col gap-3 rounded-xl border border-border bg-bg-card px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 items-center gap-3">
                  <FileText className="size-4 shrink-0 text-accent" strokeWidth={1.75} />
                  <p className="min-w-0 truncate text-sm text-muted">
                    Showing one report:{" "}
                    <span className="text-fg">{targetReport ? targetReport.title : searchParams.selected}</span>
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {targetReport && (
                    <>
                      <ActionButton icon={ArrowUpRight} onClick={() => openReport(targetReport.id)}>
                        Open report
                      </ActionButton>
                      <ActionButton icon={Shield} onClick={() => setEvidenceReport(targetReport)}>
                        Evidence
                      </ActionButton>
                    </>
                  )}
                  <ActionButton variant="ghost" icon={X} onClick={clearSelection}>
                    Show all {allReports.length}
                  </ActionButton>
                </div>
              </div>
            )}
          </div>
        }
        footer={
          sortedReports.length > 0 ? (
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <label className="flex items-center gap-2 text-sm text-muted">
                Rows per page
                <select
                  value={String(pageSize)}
                  onChange={(e) => {
                    const v = e.target.value;
                    setPageSize(v === "all" ? "all" : (Number(v) as PageSize));
                    setCurrentPage(1);
                  }}
                  className="h-8 rounded-lg border border-border bg-bg-elevated px-2 text-sm text-fg"
                >
                  {PAGE_SIZES.map((s) => (
                    <option key={s} value={String(s)}>
                      {s === "all" ? "All" : s}
                    </option>
                  ))}
                </select>
              </label>
              <div className="sm:min-w-[320px]">
                <Pagination
                  page={Math.min(currentPage, pageCount)}
                  pageCount={pageCount}
                  total={sortedReports.length}
                  pageSize={numericPageSize}
                  onPage={handlePageChange}
                />
              </div>
            </div>
          ) : undefined
        }
      >
        {isLoading && allReports.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-bg-card py-16 text-muted">
            <ActivitySpinner size="lg" className="mb-2 text-accent" />
            <p className="text-sm">Loading the library…</p>
          </div>
        ) : (
          <ReportTable
            rows={pagedReports}
            sort={colSort}
            onSort={onSort}
            actions={rowActions}
            isHighlighted={isHighlighted}
            showSnippets={isDeepSearchActive}
            empty={
              isLoading ? (
                <div className="flex justify-center">
                  <ActivitySpinner size="lg" className="text-accent" />
                </div>
              ) : (
                <EmptyState
                  icon={SearchX}
                  title="No reports match these filters"
                  description="Try a broader search or remove some filters."
                  action={
                    activeFiltersCount > 0 || q || searchParams.selected ? (
                      <ActionButton onClick={resetFilters}>Reset filters</ActionButton>
                    ) : undefined
                  }
                />
              )
            }
          />
        )}
      </ListPageTemplate>

      <ReportPdfDialog
        reportId={previewReportId}
        onClose={closePdfModal}
        onOpenReport={(id) => {
          setPreviewReportId(null);
          openReport(id);
        }}
      />

      <AiReviewDialog report={auditModalReport} onClose={() => setAuditModalReport(null)} onOpenPdf={openPdfModal} />

      {evidenceReport && (
        <ReportEvidenceDialog
          reportId={evidenceReport.id}
          title={evidenceReport.title}
          open={Boolean(evidenceReport)}
          onOpenChange={(o) => !o && setEvidenceReport(null)}
        />
      )}
    </AppShell>
  );
}
