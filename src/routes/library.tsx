import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { z } from "zod";
import {
  AlertTriangle,
  ArrowUpRight,
  EyeOff,
  FileText,
  FlaskConical,
  GitBranch,
  LayoutGrid,
  Layers,
  List,
  Megaphone,
  Plus,
  RefreshCw,
  Search,
  SearchX,
  Shield,
  SlidersHorizontal,
  Sparkles,
  Swords,
  Table2,
  Undo2,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { Select } from "@/components/ui/select";
import { EmptyState } from "@/components/ui/primitives";
import { DOC_TYPE_META, DocTypeBadge } from "@/components/ui/entity";
import { formatDomainId, formatReportId } from "@/lib/aie/ids";
import { getReportPdf, listReports } from "@/lib/aie/server";
import { analyseReportWithAi, recoverHiddenReports, reportsToAnalyse } from "@/lib/aie/server-review";
import { searchLibrary } from "@/lib/aie/server-search";
import { dateLibraryReports, labelLibraryResearch, runLibraryGate, setReportVisibility } from "@/lib/aie/server-library";
import { researchCategory } from "@/lib/aie/research-taxonomy";
import { DataSourceNotice } from "@/components/layout/data-source-notice";
import { cn } from "@/lib/cn";
import type { DocType, ReportListItem, SourceTier } from "@/lib/aie/types";
import { EMULATION_GRADE_META, effectiveGrade, type EmulationGrade } from "@/lib/aie/emulation-value";
import { ReportEvidenceDialog } from "@/components/evidence/report-evidence-dialog";
import { ActionButton, PageHeader, SegmentedTabs } from "@/components/layout/page";
import { Pagination } from "@/components/templates/page-templates";
import { ReportTable } from "@/components/library/report-table";
import { ReportPdfDialog } from "@/components/library/report-pdf-dialog";
import { AiReviewDialog } from "@/components/library/ai-review-dialog";
import { ReportFeedCard, ReportListRow, TierDot } from "@/components/library/report-card";
import { FacetGroup, FacetPanel, FacetToggle, type FacetOption } from "@/components/library/facet-sidebar";
import { LibraryKpiStrip, type LibraryKpi } from "@/components/library/library-kpis";
import {
  DOC_TABS,
  TIER_META,
  actorsOf,
  cvesOf,
  docTypesOf,
  hasEmulationContent,
  malwareOf,
  publisherOf,
  tacticsOf,
  techniquesOf,
  tierOf,
} from "@/components/library/intel-taxonomy";
import { fetchEmulationOptions, fetchIntelCoverage, hasEmulationOptionsApi, hasIntelCoverageApi } from "@/components/library/intel-api";
import { compareReports, dateValue, downloadHtml, type ReportSort, type ReportSortKey } from "@/components/library/report-utils";

const librarySearchSchema = z.object({
  q: z.string().optional(),
  selected: z.string().optional(),
  highlight: z.string().optional(),
  pdf: z.string().optional(),
  tag: z.string().optional(),
  /** A research category id (research-taxonomy), e.g. from the coverage view. */
  research: z.string().optional(),
  sort: z.enum(["published", "newest", "emulation", "quality", "iocs", "words", "rejected"]).optional(),
  /** Publication window, e.g. from the dashboard's "latest" links. */
  published: z.enum(["any", "7d", "30d", "90d", "365d"]).optional(),
});

export const Route = createFileRoute("/library")({
  validateSearch: (search) => librarySearchSchema.parse(search),
  component: LibraryPage,
});

/** The Library loads every report, in pages of this size (up to LIST_MAX_PAGES pages). */
const LIST_PAGE = 500;
const LIST_MAX_PAGES = 40;
const PAGE_SIZES = [20, 40, 60, 100, "all"] as const;
type PageSize = (typeof PAGE_SIZES)[number];

const TEXT_SORTS: ReportSortKey[] = ["title", "publisher", "type"];

type ViewMode = "cards" | "table" | "list";
const VIEW_KEY = "aie_library_view";
type OrderBy = "relevance" | "newest" | "published" | "emulation" | "quality" | "iocs" | "techniques" | "words";

const GRADE_ORDER: Array<EmulationGrade | "ungraded"> = ["chain", "procedures", "context", "news", "ungraded"];
const gradeRank = (r: ReportListItem) => {
  const g = effectiveGrade(r.emulation);
  return g ? EMULATION_GRADE_META[g].rank : -1;
};
/** The default order: the latest research first, by the date the source published it. */
const DEFAULT_ORDER: OrderBy = "published";

/** Publication window: always one selected ("Any time" by default), custom uses the From/To dates. */
type PublishedWindow = "any" | "7d" | "30d" | "90d" | "365d" | "custom";
const PUBLISHED_WINDOWS: Array<{ value: PublishedWindow; label: string; days?: number }> = [
  { value: "any", label: "Any time" },
  { value: "7d", label: "Last 7 days", days: 7 },
  { value: "30d", label: "Last 30 days", days: 30 },
  { value: "90d", label: "Last 90 days", days: 90 },
  { value: "365d", label: "Last 12 months", days: 365 },
  { value: "custom", label: "Custom range" },
];

type Derived = {
  types: DocType[];
  tier: SourceTier | null;
  publisher: string;
  actors: string[];
  malware: string[];
  tactics: string[];
  techniques: string[];
  cves: string[];
  emulation: boolean;
  /** Emulation value grade (./emulation-value), "ungraded" until the library check has run. */
  grade: EmulationGrade | "ungraded";
  published: number;
  research: string[];
};

function derive(r: ReportListItem): Derived {
  return {
    types: docTypesOf(r),
    tier: tierOf(r),
    publisher: publisherOf(r),
    actors: actorsOf(r),
    malware: malwareOf(r),
    tactics: tacticsOf(r),
    techniques: techniquesOf(r).map((t) => t.id),
    cves: cvesOf(r),
    emulation: hasEmulationContent(r),
    grade: effectiveGrade(r.emulation) ?? "ungraded",
    published: dateValue(r.publishedAt),
    research: (r.research?.labels ?? []).map((l) => l.id),
  };
}

function countBy(values: string[][]): FacetOption[] {
  const m = new Map<string, number>();
  for (const vs of values) for (const v of new Set(vs)) m.set(v, (m.get(v) ?? 0) + 1);
  return Array.from(m.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([value, count]) => ({ value, label: value, count, text: value }));
}

function toggle(list: string[], v: string): string[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
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
  const [docTab, setDocTab] = useState("ALL");
  const [selDocTypes, setSelDocTypes] = useState<string[]>([]);
  const [selTiers, setSelTiers] = useState<string[]>([]);
  const [selPublishers, setSelPublishers] = useState<string[]>([]);
  const [selActors, setSelActors] = useState<string[]>([]);
  const [selMalware, setSelMalware] = useState<string[]>([]);
  const [selTactics, setSelTactics] = useState<string[]>([]);
  const [selTags, setSelTags] = useState<string[]>(searchParams.tag ? [searchParams.tag] : []);
  const [selEmulation, setSelEmulation] = useState<string[]>([]);
  const [selResearch, setSelResearch] = useState<string[]>(searchParams.research && researchCategory(searchParams.research) ? [searchParams.research] : []);
  // A link to /library?research=… while the Library is already open selects that category too.
  useEffect(() => {
    if (searchParams.research && researchCategory(searchParams.research)) setSelResearch([searchParams.research]);
  }, [searchParams.research]);
  const [publishedWindow, setPublishedWindow] = useState<PublishedWindow>(searchParams.published ?? "any");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [minQuality, setMinQuality] = useState<number>(0);
  const [onlyWithIocs, setOnlyWithIocs] = useState(false);
  const [onlyWithEmulation, setOnlyWithEmulation] = useState(false);
  const [onlyNeedsReview, setOnlyNeedsReview] = useState(false);
  const [showRejected, setShowRejected] = useState(searchParams.sort === "rejected");
  const [orderBy, setOrderBy] = useState<OrderBy>(
    searchParams.sort && searchParams.sort !== "rejected" ? searchParams.sort : DEFAULT_ORDER,
  );
  const [colSort, setColSort] = useState<ReportSort>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [previewReportId, setPreviewReportId] = useState<string | null>(searchParams.pdf || null);
  const [auditModalReport, setAuditModalReport] = useState<ReportListItem | null>(null);
  const [evidenceReport, setEvidenceReport] = useState<ReportListItem | null>(null);
  const [reviewProgress, setReviewProgress] = useState<{ done: number; total: number } | null>(null);
  const cancelReview = useRef(false);
  const [view, setViewState] = useState<ViewMode>("cards");

  useEffect(() => {
    try {
      const v = localStorage.getItem(VIEW_KEY);
      if (v === "cards" || v === "table" || v === "list") setViewState(v);
    } catch {
      /* storage unavailable */
    }
  }, []);
  const setView = (v: ViewMode) => {
    setViewState(v);
    try {
      localStorage.setItem(VIEW_KEY, v);
    } catch {
      /* storage unavailable */
    }
  };

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
  const serverOrder = orderBy === "newest" ? "ingested" : "published";

  // Server-side hybrid ranker (aliases, technique names, field syntax); see src/lib/aie/search.
  const { data: searchData, isLoading: isSearchLoading } = useQuery({
    queryKey: ["reports-search", debouncedQ],
    queryFn: () => searchLibrary({ data: { q: debouncedQ, limit: 200 } }),
    enabled: isDeepSearchActive,
    staleTime: 30_000,
  });
  // Rank by relevance while a search is active, unless the analyst picked another order.
  useEffect(() => {
    setOrderBy((prev) =>
      isDeepSearchActive ? (prev === DEFAULT_ORDER || prev === "newest" ? "relevance" : prev) : prev === "relevance" ? DEFAULT_ORDER : prev,
    );
  }, [isDeepSearchActive]);

  const {
    data: rawReports,
    isLoading: isBaseLoading,
    error: reportsError,
    refetch: refetchReports,
  } = useQuery({
    // The whole library, fetched in pages of 500 (newest first), so tabs, facets and counts cover
    // every report rather than the latest 500.
    queryKey: ["reports-all", serverOrder],
    queryFn: async () => {
      const out: ReportListItem[] = [];
      for (let page = 0; page < LIST_MAX_PAGES; page++) {
        const batch = await listReports({ data: { limit: LIST_PAGE, offset: page * LIST_PAGE, order: serverOrder, view: "list" } });
        out.push(...batch);
        if (batch.length < LIST_PAGE) break;
      }
      return out;
    },
    staleTime: 60_000,
    placeholderData: (previousData) => previousData,
  });

  // Library gate: hides reports that are not technical threat intel (homepages, listings, webinars,
  // product pages, strategy pieces, news without technical detail, stubs) once
  // per rules version; nothing is deleted. See src/lib/aie/library-gate.ts.
  const gateQuery = useQuery({
    queryKey: ["library-gate"],
    queryFn: () => runLibraryGate(),
    staleTime: 10 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const [gateNoticeDismissed, setGateNoticeDismissed] = useState(false);
  const refreshLibrary = useCallback(() => {
    for (const key of ["reports-all", "reports-search", "intel-coverage", "nav-counts", "dashboard", "research-coverage"]) {
      void queryClient.invalidateQueries({ queryKey: [key] });
    }
  }, [queryClient]);
  useEffect(() => {
    if (gateQuery.data?.newlyHidden.length) refreshLibrary();
  }, [gateQuery.data, refreshLibrary]);

  // Research labels (research-taxonomy) for reports stored before labelling or under an older
  // labeller: a few batches on open, then the Library reloads with the "Research type" facet filled.
  const labelQuery = useQuery({
    queryKey: ["library-research-labels"],
    queryFn: async () => {
      let labelled = 0;
      for (let i = 0; i < 10; i++) {
        const r = await labelLibraryResearch();
        labelled += r.labelled;
        if (r.remaining === 0 || r.labelled === 0) break;
      }
      return { labelled };
    },
    staleTime: 10 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
  });
  useEffect(() => {
    if (labelQuery.data?.labelled) refreshLibrary();
  }, [labelQuery.data, refreshLibrary]);

  // Publication dates (published-date) for reports stored before the resolver or under an older one:
  // a few batches on open; the Library reloads when a date changed.
  const dateQuery = useQuery({
    queryKey: ["library-published-dates"],
    queryFn: async () => {
      let changed = 0;
      for (let i = 0; i < 12; i++) {
        const r = await dateLibraryReports();
        changed += r.changed;
        if (r.remaining === 0 || r.dated === 0) break;
      }
      return { changed };
    },
    staleTime: 10 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
  });
  useEffect(() => {
    if (dateQuery.data?.changed) refreshLibrary();
  }, [dateQuery.data, refreshLibrary]);

  // Reports the earlier AI audit hid although they carry indicators, techniques or technical depth
  // come back once, flagged "Needs review" (deterministic, no AI call).
  const recoveryQuery = useQuery({
    queryKey: ["library-recover-hidden"],
    queryFn: () => recoverHiddenReports(),
    staleTime: 30 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
  });
  useEffect(() => {
    const n = recoveryQuery.data?.restored ?? 0;
    if (!n) return;
    refreshLibrary();
    toast.info(`Restored ${n} report${n === 1 ? "" : "s"} the earlier AI audit had hidden`, {
      description: "They carry indicators, techniques or technical depth. Find them under Needs review to confirm.",
    });
  }, [recoveryQuery.data, refreshLibrary]);

  const changeVisibility = useCallback(
    async (ids: string[], action: "hide" | "restore") => {
      try {
        const res = await setReportVisibility({ data: { ids, action } });
        const n = res.changed;
        toast.success(
          action === "hide"
            ? `Hid ${n} report${n === 1 ? "" : "s"} from the library. Find ${n === 1 ? "it" : "them"} under Hidden.`
            : `Restored ${n} report${n === 1 ? "" : "s"} to the library.`,
        );
        refreshLibrary();
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Could not change the report's visibility");
      }
    },
    [refreshLibrary],
  );

  const { data: coverage } = useQuery({
    queryKey: ["intel-coverage"],
    queryFn: fetchIntelCoverage,
    enabled: hasIntelCoverageApi,
    staleTime: 60_000,
  });

  const isLoading = isDeepSearchActive ? isSearchLoading : isBaseLoading;

  const allReports = useMemo(() => rawReports || [], [rawReports]);
  const searchRank = useMemo(() => new Map((searchData?.hits ?? []).map((h) => [h.id, h.rank])), [searchData]);
  const searchResults = useMemo(() => {
    if (!searchData) return undefined;
    const loaded = new Map(allReports.map((r) => [r.id, r]));
    return searchData.hits.map((h) => ({ ...(loaded.get(h.id) ?? h.item), matchedSnippet: h.matchedSnippet }));
  }, [searchData, allReports]);
  // Full-text hits from the server, plus everything already loaded (matched client-side on entities below).
  const activeReportsPool = useMemo(() => {
    if (!isDeepSearchActive || !searchResults) return allReports;
    const ids = new Set(searchResults.map((r) => r.id));
    return [...searchResults, ...allReports.filter((r) => !ids.has(r.id))];
  }, [isDeepSearchActive, searchResults, allReports]);
  const serverHitIds = useMemo(() => new Set((isDeepSearchActive ? searchResults : undefined)?.map((r) => r.id) ?? []), [isDeepSearchActive, searchResults]);

  // Derived taxonomy/entities per report, computed once per record.
  const derivedRef = useRef(new WeakMap<ReportListItem, Derived>());
  const d = useCallback((r: ReportListItem): Derived => {
    let v = derivedRef.current.get(r);
    if (!v) {
      v = derive(r);
      derivedRef.current.set(r, v);
    }
    return v;
  }, []);

  const libraryTechniques = useMemo(() => {
    const s = new Set<string>();
    for (const r of allReports) if (r.status !== "rejected") for (const t of d(r).techniques) s.add(t);
    return Array.from(s).sort();
  }, [allReports, d]);

  const { data: emulationOptions } = useQuery({
    queryKey: ["emulation-options", libraryTechniques.join(",")],
    queryFn: () => fetchEmulationOptions(libraryTechniques),
    enabled: hasEmulationOptionsApi && libraryTechniques.length > 0,
    staleTime: 5 * 60_000,
  });

  // AI analysis + safe review of the newest-published reports not analysed yet, one report per
  // request so a slow model never times out the page. Nothing is deleted; uncertain reports are
  // flagged "Needs review". Clicking again stops after the current report.
  const handleRunAiReview = async () => {
    if (reviewProgress) {
      cancelReview.current = true;
      return;
    }
    cancelReview.current = false;
    const tid = toast.loading("Finding reports to analyse…");
    const tally = { keep: 0, flag: 0, hide: 0, restore_and_flag: 0, unchanged: 0, failed: 0 };
    let firstError = "";
    try {
      const queue = await reportsToAnalyse({ data: { limit: 10 } });
      if (queue.length === 0) {
        toast.success("Every report already has an AI analysis.", { id: tid });
        return;
      }
      setReviewProgress({ done: 0, total: queue.length });
      for (const [i, item] of queue.entries()) {
        if (cancelReview.current) break;
        toast.loading(`Analysing ${i + 1} of ${queue.length}: ${item.title.slice(0, 70)}`, { id: tid });
        const res = await analyseReportWithAi({ data: { id: item.id } }).catch((err: unknown) => ({ ok: false as const, error: err instanceof Error ? err.message : "failed" }));
        if (res.ok) tally[res.action]++;
        else {
          tally.failed++;
          firstError ||= res.error;
          // The provider is down: stop instead of failing every report.
          if (tally.failed >= 2 && tally.failed === i + 1) break;
        }
        setReviewProgress({ done: i + 1, total: queue.length });
      }
      const analysed = tally.keep + tally.flag + tally.hide + tally.restore_and_flag + tally.unchanged;
      const parts = [
        tally.keep && `${tally.keep} useful`,
        tally.flag && `${tally.flag} flagged for review`,
        tally.restore_and_flag && `${tally.restore_and_flag} restored and flagged`,
        tally.hide && `${tally.hide} hidden (restorable)`,
        tally.failed && `${tally.failed} failed`,
      ].filter(Boolean);
      if (analysed === 0) toast.error(`AI analysis failed: ${firstError || "no AI provider answered"}`, { id: tid });
      else toast.success(`Analysed ${analysed} report${analysed === 1 ? "" : "s"}${parts.length ? `: ${parts.join(", ")}` : ""}.`, { id: tid, description: cancelReview.current ? "Stopped early." : undefined });
      refreshLibrary();
    } catch (err) {
      toast.error(`AI analysis failed: ${err instanceof Error ? err.message : "unknown error"}`, { id: tid });
    } finally {
      setReviewProgress(null);
      cancelReview.current = false;
    }
  };

  const acceptedReports = useMemo(() => allReports.filter((r) => r.status !== "rejected"), [allReports]);
  const rejectedCount = allReports.length - acceptedReports.length;

  const tabCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const t of DOC_TABS) out[t.id] = acceptedReports.filter((r) => !t.types || d(r).types.some((x) => t.types!.includes(x))).length;
    return out;
  }, [acceptedReports, d]);

  // Robust target report resolution: matches by ID, formatted ID, URL, canonical URL, or title
  const targetReport = useMemo(() => {
    if (!targetHighlightId || allReports.length === 0) return null;
    const rawTarget = targetHighlightId.trim();
    const lower = rawTarget.toLowerCase();
    const cleanTarget = lower.replace(/^(rpt_|rst[-_]|report[-_])/i, "");

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

    const byUrl = allReports.find(
      (r) =>
        (r.canonicalUrl && (r.canonicalUrl === rawTarget || r.canonicalUrl.toLowerCase() === lower)) ||
        (r.url && (r.url === rawTarget || r.url.toLowerCase() === lower)),
    );
    if (byUrl) return byUrl;

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

    const byExactTitle = allReports.find((r) => r.title && r.title.trim().toLowerCase() === lower);
    if (byExactTitle) return byExactTitle;

    if (lower.length >= 3) {
      const byTitle = allReports.find(
        (r) => r.title && (r.title.toLowerCase().includes(lower) || lower.includes(r.title.toLowerCase())),
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

  const query = q.trim().toLowerCase();

  /** Status + tab + text search: the pool that facet counts describe. */
  const basePool = useMemo(() => {
    const tab = DOC_TABS.find((t) => t.id === docTab) ?? DOC_TABS[0];
    return activeReportsPool.filter((r) => {
      if (showRejected ? r.status !== "rejected" : r.status === "rejected") return false;
      if (tab.types && !d(r).types.some((t) => tab.types!.includes(t))) return false;
      if (query && !serverHitIds.has(r.id)) {
        const x = d(r);
        const searchable = `${r.title} ${r.sourceName} ${r.publisher} ${r.url} ${r.canonicalUrl} ${r.id} ${formatReportId(r.id)} ${r.sourceId} ${
          r.ingestOrigin || ""
        } ${formatDomainId(r.sourceDomain || r.url)} ${r.excerpt} ${r.classification} ${r.resourceKind || ""} ${r.tags?.join(" ") || ""} ${x.actors.join(
          " ",
        )} ${x.malware.join(" ")} ${x.cves.join(" ")} ${x.techniques.join(" ")} ${r.analysis?.ttps?.join(" ") || ""} ${r.analysis?.ioas?.join(" ") || ""} ${x.tactics.join(" ")} ${r.iocs?.map((i) => i.value).join(" ") || ""}`.toLowerCase();
        if (!searchable.includes(query)) return false;
      }
      return true;
    });
  }, [activeReportsPool, showRejected, docTab, query, serverHitIds, d]);

  const facets = useMemo(() => {
    const types = countBy(basePool.map((r) => d(r).types));
    const tiers = countBy(basePool.map((r) => [d(r).tier ? String(d(r).tier) : "unrated"]));
    return {
      docTypes: types.map((o) => ({ ...o, label: <DocTypeBadge type={o.value as DocType} />, text: DOC_TYPE_META[o.value as DocType]?.label ?? o.value })),
      tiers: tiers
        .sort((a, b) => a.value.localeCompare(b.value))
        .map((o) => ({
          ...o,
          label:
            o.value === "unrated" ? (
              <span className="text-subtle">Unrated source</span>
            ) : (
              <span className="inline-flex items-center gap-2">
                <TierDot tier={Number(o.value) as SourceTier} />
                {TIER_META[Number(o.value) as SourceTier].label.replace(/^Tier \d · /, "")}
                <span className="text-subtle">· T{o.value}</span>
              </span>
            ),
        })),
      publishers: countBy(basePool.map((r) => [d(r).publisher])),
      actors: countBy(basePool.map((r) => d(r).actors)).map((o) => ({
        ...o,
        label: <span style={{ color: "var(--color-cat-actor)" }}>{o.value}</span>,
      })),
      malware: countBy(basePool.map((r) => d(r).malware)).map((o) => ({
        ...o,
        label: <span style={{ color: "var(--color-cat-malware)" }}>{o.value}</span>,
      })),
      tactics: countBy(basePool.map((r) => d(r).tactics)),
      emulation: countBy(basePool.map((r) => [d(r).grade]))
        .sort((a, b) => GRADE_ORDER.indexOf(a.value as EmulationGrade) - GRADE_ORDER.indexOf(b.value as EmulationGrade))
        .map((o) =>
          o.value === "ungraded"
            ? { ...o, label: <span className="text-subtle">Not graded yet</span>, text: "Not graded yet" }
            : {
                ...o,
                label: <span title={EMULATION_GRADE_META[o.value as EmulationGrade].description}>{EMULATION_GRADE_META[o.value as EmulationGrade].label}</span>,
                text: EMULATION_GRADE_META[o.value as EmulationGrade].label,
              },
        ),
      research: countBy(basePool.map((r) => d(r).research)).map((o) => {
        const c = researchCategory(o.value);
        return { ...o, label: <span title={c?.label}>{c?.short ?? o.value}{c?.scope === "bas" ? <span className="text-subtle"> · BAS</span> : null}</span>, text: c?.short ?? o.value };
      }),
      tags: countBy(basePool.map((r) => r.tags ?? [])),
      withIocs: basePool.filter((r) => (r.iocCount || 0) > 0).length,
      withEmulation: basePool.filter((r) => d(r).emulation).length,
      needsReview: basePool.filter((r) => r.needsReview).length,
    };
  }, [basePool, d]);

  const windowDays = PUBLISHED_WINDOWS.find((w) => w.value === publishedWindow)?.days;
  // Start of the window at UTC midnight, so the filter is stable through the day.
  const windowStart = windowDays ? Date.parse(`${new Date(Date.now() - windowDays * 86_400_000).toISOString().slice(0, 10)}T00:00:00Z`) : null;
  const fromTs = publishedWindow === "custom" ? (dateFrom ? Date.parse(`${dateFrom}T00:00:00Z`) : null) : windowStart;
  const toTs = publishedWindow === "custom" && dateTo ? Date.parse(`${dateTo}T23:59:59Z`) : null;

  // Reports per publication window over the current pool, for the Published facet.
  const publishedCounts = useMemo(() => {
    const counts: Record<Exclude<PublishedWindow, "custom">, number> & { undated: number } = { any: basePool.length, "7d": 0, "30d": 0, "90d": 0, "365d": 0, undated: 0 };
    const today = Date.parse(`${new Date().toISOString().slice(0, 10)}T00:00:00Z`);
    for (const r of basePool) {
      const t = d(r).published;
      if (!t) {
        counts.undated++;
        continue;
      }
      for (const w of PUBLISHED_WINDOWS) {
        if (w.days && w.value !== "custom" && w.value !== "any" && t >= today - w.days * 86_400_000) counts[w.value]++;
      }
    }
    return counts;
  }, [basePool, d]);

  const filteredReports = useMemo(() => {
    if (searchParams.selected) return targetReport ? [targetReport] : [];

    const anyMatch = (sel: string[], vals: string[]) =>
      sel.length === 0 || sel.some((s) => vals.some((v) => v.toLowerCase() === s.toLowerCase()));

    const list = basePool.filter((r) => {
      const x = d(r);
      if (!anyMatch(selDocTypes, x.types)) return false;
      if (!anyMatch(selTiers, [x.tier ? String(x.tier) : "unrated"])) return false;
      if (!anyMatch(selPublishers, [x.publisher])) return false;
      if (!anyMatch(selActors, x.actors)) return false;
      if (!anyMatch(selMalware, x.malware)) return false;
      if (!anyMatch(selTactics, x.tactics)) return false;
      if (!anyMatch(selTags, r.tags ?? [])) return false;
      if (!anyMatch(selResearch, x.research)) return false;
      if (!anyMatch(selEmulation, [x.grade])) return false;
      if (fromTs !== null && (!x.published || x.published < fromTs)) return false;
      if (toTs !== null && (!x.published || x.published > toTs)) return false;
      if (minQuality > 0 && r.qualityScore < minQuality) return false;
      if (onlyWithIocs && (r.iocCount || 0) === 0) return false;
      if (onlyWithEmulation && !x.emulation) return false;
      if (onlyNeedsReview && !r.needsReview) return false;
      return true;
    });

    const cmp = (a: ReportListItem, b: ReportListItem) => {
      switch (orderBy) {
        case "relevance":
          return (searchRank.get(a.id) ?? Infinity) - (searchRank.get(b.id) ?? Infinity) || dateValue(b.ingestedAt) - dateValue(a.ingestedAt);
        case "published":
          // Undated reports (0) sort last; ingest time orders reports published the same day.
          return d(b).published - d(a).published || dateValue(b.ingestedAt) - dateValue(a.ingestedAt);
        case "emulation":
          return gradeRank(b) - gradeRank(a) || (b.emulation?.score ?? 0) - (a.emulation?.score ?? 0) || d(b).published - d(a).published;
        case "quality":
          return b.qualityScore - a.qualityScore;
        case "iocs":
          return (b.iocCount || 0) - (a.iocCount || 0);
        case "techniques":
          return d(b).techniques.length - d(a).techniques.length;
        case "words":
          return (b.wordCount || 0) - (a.wordCount || 0);
        default:
          return dateValue(b.ingestedAt) - dateValue(a.ingestedAt);
      }
    };

    // Keep the highlighted report visible even when filters would exclude it.
    if (targetReport && !list.some((r) => r.id === targetReport.id)) list.push(targetReport);
    return list.sort(cmp);
  }, [
    basePool,
    searchParams.selected,
    targetReport,
    selDocTypes,
    selTiers,
    selPublishers,
    selActors,
    selMalware,
    selTactics,
    selTags,
    selResearch,
    selEmulation,
    fromTs,
    toTs,
    minQuality,
    onlyWithIocs,
    onlyWithEmulation,
    onlyNeedsReview,
    orderBy,
    searchRank,
    d,
  ]);

  const sortedReports = useMemo(() => {
    if (!colSort || view !== "table") return filteredReports;
    const cmp = compareReports(colSort.key);
    const list = [...filteredReports].sort(cmp);
    return colSort.desc ? list.reverse() : list;
  }, [filteredReports, colSort, view]);

  const onSort = useCallback((key: ReportSortKey) => {
    setColSort((prev) => (prev?.key === key ? { key, desc: !prev.desc } : { key, desc: !TEXT_SORTS.includes(key) }));
  }, []);

  const filterChips: Array<{ label: string; clear: () => void }> = [
    ...selDocTypes.map((v) => ({ label: DOC_TYPE_META[v as DocType]?.label ?? v, clear: () => setSelDocTypes((s) => s.filter((x) => x !== v)) })),
    ...selTiers.map((v) => ({
      label: v === "unrated" ? "Unrated source" : TIER_META[Number(v) as SourceTier].short,
      clear: () => setSelTiers((s) => s.filter((x) => x !== v)),
    })),
    ...selPublishers.map((v) => ({ label: `Publisher: ${v}`, clear: () => setSelPublishers((s) => s.filter((x) => x !== v)) })),
    ...selActors.map((v) => ({ label: `Actor: ${v}`, clear: () => setSelActors((s) => s.filter((x) => x !== v)) })),
    ...selMalware.map((v) => ({ label: `Malware: ${v}`, clear: () => setSelMalware((s) => s.filter((x) => x !== v)) })),
    ...selTactics.map((v) => ({ label: `Tactic: ${v}`, clear: () => setSelTactics((s) => s.filter((x) => x !== v)) })),
    ...selTags.map((v) => ({ label: `Tag: ${v}`, clear: () => setSelTags((s) => s.filter((x) => x !== v)) })),
    ...selEmulation.map((v) => ({
      label: `Emulation: ${v === "ungraded" ? "not graded" : EMULATION_GRADE_META[v as EmulationGrade].label}`,
      clear: () => setSelEmulation((s) => s.filter((x) => x !== v)),
    })),
    ...selResearch.map((v) => ({ label: `Research: ${researchCategory(v)?.short ?? v}`, clear: () => setSelResearch((s) => s.filter((x) => x !== v)) })),
    ...(windowDays ? [{ label: `Published: ${PUBLISHED_WINDOWS.find((w) => w.value === publishedWindow)?.label.toLowerCase()}`, clear: () => setPublishedWindow("any") }] : []),
    ...(publishedWindow === "custom" && dateFrom ? [{ label: `From ${dateFrom}`, clear: () => setDateFrom("") }] : []),
    ...(publishedWindow === "custom" && dateTo ? [{ label: `To ${dateTo}`, clear: () => setDateTo("") }] : []),
    ...(minQuality > 0 ? [{ label: `Quality ≥ ${Math.round(minQuality * 100)}%`, clear: () => setMinQuality(0) }] : []),
    ...(onlyWithIocs ? [{ label: "Has IOCs", clear: () => setOnlyWithIocs(false) }] : []),
    ...(onlyWithEmulation ? [{ label: "Has emulation", clear: () => setOnlyWithEmulation(false) }] : []),
    ...(onlyNeedsReview ? [{ label: "Needs review", clear: () => setOnlyNeedsReview(false) }] : []),
    ...(showRejected ? [{ label: `Hidden (${rejectedCount})`, clear: () => setShowRejected(false) }] : []),
  ];
  const activeFiltersCount = filterChips.length;

  useEffect(() => {
    setCurrentPage(1);
  }, [
    q,
    docTab,
    selDocTypes,
    selTiers,
    selPublishers,
    selActors,
    selMalware,
    selTactics,
    selTags,
    selResearch,
    selEmulation,
    publishedWindow,
    dateFrom,
    dateTo,
    minQuality,
    onlyWithIocs,
    onlyWithEmulation,
    onlyNeedsReview,
    showRejected,
    orderBy,
    colSort,
  ]);

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
      const el = document.getElementById(`report-${id}`) || document.querySelector(`[data-report-id="${CSS.escape(id)}"]`);
      if (el) {
        (el.closest("tr") ?? el).scrollIntoView({ behavior: "smooth", block: "center" });
      } else if (attempts < 40) {
        setTimeout(tryScroll, 80);
      }
    };
    const timer = setTimeout(tryScroll, 120);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [targetHighlightId, targetReport, currentPage, view]);

  const pagedReports = useMemo(
    () => sortedReports.slice((currentPage - 1) * numericPageSize, currentPage * numericPageSize),
    [sortedReports, currentPage, numericPageSize],
  );

  const handlePageChange = (newPage: number) => {
    setCurrentPage(newPage);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const resetFilters = () => {
    setSelDocTypes([]);
    setSelTiers([]);
    setSelPublishers([]);
    setSelActors([]);
    setSelMalware([]);
    setSelTactics([]);
    setSelTags([]);
    setSelResearch([]);
    setSelEmulation([]);
    setPublishedWindow("any");
    setDateFrom("");
    setDateTo("");
    setMinQuality(0);
    setOnlyWithIocs(false);
    setOnlyWithEmulation(false);
    setOnlyNeedsReview(false);
    setShowRejected(false);
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
      hide: (r: ReportListItem) => void changeVisibility([r.id], "hide"),
      restore: (r: ReportListItem) => void changeVisibility([r.id], "restore"),
    }),
    [openReport, openPdfModal, handleDownload, changeVisibility],
  );

  // ---------------------------------------------------------------- KPIs
  const kpis = useMemo<LibraryKpi[]>(() => {
    // Each tile counts exactly what its tab lists (same document types, same reports).
    const typeCount = (tabId: string) => tabCounts[tabId] ?? 0;
    let atomic: number | null = coverage?.atomicTechniques ?? null;
    let atomicHint: string = "Coverage index";
    if (atomic === null && emulationOptions) {
      atomic = libraryTechniques.filter((t) => (emulationOptions[t] ?? []).some((o) => o.kind === "atomic_test")).length;
      atomicHint = `of ${libraryTechniques.length} library techniques`;
    }
    if (atomic === null) atomicHint = hasEmulationOptionsApi ? "Checking Atomic Red Team…" : "Atomic tests not synced yet";
    return [
      {
        id: "reports",
        label: "Reports",
        value: acceptedReports.length,
        kind: "source",
        icon: FileText,
        hint: rejectedCount > 0 ? `${rejectedCount} hidden` : "In the library",
        onClick: () => setDocTab("ALL"),
        active: docTab === "ALL",
      },
      {
        id: "advisories",
        label: "Advisories",
        value: typeCount("advisory"),
        kind: "advisory",
        icon: Megaphone,
        hint: "Threat advisories",
        onClick: () => setDocTab("advisory"),
        active: docTab === "advisory",
      },
      {
        id: "emulation",
        label: "Emulation plans",
        value: typeCount("emulation"),
        kind: "emulation",
        icon: Swords,
        hint: "Full & micro plans",
        onClick: () => setDocTab("emulation"),
        active: docTab === "emulation",
      },
      {
        id: "flows",
        label: "Attack flows",
        value: typeCount("flow"),
        kind: "flow",
        icon: GitBranch,
        hint: "CTID Attack Flow",
        onClick: () => setDocTab("flow"),
        active: docTab === "flow",
      },
      {
        id: "techniques",
        label: "Techniques",
        value: libraryTechniques.length,
        kind: "technique",
        icon: Layers,
        hint: "Distinct ATT&CK IDs",
      },
      {
        id: "atomic",
        label: "Atomic-covered",
        value: atomic,
        kind: "emulation",
        icon: FlaskConical,
        hint: atomicHint,
      },
    ];
  }, [coverage, acceptedReports, rejectedCount, tabCounts, emulationOptions, libraryTechniques, docTab]);

  // ---------------------------------------------------------------- sidebar
  const sidebar = (
    <FacetPanel activeCount={activeFiltersCount} onClearAll={resetFilters}>
      <FacetGroup
        title="Emulation value"
        options={facets.emulation}
        selected={selEmulation}
        onToggle={(v) => setSelEmulation((s) => toggle(s, v))}
        onClear={() => setSelEmulation([])}
      />
      <FacetGroup
        title="Document type"
        options={facets.docTypes}
        selected={selDocTypes}
        onToggle={(v) => setSelDocTypes((s) => toggle(s, v))}
        onClear={() => setSelDocTypes([])}
      />
      <FacetGroup
        title="Research type"
        options={facets.research}
        selected={selResearch}
        onToggle={(v) => setSelResearch((s) => toggle(s, v))}
        onClear={() => setSelResearch([])}
        emptyText={labelQuery.isFetching ? "Labelling reports…" : "No labelled reports yet"}
      />
      <FacetGroup
        title="Source tier"
        options={facets.tiers}
        selected={selTiers}
        onToggle={(v) => setSelTiers((s) => toggle(s, v))}
        onClear={() => setSelTiers([])}
      />
      <FacetGroup
        title="Publisher"
        options={facets.publishers}
        selected={selPublishers}
        onToggle={(v) => setSelPublishers((s) => toggle(s, v))}
        onClear={() => setSelPublishers([])}
      />
      <FacetGroup
        title="Threat actor"
        options={facets.actors}
        selected={selActors}
        onToggle={(v) => setSelActors((s) => toggle(s, v))}
        onClear={() => setSelActors([])}
        emptyText="No attributed actors"
      />
      <FacetGroup
        title="Malware & tools"
        options={facets.malware}
        selected={selMalware}
        onToggle={(v) => setSelMalware((s) => toggle(s, v))}
        onClear={() => setSelMalware([])}
        emptyText="No named malware"
      />
      <FacetGroup
        title="ATT&CK tactic"
        options={facets.tactics}
        selected={selTactics}
        onToggle={(v) => setSelTactics((s) => toggle(s, v))}
        onClear={() => setSelTactics([])}
        defaultOpen={false}
      />
      {facets.tags.length > 0 && (
        <FacetGroup
          title="Tag"
          options={facets.tags}
          selected={selTags}
          onToggle={(v) => setSelTags((s) => toggle(s, v))}
          onClear={() => setSelTags([])}
          defaultOpen={selTags.length > 0}
        />
      )}
      <section className="border-b border-border px-4 py-3.5" aria-labelledby="facet-published">
        <div className="mb-2 flex items-center justify-between">
          <h3 id="facet-published" className="text-sm font-medium text-fg">
            Published
          </h3>
          {publishedWindow !== "any" && (
            <button
              type="button"
              onClick={() => {
                setPublishedWindow("any");
                setDateFrom("");
                setDateTo("");
              }}
              className="text-xs text-muted hover:text-fg"
            >
              Any time
            </button>
          )}
        </div>
        <div role="radiogroup" aria-labelledby="facet-published" className="space-y-0.5">
          {PUBLISHED_WINDOWS.map((w) => {
            const checked = publishedWindow === w.value;
            const count = w.value === "custom" ? null : publishedCounts[w.value];
            return (
              <button
                key={w.value}
                type="button"
                role="radio"
                aria-checked={checked}
                onClick={() => setPublishedWindow(w.value)}
                className={cn(
                  "flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left text-sm transition-colors hover:bg-bg-subtle",
                  checked ? "text-fg" : "text-muted",
                )}
              >
                <span
                  aria-hidden
                  className={cn(
                    "grid size-3.5 shrink-0 place-items-center rounded-full border",
                    checked ? "border-[var(--color-primary)]" : "border-border-strong",
                  )}
                >
                  {checked && <span className="size-1.5 rounded-full bg-[var(--color-primary)]" />}
                </span>
                <span className="flex-1">{w.label}</span>
                {count !== null && <span className="text-xs tabular-nums text-subtle">{count}</span>}
              </button>
            );
          })}
        </div>
        {publishedWindow === "custom" && (
          <div className="mt-2 grid grid-cols-2 gap-2 px-2">
            <label className="space-y-1">
              <span className="text-[11px] text-subtle">From</span>
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                className="h-8 w-full rounded-md border border-border bg-bg-elevated px-2 text-xs text-fg [color-scheme:inherit]"
              />
            </label>
            <label className="space-y-1">
              <span className="text-[11px] text-subtle">To</span>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                className="h-8 w-full rounded-md border border-border bg-bg-elevated px-2 text-xs text-fg"
              />
            </label>
          </div>
        )}
        {publishedCounts.undated > 0 && (
          <p className="mt-2 px-2 text-[11px] leading-relaxed text-subtle">
            {publishedCounts.undated} {publishedCounts.undated === 1 ? "report gives" : "reports give"} no publication date: listed last, and left out when a
            window is chosen.
          </p>
        )}
      </section>
      <section className="space-y-0.5 px-2.5 py-3">
        <FacetToggle label="Has IOCs" checked={onlyWithIocs} onChange={setOnlyWithIocs} count={facets.withIocs} />
        <FacetToggle
          label="Has emulation content"
          hint="Plans, flows, atomics or drafted procedures"
          checked={onlyWithEmulation}
          onChange={setOnlyWithEmulation}
          count={facets.withEmulation}
        />
        <FacetToggle
          label="Needs review"
          hint="The AI review was unsure, or judged a report not useful while it carries technical evidence"
          checked={onlyNeedsReview}
          onChange={setOnlyNeedsReview}
          count={facets.needsReview}
        />
        <FacetToggle
          label="Hidden reports only"
          hint="Unrelated pages the library gate, the AI audit or an analyst hid"
          checked={showRejected}
          onChange={setShowRejected}
          count={rejectedCount}
        />
        <label className="flex items-center justify-between gap-3 px-1.5 pt-2 text-sm text-muted">
          Minimum quality
          <Select size="sm" value={String(minQuality)} onValueChange={(v) => setMinQuality(parseFloat(v))} className="px-2.5 text-xs">
            <option value={0}>Any</option>
            <option value={0.6}>≥ 60%</option>
            <option value={0.8}>≥ 80%</option>
          </Select>
        </label>
      </section>
    </FacetPanel>
  );

  const emptyState = isLoading ? (
    <div className="flex justify-center py-10">
      <ActivitySpinner size="lg" className="text-accent" />
    </div>
  ) : reportsError && allReports.length === 0 ? (
    <EmptyState
      icon={AlertTriangle}
      title="The library could not be loaded"
      description={reportsError instanceof Error ? reportsError.message : "The report store did not answer."}
      action={
        <ActionButton icon={RefreshCw} onClick={() => void refetchReports()}>
          Try again
        </ActionButton>
      }
    />
  ) : (
    <EmptyState
      icon={SearchX}
      title={allReports.length === 0 ? "The library is empty" : "No reports match these filters"}
      description={
        allReports.length === 0
          ? "Ingest a report URL or sync a structured source to start building the library."
          : "Try a broader search, another document type, or remove some filters."
      }
      action={
        allReports.length === 0 ? (
          <ActionButton variant="primary" icon={Plus} to="/ingest">
            Ingest report
          </ActionButton>
        ) : activeFiltersCount > 0 || q || searchParams.selected || docTab !== "ALL" ? (
          <ActionButton
            onClick={() => {
              resetFilters();
              setDocTab("ALL");
            }}
          >
            Reset filters
          </ActionButton>
        ) : undefined
      }
    />
  );

  return (
    <AppShell>
      <div className="mx-auto w-full max-w-[1480px]">
        <PageHeader
          title="Library"
          description="Threat reports, advisories, DFIR cases, emulation plans, attack flows and ATT&CK knowledge — with evidence, IOCs and emulation coverage."
          actions={
            <>
              <ActionButton
                icon={Sparkles}
                onClick={() => void handleRunAiReview()}
                title={
                  reviewProgress
                    ? "Stop after the current report"
                    : "Analyse the newest-published reports with AI: summary, indicators, attack chain, adversary and a usefulness review. Nothing is deleted; uncertain reports are flagged for review."
                }
              >
                {reviewProgress ? `Analysing ${reviewProgress.done + 1 > reviewProgress.total ? reviewProgress.total : reviewProgress.done + 1} of ${reviewProgress.total} · Stop` : "Analyse with AI"}
              </ActionButton>
              <ActionButton variant="primary" icon={Plus} to="/ingest">
                Ingest report
              </ActionButton>
            </>
          }
        />

        <DataSourceNotice className="mb-4" />
        {gateQuery.data && gateQuery.data.newlyHidden.length > 0 && !gateNoticeDismissed && (
          <div role="status" className="mb-4 flex flex-col gap-3 rounded-xl border border-border bg-bg-card px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 items-start gap-3">
              <EyeOff className="mt-0.5 size-4 shrink-0 text-muted" strokeWidth={1.75} />
              <p className="text-sm text-muted">
                <span className="font-medium text-fg">
                  Hid {gateQuery.data.newlyHidden.length} report{gateQuery.data.newlyHidden.length === 1 ? "" : "s"} that {gateQuery.data.newlyHidden.length === 1 ? "is" : "are"} not technical threat intelligence
                </span>{" "}
                (product and marketing pages, strategy pieces, news without technical detail, listing pages, empty stubs). Nothing was deleted: each
                one shows why it was hidden, and Restore brings it back for good.
              </p>
            </div>
            <div className="flex shrink-0 gap-2">
              <ActionButton icon={EyeOff} onClick={() => setShowRejected(true)}>
                Review hidden
              </ActionButton>
              <ActionButton variant="ghost" icon={X} onClick={() => setGateNoticeDismissed(true)}>
                Dismiss
              </ActionButton>
            </div>
          </div>
        )}

        <LibraryKpiStrip items={kpis} />

        <div className="mb-5">
          <SegmentedTabs
            ariaLabel="Document type"
            items={DOC_TABS.map((t) => ({ value: t.id, label: t.label, count: tabCounts[t.id] ?? 0 }))}
            value={docTab}
            onChange={setDocTab}
          />
        </div>

        <div className="grid gap-6 xl:grid-cols-[280px_minmax(0,1fr)]">
          <aside className="hidden min-w-0 xl:block">
            <div className="sticky top-6 max-h-[calc(100vh-3rem)] overflow-y-auto rounded-xl">{sidebar}</div>
          </aside>

          <div className="@container min-w-0">
            {/* Results toolbar. Breakpoints follow the width of this column (container queries), not
                the window: the filter sidebar takes 280px at xl, so the window size says little. */}
            <div className="mb-3 flex flex-col gap-2 @min-[40rem]:flex-row @min-[40rem]:items-center @min-[40rem]:justify-between">
              <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
                <div className="relative w-full @lg:w-auto @lg:min-w-48 @lg:max-w-80 @lg:flex-1">
                  <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" />
                  <input
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                    placeholder="Search title, actor, malware, CVE, technique, hash…"
                    aria-label="Search library"
                    className="h-9 w-full rounded-lg border border-border bg-bg-elevated pl-9 pr-8 text-sm text-fg placeholder:text-subtle focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)]"
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
                    "inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle xl:hidden",
                    showFilters && "bg-bg-subtle",
                  )}
                >
                  <SlidersHorizontal className="size-4" strokeWidth={1.75} />
                  Filters
                  {activeFiltersCount > 0 && (
                    <span className="rounded bg-[var(--color-primary)] px-1.5 text-[11px] font-medium text-[var(--color-primary-fg)] tabular-nums">
                      {activeFiltersCount}
                    </span>
                  )}
                </button>
                <span className="whitespace-nowrap text-sm text-muted">
                  <span className="tabular-nums text-fg">{sortedReports.length}</span> {sortedReports.length === 1 ? "result" : "results"}
                  {isDeepSearchActive && (
                    <span className="text-subtle" title="Ranked by the hybrid search engine: aliases, technique names and field syntax are understood">
                      {" "}
                      · ranked{searchData?.interpreted.summary ? ` · ${searchData.interpreted.summary}` : ""}
                    </span>
                  )}
                </span>
              </div>
              <div className="flex shrink-0 flex-wrap items-center gap-2 @min-[40rem]:flex-nowrap">
                {showRejected && sortedReports.length > 0 && (
                  <ActionButton
                    icon={Undo2}
                    onClick={() => void changeVisibility(sortedReports.slice(0, 500).map((r) => r.id), "restore")}
                    title="Put these reports back in the library; the rules will not hide them again"
                  >
                    Restore {Math.min(sortedReports.length, 500)} shown
                  </ActionButton>
                )}
                <label className="flex shrink-0 items-center gap-2 text-sm text-muted">
                  <span className="hidden @xl:inline">Sort</span>
                  <Select
                    value={orderBy}
                    onValueChange={(v) => {
                      setOrderBy(v as OrderBy);
                      setColSort(null);
                    }}
                    aria-label="Sort results"
                    className="w-44 shrink-0 px-2.5"
                  >
                    {isDeepSearchActive && <option value="relevance">Relevance</option>}
                    <option value="newest">Newest ingested</option>
                    <option value="emulation">Emulation value</option>
                    <option value="published">Newest published</option>
                    <option value="quality">Quality score</option>
                    <option value="techniques">Most techniques</option>
                    <option value="iocs">Most IOCs</option>
                    <option value="words">Longest</option>
                  </Select>
                </label>
                <SegmentedTabs<ViewMode>
                  ariaLabel="Result view"
                  size="sm"
                  items={[
                    { value: "cards", label: <span className="@max-4xl:sr-only">Cards</span>, title: "Cards", icon: LayoutGrid },
                    { value: "list", label: <span className="@max-4xl:sr-only">List</span>, title: "List", icon: List },
                    { value: "table", label: <span className="@max-4xl:sr-only">Table</span>, title: "Table", icon: Table2 },
                  ]}
                  value={view}
                  onChange={setView}
                />
              </div>
            </div>

            {showFilters && <div className="mb-4 xl:hidden">{sidebar}</div>}

            {filterChips.length > 0 && (
              <div className="mb-3 flex flex-wrap items-center gap-2">
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
              <div className="mb-3 flex flex-col gap-3 rounded-xl border border-border bg-bg-card px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 items-center gap-3">
                  <FileText className="size-4 shrink-0 text-[var(--color-primary)]" strokeWidth={1.75} />
                  <p className="min-w-0 truncate text-sm text-muted">
                    Showing one report: <span className="text-fg">{targetReport ? targetReport.title : searchParams.selected}</span>
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

            {isLoading && allReports.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-bg-card py-16 text-muted">
                <ActivitySpinner size="lg" className="mb-2 text-accent" />
                <p className="text-sm">Loading the library…</p>
              </div>
            ) : view === "table" ? (
              <ReportTable
                rows={pagedReports}
                sort={colSort}
                onSort={onSort}
                actions={rowActions}
                isHighlighted={isHighlighted}
                showSnippets={isDeepSearchActive}
                empty={emptyState}
              />
            ) : pagedReports.length === 0 ? (
              <div className="rounded-xl border border-border bg-bg-card">{emptyState}</div>
            ) : view === "list" ? (
              <ul className="divide-y divide-border overflow-hidden rounded-xl border border-border bg-bg-card">
                {pagedReports.map((r) => (
                  <ReportListRow key={r.id} r={r} actions={rowActions} highlighted={isHighlighted(r)} />
                ))}
              </ul>
            ) : (
              <div className="space-y-3">
                {pagedReports.map((r) => (
                  <ReportFeedCard key={r.id} r={r} actions={rowActions} highlighted={isHighlighted(r)} showSnippet={isDeepSearchActive} />
                ))}
              </div>
            )}

            {sortedReports.length > 0 && (
              <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <label className="flex items-center gap-2 text-sm text-muted">
                  Per page
                  <Select
                    size="sm"
                    value={String(pageSize)}
                    onValueChange={(v) => {
                      setPageSize(v === "all" ? "all" : (Number(v) as PageSize));
                      setCurrentPage(1);
                    }}
                  >
                    {PAGE_SIZES.map((s) => (
                      <option key={s} value={String(s)}>
                        {s === "all" ? "All" : s}
                      </option>
                    ))}
                  </Select>
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
            )}
          </div>
        </div>
      </div>

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
