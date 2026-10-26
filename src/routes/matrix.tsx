import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  Columns3,
  ExternalLink,
  Eye,
  FileText,
  Filter,
  Grid3X3,
  Info,
  Layers,
  LayoutGrid,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  X,
  Zap,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { StatusChip } from "@/components/ui/primitives";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { getReportPdf, listReports } from "@/lib/aie/server";
import {
  mapReportsToMitreMatrix,
  type MappedSubTechnique,
  type MappedTactic,
  type MappedTechnique,
} from "@/lib/aie/mitre-matrix";
import { cn } from "@/lib/cn";
import { toSafeSrcDoc } from "@/lib/aie/safe-srcdoc";
import { ActionButton, PageHeader, SegmentedTabs } from "@/components/layout/page";

export const Route = createFileRoute("/matrix")({
  // ?technique=T1003.001 opens that technique (deep links from search, actor and purple-path pages).
  validateSearch: (search: Record<string, unknown>): { technique?: string } => {
    const t = typeof search.technique === "string" ? search.technique.trim().toUpperCase() : "";
    return /^T\d{4}(\.\d{3})?$/.test(t) ? { technique: t } : {};
  },
  component: MatrixPage,
});

type LayoutMode = "side" | "flat" | "mini";

function SpinnerIcon({ className }: { className?: string }) {
  return <ActivitySpinner size="xs" className={cn("text-accent", className)} />;
}

const PLATFORMS = ["All", "Windows", "Linux", "macOS", "Cloud", "Network", "Identity", "PRE"] as const;

const THREAT_ACTORS = [
  "All Actors",
  "Volt Typhoon",
  "Scattered Spider",
  "Lazarus Group",
  "Midnight Blizzard",
  "Sandworm",
  "LockBit",
  "Akira",
  "FIN7",
  "MuddyWater",
  "Mustang Panda",
] as const;

const OFFENSIVE_TOOLS = [
  "All Tools",
  "Cobalt Strike",
  "Mimikatz",
  "Chisel",
  "PlugX",
  "Masscan",
  "Nmap",
  "PowerShell",
] as const;

const TACTIC_OPTIONS = [
  "All 15 Tactics",
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Stealth",
  "Defense Impairment",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

/**
 * MITRE ATT&CK Matrix Theme Tokens
 * Fully integrated with platform CSS variables (--color-bg, --color-accent, etc.)
 */
const MATRIX_STYLES = {
  headerBg: "bg-bg-elevated",
  headerBorder: "border-border",
  cardBg: "bg-bg-elevated",
  cardHover: "hover:bg-bg-subtle",
  cardBorder: "border-border",
  activeBorder: "border-border-strong",
  techniqueText: "text-fg hover:underline",
  indicatorActive: "bg-accent",
  indicatorInactive: "bg-transparent",
};

function MatrixPage() {
  const navigate = useNavigate();

  // View & Layout State
  const [layoutMode, setLayoutMode] = useState<LayoutMode>("side");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedPlatform, setSelectedPlatform] = useState<string>("All");
  const [selectedActor, setSelectedActor] = useState<string>("All Actors");
  const [selectedTool, setSelectedTool] = useState<string>("All Tools");
  const [selectedTactic, setSelectedTactic] = useState<string>("All 15 Tactics");
  const [coverageStatus, setCoverageStatus] = useState<"all" | "covered" | "uncovered">("all");
  const [showSubTechniques, setShowSubTechniques] = useState(false);
  const [expandedTechniqueIds, setExpandedTechniqueIds] = useState<Set<string>>(new Set());

  // Selected Technique / Modal State
  const [selectedTechnique, setSelectedTechnique] = useState<MappedTechnique | null>(null);
  const [selectedSubTech, setSelectedSubTech] = useState<MappedSubTechnique | null>(null);
  const [previewReportId, setPreviewReportId] = useState<string | null>(null);
  // Reports shown in the technique drawer: the open sub-technique's own mapping, else the technique's.
  const drawerReports = (selectedSubTech ? selectedSubTech.mappedReports : selectedTechnique?.mappedReports) ?? [];

  // Fetch Central Intelligence Reports with 60s cache for fast 0ms navigation
  const { data: allReports = [], isFetching, refetch } = useQuery({
    // The 500 newest by publication date, shared with the Library's default view.
    queryKey: ["reports-all", "published"],
    queryFn: () => listReports({ data: { limit: 500, order: "published" } }),
    staleTime: 60_000,
    placeholderData: (previousData) => previousData,
  });

  // Fetch PDF Preview
  const { data: previewData, isLoading: isPreviewLoading } = useQuery({
    queryKey: ["report-pdf-matrix", previewReportId],
    queryFn: () => (previewReportId ? getReportPdf({ data: { id: previewReportId } }) : null),
    enabled: Boolean(previewReportId),
    staleTime: 60_000,
  });

  // Build MITRE ATT&CK Tactics & Techniques Matrix
  const mappedTactics: MappedTactic[] = useMemo(() => {
    return mapReportsToMitreMatrix(allReports);
  }, [allReports]);

  // Deep link: open the requested technique once the matrix is built (only once per id).
  const { technique: linkedTechnique } = Route.useSearch();
  const openedLink = useRef<string | null>(null);
  useEffect(() => {
    if (!linkedTechnique || openedLink.current === linkedTechnique || mappedTactics.length === 0) return;
    const parentId = linkedTechnique.split(".")[0];
    for (const tactic of mappedTactics) {
      const tech = tactic.techniques.find((t) => t.id === parentId);
      if (!tech) continue;
      openedLink.current = linkedTechnique;
      setSelectedTechnique(tech);
      setSelectedSubTech(linkedTechnique.includes(".") ? tech.subTechniques.find((st) => st.id === linkedTechnique) ?? null : null);
      return;
    }
  }, [linkedTechnique, mappedTactics]);

  // Keep an open drawer in sync with the rebuilt matrix (reports load or refetch after it opened).
  useEffect(() => {
    if (!selectedTechnique) return;
    for (const tactic of mappedTactics) {
      const fresh = tactic.techniques.find((t) => t.id === selectedTechnique.id && t.tacticId === selectedTechnique.tacticId);
      if (!fresh) continue;
      if (fresh !== selectedTechnique) setSelectedTechnique(fresh);
      if (selectedSubTech) {
        const sub = fresh.subTechniques.find((st) => st.id === selectedSubTech.id) ?? null;
        if (sub !== selectedSubTech) setSelectedSubTech(sub);
      }
      return;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-sync only when the matrix is rebuilt
  }, [mappedTactics]);

  // Aggregate Metrics
  const stats = useMemo(() => {
    let totalTechniques = 0;
    let totalSubTechniques = 0;
    let coveredTechniques = 0;
    let totalMappedReports = 0;

    for (const tactic of mappedTactics) {
      totalTechniques += tactic.totalTechniques;
      totalSubTechniques += tactic.totalSubTechniques;
      coveredTechniques += tactic.coveredTechniques;
      totalMappedReports += tactic.totalMappedReports;
    }

    const coveragePct = totalTechniques > 0 ? Math.round((coveredTechniques / totalTechniques) * 100) : 0;

    return {
      tacticsCount: mappedTactics.length,
      totalTechniques,
      totalSubTechniques,
      coveredTechniques,
      coveragePct,
      totalMappedReports,
    };
  }, [mappedTactics]);

  // Filter Tactics by search, platform, actor, tool, tactic, and coverage
  const filteredTactics: MappedTactic[] = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();

    let tacticsList = Array.isArray(mappedTactics) ? mappedTactics : [];

    // Tactic phase filter
    if (selectedTactic !== "All 15 Tactics") {
      tacticsList = tacticsList.filter(
        (t) =>
          t.name.toLowerCase() === selectedTactic.toLowerCase() ||
          t.shortName.toLowerCase() === selectedTactic.toLowerCase(),
      );
    }

    return tacticsList.map((tactic) => {
      let techniques = Array.isArray(tactic?.techniques) ? tactic.techniques : [];

      // Platform filter
      if (selectedPlatform !== "All") {
        techniques = techniques.filter(
          (t) =>
            (Array.isArray(t?.platforms) &&
              t.platforms.some((p) => p.toLowerCase().includes(selectedPlatform.toLowerCase()))) ||
            (Array.isArray(t?.subTechniques) &&
              t.subTechniques.some((st) =>
                Array.isArray(st?.platforms) &&
                st.platforms.some((p) => p.toLowerCase().includes(selectedPlatform.toLowerCase())),
              )),
        );
      }

      // Threat Actor filter
      if (selectedActor !== "All Actors") {
        const aLow = selectedActor.toLowerCase();
        techniques = techniques.filter(
          (t) =>
            (Array.isArray(t?.threatActors) &&
              t.threatActors.some((a) => a.toLowerCase().includes(aLow))) ||
            (Array.isArray(t?.detectionKeywords) &&
              t.detectionKeywords.some((kw) => kw.toLowerCase().includes(aLow))) ||
            (Array.isArray(t?.mappedReports) &&
              t.mappedReports.some((r) =>
                `${r.title || ""} ${r.excerpt || ""}`.toLowerCase().includes(aLow),
              )),
        );
      }

      // Offensive Tool / Malware filter
      if (selectedTool !== "All Tools") {
        const mLow = selectedTool.toLowerCase();
        techniques = techniques.filter(
          (t) =>
            (Array.isArray(t?.malware) &&
              t.malware.some((m) => m.toLowerCase().includes(mLow))) ||
            (Array.isArray(t?.detectionKeywords) &&
              t.detectionKeywords.some((kw) => kw.toLowerCase().includes(mLow))) ||
            (Array.isArray(t?.mappedReports) &&
              t.mappedReports.some((r) =>
                `${r.title || ""} ${r.excerpt || ""}`.toLowerCase().includes(mLow),
              )),
        );
      }

      // Coverage Status filter (all, covered, uncovered)
      if (coverageStatus === "covered") {
        techniques = techniques.filter((t) => (t?.coverageCount ?? 0) > 0);
      } else if (coverageStatus === "uncovered") {
        techniques = techniques.filter((t) => (t?.coverageCount ?? 0) === 0);
      }

      // Search query filter
      if (q) {
        techniques = techniques.filter(
          (t) =>
            (typeof t?.id === "string" && t.id.toLowerCase().includes(q)) ||
            (typeof t?.name === "string" && t.name.toLowerCase().includes(q)) ||
            (typeof t?.description === "string" && t.description.toLowerCase().includes(q)) ||
            (Array.isArray(t?.subTechniques) &&
              t.subTechniques.some(
                (st) =>
                  (typeof st?.id === "string" && st.id.toLowerCase().includes(q)) ||
                  (typeof st?.name === "string" && st.name.toLowerCase().includes(q)),
              )) ||
            (Array.isArray(t?.mappedReports) &&
              t.mappedReports.some(
                (r) =>
                  (typeof r?.title === "string" && r.title.toLowerCase().includes(q)) ||
                  (typeof r?.publisher === "string" && r.publisher.toLowerCase().includes(q)),
              )),
        );
      }

      return {
        ...tactic,
        techniques,
        coveredTechniques: techniques.filter((t) => (t?.coverageCount ?? 0) > 0).length,
      };
    });
  }, [mappedTactics, selectedPlatform, selectedActor, selectedTool, selectedTactic, coverageStatus, searchQuery]);

  // Aggregate count of currently visible techniques
  const totalVisibleTechniques = useMemo(() => {
    return filteredTactics.reduce((acc, t) => acc + (t?.techniques?.length ?? 0), 0);
  }, [filteredTactics]);

  const hasActiveFilters = Boolean(
    searchQuery ||
    selectedPlatform !== "All" ||
    selectedActor !== "All Actors" ||
    selectedTool !== "All Tools" ||
    selectedTactic !== "All 15 Tactics" ||
    coverageStatus !== "all",
  );

  const resetAllFilters = () => {
    setSearchQuery("");
    setSelectedPlatform("All");
    setSelectedActor("All Actors");
    setSelectedTool("All Tools");
    setSelectedTactic("All 15 Tactics");
    setCoverageStatus("all");
  };

  // Toggle sub-techniques globally
  const handleToggleGlobalSubTechs = () => {
    if (showSubTechniques) {
      setExpandedTechniqueIds(new Set());
      setShowSubTechniques(false);
    } else {
      const allIds = new Set<string>();
      for (const tac of mappedTactics) {
        const techs = Array.isArray(tac?.techniques) ? tac.techniques : [];
        for (const tech of techs) {
          if (Array.isArray(tech?.subTechniques) && tech.subTechniques.length > 0) {
            allIds.add(tech.id);
          }
        }
      }
      setExpandedTechniqueIds(allIds);
      setShowSubTechniques(true);
    }
  };

  // Toggle single technique expand
  const toggleTechniqueExpand = (techId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedTechniqueIds((prev) => {
      const next = new Set(prev);
      if (next.has(techId)) {
        next.delete(techId);
      } else {
        next.add(techId);
      }
      return next;
    });
  };

  return (
    <AppShell>
      <PageHeader
        title="ATT&CK matrix"
        description="Official MITRE ATT&CK® Enterprise Matrix mapping across 15 tactical phases. Techniques with verified intelligence reports in your library are highlighted with direct links to full evidence."
        actions={
          <>
            <ActionButton
              variant="outline"
              icon={isFetching ? SpinnerIcon : RefreshCw}
              onClick={() => void refetch()}
              disabled={isFetching}
            >
              Sync intel ({stats.totalMappedReports})
            </ActionButton>
            <ActionButton variant="primary" icon={Zap} onClick={() => void navigate({ to: "/ingest" })}>
              Hunt new TTP
            </ActionButton>
          </>
        }
      />
      <div className="space-y-6">
        {/* ========================================================================= */}
        {/* CONTROLS BAR: SEARCH, TACTIC, ACTOR, TOOL, PLATFORM, COVERAGE, LAYOUT     */}
        {/* ========================================================================= */}
        <div className="space-y-3 rounded-xl border border-border bg-bg-card p-4">
          {/* Primary Controls Row: Search, Selectors, Toggles */}
          <div className="flex flex-1 flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative min-w-[200px] max-w-xs flex-1">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" strokeWidth={1.75} />
              <Input
                type="text"
                placeholder="Search ID, name, or report..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-9 rounded-lg border-border bg-bg-elevated pl-9 text-sm placeholder:text-subtle"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-subtle hover:text-fg"
                >
                  <X className="size-3" />
                </button>
              )}
            </div>

            {/* Tactic Phase Selector */}
            <Select
              value={selectedTactic}
              onValueChange={(v) => setSelectedTactic(v)}
              title="Filter by MITRE ATT&CK Tactic Phase"
              aria-label="Filter by MITRE ATT&CK Tactic Phase"
            >
              {TACTIC_OPTIONS.map((t) => (
                <option key={t} value={t}>
                  Tactic: {t}
                </option>
              ))}
            </Select>

            {/* Threat Actor Selector */}
            <Select
              value={selectedActor}
              onValueChange={(v) => setSelectedActor(v)}
              title="Filter by Associated Adversary Group"
              aria-label="Filter by Associated Adversary Group"
            >
              {THREAT_ACTORS.map((a) => (
                <option key={a} value={a}>
                  Adversary: {a}
                </option>
              ))}
            </Select>

            {/* Tool / Malware Selector */}
            <Select
              value={selectedTool}
              onValueChange={(v) => setSelectedTool(v)}
              title="Filter by Associated Tool or Malware"
              aria-label="Filter by Associated Tool or Malware"
            >
              {OFFENSIVE_TOOLS.map((m) => (
                <option key={m} value={m}>
                  Tool: {m}
                </option>
              ))}
            </Select>

            {/* Platform Filter */}
            <Select
              value={selectedPlatform}
              onValueChange={(v) => setSelectedPlatform(v)}
              title="Filter by Operating System / Platform"
              aria-label="Filter by Operating System / Platform"
            >
              {PLATFORMS.map((p) => (
                <option key={p} value={p}>
                  Platform: {p}
                </option>
              ))}
            </Select>

            {/* Coverage Status Filter */}
            <Select
              value={coverageStatus}
              onValueChange={(v) => setCoverageStatus(v as "all" | "covered" | "uncovered")}
              title="Filter by Library Intelligence Mapping Status"
              aria-label="Filter by Library Intelligence Mapping Status"
            >
              <option value="all">Coverage: All ({stats.totalTechniques})</option>
              <option value="covered">Coverage: Mapped in Library ({stats.coveredTechniques})</option>
              <option value="uncovered">Coverage: Gaps / Unmapped ({stats.totalTechniques - stats.coveredTechniques})</option>
            </Select>

            {/* Sub-Techniques Global Toggle Button */}
            <button
              type="button"
              onClick={handleToggleGlobalSubTechs}
              className={cn(
                "flex h-9 items-center gap-1.5 rounded-lg border px-3 text-sm transition-colors",
                showSubTechniques
                  ? "border-border-strong bg-bg-subtle text-fg"
                  : "border-border bg-bg-elevated text-muted hover:bg-bg-subtle hover:text-fg",
              )}
            >
              <ChevronDown className={cn("size-4 transition-transform", showSubTechniques && "rotate-180")} strokeWidth={1.75} />
              <span>{showSubTechniques ? "Hide sub-techniques" : "Show sub-techniques"}</span>
            </button>

            {/* Reset All Filters Button */}
            {hasActiveFilters && (
              <button
                type="button"
                onClick={resetAllFilters}
                className="flex h-9 items-center gap-1.5 rounded-lg px-3 text-sm text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
                title="Clear all active filters"
              >
                <X className="size-4" strokeWidth={1.75} />
                <span>Reset filters</span>
              </button>
            )}
          </div>

          {/* Secondary Info & Layout Bar */}
          <div className="flex flex-col gap-2 border-t border-border pt-3 text-sm sm:flex-row sm:items-center sm:justify-between">
            {/* Filter Status Badge */}
            <div className="flex items-center gap-2 text-sm text-muted">
              <span>
                Showing <span className="font-medium text-fg tabular-nums">{totalVisibleTechniques}</span> of{" "}
                <span className="text-fg tabular-nums">{stats.totalTechniques}</span> techniques
              </span>
              {hasActiveFilters && (
                <StatusChip tone="info">Filtered</StatusChip>
              )}
            </div>

            {/* Layout Selector (side / flat / mini) */}
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted">Layout</span>
              <SegmentedTabs<LayoutMode>
                size="sm"
                ariaLabel="Matrix layout"
                value={layoutMode}
                onChange={setLayoutMode}
                items={[
                  { value: "side", label: "Side", icon: Columns3 },
                  { value: "flat", label: "Flat", icon: LayoutGrid },
                  { value: "mini", label: "Mini", icon: Grid3X3 },
                ]}
              />
            </div>
          </div>

          {/* Active Filter Chips (Removable) */}
          {hasActiveFilters && (
            <div className="flex flex-wrap items-center gap-1.5 border-t border-border pt-3">
              <span className="mr-1 text-xs text-muted">Active filters</span>

              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  className={filterChipCls}
                >
                  <span>Query: "{searchQuery}"</span>
                  <X className="size-3" />
                </button>
              )}

              {selectedTactic !== "All 15 Tactics" && (
                <button
                  type="button"
                  onClick={() => setSelectedTactic("All 15 Tactics")}
                  className={filterChipCls}
                >
                  <span>Tactic: {selectedTactic}</span>
                  <X className="size-3" />
                </button>
              )}

              {selectedActor !== "All Actors" && (
                <button
                  type="button"
                  onClick={() => setSelectedActor("All Actors")}
                  className={filterChipCls}
                >
                  <span>Actor: {selectedActor}</span>
                  <X className="size-3" />
                </button>
              )}

              {selectedTool !== "All Tools" && (
                <button
                  type="button"
                  onClick={() => setSelectedTool("All Tools")}
                  className={filterChipCls}
                >
                  <span>Tool: {selectedTool}</span>
                  <X className="size-3" />
                </button>
              )}

              {selectedPlatform !== "All" && (
                <button
                  type="button"
                  onClick={() => setSelectedPlatform("All")}
                  className={filterChipCls}
                >
                  <span>Platform: {selectedPlatform}</span>
                  <X className="size-3" />
                </button>
              )}

              {coverageStatus !== "all" && (
                <button
                  type="button"
                  onClick={() => setCoverageStatus("all")}
                  className={filterChipCls}
                >
                  <span>Coverage: {coverageStatus}</span>
                  <X className="size-3" />
                </button>
              )}
            </div>
          )}
        </div>

        {/* ========================================================================= */}
        {/* OFFICIAL MITRE ATT&CK ENTERPRISE MATRIX GRID                              */}
        {/* 15 Tactic Columns with Sticky Headers & Dense Technique Stacking          */}
        {/* ========================================================================= */}
        <div className="overflow-hidden rounded-xl border border-border bg-bg-card">
          <div className="relative overflow-x-auto">
            <div className="inline-flex min-w-full divide-x divide-border">
              {filteredTactics.map((tactic) => (
                <div
                  key={tactic.id}
                  className={cn(
                    "flex shrink-0 flex-col",
                    layoutMode === "mini" ? "w-44 min-w-[176px]" : "w-56 min-w-[224px]",
                  )}
                >
                  {/* TACTIC COLUMN HEADER (Exact official MITRE layout: Name + technique count) */}
                  <div className="sticky top-0 z-20 select-none border-b border-border bg-bg-card px-3 py-3">
                    <div className="text-sm font-medium leading-tight text-fg">
                      {tactic.name}
                    </div>
                    <div className="mt-0.5 text-xs text-muted tabular-nums">
                      {(tactic?.techniques?.length ?? 0)} techniques
                    </div>
                  </div>

                  {/* DENSE VERTICAL STACK OF TECHNIQUES */}
                  <div className="flex-1 p-1.5 space-y-1 overflow-y-auto max-h-[800px]">
                    {(!tactic?.techniques || tactic.techniques.length === 0) ? (
                      <div className="p-3 text-center text-xs text-subtle">
                        No matches
                      </div>
                    ) : (
                      tactic.techniques.map((tech) => {
                        const isExpanded = showSubTechniques || expandedTechniqueIds.has(tech.id);
                        const isSelected = selectedTechnique?.id === tech.id;
                        const hasReports = (tech?.coverageCount ?? 0) > 0;
                        const subCount = Array.isArray(tech?.subTechniques) ? tech.subTechniques.length : 0;

                        // Mini Layout Cell
                        if (layoutMode === "mini") {
                          return (
                            <div
                              key={tech.id}
                              onClick={() => {
                                setSelectedTechnique(tech);
                                setSelectedSubTech(null);
                              }}
                              className={cn(
                                "group relative cursor-pointer select-none rounded-md border px-2 py-1.5 transition-colors duration-100",
                                isSelected
                                  ? "border-border-strong bg-bg-subtle ring-1 ring-border-strong"
                                  : hasReports
                                    ? "border-border bg-bg-elevated hover:bg-bg-subtle"
                                    : "border-border bg-bg-elevated hover:bg-bg-subtle",
                              )}
                              title={`${tech.id} ${tech.name} (${hasReports ? `${tech.coverageCount} reports` : "no reports"})`}
                            >
                              <div className="flex items-center justify-between text-[11px]">
                                <span className="font-mono text-subtle">{tech.id}</span>
                                {hasReports && (
                                  <CoverageDot count={tech.coverageCount} />
                                )}
                              </div>
                              <div className="truncate text-xs font-medium text-fg mt-0.5">
                                {tech.name}
                              </div>
                            </div>
                          );
                        }

                        // Side / Flat Layout Card
                        return (
                          <div key={tech.id} className="space-y-1">
                            {/* RECTANGULAR TECHNIQUE CARD */}
                            <div
                              onClick={() => {
                                setSelectedTechnique(tech);
                                setSelectedSubTech(null);
                              }}
                              className={cn(
                                "group relative flex rounded-md border p-2 text-left cursor-pointer transition-colors duration-100 select-none",
                                isSelected
                                  ? "border-border-strong bg-bg-subtle ring-1 ring-border-strong shadow-xs"
                                  : hasReports
                                    ? "border-border bg-bg-elevated hover:bg-bg-subtle hover:border-border-strong"
                                    : "border-border bg-bg-elevated hover:bg-bg-subtle",
                              )}
                            >
                              {/* Small Vertical Indicator Bar */}
                              <div
                                className={cn(
                                  "absolute left-0 top-1 bottom-1 w-0.5 rounded-r",
                                  hasReports ? "bg-accent" : subCount > 0 ? "bg-muted/40" : "bg-transparent",
                                )}
                              />

                              <div className="ml-1.5 flex-1 min-w-0">
                                <div className="flex items-baseline justify-between gap-1">
                                  {/* Technique Name */}
                                  <span className="text-xs font-medium leading-snug text-fg group-hover:underline">
                                    {tech.name}
                                  </span>

                                  {/* Sub-Technique Count in Parentheses & Official '=' Toggle */}
                                  {subCount > 0 && layoutMode === "side" && (
                                    <div className="flex items-center gap-1 shrink-0">
                                      <span className="text-[11px] text-muted tabular-nums">
                                        ({subCount})
                                      </span>
                                      <button
                                        type="button"
                                        onClick={(e) => toggleTechniqueExpand(tech.id, e)}
                                        className="flex size-4 items-center justify-center rounded border border-border bg-bg font-mono text-[10px] text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
                                        title={isExpanded ? "Collapse sub-techniques" : "Expand sub-techniques"}
                                      >
                                        {isExpanded ? "−" : "="}
                                      </button>
                                    </div>
                                  )}
                                </div>

                                {/* Mapped Reports Badge */}
                                {hasReports && (
                                  <div className="mt-1 flex items-center gap-1.5 text-[11px] text-sage">
                                    <span className="size-1.5 rounded-full bg-sage" />
                                    <span>{tech.coverageCount} mapped</span>
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* EXPANDED SUB-TECHNIQUES (In Side or Flat Layout) */}
                            {((layoutMode === "side" && isExpanded) || layoutMode === "flat") &&
                              subCount > 0 && (
                                <div className="ml-3 pl-2 border-l border-border space-y-1">
                                  {tech.subTechniques.map((sub, subIdx) => {
                                    const isSubSelected = selectedSubTech?.id === sub.id;
                                    const hasSubReports = sub.coverageCount > 0;

                                    return (
                                      <div
                                        key={`${sub.id}-${subIdx}`}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setSelectedTechnique(tech);
                                          setSelectedSubTech(sub);
                                        }}
                                        className={cn(
                                          "cursor-pointer rounded-md border px-2 py-1 text-left transition-colors",
                                          isSubSelected
                                            ? "border-border-strong bg-bg-subtle ring-1 ring-border-strong"
                                            : hasSubReports
                                              ? "border-border bg-bg-elevated hover:bg-bg-subtle text-fg"
                                              : "border-border bg-bg-elevated hover:bg-bg-subtle text-muted hover:text-fg",
                                        )}
                                      >
                                        <div className="flex items-baseline justify-between gap-1">
                                          <span className="text-[11px] font-normal leading-tight text-fg hover:underline">
                                            {sub.name}
                                          </span>
                                          {hasSubReports && (
                                            <CoverageDot count={sub.coverageCount} />
                                          )}
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              )}
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* OFFICIAL MITRE ATT&CK BRANDING & TRADEMARK ATTRIBUTION                     */}
        {/* ========================================================================= */}
        <div className="rounded-xl border border-border bg-bg-card p-5 text-xs leading-relaxed text-muted">
          <div className="mb-2 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
            <span className="text-sm font-medium text-fg">MITRE ATT&CK® Enterprise matrix notice</span>
            <span className="text-xs text-subtle">Official ATT&CK framework, Enterprise</span>
          </div>
          <p>
            © 2026 The MITRE Corporation. This work is reproduced and adapted from the MITRE ATT&CK® matrix.
            MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.
            Adversary Intelligence Engine automatically connects incoming threat reports with standardized techniques
            to provide continuous adversary emulation and detection intelligence.
          </p>
        </div>

        {/* ========================================================================= */}
        {/* CLEAN TECHNIQUE INTELLIGENCE INSPECTOR MODAL / DRAWER                      */}
        {/* Shows focused technique info and cleanly aligned mapped library resources  */}
        {/* ========================================================================= */}
        {selectedTechnique && (
          <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-xs p-0 sm:p-4">
            <div className="flex h-full w-full max-w-2xl flex-col overflow-hidden rounded-none border border-border bg-bg-card shadow-2xl animate-in slide-in-from-right duration-150 sm:h-[94vh] sm:rounded-xl">
              {/* Drawer Header */}
              <div className="flex items-start justify-between gap-4 border-b border-border px-6 py-5">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm text-muted">
                      {selectedSubTech ? selectedSubTech.id : selectedTechnique.id}
                    </span>
                    <span className="text-sm text-muted">· {selectedTechnique.tacticName}</span>
                    {drawerReports.length > 0 && (
                      <StatusChip tone="success" dot>
                        {drawerReports.length} {drawerReports.length === 1 ? "report" : "reports"} mapped
                      </StatusChip>
                    )}
                  </div>

                  <h2 className="mt-1.5 text-xl font-semibold text-fg">
                    {selectedSubTech ? selectedSubTech.name : selectedTechnique.name}
                  </h2>

                  <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-muted">
                    <a
                      href={`https://attack.mitre.org/techniques/${(selectedSubTech ? selectedSubTech.id : selectedTechnique.id).replace(/\./g, "/")}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-muted hover:text-fg hover:underline"
                    >
                      <span>attack.mitre.org/techniques/{selectedSubTech ? selectedSubTech.id : selectedTechnique.id}</span>
                      <ExternalLink className="size-3" />
                    </a>
                    <span>·</span>
                    <span>Platforms: {selectedTechnique.platforms.join(", ")}</span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    setSelectedTechnique(null);
                    setSelectedSubTech(null);
                  }}
                  aria-label="Close"
                  className="flex size-8 shrink-0 items-center justify-center rounded-lg text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
                >
                  <X className="size-4" />
                </button>
              </div>

              {/* Drawer Scrollable Content */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6">
                {/* Description */}
                <div>
                  <h3 className="text-sm font-medium text-fg">
                    Description
                  </h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted">
                    {selectedSubTech ? selectedSubTech.description : selectedTechnique.description}
                  </p>
                </div>

                {/* Sub-Techniques List (Clickable to switch view) */}
                {Array.isArray(selectedTechnique?.subTechniques) && selectedTechnique.subTechniques.length > 0 && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-medium text-fg">
                        Sub-techniques ({selectedTechnique.subTechniques.length})
                      </h3>
                      {selectedSubTech && (
                        <button
                          type="button"
                          onClick={() => setSelectedSubTech(null)}
                          className="text-xs text-muted hover:text-fg"
                        >
                          View parent technique
                        </button>
                      )}
                    </div>

                    <div className="divide-y divide-border overflow-hidden rounded-lg border border-border">
                      {selectedTechnique.subTechniques.map((st, stIdx) => (
                        <button
                          key={`${st.id}-${stIdx}`}
                          type="button"
                          onClick={() => setSelectedSubTech(st)}
                          className={cn(
                            "flex w-full items-center justify-between px-3 py-2.5 text-left transition-colors",
                            selectedSubTech?.id === st.id ? "bg-bg-subtle text-fg" : "text-muted hover:bg-bg-subtle hover:text-fg",
                          )}
                        >
                          <div>
                            <span className="font-mono text-[11px] text-subtle">{st.id}</span>
                            <div className="mt-0.5 text-sm text-fg">{st.name}</div>
                          </div>
                          {st.coverageCount > 0 && (
                            <StatusChip tone="success" dot>
                              {st.coverageCount}
                            </StatusChip>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* MAPPED INTELLIGENCE RESOURCES FROM YOUR LIBRARY */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between border-b border-border pb-2">
                    <h3 className="text-sm font-medium text-fg">
                      Mapped intelligence reports ({drawerReports.length})
                    </h3>
                    {drawerReports.length === 0 && (
                      <Button
                        size="sm"
                        variant="secondary"
                        className="h-7 text-xs"
                        onClick={() => navigate({ to: "/ingest" })}
                      >
                        Hunt for this TTP
                      </Button>
                    )}
                  </div>

                  {drawerReports.length === 0 ? (
                    <div className="space-y-2 rounded-xl bg-bg-subtle/50 p-6 text-center text-sm text-muted">
                      <ShieldAlert className="mx-auto size-6 text-subtle" strokeWidth={1.75} />
                      <p className="font-medium text-fg">
                        No intelligence reports in knowledge base currently exhibiting this TTP.
                      </p>
                      <p className="text-xs text-muted max-w-md mx-auto">
                        Initiate a targeted crawl on "{selectedTechnique.name}" to discover and acquire verified technical threat intelligence.
                      </p>
                      <Button
                        size="sm"
                        className="mt-2 text-xs gap-1.5"
                        onClick={() => navigate({ to: "/ingest" })}
                      >
                        <Zap className="size-3.5" />
                        <span>Discover TTP intelligence</span>
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {drawerReports.map((report) => (
                        <div
                          key={report.id}
                          className="space-y-2.5 rounded-xl bg-bg-subtle/50 p-4 transition-colors hover:bg-bg-subtle"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
                              <span className="text-fg">{report.publisher || report.sourceName}</span>
                              {report.resourceKind && (
                                <>
                                  <span className="text-subtle">·</span>
                                  <span>{sentence(report.resourceKind.replace(/_/g, " "))}</span>
                                </>
                              )}
                              {report.simulationScore !== undefined && report.simulationScore > 0 && (
                                <StatusChip tone="success">Simulation {Math.round(report.simulationScore * 100)}%</StatusChip>
                              )}
                            </div>

                            <span className="text-xs text-subtle tabular-nums">
                              {report.wordCount} words · {report.iocCount} IOCs
                            </span>
                          </div>

                          <Link
                            to="/library"
                            search={{ selected: report.id }}
                            className="block text-sm font-medium leading-snug text-fg hover:underline"
                          >
                            {report.title}
                          </Link>

                          <p className="line-clamp-2 text-xs text-muted leading-relaxed">
                            {report.excerpt}
                          </p>

                          <div className="flex items-center justify-between pt-2 border-t border-border text-xs">
                            <a
                              href={report.canonicalUrl || report.url}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg"
                              title="Open original vendor source"
                            >
                              <span>Source paper</span>
                              <ArrowUpRight className="size-3" />
                            </a>

                            <div className="flex items-center gap-2">
                              <Button
                                size="sm"
                                variant="secondary"
                                className="h-7 text-xs gap-1"
                                onClick={() => setPreviewReportId(report.id)}
                              >
                                <Eye className="size-3" />
                                <span>PDF view</span>
                              </Button>

                              <Link
                                to="/library"
                                search={{ selected: report.id }}
                                className="inline-flex h-7 items-center gap-1 rounded-lg bg-accent px-2.5 text-xs font-medium text-accent-fg transition-opacity hover:opacity-90"
                              >
                                <span>View in Library</span>
                                <ArrowRight className="size-3" />
                              </Link>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* PDF / DOCUMENT VIEWER MODAL                                               */}
        {/* ========================================================================= */}
        {previewReportId && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs">
            <div className="flex h-[90vh] w-full max-w-5xl flex-col overflow-hidden rounded-xl border border-border bg-bg-card shadow-2xl animate-in fade-in zoom-in-95 duration-150">
              <div className="flex items-center justify-between gap-3 border-b border-border px-6 py-4">
                <div className="flex items-center gap-3 overflow-hidden">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-subtle">
                    <FileText className="size-4 text-accent" />
                  </div>
                  <div className="overflow-hidden">
                    <h3 className="truncate text-sm font-medium text-fg">
                      {previewData?.title || "Document representation"}
                    </h3>
                    <p className="truncate text-xs text-subtle font-mono">
                      {previewData?.canonicalUrl || previewData?.url}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Link
                    to="/library"
                    search={{ selected: previewReportId }}
                    className="rounded-lg border border-border bg-bg-elevated px-3 py-1.5 text-xs text-fg transition-colors hover:bg-bg-subtle"
                  >
                    View in Library
                  </Link>

                  <button
                    type="button"
                    onClick={() => setPreviewReportId(null)}
                    className="flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg transition-colors"
                  >
                    <X className="size-4" />
                  </button>
                </div>
              </div>

              <div className="flex-1 overflow-hidden bg-neutral-950">
                {isPreviewLoading ? (
                  <div className="flex h-full flex-col items-center justify-center text-muted">
                    <ActivitySpinner size="lg" className="text-accent mb-2" />
                    <p className="text-sm">Rendering document view…</p>
                  </div>
                ) : previewData?.rawHtml ? (
                  <iframe
                    title="PDF Preview"
                    srcDoc={toSafeSrcDoc(previewData.rawHtml)}
                    className="h-full w-full border-none bg-white"
                    sandbox=""
                  />
                ) : (
                  <div className="flex h-full flex-col items-center justify-center text-muted">
                    <p className="text-sm">Document preview unavailable for this report.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}

const filterChipCls =
  "inline-flex items-center gap-1 rounded-md border border-border bg-bg-elevated px-2 py-0.5 text-xs text-muted hover:bg-bg-subtle hover:text-fg";

function sentence(s: string) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : s;
}

function CoverageDot({ count }: { count: number }) {
  return (
    <span className="inline-flex shrink-0 items-center gap-1 text-[11px] text-sage tabular-nums" title={`${count} mapped reports`}>
      <span className="size-1.5 rounded-full bg-sage" />
      {count}
    </span>
  );
}
