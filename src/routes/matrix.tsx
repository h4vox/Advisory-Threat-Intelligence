import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState } from "react";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getReportPdf, listReports } from "@/lib/aie/server";
import {
  mapReportsToMitreMatrix,
  type MappedSubTechnique,
  type MappedTactic,
  type MappedTechnique,
} from "@/lib/aie/mitre-matrix";
import { cn } from "@/lib/cn";

export const Route = createFileRoute("/matrix")({ component: MatrixPage });

type LayoutMode = "side" | "flat" | "mini";

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

  // Fetch Central Intelligence Reports with 60s cache for fast 0ms navigation
  const { data: allReports = [], isFetching, refetch } = useQuery({
    queryKey: ["reports-matrix"],
    queryFn: () => listReports({ data: {} }),
    staleTime: 60_000,
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
      <div className="space-y-4">
        {/* ========================================================================= */}
        {/* MATRIX HEADER & BREADCRUMB                                                */}
        {/* ========================================================================= */}
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between border-b border-border pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs uppercase tracking-widest text-subtle">
                Enterprise Framework
              </span>
              <span className="text-subtle">/</span>
              <Badge tone="accent" className="font-mono text-[10px]">
                ATT&CK® Enterprise Matrix
              </Badge>
            </div>
            <h1 className="mt-1 text-2xl font-bold tracking-tight text-fg md:text-3xl">
              Enterprise Matrix
            </h1>
            <p className="mt-1 text-xs text-muted max-w-3xl">
              Official MITRE ATT&CK® Enterprise Matrix mapping across 15 tactical phases.
              Techniques with verified intelligence reports in your library are highlighted with direct links to full evidence.
            </p>
          </div>

          {/* Quick Metrics & Actions */}
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              className="h-8 gap-1.5 text-xs font-mono"
              onClick={() => refetch()}
              disabled={isFetching}
            >
              <RefreshCw className={cn("size-3.5", isFetching && "animate-spin text-accent")} />
              <span>Sync Intel ({stats.totalMappedReports})</span>
            </Button>

            <Button
              size="sm"
              className="h-8 gap-1.5 text-xs font-mono"
              onClick={() => navigate({ to: "/ingest" })}
            >
              <Zap className="size-3.5" />
              <span>Hunt New TTP</span>
            </Button>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* CONTROLS BAR: SEARCH, TACTIC, ACTOR, TOOL, PLATFORM, COVERAGE, LAYOUT     */}
        {/* ========================================================================= */}
        <div className="space-y-2.5 rounded-xl border border-border bg-bg-elevated p-3 shadow-xs">
          {/* Primary Controls Row: Search, Selectors, Toggles */}
          <div className="flex flex-1 flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative min-w-[200px] max-w-xs flex-1">
              <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-subtle" />
              <Input
                type="text"
                placeholder="Search ID, name, or report..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-8 pl-8 text-xs font-mono placeholder:text-subtle"
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
            <select
              value={selectedTactic}
              onChange={(e) => setSelectedTactic(e.target.value)}
              className="h-8 rounded-md border border-border bg-bg-subtle px-2.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent font-mono"
              title="Filter by MITRE ATT&CK Tactic Phase"
            >
              {TACTIC_OPTIONS.map((t) => (
                <option key={t} value={t}>
                  Tactic: {t}
                </option>
              ))}
            </select>

            {/* Threat Actor Selector */}
            <select
              value={selectedActor}
              onChange={(e) => setSelectedActor(e.target.value)}
              className="h-8 rounded-md border border-border bg-bg-subtle px-2.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent font-mono"
              title="Filter by Associated Adversary Group"
            >
              {THREAT_ACTORS.map((a) => (
                <option key={a} value={a}>
                  Adversary: {a}
                </option>
              ))}
            </select>

            {/* Tool / Malware Selector */}
            <select
              value={selectedTool}
              onChange={(e) => setSelectedTool(e.target.value)}
              className="h-8 rounded-md border border-border bg-bg-subtle px-2.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent font-mono"
              title="Filter by Associated Tool or Malware"
            >
              {OFFENSIVE_TOOLS.map((m) => (
                <option key={m} value={m}>
                  Tool: {m}
                </option>
              ))}
            </select>

            {/* Platform Filter */}
            <select
              value={selectedPlatform}
              onChange={(e) => setSelectedPlatform(e.target.value)}
              className="h-8 rounded-md border border-border bg-bg-subtle px-2.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent font-mono"
              title="Filter by Operating System / Platform"
            >
              {PLATFORMS.map((p) => (
                <option key={p} value={p}>
                  Platform: {p}
                </option>
              ))}
            </select>

            {/* Coverage Status Filter */}
            <select
              value={coverageStatus}
              onChange={(e) => setCoverageStatus(e.target.value as "all" | "covered" | "uncovered")}
              className="h-8 rounded-md border border-border bg-bg-subtle px-2.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent font-mono"
              title="Filter by Library Intelligence Mapping Status"
            >
              <option value="all">Coverage: All ({stats.totalTechniques})</option>
              <option value="covered">Coverage: Mapped in Library ({stats.coveredTechniques})</option>
              <option value="uncovered">Coverage: Gaps / Unmapped ({stats.totalTechniques - stats.coveredTechniques})</option>
            </select>

            {/* Sub-Techniques Global Toggle Button */}
            <button
              type="button"
              onClick={handleToggleGlobalSubTechs}
              className={cn(
                "flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-mono transition-colors",
                showSubTechniques
                  ? "border-border-strong bg-bg-subtle text-fg font-semibold shadow-xs"
                  : "border-border bg-bg-subtle text-muted hover:text-fg",
              )}
            >
              <ChevronDown className={cn("size-3.5 transition-transform", showSubTechniques && "rotate-180")} />
              <span>{showSubTechniques ? "hide sub-techniques" : "show sub-techniques"}</span>
            </button>

            {/* Reset All Filters Button */}
            {hasActiveFilters && (
              <button
                type="button"
                onClick={resetAllFilters}
                className="flex h-8 items-center gap-1 rounded-md border border-border bg-bg-subtle px-2.5 text-xs font-mono text-muted hover:text-fg hover:border-border-strong transition-colors"
                title="Clear all active filters"
              >
                <X className="size-3" />
                <span>Reset</span>
              </button>
            )}
          </div>

          {/* Secondary Info & Layout Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-t border-border/70 pt-2 text-xs">
            {/* Filter Status Badge */}
            <div className="flex items-center gap-2 font-mono text-[11px] text-muted">
              <span>
                Displaying <span className="font-bold text-fg">{totalVisibleTechniques}</span> of{" "}
                <span className="text-fg">{stats.totalTechniques}</span> techniques
              </span>
              {hasActiveFilters && (
                <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] text-fg font-medium">
                  Filtered
                </span>
              )}
            </div>

            {/* Layout Selector (side / flat / mini) */}
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-[11px] text-subtle mr-1">layout:</span>
              <div className="flex items-center rounded-md border border-border bg-bg-subtle p-0.5">
                <button
                  type="button"
                  onClick={() => setLayoutMode("side")}
                  className={cn(
                    "flex h-6 items-center gap-1 rounded px-2 text-[11px] font-mono transition-colors",
                    layoutMode === "side"
                      ? "bg-bg-elevated text-fg font-semibold shadow-xs"
                      : "text-muted hover:text-fg",
                  )}
                  title="Side layout: expandable sub-techniques with official '=' toggle"
                >
                  <Columns3 className="size-3" />
                  <span>side</span>
                </button>

                <button
                  type="button"
                  onClick={() => setLayoutMode("flat")}
                  className={cn(
                    "flex h-6 items-center gap-1 rounded px-2 text-[11px] font-mono transition-colors",
                    layoutMode === "flat"
                      ? "bg-bg-elevated text-fg font-semibold shadow-xs"
                      : "text-muted hover:text-fg",
                  )}
                  title="Flat layout: continuous list of all techniques"
                >
                  <LayoutGrid className="size-3" />
                  <span>flat</span>
                </button>

                <button
                  type="button"
                  onClick={() => setLayoutMode("mini")}
                  className={cn(
                    "flex h-6 items-center gap-1 rounded px-2 text-[11px] font-mono transition-colors",
                    layoutMode === "mini"
                      ? "bg-bg-elevated text-fg font-semibold shadow-xs"
                      : "text-muted hover:text-fg",
                  )}
                  title="Mini layout: compact heatmap view"
                >
                  <Grid3X3 className="size-3" />
                  <span>mini</span>
                </button>
              </div>
            </div>
          </div>

          {/* Active Filter Chips (Removable) */}
          {hasActiveFilters && (
            <div className="flex flex-wrap items-center gap-1.5 border-t border-border/50 pt-2">
              <span className="text-[10px] font-mono uppercase text-subtle mr-1">Active:</span>

              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-[11px] font-mono text-muted hover:text-fg hover:border-border-strong"
                >
                  <span>query: "{searchQuery}"</span>
                  <X className="size-2.5" />
                </button>
              )}

              {selectedTactic !== "All 15 Tactics" && (
                <button
                  type="button"
                  onClick={() => setSelectedTactic("All 15 Tactics")}
                  className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-[11px] font-mono text-muted hover:text-fg hover:border-border-strong"
                >
                  <span>tactic: {selectedTactic}</span>
                  <X className="size-2.5" />
                </button>
              )}

              {selectedActor !== "All Actors" && (
                <button
                  type="button"
                  onClick={() => setSelectedActor("All Actors")}
                  className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-[11px] font-mono text-muted hover:text-fg hover:border-border-strong"
                >
                  <span>actor: {selectedActor}</span>
                  <X className="size-2.5" />
                </button>
              )}

              {selectedTool !== "All Tools" && (
                <button
                  type="button"
                  onClick={() => setSelectedTool("All Tools")}
                  className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-[11px] font-mono text-muted hover:text-fg hover:border-border-strong"
                >
                  <span>tool: {selectedTool}</span>
                  <X className="size-2.5" />
                </button>
              )}

              {selectedPlatform !== "All" && (
                <button
                  type="button"
                  onClick={() => setSelectedPlatform("All")}
                  className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-[11px] font-mono text-muted hover:text-fg hover:border-border-strong"
                >
                  <span>platform: {selectedPlatform}</span>
                  <X className="size-2.5" />
                </button>
              )}

              {coverageStatus !== "all" && (
                <button
                  type="button"
                  onClick={() => setCoverageStatus("all")}
                  className="inline-flex items-center gap-1 rounded-md border border-border bg-bg-subtle px-2 py-0.5 text-[11px] font-mono text-muted hover:text-fg hover:border-border-strong"
                >
                  <span>coverage: {coverageStatus}</span>
                  <X className="size-2.5" />
                </button>
              )}
            </div>
          )}
        </div>

        {/* ========================================================================= */}
        {/* OFFICIAL MITRE ATT&CK ENTERPRISE MATRIX GRID                              */}
        {/* 15 Tactic Columns with Sticky Headers & Dense Technique Stacking          */}
        {/* ========================================================================= */}
        <div className="rounded-xl border border-border bg-bg-elevated shadow-xs overflow-hidden">
          <div className="relative overflow-x-auto">
            <div className="inline-flex min-w-full divide-x divide-border">
              {filteredTactics.map((tactic) => (
                <div
                  key={tactic.id}
                  className={cn(
                    "shrink-0 flex flex-col bg-bg",
                    layoutMode === "mini" ? "w-44 min-w-[176px]" : "w-56 min-w-[224px]",
                  )}
                >
                  {/* TACTIC COLUMN HEADER (Exact official MITRE layout: Name + technique count) */}
                  <div className="sticky top-0 z-20 border-b border-border bg-bg-elevated px-3 py-2.5 shadow-xs select-none">
                    <div className="text-xs font-bold leading-tight text-fg tracking-tight">
                      {tactic.name}
                    </div>
                    <div className="mt-0.5 text-[11px] font-mono text-muted">
                      {(tactic?.techniques?.length ?? 0)} techniques
                    </div>
                  </div>

                  {/* DENSE VERTICAL STACK OF TECHNIQUES */}
                  <div className="flex-1 p-1.5 space-y-1 overflow-y-auto max-h-[800px]">
                    {(!tactic?.techniques || tactic.techniques.length === 0) ? (
                      <div className="p-3 text-center text-[11px] font-mono text-subtle">
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
                                "group relative rounded border px-2 py-1.5 cursor-pointer transition-all duration-100 select-none",
                                isSelected
                                  ? "border-border-strong bg-bg-subtle ring-1 ring-border-strong"
                                  : hasReports
                                    ? "border-border bg-bg-elevated hover:bg-bg-subtle"
                                    : "border-border bg-bg-elevated hover:bg-bg-subtle",
                              )}
                              title={`${tech.id} ${tech.name} (${hasReports ? `${tech.coverageCount} reports` : "no reports"})`}
                            >
                              <div className="flex items-center justify-between text-[10px] font-mono">
                                <span className="font-semibold text-subtle">{tech.id}</span>
                                {hasReports && (
                                  <span className="text-sage font-bold">● {tech.coverageCount}</span>
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
                                      <span className="font-mono text-[10px] text-muted">
                                        ({subCount})
                                      </span>
                                      <button
                                        type="button"
                                        onClick={(e) => toggleTechniqueExpand(tech.id, e)}
                                        className="flex size-4 items-center justify-center rounded border border-border bg-bg text-[10px] font-mono font-bold text-muted hover:bg-bg-subtle hover:text-fg transition-colors"
                                        title={isExpanded ? "Collapse sub-techniques" : "Expand sub-techniques"}
                                      >
                                        {isExpanded ? "−" : "="}
                                      </button>
                                    </div>
                                  )}
                                </div>

                                {/* Mapped Reports Badge */}
                                {hasReports && (
                                  <div className="mt-1 flex items-center gap-1 font-mono text-[10px] text-sage">
                                    <span>●</span>
                                    <span>{tech.coverageCount} mapped</span>
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* EXPANDED SUB-TECHNIQUES (In Side or Flat Layout) */}
                            {((layoutMode === "side" && isExpanded) || layoutMode === "flat") &&
                              subCount > 0 && (
                                <div className="ml-3 pl-2 border-l border-border space-y-1">
                                  {tech.subTechniques.map((sub) => {
                                    const isSubSelected = selectedSubTech?.id === sub.id;
                                    const hasSubReports = sub.coverageCount > 0;

                                    return (
                                      <div
                                        key={sub.id}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setSelectedTechnique(tech);
                                          setSelectedSubTech(sub);
                                        }}
                                        className={cn(
                                          "rounded border px-2 py-1 cursor-pointer transition-colors text-left",
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
                                            <span className="font-mono text-[9px] text-sage font-bold">
                                              ● {sub.coverageCount}
                                            </span>
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
        <div className="rounded-xl border border-border bg-bg-elevated p-3.5 text-xs text-muted leading-relaxed">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-border pb-2 mb-2">
            <span className="font-mono text-[11px] uppercase font-bold text-fg">
              MITRE ATT&CK® Enterprise Matrix Notice
            </span>
            <span className="font-mono text-[10px] text-subtle">
              Official ATT&CK Framework Enterprise
            </span>
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
            <div className="h-full sm:h-[94vh] w-full max-w-2xl flex flex-col rounded-none sm:rounded-2xl border border-border bg-bg-elevated shadow-2xl overflow-hidden animate-in slide-in-from-right duration-150">
              {/* Drawer Header */}
              <div className="flex items-start justify-between border-b border-border bg-bg px-6 py-5">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-base font-bold text-fg">
                      {selectedSubTech ? selectedSubTech.id : selectedTechnique.id}
                    </span>
                    <Badge tone="neutral">{selectedTechnique.tacticName}</Badge>
                    {selectedTechnique.coverageCount > 0 && (
                      <Badge tone="sage" className="font-mono text-[10px]">
                        {selectedTechnique.coverageCount} Reports Mapped
                      </Badge>
                    )}
                  </div>

                  <h2 className="mt-1.5 text-xl font-bold text-fg">
                    {selectedSubTech ? selectedSubTech.name : selectedTechnique.name}
                  </h2>

                  <div className="mt-1 flex flex-wrap items-center gap-3 text-xs font-mono text-muted">
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
                  className="flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg transition-colors"
                >
                  <X className="size-4" />
                </button>
              </div>

              {/* Drawer Scrollable Content */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6">
                {/* Description */}
                <div>
                  <h3 className="font-mono text-xs uppercase tracking-wider text-subtle">
                    Description
                  </h3>
                  <p className="mt-2 text-sm text-fg leading-relaxed">
                    {selectedSubTech ? selectedSubTech.description : selectedTechnique.description}
                  </p>
                </div>

                {/* Sub-Techniques List (Clickable to switch view) */}
                {Array.isArray(selectedTechnique?.subTechniques) && selectedTechnique.subTechniques.length > 0 && (
                  <div className="rounded-xl border border-border bg-bg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <h3 className="font-mono text-xs uppercase tracking-wider text-fg">
                        Sub-Techniques ({selectedTechnique.subTechniques.length})
                      </h3>
                      {selectedSubTech && (
                        <button
                          type="button"
                          onClick={() => setSelectedSubTech(null)}
                          className="font-mono text-xs text-muted hover:text-fg hover:underline"
                        >
                          View Parent Technique
                        </button>
                      )}
                    </div>

                    <div className="grid grid-cols-1 gap-1.5 pt-1">
                      {selectedTechnique.subTechniques.map((st) => (
                        <button
                          key={st.id}
                          type="button"
                          onClick={() => setSelectedSubTech(st)}
                          className={cn(
                            "rounded-lg border p-2.5 text-left transition-colors flex items-center justify-between",
                            selectedSubTech?.id === st.id
                              ? "border-border-strong bg-bg-subtle text-fg font-medium"
                              : "border-border bg-bg-elevated hover:bg-bg-subtle text-muted hover:text-fg",
                          )}
                        >
                          <div>
                            <span className="font-mono text-[10px] text-muted font-semibold">{st.id}</span>
                            <div className="text-xs mt-0.5 text-fg">{st.name}</div>
                          </div>
                          {st.coverageCount > 0 && (
                            <Badge tone="sage" className="font-mono text-[9px]">
                              ● {st.coverageCount}
                            </Badge>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* MAPPED INTELLIGENCE RESOURCES FROM YOUR LIBRARY */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between border-b border-border pb-2">
                    <h3 className="font-mono text-xs uppercase tracking-wider text-fg">
                      Mapped Intelligence Reports ({selectedTechnique?.mappedReports?.length ?? 0})
                    </h3>
                    {(!selectedTechnique?.mappedReports || selectedTechnique.mappedReports.length === 0) && (
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

                  {(!selectedTechnique?.mappedReports || selectedTechnique.mappedReports.length === 0) ? (
                    <div className="rounded-xl border border-dashed border-border p-6 text-center text-sm text-muted space-y-2">
                      <ShieldAlert className="size-8 mx-auto text-subtle" />
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
                        <span>Discover TTP Intelligence</span>
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {selectedTechnique.mappedReports.map((report) => (
                        <div
                          key={report.id}
                          className="rounded-xl border border-border bg-bg p-4 space-y-2.5 hover:border-border-strong transition-colors"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <Badge tone="neutral">{report.publisher || report.sourceName}</Badge>
                              {report.resourceKind && (
                                <Badge tone="accent" className="text-[10px]">
                                  {report.resourceKind.replace(/_/g, " ")}
                                </Badge>
                              )}
                              {report.simulationScore !== undefined && report.simulationScore > 0 && (
                                <Badge tone="sage" className="font-mono text-[10px]">
                                  SIM {Math.round(report.simulationScore * 100)}%
                                </Badge>
                              )}
                            </div>

                            <span className="font-mono text-[10px] text-subtle">
                              {report.wordCount} words · {report.iocCount} IOCs
                            </span>
                          </div>

                          <Link
                            to="/library/$reportId"
                            params={{ reportId: report.id }}
                            className="block text-sm font-semibold text-fg hover:underline transition-colors leading-snug"
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
                              className="inline-flex items-center gap-1 font-mono text-[11px] text-subtle hover:text-fg"
                              title="Open original vendor source"
                            >
                              <span>Source Paper</span>
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
                                <span>PDF View</span>
                              </Button>

                              <Link
                                to="/library/$reportId"
                                params={{ reportId: report.id }}
                                className="inline-flex h-7 items-center gap-1 rounded-md bg-accent px-2.5 text-xs font-medium text-accent-fg hover:opacity-90 transition-opacity"
                              >
                                <span>View Report</span>
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
            <div className="flex h-[90vh] w-full max-w-5xl flex-col rounded-2xl border border-border bg-bg-elevated shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
              <div className="flex items-center justify-between border-b border-border bg-bg px-6 py-4">
                <div className="flex items-center gap-3 overflow-hidden">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-subtle">
                    <FileText className="size-4 text-accent" />
                  </div>
                  <div className="overflow-hidden">
                    <h3 className="truncate text-sm font-medium text-fg">
                      {previewData?.title || "Document Representation"}
                    </h3>
                    <p className="truncate text-xs text-subtle font-mono">
                      {previewData?.canonicalUrl || previewData?.url}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Link
                    to="/library/$reportId"
                    params={{ reportId: previewReportId }}
                    className="rounded-lg border border-border bg-bg-subtle px-3 py-1.5 text-xs text-fg hover:bg-bg transition-colors"
                  >
                    Full Details
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
                    <RefreshCw className="size-6 animate-spin text-accent mb-2" />
                    <p className="text-sm font-mono">Rendering document view...</p>
                  </div>
                ) : previewData?.rawHtml ? (
                  <iframe
                    title="PDF Preview"
                    srcDoc={previewData.rawHtml}
                    className="h-full w-full border-none bg-white"
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
