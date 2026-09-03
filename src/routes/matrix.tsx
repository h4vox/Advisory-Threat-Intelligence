import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  Code2,
  Columns3,
  Copy,
  Download,
  ExternalLink,
  Eye,
  FileText,
  Filter,
  Flame,
  Globe2,
  Grid3X3,
  HelpCircle,
  Layers,
  LayoutGrid,
  List,
  Printer,
  Radar,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getReportPdf, listReports } from "@/lib/aie/server";
import {
  mapReportsToMitreMatrix,
  type MappedTactic,
  type MappedTechnique,
} from "@/lib/aie/mitre-matrix";
import { cn } from "@/lib/cn";

export const Route = createFileRoute("/matrix")({ component: MatrixPage });

type ViewMode = "matrix" | "side" | "flat";

function MatrixPage() {
  const navigate = useNavigate();
  const [viewMode, setViewMode] = useState<ViewMode>("matrix");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTacticId, setSelectedTacticId] = useState<string>("ALL");
  const [onlyCovered, setOnlyCovered] = useState(false);
  const [heatmapMode, setHeatmapMode] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState<MappedTechnique | null>(null);
  const [previewReportId, setPreviewReportId] = useState<string | null>(null);

  // Fetch all reports from Central Intelligence Store
  const { data: allReports = [], isLoading, refetch, isFetching } = useQuery({
    queryKey: ["reports-matrix"],
    queryFn: () => listReports({ data: {} }),
  });

  // Fetch PDF preview data when requested
  const { data: previewData, isLoading: isPreviewLoading } = useQuery({
    queryKey: ["report-pdf-matrix", previewReportId],
    queryFn: () => (previewReportId ? getReportPdf({ data: { id: previewReportId } }) : null),
    enabled: Boolean(previewReportId),
  });

  // Compute MITRE ATT&CK Matrix with mapped library reports
  const mappedTactics: MappedTactic[] = useMemo(() => {
    return mapReportsToMitreMatrix(allReports);
  }, [allReports]);

  // Aggregate matrix statistics
  const stats = useMemo(() => {
    let totalTechniques = 0;
    let coveredTechniques = 0;
    let totalMappedReports = 0;
    let highSimCoverage = 0;
    let novelTtpCount = 0;

    for (const tactic of mappedTactics) {
      totalTechniques += tactic.totalTechniques;
      coveredTechniques += tactic.coveredTechniques;
      totalMappedReports += tactic.totalMappedReports;
      for (const tech of tactic.techniques) {
        if (tech.avgSimulationScore >= 0.7) highSimCoverage++;
        if (tech.hasNovelTtp) novelTtpCount++;
      }
    }

    const coveragePct = totalTechniques > 0 ? Math.round((coveredTechniques / totalTechniques) * 100) : 0;

    return {
      totalTactics: mappedTactics.length,
      totalTechniques,
      coveredTechniques,
      coveragePct,
      totalMappedReports,
      highSimCoverage,
      novelTtpCount,
    };
  }, [mappedTactics]);

  // Filtered matrix based on search, selected tactic, and covered-only toggle
  const filteredTactics: MappedTactic[] = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();

    return mappedTactics
      .filter((tactic) => {
        if (selectedTacticId !== "ALL" && tactic.id !== selectedTacticId) return false;
        return true;
      })
      .map((tactic) => {
        let techniques = tactic.techniques;

        if (onlyCovered) {
          techniques = techniques.filter((t) => t.coverageCount > 0);
        }

        if (q) {
          techniques = techniques.filter(
            (t) =>
              t.id.toLowerCase().includes(q) ||
              t.name.toLowerCase().includes(q) ||
              t.description.toLowerCase().includes(q) ||
              t.detectionKeywords.some((kw) => kw.toLowerCase().includes(q)) ||
              t.mappedReports.some((r) => r.title.toLowerCase().includes(q) || r.publisher.toLowerCase().includes(q)),
          );
        }

        return {
          ...tactic,
          techniques,
          coveredTechniques: techniques.filter((t) => t.coverageCount > 0).length,
        };
      })
      .filter((tactic) => tactic.techniques.length > 0 || !q);
  }, [mappedTactics, selectedTacticId, onlyCovered, searchQuery]);

  // Flat techniques list for Flat view
  const flatTechniques: MappedTechnique[] = useMemo(() => {
    return filteredTactics.flatMap((t) => t.techniques);
  }, [filteredTactics]);

  const copyToClipboard = (text: string, label: string) => {
    void navigator.clipboard.writeText(text);
    toast.success(`Copied ${label} to clipboard`);
  };

  const handleExportNavigatorLayer = () => {
    const techniquesObj = flatTechniques.map((t) => ({
      techniqueID: t.id,
      tactic: t.tacticName.toLowerCase().replace(/\s+/g, "-"),
      score: t.coverageCount > 0 ? Math.min(100, t.coverageCount * 25) : 0,
      color: t.coverageCount > 0 ? "#00f0ff" : "#1a1e24",
      comment: `${t.coverageCount} mapped intelligence reports in AIE database`,
      enabled: true,
    }));

    const layer = {
      name: "AIE Adversary Intelligence Coverage Layer",
      versions: { attack: "15", navigator: "5.0", layer: "4.5" },
      domain: "enterprise-attack",
      description: "Autonomous Threat Crawler & Emulation Intelligence Layer mapping observed enterprise TTPs.",
      techniques: techniquesObj,
    };

    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "aie_mitre_attack_matrix_layer.json";
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Exported ATT&CK Navigator Layer", {
      description: "Import into https://mitre-attack.github.io/attack-navigator/ for full visual matrix overlay.",
    });
  };

  return (
    <AppShell>
      {/* Header Bar */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-lg bg-accent/15 text-accent">
              <Layers className="size-4" />
            </span>
            <h1 className="text-2xl font-medium tracking-tight">MITRE ATT&CK® Intelligence Matrix</h1>
            <Badge tone="accent" className="font-mono text-[10px] uppercase">
              Enterprise v15
            </Badge>
          </div>
          <p className="mt-1 text-xs text-muted max-w-3xl leading-relaxed">
            Interactive TTP stack-up mapping adversary procedures, execution telemetry, and simulation commands against
            the official MITRE ATT&CK Matrix. Click any technique to inspect mapped reports and atomic purple-team replays.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            className="h-8 gap-1.5 text-xs font-mono"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={cn("size-3.5", isFetching && "animate-spin text-accent")} />
            <span>Sync Intel</span>
          </Button>

          <Button
            size="sm"
            variant="secondary"
            className="h-8 gap-1.5 text-xs font-mono"
            onClick={handleExportNavigatorLayer}
            title="Download MITRE ATT&CK Navigator compatible JSON"
          >
            <Download className="size-3.5" />
            <span>Export Layer</span>
          </Button>
        </div>
      </div>

      {/* KPI Stats Bar */}
      <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <div className="rounded-xl border border-border bg-bg-elevated p-3">
          <span className="text-[10px] uppercase font-mono text-subtle">Tactics</span>
          <div className="mt-1 text-2xl font-mono font-medium">{stats.totalTactics}</div>
          <span className="text-[11px] text-muted">Enterprise phases</span>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated p-3">
          <span className="text-[10px] uppercase font-mono text-subtle">Total Techniques</span>
          <div className="mt-1 text-2xl font-mono font-medium">{stats.totalTechniques}</div>
          <span className="text-[11px] text-muted">Mapped catalog</span>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated p-3">
          <span className="text-[10px] uppercase font-mono text-subtle">Observed Coverage</span>
          <div className="mt-1 text-2xl font-mono font-medium text-accent">
            {stats.coveredTechniques} <span className="text-xs text-muted">({stats.coveragePct}%)</span>
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-bg-subtle">
            <div
              className="h-full bg-accent transition-all duration-300"
              style={{ width: `${stats.coveragePct}%` }}
            />
          </div>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated p-3">
          <span className="text-[10px] uppercase font-mono text-subtle">Mapped Intel Reports</span>
          <div className="mt-1 text-2xl font-mono font-medium text-sage">{stats.totalMappedReports}</div>
          <span className="text-[11px] text-muted">Active cross-references</span>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated p-3">
          <span className="text-[10px] uppercase font-mono text-subtle">Simulation Replay</span>
          <div className="mt-1 text-2xl font-mono font-medium text-warn">{stats.highSimCoverage}</div>
          <span className="text-[11px] text-muted">SIM score &ge; 70%</span>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated p-3">
          <span className="text-[10px] uppercase font-mono text-subtle">Novel / Emerging TTPs</span>
          <div className="mt-1 text-2xl font-mono font-medium text-danger">{stats.novelTtpCount}</div>
          <span className="text-[11px] text-muted">BYOVD, LOTC, PRT</span>
        </div>
      </div>

      {/* Control Bar: Layout Switcher, Search, Tactic Filter, Toggles */}
      <div className="mt-5 flex flex-col gap-3 rounded-xl border border-border bg-bg-elevated p-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-1 flex-wrap items-center gap-2">
          {/* Search Input */}
          <div className="relative min-w-[220px] max-w-sm flex-1">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted" />
            <Input
              type="text"
              placeholder="Search by TTP ID (T1059), name, command..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 pl-8 text-xs font-mono"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted hover:text-fg"
              >
                <X className="size-3" />
              </button>
            )}
          </div>

          {/* Tactic Selector Dropdown */}
          <select
            value={selectedTacticId}
            onChange={(e) => setSelectedTacticId(e.target.value)}
            className="h-8 rounded-lg border border-border bg-bg px-2.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-accent font-mono"
          >
            <option value="ALL">All 14 Tactics ({stats.totalTechniques} techniques)</option>
            {mappedTactics.map((tac) => (
              <option key={tac.id} value={tac.id}>
                {tac.name} ({tac.coveredTechniques}/{tac.totalTechniques} mapped)
              </option>
            ))}
          </select>

          {/* Only Covered Toggle */}
          <button
            type="button"
            onClick={() => setOnlyCovered((prev) => !prev)}
            className={cn(
              "flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-mono transition-colors",
              onlyCovered
                ? "border-accent bg-accent/15 text-accent font-semibold"
                : "border-border bg-bg text-muted hover:text-fg",
            )}
          >
            <CheckCircle2 className="size-3.5" />
            <span>Only Covered ({stats.coveredTechniques})</span>
          </button>

          {/* Heatmap Mode Toggle */}
          <button
            type="button"
            onClick={() => setHeatmapMode((prev) => !prev)}
            className={cn(
              "flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-mono transition-colors",
              heatmapMode
                ? "border-warn/40 bg-warn/10 text-warn font-semibold"
                : "border-border bg-bg text-muted hover:text-fg",
            )}
            title="Color intensity represents intelligence document density"
          >
            <Flame className="size-3.5" />
            <span>Heatmap</span>
          </button>
        </div>

        {/* View Mode Switcher */}
        <div className="flex items-center rounded-lg border border-border bg-bg p-0.5 shrink-0">
          <button
            type="button"
            onClick={() => setViewMode("matrix")}
            className={cn(
              "flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors",
              viewMode === "matrix" ? "bg-accent/20 text-accent font-semibold" : "text-muted hover:text-fg",
            )}
            title="Classic ATT&CK Matrix Grid with horizontal scroll"
          >
            <Grid3X3 className="size-3.5" />
            <span className="hidden sm:inline">Matrix Grid</span>
          </button>

          <button
            type="button"
            onClick={() => setViewMode("side")}
            className={cn(
              "flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors",
              viewMode === "side" ? "bg-accent/20 text-accent font-semibold" : "text-muted hover:text-fg",
            )}
            title="Split-Screen Explorer View"
          >
            <Columns3 className="size-3.5" />
            <span className="hidden sm:inline">Split Explorer</span>
          </button>

          <button
            type="button"
            onClick={() => setViewMode("flat")}
            className={cn(
              "flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors",
              viewMode === "flat" ? "bg-accent/20 text-accent font-semibold" : "text-muted hover:text-fg",
            )}
            title="High-density searchable table"
          >
            <List className="size-3.5" />
            <span className="hidden sm:inline">Flat Table</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* VIEW MODE 1: CLASSIC ATT&CK MATRIX GRID (Stacked Columns)                */}
      {/* ========================================================================= */}
      {viewMode === "matrix" && (
        <div className="mt-6">
          <div className="relative overflow-x-auto rounded-xl border border-border bg-bg-elevated shadow-inner">
            <div className="inline-flex min-w-full divide-x divide-border">
              {filteredTactics.map((tactic) => (
                <div key={tactic.id} className="w-60 min-w-[240px] shrink-0 flex flex-col bg-bg/50">
                  {/* Tactic Column Header */}
                  <div className="sticky top-0 z-10 border-b border-border bg-bg p-3 backdrop-blur-md">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] text-accent uppercase tracking-wider">{tactic.id}</span>
                      <Badge
                        tone={tactic.coveredTechniques > 0 ? "accent" : "neutral"}
                        className="text-[9px] font-mono px-1.5 py-0"
                      >
                        {tactic.coveredTechniques}/{tactic.totalTechniques}
                      </Badge>
                    </div>
                    <div className="mt-1 text-sm font-semibold leading-tight text-fg">{tactic.name}</div>
                    <div className="mt-0.5 text-[10px] text-muted font-mono">{tactic.totalTechniques} techniques</div>

                    {/* Mini Coverage Progress */}
                    <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-border">
                      <div
                        className="h-full bg-accent transition-all duration-300"
                        style={{ width: `${tactic.coveragePercentage}%` }}
                      />
                    </div>
                  </div>

                  {/* Vertically Stacked Technique Cards */}
                  <div className="flex-1 p-2 space-y-1.5 overflow-y-auto max-h-[750px]">
                    {tactic.techniques.length === 0 ? (
                      <div className="p-3 text-center text-xs text-muted font-mono">No techniques matching filter</div>
                    ) : (
                      tactic.techniques.map((tech) => {
                        const isSelected = selectedTechnique?.id === tech.id;
                        const isCovered = tech.coverageCount > 0;

                        // Calculate Heatmap Intensity Styling
                        let heatmapClasses = "border-border/60 bg-bg hover:border-border";
                        if (isCovered && heatmapMode) {
                          if (tech.coverageCount >= 3) {
                            heatmapClasses = "border-accent/80 bg-accent/15 text-fg shadow-[0_0_12px_rgba(0,240,255,0.15)]";
                          } else if (tech.coverageCount === 2) {
                            heatmapClasses = "border-sage/70 bg-sage/10 text-fg";
                          } else {
                            heatmapClasses = "border-border bg-accent/5 text-fg";
                          }
                        } else if (isCovered) {
                          heatmapClasses = "border-accent/40 bg-accent/5 text-fg";
                        }

                        if (isSelected) {
                          heatmapClasses = "border-accent ring-2 ring-accent/30 bg-accent/20";
                        }

                        return (
                          <div
                            key={tech.id}
                            onClick={() => setSelectedTechnique(tech)}
                            className={cn(
                              "group relative rounded-lg border p-2.5 text-left cursor-pointer transition-all duration-150 select-none",
                              heatmapClasses,
                            )}
                          >
                            <div className="flex items-start justify-between gap-1.5">
                              <span className="font-mono text-[10px] font-bold text-accent">{tech.id}</span>
                              <div className="flex items-center gap-1">
                                {tech.hasNovelTtp && (
                                  <span className="rounded bg-danger/20 px-1 py-0.2 text-[8px] font-bold font-mono text-danger">
                                    NOVEL
                                  </span>
                                )}
                                {isCovered && (
                                  <span
                                    className={cn(
                                      "inline-flex items-center gap-0.5 rounded px-1.5 py-0.2 text-[9px] font-mono font-semibold tabular-nums",
                                      tech.coverageCount >= 3
                                        ? "bg-accent/20 text-accent border border-accent/30"
                                        : "bg-sage/15 text-sage border border-sage/30",
                                    )}
                                  >
                                    ● {tech.coverageCount}
                                  </span>
                                )}
                              </div>
                            </div>

                            <div className="mt-1 text-xs font-medium leading-snug text-fg group-hover:text-accent transition-colors">
                              {tech.name}
                            </div>

                            {/* Command Snippet Preview */}
                            {tech.simulationCommands.length > 0 && (
                              <div className="mt-1.5 truncate font-mono text-[9px] text-muted group-hover:text-subtle">
                                $ {tech.simulationCommands[0]}
                              </div>
                            )}

                            {/* Simulation Score Pill if high */}
                            {tech.avgSimulationScore > 0 && (
                              <div className="mt-1.5 flex items-center justify-between text-[9px] font-mono text-subtle">
                                <span>SIM Replay</span>
                                <span className="text-accent font-semibold">
                                  {Math.round(tech.avgSimulationScore * 100)}%
                                </span>
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
      )}

      {/* ========================================================================= */}
      {/* VIEW MODE 2: SPLIT EXPLORER VIEW (Side-by-Side)                          */}
      {/* ========================================================================= */}
      {viewMode === "side" && (
        <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left Column: Tactics Selector */}
          <div className="lg:col-span-4 space-y-2">
            <h3 className="text-xs font-mono uppercase tracking-wider text-subtle mb-3">Enterprise Tactics</h3>
            <div className="space-y-1.5 max-h-[750px] overflow-y-auto pr-1">
              {mappedTactics.map((tactic) => {
                const isActive = selectedTacticId === tactic.id;
                return (
                  <button
                    key={tactic.id}
                    type="button"
                    onClick={() => setSelectedTacticId(tactic.id)}
                    className={cn(
                      "w-full rounded-xl border p-3.5 text-left transition-colors flex items-center justify-between",
                      isActive
                        ? "border-accent bg-accent/15 text-fg shadow-sm"
                        : "border-border bg-bg-elevated hover:bg-bg-subtle/50 text-muted hover:text-fg",
                    )}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-accent">{tactic.id}</span>
                        <span className="text-sm font-medium text-fg">{tactic.name}</span>
                      </div>
                      <div className="mt-1 text-xs text-muted font-mono">
                        {tactic.coveredTechniques} of {tactic.totalTechniques} techniques observed (
                        {tactic.coveragePercentage}%)
                      </div>
                    </div>
                    <Badge tone={tactic.coveredTechniques > 0 ? "sage" : "neutral"} className="font-mono text-xs">
                      {tactic.totalMappedReports} reports
                    </Badge>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Center Column: Techniques for Active Tactic */}
          <div className="lg:col-span-8 space-y-3">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="text-base font-medium">
                  {selectedTacticId === "ALL"
                    ? "All Techniques"
                    : mappedTactics.find((t) => t.id === selectedTacticId)?.name}
                </h3>
                <p className="text-xs text-muted">
                  {filteredTactics.reduce((acc, t) => acc + t.techniques.length, 0)} techniques found
                </p>
              </div>
              <Badge tone="accent">Select a technique to inspect intelligence</Badge>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-[700px] overflow-y-auto p-1">
              {flatTechniques.map((tech) => {
                const isSelected = selectedTechnique?.id === tech.id;
                return (
                  <div
                    key={`${tech.tacticId}-${tech.id}`}
                    onClick={() => setSelectedTechnique(tech)}
                    className={cn(
                      "rounded-xl border p-4 cursor-pointer transition-all",
                      isSelected
                        ? "border-accent ring-2 ring-accent/30 bg-accent/10"
                        : tech.coverageCount > 0
                          ? "border-border bg-bg-elevated hover:border-accent/50"
                          : "border-border/50 bg-bg-elevated/40 hover:border-border",
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-accent">{tech.id}</span>
                      <div className="flex items-center gap-1.5">
                        {tech.hasNovelTtp && (
                          <Badge tone="danger" className="font-mono text-[9px]">
                            NOVEL TTP
                          </Badge>
                        )}
                        <Badge tone={tech.coverageCount > 0 ? "sage" : "neutral"}>
                          {tech.coverageCount} reports
                        </Badge>
                      </div>
                    </div>

                    <h4 className="mt-2 text-sm font-medium text-fg">{tech.name}</h4>
                    <p className="mt-1 line-clamp-2 text-xs text-muted leading-relaxed">{tech.description}</p>

                    {tech.simulationCommands.length > 0 && (
                      <div className="mt-3 rounded-md bg-bg p-2 font-mono text-[10px] text-subtle truncate">
                        $ {tech.simulationCommands[0]}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW MODE 3: FLAT / HIGH-DENSITY TABLE                                    */}
      {/* ========================================================================= */}
      {viewMode === "flat" && (
        <div className="mt-6 rounded-xl border border-border bg-bg-elevated overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border bg-bg font-mono text-[10px] uppercase text-subtle">
                <tr>
                  <th className="p-3">Technique ID</th>
                  <th className="p-3">Technique Name</th>
                  <th className="p-3">Tactic</th>
                  <th className="p-3">Mapped Reports</th>
                  <th className="p-3">Simulation Replay</th>
                  <th className="p-3">Novel Tradecraft</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {flatTechniques.map((tech) => (
                  <tr
                    key={`${tech.tacticId}-${tech.id}`}
                    onClick={() => setSelectedTechnique(tech)}
                    className={cn(
                      "hover:bg-bg-subtle/40 cursor-pointer transition-colors",
                      selectedTechnique?.id === tech.id && "bg-accent/10",
                    )}
                  >
                    <td className="p-3 font-mono font-bold text-accent">{tech.id}</td>
                    <td className="p-3 font-medium text-fg">{tech.name}</td>
                    <td className="p-3">
                      <span className="rounded bg-bg-subtle px-2 py-0.5 font-mono text-[10px] text-muted">
                        {tech.tacticName}
                      </span>
                    </td>
                    <td className="p-3 font-mono">
                      {tech.coverageCount > 0 ? (
                        <span className="font-semibold text-sage">● {tech.coverageCount} reports</span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className="p-3 font-mono">
                      {tech.avgSimulationScore > 0 ? (
                        <span className="text-accent">{Math.round(tech.avgSimulationScore * 100)}% SIM</span>
                      ) : tech.simulationCommands.length > 0 ? (
                        <span className="text-muted">Atomic ready</span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="p-3">
                      {tech.hasNovelTtp ? (
                        <span className="rounded bg-danger/15 px-1.5 py-0.5 text-[9px] font-bold font-mono text-danger">
                          YES (NOVEL)
                        </span>
                      ) : (
                        <span className="text-muted text-[10px] font-mono">Standard</span>
                      )}
                    </td>
                    <td className="p-3 text-right">
                      <Button
                        size="sm"
                        variant="secondary"
                        className="h-7 text-xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedTechnique(tech);
                        }}
                      >
                        Inspect TTP
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TECHNIQUE INTELLIGENCE INSPECTOR (Drawer / Modal)                         */}
      {/* ========================================================================= */}
      {selectedTechnique && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm p-0 sm:p-4">
          <div className="h-full sm:h-[92vh] w-full max-w-2xl flex flex-col rounded-none sm:rounded-2xl border-l sm:border border-border bg-bg-elevated shadow-2xl overflow-hidden animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-border bg-bg p-5">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-base font-bold text-accent">{selectedTechnique.id}</span>
                  <Badge tone="neutral">{selectedTechnique.tacticName}</Badge>
                  {selectedTechnique.hasNovelTtp && (
                    <Badge tone="danger" className="font-mono font-bold">
                      NOVEL TTP
                    </Badge>
                  )}
                  {selectedTechnique.coverageCount > 0 && (
                    <Badge tone="sage" className="font-mono font-semibold">
                      {selectedTechnique.coverageCount} Mapped Reports
                    </Badge>
                  )}
                </div>
                <h2 className="mt-1 text-xl font-medium text-fg">{selectedTechnique.name}</h2>
                <a
                  href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace(/\./g, "/")}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-1 inline-flex items-center gap-1 font-mono text-xs text-subtle hover:text-accent"
                >
                  <span>https://attack.mitre.org/techniques/{selectedTechnique.id}</span>
                  <ExternalLink className="size-3" />
                </a>
              </div>

              <button
                type="button"
                onClick={() => setSelectedTechnique(null)}
                className="flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg transition-colors"
              >
                <X className="size-4" />
              </button>
            </div>

            {/* Drawer Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Description */}
              <div>
                <h3 className="text-xs font-mono uppercase tracking-wider text-subtle">Technique Overview</h3>
                <p className="mt-2 text-sm text-fg/90 leading-relaxed">{selectedTechnique.description}</p>
              </div>

              {/* Purple-Team Adversary Simulation Commands */}
              {selectedTechnique.simulationCommands.length > 0 && (
                <div className="rounded-xl border border-border bg-bg p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-mono text-accent">
                      <Terminal className="size-3.5" />
                      <span>Purple-Team Atomic Replay Syntax</span>
                    </div>
                    <span className="text-[10px] text-muted font-mono">Atomic Red Team Emulation</span>
                  </div>

                  <div className="space-y-2">
                    {selectedTechnique.simulationCommands.map((cmd, idx) => (
                      <div
                        key={idx}
                        className="group relative flex items-center justify-between rounded-lg bg-black/60 p-3 font-mono text-xs text-emerald-400 border border-emerald-950 overflow-x-auto"
                      >
                        <code className="select-all">{cmd}</code>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(cmd, "command syntax")}
                          className="ml-2 shrink-0 p-1 text-muted hover:text-fg transition-colors"
                          title="Copy command"
                        >
                          <Copy className="size-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Mapped Intelligence Reports from Knowledge Base */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-subtle">
                    Mapped Intelligence Reports ({selectedTechnique.mappedReports.length})
                  </h3>
                  {selectedTechnique.mappedReports.length === 0 && (
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

                {selectedTechnique.mappedReports.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-border p-6 text-center text-sm text-muted space-y-2">
                    <ShieldAlert className="size-8 mx-auto text-muted/50" />
                    <p className="font-medium text-fg">No intelligence reports in library exhibiting this TTP yet.</p>
                    <p className="text-xs text-muted max-w-md mx-auto">
                      Launch an autonomous crawl targeting "{selectedTechnique.name}" to discover whitepapers and technical evidence.
                    </p>
                    <Button
                      size="sm"
                      className="mt-2 text-xs gap-1.5"
                      onClick={() => navigate({ to: "/ingest" })}
                    >
                      <Radar className="size-3.5" />
                      <span>Launch Autonomous Crawl</span>
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {selectedTechnique.mappedReports.map((report) => (
                      <div
                        key={report.id}
                        className="rounded-xl border border-border bg-bg p-4 space-y-2 hover:border-accent/40 transition-colors"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <Badge tone="neutral">{report.publisher || report.sourceName}</Badge>
                            {report.resourceKind && (
                              <Badge tone="accent" className="font-semibold text-[10px]">
                                {report.resourceKind.replace(/_/g, " ")}
                              </Badge>
                            )}
                            {report.simulationScore !== undefined && report.simulationScore > 0 && (
                              <Badge tone="accent" className="font-mono text-[10px]">
                                SIM {Math.round(report.simulationScore * 100)}%
                              </Badge>
                            )}
                            {report.isEmergingTechnique && (
                              <Badge tone="danger" className="font-mono text-[10px]">
                                NOVEL
                              </Badge>
                            )}
                          </div>

                          <span className="font-mono text-[10px] text-muted">
                            {report.wordCount} words · {report.iocCount} IOCs
                          </span>
                        </div>

                        <Link
                          to="/library/$reportId"
                          params={{ reportId: report.id }}
                          className="block text-sm font-medium text-fg hover:text-accent transition-colors leading-snug"
                        >
                          {report.title}
                        </Link>

                        <p className="line-clamp-2 text-xs text-muted leading-relaxed">{report.excerpt}</p>

                        <div className="flex items-center justify-between pt-2 border-t border-border/60">
                          <a
                            href={report.canonicalUrl || report.url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-[10px] text-subtle hover:text-accent"
                            title="Open original external research"
                          >
                            <span>Open Source Link</span>
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
                              <span>View PDF</span>
                            </Button>

                            <Link
                              to="/library/$reportId"
                              params={{ reportId: report.id }}
                              className="inline-flex h-7 items-center gap-1 rounded-md bg-accent/15 px-2.5 text-xs font-medium text-accent hover:bg-accent/25 transition-colors"
                            >
                              <span>Report Deepdive</span>
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
      {/* HIGH-FIDELITY PDF / DOCUMENT PREVIEW MODAL                                */}
      {/* ========================================================================= */}
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
                  <h3 className="truncate text-sm font-medium">
                    {previewData?.title || "High-Fidelity PDF Representation"}
                  </h3>
                  <p className="truncate text-xs text-muted font-mono">
                    {previewData?.canonicalUrl || previewData?.url}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Link
                  to="/library/$reportId"
                  params={{ reportId: previewReportId }}
                  className="rounded-lg border border-border bg-bg-elevated px-3 py-1.5 text-xs text-muted hover:text-fg transition-colors"
                >
                  Full Report Detail
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

            {/* Modal Body / Document Preview */}
            <div className="flex-1 overflow-hidden bg-neutral-900">
              {isPreviewLoading ? (
                <div className="flex h-full flex-col items-center justify-center text-muted">
                  <RefreshCw className="size-6 animate-spin text-accent mb-2" />
                  <p className="text-sm">Synthesizing document view...</p>
                </div>
              ) : previewData?.rawHtml ? (
                <iframe
                  title="PDF Preview"
                  srcDoc={previewData.rawHtml}
                  className="h-full w-full border-none bg-white"
                />
              ) : (
                <div className="flex h-full flex-col items-center justify-center text-muted">
                  <p className="text-sm">Document preview unavailable for this item.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
