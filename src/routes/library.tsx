import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  ArrowUpRight,
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
  X,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getReportPdf, listReports } from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";
import type { ReportListItem, ResourceKind } from "@/lib/aie/types";

export const Route = createFileRoute("/library")({ component: LibraryPage });

const RESOURCE_KINDS: { id: string; label: string }[] = [
  { id: "ALL", label: "All Intelligence" },
  { id: "FULL_ATTACK_CHAIN", label: "Attack Chains" },
  { id: "CAMPAIGN_INTEL", label: "Campaigns" },
  { id: "PROCEDURE_DEEPDIVE", label: "Procedures & TTPs" },
  { id: "MALWARE_ANALYSIS", label: "Malware Analysis" },
  { id: "DETECTION_GUIDANCE", label: "Detections & Sigma" },
  { id: "VULNERABILITY_ADVISORY", label: "Vulnerability Advisories" },
];

function LibraryPage() {
  const [q, setQ] = useState("");
  const [selectedKind, setSelectedKind] = useState("ALL");
  const [selectedActor, setSelectedActor] = useState("ALL");
  const [selectedMalware, setSelectedMalware] = useState("ALL");
  const [selectedTactic, setSelectedTactic] = useState("ALL");
  const [selectedPublisher, setSelectedPublisher] = useState("ALL");
  const [minQuality, setMinQuality] = useState<number>(0);
  const [onlyWithIocs, setOnlyWithIocs] = useState(false);
  const [sortBy, setSortBy] = useState<"newest" | "quality" | "iocs" | "words">("newest");
  const [showFilters, setShowFilters] = useState(false);
  const [previewReportId, setPreviewReportId] = useState<string | null>(null);

  // Fetch all reports to enable rich interactive filtering and instant counts
  const { data: rawReports, isLoading } = useQuery({
    queryKey: ["reports-all"],
    queryFn: () => listReports({ data: {} }),
  });

  const allReports = useMemo(() => rawReports || [], [rawReports]);

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

    for (const r of allReports) {
      if (r.publisher) publishersSet.add(r.publisher);
      if (r.sourceName) publishersSet.add(r.sourceName);

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
    };
  }, [allReports]);

  // Filter and sort reports
  const filteredReports = useMemo(() => {
    const query = q.trim().toLowerCase();

    return allReports
      .filter((r) => {
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

        if (minQuality > 0 && r.qualityScore < minQuality) {
          return false;
        }

        if (onlyWithIocs && (r.iocCount || 0) === 0) {
          return false;
        }

        if (query) {
          const searchable = `${r.title} ${r.sourceName} ${r.publisher} ${r.url} ${r.canonicalUrl} ${r.excerpt} ${r.classification} ${r.resourceKind || ""} ${
            r.analysis?.threatActors?.join(" ") || ""
          } ${r.analysis?.malware?.join(" ") || ""} ${r.extractedEntities?.cves?.join(" ") || ""} ${
            r.iocs?.map((i) => i.value).join(" ") || ""
          }`.toLowerCase();

          if (!searchable.includes(query)) return false;
        }

        return true;
      })
      .sort((a, b) => {
        if (sortBy === "quality") return b.qualityScore - a.qualityScore;
        if (sortBy === "iocs") return (b.iocCount || 0) - (a.iocCount || 0);
        if (sortBy === "words") return (b.wordCount || 0) - (a.wordCount || 0);
        return new Date(b.ingestedAt).getTime() - new Date(a.ingestedAt).getTime();
      });
  }, [
    allReports,
    selectedKind,
    selectedActor,
    selectedMalware,
    selectedTactic,
    selectedPublisher,
    minQuality,
    onlyWithIocs,
    q,
    sortBy,
  ]);

  const activeFiltersCount = useMemo(() => {
    let count = 0;
    if (selectedActor !== "ALL") count++;
    if (selectedMalware !== "ALL") count++;
    if (selectedTactic !== "ALL") count++;
    if (selectedPublisher !== "ALL") count++;
    if (minQuality > 0) count++;
    if (onlyWithIocs) count++;
    return count;
  }, [selectedActor, selectedMalware, selectedTactic, selectedPublisher, minQuality, onlyWithIocs]);

  const resetFilters = () => {
    setSelectedActor("ALL");
    setSelectedMalware("ALL");
    setSelectedTactic("ALL");
    setSelectedPublisher("ALL");
    setMinQuality(0);
    setOnlyWithIocs(false);
    setQ("");
  };

  const { data: previewData, isLoading: isPreviewLoading } = useQuery({
    queryKey: ["report-pdf", previewReportId],
    queryFn: () => (previewReportId ? getReportPdf({ data: { id: previewReportId } }) : null),
    enabled: Boolean(previewReportId),
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
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">MongoDB Central Intelligence Store</p>
          <h1 className="mt-1 text-3xl font-medium tracking-tight">Intelligence Library</h1>
          <p className="mt-1 text-xs text-muted">
            Acquired adversary intelligence, normalized evidence, IOCs, and reconstructed attack chains stored in MongoDB Atlas.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative w-full md:w-80">
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

          <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
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
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Active Filter Badges Bar */}
      {activeFiltersCount > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-mono text-muted mr-1">Active filters:</span>
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
      <div className="mt-4 flex items-center justify-between text-xs text-muted">
        <span>
          Showing <strong className="text-fg">{filteredReports.length}</strong> of{" "}
          <strong className="text-fg">{allReports.length}</strong> intelligence records
        </span>
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
            <p className="text-sm">Querying MongoDB Central Intelligence Store…</p>
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

        {filteredReports.map((r) => {
          const actors = r.analysis?.threatActors || r.extractedEntities?.threatActors || [];
          const malware = r.analysis?.malware || r.extractedEntities?.malwareFamilies || [];
          const cves = r.extractedEntities?.cves || [];

          return (
            <div
              key={r.id}
              className="group rounded-xl border border-border bg-bg-elevated p-5 transition-colors hover:border-border/80 hover:bg-bg-subtle/40"
            >
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
                  <Badge tone="sage" className="gap-1">
                    <FileText className="size-2.5" /> High-Fidelity PDF
                  </Badge>
                </div>

                <span className="font-mono text-[11px] text-subtle tabular-nums">
                  {Math.round(r.qualityScore * 100)}% quality · {r.wordCount} words · {r.iocCount} IOCs
                </span>
              </div>

              <div className="mt-3 flex items-start justify-between gap-4">
                <Link to="/library/$reportId" params={{ reportId: r.id }} className="flex-1">
                  <h2 className="text-base font-medium leading-snug group-hover:text-accent transition-colors">
                    {r.title}
                  </h2>
                  <p className="mt-1.5 line-clamp-2 text-xs text-muted leading-relaxed">{r.excerpt}</p>
                </Link>

                <div className="flex shrink-0 items-center gap-2 pt-1">
                  <Button
                    size="sm"
                    variant="secondary"
                    className="h-8 gap-1.5 text-xs"
                    onClick={() => setPreviewReportId(r.id)}
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

                  <Link
                    to="/library/$reportId"
                    params={{ reportId: r.id }}
                    className="p-1 text-subtle hover:text-fg transition-colors"
                  >
                    <ArrowUpRight className="size-4" />
                  </Link>
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

              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2.5 font-mono text-[10px] text-subtle">
                <span>Domain: {r.sourceDomain || "Verified source"}</span>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setPreviewReportId(r.id)}
                    className="text-accent hover:underline flex items-center gap-1"
                  >
                    <FileText className="size-3" /> Preview Document & Evidence
                  </button>
                  <span>Ingested: {formatDateTime(r.ingestedAt)}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

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
                <div className="flex h-full items-center justify-center text-muted text-sm">
                  Loading high-fidelity PDF document representation...
                </div>
              ) : previewData?.rawHtml ? (
                <iframe
                  title="Document PDF Preview"
                  srcDoc={previewData.rawHtml}
                  className="size-full border-0 bg-white"
                  sandbox="allow-same-origin allow-scripts allow-popups"
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
    </AppShell>
  );
}
