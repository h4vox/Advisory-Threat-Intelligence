import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Bug,
  ChevronLeft,
  ChevronRight,
  Database,
  FileText,
  Fingerprint,
  Flame,
  Globe2,
  Hash,
  Layers,
  MapPin,
  Network,
  Shield,
  Terminal,
  Workflow,
  Zap,
} from "lucide-react";
import { useState, useRef, type ReactNode } from "react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { ActionButton, PageHeader, SectionCard, StatCard } from "@/components/layout/page";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { IdBadge } from "@/components/id-badge";
import { formatAuditId, formatOutcomeId, formatReportId, formatSourceId } from "@/lib/aie/ids";
import { formatDateTime } from "@/lib/aie/format";
import { getDashboard } from "@/lib/aie/server";
import type {
  ThreatRegionStats,
  TacticDistributionStats,
  MonitoredActorItem,
  CveVelocityItem,
  ThreatFlowItem,
  AttackHeatmapCell,
} from "@/lib/aie/types";
import { cn } from "@/lib/cn";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => getDashboard(),
    refetchInterval: 30000,
    staleTime: 30000,
    placeholderData: (previousData) => previousData,
  });

  // Every widget below renders only what the server computed from acquired
  // reports. There is deliberately no client-side fallback data: missing or
  // empty analytics render an honest empty state instead.
  const threatRegions: ThreatRegionStats[] = data?.threatRegions ?? [];
  const tacticDistribution: TacticDistributionStats[] = data?.tacticDistribution ?? [];
  const topThreatActors: MonitoredActorItem[] = data?.topThreatActors ?? [];
  const cveVelocity: CveVelocityItem[] = data?.cveVelocity ?? [];
  const threatFlows: ThreatFlowItem[] = data?.threatFlows ?? [];
  const attackHeatmap: AttackHeatmapCell[] = data?.attackHeatmap ?? [];
  const analyticsLoading = isLoading && !data;
  const topTacticNames = tacticDistribution.slice(0, 2).map((t) => t.name);

  const [activeRegion, setActiveRegion] = useState<ThreatRegionStats | null>(null);
  const [selectedFlowId, setSelectedFlowId] = useState<string>("");
  const actorCarouselRef = useRef<HTMLDivElement>(null);

  function scrollActors(direction: "left" | "right") {
    if (actorCarouselRef.current) {
      const offset = direction === "left" ? -340 : 340;
      actorCarouselRef.current.scrollBy({ left: offset, behavior: "smooth" });
    }
  }

  const activeFlow = threatFlows.find((f) => f.id === selectedFlowId) || threatFlows[0];

  return (
    <AppShell>
      <PageHeader
        title="Overview"
        eyebrow={
          <span className="inline-flex items-center gap-2">
            <span className="size-1.5 rounded-full bg-sage animate-pulse" />
            Continuous Autonomous Threat Acquisition · SOC Node
          </span>
        }
        description="Autonomous CTI crawler, heuristic TTP quality gate, evidence hashing and MITRE ATT&CK® mapping across acquired reports."
        actions={
          <>
            <ActionButton to="/matrix" icon={Layers} variant="outline">
              ATT&CK Matrix
            </ActionButton>
            <ActionButton to="/ingest" icon={Zap} variant="primary">
              Launch Crawler
            </ActionButton>
          </>
        }
      />
      <div className="space-y-6">
        {/* KPI row */}
        {error ? (
          <p className="text-sm text-danger">{error.message}</p>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              icon={Globe2}
              label="Threat sources"
              value={data?.sourceCount ?? "—"}
              hint={`${data?.enabledSources ?? "—"} active RSS / research feeds`}
              to="/sources"
            />
            <StatCard
              icon={Database}
              label="Reports stored"
              value={data?.acquiredCount ?? "—"}
              hint={`${data?.reportCount ?? "—"} total acquired in store`}
              to="/library"
            />
            <StatCard
              icon={Shield}
              label="Avg quality gate"
              value={data ? Math.round(data.avgQuality * 100) + "%" : "—"}
              hint="Heuristic TTP & simulation density"
              to="/library"
            />
            <StatCard
              icon={Fingerprint}
              label="IOCs harvested"
              value={data?.iocCount ?? "—"}
              hint="IPs, domains, CVEs, hashes (de-duplicated)"
              to="/library"
            />
          </div>
        )}
        {/* ========================================================================= */}
        {/* INTERACTIVE THREAT ACTOR GEOLOCATION ACTIVITY MAP & TACTIC DISTRIBUTION   */}
        {/* ========================================================================= */}
        <div className="grid gap-6 xl:grid-cols-12">
          {/* Global Threat Activity Map (7 cols) */}
          <SectionCard
            className="flex flex-col xl:col-span-7"
            bodyClassName={cardBody}
            title={<CardTitle icon={Globe2}>Global threat origin & targeting activity</CardTitle>}
            actions={
              <Badge tone="neutral" className="font-mono text-[10px]">
                {threatRegions.length > 0 ? "From Reports" : "Not Available Yet"}
              </Badge>
            }
          >
            <div>
              <p className="text-xs text-muted">
                Threat origin and targeting clusters, plotted only when geography is extracted from acquired reports.
              </p>
            </div>

            {/* Interactive World Vector Canvas */}
            <div className="relative mt-4 h-[250px] w-full overflow-hidden rounded-lg border border-border bg-bg p-1 select-none">
              <svg
                viewBox="0 0 950 320"
                className="h-full w-full"
                preserveAspectRatio="xMidYMid meet"
              >
                {/* Radar Coordinate Grid Lines */}
                <g className="opacity-30">
                  <line x1="0" y1="80" x2="950" y2="80" stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                  <line x1="0" y1="160" x2="950" y2="160" stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                  <line x1="0" y1="240" x2="950" y2="240" stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                  <line x1="190" y1="0" x2="190" y2="320" stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                  <line x1="380" y1="0" x2="380" y2="320" stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                  <line x1="570" y1="0" x2="570" y2="320" stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                  <line x1="760" y1="0" x2="760" y2="320" stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                </g>

                {/* Accurate Geographic Continents Silhouettes */}
                <g className="fill-bg-subtle/70 stroke-border/70 stroke-[1]">
                  {/* North America (Alaska, Canada, Continental US, Mexico, Central America) */}
                  <path
                    d="M 60,35 L 140,25 L 210,25 L 260,40 L 285,75 L 255,100 L 235,115 L 220,150 L 195,155 L 170,195 L 155,175 L 145,145 L 120,135 L 95,115 L 50,75 L 50,45 Z"
                  />
                  {/* Greenland */}
                  <path
                    d="M 285,15 L 345,12 L 335,45 L 290,40 Z"
                  />
                  {/* South America */}
                  <path
                    d="M 195,190 L 245,195 L 280,225 L 260,285 L 220,310 L 200,260 L 185,210 Z"
                  />
                  {/* Western & Central Europe, UK, Scandinavia */}
                  <path
                    d="M 410,40 L 440,35 L 480,50 L 485,85 L 450,105 L 415,95 L 400,65 Z M 455,20 L 480,18 L 490,45 L 465,45 Z M 395,45 L 415,40 L 410,60 L 390,55 Z"
                  />
                  {/* Africa & Madagascar */}
                  <path
                    d="M 425,115 L 510,115 L 540,155 L 525,215 L 480,270 L 455,265 L 415,180 L 415,135 Z M 545,230 L 555,225 L 550,255 L 540,250 Z"
                  />
                  {/* Eastern Europe, Russia & Northern Asia */}
                  <path
                    d="M 495,40 L 600,32 L 720,30 L 830,35 L 880,55 L 850,80 L 780,90 L 700,80 L 600,80 L 515,75 Z"
                  />
                  {/* East Asia, China, Japan Archipelago, Korean Peninsula */}
                  <path
                    d="M 670,85 L 770,85 L 830,105 L 810,145 L 750,160 L 710,180 L 690,155 L 675,125 Z M 840,90 L 855,110 L 845,135 L 835,120 Z"
                  />
                  {/* Middle East & South Asia */}
                  <path
                    d="M 515,110 L 575,110 L 605,135 L 640,145 L 630,190 L 600,170 L 555,165 L 520,140 Z"
                  />
                  {/* Australia & New Zealand */}
                  <path
                    d="M 735,200 L 825,200 L 840,240 L 810,265 L 750,260 L 725,230 Z M 855,255 L 865,250 L 860,275 L 850,270 Z"
                  />
                </g>

                {/* Threat Cluster Radar Markers & Labels */}
                {threatRegions.map((region) => {
                  const isSelected = activeRegion?.name === region.name;
                  const isCritical = region.threatLevel === "critical";
                  const isHigh = region.threatLevel === "high";

                  return (
                    <g
                      key={region.name}
                      className="cursor-pointer group"
                      onClick={() => setActiveRegion(region)}
                      onMouseEnter={() => setActiveRegion(region)}
                    >
                      {/* Radar Outer Ping */}
                      <circle
                        cx={region.x}
                        cy={region.y}
                        r={isSelected ? 13 : isCritical ? 10 : 7}
                        className={cn(
                          "fill-transparent transition-all",
                          isCritical
                            ? "stroke-danger/60 animate-pulse"
                            : isHigh
                              ? "stroke-warn/50"
                              : "stroke-sage/50",
                        )}
                        strokeWidth="1"
                      />
                      {/* Inner Radar Target Beacon */}
                      <circle
                        cx={region.x}
                        cy={region.y}
                        r={isSelected ? 6 : 4.5}
                        className={cn(
                          "transition-all",
                          isCritical
                            ? "fill-danger/25 stroke-danger"
                            : isHigh
                              ? "fill-warn/25 stroke-warn"
                              : "fill-sage/25 stroke-sage",
                        )}
                        strokeWidth="1.5"
                      />
                      {/* Core Dot */}
                      <circle
                        cx={region.x}
                        cy={region.y}
                        r={2}
                        className={cn(
                          isCritical ? "fill-danger" : isHigh ? "fill-warn" : "fill-sage",
                        )}
                      />
                      {/* Regional Label */}
                      <text
                        x={region.x + 9}
                        y={region.y + 3.5}
                        className={cn(
                          "font-mono text-[9px] font-semibold select-none pointer-events-none transition-colors",
                          isSelected ? "fill-fg font-bold" : "fill-fg/80 group-hover:fill-fg",
                        )}
                      >
                        {region.name} ({region.count ?? 0})
                      </text>
                    </g>
                  );
                })}
              </svg>

              {threatRegions.length === 0 && (
                <div className="absolute inset-0 flex items-center justify-center bg-bg/60 backdrop-blur-[1px]">
                  <EmptyState
                    icon={MapPin}
                    title={analyticsLoading ? "Loading report analytics…" : "No geography is extracted from reports yet"}
                    detail={
                      analyticsLoading
                        ? undefined
                        : "Reports do not currently carry origin or target-country fields, so no regions are plotted."
                    }
                  />
                </div>
              )}

              {/* Active Region Threat Telemetry HUD Overlay */}
              {activeRegion && (
                <div className="absolute bottom-2 left-2 right-2 sm:right-auto sm:max-w-md rounded-lg border border-border bg-bg-elevated/95 p-3.5 shadow-xl backdrop-blur-md text-xs font-mono animate-in fade-in zoom-in-95 duration-100 z-10">
                  <div className="flex items-center justify-between gap-2 border-b border-border pb-2 mb-2">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={cn(
                          "size-2 rounded-full",
                          activeRegion.threatLevel === "critical"
                            ? "bg-danger animate-pulse"
                            : activeRegion.threatLevel === "high"
                              ? "bg-warn"
                              : "bg-sage",
                        )}
                      />
                      <span className="font-bold text-fg text-xs uppercase tracking-wider">
                        {activeRegion.flag ? `${activeRegion.flag} ` : ""}{activeRegion.name}
                      </span>
                    </div>
                    <Badge
                      tone={
                        activeRegion.threatLevel === "critical"
                          ? "danger"
                          : activeRegion.threatLevel === "high"
                            ? "warn"
                            : "sage"
                      }
                      className="text-[9px] uppercase font-bold px-1.5 py-0.5"
                    >
                      {activeRegion.threatLevel} · {activeRegion.count ?? 0} reports
                    </Badge>
                  </div>
                  <div className="space-y-1.5 text-[11px] text-muted">
                    {activeRegion.originCountry && (
                      <div>
                        <span className="text-subtle">Attribution Origin:</span>{" "}
                        <span className="text-fg font-medium">{activeRegion.originCountry}</span>
                      </div>
                    )}
                    <div>
                      <span className="text-subtle">Primary Threat Actors:</span>{" "}
                      <span className="text-fg font-medium">{(activeRegion.actors ?? []).join(", ")}</span>
                    </div>
                    {activeRegion.targetCountries && activeRegion.targetCountries.length > 0 && (
                      <div>
                        <span className="text-subtle">Targeted Nations:</span>{" "}
                        <span className="text-fg">{(activeRegion.targetCountries ?? []).join(", ")}</span>
                      </div>
                    )}
                    <div>
                      <span className="text-subtle">Targeted Sectors:</span>{" "}
                      <span className="text-fg">{(activeRegion.sectors ?? []).join(", ")}</span>
                    </div>
                    <div className="truncate">
                      <span className="text-subtle">Top TTP Vector:</span>{" "}
                      <span className="text-fg">{activeRegion.topVector}</span>
                    </div>
                    <div className="pt-2 mt-2 border-t border-border flex items-center justify-between">
                      <Link
                        to="/library"
                        search={{ q: activeRegion.actors?.[0] || activeRegion.name }}
                        className="inline-flex items-center gap-1 text-[11px] text-accent font-semibold hover:underline"
                      >
                        <span>Filter {activeRegion.name} Reports in Library</span>
                        <ArrowRight className="size-3" />
                      </Link>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setActiveRegion(null);
                        }}
                        className="text-[10px] text-subtle hover:text-fg font-mono px-1 py-0.5 rounded hover:bg-bg-subtle"
                      >
                        [Dismiss]
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className={cn("mt-3 flex items-center justify-between text-xs text-subtle", threatRegions.length === 0 && "invisible")}>
              <span>Threat Levels: <span className="text-danger font-mono font-bold">● Critical</span> · <span className="text-warn font-mono font-bold">● High</span> · <span className="text-sage font-mono font-bold">● Medium</span></span>
              <span className="font-mono text-[11px]">Click nodes to inspect clusters</span>
            </div>
          </SectionCard>

          {/* Tactical Phase Coverage Bar Chart (5 cols) */}
          <SectionCard
            className="flex flex-col xl:col-span-5"
            bodyClassName={cardBody}
            title={<CardTitle icon={Layers}>MITRE ATT&CK phase density</CardTitle>}
            actions={
              <Link to="/matrix" className={cardLink}>
                <span>Open Matrix</span>
                <ArrowRight className="size-3" />
              </Link>
            }
          >
            <div>
              <p className="text-xs text-muted">
                Attack-chain steps mapped to each ATT&CK tactic across acquired reports, relative to the busiest tactic.
              </p>
            </div>

            {/* Tactical Phase Bars */}
            <div className="mt-4 space-y-2.5">
              {tacticDistribution.length === 0 && (
                <EmptyState
                  icon={Layers}
                  title={analyticsLoading ? "Loading report analytics…" : "No ATT&CK tactics mapped yet"}
                  detail={analyticsLoading ? undefined : "Bars appear once acquired reports include an analyzed attack chain."}
                />
              )}
              {tacticDistribution.slice(0, 7).map((phase) => (
                <div key={phase.id} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium text-fg">{phase.name}</span>
                    <span className="font-mono text-[11px] text-muted">
                      {phase.count ?? 0} steps · {phase.reportCount ?? 0} {(phase.reportCount ?? 0) === 1 ? "report" : "reports"} ({phase.pct ?? 0}%)
                    </span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-bg">
                    <div
                      className="h-full bg-accent transition-all duration-300"
                      style={{ width: `${phase.pct}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-xs">
              <span className="text-muted">
                {topTacticNames.length > 0
                  ? `Most observed: ${topTacticNames.join(" & ")}`
                  : "No tactic data from reports yet"}
              </span>
              <Link to="/matrix" className="font-mono text-muted hover:text-fg hover:underline text-[11px]">
                Open Full Matrix →
              </Link>
            </div>
          </SectionCard>
        </div>

        {/* ========================================================================= */}
        {/* ACTIVE ADVERSARY PROFILES & MALWARE FAMILIES STRIP                        */}
        {/* ========================================================================= */}
        {/* ========================================================================= */}
        {/* MONITORED THREAT ACTORS & OFFENSIVE TOOLSETS - HORIZONTAL SCROLL CAROUSEL */}
        {/* ========================================================================= */}
        <SectionCard
          bodyClassName="pt-3"
          title={<CardTitle icon={Flame} iconClassName="text-warn">Monitored threat actors & offensive toolsets</CardTitle>}
          actions={
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-[11px] text-muted">
                {topThreatActors.length} {topThreatActors.length === 1 ? "actor" : "actors"} named in acquired reports · Ranked by report count
              </span>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => scrollActors("left")}
                  aria-label="Scroll left"
                  className="rounded border border-border bg-bg p-1.5 text-muted hover:text-fg hover:bg-bg-subtle transition-colors cursor-pointer"
                >
                  <ChevronLeft className="size-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => scrollActors("right")}
                  aria-label="Scroll right"
                  className="rounded border border-border bg-bg p-1.5 text-muted hover:text-fg hover:bg-bg-subtle transition-colors cursor-pointer"
                >
                  <ChevronRight className="size-3.5" />
                </button>
              </div>
            </div>
          }
        >

          <div
            ref={actorCarouselRef}
            className="flex gap-3 overflow-x-auto pb-2 pt-1 scroll-smooth scrollbar-none"
          >
            {topThreatActors.length === 0 && (
              <div className="w-full rounded-lg border border-dashed border-border bg-bg">
                <EmptyState
                  icon={Flame}
                  title={analyticsLoading ? "Loading report analytics…" : "No threat actors named in reports yet"}
                  detail={
                    analyticsLoading
                      ? undefined
                      : "Actors appear here once acquired reports attribute activity to a named group or tool."
                  }
                />
              </div>
            )}
            {topThreatActors.map((actor) => (
              <Link
                key={actor.name}
                to="/library"
                search={{ q: actor.name }}
                className="group relative flex-none w-[285px] flex flex-col justify-between rounded-lg border border-border bg-bg p-3.5 hover:border-border-strong hover:bg-bg-subtle/70 transition-all shadow-2xs cursor-pointer"
              >
                <div>
                  <div className="flex items-center justify-between gap-1">
                    <div className="flex items-center gap-1.5">
                      {actor.reference?.flag && (
                        <span className="text-sm" title={`${actor.reference.originCountry} (reference profile)`}>
                          {actor.reference.flag}
                        </span>
                      )}
                      <Badge
                        tone={
                          actor.badge === "APT"
                            ? "danger"
                            : actor.badge === "RaaS"
                              ? "warn"
                              : actor.badge === "TOOL"
                                ? "accent"
                                : "neutral"
                        }
                        className="font-mono text-[9px] px-1.5 py-0.2 uppercase font-bold"
                      >
                        {actor.badge}
                      </Badge>
                    </div>
                    <span className="font-mono text-[10px] text-muted font-semibold">
                      {actor.reportCount} {actor.reportCount === 1 ? "report" : "reports"}
                    </span>
                  </div>

                  <div className="mt-2.5 flex items-center justify-between">
                    <div className="text-sm font-bold text-fg leading-tight group-hover:text-accent transition-colors">
                      {actor.name}
                    </div>
                  </div>

                  {actor.reference ? (
                    <>
                      <div className="mt-1 text-[11px] text-subtle truncate" title={actor.reference.originCountry}>
                        {actor.reference.originCountry} · {actor.reference.type}
                      </div>
                      <div className="mt-2 text-[10px] font-mono text-muted line-clamp-3 leading-relaxed bg-bg-subtle/50 p-1.5 rounded border border-border/40">
                        <span className="uppercase tracking-wider text-[9px] text-subtle font-semibold">Reference profile · </span>
                        {actor.reference.focus}
                      </div>
                    </>
                  ) : (
                    <div className="mt-1 text-[11px] text-subtle truncate">
                      No reference profile in catalog
                    </div>
                  )}
                </div>

                <div className="mt-3 pt-2 border-t border-border space-y-1.5 text-[10px] font-mono">
                  <div className="flex items-center justify-between text-subtle">
                    <span className="truncate max-w-[190px]" title="Reference profile, not observed in reports">
                      {actor.reference && actor.reference.targetSectors.length > 0
                        ? `Ref. sectors: ${actor.reference.targetSectors.slice(0, 2).join(", ")}`
                        : "Open matching reports"}
                    </span>
                    <ArrowUpRight className="size-3 text-subtle group-hover:text-fg group-hover:translate-x-0.5 transition-transform shrink-0" />
                  </div>
                  {actor.associatedTools && actor.associatedTools.length > 0 && (
                    <div className="truncate text-muted" title="Malware/tools named in the same reports">
                      Co-observed: {actor.associatedTools.join(", ")}
                    </div>
                  )}
                </div>
              </Link>
            ))}
          </div>
        </SectionCard>

        {/* ========================================================================= */}
        {/* WIDGET 1: MITRE ATT&CK EXECUTION INTENSITY HEATMAP                         */}
        {/* ========================================================================= */}
        <SectionCard
          bodyClassName="pt-3"
          title={<CardTitle icon={Layers}>MITRE ATT&CK execution intensity heatmap</CardTitle>}
          actions={
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-[11px] text-muted flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-danger animate-pulse" />
                <span>Heavy (&gt;80%)</span>
                <span className="size-2 rounded-full bg-warn ml-2" />
                <span>Elevated (&gt;65%)</span>
                <span className="size-2 rounded-full bg-sage ml-2" />
                <span>Standard</span>
              </span>
              <Link to="/matrix" className={cardLink}>
                <span>Full Matrix</span>
                <ArrowRight className="size-3" />
              </Link>
            </div>
          }
        >
          <p className="mb-4 text-xs text-muted">
            Attack-chain steps and technique IDs per tactic, extracted from acquired reports. Intensity is relative to the busiest tactic.
          </p>

          {attackHeatmap.length === 0 && (
            <div className="rounded-lg border border-dashed border-border bg-bg">
              <EmptyState
                icon={Layers}
                title={analyticsLoading ? "Loading report analytics…" : "No techniques mapped from reports yet"}
                detail={analyticsLoading ? undefined : "The heatmap fills in as reports with analyzed attack chains are acquired."}
              />
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-8">
            {attackHeatmap.map((cell) => {
              const isHigh = cell.intensity >= 80;
              const isMedium = cell.intensity >= 65;
              return (
                <div
                  key={cell.tacticId}
                  className="rounded-lg border border-border bg-bg p-3 flex flex-col justify-between hover:border-border-strong hover:bg-bg-subtle/50 transition-all group"
                >
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-[10px] text-subtle font-semibold">{cell.tacticId}</span>
                      <span
                        className={cn(
                          "font-mono text-[10px] font-bold px-1.5 py-0.5 rounded",
                          isHigh
                            ? "bg-danger/15 text-danger border border-danger/30"
                            : isMedium
                              ? "bg-warn/15 text-warn border border-warn/30"
                              : "bg-sage/15 text-sage border border-sage/30",
                        )}
                      >
                        {cell.intensity}%
                      </span>
                    </div>
                    <div className="text-xs font-bold text-fg leading-tight truncate group-hover:text-accent transition-colors" title={cell.tacticName}>
                      {cell.tacticName}
                    </div>
                    <div className="mt-1 font-mono text-[10px] text-muted">
                      {cell.hitCount} steps · {cell.techniqueCount} techs
                    </div>

                    <div className="mt-2 h-1 w-full rounded-full bg-bg-subtle overflow-hidden">
                      <div
                        className={cn(
                          "h-full rounded-full transition-all duration-500",
                          isHigh ? "bg-danger" : isMedium ? "bg-warn" : "bg-sage",
                        )}
                        style={{ width: `${cell.intensity}%` }}
                      />
                    </div>
                  </div>

                  <div className="mt-3 pt-2 border-t border-border/80 space-y-1.5">
                    <span className="text-[9px] font-mono uppercase tracking-wider text-subtle block">
                      Top Techniques
                    </span>
                    {cell.topTechniques.length === 0 && (
                      <span className="block text-[10px] font-mono text-subtle">No technique IDs</span>
                    )}
                    {cell.topTechniques.map((tech) => (
                      <Link
                        key={tech.id}
                        to="/matrix"
                        className="flex items-center justify-between text-[10px] font-mono text-muted hover:text-fg hover:underline truncate"
                        title={`${tech.id} - ${tech.name}`}
                      >
                        <span className="truncate max-w-[85px]">{tech.id}</span>
                        <span className="text-subtle shrink-0">({tech.count ?? 0})</span>
                      </Link>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </SectionCard>

        {/* ========================================================================= */}
        {/* WIDGET 2: ADVERSARY THREAT FLOW & ATTACK PATH GRAPH MAP                   */}
        {/* ========================================================================= */}
        <SectionCard
          bodyClassName="pt-3"
          title={<CardTitle icon={Network}>Adversary campaign & infrastructure relational flow</CardTitle>}
          actions={
            threatFlows.length > 0 ? (
            /* Flow Selector Tabs */
            <div className="flex flex-wrap items-center gap-1.5">
              {threatFlows.map((flow) => (
                <button
                  key={flow.id}
                  type="button"
                  onClick={() => setSelectedFlowId(flow.id)}
                  className={cn(
                    "px-2.5 py-1 text-xs font-mono rounded border transition-all cursor-pointer",
                    selectedFlowId === flow.id
                      ? "border-accent bg-accent/15 text-fg font-semibold shadow-xs"
                      : "border-border bg-bg text-muted hover:text-fg hover:border-border-strong",
                  )}
                >
                  {flow.origin}
                </button>
              ))}
            </div>
            ) : undefined
          }
        >
          <p className="mb-4 text-xs text-muted">
            Multi-stage operational flow: Threat Origin & Actors ➔ Ingress Vectors ➔ Weaponized Tools ➔ Targeted Sectors.
          </p>

          {!activeFlow && (
            <div className="rounded-lg border border-dashed border-border bg-bg">
              <EmptyState
                icon={Network}
                title={analyticsLoading ? "Loading report analytics…" : "No campaign flows correlated from reports yet"}
                detail={
                  analyticsLoading
                    ? undefined
                    : "Reports do not yet carry the origin, ingress vector and target-sector fields needed to build these flows."
                }
              />
            </div>
          )}

          {/* Active Flow Graph Visualizer */}
          {activeFlow && (
            <div className="rounded-lg border border-border bg-bg p-4">
              <div className="flex items-center justify-between border-b border-border pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <Badge tone="warn" className="font-mono text-[10px] uppercase">
                    Active Flow Vector
                  </Badge>
                  <span className="text-xs font-bold text-fg font-mono">{activeFlow.origin}</span>
                </div>
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="text-subtle">Execution Intensity:</span>
                  <Badge tone={activeFlow.intensity >= 90 ? "danger" : "warn"} className="font-bold">
                    {activeFlow.intensity}%
                  </Badge>
                </div>
              </div>

              {/* 4-Stage Horizontal Node Pipeline */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 relative">
                {/* Stage 1: Origin & Threat Actors */}
                <div className="rounded-md border border-border bg-bg-elevated/70 p-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-1.5 mb-2">
                      <span className="font-mono text-[10px] font-bold text-accent uppercase tracking-wider">
                        Stage 1 · Origin & Actors
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      {(activeFlow.actors ?? []).map((actor) => (
                        <Link
                          key={actor}
                          to="/library"
                          search={{ q: actor }}
                          className="flex items-center justify-between rounded bg-bg px-2 py-1 text-xs font-medium text-fg hover:bg-bg-subtle hover:text-accent transition-colors border border-border/60"
                        >
                          <span>{actor}</span>
                          <ArrowRight className="size-3 text-subtle" />
                        </Link>
                      ))}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-subtle mt-3 pt-2 border-t border-border">
                    Sovereign / Cartel Origin
                  </span>
                </div>

                {/* Stage 2: Ingress & Vector */}
                <div className="rounded-md border border-border bg-bg-elevated/70 p-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-1.5 mb-2">
                      <span className="font-mono text-[10px] font-bold text-warn uppercase tracking-wider">
                        Stage 2 · Ingress Vectors
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      {(activeFlow.vectors ?? []).map((vec) => (
                        <div
                          key={vec}
                          className="rounded bg-bg px-2 py-1 text-xs text-muted border border-border/60 truncate"
                          title={vec}
                        >
                          {vec}
                        </div>
                      ))}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-subtle mt-3 pt-2 border-t border-border">
                    Initial Access & Foothold
                  </span>
                </div>

                {/* Stage 3: Offensive Toolsets */}
                <div className="rounded-md border border-border bg-bg-elevated/70 p-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-1.5 mb-2">
                      <span className="font-mono text-[10px] font-bold text-danger uppercase tracking-wider">
                        Stage 3 · Weaponized Tools
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      {(activeFlow.tools ?? []).map((tool) => (
                        <Link
                          key={tool}
                          to="/library"
                          search={{ q: tool }}
                          className="flex items-center justify-between rounded bg-bg px-2 py-1 text-xs font-mono font-medium text-fg hover:bg-bg-subtle hover:text-danger transition-colors border border-border/60"
                        >
                          <span className="truncate">{tool}</span>
                          <Terminal className="size-3 text-subtle shrink-0" />
                        </Link>
                      ))}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-subtle mt-3 pt-2 border-t border-border">
                    Payload & C2 Infrastructure
                  </span>
                </div>

                {/* Stage 4: Targeted Critical Sectors */}
                <div className="rounded-md border border-border bg-bg-elevated/70 p-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-1.5 mb-2">
                      <span className="font-mono text-[10px] font-bold text-sage uppercase tracking-wider">
                        Stage 4 · Targeted Sectors
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      {(activeFlow.targets ?? []).map((tgt) => (
                        <div
                          key={tgt}
                          className="rounded bg-bg px-2 py-1 text-xs text-fg border border-border/60 truncate font-medium"
                          title={tgt}
                        >
                          {tgt}
                        </div>
                      ))}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-subtle mt-3 pt-2 border-t border-border">
                    Impact & Sector Blast Radius
                  </span>
                </div>
              </div>

              {activeFlow.actors.length > 0 && (
                <div className="mt-3 pt-3 border-t border-border flex flex-wrap items-center justify-end text-xs text-muted">
                  <Link
                    to="/library"
                    search={{ q: activeFlow.actors[0] }}
                    className="font-mono text-accent hover:underline flex items-center gap-1 text-[11px]"
                  >
                    <span>Query {activeFlow.actors[0]} Reports in Library</span>
                    <ArrowRight className="size-3" />
                  </Link>
                </div>
              )}
            </div>
          )}
        </SectionCard>

        {/* ========================================================================= */}
        {/* WIDGET 3: EXPLOITED CVES & VULNERABILITY VELOCITY GAUGE                   */}
        {/* ========================================================================= */}
        <SectionCard
          bodyClassName="pt-3"
          title={<CardTitle icon={Bug} iconClassName="text-danger">CVEs referenced in acquired reports</CardTitle>}
          actions={
            <Link to="/library" className={cardLink}>
              <span>Inspect All CVEs in Library</span>
              <ArrowRight className="size-3" />
            </Link>
          }
        >
          <p className="mb-4 text-xs text-muted">
            Ranked by number of reports citing each CVE. CVSS and exploitation status, where shown, are reference values from a built-in catalog, not observed.
          </p>

          {cveVelocity.length === 0 && (
            <div className="rounded-lg border border-dashed border-border bg-bg">
              <EmptyState
                icon={Bug}
                title={analyticsLoading ? "Loading report analytics…" : "No CVEs referenced in reports yet"}
                detail={analyticsLoading ? undefined : "CVE identifiers extracted from acquired reports will be listed here."}
              />
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {cveVelocity.slice(0, 8).map((cve) => {
              const ref = cve.reference;
              const isCrit = (ref?.cvss ?? 0) >= 9.0;
              return (
                <Link
                  key={cve.cveId}
                  to="/library"
                  search={{ q: cve.cveId }}
                  className="rounded-lg border border-border bg-bg p-3.5 hover:border-border-strong hover:bg-bg-subtle transition-all flex flex-col justify-between group cursor-pointer"
                >
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-2">
                      <span className="font-mono text-xs font-bold text-fg group-hover:text-accent transition-colors">
                        {cve.cveId}
                      </span>
                      {ref && (
                        <div className="flex items-center gap-1">
                          <Badge
                            tone={isCrit ? "danger" : "warn"}
                            className="font-mono text-[9px] font-bold px-1.5 py-0.5"
                            title="Reference CVSS from built-in catalog"
                          >
                            Ref CVSS {ref.cvss}
                          </Badge>
                        </div>
                      )}
                    </div>

                    <div className="text-xs font-medium text-fg leading-snug line-clamp-2">
                      {ref?.vendorProduct ?? cve.sampleReportTitle ?? "Referenced in acquired reports"}
                    </div>

                    <div className="mt-2 flex items-center gap-2 font-mono text-[10px]">
                      {ref && (
                        <>
                          <span className="flex items-center gap-1" title="Reference status from built-in catalog, not observed">
                            <span
                              className={cn(
                                "size-1.5 rounded-full",
                                ref.exploitStatus === "In the Wild"
                                  ? "bg-danger"
                                  : ref.exploitStatus === "Weaponized"
                                    ? "bg-warn"
                                    : "bg-sage",
                              )}
                            />
                            <span className="text-muted">Ref: {ref.exploitStatus}</span>
                          </span>
                          <span className="text-subtle">·</span>
                        </>
                      )}
                      <span className="text-muted">
                        {cve.reportCount} {cve.reportCount === 1 ? "report" : "reports"}
                      </span>
                    </div>
                  </div>

                  <div className="mt-3 pt-2 border-t border-border flex items-center justify-between text-[10px] font-mono text-subtle">
                    <span className="truncate max-w-[170px]">
                      {cve.actors?.slice(0, 2).join(", ") || "No actor attributed"}
                    </span>
                    <ArrowUpRight className="size-3 text-subtle group-hover:text-fg group-hover:translate-x-0.5 transition-transform shrink-0" />
                  </div>
                </Link>
              );
            })}
          </div>
        </SectionCard>

        {/* ========================================================================= */}
        {/* RECENTLY ACQUIRED INTELLIGENCE & INGEST AUDIT LOG                         */}
        {/* ========================================================================= */}
        <div className="grid gap-6 lg:grid-cols-5">
          {/* Recently Acquired Reports (3 cols) */}
          <SectionCard
            className="min-w-0 overflow-hidden lg:col-span-3"
            bodyClassName="px-0 pb-0 pt-4"
            title={<CardTitle icon={FileText}>Recently acquired intelligence</CardTitle>}
            actions={
              <Link to="/library" className={cardLink}>
                <span>Open Library ({data?.acquiredCount ?? "—"})</span>
                <ArrowRight className="size-3" />
              </Link>
            }
          >
            <div className="divide-y divide-border border-t border-border">
              {isLoading && (
                <div className="flex flex-col items-center justify-center py-10 text-muted">
                  <ActivitySpinner size="md" className="text-accent mb-2" />
                  <p className="text-xs">Loading intelligence store…</p>
                </div>
              )}
              {data?.recent.map((r) => (
                <Link
                  key={r.id}
                  to="/library"
                  search={{ selected: r.id }}
                  className="flex items-start justify-between gap-4 px-5 py-4 transition-colors hover:bg-bg-subtle"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <IdBadge id={formatReportId(r.id)} category="report" size="xs" prefixLabel="ID" />
                      {r.sourceId && (
                        <IdBadge id={formatSourceId(r.sourceId, r.sourceName)} category="source" size="xs" prefixLabel="SRC" />
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="neutral">{r.sourceName}</Badge>
                      <Badge tone="accent">{r.classification}</Badge>
                      <Badge tone={r.status === "acquired" ? "sage" : "warn"}>{r.status}</Badge>
                      <Badge tone="sage">PDF Ready</Badge>
                    </div>
                    <div className="mt-2 text-sm font-semibold leading-snug text-fg">{r.title}</div>
                    <p className="mt-1 line-clamp-2 text-xs text-muted leading-relaxed">{r.excerpt}</p>
                  </div>
                  <ArrowUpRight className="mt-1 size-4 shrink-0 text-subtle" />
                </Link>
              ))}
            </div>
          </SectionCard>

          {/* Ingest Audit Log & Pipeline Hints (2 cols) */}
          <SectionCard
            className="min-w-0 lg:col-span-2"
            bodyClassName="pt-4"
            title={<CardTitle icon={Activity}>Crawl & ingest audit</CardTitle>}
            actions={<span className="font-mono text-xs text-subtle">Live Pipeline</span>}
          >
            <ul className="space-y-2">
              {data?.events.map((e) => {
                const outcomeMeta = formatOutcomeId(e.outcome, e.reportId || e.id, e.url);
                return (
                  <li key={e.id} className="rounded-lg border border-border bg-bg px-4 py-3">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        <IdBadge id={formatAuditId(e.id)} category="audit" size="xs" prefixLabel="AUD" />
                        <IdBadge
                          id={outcomeMeta.id}
                          category={outcomeMeta.category}
                          tone={outcomeMeta.tone}
                          size="xs"
                          label={e.outcome}
                        />
                      </div>
                      <span className="font-mono text-[10px] text-subtle">
                        {formatDateTime(e.createdAt)}
                      </span>
                    </div>
                    <p className="mt-2 truncate font-mono text-xs text-fg">{e.url}</p>
                    {e.detail ? <p className="mt-1 text-xs text-muted">{e.detail}</p> : null}
                  </li>
                );
              })}
            </ul>

            <div className="mt-5 space-y-2 border-t border-border pt-4">
              <span className="font-mono text-[10px] uppercase font-bold text-subtle tracking-wider block mb-2">
                Pipeline Security & Integrity Gates
              </span>
              <Hint icon={Workflow} text="Permalinks discriminator rejects category/index pages automatically." />
              <Hint icon={Hash} text="Cryptographic SHA-256 evidence hashing for raw bytes and clean text." />
              <Hint icon={Fingerprint} text="Regex IOC harvest with MITRE ATT&CK technique extraction." />
              <Hint icon={Shield} text="All external content is sanitized and isolated as untrusted CTI." />
            </div>
          </SectionCard>
        </div>
      </div>
    </AppShell>
  );
}

const cardBody = "flex flex-1 flex-col justify-between pt-3";
const cardLink = "inline-flex items-center gap-1 font-mono text-xs text-muted hover:text-fg hover:underline";

function CardTitle({
  icon: Icon,
  iconClassName,
  children,
}: {
  icon: typeof Hash;
  iconClassName?: string;
  children: ReactNode;
}) {
  return (
    <span className="flex items-center gap-2">
      <Icon className={cn("size-4 shrink-0 text-subtle", iconClassName)} strokeWidth={1.75} />
      <span>{children}</span>
    </span>
  );
}

function EmptyState({
  icon: Icon,
  title,
  detail,
}: {
  icon: typeof Hash;
  title: string;
  detail?: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-1.5 px-4 py-8 text-center">
      <Icon className="size-5 text-subtle/60" strokeWidth={1.75} />
      <p className="text-xs font-semibold text-fg">{title}</p>
      {detail && <p className="max-w-sm text-[11px] leading-relaxed text-muted">{detail}</p>}
    </div>
  );
}

function Hint({ icon: Icon, text }: { icon: typeof Hash; text: string }) {
  return (
    <div className="flex gap-2.5 rounded-md text-xs leading-relaxed text-muted">
      <Icon className="mt-0.5 size-3.5 shrink-0 text-subtle" strokeWidth={1.75} />
      <span>{text}</span>
    </div>
  );
}
