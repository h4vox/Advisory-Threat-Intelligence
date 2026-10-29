import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Bug,
  ChevronLeft,
  ChevronRight,
  Crosshair,
  Database,
  FileText,
  Fingerprint,
  Globe2,
  Hash,
  Layers,
  MapPin,
  Network,
  Shield,
  Skull,
  Terminal,
  Users,
  Workflow,
  Wrench,
  Zap,
} from "lucide-react";
import { useState, useRef, type ReactNode } from "react";
import { AppShell } from "@/components/app-shell";
import { EmptyState, Meter, StatusChip, StatusDot, type Tone } from "@/components/ui/primitives";
import { ActionButton, PageHeader, SectionCard, SegmentedTabs, StatCard } from "@/components/layout/page";
import { DataSourceNotice } from "@/components/layout/data-source-notice";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { DocTypeBadge, EntityChip, EntityIcon, entityMeta, type EntityKind } from "@/components/ui/entity";
import { IdBadge } from "@/components/id-badge";
import { formatAuditId, formatOutcomeId, formatReportId, formatSourceId } from "@/lib/aie/ids";
import { formatDateTime } from "@/lib/aie/format";
import { formatDate as formatShortDate } from "@/components/library/report-utils";
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
        description="Autonomous CTI crawler, heuristic TTP quality gate, evidence hashing and MITRE ATT&CK® mapping across acquired reports."
        actions={
          <>
            <ActionButton to="/matrix" icon={Layers} variant="outline">
              ATT&CK matrix
            </ActionButton>
            <ActionButton to="/ingest" icon={Zap} variant="primary">
              Launch crawler
            </ActionButton>
          </>
        }
      />
      <div className="space-y-6">
        <DataSourceNotice />
        {/* KPI row */}
        {error ? (
          <p className="text-sm text-danger">{error.message}</p>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              icon={Globe2}
              kind="source"
              label="Threat sources"
              value={data?.sourceCount ?? "—"}
              hint={`${data?.enabledSources ?? "—"} active RSS / research feeds`}
              to="/sources"
            />
            <StatCard
              icon={Database}
              kind="advisory"
              label="Reports stored"
              value={data?.acquiredCount ?? "—"}
              hint={`${data?.reportCount ?? "—"} total acquired in store`}
              to="/library"
            />
            <StatCard
              icon={Shield}
              kind="emulation"
              label="Avg quality gate"
              value={data ? Math.round(data.avgQuality * 100) + "%" : "—"}
              hint="Heuristic TTP & simulation density"
              to="/library"
            />
            <StatCard
              icon={Fingerprint}
              kind="ioc"
              label="IOCs harvested"
              value={data?.iocCount ?? "—"}
              hint="IPs, domains, CVEs, hashes (de-duplicated)"
              to="/library"
            />
          </div>
        )}

        {/* Geography map + tactic distribution */}
        <div className="grid gap-6 xl:grid-cols-12">
          <SectionCard
            className="flex flex-col xl:col-span-7"
            bodyClassName={cardBody}
            title="Global threat origin & targeting activity"
            icon={Globe2}
            iconKind="flow"
            actions={<StatusChip>{threatRegions.length > 0 ? "From reports" : "Not available yet"}</StatusChip>}
          >
            <p className="text-sm text-muted">
              Threat origin and targeting clusters, plotted only when geography is extracted from acquired reports.
            </p>

            <div className="relative mt-4 h-[260px] w-full select-none overflow-hidden rounded-lg bg-bg p-1">
              <svg viewBox="0 0 950 320" className="h-full w-full" preserveAspectRatio="xMidYMid meet">
                <g className="opacity-30">
                  {[80, 160, 240].map((y) => (
                    <line key={y} x1="0" y1={y} x2="950" y2={y} stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                  ))}
                  {[190, 380, 570, 760].map((x) => (
                    <line key={x} x1={x} y1="0" x2={x} y2="320" stroke="currentColor" strokeDasharray="2 4" className="text-border" />
                  ))}
                </g>

                {/* Continent silhouettes */}
                <g className="fill-bg-subtle/70 stroke-border/70 stroke-[1]">
                  <path d="M 60,35 L 140,25 L 210,25 L 260,40 L 285,75 L 255,100 L 235,115 L 220,150 L 195,155 L 170,195 L 155,175 L 145,145 L 120,135 L 95,115 L 50,75 L 50,45 Z" />
                  <path d="M 285,15 L 345,12 L 335,45 L 290,40 Z" />
                  <path d="M 195,190 L 245,195 L 280,225 L 260,285 L 220,310 L 200,260 L 185,210 Z" />
                  <path d="M 410,40 L 440,35 L 480,50 L 485,85 L 450,105 L 415,95 L 400,65 Z M 455,20 L 480,18 L 490,45 L 465,45 Z M 395,45 L 415,40 L 410,60 L 390,55 Z" />
                  <path d="M 425,115 L 510,115 L 540,155 L 525,215 L 480,270 L 455,265 L 415,180 L 415,135 Z M 545,230 L 555,225 L 550,255 L 540,250 Z" />
                  <path d="M 495,40 L 600,32 L 720,30 L 830,35 L 880,55 L 850,80 L 780,90 L 700,80 L 600,80 L 515,75 Z" />
                  <path d="M 670,85 L 770,85 L 830,105 L 810,145 L 750,160 L 710,180 L 690,155 L 675,125 Z M 840,90 L 855,110 L 845,135 L 835,120 Z" />
                  <path d="M 515,110 L 575,110 L 605,135 L 640,145 L 630,190 L 600,170 L 555,165 L 520,140 Z" />
                  <path d="M 735,200 L 825,200 L 840,240 L 810,265 L 750,260 L 725,230 Z M 855,255 L 865,250 L 860,275 L 850,270 Z" />
                </g>

                {threatRegions.map((region) => {
                  const isSelected = activeRegion?.name === region.name;
                  const isCritical = region.threatLevel === "critical";
                  const isHigh = region.threatLevel === "high";
                  return (
                    <g
                      key={region.name}
                      className="group cursor-pointer"
                      onClick={() => setActiveRegion(region)}
                      onMouseEnter={() => setActiveRegion(region)}
                    >
                      <circle
                        cx={region.x}
                        cy={region.y}
                        r={isSelected ? 13 : isCritical ? 10 : 7}
                        className={cn(
                          "fill-transparent transition-all",
                          isCritical ? "stroke-danger/60" : isHigh ? "stroke-warn/50" : "stroke-sage/50",
                        )}
                        strokeWidth="1"
                      />
                      <circle
                        cx={region.x}
                        cy={region.y}
                        r={isSelected ? 6 : 4.5}
                        className={cn(
                          "transition-all",
                          isCritical ? "fill-danger/25 stroke-danger" : isHigh ? "fill-warn/25 stroke-warn" : "fill-sage/25 stroke-sage",
                        )}
                        strokeWidth="1.5"
                      />
                      <circle cx={region.x} cy={region.y} r={2} className={cn(isCritical ? "fill-danger" : isHigh ? "fill-warn" : "fill-sage")} />
                      <text
                        x={region.x + 9}
                        y={region.y + 3.5}
                        className={cn(
                          "pointer-events-none select-none text-[10px] font-medium transition-colors",
                          isSelected ? "fill-fg" : "fill-fg/80 group-hover:fill-fg",
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
                    description={
                      analyticsLoading
                        ? undefined
                        : "Reports do not currently carry origin or target-country fields, so no regions are plotted."
                    }
                  />
                </div>
              )}

              {activeRegion && (
                <div className="absolute bottom-2 left-2 right-2 z-10 rounded-lg border border-border bg-bg-elevated/95 p-4 text-sm shadow-xl backdrop-blur-md sm:right-auto sm:max-w-md">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <span className="flex items-center gap-2 font-medium text-fg">
                      <MapPin className="size-4 text-muted" strokeWidth={1.75} />
                      {activeRegion.name}
                    </span>
                    <StatusChip tone={levelTone(activeRegion.threatLevel)} dot>
                      {capitalize(activeRegion.threatLevel)} · {activeRegion.count ?? 0} reports
                    </StatusChip>
                  </div>
                  <dl className="grid grid-cols-[8rem_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-xs">
                    {activeRegion.originCountry && (
                      <>
                        <dt className="text-muted">Attribution origin</dt>
                        <dd className="text-fg">{activeRegion.originCountry}</dd>
                      </>
                    )}
                    <dt className="text-muted">Primary actors</dt>
                    <dd className="text-fg">{(activeRegion.actors ?? []).join(", ")}</dd>
                    {activeRegion.targetCountries && activeRegion.targetCountries.length > 0 && (
                      <>
                        <dt className="text-muted">Targeted nations</dt>
                        <dd className="text-fg">{activeRegion.targetCountries.join(", ")}</dd>
                      </>
                    )}
                    <dt className="text-muted">Targeted sectors</dt>
                    <dd className="text-fg">{(activeRegion.sectors ?? []).join(", ")}</dd>
                    <dt className="text-muted">Top TTP vector</dt>
                    <dd className="truncate text-fg">{activeRegion.topVector}</dd>
                  </dl>
                  <div className="mt-3 flex items-center justify-between border-t border-border pt-3">
                    <Link
                      to="/library"
                      search={{ q: activeRegion.actors?.[0] || activeRegion.name }}
                      className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
                    >
                      Filter {activeRegion.name} reports in Library
                      <ArrowRight className="size-3.5" />
                    </Link>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setActiveRegion(null);
                      }}
                      className="rounded-md px-2 py-1 text-xs text-muted hover:bg-bg-subtle hover:text-fg"
                    >
                      Dismiss
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div
              className={cn(
                "mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted",
                threatRegions.length === 0 && "hidden",
              )}
            >
              <span className="flex flex-wrap items-center gap-3">
                <StatusDot tone="danger">Critical</StatusDot>
                <StatusDot tone="warning">High</StatusDot>
                <StatusDot tone="success">Medium</StatusDot>
              </span>
              <span className="text-subtle">Select a cluster to inspect it</span>
            </div>
          </SectionCard>

          <SectionCard
            className="flex flex-col xl:col-span-5"
            bodyClassName={cardBody}
            title="MITRE ATT&CK phase density"
            icon={Layers}
            iconKind="technique"
            actions={
              <Link to="/matrix" className={cardLink}>
                Open matrix
                <ArrowRight className="size-3.5" />
              </Link>
            }
          >
            <p className="text-sm text-muted">
              Attack-chain steps mapped to each ATT&CK tactic across acquired reports, relative to the busiest tactic.
            </p>

            <div className="mt-5 space-y-3.5">
              {tacticDistribution.length === 0 && (
                <EmptyState
                  icon={Layers}
                  title={analyticsLoading ? "Loading report analytics…" : "No ATT&CK tactics mapped yet"}
                  description={analyticsLoading ? undefined : "Bars appear once acquired reports include an analyzed attack chain."}
                />
              )}
              {tacticDistribution.slice(0, 7).map((phase) => (
                <div key={phase.id} className="space-y-1.5">
                  <div className="flex items-center justify-between gap-3 text-sm">
                    <span className="truncate text-fg">{phase.name}</span>
                    <span className="shrink-0 text-xs text-muted tabular-nums">
                      {phase.count ?? 0} steps · {phase.reportCount ?? 0}{" "}
                      {(phase.reportCount ?? 0) === 1 ? "report" : "reports"}
                    </span>
                  </div>
                  <Meter
                    value={(phase.pct ?? 0) / 100}
                    color={entityMeta("technique").color}
                    label={`${phase.name} ${phase.pct ?? 0}%`}
                  />
                </div>
              ))}
            </div>

            <div className="mt-5 border-t border-border pt-4 text-xs text-muted">
              {topTacticNames.length > 0
                ? `Most observed: ${topTacticNames.join(" & ")}`
                : "No tactic data from reports yet"}
            </div>
          </SectionCard>
        </div>

        {/* Monitored threat actors carousel */}
        <SectionCard
          bodyClassName="pt-4"
          title="Monitored threat actors & offensive toolsets"
          icon={Users}
          iconKind="actor"
          actions={
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-xs text-muted">
                {topThreatActors.length} {topThreatActors.length === 1 ? "actor" : "actors"} named in reports · ranked by
                report count
              </span>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => scrollActors("left")}
                  aria-label="Scroll left"
                  className="flex size-8 items-center justify-center rounded-lg border border-border text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
                >
                  <ChevronLeft className="size-4" />
                </button>
                <button
                  type="button"
                  onClick={() => scrollActors("right")}
                  aria-label="Scroll right"
                  className="flex size-8 items-center justify-center rounded-lg border border-border text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
                >
                  <ChevronRight className="size-4" />
                </button>
              </div>
            </div>
          }
        >
          <div ref={actorCarouselRef} className="scrollbar-none flex gap-4 overflow-x-auto scroll-smooth pb-1">
            {topThreatActors.length === 0 && (
              <EmptyState
                className="w-full"
                icon={Users}
                title={analyticsLoading ? "Loading report analytics…" : "No threat actors named in reports yet"}
                description={
                  analyticsLoading
                    ? undefined
                    : "Actors appear here once acquired reports attribute activity to a named group or tool."
                }
              />
            )}
            {topThreatActors.map((actor) => {
              const ActorIcon = actorIcon(actor.badge);
              const kind = actorKind(actor.badge);
              return (
                <Link
                  key={actor.name}
                  to="/library"
                  search={{ q: actor.name }}
                  className="group flex w-[300px] flex-none flex-col rounded-xl bg-bg-subtle/60 p-4 transition-colors hover:bg-bg-subtle"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex min-w-0 items-center gap-3">
                      <EntityIcon kind={kind} icon={ActorIcon} size="lg" />
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium text-fg group-hover:text-accent">{actor.name}</div>
                        <div className="truncate text-xs text-muted">
                          {actor.reference
                            ? `${actor.reference.type} · ${actor.reference.originCountry}`
                            : "No reference profile in catalog"}
                        </div>
                      </div>
                    </div>
                    <span className="shrink-0">
                      <EntityChip kind={kind} noContext>{actorTypeLabel(actor.badge)}</EntityChip>
                    </span>
                  </div>

                  <p
                    className="mt-3 line-clamp-3 min-h-[3.75rem] text-xs leading-5 text-muted"
                    title="Reference profile from the built-in catalog, not observed in reports"
                  >
                    {actor.reference ? (
                      <>
                        <span className="text-subtle">Reference profile: </span>
                        {actor.reference.focus}
                      </>
                    ) : (
                      <span className="text-subtle">Only observed in acquired reports.</span>
                    )}
                  </p>

                  <div className="mt-3 space-y-1 border-t border-border pt-3 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="tabular-nums text-fg">
                        {actor.reportCount} {actor.reportCount === 1 ? "report" : "reports"}
                      </span>
                      <ArrowUpRight className="size-3.5 shrink-0 text-subtle transition-colors group-hover:text-fg" />
                    </div>
                    <div className="truncate text-subtle" title="Reference profile, not observed in reports">
                      {actor.reference && actor.reference.targetSectors.length > 0
                        ? `Reference sectors: ${actor.reference.targetSectors.slice(0, 2).join(", ")}`
                        : "Open matching reports"}
                    </div>
                    {actor.associatedTools && actor.associatedTools.length > 0 && (
                      <div className="truncate text-muted" title="Malware/tools named in the same reports">
                        Co-observed: <span style={{ color: entityMeta("malware").color }}>{actor.associatedTools.join(", ")}</span>
                      </div>
                    )}
                  </div>
                </Link>
              );
            })}
          </div>
        </SectionCard>

        {/* ATT&CK execution intensity heatmap */}
        <SectionCard
          bodyClassName="pt-4"
          title="MITRE ATT&CK execution intensity"
          icon={Activity}
          iconKind="technique"
          actions={
            <div className="flex flex-wrap items-center gap-4">
              <span className="flex items-center gap-2 text-xs text-muted" aria-label="Intensity scale, low to high">
                Low
                <span className="flex gap-0.5">
                  {[15, 35, 55, 75, 95].map((v) => (
                    <span key={v} className="h-2.5 w-4 rounded-sm" style={{ backgroundColor: heat(v) }} />
                  ))}
                </span>
                High
              </span>
              <Link to="/matrix" className={cardLink}>
                Full matrix
                <ArrowRight className="size-3.5" />
              </Link>
            </div>
          }
        >
          <p className="mb-4 text-sm text-muted">
            Attack-chain steps and technique IDs per tactic, extracted from acquired reports. Intensity is relative to the
            busiest tactic.
          </p>

          {attackHeatmap.length === 0 && (
            <EmptyState
              icon={Layers}
              title={analyticsLoading ? "Loading report analytics…" : "No techniques mapped from reports yet"}
              description={analyticsLoading ? undefined : "The heatmap fills in as reports with analyzed attack chains are acquired."}
            />
          )}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 min-[1800px]:grid-cols-7">
            {attackHeatmap.map((cell) => {
              const techColor = entityMeta("technique").color;
              return (
                <div
                  key={cell.tacticId}
                  className="flex flex-col rounded-xl p-4"
                  style={{
                    backgroundColor: `color-mix(in oklab, ${techColor} ${Math.round(2 + cell.intensity * 0.06)}%, var(--color-bg-subtle))`,
                  }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="text-sm font-medium leading-snug text-fg">{cell.tacticName}</div>
                      <div className="mt-0.5 font-mono text-[11px] text-subtle">{cell.tacticId}</div>
                    </div>
                    <span
                      className="rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums"
                      style={{
                        backgroundColor: heat(cell.intensity),
                        color: cell.intensity >= 55 ? "var(--color-primary-fg)" : techColor,
                      }}
                    >
                      {cell.intensity}%
                    </span>
                  </div>
                  <div className="mt-3">
                    <Meter value={cell.intensity / 100} color={techColor} label={`${cell.tacticName} intensity`} />
                  </div>
                  <div className="mt-2 text-xs text-muted tabular-nums">
                    {plural(cell.hitCount, "step")} · {plural(cell.techniqueCount, "technique")}
                  </div>

                  <div className="mt-3 border-t border-border pt-3">
                    <div className="mb-1.5 text-xs text-subtle">Top techniques</div>
                    {cell.topTechniques.length === 0 && <span className="block text-xs text-subtle">No technique IDs</span>}
                    <ul className="space-y-1">
                      {cell.topTechniques.map((tech) => (
                        <li key={tech.id}>
                          <Link
                            to="/matrix"
                            className="flex items-center justify-between gap-2 text-xs text-muted hover:text-fg"
                            title={`${tech.id} - ${tech.name}`}
                          >
                            <span className="truncate font-mono" style={{ color: techColor }}>
                              {tech.id}
                            </span>
                            <span className="shrink-0 text-subtle tabular-nums">{tech.count ?? 0}</span>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              );
            })}
          </div>
        </SectionCard>

        {/* Adversary threat flow */}
        <SectionCard
          bodyClassName="pt-4"
          title="Adversary campaign & infrastructure flow"
          icon={Network}
          iconKind="flow"
          actions={
            threatFlows.length > 0 ? (
              <SegmentedTabs
                size="sm"
                ariaLabel="Campaign flow"
                value={activeFlow?.id ?? ""}
                onChange={(v) => setSelectedFlowId(v)}
                items={threatFlows.map((flow) => ({ value: flow.id, label: flow.origin }))}
              />
            ) : undefined
          }
        >
          <p className="mb-4 text-sm text-muted">
            Multi-stage operational flow: origin and actors, ingress vectors, weaponized tools, targeted sectors.
          </p>

          {!activeFlow && (
            <EmptyState
              icon={Network}
              title={analyticsLoading ? "Loading report analytics…" : "No campaign flows correlated from reports yet"}
              description={
                analyticsLoading
                  ? undefined
                  : "Reports do not yet carry the origin, ingress vector and target-sector fields needed to build these flows."
              }
            />
          )}

          {activeFlow && (
            <div>
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <span className="text-sm font-medium text-fg">{activeFlow.origin}</span>
                <span className="flex items-center gap-2 text-xs text-muted">
                  Execution intensity
                  <StatusChip tone={activeFlow.intensity >= 90 ? "danger" : "warning"}>{activeFlow.intensity}%</StatusChip>
                </span>
              </div>

              <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
                <FlowStage step={1} kind="actor" title="Origin & actors" footer="Sovereign / cartel origin">
                  {(activeFlow.actors ?? []).map((actor) => (
                    <Link
                      key={actor}
                      to="/library"
                      search={{ q: actor }}
                      className="flex items-center justify-between gap-2 rounded-md px-2 py-1.5 text-sm text-fg hover:bg-bg-subtle hover:text-accent"
                    >
                      <span className="truncate">{actor}</span>
                      <ArrowRight className="size-3.5 shrink-0 text-subtle" />
                    </Link>
                  ))}
                </FlowStage>
                <FlowStage step={2} kind="technique" title="Ingress vectors" footer="Initial access & foothold">
                  {(activeFlow.vectors ?? []).map((vec) => (
                    <div key={vec} className="truncate px-2 py-1.5 text-sm text-muted" title={vec}>
                      {vec}
                    </div>
                  ))}
                </FlowStage>
                <FlowStage step={3} kind="malware" title="Weaponized tools" footer="Payload & C2 infrastructure">
                  {(activeFlow.tools ?? []).map((tool) => (
                    <Link
                      key={tool}
                      to="/library"
                      search={{ q: tool }}
                      className="flex items-center justify-between gap-2 rounded-md px-2 py-1.5 text-sm text-fg hover:bg-bg-subtle hover:text-accent"
                    >
                      <span className="truncate">{tool}</span>
                      <Terminal className="size-3.5 shrink-0 text-subtle" />
                    </Link>
                  ))}
                </FlowStage>
                <FlowStage step={4} kind="advisory" title="Targeted sectors" footer="Impact & sector blast radius">
                  {(activeFlow.targets ?? []).map((tgt) => (
                    <div key={tgt} className="truncate px-2 py-1.5 text-sm text-fg" title={tgt}>
                      {tgt}
                    </div>
                  ))}
                </FlowStage>
              </div>

              {activeFlow.actors.length > 0 && (
                <div className="mt-4 flex justify-end border-t border-border pt-4">
                  <Link
                    to="/library"
                    search={{ q: activeFlow.actors[0] }}
                    className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
                  >
                    Query {activeFlow.actors[0]} reports in Library
                    <ArrowRight className="size-3.5" />
                  </Link>
                </div>
              )}
            </div>
          )}
        </SectionCard>

        {/* CVEs referenced in reports */}
        <SectionCard
          bodyClassName="pt-4"
          title="CVEs referenced in acquired reports"
          icon={Bug}
          iconKind="cve"
          actions={
            <Link to="/library" className={cardLink}>
              Inspect all CVEs in Library
              <ArrowRight className="size-3.5" />
            </Link>
          }
        >
          <p className="mb-4 text-sm text-muted">
            Ranked by number of reports citing each CVE. CVSS and exploitation status, where shown, are reference values
            from a built-in catalog, not observed.
          </p>

          {cveVelocity.length === 0 && (
            <EmptyState
              icon={Bug}
              title={analyticsLoading ? "Loading report analytics…" : "No CVEs referenced in reports yet"}
              description={analyticsLoading ? undefined : "CVE identifiers extracted from acquired reports will be listed here."}
            />
          )}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {cveVelocity.slice(0, 8).map((cve) => {
              const ref = cve.reference;
              const isCrit = (ref?.cvss ?? 0) >= 9.0;
              return (
                <Link
                  key={cve.cveId}
                  to="/library"
                  search={{ q: cve.cveId }}
                  className="group flex flex-col justify-between rounded-xl bg-bg-subtle/60 p-4 transition-colors hover:bg-bg-subtle"
                >
                  <div>
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-2">
                        <EntityIcon kind="cve" size="sm" />
                        <span className="truncate font-mono text-sm font-medium text-fg group-hover:text-accent">{cve.cveId}</span>
                      </span>
                      {ref && (
                        <span title="Reference CVSS from built-in catalog">
                          <StatusChip tone={isCrit ? "danger" : "warning"}>CVSS {ref.cvss}</StatusChip>
                        </span>
                      )}
                    </div>
                    <div className="line-clamp-2 text-sm leading-snug text-fg">
                      {ref?.vendorProduct ?? cve.sampleReportTitle ?? "Referenced in acquired reports"}
                    </div>
                    <div className="mt-2 text-xs text-muted">
                      {ref && <span title="Reference status from built-in catalog, not observed">Ref: {ref.exploitStatus} · </span>}
                      {cve.reportCount} {cve.reportCount === 1 ? "report" : "reports"}
                    </div>
                  </div>
                  <div className="mt-3 flex items-center justify-between gap-2 border-t border-border pt-3 text-xs text-subtle">
                    <span className="truncate">{cve.actors?.slice(0, 2).join(", ") || "No actor attributed"}</span>
                    <ArrowUpRight className="size-3.5 shrink-0 transition-colors group-hover:text-fg" />
                  </div>
                </Link>
              );
            })}
          </div>
        </SectionCard>

        {/* Recently acquired intelligence + ingest audit */}
        <div className="grid gap-6 lg:grid-cols-5">
          <SectionCard
            className="min-w-0 overflow-hidden lg:col-span-3"
            bodyClassName="px-0 pb-0 pt-4"
            title="Latest published intelligence"
            icon={FileText}
            iconKind="advisory"
            actions={
              <Link to="/library" className={cardLink}>
                Open Library ({data?.acquiredCount ?? "—"})
                <ArrowRight className="size-3.5" />
              </Link>
            }
          >
            <div className="divide-y divide-border border-t border-border">
              {isLoading && (
                <div className="flex flex-col items-center justify-center py-10 text-muted">
                  <ActivitySpinner size="md" className="mb-2 text-accent" />
                  <p className="text-xs">Loading intelligence store…</p>
                </div>
              )}
              {data && data.recent.length === 0 && (
                <EmptyState icon={FileText} title="No reports acquired yet" description="Launch the crawler to acquire reports." />
              )}
              {data?.recent.map((r) => (
                <Link
                  key={r.id}
                  to="/library"
                  search={{ selected: r.id }}
                  className="flex items-start justify-between gap-4 px-5 py-4 transition-colors hover:bg-bg-subtle"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      {r.docTypes?.[0] && <DocTypeBadge type={r.docTypes[0]} />}
                      <span className="text-sm font-medium leading-snug text-fg">{r.title}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
                      <span>{r.sourceName}</span>
                      <span className="text-subtle">·</span>
                      <span>{humanize(r.classification)}</span>
                      <span className="text-subtle">·</span>
                      <span className="tabular-nums text-fg/80" title="When the source published it">
                        {r.publishedAt ? `Published ${formatShortDate(r.publishedAt)}` : "Publication date unknown"}
                      </span>
                      <span className="text-subtle">·</span>
                      <span className="tabular-nums" title="When AIE ingested it">
                        Ingested {formatShortDate(r.ingestedAt)}
                      </span>
                    </div>
                    <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-muted">{r.excerpt}</p>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <IdBadge id={formatReportId(r.id)} category="report" size="xs" prefixLabel="ID" />
                      {r.sourceId && (
                        <IdBadge id={formatSourceId(r.sourceId, r.sourceName)} category="source" size="xs" prefixLabel="Source" />
                      )}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <StatusChip tone={r.status === "acquired" ? "success" : "warning"}>{capitalize(r.status)}</StatusChip>
                    <ArrowUpRight className="size-4 text-subtle" />
                  </div>
                </Link>
              ))}
            </div>
          </SectionCard>

          <SectionCard
            className="min-w-0 overflow-hidden lg:col-span-2"
            bodyClassName="px-0 pb-5 pt-4"
            title="Crawl & ingest audit"
            icon={Activity}
            iconKind="source"
            actions={<StatusDot tone="success">Live pipeline</StatusDot>}
          >
            <ul className="divide-y divide-border border-y border-border">
              {data && data.events.length === 0 && (
                <EmptyState icon={Activity} title="No ingest events yet" description="Crawl and ingest outcomes appear here." />
              )}
              {data?.events.map((e) => {
                const outcomeMeta = formatOutcomeId(e.outcome, e.reportId || e.id, e.url);
                return (
                  <li key={e.id} className="px-5 py-3">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                        <IdBadge
                          id={outcomeMeta.id}
                          category={outcomeMeta.category}
                          tone={outcomeMeta.tone}
                          size="xs"
                          label={e.outcome}
                        />
                        <IdBadge id={formatAuditId(e.id)} category="audit" size="xs" />
                      </div>
                      <span className="shrink-0 text-xs text-subtle tabular-nums">{formatDateTime(e.createdAt)}</span>
                    </div>
                    <p className="mt-1.5 truncate font-mono text-xs text-fg">{e.url}</p>
                    {e.detail ? <p className="mt-1 text-xs text-muted">{e.detail}</p> : null}
                  </li>
                );
              })}
            </ul>

            <div className="space-y-2.5 px-5 pt-4">
              <div className="text-sm font-medium text-fg">Pipeline security & integrity gates</div>
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

const cardBody = "flex flex-1 flex-col pt-3";
const cardLink = "inline-flex items-center gap-1 text-sm text-muted hover:text-fg";

function capitalize(s: string) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

function humanize(s: string) {
  return capitalize((s ?? "").replace(/_/g, " ").toLowerCase());
}

function plural(n: number, word: string) {
  return `${n} ${n === 1 ? word : word + "s"}`;
}

function levelTone(level: ThreatRegionStats["threatLevel"]): Tone {
  return level === "critical" ? "danger" : level === "high" ? "warning" : "success";
}

/** Sequential technique-hue scale for heatmap intensity (0..100). */
function heat(intensity: number) {
  const pct = Math.round(14 + Math.max(0, Math.min(100, intensity)) * 0.86);
  return `color-mix(in oklab, var(--color-cat-technique) ${pct}%, transparent)`;
}

function actorKind(badge: string): EntityKind {
  const b = badge.toUpperCase();
  return b === "TOOL" || b === "MALWARE" ? "malware" : "actor";
}

function actorIcon(badge: string): typeof Hash {
  switch (badge.toUpperCase()) {
    case "APT":
      return Crosshair;
    case "RAAS":
      return Skull;
    case "TOOL":
      return Wrench;
    case "MALWARE":
      return Bug;
    default:
      return Users;
  }
}

function actorTypeLabel(badge: string) {
  const b = badge.toUpperCase();
  if (b === "APT") return "APT";
  if (b === "RAAS") return "RaaS";
  if (b === "TOOL") return "Tool";
  return capitalize(badge.toLowerCase());
}

function FlowStage({
  step,
  kind,
  title,
  footer,
  children,
}: {
  step: number;
  kind: EntityKind;
  title: string;
  footer: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col justify-between rounded-xl bg-bg-subtle/60 p-3">
      <div>
        <div className="mb-2 flex items-center gap-2 px-2 pt-1">
          <span
            className="flex size-5 items-center justify-center rounded-md text-[11px] font-semibold tabular-nums"
            style={{
              color: entityMeta(kind).color,
              backgroundColor: `color-mix(in oklab, ${entityMeta(kind).color} 16%, transparent)`,
            }}
          >
            {step}
          </span>
          <span className="text-sm font-medium text-fg">{title}</span>
        </div>
        <div className="space-y-0.5">{children}</div>
      </div>
      <span className="mx-2 mt-3 border-t border-border pt-2 text-xs text-subtle">{footer}</span>
    </div>
  );
}

function Hint({ icon: Icon, text }: { icon: typeof Hash; text: string }) {
  return (
    <div className="flex gap-2.5 text-xs leading-relaxed text-muted">
      <Icon className="mt-0.5 size-3.5 shrink-0 text-primary" strokeWidth={1.9} />
      <span>{text}</span>
    </div>
  );
}
