import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Bot,
  CheckCircle2,
  Cpu,
  Database,
  Eye,
  FileText,
  Fingerprint,
  Flame,
  Globe2,
  Hash,
  Layers,
  Library,
  MapPin,
  Play,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  Terminal,
  Workflow,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/aie/format";
import { getDashboard } from "@/lib/aie/server";
import { cn } from "@/lib/cn";

export const Route = createFileRoute("/")({ component: Home });

// Global Threat Geolocation Hotspots
const THREAT_REGIONS = [
  {
    name: "North America",
    x: 180,
    y: 95,
    actors: ["Scattered Spider", "FIN7", "Volt Typhoon Targets"],
    count: 42,
    threatLevel: "high",
    sectors: ["Defense Industrial Base", "Critical Infrastructure", "Finance"],
    topVector: "SIM Swapping, Cloud Token Replay, WMI Abuse",
  },
  {
    name: "Western Europe",
    x: 440,
    y: 75,
    actors: ["LockBit Affiliates", "BlackCat", "Akira"],
    count: 35,
    threatLevel: "medium",
    sectors: ["Healthcare", "Manufacturing", "Government"],
    topVector: "VPN Exploitation, Ransomware Deployment, AuKill",
  },
  {
    name: "Eastern Europe",
    x: 530,
    y: 65,
    actors: ["Midnight Blizzard", "Sandworm", "APT28"],
    count: 88,
    threatLevel: "critical",
    sectors: ["Energy Grid", "Foreign Affairs", "Military Logistics"],
    topVector: "Kerberoasting, Supply Chain, Exchange Zero-Days",
  },
  {
    name: "Middle East",
    x: 555,
    y: 135,
    actors: ["MuddyWater", "Charming Kitten", "OilRig"],
    count: 29,
    threatLevel: "medium",
    sectors: ["Oil & Gas", "Telecommunications", "Aviation"],
    topVector: "Spearphishing Attachments, ScreenConnect, Chisel",
  },
  {
    name: "East Asia",
    x: 750,
    y: 110,
    actors: ["Volt Typhoon", "Lazarus Group", "Flax Typhoon"],
    count: 74,
    threatLevel: "critical",
    sectors: ["Ports & Maritime", "Financial Institutions", "Defense"],
    topVector: "Living-off-the-Land, Router Botnets, Fast-Flux C2",
  },
  {
    name: "Southeast Asia",
    x: 720,
    y: 175,
    actors: ["Mustang Panda", "BlackTech"],
    count: 21,
    threatLevel: "low",
    sectors: ["Public Sector", "Diplomatic Channels", "Education"],
    topVector: "USB Staging, PlugX DLL Side-Loading, Web Shells",
  },
];

// Tactical Phases for Live Matrix Coverage Bar Chart
const TACTIC_PHASE_DISTRIBUTION = [
  { name: "Initial Access", id: "TA0001", count: 18, pct: 75 },
  { name: "Execution", id: "TA0002", count: 24, pct: 90 },
  { name: "Persistence", id: "TA0003", count: 16, pct: 68 },
  { name: "Priv Escalation", id: "TA0004", count: 14, pct: 60 },
  { name: "Stealth", id: "TA0005.1", count: 22, pct: 85 },
  { name: "Defense Impairment", id: "TA0005.2", count: 20, pct: 82 },
  { name: "Credential Access", id: "TA0006", count: 28, pct: 95 },
  { name: "Discovery", id: "TA0007", count: 19, pct: 70 },
  { name: "Lateral Movement", id: "TA0008", count: 17, pct: 65 },
  { name: "Command & Control", id: "TA0011", count: 21, pct: 80 },
  { name: "Exfiltration", id: "TA0010", count: 15, pct: 62 },
  { name: "Impact", id: "TA0040", count: 19, pct: 78 },
];

function Home() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => getDashboard(),
    refetchInterval: 12000,
    staleTime: 10000,
  });

  const [activeRegion, setActiveRegion] = useState<(typeof THREAT_REGIONS)[0] | null>(null);

  return (
    <AppShell>
      <div className="space-y-8">
        {/* ========================================================================= */}
        {/* DASHBOARD HERO HEADER & QUICK ACTIONS                                     */}
        {/* ========================================================================= */}
        <div className="flex flex-col justify-between gap-4 border-b border-border pb-6 md:flex-row md:items-center">
          <div>
            <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">
              <span className="size-2 rounded-full bg-sage animate-pulse" />
              <span>Continuous Autonomous Threat Acquisition · SOC Node</span>
            </div>
            <h1 className="mt-1 text-3xl font-bold tracking-tight text-fg md:text-4xl">
              Adversary Intelligence Engine
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted">
              Autonomous CTI crawler, heuristic TTP qualification gate, cryptographic evidence hashing,
              and MITRE ATT&CK® adversary emulation mapping for red teams, blue teams, and detection engineers.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/matrix">
              <Button variant="secondary" className="gap-2 text-xs font-mono">
                <Layers className="size-4 text-accent" />
                <span>ATT&CK Matrix</span>
              </Button>
            </Link>
            <Link to="/ingest">
              <Button className="gap-2 text-xs font-mono">
                <Zap className="size-4" />
                <span>Launch Crawler</span>
              </Button>
            </Link>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* TOP LEVEL KEY PERFORMANCE METRICS                                         */}
        {/* ========================================================================= */}
        {error ? (
          <p className="text-sm text-danger">{error.message}</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              label="Threat Sources"
              value={data?.sourceCount}
              sub={`${data?.enabledSources ?? "—"} active RSS / research feeds`}
              badge="Monitored"
              icon={Globe2}
            />
            <Stat
              label="Reports Stored"
              value={data?.acquiredCount}
              sub={`${data?.reportCount ?? "—"} total acquired in store`}
              badge="SHA-256 Verified"
              icon={Database}
            />
            <Stat
              label="Avg Quality Gate"
              value={data ? Math.round(data.avgQuality * 100) + "%" : undefined}
              sub="Heuristic TTP & simulation density"
              badge="Qualified"
              icon={Shield}
            />
            <Stat
              label="IOCs Harvested"
              value={data?.iocCount}
              sub="IPs, Domains, CVEs, Hashes"
              badge="De-duplicated"
              icon={Fingerprint}
            />
          </div>
        )}

        {/* ========================================================================= */}
        {/* INTERACTIVE THREAT ACTOR GEOLOCATION ACTIVITY MAP & TACTIC DISTRIBUTION   */}
        {/* ========================================================================= */}
        <div className="grid gap-6 lg:grid-cols-12">
          {/* Global Threat Activity Map (7 cols) */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 shadow-xs lg:col-span-7 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Globe2 className="size-4 text-subtle" />
                  <h2 className="text-sm font-bold uppercase tracking-wider text-fg">
                    Global Threat Origin & Targeting Activity
                  </h2>
                </div>
                <Badge tone="neutral" className="font-mono text-[10px]">
                  Real-time Telemetry
                </Badge>
              </div>
              <p className="mt-1 text-xs text-muted">
                Observed adversary infrastructure and nation-state threat actor origin clusters derived from acquired intelligence papers.
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
                {THREAT_REGIONS.map((region) => {
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
                        {region.name} ({region.count})
                      </text>
                    </g>
                  );
                })}
              </svg>

              {/* Active Region Threat Telemetry HUD Overlay */}
              {activeRegion && (
                <div className="absolute bottom-2 left-2 right-2 sm:right-auto sm:max-w-md rounded-lg border border-border bg-bg-elevated/95 p-3 shadow-lg backdrop-blur-md text-xs font-mono animate-in fade-in zoom-in-95 duration-100">
                  <div className="flex items-center justify-between gap-2 border-b border-border pb-1.5 mb-1.5">
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
                      <span className="font-bold text-fg text-[11px] uppercase tracking-wider">
                        {activeRegion.name}
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
                      className="text-[9px] uppercase font-bold"
                    >
                      {activeRegion.threatLevel} · {activeRegion.count} campaigns
                    </Badge>
                  </div>
                  <div className="space-y-1 text-[11px] text-muted">
                    <div>
                      <span className="text-subtle">Adversary Groups:</span>{" "}
                      <span className="text-fg font-medium">{activeRegion.actors.join(", ")}</span>
                    </div>
                    <div>
                      <span className="text-subtle">Targeted Sectors:</span>{" "}
                      <span className="text-fg">{activeRegion.sectors.join(", ")}</span>
                    </div>
                    <div className="truncate">
                      <span className="text-subtle">Top TTP Vector:</span>{" "}
                      <span className="text-fg">{activeRegion.topVector}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="mt-3 flex items-center justify-between text-xs text-subtle">
              <span>Threat Levels: <span className="text-danger font-mono font-bold">● Critical</span> · <span className="text-warn font-mono font-bold">● High</span> · <span className="text-sage font-mono font-bold">● Medium</span></span>
              <span className="font-mono text-[11px]">Click nodes to inspect clusters</span>
            </div>
          </div>

          {/* Tactical Phase Coverage Bar Chart (5 cols) */}
          <div className="rounded-xl border border-border bg-bg-elevated p-5 shadow-xs lg:col-span-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers className="size-4 text-subtle" />
                  <h2 className="text-sm font-bold uppercase tracking-wider text-fg">
                    MITRE ATT&CK Phase Density
                  </h2>
                </div>
                <Link to="/matrix" className="text-xs text-muted hover:text-fg hover:underline flex items-center gap-1 font-mono">
                  <span>Open Matrix</span>
                  <ArrowRight className="size-3" />
                </Link>
              </div>
              <p className="mt-1 text-xs text-muted">
                Adversary emulation technique coverage across the 15 enterprise attack phases.
              </p>
            </div>

            {/* Tactical Phase Bars */}
            <div className="mt-4 space-y-2.5">
              {TACTIC_PHASE_DISTRIBUTION.slice(0, 7).map((phase) => (
                <div key={phase.id} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium text-fg">{phase.name}</span>
                    <span className="font-mono text-[11px] text-muted">{phase.count} techniques ({phase.pct}%)</span>
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
              <span className="text-muted">High-density areas: Credential Access & Execution</span>
              <Link to="/matrix" className="font-mono text-muted hover:text-fg hover:underline text-[11px]">
                View All 15 Tactics →
              </Link>
            </div>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* ACTIVE ADVERSARY PROFILES & MALWARE FAMILIES STRIP                        */}
        {/* ========================================================================= */}
        <div className="rounded-xl border border-border bg-bg-elevated p-5 shadow-xs">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
            <div className="flex items-center gap-2">
              <Flame className="size-4 text-warn" />
              <h2 className="text-sm font-bold uppercase tracking-wider text-fg">
                Monitored Threat Actors & Offensive Toolsets
              </h2>
            </div>
            <span className="font-mono text-[11px] text-muted">
              Auto-extracted from verified vendor threat reports
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
            {[
              { name: "Volt Typhoon", type: "Nation-State", focus: "Living-off-the-Land, WMI", reports: 24, badge: "TA-01" },
              { name: "Akira Ransomware", type: "Ransomware Gang", focus: "LSASS, AuKill, BYOVD", reports: 31, badge: "FIN" },
              { name: "Black Basta", type: "Ransomware / Extortion", focus: "AnyDesk, Quick Assist, Chisel", reports: 19, badge: "FIN" },
              { name: "Midnight Blizzard", type: "APT29 / Russian SVR", focus: "OAuth, Cloud Tokens, Graph API", reports: 17, badge: "APT" },
              { name: "Scattered Spider", type: "Social Engineering", focus: "SIM Swapping, Okta, MFA Bypass", reports: 14, badge: "UNC" },
              { name: "LockBit 3.0", type: "Ransomware / Builder", focus: "PsExec, Shadow Copy Inhibit", reports: 28, badge: "RaaS" },
            ].map((actor) => (
              <div
                key={actor.name}
                className="rounded-lg border border-border bg-bg p-3 hover:border-border-strong transition-colors"
              >
                <div className="flex items-center justify-between">
                  <Badge tone="warn" className="font-mono text-[9px] px-1.5 py-0.2">
                    {actor.badge}
                  </Badge>
                  <span className="font-mono text-[10px] text-muted font-semibold">
                    {actor.reports} papers
                  </span>
                </div>
                <div className="mt-2 text-xs font-semibold text-fg leading-tight">
                  {actor.name}
                </div>
                <div className="mt-1 text-[11px] text-subtle truncate">
                  {actor.type}
                </div>
                <div className="mt-2 text-[10px] font-mono text-muted line-clamp-1 border-t border-border pt-1.5">
                  {actor.focus}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ========================================================================= */}
        {/* RECENTLY ACQUIRED INTELLIGENCE & INGEST AUDIT LOG                         */}
        {/* ========================================================================= */}
        <div className="grid gap-8 lg:grid-cols-5">
          {/* Recently Acquired Reports (3 cols) */}
          <section className="lg:col-span-3">
            <div className="mb-3 flex items-baseline justify-between">
              <div className="flex items-center gap-2">
                <FileText className="size-4 text-subtle" />
                <h2 className="text-base font-bold tracking-tight text-fg">
                  Recently Acquired Intelligence
                </h2>
              </div>
              <Link to="/library" className="text-xs text-muted hover:text-fg hover:underline font-mono">
                Open Library ({data?.acquiredCount ?? "—"}) →
              </Link>
            </div>
            <div className="divide-y divide-border rounded-xl border border-border bg-bg-elevated shadow-xs">
              {isLoading && <p className="p-5 text-sm text-muted">Loading intelligence store…</p>}
              {data?.recent.map((r) => (
                <Link
                  key={r.id}
                  to="/library/$reportId"
                  params={{ reportId: r.id }}
                  className="flex items-start justify-between gap-4 px-5 py-4 transition-colors hover:bg-bg-subtle"
                >
                  <div className="min-w-0">
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
          </section>

          {/* Ingest Audit Log & Pipeline Hints (2 cols) */}
          <section className="lg:col-span-2">
            <div className="mb-3 flex items-baseline justify-between">
              <div className="flex items-center gap-2">
                <Activity className="size-4 text-subtle" />
                <h2 className="text-base font-bold tracking-tight text-fg">
                  Crawl & Ingest Audit
                </h2>
              </div>
              <span className="font-mono text-xs text-subtle">Live Pipeline</span>
            </div>
            <ul className="space-y-2">
              {data?.events.map((e) => (
                <li key={e.id} className="rounded-lg border border-border bg-bg-elevated px-4 py-3 shadow-xs">
                  <div className="flex items-center justify-between gap-2">
                    <Badge
                      tone={
                        e.outcome === "failed" || e.outcome === "rejected"
                          ? "danger"
                          : e.outcome === "duplicate"
                            ? "warn"
                            : "sage"
                      }
                    >
                      {e.outcome}
                    </Badge>
                    <span className="font-mono text-[10px] text-subtle">
                      {formatDateTime(e.createdAt)}
                    </span>
                  </div>
                  <p className="mt-2 truncate font-mono text-xs text-fg">{e.url}</p>
                  {e.detail ? <p className="mt-1 text-xs text-muted">{e.detail}</p> : null}
                </li>
              ))}
            </ul>

            <div className="mt-6 space-y-2 rounded-xl border border-border bg-bg-elevated p-4">
              <span className="font-mono text-[10px] uppercase font-bold text-subtle tracking-wider block mb-2">
                Pipeline Security & Integrity Gates
              </span>
              <Hint icon={Workflow} text="Permalinks discriminator rejects category/index pages automatically." />
              <Hint icon={Hash} text="Cryptographic SHA-256 evidence hashing for raw bytes and clean text." />
              <Hint icon={Fingerprint} text="Regex IOC harvest with MITRE ATT&CK technique extraction." />
              <Hint icon={Shield} text="All external content is sanitized and isolated as untrusted CTI." />
            </div>
          </section>
        </div>
      </div>
    </AppShell>
  );
}

function Stat({
  label,
  value,
  sub,
  badge,
  icon: Icon,
}: {
  label: string;
  value?: number | string;
  sub: string;
  badge?: string;
  icon?: typeof Globe2;
}) {
  return (
    <div className="rounded-xl border border-border bg-bg-elevated p-4 shadow-xs">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase font-medium tracking-wider text-subtle">{label}</span>
        {badge && (
          <Badge tone="neutral" className="font-mono text-[9px]">
            {badge}
          </Badge>
        )}
      </div>
      <div className="mt-2 flex items-baseline justify-between">
        <div className="font-mono text-3xl font-bold tabular-nums tracking-tight text-fg">
          {value ?? "—"}
        </div>
        {Icon && <Icon className="size-5 text-subtle/50" />}
      </div>
      <div className="mt-1 text-xs text-muted">{sub}</div>
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
