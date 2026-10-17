import type { ColumnDef } from "@tanstack/react-table";
import { AlertTriangle, CalendarClock, CheckCircle2, Filter, History, Link2, Radar, ShieldOff } from "lucide-react";
import { SectionCard, StatCard } from "@/components/layout/page";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState, StatusChip, type Tone } from "@/components/ui/primitives";
import { RowMenu } from "@/components/sources/row-menu";
import { entityMeta } from "@/components/ui/entity";
import { humanize } from "@/components/ingest/format";
import { cn } from "@/lib/cn";
import type { CollectorOverview, CollectorSourceRow } from "@/lib/aie/server-collector";
import type { CrawlFunnel, SourceTier } from "@/lib/aie/types";

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** "in 5 h", "3 d ago", "now" — compact relative time. */
function relTime(iso?: string | null, now = Date.now()): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "—";
  const diff = t - now;
  const abs = Math.abs(diff);
  const unit = abs < 3_600_000 ? [Math.max(1, Math.round(abs / 60_000)), "min"] : abs < 86_400_000 ? [Math.round(abs / 3_600_000), "h"] : [Math.round(abs / 86_400_000), "d"];
  if (abs < 60_000) return "now";
  return diff > 0 ? `in ${unit[0]} ${unit[1]}` : `${unit[0]} ${unit[1]} ago`;
}

const HEALTH_META: Record<CollectorSourceRow["status"], { tone: Tone; label: string }> = {
  healthy: { tone: "success", label: "Healthy" },
  degraded: { tone: "warning", label: "Degraded" },
  failing: { tone: "danger", label: "Failing" },
  backoff: { tone: "danger", label: "Backing off" },
  idle: { tone: "neutral", label: "Not crawled yet" },
};

export function HealthChip({ status }: { status: CollectorSourceRow["status"] }) {
  const m = HEALTH_META[status];
  return (
    <StatusChip tone={m.tone} dot>
      {m.label}
    </StatusChip>
  );
}

/**
 * Acceptance bar: share of decided candidates that were stored (sage), rejected by the quality gate
 * (warn) and skipped by the relevance pre-score (neutral).
 */
export function AcceptanceBar({ row, compact }: { row: CollectorSourceRow; compact?: boolean }) {
  const t = row.health?.totals;
  const decided = t ? t.accepted + t.rejectedQuality + t.skippedRelevance : 0;
  if (!t || decided === 0) {
    return <span className="text-xs text-subtle">{row.health ? "No decisions yet" : "—"}</span>;
  }
  const seg = (n: number) => `${(n / decided) * 100}%`;
  const title = `${t.accepted} stored · ${t.rejectedQuality} rejected by quality · ${t.skippedRelevance} skipped by relevance`;
  return (
    <div className={cn("min-w-0", compact ? "w-full" : "w-36")} title={title}>
      <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-bg-subtle" role="img" aria-label={title}>
        <span style={{ width: seg(t.accepted), backgroundColor: "var(--color-sage)" }} />
        <span style={{ width: seg(t.rejectedQuality), backgroundColor: "var(--color-warn)" }} />
        <span style={{ width: seg(t.skippedRelevance), backgroundColor: "var(--color-border-strong)" }} />
      </div>
      <div className="mt-1 flex items-center justify-between gap-2 text-xs tabular-nums">
        <span className="whitespace-nowrap text-fg">{Math.round((row.acceptance ?? 0) * 100)}% accepted</span>
        <span className="whitespace-nowrap text-subtle">of {decided}</span>
      </div>
    </div>
  );
}

function DueCell({ row }: { row: CollectorSourceRow }) {
  if (!row.enabled) return <span className="text-xs text-subtle">Paused</span>;
  if (row.status === "backoff") {
    return (
      <span className="text-xs text-danger tabular-nums" title={row.due.reason}>
        Retry {relTime(row.due.nextDueAt)}
      </span>
    );
  }
  if (row.due.dueNow) {
    return (
      <span title={row.due.reason}>
        <StatusChip tone="info">Due now</StatusChip>
      </span>
    );
  }
  return (
    <span className="whitespace-nowrap text-xs text-muted tabular-nums" title={`${row.due.reason}: ${row.due.nextDueAt ?? ""}`}>
      {relTime(row.due.nextDueAt)}
    </span>
  );
}

/** Compact health line used inside registry rows. */
export function RegistryHealthLine({ row }: { row?: CollectorSourceRow }) {
  if (!row) return null;
  return (
    <div className="mt-1.5 flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-1.5">
        <HealthChip status={row.status} />
        {row.enabled && row.status !== "backoff" && (
          <span className="text-[11px] text-subtle tabular-nums">{row.due.dueNow ? "due now" : `next ${relTime(row.due.nextDueAt)}`}</span>
        )}
      </div>
      {row.health && (row.acceptance !== null || row.health.lastError) && (
        <div className="w-full max-w-[9.5rem]">
          {row.acceptance !== null && <AcceptanceBar row={row} compact />}
          {row.health.lastError && (row.status === "failing" || row.status === "backoff" || row.status === "degraded") && (
            <p className="mt-0.5 line-clamp-2 text-[11px] text-danger/90" title={row.health.lastError}>
              {row.health.lastError}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

const CONNECTOR_LABEL: Record<string, string> = { rss: "RSS feed", html: "HTML archive", search: "Search", json_feed: "JSON feed", github_repo: "GitHub", stix_bundle: "STIX" };

function TierMark({ tier }: { tier: SourceTier }) {
  const kind = tier === 1 ? "advisory" : tier === 2 ? "emulation" : tier === 3 ? "technique" : "source";
  const color = entityMeta(kind).color;
  return (
    <span
      className="inline-flex shrink-0 items-center rounded-md px-1.5 py-0.5 font-mono text-[11px] font-semibold tabular-nums"
      style={{ color, backgroundColor: `color-mix(in oklab, ${color} 16%, transparent)` }}
    >
      T{tier}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Collection health view (Sources page tab)
// ---------------------------------------------------------------------------

export function CollectionHealthView({
  overview,
  loading,
  query,
  backfillingId,
  onBackfill,
}: {
  overview?: CollectorOverview;
  loading: boolean;
  query: string;
  backfillingId: string | null;
  onBackfill: (sourceId: string, months: 6 | 12 | 24) => void;
}) {
  if (loading && !overview) {
    return <div className="h-64 animate-pulse rounded-xl border border-border bg-bg-card" aria-label="Loading collection health" />;
  }
  if (!overview) {
    return <EmptyState icon={Radar} title="Collection health unavailable" description="Source health could not be loaded. Try again shortly." />;
  }
  const q = query.trim().toLowerCase();
  const rows = overview.sources
    .filter((r) => !q || r.name.toLowerCase().includes(q) || r.sourceId.toLowerCase().includes(q) || r.homepageUrl.toLowerCase().includes(q))
    .sort((a, b) => {
      const rank = (r: CollectorSourceRow) => (r.status === "backoff" ? 0 : r.status === "failing" ? 1 : r.status === "degraded" ? 2 : r.status === "healthy" ? 3 : 4);
      return rank(a) - rank(b) || a.tier - b.tier || a.name.localeCompare(b.name);
    });
  const crawled = overview.sources.filter((r) => r.health).length;
  const t = overview.totals;
  const decided = t.accepted + t.rejectedQuality + t.skippedRelevance;

  const columns: ColumnDef<CollectorSourceRow, any>[] = [
    {
      id: "source",
      header: "Source",
      accessorFn: (r) => r.name,
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="flex min-w-0 items-start gap-2.5">
            <TierMark tier={r.tier} />
            <div className="min-w-0">
              <div className="max-w-[180px] truncate font-medium text-fg sm:max-w-[240px]" title={r.name}>
                {r.name}
              </div>
              <div className="truncate text-xs text-subtle">
                {CONNECTOR_LABEL[r.connector] ?? humanize(r.connector)} · {r.schedule}
                {r.discovered ? " · discovered" : ""}
              </div>
            </div>
          </div>
        );
      },
    },
    {
      id: "health",
      header: "Health",
      accessorFn: (r) => r.status,
      cell: ({ row }) => {
        const r = row.original;
        const h = r.health;
        return (
          <div className="min-w-0 max-w-[220px]">
            <HealthChip status={r.status} />
            {h?.lastError && r.status !== "healthy" ? (
              <p className="mt-1 line-clamp-2 text-xs text-danger/90" title={h.lastError}>
                {h.consecutiveFailures > 0 ? `${h.consecutiveFailures}× · ` : ""}
                {h.lastError}
              </p>
            ) : h?.lastCrawledAt ? (
              <p className="mt-1 text-xs text-subtle tabular-nums">Crawled {relTime(h.lastCrawledAt)}</p>
            ) : null}
          </div>
        );
      },
    },
    {
      id: "yield",
      header: "Acceptance",
      accessorFn: (r) => r.acceptance ?? -1,
      cell: ({ row }) => <AcceptanceBar row={row.original} />,
      meta: { hideBelow: "sm" },
    },
    {
      id: "counts",
      header: () => <span title="Fetched · new · unchanged · duplicate · skipped by relevance">Yield</span>,
      accessorFn: (r) => r.health?.totals.fetched ?? 0,
      cell: ({ row }) => {
        const c = row.original.health?.totals;
        if (!c) return <span className="text-xs text-subtle">—</span>;
        return (
          <div className="text-xs tabular-nums" title={`${c.failed} failed fetches · ${c.versions} new versions · ${c.rejectedQuality} rejected by quality`}>
            <div className="whitespace-nowrap text-fg">
              {c.fetched} fetched · {c.new} new
            </div>
            <div className="whitespace-nowrap text-subtle">
              {c.unchanged} unchanged · {c.duplicate} dup · {c.skippedRelevance} skipped
            </div>
            {row.original.avgQuality !== null && <div className="whitespace-nowrap text-subtle">avg quality {Math.round(row.original.avgQuality * 100)}%</div>}
          </div>
        );
      },
      meta: { hideBelow: "lg" },
    },
    {
      id: "due",
      header: "Next crawl",
      accessorFn: (r) => (r.due.dueNow ? 0 : r.due.nextDueAt ? Date.parse(r.due.nextDueAt) : Number.MAX_SAFE_INTEGER),
      cell: ({ row }) => <DueCell row={row.original} />,
      meta: { hideBelow: "md" },
    },
    {
      id: "actions",
      // sr-only is absolutely positioned: anchor it inside the cell so it cannot widen the page.
      header: () => (
        <span className="relative">
          <span className="sr-only">Actions</span>
        </span>
      ),
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        const busy = backfillingId === r.sourceId;
        return (
          <RowMenu
            label={`Actions for ${r.name}`}
            items={[
              { label: busy ? "Backfill starting…" : "Backfill 6 months", icon: History, disabled: busy || !!backfillingId, onSelect: () => onBackfill(r.sourceId, 6) },
              { label: "Backfill 12 months", icon: History, disabled: !!backfillingId, onSelect: () => onBackfill(r.sourceId, 12) },
              { label: "Backfill 24 months", icon: History, disabled: !!backfillingId, onSelect: () => onBackfill(r.sourceId, 24) },
              ...(r.homepageUrl
                ? [{ label: "Open source", icon: Link2, separated: true, onSelect: () => window.open(r.homepageUrl, "_blank", "noopener,noreferrer") }]
                : []),
            ]}
          />
        );
      },
      meta: { align: "right", className: "w-12" },
    },
  ];

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Radar}
          kind="source"
          label="Sources crawled"
          value={crawled || "—"}
          hint={`${overview.sources.length} crawlable · ${overview.trackedUrls.toLocaleString()} URLs with fetch state`}
        />
        <StatCard
          icon={CheckCircle2}
          kind="ioc"
          label="Acceptance"
          value={decided ? `${Math.round((t.accepted / decided) * 100)}%` : "—"}
          hint={decided ? `${t.accepted} stored · ${t.rejectedQuality} rejected · ${t.skippedRelevance} skipped` : "No collection decisions yet"}
        />
        <StatCard
          icon={Filter}
          kind="technique"
          label="Saved fetches"
          value={t.unchanged + t.skippedRelevance + t.duplicate || "—"}
          hint={`${t.unchanged} unchanged · ${t.duplicate} duplicates · ${t.skippedRelevance} junk skipped`}
        />
        <StatCard
          icon={overview.failing ? AlertTriangle : CalendarClock}
          kind={overview.failing ? "actor" : "advisory"}
          label={overview.failing ? "Failing sources" : "Due now"}
          value={overview.failing || overview.dueNow}
          hint={overview.failing ? `${overview.dueNow} due now · failing sources back off automatically` : "by each source's schedule hint"}
        />
      </div>

      <div
        role="note"
        className="flex items-start gap-3 rounded-xl border px-4 py-3 text-sm"
        style={{
          borderColor: `color-mix(in oklab, var(--color-${overview.schedulerActive ? "sage" : "info"}) 35%, transparent)`,
          backgroundColor: `color-mix(in oklab, var(--color-${overview.schedulerActive ? "sage" : "info"}) 7%, transparent)`,
        }}
      >
        <CalendarClock className="mt-0.5 size-4 shrink-0" style={{ color: `var(--color-${overview.schedulerActive ? "sage" : "info"})` }} />
        <div className="min-w-0">
          <div className="font-medium text-fg">{overview.schedulerActive ? "Per-source schedules active" : "Schedules computed, crawls on demand"}</div>
          <p className="mt-0.5 text-muted">
            {overview.schedulerNote} Sources back off after 3 consecutive failures (2 h, doubling, up to 7 days).
            {overview.persistence === "local" ? " Health and fetch state are kept in the local workspace database, which resets when the workspace restarts." : ""}
          </p>
        </div>
      </div>

      <SectionCard
        icon={Radar}
        iconKind="source"
        title="Collection health and yield"
        info="Counters accumulate per source across crawl runs. Acceptance = stored ÷ (stored + rejected by quality + skipped by relevance)."
        bodyClassName="p-0 pt-3"
      >
        <DataTable
          data={rows}
          columns={columns}
          getRowId={(r) => r.sourceId}
          caption="Collection health by source"
          empty={<EmptyState icon={ShieldOff} title="No sources match" description={q ? "Try a different search." : "Crawlable sources appear here."} />}
        />
      </SectionCard>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Job funnel (Ingest page)
// ---------------------------------------------------------------------------

const STAGES: Array<{ key: keyof CrawlFunnel; label: string; hint: string }> = [
  { key: "discovered", label: "Discovered", hint: "Candidates enqueued from feeds, sitemaps, listings and citations" },
  { key: "relevant", label: "Relevant", hint: "Passed the relevance pre-score (title, summary, URL, source history)" },
  { key: "fetched", label: "Acquired", hint: "Full text obtained: downloaded, or supplied by the feed (revalidations of stored URLs are counted as unchanged or new versions)" },
  { key: "unique", label: "Unique", hint: "Not a duplicate of a stored document (SHA-256, normalised text, title+publisher, SimHash)" },
  { key: "qualified", label: "Qualified", hint: "Passed the quality and evidence gate" },
  { key: "stored", label: "Stored", hint: "New reports plus new versions of changed reports" },
];

export function CrawlFunnelPanel({ funnel, jobLabel, loading }: { funnel?: CrawlFunnel | null; jobLabel: string; loading?: boolean }) {
  if (loading && !funnel) return <div className="h-48 animate-pulse rounded-xl border border-border bg-bg-card" aria-label="Loading funnel" />;
  if (!funnel) {
    return (
      <SectionCard icon={Filter} iconKind="technique" title="Collection funnel" actions={<span className="font-mono text-xs text-subtle">{jobLabel}</span>}>
        <p className="text-sm text-muted">No funnel was recorded for this job. Funnels are recorded for crawls run with the incremental collector.</p>
      </SectionCard>
    );
  }
  const max = Math.max(1, funnel.discovered);
  const dupTotal = Object.values(funnel.duplicates ?? {}).reduce((a, b) => a + b, 0);
  const exits: Array<{ label: string; value: number; tone: Tone; title?: string }> = [
    { label: "Skipped by relevance", value: funnel.skippedRelevance, tone: "neutral" },
    { label: "Unchanged", value: funnel.unchanged, tone: "neutral", title: `${funnel.notModified} answered HTTP 304 Not Modified` },
    { label: "Duplicates", value: dupTotal, tone: "warning", title: Object.entries(funnel.duplicates ?? {}).map(([k, v]) => `${humanize(k)}: ${v}`).join(" · ") || undefined },
    { label: "New versions", value: funnel.newVersions, tone: "info" },
    { label: "Robots.txt", value: funnel.robotsBlocked, tone: "neutral" },
    { label: "Failed", value: funnel.failed, tone: "danger" },
    { label: "PDFs attached", value: funnel.pdfAttached, tone: "success" },
  ].filter((e) => e.value > 0) as Array<{ label: string; value: number; tone: Tone; title?: string }>;
  const discovery = [
    funnel.feedsNotModified ? `${funnel.feedsNotModified} feeds unchanged (304)` : null,
    funnel.sitemapUrls ? `${funnel.sitemapUrls} from sitemaps` : null,
    funnel.feedsAutodiscovered ? `${funnel.feedsAutodiscovered} feeds autodiscovered` : null,
    funnel.listingPages ? `${funnel.listingPages} listing pages` : null,
  ].filter(Boolean);

  return (
    <SectionCard
      icon={Filter}
      iconKind="technique"
      title="Collection funnel"
      info="Where candidates left the pipeline in this job."
      actions={
        <span className="flex flex-wrap items-center gap-2 text-xs text-subtle">
          {funnel.mode === "backfill" && funnel.backfill && (
            <StatusChip tone="info">
              Backfill · {funnel.backfill.months} months
            </StatusChip>
          )}
          <span className="font-mono">{jobLabel}</span>
        </span>
      }
    >
      <ol className="grid grid-cols-2 gap-x-4 gap-y-4 sm:grid-cols-3 lg:grid-cols-6">
        {STAGES.map((s, i) => {
          const v = Number(funnel[s.key] ?? 0);
          return (
            <li key={s.key} title={s.hint} className="min-w-0">
              <div className="flex items-baseline justify-between gap-2">
                <span className="truncate text-xs text-muted">
                  <span className="mr-1 text-subtle tabular-nums">{i + 1}</span>
                  {s.label}
                </span>
              </div>
              <div className="mt-1 text-2xl font-semibold leading-none text-fg tabular-nums">{v.toLocaleString()}</div>
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-bg-subtle">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${Math.min(100, (v / max) * 100)}%`, backgroundColor: i === STAGES.length - 1 ? "var(--color-sage)" : "var(--color-cat-technique)" }}
                />
              </div>
            </li>
          );
        })}
      </ol>

      {(exits.length > 0 || discovery.length > 0) && (
        <div className="mt-5 flex flex-col gap-3 border-t border-border pt-4 md:flex-row md:items-start md:justify-between">
          <div className="flex flex-wrap gap-1.5">
            {exits.map((e) => (
              <span key={e.label} title={e.title}>
                <StatusChip tone={e.tone}>
                  {e.label} <span className="tabular-nums">{e.value}</span>
                </StatusChip>
              </span>
            ))}
          </div>
          {discovery.length > 0 && <p className="text-xs text-subtle md:text-right">{discovery.join(" · ")}</p>}
        </div>
      )}

      {funnel.sourcesSkipped?.length > 0 && (
        <div className="mt-4 border-t border-border pt-4">
          <h3 className="text-sm font-medium text-fg">Sources not crawled ({funnel.sourcesSkipped.length})</h3>
          <ul className="mt-2 space-y-1">
            {funnel.sourcesSkipped.slice(0, 6).map((s) => (
              <li key={s.sourceId} className="flex min-w-0 flex-col gap-0.5 text-xs sm:flex-row sm:gap-2">
                <span className="shrink-0 font-medium text-fg">{s.name}</span>
                <span className="min-w-0 truncate text-muted" title={s.reason}>
                  {s.reason}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {funnel.relevanceSamples?.length > 0 && (
        <div className="mt-4 border-t border-border pt-4">
          <h3 className="text-sm font-medium text-fg">Skipped before fetch (lowest relevance)</h3>
          <ul className="mt-2 divide-y divide-border">
            {funnel.relevanceSamples.slice(0, 6).map((r) => (
              <li key={r.url} className="flex min-w-0 items-start gap-3 py-2 text-xs">
                <span className="mt-0.5 w-9 shrink-0 font-mono tabular-nums text-subtle">{r.score.toFixed(2)}</span>
                <div className="min-w-0">
                  <div className="truncate text-fg" title={r.url}>
                    {r.title}
                  </div>
                  <div className="line-clamp-2 text-muted">{r.reason}</div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </SectionCard>
  );
}
