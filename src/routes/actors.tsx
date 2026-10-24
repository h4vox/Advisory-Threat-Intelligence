import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { z } from "zod";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Activity,
  CalendarClock,
  LayoutGrid,
  Layers,
  List,
  Search,
  Users,
  UserRoundX,
  X,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SegmentedTabs, StatCard, Toolbar } from "@/components/layout/page";
import { Pagination } from "@/components/templates/page-templates";
import { DataTable, type DataTableColumnMeta } from "@/components/ui/data-table";
import { EntityIcon } from "@/components/ui/entity";
import { EmptyState, StatusChip } from "@/components/ui/primitives";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { Select } from "@/components/ui/select";
import { ActorCard } from "@/components/actors/actor-card";
import { KpiStrip } from "@/components/actors/kpi-strip";
import { EmulationCell, TechniqueBarLegend, TechniqueMiniBar } from "@/components/actors/actor-ui";
import { formatDay } from "@/components/actors/actor-format";
import { listActors } from "@/lib/aie/server-actors";
import type { ActorRow, ActorSort } from "@/lib/aie/actors/types";
import { cn } from "@/lib/cn";

const SORTS: Array<{ value: ActorSort; label: string }> = [
  { value: "recent", label: "Recent activity" },
  { value: "reports", label: "Library reports" },
  { value: "techniques", label: "Techniques" },
  { value: "name", label: "Name" },
];

const searchSchema = z.object({
  q: z.string().optional(),
  observed: z.boolean().optional(),
  sort: z.enum(["recent", "reports", "techniques", "name"]).optional(),
  view: z.enum(["table", "cards"]).optional(),
  page: z.number().int().min(1).optional(),
});

export const Route = createFileRoute("/actors")({
  validateSearch: (search) => searchSchema.parse(search),
  component: ActorsPage,
});

const PAGE_SIZE = 25;
function ActorsPage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/actors" });
  const sort: ActorSort = search.sort ?? "recent";
  const view = search.view ?? "table";
  const page = search.page ?? 1;
  const observedOnly = Boolean(search.observed);
  const [q, setQ] = useState(search.q ?? "");

  const update = (patch: Partial<z.infer<typeof searchSchema>>) =>
    void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });

  // Debounce the search box into the URL.
  useEffect(() => {
    const t = setTimeout(() => {
      const next = q.trim() || undefined;
      if (next !== (search.q || undefined)) update({ q: next, page: undefined });
    }, 250);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);

  const query = useQuery({
    queryKey: ["actors", search.q ?? "", observedOnly, sort, page],
    queryFn: () =>
      listActors({
        data: {
          q: search.q || undefined,
          observedOnly,
          sort,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
      }),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
  const data = query.data;
  const rows = useMemo(() => data?.rows ?? [], [data]);
  const kpis = data?.kpis;

  const maxTech = useMemo(
    () =>
      Math.max(
        1,
        ...rows.map(
          (r) =>
            Math.max(r.attributedTechniques, r.observedTechniques - r.newTechniques) +
            r.newTechniques,
        ),
      ),
    [rows],
  );

  const columns = useMemo<ColumnDef<ActorRow, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Actor",
        accessorFn: (r) => r.name,
        cell: ({ row: { original: r } }) => {
          const aliases = r.aliases.slice(0, 3);
          return (
            <div className="flex min-w-0 items-center gap-3">
              <EntityIcon kind="actor" size="sm" />
              <div className="min-w-0">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="truncate font-medium text-fg">{r.name}</span>
                  {r.observed && (
                    <StatusChip tone="info" dot>
                      In library
                    </StatusChip>
                  )}
                </div>
                {aliases.length > 0 && (
                  <div className="truncate text-xs text-subtle">
                    {aliases.join(", ")}
                    {r.aliases.length > 3 && ` +${r.aliases.length - 3}`}
                  </div>
                )}
              </div>
            </div>
          );
        },
        meta: { className: "max-w-[230px] sm:max-w-[340px]" } satisfies DataTableColumnMeta,
      },
      {
        id: "attackId",
        header: "ATT&CK ID",
        accessorFn: (r) => r.attackId ?? "~",
        cell: ({ row: { original: r } }) =>
          r.attackId ? (
            <span className="font-mono text-xs text-muted">{r.attackId}</span>
          ) : (
            <span className="text-xs text-subtle">Not in ATT&CK</span>
          ),
        meta: { hideBelow: "sm" } satisfies DataTableColumnMeta,
      },
      {
        id: "reports",
        header: "Library reports",
        accessorFn: (r) => r.reportCount,
        cell: ({ row: { original: r } }) =>
          r.reportCount ? (
            <div>
              <div className="font-medium tabular-nums text-fg">{r.reportCount}</div>
              <div className="text-xs text-subtle">Last {formatDay(r.lastSeen) ?? "unknown"}</div>
            </div>
          ) : (
            <span className="text-subtle">–</span>
          ),
      },
      {
        id: "techniques",
        header: "Techniques",
        accessorFn: (r) => r.attributedTechniques + r.newTechniques,
        cell: ({ row: { original: r } }) => <TechniqueMiniBar row={r} max={maxTech} />,
        meta: { hideBelow: "md", className: "w-[220px]" } satisfies DataTableColumnMeta,
      },
      {
        id: "software",
        header: "Software",
        accessorFn: (r) => r.software,
        cell: ({ getValue }) => (
          <span className="tabular-nums text-muted">{getValue() as number}</span>
        ),
        meta: { align: "right", hideBelow: "lg" } satisfies DataTableColumnMeta,
      },
      {
        id: "campaigns",
        header: "Campaigns",
        accessorFn: (r) => r.campaigns,
        cell: ({ getValue }) => (
          <span className="tabular-nums text-muted">{(getValue() as number) || "–"}</span>
        ),
        meta: { align: "right", hideBelow: "lg" } satisfies DataTableColumnMeta,
      },
      {
        id: "emulation",
        header: "Emulation",
        enableSorting: false,
        cell: ({ row: { original: r } }) => <EmulationCell emu={r.emulation} />,
        meta: { hideBelow: "xl" } satisfies DataTableColumnMeta,
      },
    ],
    [maxTech],
  );

  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const notSynced = data && !data.emulationSynced;

  return (
    <AppShell>
      <div className="mx-auto w-full max-w-[1400px]">
        <PageHeader
          title="Threat actors"
          description={
            kpis
              ? `${kpis.attackGroups} ATT&CK groups${data?.attackVersion ? ` (v${data.attackVersion})` : ""}, ${kpis.observedInLibrary} seen in ${kpis.libraryReports} library report${kpis.libraryReports === 1 ? "" : "s"}. Open an actor to compare what ATT&CK attributes with what your library observed.`
              : "ATT&CK groups and actors observed in your library."
          }
        />

        <div className="mb-6 sm:hidden">
          <KpiStrip
            items={[
              { icon: Users, kind: "actor", label: "ATT&CK groups", value: kpis?.attackGroups ?? "–" },
              { icon: Activity, kind: "advisory", label: "In library", value: kpis?.observedInLibrary ?? "–" },
              { icon: UserRoundX, kind: "actor", label: "Not in ATT&CK", value: kpis?.notInAttack ?? "–" },
              { icon: Layers, kind: "technique", label: "Techniques seen", value: kpis?.techniquesObserved ?? "–" },
              {
                icon: CalendarClock,
                kind: "source",
                label: "Last activity",
                value: <span className="text-base">{kpis?.lastActivity ? formatDay(kpis.lastActivity) : "–"}</span>,
              },
            ]}
          />
        </div>
        <div className="mb-6 hidden gap-4 sm:grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          <StatCard
            icon={Users}
            kind="actor"
            label="ATT&CK groups"
            value={kpis?.attackGroups ?? "–"}
            hint="Bundled ATT&CK snapshot"
          />
          <StatCard
            icon={Activity}
            kind="advisory"
            label="In library"
            value={kpis?.observedInLibrary ?? "–"}
            hint="Actors linked to at least one report"
          />
          <StatCard
            icon={UserRoundX}
            kind="actor"
            label="Not in ATT&CK"
            value={kpis?.notInAttack ?? "–"}
            hint="Named in reports, no ATT&CK group"
          />
          <StatCard
            icon={Layers}
            kind="technique"
            label="Techniques seen"
            value={kpis?.techniquesObserved ?? "–"}
            hint="Across actor-linked reports"
          />
          <StatCard
            icon={CalendarClock}
            kind="source"
            label="Last activity"
            value={
              <span className="text-2xl">
                {kpis?.lastActivity ? formatDay(kpis.lastActivity) : "–"}
              </span>
            }
            hint="Latest actor-linked report"
          />
        </div>

        <Toolbar
          left={
            <>
              <div className="relative w-full sm:w-72">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Search name or alias…"
                  aria-label="Search threat actors"
                  className="h-9 w-full rounded-lg border border-border bg-bg-elevated pl-9 pr-8 text-sm text-fg placeholder:text-subtle focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)]"
                />
                {q && (
                  <button
                    type="button"
                    aria-label="Clear search"
                    onClick={() => setQ("")}
                    className="absolute right-2 top-1/2 flex size-6 -translate-y-1/2 items-center justify-center rounded text-subtle hover:text-fg"
                  >
                    <X className="size-3.5" />
                  </button>
                )}
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={observedOnly}
                onClick={() =>
                  update({ observed: observedOnly ? undefined : true, page: undefined })
                }
                className={cn(
                  "inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-sm font-medium transition-colors",
                  observedOnly
                    ? "border-[color-mix(in_oklab,var(--color-primary)_45%,transparent)] bg-bg-subtle text-fg"
                    : "border-border bg-bg-elevated text-muted hover:text-fg",
                )}
              >
                <span
                  aria-hidden
                  className={cn(
                    "relative h-4 w-7 rounded-full transition-colors",
                    observedOnly ? "bg-[var(--color-primary)]" : "bg-bg-subtle ring-1 ring-border",
                  )}
                >
                  <span
                    className={cn(
                      "absolute top-0.5 size-3 rounded-full bg-white shadow transition-all",
                      observedOnly ? "left-3.5" : "left-0.5",
                    )}
                  />
                </span>
                Observed in library
              </button>
              <label className="inline-flex items-center gap-2 text-sm text-muted">
                <span className="hidden sm:inline">Sort</span>
                <Select
                  value={sort}
                  onValueChange={(v) => update({ sort: v as ActorSort, page: undefined })}
                  aria-label="Sort actors"
                  className="px-2.5"
                >
                  {SORTS.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </Select>
              </label>
            </>
          }
          right={
            <SegmentedTabs
              ariaLabel="View"
              items={[
                { value: "table", label: "Table", icon: List },
                { value: "cards", label: "Cards", icon: LayoutGrid },
              ]}
              value={view}
              onChange={(v) => update({ view: v === "table" ? undefined : v })}
            />
          }
        />

        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm text-muted">
            {query.isLoading ? "Loading actors…" : `${total} actor${total === 1 ? "" : "s"}`}
            {search.q ? ` matching “${search.q}”` : ""}
            {observedOnly ? " seen in the library" : ""}
            {notSynced && <span className="text-subtle"> · Emulation sources not synced yet</span>}
          </p>
          {view === "table" && (
            <div className="hidden md:block">
              <TechniqueBarLegend />
            </div>
          )}
        </div>

        {query.isLoading ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-bg-card py-20 text-muted">
            <ActivitySpinner size="lg" className="mb-2 text-accent" />
            <p className="text-sm">Building the actor index…</p>
          </div>
        ) : query.isError ? (
          <EmptyState
            className="rounded-xl border border-border bg-bg-card"
            icon={Users}
            title="Could not load threat actors"
            description={String((query.error as Error | null)?.message ?? "Unknown error")}
          />
        ) : view === "cards" ? (
          rows.length ? (
            <div
              className={cn(
                "grid gap-4 sm:grid-cols-2 xl:grid-cols-3",
                query.isFetching && "opacity-70",
              )}
            >
              {rows.map((r) => (
                <ActorCard key={r.id} row={r} />
              ))}
            </div>
          ) : (
            <NoActors q={search.q} observedOnly={observedOnly} />
          )
        ) : (
          <div className={cn(query.isFetching && "opacity-70")}>
            <DataTable
              data={rows}
              columns={columns}
              getRowId={(r) => r.id}
              onRowClick={(r) =>
                void navigate({ to: "/actors/$actorId", params: { actorId: r.id } })
              }
              caption="Threat actors"
              empty={<NoActors q={search.q} observedOnly={observedOnly} />}
            />
          </div>
        )}

        {total > PAGE_SIZE && (
          <div className="mt-4">
            <Pagination
              page={page}
              pageCount={pageCount}
              total={total}
              pageSize={PAGE_SIZE}
              onPage={(p) => update({ page: p === 1 ? undefined : p })}
            />
          </div>
        )}
      </div>
    </AppShell>
  );
}

function NoActors({ q, observedOnly }: { q?: string; observedOnly: boolean }) {
  return (
    <EmptyState
      icon={Users}
      title={
        q
          ? `No actors match “${q}”`
          : observedOnly
            ? "No actors observed in the library yet"
            : "No actors"
      }
      description={
        observedOnly
          ? "Actors appear here once an ingested report names an ATT&CK group, alias or a new actor. Turn the toggle off to browse all ATT&CK groups."
          : "Search matches ATT&CK names, aliases and IDs, plus actor names found in library reports."
      }
    />
  );
}
