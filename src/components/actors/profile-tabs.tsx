import { useMemo, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import { ArrowRight, Bug, FileText, FlaskConical, Layers, Quote, Target } from "lucide-react";
import type {
  ActorCampaignRow,
  ActorProfile,
  ActorReportRef,
  ActorSoftwareRow,
  ActorTechniqueRow,
} from "@/lib/aie/actors/types";
import { SectionCard, SegmentedTabs } from "@/components/layout/page";
import { DataTable, type DataTableColumnMeta } from "@/components/ui/data-table";
import { EmptyState, Meter, StatusChip } from "@/components/ui/primitives";
import { TacticDot } from "./actor-ui";
import {
  attackCampaignUrl,
  attackSoftwareUrl,
  attackTechniqueUrl,
  formatDay,
  purpleLink,
  shortTactic,
} from "./actor-format";

// ---------------------------------------------------------------------------------------------
// Techniques
// ---------------------------------------------------------------------------------------------

type TechFilter = "all" | "observed" | "new" | "attack";

const SOURCE_LABEL: Record<ActorTechniqueRow["source"], string> = {
  attack: "ATT&CK",
  observed: "Observed",
  both: "Both",
};

function SourceChip({ t }: { t: ActorTechniqueRow }) {
  if (t.isNew)
    return (
      <StatusChip tone="warning">
        <span className="sm:hidden">New</span>
        <span className="hidden sm:inline">New vs ATT&CK</span>
      </StatusChip>
    );
  if (t.source === "both") return <StatusChip tone="success">Both</StatusChip>;
  if (t.source === "observed") return <StatusChip tone="info">Observed</StatusChip>;
  return <StatusChip>ATT&CK</StatusChip>;
}

export function TechniquesTab({ profile }: { profile: ActorProfile }) {
  const [filter, setFilter] = useState<TechFilter>("all");
  const [open, setOpen] = useState<string | null>(null);
  const counts = useMemo(
    () => ({
      all: profile.techniques.length,
      observed: profile.techniques.filter((t) => t.source !== "attack").length,
      new: profile.techniques.filter((t) => t.isNew).length,
      attack: profile.techniques.filter((t) => t.source !== "observed").length,
    }),
    [profile.techniques],
  );
  const rows = profile.techniques.filter((t) =>
    filter === "all"
      ? true
      : filter === "observed"
        ? t.source !== "attack"
        : filter === "new"
          ? t.isNew
          : t.source !== "observed",
  );
  const selected = open ? profile.techniques.find((t) => t.id === open) : undefined;

  const columns = useMemo<ColumnDef<ActorTechniqueRow, unknown>[]>(() => {
    const all: ColumnDef<ActorTechniqueRow, unknown>[] = [
      {
        id: "id",
        header: "Technique",
        accessorFn: (t) => t.id,
        cell: ({ row: { original: t } }) => (
          <div className="min-w-0">
            <a
              href={attackTechniqueUrl(t.id)}
              target="_blank"
              rel="noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="font-mono text-xs text-muted hover:underline"
            >
              {t.id}
            </a>
            {t.name === t.id ? (
              <div className="truncate text-sm text-subtle">Not in the bundled ATT&CK snapshot</div>
            ) : (
              <div className="truncate text-sm text-fg" title={t.name}>
                {t.name}
              </div>
            )}
          </div>
        ),
        meta: { className: "max-w-[200px] sm:max-w-[280px]" } satisfies DataTableColumnMeta,
      },
      {
        id: "tactic",
        header: "Tactic",
        accessorFn: (t) => t.tactic ?? "~",
        cell: ({ row: { original: t } }) =>
          t.tactic ? (
            <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm text-muted">
              <TacticDot tactic={t.tactic} />
              {shortTactic(t.tactic)}
              {t.tactics.length > 1 && (
                <span className="text-xs text-subtle">+{t.tactics.length - 1}</span>
              )}
            </span>
          ) : (
            <span className="text-subtle">–</span>
          ),
        meta: { hideBelow: "sm" } satisfies DataTableColumnMeta,
      },
      {
        id: "source",
        header: "Source",
        accessorFn: (t) => (t.isNew ? "0" : SOURCE_LABEL[t.source]),
        cell: ({ row: { original: t } }) => <SourceChip t={t} />,
      },
      {
        id: "evidence",
        header: "Evidence",
        accessorFn: (t) => t.observedReports * 1000 + t.evidenceCount,
        cell: ({ row: { original: t } }) =>
          t.observedReports ? (
            <span
              className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs tabular-nums text-muted"
              title={`${t.observedReports} report(s), ${t.evidenceCount} quote(s)`}
            >
              <Quote className="size-3.5" />
              {t.observedReports} rpt · {t.evidenceCount}
            </span>
          ) : (
            <span className="text-subtle">–</span>
          ),
        meta: { hideBelow: "md" } satisfies DataTableColumnMeta,
      },
      {
        id: "atomic",
        header: "Atomic",
        accessorFn: (t) => (t.atomic === null ? -1 : Number(t.atomic)),
        cell: ({ row: { original: t } }) =>
          t.atomic === null ? (
            <span className="text-xs text-subtle">Not synced</span>
          ) : t.atomic ? (
            <StatusChip tone="success">Available</StatusChip>
          ) : (
            <span className="text-xs text-subtle">None</span>
          ),
        meta: { hideBelow: "lg" } satisfies DataTableColumnMeta,
      },
    ];
    return profile.emulation.synced ? all : all.filter((c) => c.id !== "atomic");
  }, [profile.emulation.synced]);

  return (
    <SectionCard
      title="Techniques"
      icon={Layers}
      iconKind="technique"
      info="ATT&CK-attributed techniques merged with techniques observed in this actor's library reports. 'New vs ATT&CK' = observed but not attributed (no exact, parent or sub-technique match)."
      actions={
        <SegmentedTabs
          size="sm"
          ariaLabel="Filter techniques"
          items={[
            { value: "all", label: "All", count: counts.all },
            { value: "observed", label: "Observed", count: counts.observed },
            { value: "new", label: "New vs ATT&CK", count: counts.new },
            { value: "attack", label: "ATT&CK", count: counts.attack },
          ]}
          value={filter}
          onChange={setFilter}
        />
      }
      bodyClassName="p-0 pt-4"
    >
      {selected && selected.evidence.length > 0 && (
        <div className="border-t border-border bg-bg-subtle/40 p-5">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-medium text-fg">
              Evidence for <span className="font-mono">{selected.id}</span> {selected.name}
            </h3>
            <span className="flex items-center gap-3">
              <a
                href={attackTechniqueUrl(selected.id)}
                target="_blank"
                rel="noreferrer"
                className="text-sm text-accent hover:underline"
              >
                ATT&CK page →
              </a>
              <button
                type="button"
                onClick={() => setOpen(null)}
                className="text-sm text-muted hover:text-fg"
              >
                Close
              </button>
            </span>
          </div>
          <ul className="space-y-3">
            {selected.evidence.map((e, i) => (
              <li
                key={i}
                className="border-l-2 pl-3 text-sm"
                style={{ borderColor: "var(--color-cat-technique)" }}
              >
                <p className="text-fg">“{e.quote}”</p>
                <p className="mt-1 text-xs text-subtle">
                  <StatusChip tone={e.label === "observed" ? "success" : "neutral"}>
                    {e.label}
                  </StatusChip>{" "}
                  <Link
                    to="/library/$reportId"
                    params={{ reportId: e.reportId }}
                    className="hover:underline"
                  >
                    {e.reportTitle}
                  </Link>
                  {e.section ? ` · ${e.section}` : ""}
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="[&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
        <DataTable
          data={rows}
          columns={columns}
          getRowId={(t) => t.id}
          onRowClick={(t) =>
            t.evidence.length
              ? setOpen(open === t.id ? null : t.id)
              : window.open(attackTechniqueUrl(t.id), "_blank", "noopener")
          }
          dense
          empty={<EmptyState icon={Layers} title="No techniques in this view" />}
        />
      </div>
      <p className="border-t border-border px-5 py-3 text-xs text-subtle">
        Select a row with evidence to read its quotes; other rows open the ATT&CK technique page.{" "}
        {!profile.emulation.synced &&
          "Atomic availability appears once the Atomic Red Team source is synced. "}{" "}
        Observed techniques are report-level: a report linked to several actors counts for each.
      </p>
    </SectionCard>
  );
}

// ---------------------------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------------------------

export function ReportsTab({ profile }: { profile: ActorProfile }) {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<ActorReportRef, unknown>[]>(
    () => [
      {
        id: "title",
        header: "Report",
        accessorFn: (r) => r.title,
        cell: ({ row: { original: r } }) => (
          <div className="min-w-0">
            <div className="line-clamp-2 font-medium text-fg">{r.title}</div>
            <div className="text-xs text-subtle">
              {r.publisher || "Unknown publisher"} · linked by “{r.matched}”
            </div>
          </div>
        ),
        meta: { className: "max-w-[520px]" } satisfies DataTableColumnMeta,
      },
      {
        id: "date",
        header: "Published",
        accessorFn: (r) => r.publishedAt ?? r.ingestedAt,
        cell: ({ row: { original: r } }) => (
          <span className="whitespace-nowrap tabular-nums text-muted">
            {formatDay(r.publishedAt ?? r.ingestedAt) ?? "–"}
          </span>
        ),
        meta: { hideBelow: "sm" } satisfies DataTableColumnMeta,
      },
      {
        id: "techniques",
        header: "Techniques",
        accessorFn: (r) => r.techniqueCount,
        cell: ({ getValue }) => (
          <span className="tabular-nums text-muted">{getValue() as number}</span>
        ),
        meta: { align: "right", hideBelow: "md" } satisfies DataTableColumnMeta,
      },
      {
        id: "quality",
        header: "Quality",
        accessorFn: (r) => r.qualityScore,
        cell: ({ row: { original: r } }) => {
          const v = r.qualityScore > 1 ? r.qualityScore / 100 : r.qualityScore;
          return (
            <div className="flex w-24 items-center gap-2">
              <Meter
                value={v}
                tone={v >= 0.75 ? "success" : v >= 0.5 ? "warning" : "danger"}
                label="Quality"
              />
              <span className="text-xs tabular-nums text-muted">{Math.round(v * 100)}</span>
            </div>
          );
        },
        meta: { hideBelow: "lg" } satisfies DataTableColumnMeta,
      },
    ],
    [],
  );
  return (
    <DataTable
      data={profile.reports}
      columns={columns}
      getRowId={(r) => r.id}
      onRowClick={(r) => void navigate({ to: "/library/$reportId", params: { reportId: r.id } })}
      initialSorting={[{ id: "date", desc: true }]}
      empty={
        <EmptyState
          icon={FileText}
          title="No library reports for this actor"
          description="Ingest reports that name the group or its aliases, or search the library for them."
        />
      }
    />
  );
}

// ---------------------------------------------------------------------------------------------
// Campaigns
// ---------------------------------------------------------------------------------------------

export function CampaignsTab({ profile }: { profile: ActorProfile }) {
  const columns = useMemo<ColumnDef<ActorCampaignRow, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Campaign",
        accessorFn: (c) => c.name,
        cell: ({ row: { original: c } }) => (
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium text-fg">{c.name}</span>
              <span className="font-mono text-xs text-subtle">{c.id}</span>
            </div>
            {c.description && (
              <div className="line-clamp-2 text-xs text-muted">{c.description}</div>
            )}
          </div>
        ),
        meta: { className: "max-w-[520px]" } satisfies DataTableColumnMeta,
      },
      {
        id: "first",
        header: "First seen",
        accessorFn: (c) => c.firstSeen ?? "",
        cell: ({ row: { original: c } }) => (
          <span className="whitespace-nowrap tabular-nums text-muted">
            {formatDay(c.firstSeen) ?? "–"}
          </span>
        ),
        meta: { hideBelow: "sm" } satisfies DataTableColumnMeta,
      },
      {
        id: "last",
        header: "Last seen",
        accessorFn: (c) => c.lastSeen ?? "",
        cell: ({ row: { original: c } }) => (
          <span className="whitespace-nowrap tabular-nums text-muted">
            {formatDay(c.lastSeen) ?? "–"}
          </span>
        ),
        meta: { hideBelow: "sm" } satisfies DataTableColumnMeta,
      },
      {
        id: "techniques",
        header: "Techniques",
        accessorFn: (c) => c.techniqueCount,
        cell: ({ getValue }) => (
          <span className="tabular-nums text-muted">{getValue() as number}</span>
        ),
        meta: { align: "right" } satisfies DataTableColumnMeta,
      },
      {
        id: "software",
        header: "Software",
        accessorFn: (c) => c.softwareCount,
        cell: ({ getValue }) => (
          <span className="tabular-nums text-muted">{getValue() as number}</span>
        ),
        meta: { align: "right", hideBelow: "md" } satisfies DataTableColumnMeta,
      },
    ],
    [],
  );
  return (
    <DataTable
      data={profile.campaigns}
      columns={columns}
      getRowId={(c) => c.id}
      onRowClick={(c) => window.open(attackCampaignUrl(c.id), "_blank", "noopener")}
      empty={
        <EmptyState
          icon={Target}
          title="No ATT&CK campaigns attributed"
          description={
            profile.row.inAttack
              ? "The bundled ATT&CK snapshot links no campaigns to this group."
              : "Campaigns come from ATT&CK; this actor is not in ATT&CK."
          }
        />
      }
    />
  );
}

// ---------------------------------------------------------------------------------------------
// Software
// ---------------------------------------------------------------------------------------------

export function SoftwareTab({ profile }: { profile: ActorProfile }) {
  const columns = useMemo<ColumnDef<ActorSoftwareRow, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Software",
        accessorFn: (s) => s.name,
        cell: ({ row: { original: s } }) => (
          <div className="flex items-center gap-2">
            <span className="font-medium text-fg">{s.name}</span>
            {s.id && <span className="font-mono text-xs text-subtle">{s.id}</span>}
          </div>
        ),
      },
      {
        id: "type",
        header: "Type",
        accessorFn: (s) => s.type ?? "~",
        cell: ({ row: { original: s } }) => (
          <span className="text-sm capitalize text-muted">{s.type ?? "Unknown"}</span>
        ),
      },
      {
        id: "platforms",
        header: "Platforms",
        accessorFn: (s) => s.platforms.join(", "),
        cell: ({ row: { original: s } }) => (
          <span className="text-sm text-muted">{s.platforms.join(", ") || "–"}</span>
        ),
        meta: { hideBelow: "md", className: "max-w-[260px]" } satisfies DataTableColumnMeta,
      },
      {
        id: "source",
        header: "Source",
        accessorFn: (s) => (s.attributed ? (s.observedReports ? "Both" : "ATT&CK") : "Observed"),
        cell: ({ row: { original: s } }) =>
          s.attributed && s.observedReports ? (
            <StatusChip tone="success">Both</StatusChip>
          ) : s.attributed ? (
            <StatusChip>ATT&CK</StatusChip>
          ) : (
            <StatusChip tone="warning">New vs ATT&CK</StatusChip>
          ),
      },
      {
        id: "reports",
        header: "Reports",
        accessorFn: (s) => s.observedReports,
        cell: ({ getValue }) => (
          <span className="tabular-nums text-muted">{(getValue() as number) || "–"}</span>
        ),
        meta: { align: "right", hideBelow: "sm" } satisfies DataTableColumnMeta,
      },
      {
        id: "techniques",
        header: "Techniques",
        accessorFn: (s) => s.techniqueCount,
        cell: ({ getValue }) => (
          <span className="tabular-nums text-muted">{(getValue() as number) || "–"}</span>
        ),
        meta: { align: "right", hideBelow: "lg" } satisfies DataTableColumnMeta,
      },
    ],
    [],
  );
  return (
    <DataTable
      data={profile.software}
      columns={columns}
      getRowId={(s) => s.id ?? `n:${s.name}`}
      onRowClick={(s) =>
        s.id ? window.open(attackSoftwareUrl(s.id), "_blank", "noopener") : undefined
      }
      empty={
        <EmptyState
          icon={Bug}
          title="No software recorded"
          description="Neither ATT&CK nor the linked library reports name software for this actor."
        />
      }
    />
  );
}

// ---------------------------------------------------------------------------------------------
// Emulation
// ---------------------------------------------------------------------------------------------

export function EmulationTab({ profile }: { profile: ActorProfile }) {
  const total = profile.techniques.length;
  const atomic = profile.techniques.filter((t) => t.atomic).length;
  const synced = profile.emulation.synced;
  const observed = profile.techniques.filter((t) => t.source !== "attack").length;
  return (
    <>
      <section
        className="rounded-xl border border-border bg-bg-card p-6"
        style={{
          backgroundImage:
            "linear-gradient(135deg, color-mix(in oklab, var(--color-cat-emulation) 7%, transparent), transparent 60%)",
        }}
      >
        <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
          <div className="flex min-w-0 items-start gap-4">
            <span
              className="flex size-11 shrink-0 items-center justify-center rounded-xl"
              style={{
                color: "var(--color-cat-emulation)",
                backgroundColor: "color-mix(in oklab, var(--color-cat-emulation) 16%, transparent)",
              }}
            >
              <FlaskConical className="size-5" strokeWidth={1.9} />
            </span>
            <div className="min-w-0">
              <h2 className="text-lg font-semibold text-fg">
                Build a purple path for {profile.row.name}
              </h2>
              <p className="mt-1 max-w-2xl text-sm text-muted">
                Turn {total} technique{total === 1 ? "" : "s"} ({observed} observed in your library)
                into an ordered emulation and detection plan: procedures, expected telemetry and
                detections per step.
              </p>
            </div>
          </div>
          <Link
            to={purpleLink(profile.row).to}
            search={purpleLink(profile.row).search as never}
            className="btn-primary inline-flex h-10 shrink-0 items-center justify-center gap-2 rounded-lg px-4 text-sm font-medium"
          >
            Build purple path
            <ArrowRight className="size-4" />
          </Link>
        </div>
      </section>

      <SectionCard title="Emulation availability" icon={FlaskConical} iconKind="emulation">
        {synced ? (
          <div className="grid gap-6 md:grid-cols-2">
            <div>
              <div className="text-sm text-muted">Atomic Red Team coverage</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-[28px] font-semibold tabular-nums text-fg">
                  {total ? Math.round((atomic / total) * 100) : 0}%
                </span>
                <span className="text-sm text-muted">
                  {atomic} of {total} techniques
                </span>
              </div>
              <Meter
                className="mt-3"
                value={total ? atomic / total : 0}
                color="var(--color-cat-emulation)"
                label="Atomic coverage"
              />
            </div>
            <div>
              <div className="text-sm text-muted">CTID adversary emulation plans</div>
              {profile.emulation.plans.length ? (
                <ul className="mt-2 space-y-2">
                  {profile.emulation.plans.map((p) => (
                    <li
                      key={p.reportId}
                      className="flex items-center justify-between gap-3 text-sm"
                    >
                      <Link
                        to="/library/$reportId"
                        params={{ reportId: p.reportId }}
                        className="truncate font-medium text-fg hover:underline"
                      >
                        {p.title}
                      </Link>
                      <span className="shrink-0 text-xs text-muted">
                        {p.planType === "micro" ? "Micro plan" : "Full plan"} · {p.techniques}{" "}
                        techniques
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 text-sm text-subtle">No CTID plan names this group.</p>
              )}
            </div>
          </div>
        ) : (
          <EmptyState
            icon={FlaskConical}
            title="Emulation sources not synced"
            description="Atomic Red Team tests and CTID emulation plans appear here once those structured sources are synced from Sources. Until then, availability is unknown rather than zero."
            action={
              <Link to="/sources" className="text-sm text-accent hover:underline">
                Open sources →
              </Link>
            }
          />
        )}
      </SectionCard>
    </>
  );
}
