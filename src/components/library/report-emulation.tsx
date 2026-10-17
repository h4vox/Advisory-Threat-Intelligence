import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowRight, ClipboardCopy, Crosshair, ExternalLink, FlaskConical, GitBranch, Info, Swords, Wrench } from "lucide-react";
import { toast } from "sonner";
import { EntityChip, EntityIcon, entityMeta } from "@/components/ui/entity";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { StatusChip } from "@/components/ui/primitives";
import type { EmulationOption } from "@/lib/aie/types";
import { cn } from "@/lib/cn";
import { fetchEmulationOptions, hasEmulationOptionsApi, type EmulationOptionsMap } from "./intel-api";
import { TACTIC_ORDER, normalizeTactic, type TechniqueRef } from "./intel-taxonomy";
import { buildPurplePath, type PurpleBuildResult } from "@/lib/aie/server-emulation";
import { toMarkdown } from "@/lib/aie/purple/export";
import { PurpleExportButtons, PurplePathView } from "@/components/purple/purple-path-view";

/** Simulation objects for one report, from the purple path generator (source order kept when reported). */
function useReportPath(reportId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["purple-path-report", reportId],
    queryFn: () => buildPurplePath({ data: { kind: "report", value: reportId, options: { platforms: [], excludeHighRisk: false, maxSteps: 40 } } }),
    enabled,
    staleTime: 5 * 60_000,
  });
}

const KIND_META: Record<EmulationOption["kind"], { label: string; icon: typeof FlaskConical; color: string }> = {
  atomic_test: { label: "Atomic test", icon: FlaskConical, color: "var(--color-cat-emulation)" },
  caldera_ability: { label: "CALDERA ability", icon: Crosshair, color: "var(--color-cat-emulation)" },
  ctid_procedure: { label: "CTID procedure", icon: Swords, color: "var(--color-cat-actor)" },
  attack_flow: { label: "Attack flow", icon: GitBranch, color: "var(--color-cat-flow)" },
  custom: { label: "Custom", icon: Wrench, color: "var(--color-cat-source)" },
};

const LABEL_TONE = { observed: "success", inferred: "warning", mapped: "neutral" } as const;
const LABEL_TEXT = { observed: "Observed", inferred: "Inferred", mapped: "Mapped" } as const;

function useEmulationOptions(techniqueIds: string[]) {
  return useQuery({
    queryKey: ["emulation-options", [...techniqueIds].sort().join(",")],
    queryFn: () => fetchEmulationOptions(techniqueIds),
    enabled: hasEmulationOptionsApi && techniqueIds.length > 0,
    staleTime: 5 * 60_000,
  });
}

/** Simulation order: source-reported sequence when the evidence has one, else ATT&CK tactic order. */
function orderForSimulation(techs: TechniqueRef[], reported: boolean): TechniqueRef[] {
  if (reported) return techs;
  const idx = (t: TechniqueRef) => {
    const n = normalizeTactic(t.tactic);
    const i = n ? TACTIC_ORDER.indexOf(n as (typeof TACTIC_ORDER)[number]) : -1;
    return i === -1 ? 99 : i;
  };
  return [...techs].sort((a, b) => idx(a) - idx(b));
}

function OptionRow({ o }: { o: EmulationOption }) {
  const m = KIND_META[o.kind] ?? KIND_META.custom;
  return (
    <li className="flex flex-col gap-2 px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-2.5">
        <span
          className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md"
          style={{ color: m.color, backgroundColor: `color-mix(in oklab, ${m.color} 16%, transparent)` }}
          title={m.label}
        >
          <m.icon className="size-3.5" strokeWidth={1.9} />
        </span>
        <div className="min-w-0">
          <p className="text-sm text-fg">{o.name}</p>
          <p className="truncate text-xs text-subtle">
            {m.label}
            {o.ref ? ` · ${o.ref}` : ""}
          </p>
        </div>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-1.5 pl-8 sm:pl-0">
        {o.platforms.map((p) => (
          <span key={p} className="rounded bg-bg-subtle px-1.5 py-0.5 text-[11px] text-muted">
            {p}
          </span>
        ))}
        {o.executor && <span className="rounded bg-bg-subtle px-1.5 py-0.5 font-mono text-[11px] text-muted">{o.executor}</span>}
        {o.elevationRequired && <StatusChip tone="warning">Elevated</StatusChip>}
        {o.sourceUrl && (
          <a
            href={o.sourceUrl}
            target="_blank"
            rel="noreferrer"
            aria-label={`Open source for ${o.name}`}
            className="inline-flex size-7 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg"
          >
            <ExternalLink className="size-3.5" />
          </a>
        )}
      </div>
    </li>
  );
}

function planText(title: string, url: string, steps: TechniqueRef[], options: EmulationOptionsMap | null | undefined, basis: string) {
  const lines = [
    `# Simulation plan (draft) — ${title}`,
    `Source: ${url}`,
    `Order: ${basis}`,
    `Status: planning only. Nothing has been executed. Review every procedure and run it only in an authorised lab.`,
    "",
  ];
  steps.forEach((t, i) => {
    lines.push(`${i + 1}. ${t.id}${t.name ? ` ${t.name}` : ""}${t.tactic ? ` [${t.tactic}]` : ""} (${LABEL_TEXT[t.label].toLowerCase()})`);
    const opts = options?.[t.id] ?? [];
    if (!opts.length) lines.push("   - No emulation option synced; needs a custom procedure.");
    for (const o of opts.slice(0, 5)) {
      lines.push(`   - ${KIND_META[o.kind]?.label ?? o.kind}: ${o.name}${o.ref ? ` (${o.ref})` : ""}${o.platforms.length ? ` — ${o.platforms.join("/")}` : ""}${o.executor ? `, ${o.executor}` : ""}`);
    }
  });
  return lines.join("\n");
}

export function ReportEmulation({
  reportId,
  title,
  url,
  techniques,
  reportedOrder,
}: {
  reportId: string;
  title: string;
  url: string;
  techniques: TechniqueRef[];
  reportedOrder: boolean;
}) {
  const pathQuery = useReportPath(reportId, techniques.length > 0);
  const built = pathQuery.data && "path" in pathQuery.data ? (pathQuery.data as PurpleBuildResult) : null;
  const ids = useMemo(() => techniques.map((t) => t.id), [techniques]);
  const { data: options, isLoading, isError } = useEmulationOptions(ids);
  const steps = useMemo(() => orderForSimulation(techniques, reportedOrder), [techniques, reportedOrder]);
  const basis = reportedOrder ? "Sequence reported in the source" : "ATT&CK tactic order (the source does not give a verified sequence)";
  const synced = hasEmulationOptionsApi && !isError && options != null && (built ? built.coverage.emulationSynced : true);
  const covered = synced ? steps.filter((t) => (options![t.id] ?? []).length > 0).length : 0;
  const atomicCount = synced ? steps.reduce((n, t) => n + (options![t.id] ?? []).filter((o) => o.kind === "atomic_test").length, 0) : 0;
  const emu = entityMeta("emulation").color;

  const copyPlan = () => {
    void navigator.clipboard.writeText(built ? toMarkdown(built.path) : planText(title, url, steps, options, basis));
    toast.success("Simulation plan copied", { description: "Markdown draft. Nothing was executed." });
  };
  if (techniques.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-bg-card px-6 py-10 text-center">
        <p className="text-sm font-medium text-fg">No ATT&CK techniques mapped for this report</p>
        <p className="mt-1 text-sm text-muted">Emulation options are looked up per technique, so there is nothing to plan yet.</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Call to action */}
      <section
        className="overflow-hidden rounded-xl border"
        style={{
          borderColor: `color-mix(in oklab, ${emu} 35%, transparent)`,
          backgroundImage: `linear-gradient(135deg, color-mix(in oklab, ${emu} 14%, transparent), transparent 70%)`,
        }}
      >
        <div className="flex flex-col gap-4 p-5 md:flex-row md:items-start md:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <EntityIcon kind="emulation" size="lg" icon={Swords} />
            <div className="min-w-0">
              <h2 className="text-lg font-semibold tracking-tight text-fg">Build simulation from this report</h2>
              <p className="mt-1 max-w-2xl text-sm text-muted">
                {steps.length} techniques in {basis.toLowerCase()}.{" "}
                {synced ? (
                  <>
                    <span className="text-fg">{covered}</span> have at least one emulation option ({atomicCount} Atomic tests).
                  </>
                ) : (
                  "Emulation libraries are not synced yet, so options cannot be matched."
                )}
              </p>
              <p className="mt-2 inline-flex items-center gap-1.5 text-xs text-subtle">
                <Info className="size-3.5" />
                Planning only. AIE drafts the plan; it never executes procedures.
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2 md:max-w-[50%] md:justify-end">
            <button
              type="button"
              onClick={copyPlan}
              className="btn-primary inline-flex h-9 items-center gap-2 rounded-lg px-3 text-sm font-medium"
            >
              <ClipboardCopy className="size-4" strokeWidth={1.75} />
              Copy plan
            </button>
            {built && <PurpleExportButtons path={built.path} />}
            <Link
              to="/purple"
              search={{ report: reportId }}
              className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg hover:bg-bg-subtle"
            >
              Open in Purple paths
              <ArrowRight className="size-4" strokeWidth={1.75} />
            </Link>
          </div>
        </div>
        {built ? (
          <div className="border-t border-border bg-bg-card p-4">
            <PurplePathView path={built.path} compact />
          </div>
        ) : pathQuery.isLoading ? (
          <div className="flex items-center gap-2 border-t border-border bg-bg-card px-5 py-6 text-sm text-muted">
            <ActivitySpinner size="sm" /> Building simulation objects…
          </div>
        ) : (
        <ol className="grid border-t border-border bg-bg-card sm:grid-cols-2 xl:grid-cols-3">
          {steps.map((t, i) => {
            const n = options?.[t.id]?.length ?? 0;
            return (
              <li key={t.id} className="flex min-w-0 items-center gap-2.5 px-4 py-2.5 shadow-[inset_-1px_-1px_0_var(--color-border)]">
                <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-bg-subtle text-[11px] font-medium tabular-nums text-muted">{i + 1}</span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm text-fg">
                    <span className="font-mono text-xs" style={{ color: "var(--color-cat-technique)" }}>
                      {t.id}
                    </span>{" "}
                    {t.name ?? ""}
                  </p>
                  <p className="truncate text-[11px] text-subtle">{t.tactic ?? "Tactic unknown"}</p>
                </div>
                <span
                  className={cn("shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium tabular-nums", !n && "text-subtle")}
                  style={n ? { color: emu, backgroundColor: `color-mix(in oklab, ${emu} 14%, transparent)` } : undefined}
                  title={synced ? `${n} emulation options` : "Not synced"}
                >
                  {synced ? n : "–"}
                </span>
              </li>
            );
          })}
        </ol>
        )}
      </section>

      {!synced ? (
        <div className="flex items-start gap-3 rounded-xl border border-dashed border-border bg-bg-card px-5 py-4">
          <FlaskConical className="mt-0.5 size-4 shrink-0 text-muted" />
          <div className="text-sm">
            <p className="font-medium text-fg">Emulation library not synced yet</p>
            <p className="mt-1 text-muted">
              Atomic Red Team tests, CTID emulation plans and attack flows appear here once those structured sources are synced.{" "}
              <Link to="/sources" className="text-[var(--color-primary)] hover:underline">
                Open sources
              </Link>
            </p>
          </div>
        </div>
      ) : null}

      {/* Per-technique options (only once an emulation library is synced) */}
      {synced && (
      <section>
        <div className="mb-4">
          <h2 className="text-xl font-semibold tracking-tight text-fg">Options per technique</h2>
          <p className="mt-1.5 max-w-3xl text-sm text-muted">
            Ways to reproduce each technique in a lab. Observed and inferred labels come from the evidence analysis; mapped means the
            technique was listed by the analysis without a labelled passage.
          </p>
        </div>
        {isLoading && (
          <div className="mb-3 flex items-center gap-2 text-sm text-muted">
            <ActivitySpinner size="sm" /> Matching emulation options…
          </div>
        )}
        <ul className={cn(synced ? "space-y-3" : "divide-y divide-border overflow-hidden rounded-xl border border-border bg-bg-card")}>
          {steps.map((t, i) => {
            const opts = options?.[t.id] ?? [];
            return (
              <li key={t.id} className={cn(synced && "overflow-hidden rounded-xl border border-border bg-bg-card")}>
                <div className="flex flex-wrap items-center gap-2.5 px-4 py-3">
                  <span className="text-xs tabular-nums text-subtle">{i + 1}</span>
                  <EntityChip kind="technique">{t.id}</EntityChip>
                  <span className="order-last w-full min-w-0 text-sm font-medium text-fg sm:order-none sm:w-auto sm:flex-1">
                    {t.name ?? "Unknown technique"}
                    {t.tactic && <span className="font-normal text-muted"> · {t.tactic}</span>}
                  </span>
                  <span className="ml-auto sm:ml-0">
                    <StatusChip tone={LABEL_TONE[t.label]} dot>
                      {LABEL_TEXT[t.label]}
                    </StatusChip>
                  </span>
                </div>
                {synced ? (
                  opts.length > 0 ? (
                    <ul className="divide-y divide-border border-t border-border">
                      {opts.map((o, k) => (
                        <OptionRow key={`${o.kind}:${o.ref}:${k}`} o={o} />
                      ))}
                    </ul>
                  ) : (
                    <p className="border-t border-border px-4 py-2.5 text-xs text-subtle">
                      No Atomic test, CTID procedure or attack flow synced for this technique; it needs a custom procedure.
                    </p>
                  )
                ) : null}
              </li>
            );
          })}
        </ul>
      </section>
      )}
    </div>
  );
}
