import { useState } from "react";
import { ChevronDown, FileCode2, FileJson, FileText, FlaskConical, Layers, ListOrdered, Monitor, ShieldAlert, ShieldCheck } from "lucide-react";
import type { PurplePath, PurpleStep } from "@/lib/aie/purple/types";
import { PURPLE_PLATFORMS } from "@/lib/aie/purple/types";
import { ActionButton, StatCard } from "@/components/layout/page";
import { Meter, StatusChip } from "@/components/ui/primitives";
import { cn } from "@/lib/cn";
import { RISK_LABEL, RISK_TONE, exportPath, tacticColor, tint } from "./purple-utils";
import { StepDrawer } from "./step-drawer";

export function PurpleKpis({ path }: { path: PurplePath }) {
  const options = path.steps.reduce((n, s) => n + s.stats.libraryOptions, 0);
  const withOptions = path.steps.filter((s) => s.stats.libraryOptions > 0).length;
  const high = path.steps.filter((s) => s.simulation.risk.level === "high").length;
  const tactics = new Set(path.steps.map((s) => s.phase)).size;
  const platforms = path.options.platforms.length
    ? PURPLE_PLATFORMS.filter((p) => path.options.platforms.includes(p.id)).map((p) => p.label)
    : ["All platforms"];
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
      <StatCard icon={ListOrdered} kind="emulation" label="Steps" value={path.steps.length} hint={`${path.candidateCount} candidate techniques`} />
      <StatCard icon={Layers} kind="technique" label="Tactics" value={tactics} hint={path.orderBasis === "reported" ? "Source-reported order" : "ATT&CK tactic order"} />
      <StatCard
        icon={Monitor}
        kind="source"
        label="Platforms"
        value={path.options.platforms.length || "All"}
        hint={<span className="line-clamp-1">{platforms.join(", ")}</span>}
      />
      <StatCard
        icon={FlaskConical}
        kind="emulation"
        label="Emulation"
        value={path.emulationSynced ? options : "–"}
        hint={path.emulationSynced ? `${withOptions} of ${path.steps.length} steps covered` : "Not synced yet"}
      />
      <div className="col-span-2 lg:col-span-1">
        <StatCard icon={ShieldAlert} kind="actor" label="High risk" value={high} hint={path.options.excludeHighRisk ? "High risk excluded" : "Run on disposable hosts"} />
      </div>
    </div>
  );
}

export function PurpleExportButtons({ path }: { path: PurplePath }) {
  return (
    <>
      <ActionButton icon={FileText} onClick={() => exportPath(path, "md")}>
        Markdown
      </ActionButton>
      <ActionButton icon={FileJson} onClick={() => exportPath(path, "json")}>
        JSON
      </ActionButton>
      <ActionButton icon={FileCode2} onClick={() => exportPath(path, "yaml")} title="CALDERA-style adversary profile (planning artefact)">
        CALDERA YAML
      </ActionButton>
    </>
  );
}

function StepCard({ s, onOpen }: { s: PurpleStep; onOpen: () => void }) {
  const color = tacticColor(s.phase);
  const risk = s.simulation.risk.level;
  return (
    <button
      type="button"
      onClick={onOpen}
      className="group w-full rounded-lg border border-border bg-bg-card p-3 text-left transition-colors hover:border-[color-mix(in_oklab,var(--color-fg)_22%,var(--color-border))] hover:bg-bg-subtle focus-visible:outline-2 focus-visible:outline-[var(--color-primary)]"
      aria-label={`Step ${s.order}: ${s.technique.id} ${s.technique.name}. Open details`}
    >
      <div className="flex items-start gap-2.5">
        <span className="flex size-6 shrink-0 items-center justify-center rounded-md font-mono text-[11px] font-semibold tabular-nums" style={tint(color, 16)}>
          {s.order}
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-mono text-[11px]" style={{ color: "var(--color-cat-technique)" }}>
            {s.technique.id}
          </p>
          <p className="line-clamp-2 text-sm font-medium leading-snug text-fg">{s.technique.name}</p>
        </div>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <Meter value={s.score} color={color} label={`Priority ${s.score.toFixed(2)}`} className="flex-1" />
        <span className="font-mono text-[11px] tabular-nums text-muted">{s.score.toFixed(2)}</span>
      </div>
      <div className="mt-2.5 flex flex-wrap items-center justify-between gap-1.5">
        <StatusChip tone={RISK_TONE[risk]} dot>
          {RISK_LABEL[risk]}
        </StatusChip>
        <span className="text-[11px] text-subtle">
          {s.stats.reports ? `${s.stats.reports} report${s.stats.reports === 1 ? "" : "s"}` : s.stats.attributed ? "ATT&CK" : "Analyst"}
          {s.stats.libraryOptions ? ` · ${s.stats.libraryOptions} options` : ""}
        </span>
      </div>
    </button>
  );
}

/** Kill-chain view: tactic phases as columns that wrap, numbered step cards, step drawer. */
export function PurplePathView({ path, compact }: { path: PurplePath; compact?: boolean }) {
  const [open, setOpen] = useState<PurpleStep | null>(null);
  const [showExcluded, setShowExcluded] = useState(false);
  let cursor = 0;
  const groups = path.phases.map((ph) => {
    const steps = path.steps.slice(cursor, cursor + ph.steps);
    cursor += ph.steps;
    return { ...ph, list: steps };
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
        <span className="inline-flex items-center gap-1.5">
          <ListOrdered className="size-3.5" />
          {path.orderNote}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <ShieldCheck className="size-3.5" />
          Detection coverage: unknown; connect a detection repository
        </span>
      </div>
      <ol className={cn("grid gap-3", compact ? "sm:grid-cols-2 xl:grid-cols-3" : "sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4")}>
        {groups.map((g, i) => {
          const color = tacticColor(g.tactic);
          return (
            <li key={`${g.tactic}-${i}`} className="flex min-w-0 flex-col rounded-xl border border-border bg-[color-mix(in_oklab,var(--color-bg-subtle)_55%,transparent)]">
              <div className="flex items-center gap-2 border-b border-border px-3 py-2.5">
                <span className="h-4 w-1 shrink-0 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-[11px] tabular-nums text-subtle">Phase {i + 1}</span>
                <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg">{g.tactic}</span>
                <span className="rounded px-1.5 py-px font-mono text-[10px] tabular-nums" style={tint(color, 14)}>
                  {g.steps}
                </span>
              </div>
              <div className="flex flex-col gap-2 p-2">
                {g.list.map((s) => (
                  <StepCard key={s.technique.id} s={s} onOpen={() => setOpen(s)} />
                ))}
              </div>
            </li>
          );
        })}
      </ol>

      {path.excluded.length > 0 && (
        <div className="rounded-xl border border-border bg-bg-card">
          <button
            type="button"
            onClick={() => setShowExcluded((v) => !v)}
            aria-expanded={showExcluded}
            className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left text-sm"
          >
            <span className="text-fg">
              {path.excluded.length} technique{path.excluded.length === 1 ? "" : "s"} left out
              <span className="text-muted"> · platform, risk or step limit</span>
            </span>
            <ChevronDown className={cn("size-4 text-muted transition-transform", showExcluded && "rotate-180")} />
          </button>
          {showExcluded && (
            <ul className="max-h-72 divide-y divide-border overflow-y-auto border-t border-border">
              {path.excluded.map((x) => (
                <li key={x.id} className="flex flex-col gap-0.5 px-4 py-2 text-sm sm:flex-row sm:items-baseline sm:gap-3">
                  <span className="shrink-0 font-mono text-xs" style={{ color: "var(--color-cat-technique)" }}>
                    {x.id}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-fg">{x.name}</span>
                  <span className="text-xs text-muted sm:max-w-[50%] sm:text-right">{x.reason}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      <StepDrawer step={open} sourceName={path.source.name} onClose={() => setOpen(null)} />
    </div>
  );
}
