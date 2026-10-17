import * as Dialog from "@radix-ui/react-dialog";
import { Link } from "@tanstack/react-router";
import { ClipboardCopy, ExternalLink, FileText, Radar, ShieldQuestion, X } from "lucide-react";
import { toast } from "sonner";
import type { ReactNode } from "react";
import type { PurpleStep } from "@/lib/aie/purple/types";
import { EntityChip } from "@/components/ui/entity";
import { Meter, StatusChip } from "@/components/ui/primitives";
import { PRIORITY_LABEL, PRIORITY_TONE, RISK_LABEL, RISK_TONE, tacticColor, tint } from "./purple-utils";

function Block({ title, children, icon }: { title: string; children: ReactNode; icon?: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="flex items-center gap-2 text-sm font-medium text-fg">
        {icon}
        {title}
      </h3>
      {children}
    </section>
  );
}

function Bullets({ items, empty }: { items: string[]; empty?: string }) {
  if (!items.length) return <p className="text-sm text-subtle">{empty ?? "None"}</p>;
  return (
    <ul className="space-y-1.5 text-sm text-muted">
      {items.map((x, i) => (
        <li key={i} className="flex gap-2">
          <span className="mt-2 size-1 shrink-0 rounded-full bg-[var(--color-subtle)]" />
          <span className="min-w-0">{x}</span>
        </li>
      ))}
    </ul>
  );
}

export function StepDrawer({ step, sourceName, onClose }: { step: PurpleStep | null; sourceName: string; onClose: () => void }) {
  const s = step;
  const color = s ? tacticColor(s.phase) : "var(--color-primary)";
  const sim = s?.simulation;
  const reportRefs = sim?.sourceRefs.filter((r) => r.kind === "report") ?? [];
  const otherRefs = sim?.sourceRefs.filter((r) => r.kind !== "report") ?? [];
  const techniqueUrl = s ? `https://attack.mitre.org/techniques/${s.technique.id.replace(".", "/")}/` : "";

  return (
    <Dialog.Root open={Boolean(s)} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-[color-mix(in_oklab,var(--color-bg)_55%,transparent)] backdrop-blur-[2px]" />
        <Dialog.Content className="fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col border-l border-border bg-bg-elevated shadow-2xl outline-none">
          {s && sim && (
            <>
              <header className="flex items-start gap-3 border-b border-border px-5 py-4">
                <span className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg font-mono text-xs font-semibold tabular-nums" style={tint(color, 16)}>
                  {s.order}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-xs text-muted">
                    {sim.simulationId} · <span style={{ color }}>{s.phase}</span>
                  </p>
                  <Dialog.Title className="mt-0.5 text-base font-semibold text-fg">{s.technique.name}</Dialog.Title>
                  <Dialog.Description className="mt-1 flex flex-wrap items-center gap-1.5">
                    <EntityChip kind="technique">{s.technique.id}</EntityChip>
                    <StatusChip tone={PRIORITY_TONE[s.priority]}>{PRIORITY_LABEL[s.priority]}</StatusChip>
                    <StatusChip tone={RISK_TONE[sim.risk.level]} dot>
                      {RISK_LABEL[sim.risk.level]}
                    </StatusChip>
                  </Dialog.Description>
                </div>
                <Dialog.Close aria-label="Close step details" className="flex size-8 shrink-0 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg">
                  <X className="size-4" />
                </Dialog.Close>
              </header>

              <div className="flex-1 space-y-6 overflow-y-auto px-5 py-5">
                <Block title="Why this step">
                  <div className="flex items-center gap-3">
                    <Meter value={s.score} color={color} label="Priority score" className="flex-1" />
                    <span className="font-mono text-xs tabular-nums text-fg">{s.score.toFixed(2)}</span>
                  </div>
                  <Bullets items={s.reasons} />
                </Block>

                <Block title="Simulation object">
                  <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-sm sm:grid-cols-[minmax(0,8.5rem)_minmax(0,1fr)] sm:gap-y-2.5">
                    <dt className="text-muted">Scenario</dt>
                    <dd className="text-fg">{sim.scenario}</dd>
                    <dt className="text-muted">Objective</dt>
                    <dd className="text-fg">{sim.objective}</dd>
                    <dt className="text-muted">Target platforms</dt>
                    <dd className="text-fg">{sim.targetPlatforms.join(", ") || "Not specified"}</dd>
                    <dt className="text-muted">Execution method</dt>
                    <dd className="text-fg">{sim.execution.summary}</dd>
                    <dt className="text-muted">Risk</dt>
                    <dd className="text-fg">{sim.risk.reason}</dd>
                  </dl>
                  {sim.execution.options.length > 0 && (
                    <ul className="divide-y divide-border rounded-lg border border-border">
                      {sim.execution.options.map((o, i) => (
                        <li key={`${o.ref}-${i}`} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                          <span className="min-w-0">
                            <span className="block truncate text-fg">{o.name}</span>
                            <span className="block truncate text-xs text-subtle">
                              {o.kind.replace("_", " ")}
                              {o.ref ? ` · ${o.ref}` : ""}
                              {o.platforms.length ? ` · ${o.platforms.join("/")}` : ""}
                            </span>
                          </span>
                          {o.sourceUrl && (
                            <a href={o.sourceUrl} target="_blank" rel="noreferrer" aria-label={`Open ${o.name}`} className="text-muted hover:text-fg">
                              <ExternalLink className="size-3.5" />
                            </a>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </Block>

                <Block title="Prerequisites">
                  <Bullets items={sim.prerequisites} />
                </Block>

                <Block title="Required telemetry">
                  {sim.requiredTelemetry.length ? (
                    <div className="flex flex-wrap gap-1.5">
                      {sim.requiredTelemetry.map((d) => (
                        <EntityChip key={d} kind="ioc" title="ATT&CK data component">
                          {d}
                        </EntityChip>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-subtle">ATT&CK lists no data components for this technique.</p>
                  )}
                  <p className="text-xs text-subtle">ATT&CK data components for {s.technique.id}.</p>
                </Block>

                <Block title="Expected behaviour and detection">
                  <p className="text-sm text-muted">{sim.expectedBehaviour}</p>
                  <p className="text-sm text-muted">{sim.expectedDetection}</p>
                  <p className="flex items-center gap-2 text-sm">
                    <ShieldQuestion className="size-4 text-warn" strokeWidth={1.75} />
                    <span className="text-fg">Detection coverage:</span>
                    <span className="text-muted">{s.detection.note}</span>
                  </p>
                </Block>

                <Block title="Success criteria">
                  <Bullets items={sim.successCriteria} />
                </Block>

                <Block title="Cleanup">
                  <Bullets items={sim.cleanup} />
                </Block>

                <Block title="Hunting hypotheses" icon={<Radar className="size-4" style={{ color: "var(--color-cat-ioc)" }} strokeWidth={1.75} />}>
                  {s.hunts.map((h) => (
                    <div key={h.huntId} className="space-y-2">
                      <p className="text-sm text-fg">
                        <span className="font-mono text-xs text-muted">{h.huntId}</span> {h.hypothesis}
                      </p>
                      <div className="overflow-hidden rounded-lg border border-border">
                        <div className="flex items-center justify-between gap-2 border-b border-border bg-bg-subtle px-3 py-1.5">
                          <span className="text-xs text-muted">Query skeleton · template, adapt before use</span>
                          <button
                            type="button"
                            aria-label="Copy query template"
                            onClick={() => {
                              void navigator.clipboard?.writeText(h.query.text);
                              toast.success("Query template copied");
                            }}
                            className="flex size-6 items-center justify-center rounded text-muted hover:text-fg"
                          >
                            <ClipboardCopy className="size-3.5" />
                          </button>
                        </div>
                        <pre className="overflow-x-auto bg-bg-card px-3 py-2.5 font-mono text-[11.5px] leading-relaxed text-muted">{h.query.text}</pre>
                      </div>
                    </div>
                  ))}
                </Block>

                <Block title="Source evidence" icon={<FileText className="size-4" style={{ color: "var(--color-cat-advisory)" }} strokeWidth={1.75} />}>
                  {reportRefs.length === 0 && otherRefs.length === 0 && <p className="text-sm text-subtle">No source references.</p>}
                  {reportRefs.map((r, i) =>
                    r.kind === "report" ? (
                      <div key={`${r.reportId}-${i}`} className="space-y-1.5">
                        <p className="text-sm">
                          <Link to="/library/$reportId" params={{ reportId: r.reportId }} className="text-accent hover:underline">
                            {r.title}
                          </Link>
                          <span className="text-xs text-subtle">
                            {" "}
                            · {r.label}
                            {r.publishedAt ? ` · ${r.publishedAt.slice(0, 10)}` : ""}
                          </span>
                        </p>
                        {r.quotes.map((q, k) => (
                          <blockquote key={k} className="border-l-2 pl-3 text-sm italic text-muted" style={{ borderColor: color }}>
                            {q}
                          </blockquote>
                        ))}
                        {r.quotes.length === 0 && <p className="text-xs text-subtle">Listed by the analysis without a labelled passage.</p>}
                      </div>
                    ) : null,
                  )}
                  {otherRefs.map((r, i) =>
                    r.kind === "attack" ? (
                      <p key={`a-${i}`} className="text-sm text-muted">
                        <a href={r.url} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                          {r.note}
                        </a>
                      </p>
                    ) : r.kind === "analyst" ? (
                      <p key={`n-${i}`} className="text-sm text-muted">
                        {r.note}
                      </p>
                    ) : null,
                  )}
                  <p className="text-sm">
                    <a href={techniqueUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
                      {s.technique.id} on ATT&CK <ExternalLink className="size-3.5" />
                    </a>
                  </p>
                </Block>
                <p className="text-xs text-subtle">Step from the {sourceName} path. Planning only; AIE never executes procedures.</p>
              </div>
            </>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
