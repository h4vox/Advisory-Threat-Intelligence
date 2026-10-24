import { useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileJson,
  FlaskConical,
  Pencil,
  RefreshCw,
  Save,
  Target,
  Trash2,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionCard } from "@/components/layout/page";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { EmptyState, StatusChip, type Tone } from "@/components/ui/primitives";
import { cn } from "@/lib/cn";
import {
  completeSimulationRun,
  deleteAdvisory,
  exportAdvisory,
  getAdvisory,
  recordStepResult,
  regenerateAdvisory,
  startSimulationRun,
  updateAdvisory,
} from "@/lib/aie/server-advisories";
import { effectiveSeverity, effectiveSummary, effectiveTitle } from "@/lib/aie/advisory/export";
import {
  STEP_OUTCOMES,
  type AdvisoryRecord,
  type AdvisorySeverity,
  type AdvisoryStatus,
  type SimulationRun,
  type StepOutcome,
  type Tlp,
} from "@/lib/aie/advisory/types";

export const Route = createFileRoute("/advisories_/$advisoryId")({ component: AdvisoryDetailPage });

const SEVERITY_TONE: Record<AdvisorySeverity, Tone> = { critical: "danger", high: "warning", medium: "info", low: "neutral" };
const STATUS_TONE: Record<AdvisoryStatus, Tone> = { published: "success", review: "info", simulating: "warning", draft: "neutral", closed: "neutral" };
const STATUSES: AdvisoryStatus[] = ["draft", "review", "published", "simulating", "closed"];
const TLPS: Tlp[] = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"];
const SEVERITIES: AdvisorySeverity[] = ["critical", "high", "medium", "low"];

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t).toLocaleDateString() : "—";
}

function AdvisoryDetailPage() {
  const { advisoryId } = Route.useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);

  const { data, isLoading } = useQuery({ queryKey: ["advisory", advisoryId], queryFn: () => getAdvisory({ data: { id: advisoryId } }) });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["advisory", advisoryId] });
    void qc.invalidateQueries({ queryKey: ["advisories"] });
  };

  const updateMutation = useMutation({
    mutationFn: (patch: Parameters<typeof updateAdvisory>[0]["data"]) => updateAdvisory({ data: patch }),
    onSuccess: () => { invalidate(); },
    onError: (err: Error) => toast.error(err.message),
  });
  const regenMutation = useMutation({
    mutationFn: () => regenerateAdvisory({ data: { id: advisoryId } }),
    onSuccess: () => { invalidate(); toast.success("Advisory regenerated from the current library"); },
    onError: (err: Error) => toast.error(err.message),
  });
  const deleteMutation = useMutation({
    mutationFn: () => deleteAdvisory({ data: { id: advisoryId } }),
    onSuccess: () => { toast.success("Advisory deleted"); void qc.invalidateQueries({ queryKey: ["advisories"] }); navigate({ to: "/advisories" }); },
    onError: (err: Error) => toast.error(err.message),
  });

  async function exportDoc(format: "markdown" | "json") {
    try {
      const res = await exportAdvisory({ data: { id: advisoryId, format } });
      const blob = new Blob([res.body], { type: res.contentType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = res.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.error((err as Error).message || "Export failed");
    }
  }

  if (isLoading) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center py-24 text-muted">
          <ActivitySpinner size="lg" className="mb-2 text-accent" />
          <p className="text-sm">Loading advisory…</p>
        </div>
      </AppShell>
    );
  }

  if (!data) {
    return (
      <AppShell>
        <div className="mx-auto max-w-5xl px-4 py-10 md:px-8">
          <EmptyState icon={AlertCircle} title="Advisory not found" description="It may have been deleted." action={<Button size="sm" variant="secondary" onClick={() => navigate({ to: "/advisories" })}>Back to advisories</Button>} />
        </div>
      </AppShell>
    );
  }

  const { record, runs } = data;
  const c = record.content;
  const title = effectiveTitle(record);
  const severity = effectiveSeverity(record);
  const summary = effectiveSummary(record);
  const scope = new Set(record.scope);

  const toggleScope = (techniqueId: string) => {
    const next = new Set(scope);
    if (next.has(techniqueId)) next.delete(techniqueId);
    else next.add(techniqueId);
    updateMutation.mutate({ id: advisoryId, scope: [...next] });
  };

  return (
    <AppShell>
      <div className="mx-auto max-w-5xl px-4 py-6 md:px-8">
        <PageHeader
          backTo="/advisories"
          eyebrow={record.number}
          title={title}
          description={`${c.subject.kind} · ${c.subject.name}`}
          actions={
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="secondary" onClick={() => exportDoc("markdown")} className="gap-1.5 text-xs"><Download className="size-3.5" />Markdown</Button>
              <Button size="sm" variant="secondary" onClick={() => exportDoc("json")} className="gap-1.5 text-xs"><FileJson className="size-3.5" />JSON</Button>
              <Button size="sm" variant="secondary" disabled={regenMutation.isPending} onClick={() => regenMutation.mutate()} className="gap-1.5 text-xs">
                {regenMutation.isPending ? <ActivitySpinner size="xs" className="text-accent" /> : <RefreshCw className="size-3.5" />}Regenerate
              </Button>
              <Button size="sm" variant="danger" disabled={deleteMutation.isPending} onClick={() => { if (confirm(`Delete advisory ${record.number}? This cannot be undone.`)) deleteMutation.mutate(); }} className="gap-1.5 text-xs"><Trash2 className="size-3.5" />Delete</Button>
            </div>
          }
        />

        {/* Status / severity / TLP controls */}
        <div className="mb-6 flex flex-wrap items-center gap-3 rounded-xl border border-border bg-bg-card p-4 text-xs">
          <StatusChip tone={SEVERITY_TONE[severity]}>{severity}</StatusChip>
          <label className="flex items-center gap-1.5 text-subtle">
            Status
            <Select size="sm" value={record.status} onValueChange={(v) => updateMutation.mutate({ id: advisoryId, status: v as AdvisoryStatus })} className="text-xs">
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </Select>
          </label>
          <label className="flex items-center gap-1.5 text-subtle">
            TLP
            <Select size="sm" value={record.tlp} onValueChange={(v) => updateMutation.mutate({ id: advisoryId, tlp: v as Tlp })} className="text-xs">
              {TLPS.map((t) => <option key={t} value={t}>TLP:{t}</option>)}
            </Select>
          </label>
          <span className="ml-auto text-subtle">Updated {fmtDate(record.updatedAt)}{record.updatedBy ? ` by ${record.updatedBy}` : ""}</span>
        </div>

        {/* Summary + analyst edits */}
        <SectionCard title="Summary" actions={<button type="button" onClick={() => setEditing((v) => !v)} className="flex items-center gap-1 text-xs text-accent hover:underline"><Pencil className="size-3" />{editing ? "Close editor" : "Analyst edits"}</button>}>
          <p className="text-sm leading-relaxed text-muted">{summary || "No summary available."}</p>
          {c.severityReasons.length > 0 && !record.overrides.severityNote && (
            <p className="mt-2 text-xs text-subtle"><span className="font-medium text-muted">Severity basis:</span> {c.severityReasons.join("; ")}</p>
          )}
          {record.overrides.severityNote && <p className="mt-2 text-xs text-subtle"><span className="font-medium text-muted">Severity note:</span> {record.overrides.severityNote}</p>}
          {editing && <OverridesEditor record={record} onSave={(ov) => updateMutation.mutate({ id: advisoryId, overrides: ov })} saving={updateMutation.isPending} />}
          {record.overrides.notes && !editing && (
            <div className="mt-3 rounded-lg border border-border bg-bg-subtle p-3 text-xs">
              <div className="mb-1 font-medium text-muted">Analyst notes</div>
              <p className="whitespace-pre-wrap text-subtle">{record.overrides.notes}</p>
            </div>
          )}
        </SectionCard>

        {c.keyPoints.length > 0 && (
          <SectionCard title="Key points" className="mt-5">
            <ul className="space-y-1.5 text-sm text-muted">
              {c.keyPoints.map((p, i) => <li key={i} className="flex gap-2"><span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-accent" />{p}</li>)}
            </ul>
          </SectionCard>
        )}

        {/* Behaviours with scope toggles */}
        {c.behaviours.length > 0 && (
          <SectionCard title={`Observed behaviours (${c.behaviours.length})`} className="mt-5" actions={<span className="text-xs text-subtle">Tick a technique to include it in simulation scope</span>}>
            <div className="divide-y divide-border">
              {c.behaviours.map((b) => (
                <label key={b.techniqueId} className="flex cursor-pointer items-start gap-3 py-2.5">
                  <input type="checkbox" checked={scope.has(b.techniqueId)} onChange={() => toggleScope(b.techniqueId)} className="mt-0.5 size-4 accent-accent" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-mono text-xs text-accent">{b.techniqueId}</span>
                      <span className="truncate font-medium text-fg">{b.name}</span>
                    </div>
                    <div className="mt-0.5 text-xs text-subtle">
                      {b.tactic}
                      {b.observedIn > 0 && ` · ${b.observedIn} observed`}
                      {b.inferredIn > 0 && ` · ${b.inferredIn} inferred`}
                      {b.attributedByAttack && " · ATT&CK-attributed"}
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </SectionCard>
        )}

        {/* Vulnerabilities */}
        {c.vulnerabilities.length > 0 && (
          <SectionCard title={`Vulnerabilities (${c.vulnerabilities.length})`} className="mt-5">
            <ul className="space-y-2 text-sm">
              {c.vulnerabilities.map((v) => (
                <li key={v.cveId} className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-fg">{v.cveId}</span>
                  {v.kev && <StatusChip tone="danger">CISA KEV</StatusChip>}
                  {v.kev && <span className="text-xs text-subtle">{v.kev.vendor} {v.kev.product}{v.kev.dueDate ? ` · due ${fmtDate(v.kev.dueDate)}` : ""}</span>}
                </li>
              ))}
            </ul>
          </SectionCard>
        )}

        {/* Indicators */}
        {c.indicators.length > 0 && (
          <SectionCard title={`Indicators of compromise (${c.indicatorTotal})`} className="mt-5">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-subtle">
                  <tr><th className="pb-2 pr-3 font-medium">Type</th><th className="pb-2 pr-3 font-medium">Indicator</th><th className="pb-2 font-medium">Role</th></tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {c.indicators.slice(0, 50).map((ind, i) => (
                    <tr key={i}><td className="py-1.5 pr-3 text-subtle">{ind.kind}</td><td className="py-1.5 pr-3 font-mono text-fg">{ind.display}</td><td className="py-1.5 text-subtle">{ind.role || "—"}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SectionCard>
        )}

        {/* Recommendations */}
        {c.recommendations.length > 0 && (
          <SectionCard title="Recommendations" className="mt-5">
            <ul className="space-y-1.5 text-sm text-muted">
              {c.recommendations.map((r, i) => (
                <li key={i} className="flex gap-2">
                  <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-sage" />
                  {r.kind === "patch" ? <span><span className="font-medium text-fg">Patch {r.cveId}</span> — {r.action}</span>
                    : r.kind === "attack_mitigation" ? <span><span className="font-medium text-fg">{r.id} {r.name}</span> — {r.description}</span>
                    : <span>{r.text}</span>}
                </li>
              ))}
            </ul>
          </SectionCard>
        )}

        {/* Gaps */}
        {c.gaps.length > 0 && (
          <SectionCard title="Intelligence gaps" className="mt-5">
            <ul className="space-y-1.5 text-sm text-muted">
              {c.gaps.map((g) => <li key={g.key} className="flex items-start gap-2"><StatusChip tone={g.impact === "high" ? "danger" : g.impact === "medium" ? "warning" : "neutral"}>{g.impact}</StatusChip><span>{g.text}</span></li>)}
            </ul>
          </SectionCard>
        )}

        {/* Simulation */}
        <SimulationPanel advisoryId={advisoryId} runs={runs} onChange={invalidate} />

        {/* Sources */}
        {c.sources.length > 0 && (
          <SectionCard title={`Sources (${c.sources.length})`} className="mt-5">
            <ol className="space-y-1.5 text-xs text-muted">
              {c.sources.map((s, i) => (
                <li key={s.reportId} className="flex gap-2"><span className="text-subtle">{i + 1}.</span><span>{s.title} — {s.publisher}{s.publishedAt ? `, ${fmtDate(s.publishedAt)}` : ""}{s.url ? <> · <a href={s.url} target="_blank" rel="noreferrer" className="text-accent hover:underline">source</a></> : ""}</span></li>
              ))}
            </ol>
          </SectionCard>
        )}
      </div>
    </AppShell>
  );
}

function OverridesEditor({ record, onSave, saving }: { record: AdvisoryRecord; onSave: (ov: { title?: string; severity?: AdvisorySeverity; severityNote?: string; summary?: string; notes?: string }) => void; saving: boolean }) {
  const [title, setTitle] = useState(record.overrides.title ?? "");
  const [severity, setSeverity] = useState<AdvisorySeverity | "">(record.overrides.severity ?? "");
  const [severityNote, setSeverityNote] = useState(record.overrides.severityNote ?? "");
  const [summary, setSummary] = useState(record.overrides.summary ?? "");
  const [notes, setNotes] = useState(record.overrides.notes ?? "");
  return (
    <div className="mt-4 space-y-3 rounded-lg border border-border bg-bg-subtle p-3.5">
      <div className="text-xs font-medium text-muted">Analyst edits — these override the generated content and survive regeneration.</div>
      <div>
        <label className="mb-1 block text-[11px] text-subtle">Title override</label>
        <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder={record.content.title} className="bg-bg-card text-sm" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label htmlFor="advisory-severity-override" className="mb-1 block text-[11px] text-subtle">Severity override</label>
          <Select id="advisory-severity-override" value={severity} onValueChange={(v) => setSeverity(v as AdvisorySeverity | "")} className="w-full bg-bg-card px-2">
            <option value="">(generated: {record.content.severity})</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
        </div>
        <div>
          <label className="mb-1 block text-[11px] text-subtle">Severity note</label>
          <Input value={severityNote} onChange={(e) => setSeverityNote(e.target.value)} className="bg-bg-card text-sm" />
        </div>
      </div>
      <div>
        <label className="mb-1 block text-[11px] text-subtle">Summary override</label>
        <Textarea value={summary} onChange={(e) => setSummary(e.target.value)} rows={3} placeholder={record.content.summary} className="bg-bg-card text-sm" />
      </div>
      <div>
        <label className="mb-1 block text-[11px] text-subtle">Analyst notes</label>
        <Textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} className="bg-bg-card text-sm" />
      </div>
      <div className="flex justify-end">
        <Button size="sm" variant="primary" disabled={saving} onClick={() => onSave({ title: title.trim(), severity: severity || undefined, severityNote: severityNote.trim(), summary: summary.trim(), notes: notes.trim() })} className="gap-1.5 text-xs">
          {saving ? <ActivitySpinner size="xs" className="text-white" /> : <Save className="size-3.5" />}Save edits
        </Button>
      </div>
    </div>
  );
}

function SimulationPanel({ advisoryId, runs, onChange }: { advisoryId: string; runs: SimulationRun[]; onChange: () => void }) {
  const active = runs.find((r) => r.status === "in_progress");
  const startMutation = useMutation({
    mutationFn: () => startSimulationRun({ data: { advisoryId } }),
    onSuccess: () => { onChange(); toast.success("Simulation run started"); },
    onError: (err: Error) => toast.error(err.message),
  });
  return (
    <SectionCard
      title="Detection simulation"
      icon={FlaskConical}
      className="mt-5"
      actions={!active ? <Button size="sm" variant="primary" disabled={startMutation.isPending} onClick={() => startMutation.mutate()} className="gap-1.5 text-xs">{startMutation.isPending ? <ActivitySpinner size="xs" className="text-white" /> : <Target className="size-3.5" />}Start run</Button> : undefined}
    >
      {active ? (
        <ActiveRun run={active} onChange={onChange} />
      ) : runs.length === 0 ? (
        <p className="text-sm text-muted">No simulation runs yet. Start a run to record how your controls handle each technique in scope, then review the findings.</p>
      ) : null}

      {runs.filter((r) => r.status === "completed").length > 0 && (
        <div className={cn("space-y-2", active || runs.length === 0 ? "mt-4 border-t border-border pt-4" : "")}>
          <div className="text-xs font-medium text-muted">Completed runs</div>
          {runs.filter((r) => r.status === "completed").sort((a, b) => b.number - a.number).map((r) => <CompletedRun key={r.id} run={r} />)}
        </div>
      )}
    </SectionCard>
  );
}

function ActiveRun({ run, onChange }: { run: SimulationRun; onChange: () => void }) {
  const recordMutation = useMutation({
    mutationFn: (vars: { techniqueId: string; outcome: StepOutcome }) => recordStepResult({ data: { runId: run.id, ...vars } }),
    onSuccess: () => onChange(),
    onError: (err: Error) => toast.error(err.message),
  });
  const completeMutation = useMutation({
    mutationFn: () => completeSimulationRun({ data: { runId: run.id } }),
    onSuccess: () => { onChange(); toast.success("Run completed — findings generated"); },
    onError: (err: Error) => toast.error(err.message),
  });
  const done = run.scope.filter((id) => run.results[id]).length;
  return (
    <div>
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm">
          <StatusChip tone="warning">Run {run.number} · in progress</StatusChip>
          <span className="text-xs text-subtle">{done}/{run.scope.length} recorded</span>
        </div>
        <Button size="sm" variant="primary" disabled={completeMutation.isPending} onClick={() => completeMutation.mutate()} className="gap-1.5 text-xs">
          {completeMutation.isPending ? <ActivitySpinner size="xs" className="text-white" /> : <CheckCircle2 className="size-3.5" />}Complete run
        </Button>
      </div>
      <div className="space-y-1.5">
        {run.scope.map((id) => {
          const current = run.results[id]?.outcome ?? "not_run";
          return (
            <div key={id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-bg-subtle px-3 py-2">
              <span className="font-mono text-xs text-fg">{id}</span>
              <div className="flex flex-wrap gap-1">
                {STEP_OUTCOMES.filter((o) => o.value !== "not_run").map((o) => (
                  <button
                    key={o.value}
                    type="button"
                    title={o.hint}
                    disabled={recordMutation.isPending && recordMutation.variables?.techniqueId === id}
                    onClick={() => recordMutation.mutate({ techniqueId: id, outcome: o.value })}
                    className={cn(
                      "rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors disabled:opacity-50",
                      current === o.value ? "border-primary/50 bg-primary/15 text-primary" : "border-border bg-bg-card text-muted hover:text-fg",
                    )}
                  >
                    {o.label}
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CompletedRun({ run }: { run: SimulationRun }) {
  const results = Object.values(run.results);
  const counts = {
    prevented: results.filter((r) => r.outcome === "prevented").length,
    detected: results.filter((r) => r.outcome === "detected").length,
    logged: results.filter((r) => r.outcome === "logged").length,
    missed: results.filter((r) => r.outcome === "missed").length,
  };
  const executed = counts.prevented + counts.detected + counts.logged + counts.missed;
  const detectionRate = executed ? Math.round(((counts.prevented + counts.detected) / executed) * 100) : null;
  return (
    <div className="rounded-lg border border-border bg-bg-subtle p-3 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium text-fg">Run {run.number} · {run.name}</span>
        <span className="text-subtle">{detectionRate === null ? "—" : `${detectionRate}% detected`}</span>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        <StatusChip tone="success">{counts.prevented} prevented</StatusChip>
        <StatusChip tone="info">{counts.detected} detected</StatusChip>
        <StatusChip tone="warning">{counts.logged} logged</StatusChip>
        <StatusChip tone="danger">{counts.missed} missed</StatusChip>
      </div>
    </div>
  );
}
