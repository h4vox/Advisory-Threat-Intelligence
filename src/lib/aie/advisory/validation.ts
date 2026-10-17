/**
 * Detection / response validation for advisory simulation runs: outcome metrics, a tactic matrix,
 * run-to-run comparison and findings with recommended detections and ATT&CK mitigations.
 * Pure; safe to import from components.
 */
import type {
  AdvisoryContent,
  AdvisoryFinding,
  FindingSeverity,
  RunComparison,
  RunMetrics,
  SimulationRun,
  StepOutcome,
} from "./types.ts";

const OUTCOMES: StepOutcome[] = ["prevented", "detected", "logged", "missed", "not_run", "not_applicable"];

/** Higher is better; not-run / not-applicable have no rank. */
export const OUTCOME_RANK: Partial<Record<StepOutcome, number>> = { prevented: 3, detected: 2, logged: 1, missed: 0 };

function emptyCounts(): Record<StepOutcome, number> {
  return { prevented: 0, detected: 0, logged: 0, missed: 0, not_run: 0, not_applicable: 0 };
}

export function outcomeOf(run: SimulationRun, techniqueId: string): StepOutcome {
  return run.results[techniqueId]?.outcome ?? "not_run";
}

/** Metrics over the run's scope, grouped by tactic in path order. */
export function computeRunMetrics(run: SimulationRun, content: Pick<AdvisoryContent, "path">): RunMetrics {
  const counts = emptyCounts();
  const tacticOf = new Map(content.path.steps.map((s) => [s.technique.id, s.phase]));
  const byTactic = new Map<string, Record<StepOutcome, number> & { total: number }>();
  for (const id of run.scope) {
    const o = outcomeOf(run, id);
    counts[o] += 1;
    const tactic = tacticOf.get(id) ?? "Other";
    const row = byTactic.get(tactic) ?? { ...emptyCounts(), total: 0 };
    row[o] += 1;
    row.total += 1;
    byTactic.set(tactic, row);
  }
  const executed = counts.prevented + counts.detected + counts.logged + counts.missed;
  const rate = (n: number) => (executed ? n / executed : null);
  const order = content.path.phases.map((p) => p.tactic);
  return {
    total: run.scope.length,
    executed,
    prevented: counts.prevented,
    detected: counts.detected,
    logged: counts.logged,
    missed: counts.missed,
    notRun: counts.not_run,
    notApplicable: counts.not_applicable,
    preventionRate: rate(counts.prevented),
    detectionRate: rate(counts.prevented + counts.detected),
    visibilityRate: rate(counts.prevented + counts.detected + counts.logged),
    byTactic: [...byTactic.entries()]
      .sort((a, b) => (order.indexOf(a[0]) === -1 ? 99 : order.indexOf(a[0])) - (order.indexOf(b[0]) === -1 ? 99 : order.indexOf(b[0])))
      .map(([tactic, row]) => ({ tactic, ...row })),
  };
}

/** Steps whose outcome changed between two runs (only steps executed in both). */
export function compareRuns(previous: SimulationRun, current: SimulationRun): RunComparison {
  const improved: RunComparison["improved"] = [];
  const regressed: RunComparison["regressed"] = [];
  for (const id of current.scope) {
    const from = outcomeOf(previous, id);
    const to = outcomeOf(current, id);
    const a = OUTCOME_RANK[from];
    const b = OUTCOME_RANK[to];
    if (a === undefined || b === undefined || a === b) continue;
    (b > a ? improved : regressed).push({ techniqueId: id, from, to });
  }
  return { previousRun: previous.number, improved, regressed };
}

const SEVERITY_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low"];

/**
 * A finding for every executed step that was not prevented or detected. Severity weighs the
 * outcome (missed > logged), the step's priority (library frequency, recency, attribution) and its
 * risk class, and the reason says so.
 */
export function deriveFindings(content: AdvisoryContent, run: SimulationRun, previous?: SimulationRun | null): AdvisoryFinding[] {
  const steps = new Map(content.path.steps.map((s) => [s.technique.id, s]));
  const behaviours = new Map(content.behaviours.map((b) => [b.techniqueId, b]));
  const detections = new Map(content.detections.map((d) => [d.techniqueId, d]));
  const out: AdvisoryFinding[] = [];
  for (const id of run.scope) {
    const outcome = outcomeOf(run, id);
    if (outcome !== "missed" && outcome !== "logged") continue;
    const step = steps.get(id);
    if (!step) continue;
    const b = behaviours.get(id);
    const d = detections.get(id);
    const points = (outcome === "missed" ? 2 : 1) + (step.priority === "high" ? 2 : step.priority === "medium" ? 1 : 0) + (step.simulation.risk.level === "high" ? 1 : 0);
    const severity: FindingSeverity = points >= 5 ? "critical" : points === 4 ? "high" : points === 3 ? "medium" : "low";
    const name = step.technique.name;
    const evidence = b && b.observedIn + b.inferredIn > 0 ? `seen in ${b.observedIn + b.inferredIn} library report${b.observedIn + b.inferredIn === 1 ? "" : "s"}` : b?.attributedByAttack || step.stats.attributed ? "attributed by ATT&CK" : "in scope";
    let trend: AdvisoryFinding["trend"];
    if (previous) {
      const before = outcomeOf(previous, id);
      const a = OUTCOME_RANK[before];
      const now = OUTCOME_RANK[outcome]!;
      trend = a === undefined ? "new" : now < a ? "regressed" : now === a ? "unchanged" : "new";
    }
    out.push({
      id: "",
      techniqueId: id,
      name,
      tactic: step.phase,
      outcome,
      severity,
      severityReason: `${outcome === "missed" ? "Not detected" : "Logged without an alert"} · ${step.priority} priority step · ${step.simulation.risk.level} risk`,
      title: outcome === "missed" ? `${name} was not detected` : `${name} was logged but raised no alert`,
      context: `${step.technique.id} (${step.phase}) is ${evidence}. ${step.reasonText}`,
      detection: {
        telemetry: d?.telemetry ?? step.simulation.requiredTelemetry,
        hypothesis: d?.hypothesis ?? step.hunts[0]?.hypothesis ?? "",
        queryTemplate: d?.queryTemplate ?? step.hunts[0]?.query.text ?? "",
      },
      mitigations: b?.mitigations ?? [],
      ...(run.results[id]?.notes ? { notes: run.results[id].notes } : {}),
      ...(trend ? { trend } : {}),
    });
  }
  out.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || content.path.steps.findIndex((s) => s.technique.id === a.techniqueId) - content.path.steps.findIndex((s) => s.technique.id === b.techniqueId));
  return out.map((f, i) => ({ ...f, id: `F-${String(i + 1).padStart(2, "0")}` }));
}

/** Latest completed run, else the latest run. */
export function latestRun(runs: SimulationRun[]): SimulationRun | undefined {
  const sorted = [...runs].sort((a, b) => b.number - a.number);
  return sorted.find((r) => r.status === "completed") ?? sorted[0];
}

export function previousCompleted(runs: SimulationRun[], run: SimulationRun): SimulationRun | undefined {
  return [...runs].filter((r) => r.status === "completed" && r.number < run.number).sort((a, b) => b.number - a.number)[0];
}

export function pct(v: number | null | undefined): string {
  return v === null || v === undefined ? "—" : `${Math.round(v * 100)}%`;
}

export { OUTCOMES };
