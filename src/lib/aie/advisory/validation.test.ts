import { test } from "node:test";
import assert from "node:assert/strict";
import {
  compareRuns,
  computeRunMetrics,
  deriveFindings,
  latestRun,
  outcomeOf,
  pct,
  previousCompleted,
} from "./validation.ts";
import type { AdvisoryContent, SimulationRun, StepOutcome, StepResult } from "./types.ts";
import type { PurpleStep } from "../purple/types.ts";

// Minimal PurpleStep — the validation functions read only these fields, so an isolated cast keeps
// the fixture from coupling to unrelated step structure.
function step(opts: {
  id: string;
  name?: string;
  phase: string;
  priority?: "high" | "medium" | "low";
  risk?: "high" | "medium" | "low";
  telemetry?: string[];
  hypothesis?: string;
  query?: string;
  attributed?: boolean;
}): PurpleStep {
  return {
    technique: { id: opts.id, name: opts.name ?? opts.id },
    phase: opts.phase,
    priority: opts.priority ?? "medium",
    reasonText: "seen recently",
    stats: { attributed: opts.attributed ?? false },
    simulation: { risk: { level: opts.risk ?? "low" }, requiredTelemetry: opts.telemetry ?? ["edr"] },
    hunts: [{ hypothesis: opts.hypothesis ?? "hunt hypothesis", query: { text: opts.query ?? "SELECT 1" } }],
  } as unknown as PurpleStep;
}

function result(techniqueId: string, outcome: StepOutcome, notes?: string): StepResult {
  return { techniqueId, outcome, recordedAt: "2026-02-10T00:00:00.000Z", recordedBy: "analyst", ...(notes ? { notes } : {}) };
}

function run(over: Partial<SimulationRun> = {}): SimulationRun {
  return {
    id: "run-1",
    advisoryId: "adv-1",
    number: 1,
    name: "Run 1",
    status: "completed",
    startedAt: "2026-02-10T00:00:00.000Z",
    startedBy: "analyst",
    scope: [],
    results: {},
    ...over,
  };
}

function contentWithPath(steps: PurpleStep[]): AdvisoryContent {
  const phases = [...new Set(steps.map((s) => s.phase))].map((tactic) => ({ tactic, steps: 1 }));
  return {
    behaviours: [],
    detections: [],
    path: { steps, phases } as AdvisoryContent["path"],
  } as unknown as AdvisoryContent;
}

test("outcomeOf returns the recorded outcome, else not_run", () => {
  const r = run({ scope: ["T1", "T2"], results: { T1: result("T1", "detected") } });
  assert.equal(outcomeOf(r, "T1"), "detected");
  assert.equal(outcomeOf(r, "T2"), "not_run");
});

test("computeRunMetrics counts outcomes, rates and per-tactic rows in path order", () => {
  const content = contentWithPath([
    step({ id: "T1", phase: "Initial Access" }),
    step({ id: "T2", phase: "Execution" }),
    step({ id: "T3", phase: "Execution" }),
    step({ id: "T4", phase: "Impact" }),
  ]);
  const r = run({
    scope: ["T1", "T2", "T3", "T4", "T5"],
    results: {
      T1: result("T1", "prevented"),
      T2: result("T2", "detected"),
      T3: result("T3", "logged"),
      T4: result("T4", "missed"),
      // T5 has no result → not_run, and no path step → "Other" tactic.
    },
  });
  const m = computeRunMetrics(r, content);
  assert.equal(m.total, 5);
  assert.equal(m.executed, 4);
  assert.equal(m.prevented, 1);
  assert.equal(m.detected, 1);
  assert.equal(m.logged, 1);
  assert.equal(m.missed, 1);
  assert.equal(m.notRun, 1);
  assert.equal(m.preventionRate, 0.25);
  assert.equal(m.detectionRate, 0.5);
  assert.equal(m.visibilityRate, 0.75);
  // Ordered by path phases: Initial Access, Execution, Impact, then "Other".
  assert.deepEqual(m.byTactic.map((t) => t.tactic), ["Initial Access", "Execution", "Impact", "Other"]);
  assert.equal(m.byTactic.find((t) => t.tactic === "Execution")?.total, 2);
});

test("computeRunMetrics rates are null before anything executes", () => {
  const content = contentWithPath([step({ id: "T1", phase: "Execution" })]);
  const r = run({ scope: ["T1"], results: {} });
  const m = computeRunMetrics(r, content);
  assert.equal(m.executed, 0);
  assert.equal(m.preventionRate, null);
  assert.equal(m.detectionRate, null);
  assert.equal(m.visibilityRate, null);
});

test("compareRuns reports improved and regressed steps only", () => {
  const prev = run({ number: 1, scope: ["T1", "T2", "T3"], results: { T1: result("T1", "missed"), T2: result("T2", "detected"), T3: result("T3", "logged") } });
  const curr = run({ number: 2, scope: ["T1", "T2", "T3"], results: { T1: result("T1", "detected"), T2: result("T2", "missed"), T3: result("T3", "logged") } });
  const cmp = compareRuns(prev, curr);
  assert.equal(cmp.previousRun, 1);
  assert.deepEqual(cmp.improved, [{ techniqueId: "T1", from: "missed", to: "detected" }]);
  assert.deepEqual(cmp.regressed, [{ techniqueId: "T2", from: "detected", to: "missed" }]);
  // T3 unchanged → in neither list.
});

test("deriveFindings produces findings for missed/logged steps with severity and trend", () => {
  const content = contentWithPath([
    step({ id: "T1", name: "Phishing", phase: "Initial Access", priority: "high", risk: "high" }),
    step({ id: "T2", name: "Exec", phase: "Execution", priority: "low", risk: "low" }),
    step({ id: "T3", name: "Prevented thing", phase: "Impact" }),
  ]);
  const curr = run({ number: 2, scope: ["T1", "T2", "T3"], results: { T1: result("T1", "missed"), T2: result("T2", "logged"), T3: result("T3", "prevented") } });
  const prev = run({ number: 1, scope: ["T1"], results: { T1: result("T1", "detected") } });
  const findings = deriveFindings(content, curr, prev);
  // T3 prevented → no finding; T1 missed + T2 logged → two findings.
  assert.equal(findings.length, 2);
  // Sorted by severity: T1 (missed, high prio, high risk → points 2+2+1=5 → critical) first.
  assert.equal(findings[0].techniqueId, "T1");
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[0].outcome, "missed");
  assert.equal(findings[0].trend, "regressed"); // was detected, now missed
  assert.equal(findings[1].techniqueId, "T2");
  assert.equal(findings[1].outcome, "logged");
  // Stable finding ids.
  assert.deepEqual(findings.map((f) => f.id), ["F-01", "F-02"]);
});

test("latestRun prefers the latest completed run", () => {
  const runs = [run({ number: 1, status: "completed" }), run({ number: 3, status: "in_progress" }), run({ number: 2, status: "completed" })];
  assert.equal(latestRun(runs)?.number, 2);
  assert.equal(latestRun([])?.number, undefined);
});

test("previousCompleted finds the prior completed run", () => {
  const runs = [run({ number: 1, status: "completed" }), run({ number: 2, status: "in_progress" }), run({ number: 3, status: "completed" })];
  const r3 = runs[2];
  assert.equal(previousCompleted(runs, r3)?.number, 1);
});

test("pct formats a 0..1 ratio or an em dash", () => {
  assert.equal(pct(0.25), "25%");
  assert.equal(pct(1), "100%");
  assert.equal(pct(null), "—");
  assert.equal(pct(undefined), "—");
});
