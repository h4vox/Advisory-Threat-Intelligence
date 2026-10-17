import { test } from "node:test";
import assert from "node:assert/strict";
import { TACTIC_ORDER, getTechnique, getGroup } from "../attack-knowledge.ts";
import { generatePurplePath } from "./generate.ts";
import { libraryEvidenceFromReport } from "./evidence.ts";
import { toCalderaYaml, toJson, toMarkdown } from "./export.ts";
import { riskFor } from "./templates.ts";
import { DETECTION_UNKNOWN, type EmulationContext, type LibraryEvidence, type PurpleOptions, type PurpleSeed } from "./types.ts";
import type { IntelAnalysis } from "../types.ts";

const deps = { getTechnique, tacticOrder: TACTIC_ORDER, now: "2026-10-16T00:00:00.000Z" };
const noEmu: EmulationContext = { synced: false, options: {} };
const all: PurpleOptions = { platforms: [], excludeHighRisk: false, maxSteps: 30 };

function report(id: string, publishedAt: string, techniques: Array<[string, "observed" | "inferred" | "mapped", number?]>, sourceConfidence = 0.9): LibraryEvidence {
  return {
    reportId: id,
    title: `Report ${id}`,
    publishedAt,
    sourceConfidence,
    techniques: techniques.map(([tid, label, position]) => ({ id: tid, label, quotes: label === "observed" ? [`${tid} was seen.`] : [], position })),
  };
}

const akira = getGroup("G1024")!;
const actorSeed = (reports: LibraryEvidence[] = []): PurpleSeed => ({
  kind: "actor",
  id: "G1024",
  name: "Akira",
  attributed: akira.techniques,
  attributedBy: { id: "G1024", url: "https://attack.mitre.org/groups/G1024/" },
  reports,
});

test("orders steps by ATT&CK tactic phase", () => {
  const p = generatePurplePath(actorSeed(), all, noEmu, deps);
  assert.equal(p.orderBasis, "tactic");
  const ranks = p.steps.map((s) => TACTIC_ORDER.indexOf(s.phase as (typeof TACTIC_ORDER)[number]));
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
  assert.equal(p.steps[0].simulation.simulationId, "SIM-001");
  assert.ok(p.phases.length >= 5);
});

test("keeps the source-reported order for a single report", () => {
  const seed: PurpleSeed = {
    kind: "report",
    id: "rpt_x",
    name: "Report x",
    attributed: [],
    reports: [report("rpt_x", "2026-06-01", [["T1486", "observed", 0], ["T1059.001", "observed", 1], ["T1003.001", "observed", 2]])],
    reportedOrder: true,
  };
  const p = generatePurplePath(seed, all, noEmu, deps);
  assert.equal(p.orderBasis, "reported");
  assert.deepEqual(p.steps.map((s) => s.technique.id), ["T1486", "T1059.001", "T1003.001"]);
  const tacticOrdered = generatePurplePath({ ...seed, reportedOrder: false }, all, noEmu, deps);
  assert.equal(tacticOrdered.steps[0].technique.id, "T1059.001");
});

test("scores with human-readable reasons from library frequency, recency, attribution and emulation status", () => {
  const p = generatePurplePath(
    actorSeed([report("r1", "2026-05-10", [["T1486", "observed"]]), report("r2", "2026-03-01", [["T1486", "observed"]])]),
    { ...all, platforms: ["windows"] },
    noEmu,
    deps,
  );
  const s = p.steps.find((x) => x.technique.id === "T1486")!;
  assert.match(s.reasonText, /^Observed in 2 library reports \(latest May 2026\)/);
  assert.match(s.reasonText, /attributed by ATT&CK \(G1024\)/);
  assert.match(s.reasonText, /no emulation library synced/);
  assert.match(s.reasonText, /fits Windows/);
  const unseen = p.steps.find((x) => x.stats.reports === 0)!;
  assert.match(unseen.reasonText, /Not seen in library reports yet/);
  assert.ok(s.score > unseen.score, "library-observed techniques rank above attribution-only ones");
  assert.ok(s.score >= 0 && s.score <= 1);
  assert.equal(s.stats.recentReports, 1, "only May 2026 is inside the 180-day window");
});

test("emulation availability raises the score when a library is synced", () => {
  const emu: EmulationContext = {
    synced: true,
    options: { "T1059.001": [{ techniqueId: "T1059.001", kind: "atomic_test", name: "Atomic 1", ref: "a8b5a1ad-0000-4f1b-9f2e-3f1b1d6c7e01", platforms: ["windows"], sourceUrl: "https://example.test/a" }] },
  };
  const seed: PurpleSeed = { kind: "custom", id: "custom", name: "Custom", attributed: [], custom: ["T1059.001", "T1059.003"], reports: [] };
  const p = generatePurplePath(seed, { ...all, platforms: ["windows"] }, emu, deps);
  const a = p.steps.find((s) => s.technique.id === "T1059.001")!;
  const b = p.steps.find((s) => s.technique.id === "T1059.003")!;
  assert.ok(a.score > b.score);
  assert.match(a.reasonText, /1 emulation option \(1 Atomic\)/);
  assert.equal(a.simulation.execution.kind, "atomic_test");
  assert.match(b.simulation.execution.summary, /no synced emulation procedure/);
  assert.match(toCalderaYaml(p), /"a8b5a1ad-0000-4f1b-9f2e-3f1b1d6c7e01"/);
});

test("platform filter drops techniques with no matching ATT&CK platform", () => {
  const seed: PurpleSeed = { kind: "custom", id: "custom", name: "Custom", attributed: [], custom: ["T1059.001", "T1059.004"], reports: [] };
  const p = generatePurplePath(seed, { ...all, platforms: ["windows"] }, noEmu, deps);
  assert.deepEqual(p.steps.map((s) => s.technique.id), ["T1059.001"]);
  assert.match(p.excluded.find((x) => x.id === "T1059.004")!.reason, /No ATT&CK platform match for Windows/);
  assert.deepEqual(p.steps[0].simulation.targetPlatforms, ["Windows"]);
});

test("exclude high risk removes impact and credential dumping steps", () => {
  assert.equal(riskFor(getTechnique("T1003.001")!, "Credential Access").level, "high");
  assert.equal(riskFor(getTechnique("T1486")!, "Impact").level, "high");
  assert.equal(riskFor(getTechnique("T1021.001")!, "Lateral Movement").level, "medium");
  assert.equal(riskFor(getTechnique("T1018")!, "Discovery").level, "low");
  const seed: PurpleSeed = { kind: "custom", id: "custom", name: "Custom", attributed: [], custom: ["T1003.001", "T1486", "T1018"], reports: [] };
  const p = generatePurplePath(seed, { ...all, excludeHighRisk: true }, noEmu, deps);
  assert.deepEqual(p.steps.map((s) => s.technique.id), ["T1018"]);
  assert.equal(p.excluded.filter((x) => /High risk/.test(x.reason)).length, 2);
});

test("maxSteps keeps one step per tactic before filling by score", () => {
  const full = generatePurplePath(actorSeed(), all, noEmu, deps);
  const tactics = new Set(full.steps.map((s) => s.phase));
  const p = generatePurplePath(actorSeed([report("r1", "2026-09-01", [["T1018", "observed"], ["T1482", "observed"]])]), { ...all, maxSteps: tactics.size }, noEmu, deps);
  assert.equal(p.steps.length, tactics.size);
  assert.deepEqual(new Set(p.steps.map((s) => s.phase)), tactics);
  assert.ok(p.excluded.some((x) => /Lower priority/.test(x.reason)));
  const two = generatePurplePath(actorSeed(), { ...all, maxSteps: 2 }, noEmu, deps);
  assert.equal(two.steps.length, 2);
  assert.notEqual(two.steps[0].phase, two.steps[1].phase);
});

test("simulation objects carry every spec §33 field and honest statuses", () => {
  const p = generatePurplePath(actorSeed([report("r1", "2026-05-10", [["T1486", "observed"]])]), { ...all, platforms: ["windows"] }, noEmu, deps);
  const s = p.steps.find((x) => x.technique.id === "T1486")!;
  const sim = s.simulation;
  assert.match(sim.simulationId, /^SIM-\d{3}$/);
  assert.ok(sim.scenario.includes("Akira"));
  assert.ok(sim.objective.includes("T1486"));
  assert.deepEqual(sim.ttp, { id: "T1486", name: getTechnique("T1486")!.name, tactic: "Impact" });
  assert.ok(sim.prerequisites.length > 0);
  assert.deepEqual(sim.requiredTelemetry, getTechnique("T1486")!.dataSources);
  assert.equal(sim.execution.summary, "Custom procedure; no emulation library synced");
  assert.match(sim.expectedBehaviour, /T1486 was seen/);
  assert.ok(sim.successCriteria.length >= 3 && sim.cleanup.length >= 1);
  assert.equal(sim.risk.level, "high");
  assert.ok(sim.sourceRefs.some((r) => r.kind === "report" && r.quotes.length > 0));
  assert.ok(sim.sourceRefs.some((r) => r.kind === "attack"));
  assert.equal(s.detection.note, DETECTION_UNKNOWN);
  assert.equal(s.hunts[0].query.isTemplate, true);
  assert.match(s.hunts[0].query.text, /^-- TEMPLATE/);
});

test("exports: markdown, json and a CALDERA-style YAML with placeholders when nothing is synced", () => {
  const p = generatePurplePath(actorSeed(), { ...all, maxSteps: 4 }, noEmu, deps);
  const md = toMarkdown(p);
  assert.match(md, /^# Purple path: Akira/);
  assert.match(md, /AIE never executes procedures/);
  assert.match(md, /## SIM-001/);
  const json = JSON.parse(toJson(p));
  assert.equal(json.status, "planning_only");
  assert.equal(json.steps.length, 4);
  const yaml = toCalderaYaml(p);
  assert.match(yaml, /^# AIE purple path/);
  assert.match(yaml, /PLANNING ARTEFACT ONLY/);
  assert.equal((yaml.match(/PLACEHOLDER-T\d{4}/g) ?? []).length, 4);
  assert.match(yaml, /0 of 4 entries reference a synced ability/);
});

test("report evidence keeps adversary techniques with quotes and source positions", () => {
  const analysis = {
    method: "heuristic",
    classification: "x",
    threatActors: ["Akira"],
    malware: [],
    vulnerabilities: [],
    ttps: ["T1059.001 PowerShell", "T1562.001 Disable tools", "T1018"],
    ioas: [],
    attackChain: [],
    detections: [],
    hunting: [],
    emulation: [],
    evidence: {
      version: 1,
      sections: [],
      techniques: [
        { id: "T1018", name: "Remote System Discovery", tactic: "Discovery", label: "observed", mappedBy: "keyword", evidence: [{ quote: "They ran nltest.", start: 0, end: 16 }], confidence: 0.8 },
        { id: "T1059.001", name: "PowerShell", tactic: "Execution", label: "observed", mappedBy: "keyword", evidence: [{ quote: "PowerShell was used.", start: 20, end: 40 }], confidence: 0.8 },
        { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", label: "hypothetical", mappedBy: "keyword", evidence: [], confidence: 0.5 },
      ],
      actors: [],
      malware: [],
      targeting: [],
      relationships: [],
      chain: {
        orderBasis: "reported",
        steps: [
          { order: 1, tactic: "Execution", techniques: ["T1059.001"], position: 20, evidence: [] },
          { order: 2, tactic: "Discovery", techniques: ["T1018"], position: 0, evidence: [] },
        ],
      },
      excluded: [{ techniqueId: "T1562.001", label: "defensive", evidence: { quote: "Enable tamper protection.", start: 50, end: 70 } }],
    },
  } as unknown as IntelAnalysis;
  const ev = libraryEvidenceFromReport({ id: "r", title: "R", publishedAt: "2026-01-01", sourceConfidence: 0.9, analysis });
  const ids = ev.techniques.map((t) => t.id).sort();
  assert.deepEqual(ids, ["T1018", "T1059.001"]);
  const ps = ev.techniques.find((t) => t.id === "T1059.001")!;
  assert.equal(ps.position, 0);
  assert.deepEqual(ps.quotes, ["PowerShell was used."]);
});
