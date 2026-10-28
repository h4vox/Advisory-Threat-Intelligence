import { test } from "node:test";
import assert from "node:assert/strict";
import { slimForList } from "./list-view.ts";

const quote = (q: string) => ({ quote: q, start: 0, end: q.length, section: "Intro" });

const report = {
  id: "rpt_1",
  title: "T",
  iocs: [{ kind: "ipv4", value: "1.2.3.4", original: "1.2.3[.]4", defanged: true, role: "C2", evidence: quote("C2 at 1.2.3[.]4") }],
  analysis: {
    method: "heuristic",
    threatActors: ["APT29"],
    attackChain: [{ order: 1, tactic: "Initial Access", summary: "s", techniques: ["T1566"] }],
    evidence: {
      version: 1,
      sections: [{ heading: "Intro", start: 0 }],
      techniques: [{ id: "T1566", name: "Phishing", tactic: "Initial Access", label: "observed", mappedBy: "explicit_id", evidence: [quote("They phished.")], confidence: 0.9 }],
      actors: [{ value: "APT29", label: "observed", evidence: [quote("APT29 did it.")], confidence: 0.8 }],
      malware: [],
      targeting: [],
      relationships: [],
      chain: { steps: [{ order: 1, tactic: "Initial Access", techniques: ["T1566"], position: 10, evidence: [quote("They phished.")] }], orderBasis: "reported" },
      excluded: [{ techniqueId: "T1003", label: "defensive", evidence: quote("Protect LSASS.") }],
    },
  },
};

test("quotes and offsets are dropped; labels, names, values and order stay", () => {
  const s = slimForList(report) as typeof report;
  const ev = s.analysis.evidence;
  assert.deepEqual(ev.techniques[0], { id: "T1566", name: "Phishing", tactic: "Initial Access", label: "observed", mappedBy: "explicit_id", evidence: [], confidence: 0.9 });
  assert.deepEqual(ev.actors[0], { value: "APT29", label: "observed", evidence: [], confidence: 0.8 });
  assert.deepEqual(ev.chain, { steps: [{ order: 1, tactic: "Initial Access", techniques: ["T1566"], position: 10, evidence: [] }], orderBasis: "reported" });
  assert.deepEqual(ev.excluded, []);
  assert.deepEqual(ev.sections, []);
  assert.deepEqual(s.analysis.attackChain, report.analysis.attackChain);
  assert.deepEqual(s.analysis.threatActors, ["APT29"]);
  assert.deepEqual(s.iocs, [{ kind: "ipv4", value: "1.2.3.4", defanged: true, role: "C2" }]);
});

test("the original report is not modified", () => {
  slimForList(report);
  assert.equal(report.analysis.evidence.techniques[0].evidence.length, 1);
  assert.ok(report.iocs[0].evidence);
});

test("reports without analysis or indicators pass through", () => {
  assert.deepEqual(slimForList({ id: "x", analysis: null }), { id: "x", analysis: null });
  assert.deepEqual(slimForList({ id: "y" }), { id: "y" });
});

test("it is much smaller", () => {
  const big = { ...report, analysis: { ...report.analysis, evidence: { ...report.analysis.evidence, techniques: Array.from({ length: 50 }, (_, i) => ({ ...report.analysis.evidence.techniques[0], id: `T${1000 + i}`, evidence: Array.from({ length: 5 }, () => quote("x".repeat(300))) })) } } };
  assert.ok(JSON.stringify(slimForList(big)).length < JSON.stringify(big).length / 5);
});
