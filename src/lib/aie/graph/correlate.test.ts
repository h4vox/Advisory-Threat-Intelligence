import { test } from "node:test";
import assert from "node:assert/strict";
import { buildIntelGraph, type GraphSourceReport } from "./build.ts";
import { indexGraph } from "./analyze.ts";
import { connectionPaths, entityContext, resolveRef } from "./correlate.ts";
import { resolveEntity } from "../attack-knowledge.ts";

const ev = (q: string) => [{ quote: q, start: 0, end: q.length }];
const fact = (value: string) => ({ value, label: "observed" as const, evidence: ev(value), confidence: 0.8 });
const tech = (id: string, name: string, tactic: string) => ({ id, name, tactic, label: "observed" as const, mappedBy: "explicit_id" as const, evidence: ev(id), confidence: 0.8 });
const report = (id: string, date: string, actors: string[], malware: string[], techniques: ReturnType<typeof tech>[], sectors: string[], cves: string[] = []): GraphSourceReport => ({
  id,
  title: `R ${id}`,
  publishedAt: date,
  status: "acquired",
  iocs: cves.map((c) => ({ kind: "cve" as const, value: c })),
  analysis: {
    method: "heuristic", classification: "x", threatActors: [], malware: [], vulnerabilities: [], ttps: [], ioas: [], attackChain: [], detections: [], hunting: [], emulation: [],
    evidence: { version: 1, sections: [], techniques, actors: actors.map(fact), malware: malware.map(fact), targeting: sectors.map((s) => ({ kind: "sector" as const, value: s, status: "targeted" as const, evidence: ev(s), confidence: 0.7 })), relationships: [], chain: { steps: [], orderBasis: "unknown" }, excluded: [] },
  },
});
const PHISH = tech("T1566", "Phishing", "Initial Access");
const PS = tech("T1059.001", "PowerShell", "Execution");
const NOVEL = tech("T1027", "Obfuscated Files or Information", "Defense Evasion");
const now = Date.parse("2026-10-29");
const g = buildIntelGraph([
  report("r1", "2026-10-01", ["APT29"], ["Cobalt Strike"], [PHISH, PS, NOVEL], ["government"], ["CVE-2024-1234"]),
  report("r2", "2026-09-20", ["APT29"], ["Cobalt Strike"], [PHISH], ["energy"]),
  report("r3", "2026-03-01", ["Storm-1"], ["Cobalt Strike"], [PHISH, PS], ["government"]),
  report("r4", "2025-01-01", ["Storm-2"], [], [NOVEL], ["finance"]),
]);
const ix = indexGraph(g);
const apt29 = `actor:${resolveEntity("APT29", ["group"])[0].id}`;

test("names, aliases, IDs and CVEs resolve to entities", () => {
  assert.equal(resolveRef(ix, "Cozy Bear")?.id, apt29);
  assert.equal(resolveRef(ix, "t1566")?.id, "technique:T1566");
  assert.equal(resolveRef(ix, "cve-2024-1234")?.id, "vulnerability:CVE-2024-1234");
  assert.equal(resolveRef(ix, apt29)?.id, apt29);
  assert.equal(resolveRef(ix, "no such thing"), null);
});

test("entity context: grouped links, related entities with the reason, trend and findings", () => {
  const c = entityContext(ix, apt29, { now })!;
  assert.deepEqual(c.links.map((l) => l.type).slice(0, 2), ["malware", "technique"]);
  const storm = c.related.find((r) => r.node.id === "actor:x-storm-1");
  assert.ok(storm, "Storm-1 is related through shared links");
  assert.ok(storm!.via.some((v) => v.label === "Cobalt Strike" || v.id === "technique:T1566"));
  assert.equal(c.trend, "new");
  assert.ok(c.findings.some((f) => f.kind === "targeting" && /Government|Energy/.test(f.text)));
  assert.ok(c.findings.some((f) => f.kind === "exploitation"));
  assert.ok(c.attack && c.attack.id.startsWith("G"), "ATT&CK comparison");
  assert.match(c.summary, /appears in 2 reports/);
});

test("technique context lists who uses it and ATT&CK details", () => {
  const c = entityContext(ix, "technique:T1566", { now })!;
  assert.ok(c.findings.some((f) => /Used by/.test(f.text)));
  assert.deepEqual(c.attack?.tactics, ["Initial Access"]);
});

test("connection paths explain how two entities are linked", () => {
  const p = connectionPaths(ix, apt29, "actor:x-storm-1");
  assert.ok(p.length >= 1);
  assert.equal(p[0].nodes.length, 3, "shortest path through one shared entity");
  assert.equal(p[0].nodes[0].id, apt29);
  assert.match(p[0].text, /Storm-1$/);
  assert.deepEqual(connectionPaths(ix, apt29, apt29), []);
});
