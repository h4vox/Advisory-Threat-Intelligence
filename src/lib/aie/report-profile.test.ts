import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeForMatch, reportProfile } from "./report-profile.ts";
import type { IntelAnalysis } from "./types.ts";
import type { ReportAiAnalysis } from "./report-ai-analysis.ts";

const TEXT = `Volt Typhoon exploited CVE-2024-39717 in Versa Director and deployed the VersaMem web shell.
The actor used rotating relays at 203.0.113[.]7 and hxxps://relay.example[.]net/path. APT10 is not involved.`;

const analysis = {
  method: "llm",
  classification: "x",
  threatActors: ["Volt Typhoon", "Vanguard Panda", "Bronze Silhouette", "UNC3236", "APT1"],
  malware: [],
  vulnerabilities: ["CVE-2024-39717", "CVE-2026-16812"],
  ttps: [],
  ioas: [],
  attackChain: [
    { order: 1, tactic: "Initial Access", techniques: ["T1190 - Exploit Public-Facing Application"], summary: "zero-day exploitation" },
    { order: 2, tactic: "Persistence", techniques: ["T1505.003 - Server Software Component: Web Shell"], summary: "web shells" },
  ],
  detections: [],
  hunting: [],
  emulation: [],
} as unknown as IntelAnalysis;

const iocs = [
  { kind: "cve" as const, value: "CVE-2024-39717" },
  { kind: "cve" as const, value: "CVE-2026-16812" },
  { kind: "technique" as const, value: "T1190" },
  { kind: "ipv4" as const, value: "203.0.113.7", original: "203.0.113[.]7", defanged: true },
  { kind: "url" as const, value: "https://relay.example.net/path" },
  { kind: "domain" as const, value: "not-in-report.example" },
];

test("only names, CVEs and indicators the report contains are kept; techniques are not indicators", () => {
  const p = reportProfile({ extractedText: TEXT, analysis, iocs });
  assert.deepEqual(p.actors, ["Volt Typhoon"], "ATT&CK aliases absent from the text are dropped; APT1 does not match APT10");
  assert.deepEqual(p.vulnerabilities, ["CVE-2024-39717"]);
  assert.deepEqual(
    p.indicators.map((i) => i.value),
    ["203.0.113.7", "https://relay.example.net/path"],
  );
  assert.ok(p.dropped.includes("Vanguard Panda") && p.dropped.includes("CVE-2026-16812") && p.dropped.includes("not-in-report.example"));
  assert.equal(p.source, "analysis");
  assert.equal(p.chain.length, 2);
  assert.equal(p.chainQuoted, false);
});

test("the grounded AI analysis is preferred and brings malware and quoted steps", () => {
  const ai = {
    adversary: { name: "Volt Typhoon", aliases: ["Vanguard Panda"], type: "state-sponsored", motivation: "", sectors: [], regions: [], malware: ["VersaMem"], tools: [], summary: "" },
    attackChain: [{ order: 1, stage: "Initial Access", technique: { id: "T1190", name: "Exploit Public-Facing Application" }, summary: "Exploited Versa Director", quote: "Volt Typhoon exploited CVE-2024-39717 in Versa Director" }],
    iocs: [{ type: "domain", value: "relay.example.net" }],
  } as unknown as ReportAiAnalysis;
  const p = reportProfile({ extractedText: TEXT, analysis, aiAnalysis: ai, iocs });
  assert.equal(p.source, "ai");
  assert.deepEqual(p.malware, ["VersaMem"]);
  assert.equal(p.chain[0].quote, "Volt Typhoon exploited CVE-2024-39717 in Versa Director");
  assert.ok(p.chainQuoted);
  assert.ok(p.indicators.some((i) => i.value === "relay.example.net"));
});

test("evidence limits the older chain to supported techniques", () => {
  const withEvidence = {
    ...analysis,
    evidence: { version: 1, sections: [], techniques: [{ id: "T1190", name: "x", tactic: "Initial Access", label: "observed", mappedBy: "explicit_id", evidence: [], confidence: 0.8 }], actors: [], malware: [], targeting: [], relationships: [], chain: { steps: [], orderBasis: "unknown" }, excluded: [] },
  } as unknown as IntelAnalysis;
  const p = reportProfile({ extractedText: TEXT, analysis: withEvidence, iocs });
  assert.equal(p.source, "evidence");
  assert.deepEqual(p.chain.map((s) => s.tactic), ["Initial Access"]);
});

test("defanged text matches refanged values", () => {
  assert.equal(normalizeForMatch("hxxps://a[.]b(.)c"), "https://a.b.c");
});
