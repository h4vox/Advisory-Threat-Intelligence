import { test } from "node:test";
import assert from "node:assert/strict";
import {
  advisoryExportFilename,
  advisoryToExportObject,
  effectiveSeverity,
  effectiveSummary,
  effectiveTitle,
  renderAdvisoryJson,
  renderAdvisoryMarkdown,
} from "./export.ts";
import type { AdvisoryContent, AdvisoryRecord } from "./types.ts";
import { DEFAULT_PURPLE_OPTIONS, type PurplePath } from "../purple/types.ts";

const emptyPath: PurplePath = {
  version: 1,
  id: "path-1",
  generatedAt: "2026-01-01T00:00:00.000Z",
  source: { kind: "actor", id: "a1", name: "Testers" },
  options: DEFAULT_PURPLE_OPTIONS,
  orderBasis: "tactic",
  orderNote: "ordered by tactic",
  emulationSynced: false,
  steps: [],
  phases: [],
  excluded: [],
  candidateCount: 0,
  libraryReports: 0,
  disclaimer: "demo",
};

function makeContent(over: Partial<AdvisoryContent> = {}): AdvisoryContent {
  return {
    version: 1,
    generatedAt: "2026-02-10T00:00:00.000Z",
    attackVersion: "15.1",
    subject: { kind: "actor", name: "APT-Demo", id: "apt-demo", aliases: [] },
    title: "APT-Demo targeting the finance sector",
    severity: "high",
    severityReasons: ["Active KEV exploitation", "Credential theft observed"],
    summary: "APT-Demo is an espionage group active against finance.",
    keyPoints: ["Uses spearphishing", "Exploits CVE-2026-1234"],
    activity: { firstSeen: "2026-01-02T00:00:00.000Z", lastSeen: "2026-02-01T00:00:00.000Z", reports: 4, publishers: ["Acme", "Globex"] },
    behaviours: [
      {
        techniqueId: "T1566",
        name: "Phishing",
        tactic: "Initial Access",
        observedIn: 3,
        inferredIn: 1,
        mappedIn: 0,
        attributedByAttack: true,
        inPath: true,
        citations: [{ reportId: "r1", title: "Report One", publisher: "Acme", publishedAt: "2026-01-05T00:00:00.000Z", label: "observed" }],
        mitigations: [{ id: "M1049", name: "Antivirus" }],
      },
      {
        techniqueId: "T1059",
        name: "Command and Scripting Interpreter",
        tactic: "Execution",
        observedIn: 0,
        inferredIn: 0,
        mappedIn: 2,
        attributedByAttack: false,
        inPath: false,
        citations: [],
        mitigations: [],
      },
    ],
    attackOnlyBehaviours: [{ techniqueId: "T1047", name: "WMI", tactic: "Execution" }],
    targeting: [{ kind: "sector", value: "Finance", status: "targeted", reports: 3, citations: [] }],
    vulnerabilities: [
      {
        cveId: "CVE-2026-1234",
        citations: [{ reportId: "r2", title: "KEV Note", publisher: "CISA", publishedAt: "2026-01-20T00:00:00.000Z" }],
        kev: { vendor: "VendorX", product: "ProductY", name: "RCE", dateAdded: "2026-01-21T00:00:00.000Z", dueDate: "2026-02-11T00:00:00.000Z" },
      },
    ],
    indicators: [
      { kind: "domain", value: "evil.example", display: "evil[.]example", role: "c2", firstSeen: "2026-01-03T00:00:00.000Z", reports: 2, citations: [] },
      { kind: "url", value: "http://evil.example/a|b", display: "hxxp://evil[.]example/a|b", firstSeen: null, reports: 1, citations: [] },
    ],
    indicatorTotal: 7,
    detections: [
      { techniqueId: "T1566", name: "Phishing", tactic: "Initial Access", telemetry: ["email gateway"], hypothesis: "Unusual sender domains", queryTemplate: "SELECT * FROM email WHERE suspicious = 1" },
    ],
    recommendations: [
      { kind: "patch", cveId: "CVE-2026-1234", action: "Apply VendorX patch", dueDate: "2026-02-11T00:00:00.000Z", source: "CISA KEV" },
      { kind: "attack_mitigation", id: "M1049", name: "Antivirus/Antimalware", description: "Deploy AV", techniques: ["T1566"] },
      { kind: "source_guidance", text: "Enable MFA on all accounts", citation: { reportId: "r1", title: "Report One", publisher: "Acme", publishedAt: "2026-01-05T00:00:00.000Z" } },
    ],
    gaps: [{ key: "attribution", text: "Attribution confidence is moderate", impact: "medium" }],
    sources: [
      { reportId: "r1", title: "Report One", publisher: "Acme", publishedAt: "2026-01-05T00:00:00.000Z", url: "https://acme.example/r1" },
      { reportId: "r2", title: "KEV Note", publisher: "CISA", publishedAt: "2026-01-20T00:00:00.000Z" },
    ],
    path: emptyPath,
    emulationSynced: false,
    kevSynced: true,
    ...over,
  };
}

function makeRecord(over: Partial<AdvisoryRecord> = {}): AdvisoryRecord {
  return {
    id: "adv-1",
    number: "ADV-2026-0001",
    status: "review",
    tlp: "AMBER",
    createdAt: "2026-02-10T00:00:00.000Z",
    updatedAt: "2026-02-11T00:00:00.000Z",
    createdBy: "analyst",
    overrides: {},
    scope: ["T1566"],
    options: { platforms: [], excludeHighRisk: false, maxSteps: 12 },
    input: { kind: "actor", value: "APT-Demo" },
    content: makeContent(),
    ...over,
  };
}

test("markdown renders the advisory header, metadata and summary", () => {
  const md = renderAdvisoryMarkdown(makeRecord());
  assert.match(md, /^# ADV-2026-0001 — APT-Demo targeting the finance sector/);
  assert.match(md, /\| TLP \| AMBER \|/);
  assert.match(md, /\| Severity \| High \|/);
  assert.match(md, /## Summary/);
  assert.match(md, /APT-Demo is an espionage group active against finance\./);
});

test("analyst overrides win over generated content", () => {
  const rec = makeRecord({
    overrides: { title: "Override title", severity: "critical", summary: "Override summary", severityNote: "Escalated by SOC lead", notes: "Internal only." },
  });
  assert.equal(effectiveTitle(rec), "Override title");
  assert.equal(effectiveSeverity(rec), "critical");
  assert.equal(effectiveSummary(rec), "Override summary");
  const md = renderAdvisoryMarkdown(rec);
  assert.match(md, /Override title/);
  assert.match(md, /\| Severity \| Critical \|/);
  assert.match(md, /Override summary/);
  assert.match(md, /\*\*Severity note:\*\* Escalated by SOC lead/);
  assert.match(md, /## Analyst notes/);
  assert.match(md, /Internal only\./);
});

test("behaviours table marks in-scope and path techniques", () => {
  const md = renderAdvisoryMarkdown(makeRecord());
  assert.match(md, /## Observed behaviours \(MITRE ATT&CK\)/);
  // T1566 is in record.scope → "yes"; T1059 is neither → "—".
  assert.match(md, /\| T1566 Phishing \| Initial Access \| 3 observed, 1 inferred \| yes \|/);
  assert.match(md, /\| T1059 Command and Scripting Interpreter \| Execution \| 2 mapped \| — \|/);
});

test("vulnerabilities render with CISA KEV detail", () => {
  const md = renderAdvisoryMarkdown(makeRecord());
  assert.match(md, /\*\*CVE-2026-1234\*\* — CISA KEV: VendorX ProductY \(added 2026-01-21, due 2026-02-11\)/);
});

test("indicators table escapes pipes and shows the truncation note", () => {
  const md = renderAdvisoryMarkdown(makeRecord());
  assert.match(md, /## Indicators of compromise \(7\)/);
  assert.match(md, /`evil\[\.\]example`/);
  // The pipe inside the URL display must be escaped so the table stays valid.
  assert.match(md, /hxxp:\/\/evil\[\.\]example\/a\\\|b/);
  assert.match(md, /_Showing 2 of 7 indicators\._/);
});

test("detection query is fenced and labelled as a template", () => {
  const md = renderAdvisoryMarkdown(makeRecord());
  assert.match(md, /## Detection guidance/);
  assert.match(md, /Query \(template — validate before use\):/);
  assert.match(md, /```\nSELECT \* FROM email WHERE suspicious = 1\n```/);
});

test("all three recommendation kinds render", () => {
  const md = renderAdvisoryMarkdown(makeRecord());
  assert.match(md, /\*\*Patch CVE-2026-1234\*\* — Apply VendorX patch \(due 2026-02-11, CISA KEV\)/);
  assert.match(md, /\*\*M1049 Antivirus\/Antimalware\*\* — Deploy AV \(T1566\)/);
  assert.match(md, /Enable MFA on all accounts — Acme, 2026-01-05/);
});

test("sources are numbered with publisher, date and url", () => {
  const md = renderAdvisoryMarkdown(makeRecord());
  assert.match(md, /## Sources/);
  assert.match(md, /1\. Report One — Acme, 2026-01-05 <https:\/\/acme\.example\/r1>/);
  assert.match(md, /2\. KEV Note — CISA, 2026-01-20/);
});

test("filename is sanitised", () => {
  assert.equal(advisoryExportFilename(makeRecord(), "md"), "ADV-2026-0001.md");
  assert.equal(advisoryExportFilename(makeRecord({ number: "ADV/2026 0002" }), "json"), "ADV-2026-0002.json");
});

test("json export applies overrides and keeps full content", () => {
  const rec = makeRecord({ overrides: { title: "T2", severity: "low", summary: "S2" } });
  const obj = JSON.parse(renderAdvisoryJson(rec));
  assert.equal(obj.title, "T2");
  assert.equal(obj.severity, "low");
  assert.equal(obj.summary, "S2");
  assert.equal(obj.number, "ADV-2026-0001");
  assert.equal(obj.content.behaviours.length, 2);
  assert.equal(obj.content.indicatorTotal, 7);
  // Round-trips through the structured object helper too.
  assert.deepEqual(advisoryToExportObject(rec).scope, ["T1566"]);
});
