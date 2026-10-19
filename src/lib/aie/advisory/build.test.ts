import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAdvisoryContent, type AdvisoryBuildDeps, type AdvisoryBuildInput, type AdvisoryReport } from "./build.ts";
import type { AdvisorySubject, KevDetails } from "./types.ts";
import { DEFAULT_PURPLE_OPTIONS, type PurplePath } from "../purple/types.ts";

const emptyPath: PurplePath = {
  version: 1,
  id: "path-1",
  generatedAt: "2026-01-01T00:00:00.000Z",
  source: { kind: "actor", id: "a1", name: "APT-Demo" },
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

const deps: AdvisoryBuildDeps = {
  getTechnique: (id) => ({ id, name: `Technique ${id}`, tactics: ["Execution"] }),
  getMitigation: () => undefined,
  mitigationsForTechniques: () => [],
  tacticRank: () => 0,
  attackVersion: "15.1",
};

const subject: AdvisorySubject = { kind: "actor", id: "apt-demo", name: "APT-Demo", aliases: [] };

const reports: AdvisoryReport[] = [
  {
    id: "r1",
    title: "APT-Demo campaign report",
    publisher: "Acme",
    publishedAt: "2026-01-05T00:00:00.000Z",
    analysis: {
      method: "heuristic",
      classification: "CAMPAIGN_INTEL",
      threatActors: ["APT-Demo"],
      malware: [],
      vulnerabilities: ["CVE-2026-1234"],
      ttps: ["T1566"],
      ioas: [],
      attackChain: [],
      detections: [],
      hunting: [],
      emulation: [],
    },
    iocs: [
      { kind: "domain", value: "evil.example", original: "evil[.]example", role: "c2" },
      { kind: "cve", value: "CVE-2026-1234" },
    ],
  },
];

const kev = new Map<string, KevDetails>([
  ["CVE-2026-1234", { vendor: "VendorX", product: "ProductY", name: "RCE", dateAdded: "2026-01-21T00:00:00.000Z", dueDate: "2026-02-11T00:00:00.000Z", requiredAction: "Apply update" }],
]);

function makeInput(over: Partial<AdvisoryBuildInput> = {}): AdvisoryBuildInput {
  return { subject, reports, attributed: [], path: emptyPath, kev, kevSynced: true, emulationSynced: false, now: "2026-02-10T00:00:00.000Z", ...over };
}

test("buildAdvisoryContent returns a well-formed advisory", () => {
  const c = buildAdvisoryContent(makeInput(), deps);
  assert.equal(c.version, 1);
  assert.equal(c.generatedAt, "2026-02-10T00:00:00.000Z");
  assert.equal(c.attackVersion, "15.1");
  assert.equal(c.subject.name, "APT-Demo");
  assert.ok(c.title.length > 0, "title should be set");
  assert.ok(["critical", "high", "medium", "low"].includes(c.severity), "severity is valid");
});

test("vulnerabilities are collected from analysis + iocs and enriched from KEV", () => {
  const c = buildAdvisoryContent(makeInput(), deps);
  const v = c.vulnerabilities.find((x) => x.cveId === "CVE-2026-1234");
  assert.ok(v, "CVE-2026-1234 present");
  assert.equal(v?.kev?.vendor, "VendorX");
  // A KEV with a required action yields a patch recommendation.
  assert.ok(
    c.recommendations.some((r) => r.kind === "patch" && r.cveId === "CVE-2026-1234"),
    "patch recommendation present",
  );
});

test("indicators come from report IOCs, excluding cve/technique, with the defanged display kept", () => {
  const c = buildAdvisoryContent(makeInput(), deps);
  const dom = c.indicators.find((i) => i.value === "evil.example");
  assert.ok(dom, "domain indicator present");
  assert.equal(dom?.display, "evil[.]example");
  assert.equal(dom?.role, "c2");
  // The cve-kind IOC is not an indicator.
  assert.equal(c.indicators.some((i) => i.kind === "cve"), false);
  assert.equal(c.indicatorTotal, 1);
});

test("sources list the input reports", () => {
  const c = buildAdvisoryContent(makeInput(), deps);
  assert.equal(c.sources.length, 1);
  assert.equal(c.sources[0].reportId, "r1");
  assert.equal(c.sources[0].publisher, "Acme");
});

test("ATT&CK-attributed techniques with no library evidence are kept separate", () => {
  const c = buildAdvisoryContent(makeInput({ attributed: ["T1486"] }), deps);
  assert.ok(
    c.attackOnlyBehaviours.some((b) => b.techniqueId === "T1486"),
    "attributed-only technique surfaces in attackOnlyBehaviours",
  );
});
