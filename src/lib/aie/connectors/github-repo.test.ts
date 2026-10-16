import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildCalderaResult,
  buildUnit42IocDoc,
  linkedRepoFiles,
  parseAttackFlowAfb,
  parseAttackFlowExampleIndex,
  parseCalderaAbilityYaml,
  parseCtidReadmeIndex,
  selectCtidPlanFiles,
  selectUnit42IocFiles,
  syncAttackFlowCorpus,
  syncCtidLibrary,
} from "./github-repo.ts";
import { githubRawUrl, type ConnectorFetcher } from "./fetch.ts";
import type { ConnectorSource } from "./common.ts";

const CTID: ConnectorSource = {
  id: "src_ctid_aelib",
  name: "CTID Adversary Emulation Library",
  tier: 2,
  confidenceClass: "RESEARCH_ORG",
  connectorConfig: { owner: "center-for-threat-informed-defense", repo: "adversary_emulation_library", branch: "master" },
};
const AF: ConnectorSource = {
  id: "src_attack_flow",
  name: "MITRE Attack Flow Corpus",
  tier: 2,
  confidenceClass: "RESEARCH_ORG",
  connectorConfig: { owner: "center-for-threat-informed-defense", repo: "attack-flow", branch: "main", path: "corpus/" },
};

const ROOT_README = `
| Adversary | Description |
| --- | --- |
| [FIN6](/fin6/)                   | [FIN6 is thought to be a financially motivated cyber-crime group...](/fin6/Intelligence_Summary.md) |
| [Sandworm](/sandworm/)           | [Sandworm Team is a destructive threat group...](/sandworm/Intelligence_Summary/Intelligence_Summary.md) |
| [Web Shells](/micro_emulation_plans/src/webshell/) | Emulates planting a web shell ([T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)) |
| [External](https://example.com/) | ignored |
`;

const FIN6_README = `# FIN6
* [Intelligence Summary](/fin6/Intelligence_Summary.md)
* [Operations Flow](/fin6/Operations_Flow.md)
* [Emulation Plan](/fin6/Emulation_Plan/README.md)
  - [Phase 1](./Emulation_Plan/Phase1.md)
* [Issues](https://github.com/x/issues)
* [Elsewhere](/apt29/README.md)
`;

test("CTID README index: full and micro plans, external rows ignored", () => {
  const idx = parseCtidReadmeIndex(ROOT_README);
  assert.deepEqual(
    idx.map((e) => [e.folder, e.planType]),
    [
      ["fin6", "full"],
      ["sandworm", "full"],
      ["micro_emulation_plans/src/webshell", "micro"],
    ],
  );
  assert.equal(idx[0].name, "FIN6");
  assert.equal(idx[0].summaryPath, "fin6/Intelligence_Summary.md");
  assert.match(idx[0].summary, /^FIN6 is thought to be a financially motivated cyber-crime group…$/);
  assert.match(idx[2].summary, /T1505\.003 Web Shell/);
});

test("linked repo files stay inside the plan folder", () => {
  assert.deepEqual(linkedRepoFiles(FIN6_README, "fin6"), [
    "fin6/Intelligence_Summary.md",
    "fin6/Operations_Flow.md",
    "fin6/Emulation_Plan/README.md",
    "fin6/Emulation_Plan/Phase1.md",
  ]);
});

test("tree-based plan file selection ranks README, summary, flow, plan", () => {
  const files = selectCtidPlanFiles(
    [
      { path: "fin6/Emulation_Plan/yaml/FIN6.yaml", type: "blob" },
      { path: "fin6/README.md", type: "blob" },
      { path: "fin6/Resources/tool.exe", type: "blob" },
      { path: "fin6/Operations_Flow.md", type: "blob" },
      { path: "fin6/Intelligence_Summary.md", type: "blob" },
      { path: "fin7/README.md", type: "blob" },
    ],
    "fin6",
  );
  assert.deepEqual(files, ["fin6/README.md", "fin6/Intelligence_Summary.md", "fin6/Operations_Flow.md", "fin6/Emulation_Plan/yaml/FIN6.yaml"]);
});

function stubFetcher(files: Record<string, string>, tree?: Array<{ path: string; type: string }>): ConnectorFetcher {
  return {
    async text(url) {
      const hit = Object.entries(files).find(([k]) => url.endsWith(k));
      if (!hit) throw new Error(`Source returned HTTP 404`);
      return hit[1];
    },
    async githubTree() {
      if (!tree) throw new Error("GitHub API unreachable (blocked)");
      return { entries: tree, truncated: false };
    },
  };
}

test("CTID sync without the GitHub API falls back to README links", async () => {
  const fetcher = stubFetcher({
    "/master/README.md": ROOT_README,
    "/master/fin6/README.md": FIN6_README,
    "/master/fin6/Intelligence_Summary.md": "FIN6 uses T1059.001 PowerShell and T1003.001 LSASS Memory, then T1486.",
    "/master/fin6/Operations_Flow.md": "Phase 1: T1078 valid accounts → T1021.001 RDP.",
    "/master/micro_emulation_plans/src/webshell/README.md": "Plants a web shell (T1505.003) then runs T1059.",
  });
  const r = await syncCtidLibrary(CTID, fetcher, { now: "2026-10-16T00:00:00.000Z" });
  assert.deepEqual(r.stats, { fullPlans: 1, microPlans: 1, techniques: 7 });
  assert.ok(r.warnings.some((w) => /File listing unavailable/.test(w)));
  assert.ok(r.warnings.some((w) => w.startsWith("sandworm/README.md")));
  const fin6 = r.docs.find((d) => d.id === "ctid_fin6")!;
  assert.deepEqual(fin6.docTypes, ["ADVERSARY_EMULATION_PLAN", "PURPLE_TEAM_REPORT"]);
  assert.equal(fin6.url, "https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/fin6");
  if (fin6.structured?.kind === "emulation_plan") {
    assert.equal(fin6.structured.planType, "full");
    assert.deepEqual(fin6.structured.techniques, ["T1003.001", "T1021.001", "T1059.001", "T1078", "T1486"]);
    assert.ok(fin6.structured.files.includes("fin6/Emulation_Plan/Phase1.md"));
  } else assert.fail("emulation plan payload missing");
  const micro = r.docs.find((d) => d.id === "ctid_micro_webshell")!;
  assert.deepEqual(micro.docTypes, ["MICRO_EMULATION_PLAN"]);
  const opt = r.emulation.find((e) => e.techniqueId === "T1505.003")!;
  assert.equal(opt.kind, "ctid_procedure");
  assert.equal(opt.options[0].ref, "micro_emulation_plans/src/webshell");
});

// Minimal Attack Flow Builder file: action A → AND → action B, plus a tool.
const AFB = {
  schema: "attack_flow_v2",
  objects: [
    {
      id: "flow",
      instance: "flow-1",
      properties: [
        ["name", "Example Ransomware"],
        ["description", "Phish then encrypt."],
        ["author", [["name", "Analyst"]]],
        ["scope", "incident"],
        ["external_references", [["k1", [["source_name", "Vendor"], ["url", "https://vendor.example/report"]]]]],
        ["created", "2024-06-19T15:45:49.090Z"],
      ],
    },
    { id: "action", instance: "a1", properties: [["name", "Spearphishing Attachment"], ["technique_id", "T1566.001"], ["tactic_id", "TA0001"]], anchors: { "0": "an1" } },
    { id: "AND_operator", instance: "op1", properties: [["operator", "AND"]], anchors: { "0": "an2", "90": "an3" } },
    { id: "action", instance: "a2", properties: [["name", "Data Encrypted for Impact"], ["technique_id", "t1486"]], anchors: { "0": "an4" } },
    { id: "tool", instance: "tool1", properties: [["name", "PsExec"]], anchors: { "0": "an5" } },
    { id: "horizontal_anchor", instance: "an1", latches: ["l1"] },
    { id: "horizontal_anchor", instance: "an2", latches: ["l2"] },
    { id: "vertical_anchor", instance: "an3", latches: ["l3"] },
    { id: "vertical_anchor", instance: "an4", latches: ["l4"] },
    { id: "vertical_anchor", instance: "an5", latches: [] },
    { id: "generic_latch", instance: "l1" },
    { id: "generic_latch", instance: "l2" },
    { id: "generic_latch", instance: "l3" },
    { id: "generic_latch", instance: "l4" },
    // Lines are listed B-first to check topological ordering.
    { id: "dynamic_line", instance: "line2", source: "l3", target: "l4", handles: [] },
    { id: "dynamic_line", instance: "line1", source: "l1", target: "l2", handles: [] },
  ],
};

test("Attack Flow .afb: actions, operator-resolved edges, order, objects, references", () => {
  const f = parseAttackFlowAfb(JSON.stringify(AFB));
  assert.equal(f.flowName, "Example Ransomware");
  assert.equal(f.scope, "incident");
  assert.equal(f.author, "Analyst");
  assert.deepEqual(f.references, [{ name: "Vendor", url: "https://vendor.example/report" }]);
  assert.deepEqual(
    f.actions.map((a) => [a.id, a.techniqueId]),
    [
      ["a1", "T1566.001"],
      ["a2", "T1486"],
    ],
  );
  assert.deepEqual(f.relationships, [{ from: "a1", to: "a2" }]);
  assert.deepEqual(f.objects, [{ type: "tool", name: "PsExec" }]);
});

test("Attack Flow example index + sync fallback", async () => {
  const rst = `<a href="../corpus/Example%20Ransomware.afb" download>Attack Flow</a> | <a href="../corpus/Example%20Ransomware.json">STIX</a>
  <a href="../ui/?src=https%3A//x/corpus/Example%20Ransomware.afb">open</a> <a href="../corpus/CISA%20AA22-138B%20VMWare%20%28TA1%29.afb">x</a>`;
  assert.deepEqual(parseAttackFlowExampleIndex(rst), ["Example Ransomware", "CISA AA22-138B VMWare (TA1)"]);
  const fetcher = stubFetcher({
    "/main/docs/example_flows.rst": rst,
    [`/main/corpus/${encodeURIComponent("Example Ransomware.afb")}`]: JSON.stringify(AFB),
  });
  const r = await syncAttackFlowCorpus(AF, fetcher, { now: "2026-10-16T00:00:00.000Z" });
  assert.equal(r.docs.length, 1);
  assert.equal(r.stats.flows, 1);
  assert.ok(r.warnings.some((w) => w.includes("CISA AA22-138B")), "missing file reported as warning");
  const d = r.docs[0];
  assert.equal(d.id, "af_example-ransomware");
  assert.deepEqual(d.docTypes, ["ATTACK_FLOW"]);
  assert.equal(d.url, "https://github.com/center-for-threat-informed-defense/attack-flow/blob/main/corpus/Example%20Ransomware.afb");
  assert.ok(d.structured?.kind === "attack_flow" && d.structured.relationships.length === 1);
  assert.deepEqual(r.emulation.map((e) => e.techniqueId).sort(), ["T1486", "T1566.001"]);
});

test("CALDERA ability YAML → abilities grouped by technique", () => {
  const yml = `---
- id: 3b5db901-2cb8-4df7-8043-c4628a6a5d5a
  name: Find files
  description: Locate files deemed sensitive
  tactic: collection
  technique:
    attack_id: T1005
    name: Data from Local System
  platforms:
    darwin:
      sh:
        command: find /Users -name '*.pdf'
    windows:
      psh,pwsh:
        command: Get-ChildItem C:\\Users -Recurse -Include *.pdf
  privilege: Elevated
`;
  const abilities = parseCalderaAbilityYaml(yml, "data/abilities/collection/3b5db901.yml");
  assert.equal(abilities.length, 1);
  assert.deepEqual(abilities[0].platforms, ["darwin", "windows"]);
  assert.deepEqual(abilities[0].executors, ["sh", "psh", "pwsh"]);
  const r = buildCalderaResult(abilities, { id: "src_caldera", name: "CALDERA", tier: 2, confidenceClass: "RESEARCH_ORG" }, { owner: "mitre", repo: "stockpile", branch: "master" });
  assert.equal(r.docs[0].id, "cal_T1005");
  assert.deepEqual(r.docs[0].docTypes, ["CALDERA_ABILITY"]);
  assert.equal(r.emulation[0].options[0].kind, "caldera_ability");
  assert.equal(r.emulation[0].options[0].elevationRequired, true);
});

test("Unit 42 IOC files → THREAT_REPORT with harvested indicators", () => {
  const files = selectUnit42IocFiles([
    { path: "README.md", type: "blob" },
    { path: "2023-01-10-IOCs-for-Example.txt", type: "blob", size: 1000 },
    { path: "2024-05-02-IOCs-for-Other.txt", type: "blob", size: 1000 },
    { path: "huge.txt", type: "blob", size: 5_000_000 },
  ]);
  assert.deepEqual(files, ["2024-05-02-IOCs-for-Other.txt", "2023-01-10-IOCs-for-Example.txt"]);
  const doc = buildUnit42IocDoc(
    files[0],
    "C2: hxxps://evil-example[.]com/gate.php\nSHA256: 5f4dcc3b5aa765d61d8327deb882cf995f4dcc3b5aa765d61d8327deb882cf99\nExploits CVE-2024-3400",
    { id: "src_unit42_iocs", name: "Unit 42 IOC Repository", tier: 3, confidenceClass: "TRUSTED_VENDOR" },
    { owner: "PaloAltoNetworks", repo: "Unit42-Threat-Intelligence-Article-Information", branch: "main" },
  );
  assert.equal(doc.publishedAt, "2024-05-02");
  assert.ok(doc.iocs.some((i) => i.kind === "sha256"));
  assert.ok(doc.iocs.some((i) => i.kind === "cve"));
  assert.deepEqual(doc.extractedEntities?.cves, ["CVE-2024-3400"]);
});

test("raw URL builder rejects traversal and bad names", () => {
  assert.equal(
    githubRawUrl("redcanaryco", "atomic-red-team", "master", "atomics/Indexes/index.yaml"),
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml",
  );
  assert.throws(() => githubRawUrl("a", "b", "main", "../etc/passwd"), /Invalid repository path/);
  assert.throws(() => githubRawUrl("a/b", "c", "main", "x"), /Invalid GitHub owner/);
});
