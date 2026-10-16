import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAttackTechniqueIndex, parseAttackStixBundle, techniqueLookupFrom } from "./attack-stix.ts";
import type { ConnectorSource } from "./common.ts";

const SOURCE: ConnectorSource = { id: "src_attack_stix", name: "MITRE ATT&CK Enterprise (STIX)", tier: 1, confidenceClass: "OFFICIAL_PRIMARY" };
const ref = (id: string, kind = "techniques") => [{ source_name: "mitre-attack", external_id: id, url: `https://attack.mitre.org/${kind}/${id.replace(".", "/")}` }];
const rel = (id: string, type: string, source_ref: string, target_ref: string) => ({ type: "relationship", id, relationship_type: type, source_ref, target_ref });

const BUNDLE = {
  type: "bundle",
  objects: [
    { type: "x-mitre-tactic", id: "x-mitre-tactic--exec", name: "Execution", x_mitre_shortname: "execution" },
    {
      type: "attack-pattern",
      id: "attack-pattern--t1059",
      name: "Command and Scripting Interpreter",
      external_references: ref("T1059"),
      kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "execution" }],
      x_mitre_platforms: ["Windows", "Linux"],
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--t1059-001",
      name: "PowerShell",
      x_mitre_is_subtechnique: true,
      external_references: ref("T1059.001"),
      kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "execution" }],
      x_mitre_platforms: ["Windows"],
      description: "Adversaries may abuse PowerShell. (Citation: Example)",
    },
    { type: "attack-pattern", id: "attack-pattern--old", name: "Old", x_mitre_deprecated: true, external_references: ref("T1999") },
    {
      type: "intrusion-set",
      id: "intrusion-set--apt29",
      name: "APT29",
      aliases: ["APT29", "Cozy Bear", "NOBELIUM"],
      description: "[APT29](https://attack.mitre.org/groups/G0016) is a threat group. (Citation: X)",
      external_references: ref("G0016", "groups"),
    },
    { type: "intrusion-set", id: "intrusion-set--revoked", name: "Gone", revoked: true, external_references: ref("G9999", "groups") },
    { type: "malware", id: "malware--sunburst", name: "SUNBURST", x_mitre_aliases: ["SUNBURST", "Solorigate"], x_mitre_platforms: ["Windows"], external_references: ref("S0559", "software") },
    { type: "tool", id: "tool--adfind", name: "AdFind", external_references: ref("S0552", "software") },
    {
      type: "campaign",
      id: "campaign--solarwinds",
      name: "SolarWinds Compromise",
      first_seen: "2019-08-01T00:00:00Z",
      last_seen: "2021-01-01T00:00:00Z",
      external_references: ref("C0024", "campaigns"),
    },
    { type: "x-mitre-data-component", id: "x-mitre-data-component--cmd", name: "Command Execution" },
    { type: "x-mitre-analytic", id: "x-mitre-analytic--a1", x_mitre_log_source_references: [{ x_mitre_data_component_ref: "x-mitre-data-component--cmd" }] },
    { type: "x-mitre-detection-strategy", id: "x-mitre-detection-strategy--d1", x_mitre_analytic_refs: ["x-mitre-analytic--a1"] },
    rel("r1", "uses", "intrusion-set--apt29", "attack-pattern--t1059-001"),
    rel("r2", "uses", "intrusion-set--apt29", "tool--adfind"),
    rel("r3", "uses", "malware--sunburst", "attack-pattern--t1059"),
    rel("r4", "uses", "campaign--solarwinds", "malware--sunburst"),
    rel("r5", "attributed-to", "campaign--solarwinds", "intrusion-set--apt29"),
    rel("r6", "uses", "campaign--solarwinds", "attack-pattern--t1059-001"),
    rel("r7", "uses", "intrusion-set--revoked", "attack-pattern--t1059"),
    rel("r8", "uses", "intrusion-set--apt29", "attack-pattern--old"),
    rel("r9", "detects", "x-mitre-detection-strategy--d1", "attack-pattern--t1059-001"),
  ],
};

test("technique index: names sub-techniques with parent, tactics, platforms, data components", () => {
  const idx = buildAttackTechniqueIndex(BUNDLE);
  assert.deepEqual(
    idx.map((t) => t.id),
    ["T1059", "T1059.001"],
  );
  const ps = idx.find((t) => t.id === "T1059.001")!;
  assert.equal(ps.name, "Command and Scripting Interpreter: PowerShell");
  assert.deepEqual(ps.tactics, ["Execution"]);
  assert.deepEqual(ps.platforms, ["Windows"]);
  assert.deepEqual(ps.dataSources, ["Command Execution"]);
  assert.equal(ps.description, "Adversaries may abuse PowerShell.");
  assert.equal(techniqueLookupFrom(idx)("t1059.001")?.name, "Command and Scripting Interpreter: PowerShell");
});

test("groups, software and campaigns with uses / attributed-to links", () => {
  const r = parseAttackStixBundle(BUNDLE, SOURCE, { now: "2026-10-16T00:00:00.000Z" });
  assert.deepEqual(r.stats, { groups: 1, software: 2, campaigns: 1, techniques: 2, relationships: 7 });
  const g = r.docs.find((d) => d.id === "att_G0016")!;
  assert.equal(g.title, "APT29 (G0016)");
  assert.deepEqual(g.docTypes, ["MITRE_GROUP"]);
  assert.equal(g.sourceTier, 1);
  assert.equal(g.canonicalUrl, "https://attack.mitre.org/groups/G0016");
  assert.ok(g.structured && g.structured.kind === "attack_group");
  if (g.structured?.kind === "attack_group") {
    assert.deepEqual(g.structured.aliases, ["Cozy Bear", "NOBELIUM"]);
    assert.deepEqual(g.structured.techniques, ["T1059.001"]); // deprecated T1999 dropped
    assert.deepEqual(g.structured.software.sort(), ["S0552", "S0559"]); // SUNBURST inherited via campaign
    assert.deepEqual(g.structured.campaigns, ["C0024"]);
  }
  assert.match(g.extractedText, /APT29 is a threat group\./);
  assert.doesNotMatch(g.extractedText, /Citation/);
  assert.equal(g.extractedEntities?.techniques[0].name, "Command and Scripting Interpreter: PowerShell");

  const s = r.docs.find((d) => d.id === "att_S0559")!;
  assert.deepEqual(s.docTypes, ["MITRE_SOFTWARE"]);
  if (s.structured?.kind === "attack_software") {
    assert.equal(s.structured.softwareType, "malware");
    assert.deepEqual(s.structured.aliases, ["Solorigate"]);
    assert.deepEqual(s.structured.groups, ["G0016"]);
    assert.deepEqual(s.structured.techniques, ["T1059"]);
  } else assert.fail("software structured payload missing");

  const c = r.docs.find((d) => d.id === "att_C0024")!;
  assert.deepEqual(c.docTypes, ["MITRE_CAMPAIGN", "CAMPAIGN_REPORT"]);
  if (c.structured?.kind === "attack_campaign") {
    assert.deepEqual(c.structured.groups, ["G0016"]);
    assert.deepEqual(c.structured.software, ["S0559"]);
    assert.equal(c.structured.firstSeen, "2019-08-01T00:00:00Z");
  } else assert.fail("campaign structured payload missing");
  assert.ok(!r.docs.some((d) => d.id === "att_G9999"), "revoked group skipped");
});

test("empty bundle is an error", () => {
  assert.throws(() => parseAttackStixBundle({ objects: [] }, SOURCE), /no objects/);
});
