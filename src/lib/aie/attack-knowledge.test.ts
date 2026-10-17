import { test } from "node:test";
import assert from "node:assert/strict";
import { aliasesFor, findEntitiesInText, getTechnique, resolveEntity, tacticRank } from "./attack-knowledge.ts";

test("resolves group aliases to the canonical ATT&CK group", () => {
  assert.equal(resolveEntity("Cozy Bear")[0]?.id, "G0016");
  assert.equal(resolveEntity("nobelium")[0]?.name, "APT29");
  assert.equal(resolveEntity("UNC3944")[0]?.name, "Scattered Spider");
  assert.deepEqual(resolveEntity("definitely not an actor"), []);
});

test("resolves ATT&CK IDs", () => {
  assert.equal(resolveEntity("t1059.001")[0]?.kind, "technique");
  assert.equal(resolveEntity("S0154")[0]?.name, "Cobalt Strike");
  assert.ok(getTechnique("T1003.001")?.tactics.includes("Credential Access"));
});

test("finds entities in prose and skips generic words", () => {
  const hits = findEntitiesInText("Octo Tempest used Cobalt Strike. A storm of alerts followed; the gold standard held.");
  const ids = hits.map((h) => h.id);
  assert.ok(ids.includes("G1015"), "Octo Tempest → Scattered Spider");
  assert.ok(ids.includes("S0154"));
  assert.ok(!hits.some((h) => /^(storm|gold)$/i.test(h.matched)));
});

test("single-word aliases must be capitalised in prose", () => {
  assert.ok(findEntitiesInText("Emotet returned").some((h) => h.id === "S0367"));
  assert.ok(!findEntitiesInText("we saw emotet-like spam").some((h) => h.id === "S0367"));
});

test("aliases and tactic order", () => {
  assert.ok(aliasesFor("group", "G0016").includes("NOBELIUM"));
  assert.ok(tacticRank("Initial Access") < tacticRank("Impact"));
});

test("technique prevalence counts groups, with sub-techniques rolling up to the parent", async () => {
  const { techniquePrevalence } = await import("./attack-knowledge.ts");
  const parent = techniquePrevalence("T1059");
  const sub = techniquePrevalence("T1059.001");
  assert.ok(parent.groups >= sub.groups && sub.groups > 10);
  assert.ok(parent.share > 0 && parent.share <= 1);
  assert.equal(techniquePrevalence("T9999").groups, 0);
});

test("ATT&CK mitigations: real M-IDs linked to techniques, ranked by coverage", async () => {
  const { getMitigation, getTechnique, mitigationsForTechniques } = await import("./attack-knowledge.ts");
  assert.equal(getMitigation("M1043")?.name, "Credential Access Protection");
  assert.ok(getTechnique("T1003.001")?.mitigations?.includes("M1043"));
  const ranked = mitigationsForTechniques(["T1003.001", "T1003.003", "T1021.001"]);
  assert.ok(ranked.length > 0);
  assert.ok(ranked[0].techniques.length >= ranked[ranked.length - 1].techniques.length);
  assert.ok(ranked.every((m) => /^M\d{4}$/.test(m.id) && m.name));
  assert.deepEqual(mitigationsForTechniques(["T9999"]), []);
});
