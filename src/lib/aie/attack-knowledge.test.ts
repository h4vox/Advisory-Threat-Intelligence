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
