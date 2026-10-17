/**
 * Purple path exports: Markdown, JSON and a CALDERA-style adversary profile (YAML).
 * Pure and client-safe. Every export carries the planning-only disclaimer.
 */
import type { PurplePath } from "./types.ts";

export function pathTitle(p: PurplePath): string {
  return `Purple path: ${p.source.name}`;
}

export function exportFileBase(p: PurplePath): string {
  return `purple_path_${p.source.name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 40) || "plan"}`;
}

export function toMarkdown(p: PurplePath): string {
  const L: string[] = [];
  L.push(`# ${pathTitle(p)}`, "");
  L.push(`> ${p.disclaimer}`, "");
  L.push(`- Source: ${p.source.kind} ${p.source.id} (${p.source.name})`);
  L.push(`- Generated: ${p.generatedAt}`);
  L.push(`- Order: ${p.orderNote}`);
  L.push(`- Steps: ${p.steps.length} of ${p.candidateCount} candidate techniques; ${p.phases.length} phases`);
  L.push(`- Emulation library: ${p.emulationSynced ? "synced" : "not synced"}`);
  L.push(`- Detection coverage: ${p.steps[0]?.detection.note ?? "Unknown; connect a detection repository"}`, "");
  L.push("## Path", "");
  for (const s of p.steps) L.push(`${s.order}. ${s.phase}: ${s.technique.id} ${s.technique.name} (priority ${s.priority}, ${s.score.toFixed(2)}; risk ${s.simulation.risk.level})`);
  L.push("");
  for (const s of p.steps) {
    const sim = s.simulation;
    L.push(`## ${sim.simulationId} · ${sim.ttp.id} ${sim.ttp.name}`, "");
    L.push(`**Scenario:** ${sim.scenario}  `);
    L.push(`**Objective:** ${sim.objective}  `);
    L.push(`**Tactic:** ${sim.ttp.tactic}  `);
    L.push(`**Priority:** ${s.priority} (${s.score.toFixed(2)}). ${s.reasonText}  `);
    L.push(`**Risk:** ${sim.risk.level}. ${sim.risk.reason}  `);
    L.push(`**Target platforms:** ${sim.targetPlatforms.join(", ") || "Not specified"}  `);
    L.push(`**Execution method:** ${sim.execution.summary}`);
    for (const o of sim.execution.options) L.push(`  - ${o.kind}: ${o.name}${o.ref ? ` (${o.ref})` : ""}${o.sourceUrl ? ` <${o.sourceUrl}>` : ""}`);
    L.push("", "**Prerequisites**", ...sim.prerequisites.map((x) => `- ${x}`));
    L.push("", "**Required telemetry (ATT&CK data components)**", ...(sim.requiredTelemetry.length ? sim.requiredTelemetry.map((x) => `- ${x}`) : ["- None listed in ATT&CK"]));
    L.push("", `**Expected behaviour:** ${sim.expectedBehaviour}`);
    L.push(`**Expected detection:** ${sim.expectedDetection}`);
    L.push(`**Detection coverage:** ${s.detection.note}`);
    L.push("", "**Success criteria**", ...sim.successCriteria.map((x) => `- ${x}`));
    L.push("", "**Cleanup**", ...sim.cleanup.map((x) => `- ${x}`));
    L.push("", "**Hunting hypotheses**");
    for (const h of s.hunts) {
      L.push(`- ${h.huntId}: ${h.hypothesis}`, "", "```sql", h.query.text, "```");
    }
    const refs = sim.sourceRefs;
    if (refs.length) {
      L.push("", "**Sources**");
      for (const r of refs) {
        if (r.kind === "report") {
          L.push(`- Report ${r.reportId}: ${r.title} (${r.label}${r.publishedAt ? `, ${r.publishedAt.slice(0, 10)}` : ""})`);
          for (const q of r.quotes) L.push(`  > ${q}`);
        } else if (r.kind === "attack") L.push(`- ${r.note} <${r.url}>`);
        else L.push(`- ${r.note}`);
      }
    }
    L.push("");
  }
  if (p.excluded.length) {
    L.push("## Left out", "");
    for (const x of p.excluded) L.push(`- ${x.id} ${x.name}: ${x.reason}`);
    L.push("");
  }
  return L.join("\n");
}

export function toJson(p: PurplePath): string {
  return JSON.stringify({ kind: "aie.purple_path", status: "planning_only", ...p }, null, 2);
}

function yq(s: string): string {
  return JSON.stringify(s);
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * CALDERA-style adversary profile. Abilities are referenced only when a synced CALDERA ability
 * (or an Atomic test GUID, which CALDERA's atomic plugin uses as the ability id) exists; otherwise
 * a placeholder names the technique so nothing importable is invented.
 */
export function toCalderaYaml(p: PurplePath): string {
  const L: string[] = [
    "# AIE purple path: CALDERA-style adversary profile.",
    "# PLANNING ARTEFACT ONLY. AIE never executes procedures and did not validate any ability.",
    "# Review every entry; import only into an authorised, isolated lab.",
    p.emulationSynced
      ? "# Ability ids come from synced emulation libraries; placeholders mark techniques with none."
      : "# No emulation library was synced: every entry is a technique placeholder, not an ability id.",
    `id: ${yq(p.id)}`,
    `name: ${yq(pathTitle(p))}`,
    `description: ${yq(`${p.steps.length} steps generated from ${p.source.kind} ${p.source.id}. ${p.orderNote}.`)}`,
    "objective: ''",
    "tags:",
    "  - aie",
    "  - planning-only",
    "atomic_ordering:",
  ];
  let real = 0;
  for (const s of p.steps) {
    const ability = s.simulation.execution.options.find((o) => o.kind === "caldera_ability" || (o.kind === "atomic_test" && GUID.test(o.ref)));
    const comment = `${s.simulation.simulationId} ${s.technique.id} ${s.technique.name} [${s.phase}]`;
    if (ability) {
      real++;
      L.push(`  - ${yq(ability.ref)}  # ${comment}`);
    } else {
      L.push(`  - ${yq(`PLACEHOLDER-${s.technique.id}`)}  # ${comment}: no synced ability`);
    }
  }
  L.push(`# ${real} of ${p.steps.length} entries reference a synced ability.`);
  return L.join("\n") + "\n";
}
