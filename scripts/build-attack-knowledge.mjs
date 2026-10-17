#!/usr/bin/env node
/**
 * Builds src/lib/aie/data/attack-knowledge.json: a compact, offline snapshot of MITRE ATT&CK
 * Enterprise (techniques, groups, software, campaigns with aliases and "uses" links).
 * It powers entity resolution (aliases → canonical names), actor profiles and purple paths
 * without needing MongoDB or network access at runtime.
 *
 *   node --experimental-strip-types scripts/build-attack-knowledge.mjs [path-or-url-to-enterprise-attack.json]
 *
 * ATT&CK® content © The MITRE Corporation, used under the ATT&CK Terms of Use.
 */
import { readFile, writeFile } from "node:fs/promises";
import { buildAttackTechniqueIndex } from "../src/lib/aie/connectors/attack-stix.ts";

const SRC =
  process.argv[2] ?? "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
const OUT = new URL("../src/lib/aie/data/attack-knowledge.json", import.meta.url);

const raw = SRC.startsWith("http") ? await (await fetch(SRC)).text() : await readFile(SRC, "utf8");
const bundle = JSON.parse(raw);
const objects = bundle.objects ?? [];
const active = (o) => !o.revoked && !o.x_mitre_deprecated;
const attackId = (o) => o.external_references?.find((r) => r.source_name === "mitre-attack" && r.external_id)?.external_id;
const byId = new Map(objects.map((o) => [o.id, o]));
const shortDesc = (s = "") =>
  s
    .replace(/\(Citation:[^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/<[^>]+>/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 280);

const uses = new Map(); // stix id -> {techniques:Set, software:Set}
const attributed = new Map(); // campaign stix id -> Set(group stix id)
for (const r of objects) {
  if (r.type !== "relationship" || r.revoked || r.x_mitre_deprecated) continue;
  const src = byId.get(r.source_ref);
  const dst = byId.get(r.target_ref);
  if (!src || !dst || !active(src) || !active(dst)) continue;
  if (r.relationship_type === "uses") {
    const u = uses.get(src.id) ?? { techniques: new Set(), software: new Set() };
    if (dst.type === "attack-pattern") {
      const id = attackId(dst);
      if (id) u.techniques.add(id);
    } else if (dst.type === "malware" || dst.type === "tool") {
      const id = attackId(dst);
      if (id) u.software.add(id);
    }
    uses.set(src.id, u);
  } else if (r.relationship_type === "attributed-to" && src.type === "campaign" && dst.type === "intrusion-set") {
    const s = attributed.get(src.id) ?? new Set();
    const gid = attackId(dst);
    if (gid) s.add(gid);
    attributed.set(src.id, s);
  }
}
const sortIds = (s) => [...(s ?? [])].sort((a, b) => a.localeCompare(b, "en", { numeric: true }));
const aliasesOf = (o) => [...new Set([...(o.aliases ?? []), ...(o.x_mitre_aliases ?? [])].filter((a) => a && a !== o.name))];

const groups = [];
const software = [];
const campaigns = [];
for (const o of objects) {
  if (!active(o)) continue;
  const id = attackId(o);
  if (!id || !o.name) continue;
  const u = uses.get(o.id);
  if (o.type === "intrusion-set") {
    groups.push({ id, name: o.name, aliases: aliasesOf(o), description: shortDesc(o.description), techniques: sortIds(u?.techniques), software: sortIds(u?.software) });
  } else if (o.type === "malware" || o.type === "tool") {
    software.push({ id, name: o.name, type: o.type, aliases: aliasesOf(o), platforms: o.x_mitre_platforms ?? [], description: shortDesc(o.description), techniques: sortIds(u?.techniques) });
  } else if (o.type === "campaign") {
    campaigns.push({
      id,
      name: o.name,
      aliases: aliasesOf(o),
      description: shortDesc(o.description),
      firstSeen: o.first_seen?.slice(0, 10),
      lastSeen: o.last_seen?.slice(0, 10),
      groups: sortIds(attributed.get(o.id)),
      techniques: sortIds(u?.techniques),
      software: sortIds(u?.software),
    });
  }
}
const byAttack = (a, b) => a.id.localeCompare(b.id, "en", { numeric: true });
const techniques = buildAttackTechniqueIndex(bundle).map(({ description, url, ...t }) => t);
const collection = objects.find((o) => o.type === "x-mitre-collection");
const out = {
  attackVersion: collection?.x_mitre_version ?? null,
  generatedAt: new Date().toISOString().slice(0, 10),
  source: SRC.startsWith("http") ? SRC : "local file",
  techniques,
  groups: groups.sort(byAttack),
  software: software.sort(byAttack),
  campaigns: campaigns.sort(byAttack),
};
await writeFile(OUT, JSON.stringify(out));
console.log(
  `ATT&CK ${out.attackVersion}: ${techniques.length} techniques, ${groups.length} groups, ${software.length} software, ${campaigns.length} campaigns → ${OUT.pathname}`,
);
