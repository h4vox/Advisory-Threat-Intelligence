/**
 * MITRE ATT&CK Enterprise STIX 2.1 bundle → MITRE_GROUP / MITRE_SOFTWARE /
 * MITRE_CAMPAIGN documents and a technique index.
 *
 * Relationships used:
 *   intrusion-set | malware | tool | campaign  --uses-->  attack-pattern   (techniques)
 *   intrusion-set | campaign                    --uses-->  malware | tool   (software)
 *   campaign                                    --attributed-to--> intrusion-set
 *   x-mitre-detection-strategy --detects--> attack-pattern (ATT&CK v18 data components)
 * Revoked and deprecated objects are skipped.
 */
import type { ReportRecord } from "../types.ts";
import {
  buildStructuredReport,
  cleanAttackText,
  uniq,
  type AttackTechniqueIndexEntry,
  type ConnectorResult,
  type ConnectorSource,
  type TechniqueLookup,
} from "./common.ts";

type StixObject = {
  type: string;
  id: string;
  name?: string;
  description?: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  aliases?: string[];
  x_mitre_aliases?: string[];
  x_mitre_platforms?: string[];
  x_mitre_is_subtechnique?: boolean;
  x_mitre_data_sources?: string[];
  x_mitre_analytic_refs?: string[];
  x_mitre_log_source_references?: Array<{ x_mitre_data_component_ref?: string }>;
  x_mitre_shortname?: string;
  kill_chain_phases?: Array<{ kill_chain_name: string; phase_name: string }>;
  external_references?: Array<{ source_name?: string; external_id?: string; url?: string }>;
  first_seen?: string;
  last_seen?: string;
  created?: string;
  modified?: string;
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
};

export type StixBundle = { type?: string; objects?: StixObject[] };

function attackRef(o: StixObject): { id: string; url: string } | null {
  const ref = o.external_references?.find((r) => r.source_name === "mitre-attack" && r.external_id);
  if (!ref?.external_id) return null;
  return { id: ref.external_id, url: ref.url ?? "" };
}

function active(o: StixObject): boolean {
  return !o.revoked && !o.x_mitre_deprecated;
}

const TACTIC_LABEL: Record<string, string> = {
  reconnaissance: "Reconnaissance",
  "resource-development": "Resource Development",
  "initial-access": "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion",
  stealth: "Stealth",
  "defense-impairment": "Defense Impairment",
  "credential-access": "Credential Access",
  discovery: "Discovery",
  "lateral-movement": "Lateral Movement",
  collection: "Collection",
  "command-and-control": "Command and Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

function tacticName(phase: string, tacticNames: Map<string, string>): string {
  return tacticNames.get(phase) ?? TACTIC_LABEL[phase] ?? phase.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Technique index (id → name, tactics, platforms, data sources) from a bundle.
 * Sub-technique names are prefixed with the parent ("Command and Scripting Interpreter: PowerShell").
 */
export function buildAttackTechniqueIndex(bundle: StixBundle): AttackTechniqueIndexEntry[] {
  const objects = bundle.objects ?? [];
  const byStixId = new Map<string, StixObject>();
  const tacticNames = new Map<string, string>();
  for (const o of objects) {
    byStixId.set(o.id, o);
    if (o.type === "x-mitre-tactic" && o.x_mitre_shortname && o.name) tacticNames.set(o.x_mitre_shortname, o.name);
  }

  // v18+: technique ← detects ← detection strategy → analytics → data components
  const dataComponentsByTech = new Map<string, Set<string>>();
  for (const r of objects) {
    if (r.type !== "relationship" || r.relationship_type !== "detects" || !r.source_ref || !r.target_ref) continue;
    const strategy = byStixId.get(r.source_ref);
    if (!strategy || !active(strategy)) continue;
    const set = dataComponentsByTech.get(r.target_ref) ?? new Set<string>();
    for (const aRef of strategy.x_mitre_analytic_refs ?? []) {
      const analytic = byStixId.get(aRef);
      for (const ls of analytic?.x_mitre_log_source_references ?? []) {
        const dc = ls.x_mitre_data_component_ref ? byStixId.get(ls.x_mitre_data_component_ref) : undefined;
        if (dc?.name) set.add(dc.name);
      }
    }
    dataComponentsByTech.set(r.target_ref, set);
  }

  const parents = new Map<string, string>();
  for (const o of objects) {
    if (o.type !== "attack-pattern" || !active(o) || o.x_mitre_is_subtechnique) continue;
    const ref = attackRef(o);
    if (ref && o.name) parents.set(ref.id, o.name);
  }

  const out: AttackTechniqueIndexEntry[] = [];
  for (const o of objects) {
    if (o.type !== "attack-pattern" || !active(o)) continue;
    const ref = attackRef(o);
    if (!ref || !o.name) continue;
    const isSub = Boolean(o.x_mitre_is_subtechnique) || ref.id.includes(".");
    const parentName = isSub ? parents.get(ref.id.split(".")[0]) : undefined;
    const tactics = uniq(
      (o.kill_chain_phases ?? [])
        .filter((p) => p.kill_chain_name === "mitre-attack")
        .map((p) => tacticName(p.phase_name, tacticNames)),
    );
    out.push({
      id: ref.id,
      name: parentName ? `${parentName}: ${o.name}` : o.name,
      tactics,
      platforms: o.x_mitre_platforms ?? [],
      dataSources: uniq([...(o.x_mitre_data_sources ?? []), ...(dataComponentsByTech.get(o.id) ?? [])]).sort(),
      isSubtechnique: isSub,
      url: ref.url || `https://attack.mitre.org/techniques/${ref.id.replace(".", "/")}/`,
      description: cleanAttackText(o.description).slice(0, 600),
    });
  }
  out.sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true }));
  return out;
}

/** Lookup function over a technique index (for naming techniques in other connectors). */
export function techniqueLookupFrom(index: AttackTechniqueIndexEntry[]): TechniqueLookup {
  const map = new Map(index.map((t) => [t.id, t]));
  return (id: string) => {
    const t = map.get(id.toUpperCase());
    return t ? { id: t.id, name: t.name, tactic: t.tactics[0] } : null;
  };
}

type Uses = { techniques: Set<string>; software: Set<string>; groups: Set<string>; campaigns: Set<string> };

/** Parses the bundle into ATT&CK group / software / campaign documents. */
export function parseAttackStixBundle(bundle: StixBundle, source: ConnectorSource, opts?: { now?: string }): ConnectorResult {
  const objects = bundle.objects ?? [];
  if (!Array.isArray(objects) || objects.length === 0) {
    throw new Error("STIX bundle has no objects");
  }
  const techniques = buildAttackTechniqueIndex(bundle);
  const lookup = techniqueLookupFrom(techniques);
  const byStixId = new Map<string, StixObject>();
  for (const o of objects) byStixId.set(o.id, o);

  const uses = new Map<string, Uses>();
  const get = (id: string): Uses => {
    let u = uses.get(id);
    if (!u) {
      u = { techniques: new Set(), software: new Set(), groups: new Set(), campaigns: new Set() };
      uses.set(id, u);
    }
    return u;
  };

  for (const r of objects) {
    if (r.type !== "relationship" || !r.source_ref || !r.target_ref) continue;
    const src = byStixId.get(r.source_ref);
    const tgt = byStixId.get(r.target_ref);
    if (!src || !tgt || !active(src) || !active(tgt) || r.revoked || r.x_mitre_deprecated) continue;
    if (r.relationship_type === "uses") {
      if (tgt.type === "attack-pattern") {
        const ref = attackRef(tgt);
        if (ref) get(src.id).techniques.add(ref.id);
      } else if (tgt.type === "malware" || tgt.type === "tool") {
        get(src.id).software.add(tgt.id);
        if (src.type === "intrusion-set") get(tgt.id).groups.add(src.id);
        if (src.type === "campaign") get(tgt.id).campaigns.add(src.id);
      }
    } else if (r.relationship_type === "attributed-to" && src.type === "campaign" && tgt.type === "intrusion-set") {
      get(src.id).groups.add(tgt.id);
      get(tgt.id).campaigns.add(src.id);
    }
  }

  // Groups inherit software used in their attributed campaigns; software inherits groups via campaigns.
  for (const o of objects) {
    if (o.type !== "campaign") continue;
    const cu = uses.get(o.id);
    if (!cu) continue;
    for (const g of cu.groups) {
      for (const s of cu.software) {
        get(g).software.add(s);
        get(s).groups.add(g);
      }
    }
  }

  const nameOf = (stixId: string) => byStixId.get(stixId)?.name ?? "";
  const attackIdOf = (stixId: string) => {
    const o = byStixId.get(stixId);
    return o ? attackRef(o)?.id ?? "" : "";
  };
  const labelList = (ids: Iterable<string>) =>
    Array.from(ids)
      .map((id) => ({ name: nameOf(id), attackId: attackIdOf(id) }))
      .filter((x) => x.name)
      .sort((a, b) => a.name.localeCompare(b.name));
  const sortTech = (ids: Iterable<string>) => Array.from(ids).sort((a, b) => a.localeCompare(b, "en", { numeric: true }));

  const techLines = (ids: string[]) =>
    ids.map((id) => {
      const t = lookup(id);
      return `- ${id}${t ? ` ${t.name}${t.tactic ? ` (${t.tactic})` : ""}` : ""}`;
    });

  const docs: ReportRecord[] = [];
  const stats = { groups: 0, software: 0, campaigns: 0, techniques: techniques.length, relationships: 0 };
  stats.relationships = objects.filter((o) => o.type === "relationship" && o.relationship_type === "uses").length;

  for (const o of objects) {
    if (!active(o) || !o.name) continue;
    if (o.type !== "intrusion-set" && o.type !== "malware" && o.type !== "tool" && o.type !== "campaign") continue;
    const ref = attackRef(o);
    if (!ref) continue;
    const u = uses.get(o.id) ?? { techniques: new Set<string>(), software: new Set<string>(), groups: new Set<string>(), campaigns: new Set<string>() };
    const techIds = sortTech(u.techniques);
    const description = cleanAttackText(o.description);
    const software = labelList(u.software);
    const groups = labelList(u.groups);
    const campaigns = labelList(u.campaigns);
    const url = ref.url || `https://attack.mitre.org/`;

    if (o.type === "intrusion-set") {
      const aliases = (o.aliases ?? []).filter((a) => a !== o.name);
      const text = [
        `${o.name} (${ref.id}) — MITRE ATT&CK group.`,
        aliases.length ? `Associated groups: ${aliases.join(", ")}.` : "",
        description,
        software.length ? `\nSoftware used:\n${software.map((s) => `- ${s.name} (${s.attackId})`).join("\n")}` : "",
        campaigns.length ? `\nCampaigns:\n${campaigns.map((c) => `- ${c.name} (${c.attackId})`).join("\n")}` : "",
        techIds.length ? `\nTechniques used (${techIds.length}):\n${techLines(techIds).join("\n")}` : "",
      ]
        .filter(Boolean)
        .join("\n");
      stats.groups++;
      docs.push(
        buildStructuredReport({
          id: `att_${ref.id}`,
          source,
          docTypes: ["MITRE_GROUP"],
          title: `${o.name} (${ref.id})`,
          url,
          text,
          publishedAt: o.modified ?? o.created ?? null,
          techniques: techIds,
          actors: [o.name, ...aliases],
          malware: software.map((s) => s.name),
          structured: {
            kind: "attack_group",
            attackId: ref.id,
            aliases,
            techniques: techIds,
            software: software.map((s) => s.attackId).filter(Boolean),
            campaigns: campaigns.map((c) => c.attackId).filter(Boolean),
          },
          tags: [`actor:${o.name}`, ...aliases.slice(0, 8).map((a) => `actor:${a}`), "source:mitre-attack"],
          lookup,
          now: opts?.now,
          publisher: "MITRE ATT&CK",
          author: "MITRE ATT&CK",
        }),
      );
    } else if (o.type === "malware" || o.type === "tool") {
      const aliases = (o.x_mitre_aliases ?? o.aliases ?? []).filter((a) => a !== o.name);
      const kind = o.type === "malware" ? "malware" : "tool";
      const text = [
        `${o.name} (${ref.id}) — MITRE ATT&CK ${kind}.`,
        aliases.length ? `Aliases: ${aliases.join(", ")}.` : "",
        o.x_mitre_platforms?.length ? `Platforms: ${o.x_mitre_platforms.join(", ")}.` : "",
        description,
        groups.length ? `\nUsed by groups:\n${groups.map((g) => `- ${g.name} (${g.attackId})`).join("\n")}` : "",
        campaigns.length ? `\nSeen in campaigns:\n${campaigns.map((c) => `- ${c.name} (${c.attackId})`).join("\n")}` : "",
        techIds.length ? `\nTechniques (${techIds.length}):\n${techLines(techIds).join("\n")}` : "",
      ]
        .filter(Boolean)
        .join("\n");
      stats.software++;
      docs.push(
        buildStructuredReport({
          id: `att_${ref.id}`,
          source,
          docTypes: ["MITRE_SOFTWARE"],
          title: `${o.name} (${ref.id})`,
          url,
          text,
          publishedAt: o.modified ?? o.created ?? null,
          techniques: techIds,
          actors: groups.map((g) => g.name),
          malware: [o.name, ...aliases],
          structured: {
            kind: "attack_software",
            attackId: ref.id,
            softwareType: kind,
            aliases,
            platforms: o.x_mitre_platforms ?? [],
            techniques: techIds,
            groups: groups.map((g) => g.attackId).filter(Boolean),
          },
          tags: [`malware:${o.name}`, "source:mitre-attack"],
          lookup,
          now: opts?.now,
          publisher: "MITRE ATT&CK",
          author: "MITRE ATT&CK",
        }),
      );
    } else {
      const aliases = (o.aliases ?? []).filter((a) => a !== o.name);
      const text = [
        `${o.name} (${ref.id}) — MITRE ATT&CK campaign.`,
        o.first_seen || o.last_seen ? `Active: ${o.first_seen?.slice(0, 10) ?? "?"} → ${o.last_seen?.slice(0, 10) ?? "?"}.` : "",
        groups.length ? `Attributed to: ${groups.map((g) => `${g.name} (${g.attackId})`).join(", ")}.` : "",
        description,
        software.length ? `\nSoftware used:\n${software.map((s) => `- ${s.name} (${s.attackId})`).join("\n")}` : "",
        techIds.length ? `\nTechniques used (${techIds.length}):\n${techLines(techIds).join("\n")}` : "",
      ]
        .filter(Boolean)
        .join("\n");
      stats.campaigns++;
      docs.push(
        buildStructuredReport({
          id: `att_${ref.id}`,
          source,
          docTypes: ["MITRE_CAMPAIGN", "CAMPAIGN_REPORT"],
          title: `${o.name} (${ref.id})`,
          url,
          text,
          publishedAt: o.last_seen ?? o.modified ?? null,
          techniques: techIds,
          actors: groups.map((g) => g.name),
          malware: software.map((s) => s.name),
          campaign: o.name,
          structured: {
            kind: "attack_campaign",
            attackId: ref.id,
            aliases,
            firstSeen: o.first_seen,
            lastSeen: o.last_seen,
            techniques: techIds,
            groups: groups.map((g) => g.attackId).filter(Boolean),
            software: software.map((s) => s.attackId).filter(Boolean),
          },
          tags: [`campaign:${o.name}`, ...groups.map((g) => `actor:${g.name}`), "source:mitre-attack"],
          lookup,
          now: opts?.now,
          publisher: "MITRE ATT&CK",
          author: "MITRE ATT&CK",
        }),
      );
    }
  }

  return { docs, emulation: [], techniques, stats, warnings: [] };
}
