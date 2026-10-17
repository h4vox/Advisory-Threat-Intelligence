/**
 * Search documents for the bundled ATT&CK knowledge (groups, software,
 * campaigns, techniques). Always available offline. Built once per process.
 *
 * Server-only (imports the ATT&CK snapshot).
 */
import {
  ATTACK_VERSION,
  attackCampaigns,
  attackGroups,
  attackSoftware,
  attackTechniques,
  getCampaign,
  getGroup,
  getSoftware,
  getTechnique,
} from "../attack-knowledge.ts";
import { prepareDoc, type DocEntity, type PreparedDoc, type SearchDoc } from "./rank.ts";

const PUBLISHER = "MITRE ATT&CK";

function firstSentences(text: string, max = 420): string {
  const t = String(text ?? "").replace(/\s+/g, " ").trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const dot = cut.lastIndexOf(". ");
  return `${dot > 120 ? cut.slice(0, dot + 1) : cut.trimEnd()}…`;
}

function tacticsFor(techIds: string[]): string[] {
  const set = new Set<string>();
  for (const id of techIds) for (const t of getTechnique(id)?.tactics ?? []) set.add(t);
  return [...set];
}

function self(kind: DocEntity["kind"], id: string, name: string): DocEntity {
  return { kind, id, name, via: name, count: 10, rel: "self" };
}

function uses(kind: DocEntity["kind"], id: string, name: string | undefined): DocEntity | null {
  return name ? { kind, id, name, via: name, count: 0, rel: "uses" } : null;
}

export function buildKnowledgeDocs(): SearchDoc[] {
  const docs: SearchDoc[] = [];
  const groupsBySoftware = new Map<string, string[]>();
  for (const g of attackGroups()) for (const s of g.software) groupsBySoftware.set(s, [...(groupsBySoftware.get(s) ?? []), g.id]);
  const campaignsByGroup = new Map<string, string[]>();
  for (const c of attackCampaigns()) for (const g of c.groups) campaignsByGroup.set(g, [...(campaignsByGroup.get(g) ?? []), c.id]);

  for (const g of attackGroups()) {
    const entities = [
      self("group", g.id, g.name),
      ...g.software.map((s) => uses("software", s, getSoftware(s)?.name)),
      ...(campaignsByGroup.get(g.id) ?? []).map((c) => uses("campaign", c, getCampaign(c)?.name)),
    ].filter(Boolean) as DocEntity[];
    docs.push({
      id: g.id,
      kind: "group",
      title: g.name,
      summary: firstSentences(g.description),
      body: g.description,
      aliases: [g.name, ...g.aliases, g.id],
      entities,
      techniques: g.techniques,
      techniqueRel: "uses",
      tactics: tacticsFor(g.techniques),
      cves: [],
      docTypes: ["MITRE_GROUP"],
      tier: 1,
      confidence: 1,
      publisher: PUBLISHER,
      url: `https://attack.mitre.org/groups/${g.id}/`,
      meta: { attackId: g.id, aliases: g.aliases, techniqueCount: g.techniques.length, softwareCount: g.software.length },
    });
  }
  for (const s of attackSoftware()) {
    const entities = [
      self("software", s.id, s.name),
      ...(groupsBySoftware.get(s.id) ?? []).map((g) => uses("group", g, getGroup(g)?.name)),
    ].filter(Boolean) as DocEntity[];
    docs.push({
      id: s.id,
      kind: "software",
      title: s.name,
      summary: firstSentences(s.description),
      body: s.description,
      aliases: [s.name, ...s.aliases, s.id],
      entities,
      techniques: s.techniques,
      techniqueRel: "uses",
      tactics: tacticsFor(s.techniques),
      cves: [],
      docTypes: ["MITRE_SOFTWARE"],
      tier: 1,
      confidence: 1,
      publisher: PUBLISHER,
      url: `https://attack.mitre.org/software/${s.id}/`,
      meta: { attackId: s.id, softwareType: s.type, platforms: s.platforms, techniqueCount: s.techniques.length, groups: groupsBySoftware.get(s.id) ?? [] },
    });
  }
  for (const c of attackCampaigns()) {
    const entities = [
      self("campaign", c.id, c.name),
      ...c.groups.map((g) => uses("group", g, getGroup(g)?.name)),
      ...c.software.map((s) => uses("software", s, getSoftware(s)?.name)),
    ].filter(Boolean) as DocEntity[];
    docs.push({
      id: c.id,
      kind: "campaign",
      title: c.name,
      summary: firstSentences(c.description),
      body: c.description,
      aliases: [c.name, ...c.aliases, c.id],
      entities,
      techniques: c.techniques,
      techniqueRel: "uses",
      tactics: tacticsFor(c.techniques),
      cves: [...new Set((c.description.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((x) => x.toUpperCase()))],
      docTypes: ["MITRE_CAMPAIGN"],
      tier: 1,
      confidence: 1,
      publisher: PUBLISHER,
      activeFrom: c.firstSeen,
      activeTo: c.lastSeen,
      url: `https://attack.mitre.org/campaigns/${c.id}/`,
      meta: { attackId: c.id, groups: c.groups, firstSeen: c.firstSeen, lastSeen: c.lastSeen, techniqueCount: c.techniques.length },
    });
  }
  for (const t of attackTechniques()) {
    const sub = t.name.includes(": ") ? t.name.split(": ").slice(1).join(": ") : null;
    const body = [
      `${t.id} ${t.name}.`,
      t.tactics.length ? `Tactics: ${t.tactics.join(", ")}.` : "",
      t.platforms.length ? `Platforms: ${t.platforms.join(", ")}.` : "",
      t.dataSources.length ? `Data components: ${t.dataSources.join(", ")}.` : "",
    ]
      .filter(Boolean)
      .join(" ");
    docs.push({
      id: t.id,
      kind: "technique",
      title: t.name,
      summary: [t.tactics.join(" · "), t.platforms.join(", ")].filter(Boolean).join(" — "),
      body,
      aliases: [t.id, ...(sub ? [sub] : [])],
      entities: [],
      techniques: [t.id],
      techniqueRel: "self",
      tactics: t.tactics,
      cves: [],
      docTypes: ["MITRE_TECHNIQUE"],
      tier: 1,
      confidence: 1,
      publisher: PUBLISHER,
      url: `https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`,
      meta: { attackId: t.id, isSubtechnique: t.isSubtechnique, platforms: t.platforms, dataSources: t.dataSources },
    });
  }
  return docs;
}

let cache: PreparedDoc[] | null = null;

/** Prepared (tokenized) knowledge documents, built once. */
export function knowledgeCorpus(): PreparedDoc[] {
  cache ??= buildKnowledgeDocs().map(prepareDoc);
  return cache;
}

export function knowledgeCounts() {
  return {
    version: ATTACK_VERSION,
    groups: attackGroups().length,
    software: attackSoftware().length,
    campaigns: attackCampaigns().length,
    techniques: attackTechniques().length,
  };
}
