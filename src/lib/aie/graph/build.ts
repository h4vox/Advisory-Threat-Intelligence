/**
 * Builds the intelligence graph (./types) from library reports. Pure; unit-tested.
 *
 * Per report:
 *   1. Entities: actors, campaigns, malware / tools, techniques, CVEs, targeting and indicators,
 *      from the evidence-backed analysis first (only facts labelled observed or inferred), then
 *      the older analysis lists, extracted entities and the grounded AI analysis. ATT&CK names and
 *      aliases resolve to one node per group / software / campaign / technique.
 *   2. Stated links: evidence.relationships (both entities in one sentence) with their quote.
 *   3. Co-reported links: the report's "agents" (actors and campaigns, else its malware) linked to
 *      its techniques, tools, CVEs and targets; malware to techniques; indicators to the malware
 *      (else the actor) they were reported with.
 * Across reports, edges add up: weight = reports, confidence = 1 − Π(1 − cᵢ).
 */
import { getGroup, getSoftware, getTechnique, isGenericEntityName, normalizeEntityName, resolveEntity } from "../attack-knowledge.ts";
import type { EvidenceLabel, ExtractedEntities, IntelAnalysis, IocHit, RelationshipFact } from "../types.ts";
import type { ReportAiAnalysis } from "../report-ai-analysis.ts";
import type { GraphEdge, GraphNode, GraphNodeType, GraphPredicate, GraphReportRef, IntelGraph } from "./types.ts";
import { edgeStrength } from "./analyze.ts";

export type GraphSourceReport = {
  id: string;
  title: string;
  publisher?: string;
  sourceName?: string;
  publishedAt?: string | null;
  ingestedAt?: string;
  status?: string;
  discoveryMethod?: string;
  iocs?: IocHit[];
  analysis?: IntelAnalysis | null;
  extractedEntities?: ExtractedEntities;
  aiAnalysis?: ReportAiAnalysis;
};

const ACTIVITY: ReadonlySet<EvidenceLabel> = new Set(["observed", "inferred"]);
const INDICATOR_KINDS = new Set(["ipv4", "domain", "url", "sha256", "sha1", "md5", "email"]);
const MAX_INDICATORS_PER_REPORT = 150;
const MAX_NODE_REPORTS = 60;
const MAX_EDGE_REPORTS = 25;

const TECH_ID = /\bT\d{4}(?:\.\d{3})?\b/gi;
const CVE_ID = /\bCVE-\d{4}-\d{4,7}\b/gi;

function slug(s: string): string {
  return normalizeEntityName(s).replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
}

/**
 * Ordinary words that double as tool names ("at", "net", "ping"). Longer names on ATT&CK's generic
 * list (Cobalt Strike, Mimikatz) are only kept out of free-text detection; named in an analysis
 * they are real entities.
 */
function tooGeneric(name: string): boolean {
  return name.length <= 5 && isGenericEntityName(name);
}

/** An array field from a stored report, or [] when it is missing or not an array. */
function arr<T = unknown>(v: unknown): T[] {
  return Array.isArray(v) ? (v.filter((x) => x !== null && x !== undefined) as T[]) : [];
}

const textOf = (v: unknown) => (typeof v === "string" ? v : "");

function clean(s: unknown): string {
  return typeof s === "string" ? s.replace(/\s+/g, " ").trim() : "";
}

type Mention = { id: string; type: GraphNodeType; label: string; attackId?: string; tactics?: string[]; subtype?: string; alias?: string; confidence: number };

/** Actor or campaign name → node (ATT&CK group / campaign when known). */
function actorMention(name: unknown, confidence: number): Mention | null {
  const raw = clean(name);
  if (raw.length < 2 || raw.length > 80 || tooGeneric(raw)) return null;
  const hit = resolveEntity(raw, ["group", "campaign"])[0];
  if (hit?.kind === "group") return { id: `actor:${hit.id}`, type: "actor", label: hit.name, attackId: hit.id, alias: raw, confidence };
  if (hit?.kind === "campaign") return { id: `campaign:${hit.id}`, type: "campaign", label: hit.name, attackId: hit.id, alias: raw, confidence };
  // A name ATT&CK knows as software is not an actor (analyses sometimes list it under actors).
  if (resolveEntity(raw, ["software"]).length) return null;
  const key = slug(raw);
  return key ? { id: `actor:x-${key}`, type: "actor", label: raw, confidence } : null;
}

function campaignMention(name: unknown, confidence: number): Mention | null {
  const raw = clean(name);
  if (raw.length < 2 || raw.length > 80 || tooGeneric(raw)) return null;
  const hit = resolveEntity(raw, ["campaign"])[0];
  if (hit) return { id: `campaign:${hit.id}`, type: "campaign", label: hit.name, attackId: hit.id, alias: raw, confidence };
  const key = slug(raw);
  return key ? { id: `campaign:x-${key}`, type: "campaign", label: raw, confidence } : null;
}

/** Malware or tool name → node (ATT&CK software when known; its type decides malware vs tool). */
function softwareMention(name: unknown, confidence: number, fallback: "malware" | "tool" = "malware"): Mention | null {
  const raw = clean(name);
  if (raw.length < 2 || raw.length > 80 || tooGeneric(raw)) return null;
  const hit = resolveEntity(raw, ["software"])[0];
  if (hit) {
    const sw = getSoftware(hit.id);
    const type = sw?.type === "tool" ? "tool" : "malware";
    return { id: `${type}:${hit.id}`, type, label: hit.name, attackId: hit.id, alias: raw, confidence };
  }
  // A name ATT&CK knows as a group or campaign is not malware (analyses sometimes list it there).
  if (resolveEntity(raw, ["group", "campaign"]).length) return null;
  const key = slug(raw);
  return key ? { id: `${fallback}:x-${key}`, type: fallback, label: raw, confidence } : null;
}

function techniqueMention(id: unknown, confidence: number, name?: unknown, tactic?: unknown): Mention | null {
  const tid = clean(id).toUpperCase();
  if (!/^T\d{4}(?:\.\d{3})?$/.test(tid)) return null;
  const t = getTechnique(tid);
  const label = t?.name ?? clean(name);
  if (!label) return null;
  const tactics = t?.tactics?.length ? t.tactics : clean(tactic) ? [clean(tactic)] : [];
  return { id: `technique:${tid}`, type: "technique", label, attackId: tid, tactics, confidence };
}

function vulnMention(cve: unknown, confidence: number): Mention | null {
  const id = clean(cve).toUpperCase();
  return /^CVE-\d{4}-\d{4,7}$/.test(id) ? { id: `vulnerability:${id}`, type: "vulnerability", label: id, confidence } : null;
}

function targetMention(kind: unknown, value: unknown, confidence: number): Mention | null {
  const raw = clean(value);
  if (raw.length < 2 || raw.length > 60) return null;
  const type: GraphNodeType | null = kind === "sector" || kind === "victim_type" ? "sector" : kind === "geography" ? "geography" : kind === "platform" ? "platform" : null;
  if (!type) return null;
  const key = slug(raw);
  if (!key) return null;
  const label = raw.length <= 4 ? raw.toUpperCase() : raw[0].toUpperCase() + raw.slice(1);
  return { id: `${type}:${key}`, type, label, alias: raw, confidence };
}

function indicatorMention(kind: unknown, value: unknown, confidence: number): Mention | null {
  const v = clean(value).toLowerCase();
  if (typeof kind !== "string" || !INDICATOR_KINDS.has(kind) || v.length < 4 || v.length > 300) return null;
  const label = v.length > 64 ? `${v.slice(0, 30)}…${v.slice(-12)}` : v;
  return { id: `indicator:${kind}:${v}`, type: "indicator", label, subtype: kind, confidence };
}

/** All entities of one report, deduplicated by node id (highest confidence kept). */
export function reportEntities(r: GraphSourceReport): Map<string, Mention> {
  const out = new Map<string, Mention>();
  const add = (m: Mention | null) => {
    if (!m) return;
    const prev = out.get(m.id);
    if (!prev || m.confidence > prev.confidence) out.set(m.id, { ...m, alias: m.alias ?? prev?.alias });
  };
  const a = r.analysis;
  const ev = a?.evidence;
  const ee = r.extractedEntities;
  const ai = r.aiAnalysis;

  // Actors and campaigns.
  // Evidence facts first; the older analysis list only when the report has no actor evidence.
  // (Braces matter: without them the `else` bound to the inner `if` and the older list was never read.)
  if (arr(ev?.actors).length) {
    for (const f of arr<{ value: unknown; label: EvidenceLabel; confidence?: number }>(ev?.actors)) if (ACTIVITY.has(f.label)) add(actorMention(f.value, f.confidence ?? 0.6));
  } else {
    for (const n of arr(a?.threatActors)) add(actorMention(n, 0.5));
  }
  for (const n of ee?.threatActors ?? []) add(actorMention(n, 0.45));
  if (ai?.adversary?.name) add(actorMention(ai.adversary.name, 0.6));
  if (ee?.campaign) add(campaignMention(ee.campaign, 0.5));
  for (const ref of ee?.attackRefs ?? []) {
    if (!ref || typeof ref.id !== "string") continue;
    if (ref.kind === "group") add({ id: `actor:${ref.id}`, type: "actor", label: getGroup(ref.id)?.name ?? ref.name, attackId: ref.id, alias: ref.matched, confidence: ref.inTitle ? 0.6 : 0.45 });
    else if (ref.kind === "campaign") add({ id: `campaign:${ref.id}`, type: "campaign", label: ref.name, attackId: ref.id, alias: ref.matched, confidence: 0.45 });
    else if (ref.kind === "software") {
      // A short generic name (cmd, net) counts when the report names the binary itself (cmd.exe).
      const binary = typeof ref.matched === "string" && /\.(?:exe|dll|ps1|sh)$/i.test(ref.matched);
      const sw = binary ? getSoftware(ref.id) : undefined;
      if (sw) add({ id: `${sw.type === "tool" ? "tool" : "malware"}:${ref.id}`, type: sw.type === "tool" ? "tool" : "malware", label: sw.name, attackId: ref.id, alias: ref.matched, confidence: 0.45 });
      else add(softwareMention(ref.name, ref.inTitle ? 0.6 : 0.45));
    }
  }

  // Malware and tools.
  if (arr(ev?.malware).length) {
    for (const f of arr<{ value: unknown; label: EvidenceLabel; confidence?: number }>(ev?.malware)) if (ACTIVITY.has(f.label)) add(softwareMention(f.value, f.confidence ?? 0.6));
  } else {
    for (const n of arr(a?.malware)) add(softwareMention(n, 0.5));
  }
  for (const n of ee?.malwareFamilies ?? []) add(softwareMention(n, 0.45));
  for (const n of ai?.adversary?.malware ?? []) add(softwareMention(n, 0.5));
  for (const n of ai?.adversary?.tools ?? []) add(softwareMention(n, 0.5, "tool"));

  // Techniques: evidence facts, else the older lists.
  if (arr(ev?.techniques).length) {
    for (const t of arr<{ id: unknown; name: unknown; tactic: unknown; label: EvidenceLabel; confidence?: number }>(ev?.techniques)) if (ACTIVITY.has(t.label)) add(techniqueMention(t.id, t.label === "observed" ? t.confidence ?? 0.7 : Math.min(t.confidence ?? 0.5, 0.5), t.name, t.tactic));
  } else {
    for (const t of ee?.techniques ?? []) add(techniqueMention(t.id, 0.45, t.name, t.tactic));
    for (const s of arr(a?.ttps)) for (const id of textOf(s).match(TECH_ID) ?? []) add(techniqueMention(id, 0.45));
  }
  for (const step of ai?.attackChain ?? []) if (step?.technique?.id) add(techniqueMention(step.technique.id, 0.55, step.technique.name, step.stage));
  // The analysis's attack chain lists the techniques of each observed step ("T1059.001 - PowerShell").
  for (const step of arr<{ tactic?: unknown; techniques?: unknown }>(a?.attackChain)) {
    for (const t of arr(step.techniques)) for (const id of textOf(t).match(TECH_ID) ?? []) add(techniqueMention(id, 0.5, undefined, step.tactic));
  }

  // Vulnerabilities.
  for (const s of [...arr(a?.vulnerabilities), ...arr(ee?.cves)]) for (const id of textOf(s).match(CVE_ID) ?? []) add(vulnMention(id, 0.6));
  for (const i of r.iocs ?? []) if (i.kind === "cve") add(vulnMention(i.value, 0.6));

  // Targeting: only what the source says was targeted or compromised.
  for (const t of ev?.targeting ?? []) if (t.status === "targeted" || t.status === "compromised") add(targetMention(t.kind, t.value, t.confidence ?? 0.6));
  for (const s of ai?.adversary?.sectors ?? []) add(targetMention("sector", s, 0.45));
  for (const g of ai?.adversary?.regions ?? []) add(targetMention("geography", g, 0.45));

  // Indicators.
  let n = 0;
  // Extracted indicators, then the ones the grounded AI analysis verified in the text.
  const indicators: Array<{ kind: unknown; value: unknown; c: number }> = [
    ...arr<IocHit>(r.iocs).map((i) => ({ kind: i.kind, value: i.value, c: 0.6 })),
    ...arr<{ type?: unknown; value?: unknown }>(ai?.iocs).map((i) => ({ kind: i.type === "ipv4" ? "ipv4" : i.type, value: i.value, c: 0.55 })),
  ];
  for (const i of indicators) {
    if (n >= MAX_INDICATORS_PER_REPORT) break;
    if (i.kind === "cve") {
      add(vulnMention(i.value, 0.6));
      continue;
    }
    const m = indicatorMention(i.kind, i.value, i.c);
    if (m && !out.has(m.id)) {
      add(m);
      n++;
    }
  }
  return out;
}

function refToNodeId(ref: { type: string; value: string }, entities: Map<string, Mention>): string | null {
  const m =
    ref.type === "actor"
      ? actorMention(ref.value, 0)
      : ref.type === "malware"
        ? softwareMention(ref.value, 0)
        : ref.type === "technique"
          ? techniqueMention(ref.value, 0)
          : ref.type === "ioc"
            ? null
            : targetMention(ref.type, ref.value, 0);
  if (m) {
    if (entities.has(m.id)) return m.id;
    // Software may have resolved to "tool:" in the report's entities.
    const alt = m.id.replace(/^malware:/, "tool:");
    return entities.has(alt) ? alt : null;
  }
  if (ref.type === "ioc") {
    const v = clean(ref.value).toLowerCase();
    for (const id of entities.keys()) if (id.startsWith("indicator:") && id.endsWith(`:${v}`)) return id;
  }
  return null;
}

const PREDICATE: Record<string, GraphPredicate> = { uses: "uses", performed: "uses", targeted: "targets", attributed_to: "attributed_to", communicates_with: "communicates_with" };
/** Predicates whose direction carries no meaning: their two ends are stored in id order. */
const UNDIRECTED: ReadonlySet<GraphPredicate> = new Set(["communicates_with"]);

type EdgeAcc = { source: string; target: string; predicate: GraphPredicate; reports: Map<string, number>; stated: Set<string>; quote?: { reportId: string; text: string }; lastSeen: string | null };

const reportDate = (r: GraphSourceReport) => (typeof r.publishedAt === "string" && r.publishedAt) || (typeof r.ingestedAt === "string" && r.ingestedAt) || null;

/** True for library reports (not synced ATT&CK reference documents or rejected records). */
export function isGraphReport(r: GraphSourceReport): boolean {
  if (r.discoveryMethod === "structured_sync") return false;
  return !r.status || r.status === "acquired";
}

export function buildIntelGraph(input: GraphSourceReport[], now = new Date()): IntelGraph {
  const reports = input.filter((r) => r && typeof r.id === "string" && isGraphReport(r)).sort((a, b) => String(reportDate(b) ?? "").localeCompare(String(reportDate(a) ?? "")));
  type NodeAcc = { node: Omit<GraphNode, "reports" | "reportCount" | "degree" | "aliases">; reports: string[]; count: number; aliases: Set<string> };
  const nodes = new Map<string, NodeAcc>();
  const edges = new Map<string, EdgeAcc>();
  const refs: Record<string, GraphReportRef> = {};

  const link = (from: string, to: string, predicate: GraphPredicate, reportId: string, c: number, date: string | null, quote?: string) => {
    if (from === to) return;
    let [s, t] = [from, to];
    if (UNDIRECTED.has(predicate) && t < s) [s, t] = [t, s];
    const key = `${s}|${predicate}|${t}`;
    let e = edges.get(key);
    if (!e) {
      e = { source: s, target: t, predicate, reports: new Map(), stated: new Set(), lastSeen: date };
      edges.set(key, e);
    }
    e.reports.set(reportId, Math.max(e.reports.get(reportId) ?? 0, c));
    if (quote) {
      e.stated.add(reportId);
      e.quote ??= { reportId, text: quote.slice(0, 400) };
    }
    if (date && (!e.lastSeen || date > e.lastSeen)) e.lastSeen = date;
  };

  let skipped = 0;
  for (const r of reports) {
    // One malformed stored report must not take the whole graph down: skip it and count it.
    let ents: Map<string, Mention>;
    try {
      ents = reportEntities(r);
    } catch {
      skipped++;
      continue;
    }
    if (!ents.size) continue;
    const date = reportDate(r);
    refs[r.id] = { id: r.id, title: clean(r.title) || r.id, publisher: clean(r.publisher) || clean(r.sourceName), publishedAt: typeof r.publishedAt === "string" ? r.publishedAt : null };
    for (const m of ents.values()) {
      let acc = nodes.get(m.id);
      if (!acc) {
        acc = { node: { id: m.id, type: m.type, label: m.label, attackId: m.attackId, tactics: m.tactics, subtype: m.subtype, firstSeen: date, lastSeen: date }, reports: [], count: 0, aliases: new Set() };
        nodes.set(m.id, acc);
      }
      if (acc.reports.length < MAX_NODE_REPORTS) acc.reports.push(r.id);
      acc.count++;
      if (m.alias && normalizeEntityName(m.alias) !== normalizeEntityName(acc.node.label) && acc.aliases.size < 8) acc.aliases.add(m.alias);
      if (date && (!acc.node.firstSeen || date < acc.node.firstSeen)) acc.node.firstSeen = date;
      if (date && (!acc.node.lastSeen || date > acc.node.lastSeen)) acc.node.lastSeen = date;
    }

    // Stated links: both entities in one sentence.
    for (const rel of arr<RelationshipFact>(r.analysis?.evidence?.relationships)) {
      if (!ACTIVITY.has(rel.label) || !rel.subject || !rel.object) continue;
      const predicate = PREDICATE[rel.predicate];
      const s = refToNodeId(rel.subject, ents);
      const o = refToNodeId(rel.object, ents);
      if (!predicate || !s || !o) continue;
      link(s, o, predicate, r.id, Math.max(0.5, rel.confidence ?? 0.7), date, rel.evidence?.[0]?.quote || "stated");
    }

    // Co-reported links.
    const of = (...types: GraphNodeType[]) => [...ents.values()].filter((m) => types.includes(m.type));
    const actors = of("actor");
    const campaigns = of("campaign");
    const software = of("malware", "tool");
    const malware = of("malware");
    const techniques = of("technique");
    const vulns = of("vulnerability");
    const targets = of("sector", "geography", "platform");
    const indicators = of("indicator");
    const agents = actors.length || campaigns.length ? [...actors, ...campaigns] : malware;
    const co = (a: Mention, b: Mention) => Math.min(a.confidence, b.confidence) * 0.6;
    for (const c of campaigns) for (const a of actors) link(c.id, a.id, "attributed_to", r.id, co(c, a), date);
    for (const a of agents) {
      for (const t of techniques) link(a.id, t.id, "uses", r.id, co(a, t), date);
      if (a.type !== "malware") for (const s of software) link(a.id, s.id, "uses", r.id, co(a, s), date);
      for (const v of vulns) link(a.id, v.id, "exploits", r.id, co(a, v), date);
      for (const t of targets) link(a.id, t.id, "targets", r.id, co(a, t), date);
    }
    if (agents !== malware) for (const m of malware) for (const t of techniques) link(m.id, t.id, "uses", r.id, co(m, t) * 0.8, date);
    const owners = malware.length ? malware : actors.length ? actors : campaigns;
    if (owners.length <= 3) for (const i of indicators) for (const o of owners) link(i.id, o.id, "indicator_of", r.id, co(i, o), date);
  }

  const edgeList: GraphEdge[] = [];
  const degree = new Map<string, number>();
  for (const [key, e] of edges) {
    const cs = [...e.reports.values()];
    const confidence = Math.min(0.99, 1 - cs.reduce((p, c) => p * (1 - Math.max(0, Math.min(0.95, c))), 1));
    edgeList.push({
      id: key,
      source: e.source,
      target: e.target,
      predicate: e.predicate,
      basis: e.stated.size ? "stated" : "co-reported",
      weight: e.reports.size,
      stated: e.stated.size,
      confidence: Math.round(confidence * 100) / 100,
      reports: [...e.reports.keys()].slice(0, MAX_EDGE_REPORTS),
      ...(e.quote && e.quote.text !== "stated" ? { quote: e.quote } : {}),
      lastSeen: e.lastSeen,
    });
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
  }

  const nodeList: GraphNode[] = [...nodes.values()].map((acc) => ({
    ...acc.node,
    ...(acc.aliases.size ? { aliases: [...acc.aliases] } : {}),
    reports: acc.reports,
    reportCount: acc.count,
    degree: degree.get(acc.node.id) ?? 0,
  }));
  for (const n of nodeList) {
    if (!n.attackId) delete n.attackId;
    if (!n.tactics?.length) delete n.tactics;
    if (!n.subtype) delete n.subtype;
  }

  return {
    nodes: nodeList,
    edges: edgeList,
    reports: refs,
    stats: { reports: Object.keys(refs).length, nodes: nodeList.length, edges: edgeList.length, stated: edgeList.filter((e) => e.basis === "stated").length, skipped, builtAt: now.toISOString() },
  };
}

/** Per-type caps for the copy of the graph sent to the browser (the server keeps everything). */
export const CLIENT_TYPE_CAPS: Partial<Record<GraphNodeType, number>> = { indicator: 1500, vulnerability: 1500 };

/**
 * The browser's copy of the graph: the most-reported entities of the high-volume types (indicators,
 * vulnerabilities), and shorter report lists per entity / link. Everything else is unchanged, so
 * filters and views work the same; the entity context panel and search ask the server, which has
 * the full graph. `stats.trimmed` says how many entities of each type were left out.
 */
export function clientGraph(graph: IntelGraph, opts: { nodeReports?: number; edgeReports?: number; edgesPerNode?: number; caps?: Partial<Record<GraphNodeType, number>> } = {}): IntelGraph {
  const caps = opts.caps ?? CLIENT_TYPE_CAPS;
  const nodeReports = opts.nodeReports ?? 12;
  const edgeReports = opts.edgeReports ?? 3;
  const edgesPerNode = opts.edgesPerNode ?? 24;
  const byType = new Map<GraphNodeType, GraphNode[]>();
  for (const n of graph.nodes) (byType.get(n.type) ?? byType.set(n.type, []).get(n.type)!).push(n);
  const keep = new Set<string>();
  const trimmed: Partial<Record<GraphNodeType, number>> = {};
  for (const [type, list] of byType) {
    const cap = caps[type];
    const kept = cap !== undefined && list.length > cap ? [...list].sort((a, b) => b.reportCount - a.reportCount || b.degree - a.degree).slice(0, cap) : list;
    if (kept.length < list.length) trimmed[type] = list.length - kept.length;
    for (const n of kept) keep.add(n.id);
  }
  const nodes = graph.nodes
    .filter((n) => keep.has(n.id))
    .map((n) => ({ ...n, reports: n.reports.slice(0, nodeReports), firstSeen: n.firstSeen ? n.firstSeen.slice(0, 10) : null, lastSeen: n.lastSeen ? n.lastSeen.slice(0, 10) : null }));
  // Links: each entity's strongest `edgesPerNode`, plus every stated link (the server keeps all).
  const candidates = graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target));
  const byNode = new Map<string, GraphEdge[]>();
  for (const e of candidates) {
    (byNode.get(e.source) ?? byNode.set(e.source, []).get(e.source)!).push(e);
    (byNode.get(e.target) ?? byNode.set(e.target, []).get(e.target)!).push(e);
  }
  const keptEdges = new Set<GraphEdge>(candidates.filter((e) => e.basis === "stated"));
  for (const list of byNode.values()) {
    if (list.length <= edgesPerNode) list.forEach((e) => keptEdges.add(e));
    else list.sort((a, b) => edgeStrength(b) - edgeStrength(a)).slice(0, edgesPerNode).forEach((e) => keptEdges.add(e));
  }
  // Compact for transport: no id (withEdgeIds rebuilds it), dates as days, fewer report ids.
  const edges = candidates
    .filter((e) => keptEdges.has(e))
    .map((e) => {
      const { id: _id, ...rest } = e;
      return { ...rest, reports: e.reports.slice(0, edgeReports), lastSeen: e.lastSeen ? e.lastSeen.slice(0, 10) : null } as GraphEdge;
    });
  const used = new Set<string>();
  for (const n of nodes) for (const r of n.reports) used.add(r);
  for (const e of edges) {
    for (const r of e.reports) used.add(r);
    if (e.quote) used.add(e.quote.reportId);
  }
  const reports: IntelGraph["reports"] = {};
  for (const id of used) if (graph.reports[id]) reports[id] = graph.reports[id];
  return { nodes, edges, reports, stats: { ...graph.stats, ...(Object.keys(trimmed).length ? { trimmed } : {}), clientEdges: edges.length } };
}

