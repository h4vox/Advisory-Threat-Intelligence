/**
 * Reading the intelligence graph (./types): filters, the two views the page draws, neighbours,
 * "possible hidden links" and overview insights. Pure; unit-tested.
 *
 * Views keep the screen readable:
 *   - overview: the most-reported entities of each visible type (a per-type quota) and the
 *     links among them;
 *   - focus: one entity in the centre, its strongest links on the first ring, and (2 hops) the
 *     strongest links of those on the second ring.
 */
import type { GraphEdge, GraphNode, GraphNodeType, IntelGraph } from "./types.ts";

export type GraphFilter = {
  types: GraphNodeType[];
  /** Only entities seen in at least this many reports. */
  minReports: number;
  /** Only links at or above this confidence (0..1). */
  minConfidence: number;
  /** Only links a report states in one sentence. */
  statedOnly: boolean;
  /** Only entities and links seen on or after this date (ISO), or null for all time. */
  since: string | null;
  /** Techniques: only these ATT&CK tactics (empty or missing = all). */
  tactics?: string[];
};

export const DEFAULT_FILTER: GraphFilter = {
  types: ["actor", "campaign", "malware", "tool", "technique", "vulnerability", "sector", "geography"],
  minReports: 1,
  minConfidence: 0,
  statedOnly: false,
  since: null,
};

export type GraphIndex = {
  graph: IntelGraph;
  node: Map<string, GraphNode>;
  /** Edges by node id. */
  adj: Map<string, GraphEdge[]>;
};

export function indexGraph(graph: IntelGraph): GraphIndex {
  const node = new Map(graph.nodes.map((n) => [n.id, n]));
  const adj = new Map<string, GraphEdge[]>();
  for (const e of graph.edges) {
    (adj.get(e.source) ?? adj.set(e.source, []).get(e.source)!).push(e);
    (adj.get(e.target) ?? adj.set(e.target, []).get(e.target)!).push(e);
  }
  return { graph, node, adj };
}

export const otherEnd = (e: GraphEdge, id: string) => (e.source === id ? e.target : e.source);

export function nodePasses(n: GraphNode, f: GraphFilter): boolean {
  if (!f.types.includes(n.type)) return false;
  if (n.reportCount < f.minReports) return false;
  if (f.since && (!n.lastSeen || n.lastSeen < f.since)) return false;
  if (f.tactics?.length && n.type === "technique" && !n.tactics?.some((t) => f.tactics!.includes(t))) return false;
  return true;
}

export function edgePasses(e: GraphEdge, f: GraphFilter): boolean {
  if (e.confidence < f.minConfidence) return false;
  if (f.minReports > 1 && e.weight < f.minReports) return false;
  if (f.statedOnly && e.basis !== "stated") return false;
  if (f.since && (!e.lastSeen || e.lastSeen < f.since)) return false;
  return true;
}

/** Link strength used for ranking: more reports, stated and confident links first. */
export function edgeStrength(e: GraphEdge): number {
  return Math.log2(1 + e.weight) * (0.4 + e.confidence) * (e.basis === "stated" ? 1.5 : 1);
}

/** Entity importance: reports, reach, and recent activity. */
export function nodeImportance(n: GraphNode, now = Date.now()): number {
  const ageDays = n.lastSeen ? Math.max(0, (now - Date.parse(n.lastSeen)) / 86_400_000) : 3650;
  const recency = 1 / (1 + ageDays / 180);
  return Math.log2(1 + n.reportCount) * 2 + Math.log2(1 + n.degree) + recency;
}

export type GraphView = {
  mode: "overview" | "focus";
  nodes: GraphNode[];
  edges: GraphEdge[];
  center?: string;
  /** Focus view: ring of each node (0 = centre) and, for the second ring, the first-ring node it hangs off. */
  ring?: Map<string, 0 | 1 | 2>;
  parent?: Map<string, string>;
  /** Entities that passed the filter but did not fit on screen. */
  hidden: number;
};

/** Per-type share of the overview's node budget. */
const OVERVIEW_SHARE: Partial<Record<GraphNodeType, number>> = { technique: 0.3, actor: 0.18, malware: 0.15, tool: 0.07, campaign: 0.06, vulnerability: 0.08, sector: 0.06, geography: 0.05, platform: 0.03, indicator: 0.08 };

export function overviewView(ix: GraphIndex, f: GraphFilter, maxNodes = 160, now = Date.now()): GraphView {
  const pass = ix.graph.nodes.filter((n) => nodePasses(n, f));
  const byType = new Map<GraphNodeType, GraphNode[]>();
  for (const n of pass) (byType.get(n.type) ?? byType.set(n.type, []).get(n.type)!).push(n);
  const shareSum = [...byType.keys()].reduce((s, t) => s + (OVERVIEW_SHARE[t] ?? 0.05), 0) || 1;
  const chosen: GraphNode[] = [];
  let spare = 0;
  const ranked = [...byType.entries()].map(([t, list]) => ({ t, list: list.sort((a, b) => nodeImportance(b, now) - nodeImportance(a, now)) }));
  for (const { t, list } of ranked) {
    const quota = Math.max(3, Math.round((maxNodes * (OVERVIEW_SHARE[t] ?? 0.05)) / shareSum));
    chosen.push(...list.slice(0, quota));
    spare += Math.max(0, quota - list.length);
  }
  // Unused quota goes to the most important leftovers of any type.
  if (spare > 0) {
    const taken = new Set(chosen.map((n) => n.id));
    chosen.push(...pass.filter((n) => !taken.has(n.id)).sort((a, b) => nodeImportance(b, now) - nodeImportance(a, now)).slice(0, spare));
  }
  const ids = new Set(chosen.map((n) => n.id));
  const edges = ix.graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target) && edgePasses(e, f));
  // Drop nodes left without any link: they add nothing to a map of relationships.
  const linked = new Set(edges.flatMap((e) => [e.source, e.target]));
  const nodes = chosen.filter((n) => linked.has(n.id));
  return { mode: "overview", nodes, edges, hidden: pass.length - nodes.length };
}

export function focusView(ix: GraphIndex, centerId: string, f: GraphFilter, opts: { hops: 1 | 2; ring1Max?: number; perParent?: number; ring2Max?: number } = { hops: 1 }): GraphView {
  const center = ix.node.get(centerId);
  if (!center) return { mode: "focus", nodes: [], edges: [], hidden: 0 };
  const ring1Max = opts.ring1Max ?? 48;
  const ring = new Map<string, 0 | 1 | 2>([[centerId, 0]]);
  const parent = new Map<string, string>();
  const strongest = (id: string) =>
    (ix.adj.get(id) ?? [])
      .filter((e) => edgePasses(e, f))
      .map((e) => ({ e, n: ix.node.get(otherEnd(e, id))! }))
      .filter(({ n }) => n && nodePasses(n, f))
      .sort((a, b) => edgeStrength(b.e) - edgeStrength(a.e));
  const first = strongest(centerId);
  const r1 = first.slice(0, ring1Max);
  for (const { n } of r1) ring.set(n.id, 1);
  const hidden = Math.max(0, first.length - r1.length);
  if (opts.hops === 2) {
    const perParent = opts.perParent ?? 3;
    let budget = opts.ring2Max ?? 90;
    for (const { n: p } of r1) {
      let added = 0;
      for (const { n } of strongest(p.id)) {
        if (budget <= 0 || added >= perParent) break;
        if (ring.has(n.id)) continue;
        ring.set(n.id, 2);
        parent.set(n.id, p.id);
        added++;
        budget--;
      }
    }
  }
  const ids = new Set(ring.keys());
  const edges = ix.graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target) && edgePasses(e, f));
  const nodes = [...ids].map((id) => ix.node.get(id)!).filter(Boolean);
  return { mode: "focus", nodes, edges, center: centerId, ring, parent, hidden };
}

/** A node's links (all entity types; the filter's link rules apply), strongest first. */
export function connections(ix: GraphIndex, id: string, f?: GraphFilter): Array<{ edge: GraphEdge; other: GraphNode; outgoing: boolean }> {
  return (ix.adj.get(id) ?? [])
    .filter((e) => !f || edgePasses(e, f))
    .map((e) => ({ edge: e, other: ix.node.get(otherEnd(e, id))!, outgoing: e.source === id }))
    .filter((c) => c.other)
    .sort((a, b) => edgeStrength(b.edge) - edgeStrength(a.edge));
}

export type SimilarEntity = { node: GraphNode; score: number; shared: GraphNode[]; linked: boolean };

/** Types compared when looking for hidden links, and what they are compared on. */
const SIMILAR_ON: Partial<Record<GraphNodeType, GraphNodeType[]>> = {
  actor: ["technique", "malware", "tool", "vulnerability", "sector", "geography", "indicator"],
  campaign: ["technique", "malware", "tool", "vulnerability", "sector", "geography", "indicator"],
  malware: ["technique", "vulnerability", "indicator", "actor"],
  tool: ["technique", "actor"],
  vulnerability: ["actor", "malware", "sector"],
};

/**
 * Possible hidden links: entities of the same kind (actors with actors and campaigns, malware with
 * malware and tools…) that share an unusual amount of behaviour, tooling, targets or
 * infrastructure. Shared items are weighted by rarity (IDF): sharing a rare technique or an
 * indicator says more than sharing "PowerShell". Score is 0..1 (weighted Jaccard).
 */
/** Rarity weights (IDF) per index, peer group and feature, computed once and reused. */
const idfCache = new WeakMap<GraphIndex, Map<string, number>>();

export function similarEntities(ix: GraphIndex, id: string, limit = 8): SimilarEntity[] {
  const self = ix.node.get(id);
  const on = self ? SIMILAR_ON[self.type] : undefined;
  if (!self || !on) return [];
  const peers: GraphNodeType[] = self.type === "actor" || self.type === "campaign" ? ["actor", "campaign"] : self.type === "malware" || self.type === "tool" ? ["malware", "tool"] : [self.type];
  const isPeer = (nid: string) => peers.includes(ix.node.get(nid)?.type as GraphNodeType);
  const isFeature = (nid: string) => {
    const t = ix.node.get(nid)?.type;
    return Boolean(t && on.includes(t) && !peers.includes(t));
  };
  const peerKey = peers.join(",");
  let cache = idfCache.get(ix);
  if (!cache) idfCache.set(ix, (cache = new Map()));
  let total = cache.get(`#total:${peerKey}`);
  if (total === undefined) {
    total = Math.max(1, ix.graph.nodes.filter((n) => peers.includes(n.type)).length);
    cache.set(`#total:${peerKey}`, total);
  }
  const idf = (fid: string) => {
    const key = `${peerKey}|${fid}`;
    let w = cache!.get(key);
    if (w === undefined) {
      let df = 0;
      for (const e of ix.adj.get(fid) ?? []) if (isPeer(otherEnd(e, fid))) df++;
      w = Math.log(1 + total! / Math.max(1, df));
      cache!.set(key, w);
    }
    return w;
  };
  const featuresOf = (nid: string) => {
    const out = new Set<string>();
    for (const e of ix.adj.get(nid) ?? []) {
      const o = otherEnd(e, nid);
      if (isFeature(o)) out.add(o);
    }
    return out;
  };
  const mine = featuresOf(id);
  if (!mine.size) return [];
  let mineW = 0;
  // One pass over the shared features gives each candidate's overlap weight.
  const inter = new Map<string, { w: number; shared: string[]; last: string }>();
  for (const fid of mine) {
    const w = idf(fid);
    mineW += w;
    for (const e of ix.adj.get(fid) ?? []) {
      const o = otherEnd(e, fid);
      if (o === id || !isPeer(o)) continue;
      let cur = inter.get(o);
      if (!cur) inter.set(o, (cur = { w: 0, shared: [], last: "" }));
      // Several links (predicates) between the same pair count once.
      if (cur.last === fid) continue;
      cur.last = fid;
      cur.w += w;
      cur.shared.push(fid);
    }
  }
  const directly = new Set((ix.adj.get(id) ?? []).map((e) => otherEnd(e, id)));
  const out: SimilarEntity[] = [];
  // Only the strongest overlaps need the full (union) score.
  const top = [...inter.entries()].filter(([, v]) => v.shared.length >= 2).sort((a, b) => b[1].w - a[1].w).slice(0, 150);
  for (const [cid, v] of top) {
    const wKey = `#w:${peerKey}|${cid}`;
    let theirsW = cache.get(wKey);
    if (theirsW === undefined) {
      theirsW = 0;
      for (const fid of featuresOf(cid)) theirsW += idf(fid);
      cache.set(wKey, theirsW);
    }
    const union = mineW + theirsW - v.w;
    if (union <= 0) continue;
    const score = v.w / union;
    if (score < 0.08) continue;
    out.push({
      node: ix.node.get(cid)!,
      score: Math.round(score * 100) / 100,
      shared: v.shared.sort((a, b) => idf(b) - idf(a)).slice(0, 8).map((s) => ix.node.get(s)!),
      linked: directly.has(cid),
    });
  }
  return out.sort((a, b) => b.score - a.score).slice(0, limit);
}

export type GraphInsights = {
  mostActive: GraphNode[];
  newest: GraphNode[];
  strongestStated: GraphEdge[];
  topTechniques: GraphNode[];
  byType: Array<{ type: GraphNodeType; count: number }>;
};

export function graphInsights(ix: GraphIndex, f: GraphFilter, now = Date.now()): GraphInsights {
  const nodes = ix.graph.nodes.filter((n) => nodePasses(n, f));
  const byType = new Map<GraphNodeType, number>();
  for (const n of ix.graph.nodes) byType.set(n.type, (byType.get(n.type) ?? 0) + 1);
  const agents = nodes.filter((n) => n.type === "actor" || n.type === "campaign" || n.type === "malware");
  return {
    mostActive: [...agents].sort((a, b) => nodeImportance(b, now) - nodeImportance(a, now)).slice(0, 6),
    newest: nodes.filter((n) => n.firstSeen && n.type !== "indicator" && n.type !== "technique").sort((a, b) => String(b.firstSeen).localeCompare(String(a.firstSeen))).slice(0, 6),
    strongestStated: ix.graph.edges.filter((e) => e.basis === "stated" && edgePasses(e, f)).sort((a, b) => edgeStrength(b) - edgeStrength(a)).slice(0, 6),
    topTechniques: nodes.filter((n) => n.type === "technique").sort((a, b) => b.reportCount - a.reportCount).slice(0, 6),
    byType: [...byType.entries()].map(([type, count]) => ({ type, count })),
  };
}

/** Entities whose name, alias or ATT&CK ID matches the query, best first. */
export function searchNodes(ix: GraphIndex, q: string, limit = 12): GraphNode[] {
  const s = q.trim().toLowerCase();
  if (!s) return [];
  const scored: Array<{ n: GraphNode; score: number }> = [];
  for (const n of ix.graph.nodes) {
    const names = [n.label, n.attackId ?? "", ...(n.aliases ?? [])].map((x) => x.toLowerCase());
    let score = 0;
    for (const name of names) {
      if (!name) continue;
      if (name === s) score = Math.max(score, 100);
      else if (name.startsWith(s)) score = Math.max(score, 60);
      else if (name.includes(s)) score = Math.max(score, 30);
    }
    if (score) scored.push({ n, score: score + Math.log2(1 + n.reportCount) });
  }
  return scored.sort((a, b) => b.score - a.score).slice(0, limit).map((x) => x.n);
}
