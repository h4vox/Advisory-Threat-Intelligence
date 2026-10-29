/**
 * Correlation engine over the intelligence graph (./types, ./analyze). Works without any AI: every
 * answer is computed from the library's entities and links. The AI (./brief) only adds prose on
 * top, when it is available.
 *
 *   - resolveRef:      any name, alias, ATT&CK ID, CVE, indicator or sector → an entity
 *   - entityContext:   everything correlated with one entity — links by type, entities related
 *                      through shared neighbours (with the "via" explanation), look-alikes,
 *                      activity over time, the ATT&CK knowledge compared with what the library
 *                      observed, and findings derived by rules
 *   - connectionPaths: how two entities are connected (strongest short paths)
 *
 * Pure; unit-tested.
 */
import { getGroup, getSoftware, getTechnique, mitigationsForTechniques, resolveEntity } from "../attack-knowledge.ts";
import { connections, edgeStrength, otherEnd, searchNodes, similarEntities, type GraphIndex, type SimilarEntity } from "./analyze.ts";
import { NODE_TYPE_LABEL, PREDICATE_LABEL, type GraphEdge, type GraphNode, type GraphNodeType } from "./types.ts";

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/** Finds the entity a name, alias, ATT&CK ID, CVE, indicator or node id refers to. */
export function resolveRef(ix: GraphIndex, ref: string): GraphNode | null {
  const raw = ref.trim();
  if (!raw) return null;
  const direct = ix.node.get(raw);
  if (direct) return direct;
  const up = raw.toUpperCase();
  if (/^T\d{4}(?:\.\d{3})?$/.test(up)) return ix.node.get(`technique:${up}`) ?? null;
  if (/^CVE-\d{4}-\d{4,7}$/.test(up)) return ix.node.get(`vulnerability:${up}`) ?? null;
  // ATT&CK aliases resolve to the canonical node ("Cozy Bear" → actor:G0016).
  for (const hit of resolveEntity(raw)) {
    const id = hit.kind === "group" ? `actor:${hit.id}` : hit.kind === "campaign" ? `campaign:${hit.id}` : hit.kind === "technique" ? `technique:${hit.id}` : null;
    if (id && ix.node.has(id)) return ix.node.get(id)!;
    if (hit.kind === "software") {
      const n = ix.node.get(`malware:${hit.id}`) ?? ix.node.get(`tool:${hit.id}`);
      if (n) return n;
    }
  }
  const best = searchNodes(ix, raw, 3);
  const lower = raw.toLowerCase();
  // Only an exact name / alias / ID match, or a single clear prefix match, counts as resolved.
  const exact = best.find((n) => [n.label, n.attackId ?? "", ...(n.aliases ?? [])].some((x) => x.toLowerCase() === lower));
  return exact ?? (best.length === 1 ? best[0] : null);
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export type ContextLink = { node: GraphNode; edge: GraphEdge; outgoing: boolean };
export type RelatedEntity = { node: GraphNode; score: number; via: GraphNode[] };
export type Finding = { kind: "activity" | "corroboration" | "behaviour" | "targeting" | "exploitation" | "tooling" | "overlap" | "attack"; text: string; refs: string[] };

export type AttackComparison = {
  /** ATT&CK entry the entity maps to. */
  id: string;
  name: string;
  description?: string;
  /** Group / software: ATT&CK techniques the library also observed, techniques the library observed
   *  that ATT&CK does not list (new behaviour), and ATT&CK techniques not seen in the library. */
  shared?: string[];
  newInLibrary?: string[];
  notSeen?: number;
  /** Technique: tactics, platforms, data sources and mitigations. */
  tactics?: string[];
  platforms?: string[];
  dataSources?: string[];
  mitigations?: Array<{ id: string; name: string }>;
};

export type EntityContext = {
  node: GraphNode;
  /** Links grouped by the other entity's type, strongest first (up to `perType` each). */
  links: Array<{ type: GraphNodeType; total: number; items: ContextLink[] }>;
  related: RelatedEntity[];
  similar: SimilarEntity[];
  /** Reports per month, oldest first (last 12 months with activity, or the whole span). */
  activity: Array<{ month: string; reports: number }>;
  trend: "new" | "rising" | "steady" | "falling" | "dormant" | "unknown";
  attack: AttackComparison | null;
  findings: Finding[];
  /** One paragraph written from the facts above (no AI). */
  summary: string;
};

const DAY = 86_400_000;
const month = (iso: string) => iso.slice(0, 7);
const list = (xs: string[], n = 3) => (xs.length <= n ? xs.join(", ") : `${xs.slice(0, n).join(", ")} and ${xs.length - n} more`);

function reportDates(ix: GraphIndex, n: GraphNode): number[] {
  return n.reports.map((id) => ix.graph.reports[id]?.publishedAt).filter((d): d is string => Boolean(d)).map((d) => Date.parse(d)).filter((t) => !Number.isNaN(t));
}

function activityOf(ix: GraphIndex, n: GraphNode, now: number) {
  const dates = reportDates(ix, n);
  const byMonth = new Map<string, number>();
  for (const t of dates) {
    const m = month(new Date(t).toISOString());
    byMonth.set(m, (byMonth.get(m) ?? 0) + 1);
  }
  const months = [...byMonth.keys()].sort();
  const activity = months.slice(-12).map((m) => ({ month: m, reports: byMonth.get(m)! }));
  const last90 = dates.filter((t) => now - t <= 90 * DAY).length;
  const prior90 = dates.filter((t) => now - t > 90 * DAY && now - t <= 180 * DAY).length;
  const first = dates.length ? Math.min(...dates) : null;
  let trend: EntityContext["trend"] = "unknown";
  if (dates.length) {
    if (first !== null && now - first <= 60 * DAY) trend = "new";
    else if (last90 > prior90 && last90 >= 2) trend = "rising";
    else if (last90 === 0 && dates.every((t) => now - t > 365 * DAY)) trend = "dormant";
    else if (last90 < prior90) trend = "falling";
    else trend = "steady";
  }
  return { activity, trend, last90 };
}

function attackComparison(n: GraphNode, links: ContextLink[]): AttackComparison | null {
  if (!n.attackId) return null;
  const observed = new Set(links.filter((l) => l.node.type === "technique" && l.node.attackId).map((l) => l.node.attackId!));
  const parentOf = (t: string) => t.split(".")[0];
  const compare = (known: string[]) => {
    const k = new Set(known.map((t) => t.toUpperCase()));
    const kParents = new Set([...k].map(parentOf));
    const shared = [...observed].filter((t) => k.has(t) || kParents.has(parentOf(t)));
    const newInLibrary = [...observed].filter((t) => !k.has(t) && !kParents.has(parentOf(t)));
    const notSeen = [...k].filter((t) => !observed.has(t) && ![...observed].some((o) => parentOf(o) === parentOf(t))).length;
    return { shared, newInLibrary, notSeen };
  };
  if (n.type === "actor") {
    const g = getGroup(n.attackId);
    return g ? { id: g.id, name: g.name, description: g.description, ...compare(g.techniques) } : null;
  }
  if (n.type === "malware" || n.type === "tool") {
    const s = getSoftware(n.attackId);
    return s ? { id: s.id, name: s.name, description: s.description, ...compare(s.techniques) } : null;
  }
  if (n.type === "technique") {
    const t = getTechnique(n.attackId);
    return t ? { id: t.id, name: t.name, tactics: t.tactics, platforms: t.platforms, dataSources: t.dataSources.slice(0, 8), mitigations: mitigationsForTechniques([t.id]).slice(0, 8).map((m) => ({ id: m.id, name: m.name })) } : null;
  }
  return null;
}

/** Entities two hops away, scored by the strength of the paths through shared neighbours. */
function relatedThrough(ix: GraphIndex, id: string, limit: number): RelatedEntity[] {
  const self = ix.node.get(id)!;
  const direct = new Set((ix.adj.get(id) ?? []).map((e) => otherEnd(e, id)));
  const score = new Map<string, { s: number; via: Map<string, number> }>();
  // Through the 60 strongest links only: weaker ones barely move the ranking and cost the most.
  const firstHop = (ix.adj.get(id) ?? []).slice().sort((a, b) => edgeStrength(b) - edgeStrength(a)).slice(0, 60);
  for (const e1 of firstHop) {
    const mid = otherEnd(e1, id);
    const midNode = ix.node.get(mid);
    if (!midNode || midNode.type === "indicator") continue;
    // Very common neighbours (PowerShell, "Government") explain little: damp them by their reach.
    const damp = 1 / Math.log2(2 + (ix.adj.get(mid)?.length ?? 0));
    for (const e2 of ix.adj.get(mid) ?? []) {
      const far = otherEnd(e2, mid);
      if (far === id || direct.has(far)) continue;
      const farNode = ix.node.get(far);
      if (!farNode || farNode.type === "indicator" || farNode.type === self.type && self.type === "technique") continue;
      const s = edgeStrength(e1) * edgeStrength(e2) * damp;
      const cur = score.get(far) ?? { s: 0, via: new Map() };
      cur.s += s;
      cur.via.set(mid, (cur.via.get(mid) ?? 0) + s);
      score.set(far, cur);
    }
  }
  const max = Math.max(1e-9, ...[...score.values()].map((v) => v.s));
  return [...score.entries()]
    .sort((a, b) => b[1].s - a[1].s)
    .slice(0, limit)
    .map(([fid, v]) => ({
      node: ix.node.get(fid)!,
      score: Math.round((v.s / max) * 100) / 100,
      via: [...v.via.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([m]) => ix.node.get(m)!),
    }));
}

export function entityContext(ix: GraphIndex, id: string, opts: { perType?: number; now?: number } = {}): EntityContext | null {
  const node = ix.node.get(id);
  if (!node) return null;
  const now = opts.now ?? Date.now();
  const perType = opts.perType ?? 8;
  const all = connections(ix, id).map((c) => ({ node: c.other, edge: c.edge, outgoing: c.outgoing }));
  const groups = new Map<GraphNodeType, ContextLink[]>();
  for (const l of all) (groups.get(l.node.type) ?? groups.set(l.node.type, []).get(l.node.type)!).push(l);
  const order: GraphNodeType[] = ["actor", "campaign", "malware", "tool", "technique", "vulnerability", "sector", "geography", "platform", "indicator"];
  const links = order.filter((t) => groups.has(t)).map((t) => ({ type: t, total: groups.get(t)!.length, items: groups.get(t)!.slice(0, perType) }));
  const related = relatedThrough(ix, id, 10);
  const similar = similarEntities(ix, id, 6);
  const { activity, trend, last90 } = activityOf(ix, node, now);
  const attack = attackComparison(node, all);

  // Findings: plain rules over the facts, each citing what it rests on.
  const findings: Finding[] = [];
  const of = (t: GraphNodeType) => groups.get(t) ?? [];
  const label = NODE_TYPE_LABEL[node.type].one.toLowerCase();
  if (trend === "new") findings.push({ kind: "activity", text: `New in the library: first reported ${node.firstSeen?.slice(0, 10)}.`, refs: node.reports.slice(0, 2).map((r) => `report:${r}`) });
  else if (trend === "rising") findings.push({ kind: "activity", text: `Activity is rising: ${last90} report(s) in the last 90 days, more than the 90 days before.`, refs: node.reports.slice(0, 3).map((r) => `report:${r}`) });
  else if (trend === "dormant") findings.push({ kind: "activity", text: `No report in over a year (last seen ${node.lastSeen?.slice(0, 10)}).`, refs: [] });
  const targets = [...of("sector"), ...of("geography")].filter((l) => l.edge.predicate === "targets");
  if (targets.length) findings.push({ kind: "targeting", text: `Targets ${list(targets.map((t) => t.node.label))}.`, refs: targets.slice(0, 4).map((t) => t.node.id) });
  const vulns = of("vulnerability");
  if (vulns.length) findings.push({ kind: "exploitation", text: `Linked to ${vulns.length} vulnerabilit${vulns.length === 1 ? "y" : "ies"}: ${list(vulns.map((v) => v.node.label))}.`, refs: vulns.slice(0, 4).map((v) => v.node.id) });
  const tooling = [...of("malware"), ...of("tool")];
  if (tooling.length && (node.type === "actor" || node.type === "campaign")) findings.push({ kind: "tooling", text: `Uses ${list(tooling.map((t) => t.node.label), 4)}.`, refs: tooling.slice(0, 4).map((t) => t.node.id) });
  const techs = of("technique");
  if (techs.length && node.type !== "technique") {
    const tactics = new Map<string, number>();
    for (const t of techs) for (const tac of t.node.tactics ?? []) tactics.set(tac, (tactics.get(tac) ?? 0) + 1);
    const top = [...tactics.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([t]) => t);
    findings.push({ kind: "behaviour", text: `${techs.length} technique(s) observed, mostly ${list(top)}; most reported: ${techs[0].node.label}.`, refs: techs.slice(0, 3).map((t) => t.node.id) });
  }
  if (node.type === "technique") {
    const users = [...of("actor"), ...of("campaign"), ...of("malware")];
    if (users.length) findings.push({ kind: "behaviour", text: `Used by ${list(users.map((u) => u.node.label), 4)} in the library.`, refs: users.slice(0, 4).map((u) => u.node.id) });
  }
  if (attack?.newInLibrary?.length) findings.push({ kind: "attack", text: `${attack.newInLibrary.length} observed technique(s) are not in ATT&CK's entry for ${attack.name} — possibly new behaviour: ${list(attack.newInLibrary, 4)}.`, refs: attack.newInLibrary.slice(0, 4).map((t) => `technique:${t}`) });
  const stated = all.filter((l) => l.edge.basis === "stated").length;
  const single = all.filter((l) => l.edge.weight === 1).length;
  if (all.length) findings.push({ kind: "corroboration", text: `${stated} of ${all.length} links are stated in a sentence; ${single} rest on a single report${single / all.length > 0.7 ? " — treat them as leads to confirm" : ""}.`, refs: [] });
  const top = similar.find((s) => !s.linked);
  if (top) findings.push({ kind: "overlap", text: `${top.node.label} shares ${top.shared.length} rare traits (${list(top.shared.map((s) => s.label))}) without a stated link — worth checking.`, refs: [top.node.id, ...top.shared.slice(0, 3).map((s) => s.id)] });

  // Summary paragraph.
  const parts: string[] = [];
  parts.push(`${node.label} (${label}${node.attackId ? `, ATT&CK ${node.attackId}` : ""}) appears in ${node.reportCount} report${node.reportCount === 1 ? "" : "s"}${node.firstSeen ? ` from ${node.firstSeen.slice(0, 10)} to ${node.lastSeen?.slice(0, 10)}` : ""}, with ${all.length} link${all.length === 1 ? "" : "s"}.`);
  if (tooling.length && node.type !== "malware" && node.type !== "tool") parts.push(`Tooling: ${list(tooling.map((t) => t.node.label))}.`);
  if (techs.length) parts.push(`Most reported technique${techs.length > 1 ? "s" : ""}: ${list(techs.map((t) => t.node.label), 2)}.`);
  if (targets.length) parts.push(`Targets: ${list(targets.map((t) => t.node.label))}.`);
  if (related.length) parts.push(`Closely related through shared links: ${list(related.slice(0, 3).map((r) => r.node.label))}.`);
  return { node, links, related, similar, activity, trend, attack, findings, summary: parts.join(" ") };
}

// ---------------------------------------------------------------------------
// Connections between two entities
// ---------------------------------------------------------------------------

export type ConnectionPath = { nodes: GraphNode[]; edges: GraphEdge[]; strength: number; text: string };

/**
 * The strongest short paths between two entities (up to `maxDepth` links), strongest first.
 * Indicators and very common hubs can be passed through, but paths through strong, stated links
 * rank higher. Breadth-first with a frontier cap, so it stays fast on large graphs.
 */
export function connectionPaths(ix: GraphIndex, fromId: string, toId: string, opts: { maxDepth?: number; limit?: number } = {}): ConnectionPath[] {
  if (fromId === toId || !ix.node.has(fromId) || !ix.node.has(toId)) return [];
  const maxDepth = opts.maxDepth ?? 4;
  const limit = opts.limit ?? 5;
  type Step = { id: string; path: string[]; edges: GraphEdge[] };
  const results: Array<{ path: string[]; edges: GraphEdge[] }> = [];
  let frontier: Step[] = [{ id: fromId, path: [fromId], edges: [] }];
  const bestDepth = new Map<string, number>([[fromId, 0]]);
  for (let depth = 1; depth <= maxDepth && frontier.length && results.length < 40; depth++) {
    const next: Step[] = [];
    for (const s of frontier) {
      const out = (ix.adj.get(s.id) ?? []).slice().sort((a, b) => edgeStrength(b) - edgeStrength(a)).slice(0, 60);
      for (const e of out) {
        const nid = otherEnd(e, s.id);
        if (s.path.includes(nid)) continue;
        if (nid === toId) {
          results.push({ path: [...s.path, nid], edges: [...s.edges, e] });
          continue;
        }
        const seen = bestDepth.get(nid);
        if (seen !== undefined && seen < depth) continue;
        bestDepth.set(nid, depth);
        next.push({ id: nid, path: [...s.path, nid], edges: [...s.edges, e] });
      }
    }
    // Keep the strongest partial paths only.
    frontier = next.sort((a, b) => b.edges.reduce((x, e) => x + edgeStrength(e), 0) - a.edges.reduce((x, e) => x + edgeStrength(e), 0)).slice(0, 400);
    if (results.length) break; // shortest paths found; longer ones would only add noise
  }
  return results
    .map((r) => {
      const strength = Math.round((r.edges.reduce((m, e) => Math.min(m, edgeStrength(e)), Infinity) || 0) * 100) / 100;
      const nodes = r.path.map((id) => ix.node.get(id)!);
      const text = nodes
        .map((n, i) => {
          if (i === 0) return n.label;
          const e = r.edges[i - 1];
          const forward = e.source === r.path[i - 1];
          return `${forward ? PREDICATE_LABEL[e.predicate] : `← ${PREDICATE_LABEL[e.predicate]} —`} ${n.label}`;
        })
        .join(" → ");
      return { nodes, edges: r.edges, strength, text };
    })
    .sort((a, b) => b.strength - a.strength)
    .slice(0, limit);
}
