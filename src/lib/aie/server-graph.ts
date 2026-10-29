/**
 * Intelligence graph server functions: the whole graph (built from the library, cached for a
 * minute) and an AI brief for one entity (./graph).
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { logger } from "./logger";
import { listReports } from "./server";
import { getThreatIntelCollection, isMongoConfigured } from "../mongodb/client.server";
import { buildIntelGraph, type GraphSourceReport } from "./graph/build";
import { connections, indexGraph, searchNodes, similarEntities } from "./graph/analyze";
import { connectionPaths, entityContext, resolveRef, type ConnectionPath, type EntityContext } from "./graph/correlate";
import { BRIEF_SYSTEM, buildBriefPrompt, engineBrief, parseBrief, type GraphBrief } from "./graph/brief";
import type { GraphNode, GraphReportRef, IntelGraph } from "./graph/types";

const CACHE_MS = 60_000;
const MAX_REPORTS = 10_000;

let cache: { at: number; graph: IntelGraph } | null = null;

/** AI briefs per entity, for 10 minutes or until the graph is rebuilt. */
const BRIEF_CACHE_MS = 10 * 60_000;
const briefCache = new Map<string, { at: number; builtAt: string; brief: GraphBrief }>();
let inflight: Promise<IntelGraph> | null = null;

/** Only the fields the graph reads (no report text, HTML or PDF). */
const GRAPH_PROJECTION = {
  _id: 0,
  id: 1,
  title: 1,
  publisher: 1,
  sourceName: 1,
  publishedAt: 1,
  ingestedAt: 1,
  status: 1,
  discoveryMethod: 1,
  iocs: 1,
  analysis: 1,
  extractedEntities: 1,
  "aiAnalysis.adversary": 1,
  "aiAnalysis.attackChain.technique": 1,
  "aiAnalysis.attackChain.stage": 1,
} as const;

async function loadReports(): Promise<GraphSourceReport[]> {
  if (isMongoConfigured()) {
    const col = await getThreatIntelCollection();
    return (await col
      .find({ docType: "report", status: { $nin: ["duplicate", "rejected", "failed"] }, discoveryMethod: { $ne: "structured_sync" } })
      .project(GRAPH_PROJECTION)
      .limit(MAX_REPORTS)
      .toArray()) as unknown as GraphSourceReport[];
  }
  const out: GraphSourceReport[] = [];
  for (let offset = 0; offset < MAX_REPORTS; offset += 500) {
    const page = await listReports({ data: { limit: 500, offset } });
    out.push(...(page as unknown as GraphSourceReport[]));
    if (page.length < 500) break;
  }
  return out;
}

async function getGraph(): Promise<IntelGraph> {
  if (cache && Date.now() - cache.at < CACHE_MS) return cache.graph;
  inflight ??= (async () => {
    const started = Date.now();
    try {
      const reports = await loadReports();
      const graph = buildIntelGraph(reports);
      cache = { at: Date.now(), graph };
      logger.intel("GRAPH", `Built from ${graph.stats.reports} reports: ${graph.stats.nodes} entities, ${graph.stats.edges} links (${graph.stats.stated} stated)`, {
        loaded: reports.length,
        skipped: graph.stats.skipped ?? 0,
        ms: Date.now() - started,
      });
      if (graph.stats.skipped) logger.warn("INTEL", `${graph.stats.skipped} report(s) skipped: their stored analysis is malformed`);
      return graph;
    } catch (err) {
      logger.error("INTEL", "Graph build failed", err);
      throw err;
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

export const getIntelGraph = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async (): Promise<IntelGraph> => getGraph());

export const explainGraphNode = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ nodeId: z.string().min(3).max(400), refresh: z.boolean().optional() }))
  .handler(async ({ data }): Promise<GraphBrief> => {
    const graph = await getGraph();
    const ix = indexGraph(graph);
    const node = ix.node.get(data.nodeId);
    if (!node) throw new Error("That entity is no longer in the graph. Reload the page.");
    const cached = briefCache.get(node.id);
    if (!data.refresh && cached && Date.now() - cached.at < BRIEF_CACHE_MS && cached.builtAt === graph.stats.builtAt) {
      logger.intel("BRIEF", `Cached brief for ${node.label}`, { source: cached.brief.source });
      return cached.brief;
    }
    const facts = {
      node,
      links: connections(ix, node.id).slice(0, 40),
      similar: similarEntities(ix, node.id, 6),
      reports: node.reports.slice(0, 15).map((id) => graph.reports[id]).filter(Boolean),
    };
    const started = Date.now();
    let reason = "";
    const { runUnifiedJsonTask } = await import("./ai-manager");
    // Two tries with a short pause; then the engine answers on its own.
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const { parsed, provider } = await runUnifiedJsonTask({ system: BRIEF_SYSTEM, prompt: buildBriefPrompt(facts), maxTokens: 2048, timeoutSeconds: 90 });
        const brief = parseBrief(parsed, facts, provider);
        if (!brief.summary && !brief.points.length) throw new Error("the AI answer had no usable, cited content");
        logger.intel("BRIEF", `AI brief for ${node.label}`, { provider, attempt, points: brief.points.length, dropped: brief.dropped, ms: Date.now() - started });
        briefCache.set(node.id, { at: Date.now(), builtAt: graph.stats.builtAt, brief });
        return brief;
      } catch (err) {
        reason = err instanceof Error ? err.message : String(err);
        logger.warn("INTEL", `AI brief attempt ${attempt} for ${node.label} failed: ${reason}`);
        if (attempt === 1) await new Promise((r) => setTimeout(r, 1500));
      }
    }
    const ctx = entityContext(ix, node.id)!;
    const brief = engineBrief(ctx, `The AI was not available (${reason}); this assessment is the engine's own, computed from the library.`);
    logger.intel("BRIEF", `Engine brief for ${node.label} (AI unavailable)`, { reason, ms: Date.now() - started });
    briefCache.set(node.id, { at: Date.now() - BRIEF_CACHE_MS + 60_000, builtAt: graph.stats.builtAt, brief });
    return brief;
  });

/** Everything correlated with one entity, by name, alias, ATT&CK ID, CVE, indicator or node id. */
export const getEntityContext = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ ref: z.string().trim().min(1).max(400) }))
  .handler(async ({ data }): Promise<{ context: EntityContext | null; reports: Record<string, GraphReportRef>; suggestions: Array<{ id: string; label: string; type: string }> }> => {
    const started = Date.now();
    const graph = await getGraph();
    const ix = indexGraph(graph);
    const node = resolveRef(ix, data.ref);
    if (!node) {
      const suggestions = searchNodes(ix, data.ref, 6).map((n) => ({ id: n.id, label: n.label, type: n.type }));
      logger.intel("CONTEXT", `No entity for "${data.ref}"`, { suggestions: suggestions.length });
      return { context: null, reports: {}, suggestions };
    }
    const context = entityContext(ix, node.id)!;
    const ids = new Set<string>(node.reports.slice(0, 30));
    for (const g of context.links) for (const l of g.items) for (const r of l.edge.reports.slice(0, 3)) ids.add(r);
    const reports: Record<string, GraphReportRef> = {};
    for (const id of ids) if (graph.reports[id]) reports[id] = graph.reports[id];
    logger.intel("CONTEXT", `${node.label} (${node.type})`, { links: context.links.reduce((n, g) => n + g.total, 0), related: context.related.length, findings: context.findings.length, ms: Date.now() - started });
    return { context, reports, suggestions: [] };
  });

/** How two entities are connected: the strongest short paths between them. */
export const findConnection = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ from: z.string().trim().min(1).max(400), to: z.string().trim().min(1).max(400) }))
  .handler(async ({ data }): Promise<{ from: GraphNode | null; to: GraphNode | null; paths: ConnectionPath[] }> => {
    const ix = indexGraph(await getGraph());
    const from = resolveRef(ix, data.from);
    const to = resolveRef(ix, data.to);
    const paths = from && to ? connectionPaths(ix, from.id, to.id) : [];
    logger.intel("PATH", `${from?.label ?? data.from} → ${to?.label ?? data.to}: ${paths.length} path(s)`);
    return { from, to, paths };
  });
