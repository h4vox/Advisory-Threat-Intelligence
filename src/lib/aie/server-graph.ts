/**
 * Intelligence graph server functions: the whole graph (built from the library and rebuilt in the
 * background when the library changes), entity context, paths and AI briefs (./graph).
 */
import { intelCoverage, type IntelCoverageStatus } from "../mongodb/intel-refresh-repo.server";
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { logger } from "./logger";
import { listReports } from "./server";
import { getThreatIntelCollection, isMongoConfigured } from "../mongodb/client.server";
import { buildIntelGraph, clientGraph, type GraphSourceReport } from "./graph/build";
import { connections, indexGraph, searchNodes, similarEntities, type GraphIndex } from "./graph/analyze";
import { connectionPaths, entityContext, resolveRef, type ConnectionPath, type EntityContext } from "./graph/correlate";
import { BRIEF_SYSTEM, buildBriefPrompt, engineBrief, parseBrief, type GraphBrief } from "./graph/brief";
import type { GraphNode, GraphReportRef, IntelGraph } from "./graph/types";

const MAX_REPORTS = 10_000;

let cache: Built | null = null;

/** AI briefs per entity, for 10 minutes or until the graph is rebuilt. */
const BRIEF_CACHE_MS = 10 * 60_000;
const briefCache = new Map<string, { at: number; builtAt: string; brief: GraphBrief }>();
let inflight: Promise<Built> | null = null;

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
  "aiAnalysis.iocs": 1,
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

type Built = { at: number; graph: IntelGraph; ix: GraphIndex; clientJson: string };

/** Builds the graph, its index and the browser copy (as ready-to-send JSON) together. */
function rebuild(): Promise<Built> {
  inflight ??= (async () => {
    const started = Date.now();
    try {
      const version = await readLibraryVersion();
      const reports = await loadReports();
      const graph = buildIntelGraph(reports);
      const ix = indexGraph(graph);
      const copy = clientGraph(graph);
      const clientJson = JSON.stringify(copy);
      cache = { at: Date.now(), graph, ix, clientJson };
      libraryVersion = { checkedAt: Date.now(), value: version, builtFor: version };
      logger.intel("GRAPH", `Built from ${graph.stats.reports} reports: ${graph.stats.nodes} entities, ${graph.stats.edges} links (${graph.stats.stated} stated)`, {
        loaded: reports.length,
        skipped: graph.stats.skipped ?? 0,
        browserCopy: { entities: copy.nodes.length, links: copy.edges.length, mb: Math.round(clientJson.length / 1e5) / 10, trimmed: copy.stats.trimmed ?? {} },
        ms: Date.now() - started,
      });
      if (graph.stats.skipped) logger.warn("INTEL", `${graph.stats.skipped} report(s) skipped: their stored analysis is malformed`);
      return cache;
    } catch (err) {
      logger.error("INTEL", "Graph build failed", err);
      throw err;
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

/**
 * The current graph. A fresh one is built on first use; when the library changes (or after
 * MAX_AGE_MS) the current one is still served at once while a newer one builds in the background.
 */
async function getBuilt(): Promise<Built> {
  if (!cache) return rebuild();
  // Without a library version (no MongoDB) rebuild every two minutes instead.
  const maxAge = libraryVersion.builtFor === null ? 2 * 60_000 : MAX_AGE_MS;
  if (!inflight && (Date.now() - cache.at >= maxAge || (await libraryChanged()))) {
    rebuild().catch(() => {
      /* logged in rebuild; the previous graph keeps serving */
    });
  }
  return cache;
}

/**
 * The library's version: report count, newest ingestion and newest AI analysis. Checked at most
 * every VERSION_CHECK_MS (one small aggregate), so new ingestion, re-analysis or removed reports
 * reach the graph within seconds instead of on a fixed schedule.
 */
const VERSION_CHECK_MS = 15_000;
/** Rebuild anyway after this long (changes the version cannot see, e.g. edited analyses). */
const MAX_AGE_MS = 10 * 60_000;
let libraryVersion: { checkedAt: number; value: string | null; builtFor: string | null } = { checkedAt: 0, value: null, builtFor: null };

async function readLibraryVersion(): Promise<string | null> {
  if (!isMongoConfigured()) return null;
  try {
    const col = await getThreatIntelCollection();
    const [v] = await col
      .aggregate([
        { $match: { docType: "report", status: { $nin: ["duplicate", "rejected", "failed"] } } },
        {
          $group: {
            _id: null,
            n: { $sum: 1 },
            ing: { $max: "$ingestedAt" },
            ai: { $max: "$aiAnalysis.analysedAt" },
            rev: { $max: "$review.reviewedAt" },
          },
        },
      ])
      .toArray();
    // Re-extracted intel (mongodb/intel-refresh-repo) reaches the graph with the regular rebuild
    // (MAX_AGE_MS): a full rebuild takes seconds of CPU and must not follow every refresh batch.
    return v ? `${v.n}|${v.ing ?? ""}|${v.ai ?? ""}|${v.rev ?? ""}` : "0";
  } catch {
    return null;
  }
}

async function libraryChanged(): Promise<boolean> {
  if (Date.now() - libraryVersion.checkedAt < VERSION_CHECK_MS) return false;
  libraryVersion.checkedAt = Date.now();
  const value = await readLibraryVersion();
  libraryVersion.value = value;
  if (value === null || libraryVersion.builtFor === null) return false;
  if (value !== libraryVersion.builtFor) {
    logger.intel("GRAPH", "Library changed (new or re-analysed reports): rebuilding in the background");
    return true;
  }
  return false;
}

/** What the open graph page polls: which build it has, and whether a newer one exists. */
export const getGraphVersion = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async (): Promise<{ builtAt: string | null; building: boolean; nodes: number; edges: number; reports: number }> => {
    const b = cache ? await getBuilt() : null;
    return { builtAt: b?.graph.stats.builtAt ?? null, building: Boolean(inflight), nodes: b?.graph.stats.nodes ?? 0, edges: b?.graph.stats.edges ?? 0, reports: b?.graph.stats.reports ?? 0 };
  });

/** How much of the library the extraction layers cover (rules, AI) and how many reports the graph maps. */
export const getMappingCoverage = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async (): Promise<IntelCoverageStatus & { mapped: number }> => {
    const [c, b] = await Promise.all([intelCoverage(), cache ? getBuilt().catch(() => null) : Promise.resolve(null)]);
    return { ...c, mapped: b?.graph.stats.reports ?? 0 };
  });

/** The browser copy (./graph/build clientGraph), as JSON prepared once per build. */
export const getIntelGraph = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async (): Promise<string> => (await getBuilt()).clientJson);

/** Entities matching a search, over the full graph (the browser copy leaves some out). */
export const searchGraphEntities = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .validator(z.object({ q: z.string().trim().min(1).max(200) }))
  .handler(async ({ data }): Promise<GraphNode[]> => {
    const { ix } = await getBuilt();
    const exact = resolveRef(ix, data.q);
    const list = searchNodes(ix, data.q, 12);
    return exact && !list.some((n) => n.id === exact.id) ? [exact, ...list.slice(0, 11)] : list;
  });

export const explainGraphNode = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ nodeId: z.string().min(3).max(400), refresh: z.boolean().optional() }))
  .handler(async ({ data }): Promise<GraphBrief> => {
    const { graph, ix } = await getBuilt();
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
    const { graph, ix } = await getBuilt();
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
    const { ix } = await getBuilt();
    const from = resolveRef(ix, data.from);
    const to = resolveRef(ix, data.to);
    const paths = from && to ? connectionPaths(ix, from.id, to.id) : [];
    logger.intel("PATH", `${from?.label ?? data.from} → ${to?.label ?? data.to}: ${paths.length} path(s)`);
    return { from, to, paths };
  });
