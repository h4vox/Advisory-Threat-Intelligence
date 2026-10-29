/**
 * Intelligence graph server functions: the whole graph (built from the library, cached for a
 * minute) and an AI brief for one entity (./graph).
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { listReports } from "./server";
import { getThreatIntelCollection, isMongoConfigured } from "../mongodb/client.server";
import { buildIntelGraph, type GraphSourceReport } from "./graph/build";
import { connections, indexGraph, similarEntities } from "./graph/analyze";
import { BRIEF_SYSTEM, buildBriefPrompt, parseBrief, type GraphBrief } from "./graph/brief";
import type { IntelGraph } from "./graph/types";

const CACHE_MS = 60_000;
const MAX_REPORTS = 10_000;

let cache: { at: number; graph: IntelGraph } | null = null;
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
    try {
      const graph = buildIntelGraph(await loadReports());
      cache = { at: Date.now(), graph };
      return graph;
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
  .validator(z.object({ nodeId: z.string().min(3).max(400) }))
  .handler(async ({ data }): Promise<GraphBrief> => {
    const graph = await getGraph();
    const ix = indexGraph(graph);
    const node = ix.node.get(data.nodeId);
    if (!node) throw new Error("That entity is no longer in the graph. Reload the page.");
    const facts = {
      node,
      links: connections(ix, node.id).slice(0, 40),
      similar: similarEntities(ix, node.id, 6),
      reports: node.reports.slice(0, 15).map((id) => graph.reports[id]).filter(Boolean),
    };
    const { runUnifiedJsonTask } = await import("./ai-manager");
    try {
      const { parsed, provider } = await runUnifiedJsonTask({ system: BRIEF_SYSTEM, prompt: buildBriefPrompt(facts), maxTokens: 2048, timeoutSeconds: 90 });
      return parseBrief(parsed, facts, provider);
    } catch (err) {
      throw new Error(`AI brief failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  });
