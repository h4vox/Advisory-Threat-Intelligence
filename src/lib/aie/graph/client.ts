/**
 * Browser-side helpers for the graph copy the server sends (./build clientGraph). Kept apart from
 * the builder so the page does not bundle the ATT&CK knowledge base.
 */
import type { IntelGraph } from "./types.ts";

/** Restores edge ids dropped for transport (`source|predicate|target`). */
export function withEdgeIds(graph: IntelGraph): IntelGraph {
  for (const e of graph.edges) if (!e.id) e.id = `${e.source}|${e.predicate}|${e.target}`;
  return graph;
}
