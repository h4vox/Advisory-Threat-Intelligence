/**
 * The intelligence graph: every entity the library knows about, linked by what the reports say.
 *
 * Nodes are entities (actors, campaigns, malware and tools, ATT&CK techniques, vulnerabilities,
 * targeted sectors / regions / platforms, indicators). Reports are not nodes; they are the
 * evidence behind every node and edge.
 *
 * An edge's `basis` says how strong the link is:
 *   - "stated":      a report links the two in one sentence (evidence.relationships);
 *   - "co-reported": both appear as observed facts in the same report.
 * `weight` counts the reports behind the link; `confidence` combines them (0..1).
 */

export type GraphNodeType =
  | "actor"
  | "campaign"
  | "malware"
  | "tool"
  | "technique"
  | "vulnerability"
  | "sector"
  | "geography"
  | "platform"
  | "indicator";

export const GRAPH_NODE_TYPES: GraphNodeType[] = ["actor", "campaign", "malware", "tool", "technique", "vulnerability", "sector", "geography", "platform", "indicator"];

export const NODE_TYPE_LABEL: Record<GraphNodeType, { one: string; many: string }> = {
  actor: { one: "Threat actor", many: "Threat actors" },
  campaign: { one: "Campaign", many: "Campaigns" },
  malware: { one: "Malware", many: "Malware" },
  tool: { one: "Tool", many: "Tools" },
  technique: { one: "Technique", many: "Techniques" },
  vulnerability: { one: "Vulnerability", many: "Vulnerabilities" },
  sector: { one: "Sector", many: "Sectors" },
  geography: { one: "Region", many: "Regions" },
  platform: { one: "Platform", many: "Platforms" },
  indicator: { one: "Indicator", many: "Indicators" },
};

export type GraphPredicate = "uses" | "targets" | "exploits" | "attributed_to" | "indicator_of" | "communicates_with";

export const PREDICATE_LABEL: Record<GraphPredicate, string> = {
  uses: "uses",
  targets: "targets",
  exploits: "exploits",
  attributed_to: "attributed to",
  indicator_of: "indicator of",
  communicates_with: "communicates with",
};

export type GraphNode = {
  /** `${type}:${key}`, e.g. "actor:G0096", "technique:T1566.001", "sector:finance". */
  id: string;
  type: GraphNodeType;
  label: string;
  /** ATT&CK ID when the entity is in ATT&CK (G/S/C/T IDs). */
  attackId?: string;
  /** Technique tactics; indicator kind (domain, ipv4, sha256…). */
  tactics?: string[];
  subtype?: string;
  /** Names it appears under in the reports, other than the label (up to 8). */
  aliases?: string[];
  /** Reports that mention it (newest first, up to 60) and how many there are in all. */
  reports: string[];
  reportCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  /** Number of edges (any filter) — the node's reach. */
  degree: number;
};

export type GraphEdge = {
  id: string;
  /** For directed predicates, source → target reads "source <predicate> target". */
  source: string;
  target: string;
  predicate: GraphPredicate;
  basis: "stated" | "co-reported";
  /** Reports behind the link. */
  weight: number;
  /** Reports that state it in one sentence. */
  stated: number;
  confidence: number;
  /** Supporting reports (newest first, up to 25). */
  reports: string[];
  /** One sentence that states the link, when a report does. */
  quote?: { reportId: string; text: string };
  lastSeen: string | null;
};

export type GraphReportRef = { id: string; title: string; publisher: string; publishedAt: string | null };

export type IntelGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Every report referenced by a node or edge. */
  reports: Record<string, GraphReportRef>;
  stats: { reports: number; nodes: number; edges: number; stated: number; /** Reports skipped because their stored data was malformed. */ skipped?: number;
    /** Entities per type left out of the browser copy (./build clientGraph). */ trimmed?: Partial<Record<GraphNodeType, number>>;
    /** Links in the browser copy (each entity's strongest, plus stated ones); `edges` counts all. */ clientEdges?: number;
    builtAt: string;
  };
};
