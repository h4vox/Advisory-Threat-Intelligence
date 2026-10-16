/**
 * Shared building blocks for structured-source connectors.
 *
 * Connectors are pure parsers (input text/JSON → documents) plus a thin fetch
 * layer (fetch.ts). Documents are ReportRecord-compatible so they live in the
 * same library as crawled reports, carry `docTypes`, `sourceTier`,
 * `sourceConfidence` and a typed `structured` payload, and are keyed by a
 * stable id (att_G0016, art_T1059.001, ctid_fin6, af_<slug>, …) so a re-sync
 * overwrites instead of duplicating.
 *
 * No path aliases: this file runs under `node --test` directly.
 */
import type {
  DocType,
  EmulationOption,
  ExtractedEntities,
  IntelAnalysis,
  QualityReason,
  ReportRecord,
  ResourceKind,
  SourceConfidenceClass,
  SourceTier,
  StructuredIntel,
} from "../types.ts";
import { SOURCE_CONFIDENCE } from "../types.ts";
import { sha256Hex } from "../extract.ts";

/** The slice of a registry source a connector needs. */
export type ConnectorSource = {
  id: string;
  name: string;
  tier: SourceTier;
  confidenceClass: SourceConfidenceClass;
  connectorConfig?: Record<string, string>;
};

export type TechniqueRef = { id: string; name: string; tactic?: string };
export type TechniqueLookup = (id: string) => TechniqueRef | null;

/** One technique's emulation options from one source kind (stored as an index row). */
export type EmulationIndexEntry = {
  techniqueId: string;
  kind: EmulationOption["kind"];
  sourceId: string;
  options: EmulationOption[];
};

export type KevEntry = {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  dueDate?: string;
  ransomwareUse?: string;
  requiredAction?: string;
  shortDescription?: string;
  notes?: string;
  cwes?: string[];
};

export type AttackTechniqueIndexEntry = {
  id: string;
  name: string;
  tactics: string[];
  platforms: string[];
  dataSources: string[];
  isSubtechnique: boolean;
  url: string;
  description?: string;
};

export type ConnectorResult = {
  docs: ReportRecord[];
  emulation: EmulationIndexEntry[];
  kev?: KevEntry[];
  techniques?: AttackTechniqueIndexEntry[];
  /** Human-readable counts, e.g. { groups: 180, software: 830 }. */
  stats: Record<string, number>;
  /** Non-fatal problems (skipped files, partial listings). */
  warnings: string[];
};

export const TECHNIQUE_ID_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

/** Unique ATT&CK technique ids in text, in first-seen order. */
export function techniqueIdsIn(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(TECHNIQUE_ID_RE)) {
    const id = m[0].toUpperCase();
    if (!seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

export function slugify(input: string, max = 64): string {
  return (
    input
      .toLowerCase()
      .normalize("NFKD")
      .replace(/[̀-ͯ]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, max)
      .replace(/-+$/g, "") || "item"
  );
}

export function uniq<T>(items: Iterable<T>): T[] {
  return Array.from(new Set(items));
}

/** Strips ATT&CK citation markers "(Citation: X)" and markdown links to plain text. */
export function cleanAttackText(input: string | undefined): string {
  if (!input) return "";
  return input
    .replace(/\(Citation:[^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\((?:[^)]+)\)/g, "$1")
    .replace(/<\/?code>/g, "")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

const DOC_TYPE_TO_RESOURCE_KIND: Partial<Record<DocType, ResourceKind>> = {
  MITRE_GROUP: "THREAT_ACTOR_DOSSIER",
  MITRE_CAMPAIGN: "CAMPAIGN_INTEL",
  MITRE_SOFTWARE: "MALWARE_ANALYSIS",
  ADVERSARY_EMULATION_PLAN: "PROCEDURE_DEEPDIVE",
  MICRO_EMULATION_PLAN: "PROCEDURE_DEEPDIVE",
  ATOMIC_TEST: "PROCEDURE_DEEPDIVE",
  CALDERA_ABILITY: "PROCEDURE_DEEPDIVE",
  ATTACK_FLOW: "FULL_ATTACK_CHAIN",
  KEV_ENTRY: "VULNERABILITY_ADVISORY",
  THREAT_REPORT: "CAMPAIGN_INTEL",
};

export type StructuredDocInput = {
  id: string;
  source: ConnectorSource;
  docTypes: DocType[];
  title: string;
  url: string;
  text: string;
  publishedAt?: string | null;
  structured?: StructuredIntel;
  techniques?: string[];
  actors?: string[];
  malware?: string[];
  cves?: string[];
  campaign?: string | null;
  emulation?: string[];
  contentType?: string;
  publisher?: string;
  author?: string;
  tags?: string[];
  /** Fetch timestamp (injected for deterministic tests). */
  now?: string;
  lookup?: TechniqueLookup;
};

/**
 * Structural completeness of a structured record (0..1): techniques and
 * descriptive text are what make it useful for emulation planning.
 */
function completeness(input: StructuredDocInput): { score: number; reasons: QualityReason[] } {
  const reasons: QualityReason[] = [];
  let score = 0.55;
  const techCount = input.techniques?.length ?? 0;
  if (techCount > 0) {
    const bonus = Math.min(0.3, 0.05 + techCount * 0.01);
    score += bonus;
    reasons.push({ label: `${techCount} ATT&CK technique${techCount === 1 ? "" : "s"} from structured data`, delta: Math.round(bonus * 100) });
  } else {
    reasons.push({ label: "No technique mappings in the structured record", delta: 0 });
  }
  const words = input.text.split(/\s+/).filter(Boolean).length;
  if (words >= 120) {
    score += 0.15;
    reasons.push({ label: `Descriptive text (${words} words)`, delta: 15 });
  } else if (words >= 40) {
    score += 0.08;
    reasons.push({ label: `Short description (${words} words)`, delta: 8 });
  }
  return { score: Math.min(1, score), reasons };
}

/** Builds a ReportRecord for a structured-source document. */
export function buildStructuredReport(input: StructuredDocInput): ReportRecord {
  const now = input.now ?? new Date().toISOString();
  const confidenceWeight = SOURCE_CONFIDENCE[input.source.confidenceClass] ?? SOURCE_CONFIDENCE.UNKNOWN;
  const { score, reasons } = completeness(input);
  const qualityScore = Math.round(score * 100);
  const sourceConfidence = Math.round(confidenceWeight * score * 100) / 100;
  const qualityReasons: QualityReason[] = [
    { label: `Structured source: ${input.source.name} (tier ${input.source.tier})`, delta: 0 },
    ...reasons,
    {
      label: `Source confidence ${input.source.confidenceClass} ×${confidenceWeight.toFixed(2)} × quality ${score.toFixed(2)} = ${sourceConfidence.toFixed(2)}`,
      delta: 0,
    },
  ];

  const lookup = input.lookup;
  const techniqueIds = uniq((input.techniques ?? []).map((t) => t.toUpperCase()));
  const techniqueRefs = techniqueIds.map((id) => {
    const ref = lookup?.(id);
    return { id, name: ref?.name ?? id, tactic: ref?.tactic ?? "" };
  });
  const extractedEntities: ExtractedEntities = {
    threatActors: uniq(input.actors ?? []),
    malwareFamilies: uniq(input.malware ?? []),
    cves: uniq(input.cves ?? []),
    tactics: uniq(techniqueRefs.map((t) => t.tactic).filter(Boolean)),
    techniques: techniqueRefs,
    procedures: [],
    detectionRules: [],
    mitigations: [],
    campaign: input.campaign ?? null,
  };
  const primary = input.docTypes[0] ?? "OTHER";
  // Reference records keep their entities in extractedEntities + structured.
  // The analysis lists stay empty on purpose: dashboards aggregate analysis.*
  // as *observed* activity, and 1,000+ ATT&CK reference records would
  // otherwise drown the actors/TTPs actually reported in the library.
  const analysis: IntelAnalysis = {
    method: "heuristic",
    classification: primary,
    threatActors: [],
    malware: [],
    vulnerabilities: [],
    ttps: [],
    ioas: [],
    attackChain: [],
    detections: [],
    hunting: [],
    emulation: input.emulation ?? [],
  };
  let domain = "";
  try {
    domain = new URL(input.url).hostname.replace(/^www\./, "");
  } catch {
    domain = "";
  }
  const textHash = sha256Hex(input.text);
  const rawHash = sha256Hex(JSON.stringify(input.structured ?? null) + "\n" + input.text);
  const wordCount = input.text.split(/\s+/).filter(Boolean).length;

  return {
    id: input.id,
    sourceId: input.source.id,
    sourceName: input.source.name,
    title: input.title,
    url: input.url,
    canonicalUrl: input.url,
    publishedAt: input.publishedAt ?? null,
    contentType: input.contentType ?? "application/json",
    status: "acquired",
    rawHash,
    textHash,
    qualityScore,
    qualityReasons,
    wordCount,
    extractedText: input.text,
    iocs: [],
    ingestOrigin: "crawl",
    ingestedAt: now,
    discoveryMethod: "structured_sync",
    discoveryQuery: "",
    parentSource: input.source.name,
    publisher: input.publisher ?? input.source.name,
    author: input.author ?? input.source.name,
    classification: primary,
    resourceKind: DOC_TYPE_TO_RESOURCE_KIND[primary],
    docTypes: input.docTypes,
    sourceTier: input.source.tier,
    sourceConfidence,
    structured: input.structured,
    extractedEntities,
    sourceDomain: domain,
    version: 1,
    analysis,
    tags: input.tags,
    aiVerified: false,
    aiAuditReason: "Structured source record — not evaluated by an AI model.",
  };
}

/** Runs async work over items with bounded concurrency, preserving order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}
