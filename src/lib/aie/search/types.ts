/**
 * Shared types for the intelligence search engine (query understanding, hybrid
 * ranking, unified results). Type-only module: safe to import from components.
 */
import type { DocType, SourceTier } from "../types.ts";

export type QueryEntityKind = "group" | "software" | "campaign" | "technique";

/** A structured field the query syntax understands. */
export type QueryField =
  | "actor"
  | "malware"
  | "campaign"
  | "technique"
  | "tactic"
  | "cve"
  | "type"
  | "tier"
  | "publisher"
  | "since"
  | "until"
  | "has";

export type HasFlag = "iocs" | "emulation" | "evidence";

export type Span = { start: number; end: number };

/** One lexical clause of the raw query. */
export type QueryClause =
  | { type: "word"; value: string; negated: boolean; span: Span }
  | { type: "phrase"; value: string; negated: boolean; span: Span }
  | { type: "field"; field: QueryField; value: string; negated: boolean; span: Span; rawField: string };

export type ParsedQuery = {
  raw: string;
  clauses: QueryClause[];
  /** Problems the parser noticed (bad date, unknown type…), shown to the analyst. */
  warnings: string[];
};

/** A canonical ATT&CK entity the query refers to. */
export type QueryEntity = {
  kind: QueryEntityKind;
  id: string;
  name: string;
  /** Surface form in the query ("Cozy Bear"). */
  matched: string;
  /** All known names for retrieval (name + aliases). */
  aliases: string[];
  /** "field" = actor:/malware:/campaign:/technique: (a filter); "implicit" = detected in free text (a boost). */
  source: "field" | "implicit";
  negated?: boolean;
  span?: Span;
};

export type QueryTechnique = {
  id: string;
  name: string;
  matched: string;
  tactics: string[];
  /** How the technique was recognised. */
  via: "id" | "name" | "synonym" | "token-cover" | "field";
  /** Parent and sub-technique ids that also count (with reduced weight). */
  related: string[];
  source: "field" | "implicit";
  negated?: boolean;
  span?: Span;
};

export type InterpretedChipKind =
  | "actor"
  | "software"
  | "campaign"
  | "technique"
  | "tactic"
  | "cve"
  | "type"
  | "tier"
  | "publisher"
  | "date"
  | "has"
  | "phrase"
  | "exclude"
  | "text";

/** A removable "Interpreted as" chip. `without` is the query with this clause removed / un-interpreted. */
export type InterpretedChip = {
  key: string;
  kind: InterpretedChipKind;
  label: string;
  detail?: string;
  implicit: boolean;
  negated?: boolean;
  without: string;
};

export type InterpretedQuery = {
  raw: string;
  /** Free-text retrieval terms (tokenized, stopwords removed). */
  terms: string[];
  /** Terms that were recognised as an entity / technique / tactic (not plain keywords). */
  consumedTerms: string[];
  /** Required literal phrases. */
  phrases: string[];
  /** Excluded words / phrases. */
  excluded: string[];
  entities: QueryEntity[];
  techniques: QueryTechnique[];
  tactics: Array<{ name: string; source: "field" | "implicit" }>;
  cves: string[];
  /** CVEs given with cve: (a filter, not only a boost). */
  requiredCves: string[];
  /** Hard document-type filter (type:). */
  docTypes: DocType[];
  /** Doc types implied by free-text words ("advisory", "dfir"); a boost, not a filter. */
  docTypeIntent: DocType[];
  excludedDocTypes: DocType[];
  tiers: SourceTier[];
  publishers: string[];
  excludedPublishers: string[];
  since?: string;
  until?: string;
  has: HasFlag[];
  /** Field values that did not resolve to ATT&CK (still matched as text). */
  unresolved: Array<{ field: QueryField; value: string; negated?: boolean }>;
  warnings: string[];
  chips: InterpretedChip[];
  /** "actor APT29 (G0016) · since 2025" */
  summary: string;
  /** True when nothing beyond filters was asked (list by filters only). */
  filterOnly: boolean;
};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

export type SearchResultKind = "report" | "group" | "software" | "campaign" | "technique" | "emulation" | "vulnerability";

export type SearchGroupKey = "all" | "reports" | "actors" | "techniques" | "software" | "campaigns" | "emulation" | "vulnerabilities";

export type ScorePart = { key: string; label: string; value: number };

export type MatchedEntity = {
  kind: QueryEntityKind;
  id: string;
  name: string;
  /** The alias / name the document uses ("UNC3944"). */
  via: string;
  /** What the query said ("Octo Tempest"). */
  queryForm: string;
  /** self = this card is the entity; uses = ATT&CK link (group uses software…); mention = named in the document. */
  rel?: "self" | "uses" | "mention";
};

export type ResultWhy = {
  matchedFields: string[];
  matchedTerms: string[];
  matchedEntities: MatchedEntity[];
  matchedTechniques: Array<{ id: string; name: string; relation: "exact" | "parent" | "sub" }>;
  matchedIds: string[];
  docTypeIntent?: DocType[];
  breakdown: ScorePart[];
  score: number;
};

export type SearchResult = {
  id: string;
  kind: SearchResultKind;
  title: string;
  subtitle?: string;
  /** Best passage, whitespace-collapsed. */
  snippet?: string;
  /** Strings to highlight in the snippet. */
  highlights: string[];
  href: { to: string; params?: Record<string, string>; search?: Record<string, string> };
  docTypes: DocType[];
  publisher?: string;
  publishedAt?: string | null;
  tier?: SourceTier;
  entities: Array<{ kind: "actor" | "malware" | "technique" | "cve" | "emulation"; label: string; id?: string }>;
  score: number;
  why: ResultWhy;
  /** Near-duplicates collapsed into this result. */
  duplicates?: Array<{ id: string; title: string; publisher?: string }>;
  /** Pivot search ("Reports using T1003.001"). */
  pivot?: { label: string; q: string };
  /** Authoritative external page (ATT&CK, NVD, source URL). */
  externalUrl?: string;
  /** Free-form counts for knowledge cards ("techniques: 54"). */
  stats?: Array<{ label: string; value: string | number }>;
};

export type FacetBucket = { value: string; label: string; count: number };

export type SearchFacets = {
  docType: FacetBucket[];
  tier: FacetBucket[];
  publisher: FacetBucket[];
  actor: FacetBucket[];
  year: FacetBucket[];
};

export type SearchFilters = {
  docTypes?: string[];
  tiers?: string[];
  publishers?: string[];
  actors?: string[];
  years?: string[];
};

export type SearchResponse = {
  interpreted: InterpretedQuery;
  group: SearchGroupKey;
  counts: Record<SearchGroupKey, number>;
  results: SearchResult[];
  total: number;
  facets: SearchFacets;
  /** Where results came from, for honest empty states. */
  sources: {
    persistence: "mongodb" | "local";
    reportsSearched: number;
    knowledge: { version: string | null; groups: number; software: number; campaigns: number; techniques: number };
    emulation: "synced" | "not_synced" | "unavailable";
    kev: "synced" | "not_synced" | "unavailable";
  };
  tookMs: number;
};

export type EntitySuggestion = {
  kind: QueryEntityKind | "tactic" | "type";
  id: string;
  name: string;
  /** Alias that matched the prefix, when not the name. */
  alias?: string;
  /** Text to insert into the query. */
  insert: string;
};
