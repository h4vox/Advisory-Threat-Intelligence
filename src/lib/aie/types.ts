import type { ResearchDiscoveryConfig, ResearchLabels } from "./research-taxonomy.ts";
import type { TelemetryRefs } from "./telemetry-refs.ts";
import type { PublishedDate } from "./published-date.ts";
import type { ReportAiAnalysis } from "./report-ai-analysis.ts";

export type TrustLevel = "high" | "official" | "community" | "reputable" | "unverified";

export type SourceRecord = {
  id: string;
  name: string;
  slug: string;
  category: string;
  priority: number;
  homepageUrl: string;
  crawlPattern?: string;
  feedUrl?: string;
  researchArchives?: string[];
  paginationPattern?: string;
  sitemapUrl?: string;
  enabled: boolean;
  trustLevel: TrustLevel;
  notes: string;
  lastIngestAt: string | null;
  resourceCount?: number;
  isCurated?: boolean;
  isDiscovered?: boolean;
  discoveredAt?: string;
  discoveredByJobId?: string;
  parentSourceDomain?: string;
  origin?: "seed" | "agent_discovery" | "crawler_outlink" | "manual";
  /** Source tier (1 structured/authoritative … 4 community); drives confidence. */
  tier?: SourceTier;
  /** How the source is acquired (preferred: API/Git/STIX over RSS over HTML). */
  connector?: ConnectorType;
  /** Document types this source primarily yields. */
  yields?: DocType[];
  /** Structured connector config (repo, branch, path, feed URL…). */
  connectorConfig?: Record<string, string>;
  /** Last successful structured sync and item count. */
  lastSyncAt?: string | null;
  lastSyncCount?: number;
  lastSyncError?: string | null;
};

// ---------------------------------------------------------------------------
// Advisory / emulation intelligence taxonomy (AIE Web Extraction spec §26)
// ---------------------------------------------------------------------------

/** First-class document types. A document can carry several. */
export type DocType =
  | "THREAT_REPORT"
  | "THREAT_ADVISORY"
  | "INCIDENT_REPORT"
  | "DFIR_REPORT"
  | "MALWARE_REPORT"
  | "VULNERABILITY_ADVISORY"
  | "CAMPAIGN_REPORT"
  | "MITRE_GROUP"
  | "MITRE_SOFTWARE"
  | "MITRE_CAMPAIGN"
  | "MITRE_TECHNIQUE"
  | "ADVERSARY_EMULATION_PLAN"
  | "MICRO_EMULATION_PLAN"
  | "ATTACK_FLOW"
  | "ATOMIC_TEST"
  | "CALDERA_ABILITY"
  | "PURPLE_TEAM_REPORT"
  | "DETECTION_RESEARCH"
  | "THREAT_HUNTING_REPORT"
  | "KEV_ENTRY"
  | "OTHER";

/** Spec §66 tiers: 1 structured/authoritative, 2 emulation, 3 high-quality research, 4 community. */
export type SourceTier = 1 | 2 | 3 | 4;

/** Spec §42 source confidence classes. */
export type SourceConfidenceClass =
  | "OFFICIAL_PRIMARY"
  | "TRUSTED_VENDOR"
  | "RESEARCH_ORG"
  | "SECONDARY_RESEARCH"
  | "COMMUNITY"
  | "UNKNOWN";

export const SOURCE_CONFIDENCE: Record<SourceConfidenceClass, number> = {
  OFFICIAL_PRIMARY: 1.0,
  TRUSTED_VENDOR: 0.9,
  RESEARCH_ORG: 0.9,
  SECONDARY_RESEARCH: 0.75,
  COMMUNITY: 0.6,
  UNKNOWN: 0.3,
};

/** Acquisition mechanism (spec §15 priority: API > Git > STIX/TAXII > file > RSS > HTML > search). */
export type ConnectorType =
  | "stix_bundle"
  | "github_repo"
  | "json_feed"
  | "rss"
  | "html"
  | "search";

/** Structured content kept alongside the text for structured-source documents. */
export type StructuredIntel =
  | { kind: "attack_group"; attackId: string; aliases: string[]; techniques: string[]; software: string[]; campaigns: string[] }
  | { kind: "attack_software"; attackId: string; softwareType: "malware" | "tool"; aliases: string[]; platforms: string[]; techniques: string[]; groups: string[] }
  | { kind: "attack_campaign"; attackId: string; aliases: string[]; firstSeen?: string; lastSeen?: string; techniques: string[]; groups: string[]; software: string[] }
  | { kind: "atomic_test"; techniqueId: string; tests: Array<{ name: string; guid?: string; platforms: string[]; executor: string; elevationRequired?: boolean; description?: string }> }
  | { kind: "emulation_plan"; adversary: string; planType: "full" | "micro"; techniques: string[]; files: string[] }
  | { kind: "attack_flow"; flowName: string; scope?: string; actions: Array<{ id: string; techniqueId?: string; name: string; description?: string }>; relationships: Array<{ from: string; to: string }> }
  | { kind: "kev"; cveId: string; vendor: string; product: string; dateAdded: string; dueDate?: string; ransomwareUse?: string; requiredAction?: string };

/** Ways a technique can be emulated (spec §32, extended spec §6.21). */
export type EmulationOption = {
  techniqueId: string;
  kind: "atomic_test" | "caldera_ability" | "ctid_procedure" | "attack_flow" | "custom";
  name: string;
  /** Atomic/CALDERA identifier or file path. */
  ref: string;
  platforms: string[];
  /** Executor (powershell, command_prompt, bash, manual…), when known. */
  executor?: string;
  sourceUrl: string;
  /** True when the procedure needs elevation. */
  elevationRequired?: boolean;
};

export type IocKind = "cve" | "technique" | "sha256" | "sha1" | "md5" | "ipv4" | "domain" | "url" | "email";

export type IocHit = {
  kind: IocKind;
  /** Normalized (re-fanged, lower-cased where appropriate) value. */
  value: string;
  /** Exact text as it appeared in the source, e.g. "hxxps://evil[.]com". */
  original?: string;
  /** True when the source showed the indicator defanged. */
  defanged?: boolean;
  /** Role stated near the indicator (e.g. "C2", "payload delivery"), when the source says. */
  role?: string;
  /** Where the indicator appears in the canonical extracted text. */
  evidence?: Evidence;
};

// ---------------------------------------------------------------------------
// Evidence & provenance (fact-level). Offsets index the report's stored
// extractedText, so every quote can be located and re-checked.
// ---------------------------------------------------------------------------

export type Evidence = {
  /** Exact sentence/passage from extractedText that supports the fact. */
  quote: string;
  /** Character offsets of `quote` in extractedText (start inclusive, end exclusive). */
  start: number;
  end: number;
  /** Nearest preceding heading, when the text has one. */
  section?: string;
};

/**
 * How a statement relates to adversary activity:
 * - observed: the source reports the adversary doing it.
 * - inferred: mapped by AIE (e.g. technique inferred from a procedure keyword).
 * - defensive: mitigation / detection / hardening advice, not adversary activity.
 * - negated: the source says it did NOT happen / no evidence of it.
 * - hypothetical: could/may/if statements, examples, generic capability.
 * - reference: generic ATT&CK or background description, not this incident.
 */
export type EvidenceLabel = "observed" | "inferred" | "defensive" | "negated" | "hypothetical" | "reference";

export type EvidencedValue = {
  value: string;
  label: EvidenceLabel;
  evidence: Evidence[];
  /** 0..1, heuristic confidence in the label/extraction. */
  confidence: number;
};

export type TechniqueFact = {
  id: string;
  name: string;
  tactic: string;
  label: EvidenceLabel;
  /** Explicit ID in text ("explicit_id") vs mapped from a behaviour keyword ("keyword"). */
  mappedBy: "explicit_id" | "keyword" | "model";
  evidence: Evidence[];
  confidence: number;
};

export type TargetingFact = {
  kind: "sector" | "geography" | "platform" | "victim_type" | "objective";
  value: string;
  /** What the source says about it: actually targeted/compromised, or only at risk / mentioned. */
  status: "targeted" | "compromised" | "at_risk" | "mentioned";
  evidence: Evidence[];
  confidence: number;
};

export type EntityRef = { type: "actor" | "malware" | "technique" | "ioc" | "sector" | "geography" | "platform"; value: string };

export type RelationshipFact = {
  subject: EntityRef;
  predicate: "uses" | "performed" | "targeted" | "attributed_to" | "communicates_with";
  object: EntityRef;
  label: EvidenceLabel;
  /** Relationships are only created when both entities occur in the same sentence. */
  evidence: Evidence[];
  confidence: number;
};

export type ChainStepEvidence = {
  order: number;
  tactic: string;
  techniques: string[];
  /** Offset of the earliest supporting sentence, used for ordering. */
  position: number;
  evidence: Evidence[];
};

export type IntelEvidence = {
  version: 1;
  /** textHash of the extractedText these offsets refer to. */
  textHash?: string;
  sections: Array<{ heading: string; start: number }>;
  techniques: TechniqueFact[];
  actors: EvidencedValue[];
  malware: EvidencedValue[];
  targeting: TargetingFact[];
  relationships: RelationshipFact[];
  chain: {
    steps: ChainStepEvidence[];
    /** "reported" = source order of observed steps; "unknown" when fewer than 2 observed steps. */
    orderBasis: "reported" | "unknown";
  };
  /** Statements excluded from adversary activity, with reason, for analyst review. */
  excluded: Array<{ techniqueId: string; label: EvidenceLabel; evidence: Evidence }>;
};

export type QualityReason = {
  label: string;
  delta: number;
};

export type IngestOrigin = "live" | "paste" | "seed" | "crawl" | "citation_expansion" | "pdf_extraction";

export type AttackStep = {
  order: number;
  tactic: string;
  techniques: string[];
  summary: string;
};

export type IntelAnalysis = {
  /** "mixed" = model output with some fields filled by the heuristic (see fieldOrigins). */
  method: "heuristic" | "llm" | "mixed";
  /** Which engine produced each list field, when the result is mixed. */
  fieldOrigins?: Partial<Record<"threatActors" | "malware" | "vulnerabilities" | "ttps" | "ioas" | "detections" | "hunting" | "emulation", "llm" | "heuristic">>;
  classification: string;
  threatActors: string[];
  malware: string[];
  vulnerabilities: string[];
  ttps: string[];
  ioas: string[];
  attackChain: AttackStep[];
  detections: string[];
  hunting: string[];
  emulation: string[];
  /** Fact-level evidence; absent on records analysed before evidence tracking existed. */
  evidence?: IntelEvidence;
};

export type ResourceKind =
  | "FULL_ATTACK_CHAIN"
  | "CAMPAIGN_INTEL"
  | "PROCEDURE_DEEPDIVE"
  | "MALWARE_ANALYSIS"
  | "DETECTION_GUIDANCE"
  | "VULNERABILITY_ADVISORY"
  | "THREAT_ACTOR_DOSSIER";

export type StrictnessMode = "permissive" | "balanced" | "strict";
export type DedupMethod = "canonical_url" | "content_hash" | "both" | "smart_hybrid";
export type DiscoveryBreadth = "focused" | "balanced" | "wide";

export type ExtractedEntities = {
  threatActors: string[];
  malwareFamilies: string[];
  cves: string[];
  tactics: string[];
  techniques: Array<{ id: string; name: string; tactic: string }>;
  procedures: string[];
  detectionRules: Array<{ type: "sigma" | "yara" | "kql" | "hunting"; title: string; query: string }>;
  mitigations: string[];
  campaign: string | null;
  /** Canonical ATT&CK references found at ingest (bundled knowledge), with the matched alias and first offset. */
  attackRefs?: AttackEntityRef[];
};

/** ATT&CK group / software / campaign recognised in a report at ingest (collector entity enrichment). */
export type AttackEntityRef = {
  kind: "group" | "software" | "campaign";
  /** G-ID, S-ID or C-ID. */
  id: string;
  name: string;
  /** Alias as written in the report. */
  matched: string;
  /** Offset of the first mention in extractedText (-1 when only the title mentions it). */
  firstOffset: number;
  count: number;
  inTitle?: boolean;
  /** Section heading of the first mention (structured extraction). */
  section?: string;
};

/** Multi-hash fingerprints used for de-duplication (spec §18). */
export type ReportFingerprints = {
  contentSha256: string;
  normalizedTextHash: string;
  titlePublisherHash: string | null;
  simhash: string;
  tokens: number;
};

/** Another URL where the same document (or a syndicated copy) was seen. */
export type ReportMirror = {
  url: string;
  canonicalUrl: string;
  publisher: string;
  sourceDomain: string;
  sourceId?: string | null;
  matchKind: "canonical_url" | "content_sha256" | "normalized_text" | "title_publisher" | "simhash";
  distance?: number;
  seenAt: string;
};

/** A superseded version of a report's content (incremental crawl, spec §45). */
export type ReportVersionEntry = { version: number; textHash: string; rawHash?: string; wordCount?: number; replacedAt: string };

/** A document attached to a report, e.g. the full-report PDF linked from a blog post. */
export type ReportAttachment = {
  kind: "pdf";
  url: string;
  bytes: number;
  chars: number;
  pages?: number;
  status: "attached" | "too_large" | "no_text" | "failed" | "skipped";
  detail?: string;
};

export type ReportRecord = {
  id: string;
  sourceId: string;
  sourceName?: string;
  title: string;
  url: string;
  canonicalUrl: string;
  publishedAt: string | null;
  /** How the publication date was established: source, confidence, evidence and the source's last update. */
  publishedDate?: PublishedDate;
  contentType: string;
  status: "acquired" | "rejected" | "duplicate" | "failed";
  rawHash: string;
  textHash: string;
  qualityScore: number;
  qualityReasons: QualityReason[];
  wordCount: number;
  extractedText: string;
  iocs: IocHit[];
  ingestOrigin: IngestOrigin;
  ingestedAt: string;
  discoveryMethod: string;
  discoveryQuery: string;
  parentSource: string;
  publisher: string;
  author: string;
  classification: string;
  resourceKind?: ResourceKind;
  /** Multi-label document types (spec §26); classification stays for older records. */
  docTypes?: DocType[];
  /** Tier and confidence of the source this record came from. */
  sourceTier?: SourceTier;
  sourceConfidence?: number;
  /** Structured payload for structured-source records (ATT&CK group, atomic test, emulation plan, attack flow, KEV). */
  structured?: StructuredIntel;
  extractedEntities?: ExtractedEntities;
  sourceDomain: string;
  version: number;
  rawHtml?: string;
  pdfUrl?: string;
  pdfBase64?: string;
  analysis: IntelAnalysis | null;
  discoveryPath?: string[];
  outlinkCount?: number;
  citedDomains?: string[];
  simulationScore?: number;
  isEmergingTechnique?: boolean;
  noveltyRationale?: string;
  canonicalReportId?: string;
  tags?: string[];
  aiVerified?: boolean;
  aiQualityScore?: number;
  aiAuditReason?: string;
  matchedSnippet?: string;
  scoreBreakdown?: AgentScoreBreakdown;
  aiTokensUsed?: { inputTokens: number; outputTokens: number; totalTokens: number };
  aiProvider?: string;
  /** Collector (phase 9): dedup fingerprints, mirrors, superseded versions, attachments, pre-fetch relevance. */
  fingerprints?: ReportFingerprints;
  mirrors?: ReportMirror[];
  versionHistory?: ReportVersionEntry[];
  attachments?: ReportAttachment[];
  relevance?: { score: number; reason: string };
  /** Set when the report was published in another language and translated before evaluation. */
  translation?: ReportTranslation;
  /** Research categories the report supports (./research-taxonomy), with the matching terms. */
  research?: ResearchLabels;
  /** Event IDs, log sources and detection content the report itself names (./telemetry-refs). */
  telemetry?: TelemetryRefs;
  /** Grounded AI analysis (./report-ai-analysis): summary, indicators, attack chain, adversary. */
  aiAnalysis?: ReportAiAnalysis;
  /** Latest review decision (./review-decision) and whether an analyst should decide. */
  review?: ReportReviewView;
  needsReview?: boolean;
};

/** What the Library and report page show of a review decision. */
export type ReportReviewView = {
  action: "keep" | "flag" | "hide" | "restore_and_flag" | "unchanged";
  reason: string;
  protectedBy: string[];
  verdict?: "useful" | "not_useful" | "unsure";
  confidence?: number;
  reviewedAt: string;
  by: "ai" | "recovery" | "analyst";
};

/** A report translated into English by AI (./translation); the original stays as evidence. */
export type ReportTranslation = {
  /** Source language (ISO 639-1). */
  from: string;
  /** Provider that translated, as shown to analysts. */
  provider: string;
  model?: string;
  originalTitle: string;
  /** Original text, capped at 150,000 characters. */
  originalText: string;
  /** Characters of the original that were translated (less than totalChars when partial). */
  translatedChars: number;
  totalChars: number;
  partial: boolean;
  translatedAt: string;
};

export type AgentScoreBreakdown = {
  proceduralDepth: number;     // 0 - 30 (Execution commands, LOLBins, APIs, process injection)
  attackProgression: number;   // 0 - 25 (Multi-stage flow: Initial Access -> Execution -> Lateral -> C2 -> Impact)
  attributionContext: number;  // 0 - 15 (Threat actor attribution, campaign tracking, targeted CVEs)
  emulationUtility: number;    // 0 - 20 (Atomic tests, Caldera blueprints, Sigma/YARA rules, hunting queries)
  iocVerifiability: number;    // 0 - 10 (Defanged hashes, C2 IPs/domains, Event IDs, Sysmon)
  totalScore: number;          // 0 - 100
};

export type ReportListItem = Omit<ReportRecord, "extractedText" | "qualityReasons" | "analysis"> & {
  excerpt: string;
  iocCount: number;
  analysis?: IntelAnalysis | null;
  tags?: string[];
  aiVerified?: boolean;
  aiQualityScore?: number;
  aiAuditReason?: string;
  matchedSnippet?: string;
  scoreBreakdown?: AgentScoreBreakdown;
};

export type IngestEvent = {
  id: string;
  reportId: string | null;
  url: string;
  outcome: string;
  detail: string;
  createdAt: string;
};

export type CatalogItem = {
  id: string;
  sourceSlug: string;
  title: string;
  url: string;
  published: string;
  why: string;
};

export type ThreatRegionStats = {
  name: string;
  x: number;
  y: number;
  actors: string[];
  count: number;
  threatLevel: "critical" | "high" | "medium" | "low";
  sectors: string[];
  topVector: string;
  originCountry?: string;
  targetCountries?: string[];
  flag?: string;
};

/** ATT&CK tactic frequency computed from report attack chains (no floors). */
export type TacticDistributionStats = {
  name: string;
  id: string;
  /** Number of attack-chain steps mapped to this tactic across reports. */
  count: number;
  /** Number of distinct reports with at least one step in this tactic. */
  reportCount: number;
  /** Percentage relative to the most frequent tactic (0 when there is no data). */
  pct: number;
};

/**
 * Static, curated background metadata for a known actor/tool. This is NOT
 * observed from reports and must be labelled as a reference profile in the UI.
 */
export type ActorReferenceProfile = {
  type: string;
  originCountry: string;
  flag: string;
  focus: string;
  badge: string;
  targetSectors: string[];
};

export type MonitoredActorItem = {
  name: string;
  /** Number of reports whose extracted actors/tools name this actor (or a known alias). */
  reportCount: number;
  /** Most recent matching report id, if any. */
  sampleReportId?: string;
  /** Badge shown on the card ("APT", "RaaS", "TOOL", "ACTOR", ...). */
  badge: string;
  /** Malware / tools observed in the same reports (co-occurrence, observed). */
  associatedTools: string[];
  /** Curated reference profile, if this actor is in the built-in catalog. */
  reference?: ActorReferenceProfile;
};

/** Curated reference metadata for a CVE. Not observed from reports. */
export type CveReferenceMeta = {
  vendorProduct: string;
  cvss: number;
  severity: "critical" | "high" | "medium";
  exploitStatus: "In the Wild" | "Weaponized" | "PoC Published";
};

export type CveVelocityItem = {
  cveId: string;
  /** Number of reports that reference this CVE. */
  reportCount: number;
  sampleReportId?: string;
  sampleReportTitle?: string;
  /** Threat actors named in the same reports (observed). */
  actors: string[];
  /** Curated reference metadata, if the CVE is in the built-in catalog. */
  reference?: CveReferenceMeta;
};

export type ThreatFlowItem = {
  id: string;
  origin: string;
  actors: string[];
  vectors: string[];
  tools: string[];
  targets: string[];
  intensity: number;
};

export type AttackHeatmapCell = {
  tacticId: string;
  tacticName: string;
  /** Distinct technique ids observed under this tactic. */
  techniqueCount: number;
  /** Attack-chain steps mapped to this tactic. */
  hitCount: number;
  /** hitCount relative to the busiest tactic, 0-100. */
  intensity: number;
  topTechniques: Array<{ id: string; name: string; count: number }>;
};

export type DashboardStats = {
  sourceCount: number;
  enabledSources: number;
  reportCount: number;
  acquiredCount: number;
  avgQuality: number;
  iocCount: number;
  recent: ReportListItem[];
  events: IngestEvent[];
  crawlerStatus: string;
  lastCrawlAt: string | null;
  nextCrawlAt: string | null;
  discoveredSourcesCount?: number;
  threatRegions?: ThreatRegionStats[];
  tacticDistribution?: TacticDistributionStats[];
  topThreatActors?: MonitoredActorItem[];
  cveVelocity?: CveVelocityItem[];
  threatFlows?: ThreatFlowItem[];
  attackHeatmap?: AttackHeatmapCell[];
};

export type CrawlTrigger = "MANUAL" | "SCHEDULED" | "API" | "AGENT" | "SEARCH" | "EXPANSION" | "BACKFILL";

export type CrawlJobStatus = "queued" | "running" | "paused" | "completed" | "failed" | "cancelled" | "interrupted";

export type CrawlConfig = {
  id: string;
  enabled: boolean;
  paused: boolean;
  frequencyMinutes: number;
  startHour: string;
  maxResourcesPerRun: number; // Max resources processed in single job run
  maxResourcesPerJob?: number;
  maxRunTimeMinutes?: number; // Hard time limit for crawl job execution (1 to 30 mins, default 5)
  maxResourcesPerDomain: number; // Max articles from any single domain (default 8)
  maxDepth: number; // Traversal depth for outlink exploration (1 to 5)
  discoveryBreadth: DiscoveryBreadth; // focused | balanced | wide
  allowExternalDomains: boolean; // Expand outside predefined seeds to discover new sources
  domainAllowlist: string[];
  domainBlocklist: string[];
  rateLimitMs: number; // Polite delay between requests
  concurrency: number; // Concurrent fetch workers
  maxPdfDownloads: number; // Max PDFs downloaded per run
  autoIngest: boolean;
  autoAnalyze: boolean;
  generatePdf: boolean;
  rssDiscovery: boolean;
  htmlDiscovery: boolean;
  searchDiscovery: boolean;
  recursiveDiscovery: boolean;
  keywords: string;
  noiseKeywords: string;
  minQualityScore: number;
  minWordCount: number;
  strictnessMode: StrictnessMode;
  requireIocs: boolean;
  requireAttck: boolean;
  rejectMarketingNoise: boolean;
  dedupMethod: DedupMethod;
  activeSources: string[];
  targetResourceTypes: ResourceKind[];
  dateRangeDays: number | null;
  lastRunAt: string | null;
  nextRunAt: string | null;
  // AI Agent Enhancement Layer Settings
  agentDiscoveryEnabled?: boolean;
  agentTaggingEnabled?: boolean;
  agentApprovalEnabled?: boolean;
  agentAutoIngestEnabled?: boolean;
  agentCrawlSourcesEnabled?: boolean;
  agentLibraryAuditEnabled?: boolean;
  agentAutoPruneJunkEnabled?: boolean;
  /** Translate reports in other languages with AI before they are evaluated (default on). */
  translateNonEnglish?: boolean;
  /** Web-search discovery across the research taxonomy (./research-taxonomy). */
  researchDiscovery?: ResearchDiscoveryConfig;
  agentModel?: string;
  agentTimeoutSeconds?: number;
};

export type CrawlPipelineStage =
  | "discovered"
  | "evaluated"
  | "qualified"
  | "rejected"
  | "processed"
  | "pdf_generated"
  | "ingested"
  | "indexed"
  | "failed"
  | "duplicate";

export type CrawlJob = {
  id: string;
  status: CrawlJobStatus;
  triggerType: CrawlTrigger;
  startedAt: string | null;
  completedAt: string | null;
  sourceCount: number;
  discoveredCount: number;
  evaluatedCount: number;
  qualifiedCount: number;
  ingestedCount: number;
  duplicateCount: number;
  failedCount: number;
  rejectedCount: number;
  updatedCount: number;
  skippedCount: number;
  newSourcesCount: number;
  pdfGeneratedCount: number;
  errorSummary: string;
  currentStage?: CrawlPipelineStage;
  currentUrl?: string;
  activeWorkers?: number;
  activeDomains?: string[];
  throughputDocsPerSec?: number;
  maxResourcesPerRun?: number;
  stageCounts?: Record<CrawlPipelineStage, number>;
  /** Collector funnel (discovered → fetched → relevant → unique → qualified → stored) and skip reasons. */
  funnel?: CrawlFunnel;
};

/** Per-job collection funnel with the reasons items left it (spec §53). */
export type CrawlFunnel = {
  discovered: number;
  /** Candidates that passed the relevance pre-score. */
  relevant: number;
  fetched: number;
  /** Fetched and not a duplicate of a stored document. */
  unique: number;
  qualified: number;
  stored: number;
  skippedRelevance: number;
  unchanged: number;
  notModified: number;
  duplicates: Record<string, number>;
  newVersions: number;
  robotsBlocked: number;
  failed: number;
  pdfAttached: number;
  sourcesCrawled: number;
  sourcesSkipped: Array<{ sourceId: string; name: string; reason: string }>;
  feedsNotModified: number;
  sitemapUrls: number;
  feedsAutodiscovered: number;
  listingPages: number;
  /** Lowest-scoring skipped candidates, for the job log. */
  relevanceSamples: Array<{ title: string; url: string; score: number; reason: string }>;
  mode?: "incremental" | "backfill";
  backfill?: { sourceId: string; months: number; sinceIso: string } | null;
};

export type CrawlJobItem = {
  id: string;
  jobId: string;
  sourceId: string | null;
  url: string;
  canonicalUrl: string;
  title: string;
  classification: string;
  decision: string;
  reason: string;
  stage?: CrawlPipelineStage;
  discoveryMethod: string;
  discoveryQuery: string;
  parentUrl: string | null;
  depth: number;
  publisher: string;
  qualityScore?: number;
  simulationScore?: number;
  isEmergingTechnique?: boolean;
  noveltyRationale?: string;
  resourceKind?: ResourceKind;
  discoveryPath?: string[];
  outlinkCount?: number;
  agentScore?: number;
  agentApproved?: boolean;
  agentRationale?: string;
  agentTags?: string[];
  agentClassification?: string;
  agentResourceKind?: ResourceKind;
  scoreBreakdown?: AgentScoreBreakdown;
  createdAt: string;
};

export type DiscoveredResource = {
  id: string;
  canonicalUrl: string;
  url: string;
  sourceId: string | null;
  title: string;
  publisher: string;
  author: string;
  publicationDate: string | null;
  classification: string;
  resourceKind?: ResourceKind;
  discoveryMethod: string;
  discoveryQuery: string;
  parentSource: string;
  parentUrl?: string | null;
  sourceDomain: string;
  contentType: string;
  status: string; // discovered | evaluated | qualified | rejected | ingested | awaiting_approval
  rejectReason: string;
  qualityScore: number | null;
  simulationScore?: number;
  isEmergingTechnique?: boolean;
  noveltyRationale?: string;
  reportId: string | null;
  discoveryPath?: string[];
  domainTrustScore?: number;
  isNewSource?: boolean;
  agentScore?: number;
  agentApproved?: boolean;
  agentRationale?: string;
  agentTags?: string[];
  agentClassification?: string;
  agentResourceKind?: ResourceKind;
  scoreBreakdown?: AgentScoreBreakdown;
  createdAt: string;
};

export type DiscoveryGraphNode = {
  id: string;
  label: string;
  type:
    | "seed_source"
    | "discovered_source"
    | "report"
    | "pdf_document"
    | "research_paper"
    | "repository"
    | "threat_actor"
    | "malware"
    | "cve";
  domain: string;
  depth: number;
  qualityScore?: number;
  resourceKind?: ResourceKind;
  url?: string;
  status: string;
};

export type DiscoveryGraphEdge = {
  id: string;
  from: string;
  to: string;
  relationship:
    | "CITES"
    | "LINKS_TO"
    | "DERIVED_FROM"
    | "DISCOVERED_SOURCE"
    | "DOWNLOADS_PDF"
    | "REFERENCES_REPO"
    | "USES_TTP"
    | "ATTRIBUTES";
  label: string;
  sourceDomain?: string;
  targetDomain?: string;
  jobId?: string;
  createdAt: string;
};

export type DiscoveredSourceRecord = {
  id: string;
  domain: string;
  name: string;
  homepageUrl: string;
  crawlPattern?: string;
  parentSource: string;
  parentUrl?: string;
  discoveryPath: string[];
  trustScore: number;
  resourceCount: number;
  status: "discovered" | "evaluated" | "approved" | "ignored" | "verified" | "rejected";
  origin?: "agent_discovery" | "crawler_outlink" | "manual" | "citation_expansion";
  enabled?: boolean;
  notes?: string;
  whyCrawl?: string;
  firstDiscoveredAt: string;
  lastSeenAt: string;
};

export type CrawlerState = {
  config: CrawlConfig;
  activeJob: CrawlJob | null;
  jobs: CrawlJob[];
  items: CrawlJobItem[];
  discovered: DiscoveredResource[];
  discoveredSources: DiscoveredSourceRecord[];
  graphEdges: DiscoveryGraphEdge[];
  sourceStats: { sourceName: string; found: number; ingested: number; failed: number }[];
  totalCounts?: {
    discovered: number;
    sources: number;
    jobs: number;
    graphEdges: number;
  };
};

export type AppSettings = {
  id: string;
  // General & SOC Policy
  organizationName: string;
  nodeId: string;
  defaultClassification: string;
  iocConfidenceThreshold: number;
  evidenceRetentionDays: number;
  defaultExportFormat: "json" | "stix21" | "csv" | "pdf";

  // Storage & Cache Telemetry Controls
  cacheTtlSeconds: number;
  dashboardCacheTtlSeconds: number;
  autoPurgeStaleEventsDays: number;

  // Display & UI Preferences
  defaultMatrixLayout: "standard" | "compact" | "mini";
  matrixSubtechniqueAutoExpand: boolean;
  pollingIntervalSeconds: number;
  enableSoundAlerts: boolean;
  enableLiveTelemetryStream: boolean;

  // AI Agent Enhancement Layer Controls
  agentDiscoveryEnabled: boolean;
  agentTaggingEnabled: boolean;
  agentApprovalEnabled: boolean;
  agentAutoIngestEnabled: boolean;
  agentCrawlSourcesEnabled: boolean;
  agentModel: string;
  agentTimeoutSeconds: number;
  activeAgentProvider?: string;
  /** Admin-only: reveal deep backend/frontend diagnostics in the UI. Off for everyone by default. */
  debuggerMode?: boolean;

  updatedAt?: string;
};

export type StorageStats = {
  configured: boolean;
  /** Where the library is read from: MongoDB (MONGODB_URI) or the built-in local database. */
  engine?: "mongodb" | "local";
  /**
   * The shared MongoDB is mandatory in this environment (production/deploy) but is not configured, so
   * the app is on the private, empty local store and nothing is being saved or shared. A hard error.
   */
  required?: boolean;
  /** MongoDB is configured but could not be reached (credentials removed). */
  error?: string;
  databaseName: string;
  collectionName: string;
  totalReports: number;
  /** Reports the Library shows (not hidden, not superseded copies). */
  visibleReports?: number;
  totalSources: number;
  totalDiscovered: number;
  totalJobs: number;
  totalEvents: number;
  cacheStatus: {
    reportsCached: boolean;
    dashboardCached: boolean;
    configCached: boolean;
    settingsCached: boolean;
  };
  serverUptimeSeconds: number;
};

export const DEFAULT_APP_SETTINGS: AppSettings = {
  id: "app_settings_default",
  organizationName: "Cyber Defense SOC · Advisory Threat Intelligence",
  nodeId: "SOC-NODE-01",
  defaultClassification: "INTRUSION_REPORT",
  iocConfidenceThreshold: 75,
  evidenceRetentionDays: 365,
  defaultExportFormat: "stix21",
  cacheTtlSeconds: 60,
  dashboardCacheTtlSeconds: 15,
  autoPurgeStaleEventsDays: 30,
  defaultMatrixLayout: "standard",
  matrixSubtechniqueAutoExpand: false,
  pollingIntervalSeconds: 12,
  enableSoundAlerts: false,
  enableLiveTelemetryStream: true,
  agentDiscoveryEnabled: true,
  agentTaggingEnabled: true,
  agentApprovalEnabled: true,
  agentAutoIngestEnabled: false,
  agentCrawlSourcesEnabled: true,
  agentModel: "gemini-3.8-flash-low",
  agentTimeoutSeconds: 45,
  activeAgentProvider: "agy_agent",
  debuggerMode: false,
  updatedAt: new Date().toISOString(),
};

export interface BatchIngestResult {
  total: number;
  succeeded: number;
  failed: number;
  durationMs?: number;
  results: Array<{
    discoveredId: string;
    canonicalUrl?: string;
    ok: boolean;
    reportId?: string;
    error?: string;
  }>;
}

export interface SourceProbeResult {
  sourceId: string;
  url: string;
  domain: string;
  statusCode: number;
  latencyMs: number;
  reachable: boolean;
  contentType: string;
  error?: string;
  timestamp: string;
}
