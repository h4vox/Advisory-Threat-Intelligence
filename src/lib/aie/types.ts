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
};

export type IocKind = "cve" | "technique" | "sha256" | "md5" | "ipv4" | "domain";

export type IocHit = {
  kind: IocKind;
  value: string;
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
  method: "heuristic" | "llm";
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
};

export type ReportRecord = {
  id: string;
  sourceId: string;
  sourceName?: string;
  title: string;
  url: string;
  canonicalUrl: string;
  publishedAt: string | null;
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

export type TacticDistributionStats = {
  name: string;
  id: string;
  count: number;
  pct: number;
};

export type MonitoredActorItem = {
  name: string;
  type: string;
  originCountry: string;
  flag: string;
  focus: string;
  reportCount: number;
  badge: string;
  targetSectors: string[];
  associatedTools: string[];
};

export type CveVelocityItem = {
  cveId: string;
  vendorProduct: string;
  cvss: number;
  severity: "critical" | "high" | "medium";
  exploitStatus: "In the Wild" | "Weaponized" | "PoC Published";
  reportCount: number;
  sampleReportId?: string;
  sampleReportTitle?: string;
  actors: string[];
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
  techniqueCount: number;
  hitCount: number;
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

export type CrawlTrigger = "MANUAL" | "SCHEDULED" | "API" | "AGENT" | "SEARCH" | "EXPANSION";

export type CrawlJobStatus = "queued" | "running" | "paused" | "completed" | "failed" | "cancelled";

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
  stageCounts?: Record<CrawlPipelineStage, number>;
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

  updatedAt?: string;
};

export type StorageStats = {
  configured: boolean;
  databaseName: string;
  collectionName: string;
  totalReports: number;
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
  agentModel: "AGY: gemini-3.8-flash-low",
  agentTimeoutSeconds: 45,
  activeAgentProvider: "agy_agent",
  updatedAt: new Date().toISOString(),
};
