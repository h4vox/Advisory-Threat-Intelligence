export type TrustLevel = "high" | "official" | "community";

export type SourceRecord = {
  id: string;
  name: string;
  slug: string;
  category: string;
  priority: number;
  homepageUrl: string;
  enabled: boolean;
  trustLevel: TrustLevel;
  notes: string;
  lastIngestAt: string | null;
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

export type IngestOrigin = "live" | "paste" | "seed" | "crawl";

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

export type ReportRecord = {
  id: string;
  sourceId: string;
  sourceName: string;
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
  sourceDomain: string;
  version: number;
  analysis: IntelAnalysis | null;
};

export type ReportListItem = Omit<ReportRecord, "extractedText" | "qualityReasons" | "analysis"> & {
  excerpt: string;
  iocCount: number;
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
};

export type CrawlTrigger = "MANUAL" | "SCHEDULED" | "API" | "AGENT";

export type CrawlJobStatus = "queued" | "running" | "paused" | "completed" | "failed" | "cancelled";

export type CrawlConfig = {
  id: string;
  enabled: boolean;
  paused: boolean;
  frequencyMinutes: number;
  startHour: string;
  maxResourcesPerRun: number;
  maxDepth: number;
  autoIngest: boolean;
  autoAnalyze: boolean;
  searchDiscovery: boolean;
  recursiveDiscovery: boolean;
  keywords: string;
  dateRangeDays: number | null;
  lastRunAt: string | null;
  nextRunAt: string | null;
};

export type CrawlJob = {
  id: string;
  status: CrawlJobStatus;
  triggerType: CrawlTrigger;
  startedAt: string | null;
  completedAt: string | null;
  sourceCount: number;
  discoveredCount: number;
  qualifiedCount: number;
  ingestedCount: number;
  duplicateCount: number;
  failedCount: number;
  rejectedCount: number;
  updatedCount: number;
  skippedCount: number;
  errorSummary: string;
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
  discoveryMethod: string;
  discoveryQuery: string;
  parentUrl: string | null;
  depth: number;
  publisher: string;
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
  discoveryMethod: string;
  discoveryQuery: string;
  parentSource: string;
  sourceDomain: string;
  contentType: string;
  status: string;
  rejectReason: string;
  qualityScore: number | null;
  reportId: string | null;
  createdAt: string;
};

export type CrawlerState = {
  config: CrawlConfig;
  activeJob: CrawlJob | null;
  jobs: CrawlJob[];
  items: CrawlJobItem[];
  discovered: DiscoveredResource[];
  sourceStats: { sourceName: string; found: number; ingested: number; failed: number }[];
};
