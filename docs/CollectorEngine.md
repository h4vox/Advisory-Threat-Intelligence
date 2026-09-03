# AIE Autonomous Threat Intelligence Collector & Crawling Engine
## Comprehensive Top-to-Bottom Architecture, Technical Specification & Review Guide

---

### Executive Summary

The **AIE Autonomous Threat Intelligence Collector & Crawling Engine** is an enterprise-grade, multi-stage cyber threat intelligence (CTI) acquisition, extraction, qualification, and graph discovery platform. Built to serve modern Security Operations Centers (SOC), Incident Response (DFIR) teams, Detection Engineers, and Adversary Emulation (Purple) teams, the engine continuously harvests high-signal adversary intelligence from open and closed web sources.

Rather than acting as a naive web scraper, the engine functions as an **autonomous threat hunting and citation expansion graph agent**. It starts from verified high-trust seed feeds (e.g., *The DFIR Report*, *Unit 42*, *SentinelLABS*, *Mandiant*, *CISA*, *SpecterOps*, *MITRE ATT&CK*), discovers outbound relationships, extracts cryptographic indicators of compromise (IOCs), correlates MITRE ATT&CK tactics, techniques, and procedures (TTPs), generates detection rules and Atomic Red Team emulation plans, and synthesizes publication-quality PDF dossiers.

This document serves as the **definitive reference manual and technical review specification** for security engineers, software architects, and AI review agents inspecting or extending the system.

---

## Table of Contents

1. [Architectural Overview & Component Topology](#1-architectural-overview--component-topology)
2. [Domain Models & Data Schemas](#2-domain-models--data-schemas)
3. [End-to-End Pipeline Execution Lifecycle](#3-end-to-end-pipeline-execution-lifecycle)
4. [Multi-Vector Discovery Subsystem](#4-multi-vector-discovery-subsystem)
5. [Graph Expansion & Domain Trust Scoring Engine](#5-graph-expansion--domain-trust-scoring-engine)
6. [Dual-Tier Deduplication & Content Integrity](#6-dual-tier-deduplication--content-integrity)
7. [Content Acquisition & Network Resilience Engine](#7-content-acquisition--network-resilience-engine)
8. [Multi-Dimensional Qualification & Noise Elimination Engine](#8-multi-dimensional-qualification--noise-elimination-engine)
9. [Adversary Threat Modeling & Structured Entity Extraction](#9-adversary-threat-modeling--structured-entity-extraction)
10. [High-Fidelity PDF & HTML Synthesis Engine](#10-high-fidelity-pdf--html-synthesis-engine)
11. [Dual-Storage Persistence Architecture (MongoDB Atlas & PostgreSQL)](#11-dual-storage-persistence-architecture-mongodb-atlas--postgresql)
12. [Server Function API & RPC Specification](#12-server-function-api--rpc-specification)
13. [Analyst Console & Operational Workflows](#13-analyst-console--operational-workflows)
14. [Failure Modes, Fault Tolerance & Error Recovery](#14-failure-modes-fault-tolerance--error-recovery)
15. [Reviewer & AI Agent Checklist](#15-reviewer--ai-agent-checklist)

---

## 1. Architectural Overview & Component Topology

The crawling engine is designed around a **reactive, priority-queued, graph-expanding pipeline**. It decouples discovery, extraction, qualification, analysis, and persistence into discrete stages with clear data contracts.

```
                                  +---------------------------------------+
                                  |    Trigger Vector (Manual / Sched /   |
                                  |    Search / API / Subagent / Queue)   |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |      Priority Frontier Queue          |
                                  |     (Dynamically Sorted by Score)     |
                                  +---------------------------------------+
                                       /              |              \
                                      /               |               \
                                     v                v                v
                        +----------------+  +------------------+  +-------------------+
                        | Vector A: RSS  |  | Vector B: HTML   |  | Vector C: Live Web|
                        | & Atom Feeds   |  | Outlink Seeds    |  | & Graph Search    |
                        +----------------+  +------------------+  +-------------------+
                                     \                |                /
                                      \               |               /
                                       v              v              v
                                  +---------------------------------------+
                                  |    Stage 1: Deduplication Engine      |
                                  |  (Canonical URLs + SHA-256 Text Hash) |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |    Stage 2: Content Acquisition       |
                                  | (Polite Rate Limit + Full Article DOM)|
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |  Stage 3: Recursive Citation Graph    |
                                  |   (Outlink Discovery & Domain Trust)  |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |  Stage 4: Multi-Tier Qualification    |
                                  | (TTP Density / Noise Filter / Checks) |
                                  +---------------------------------------+
                                         /                         \
                          Qualified (Score >= Min)          Rejected (Noise / Short)
                                       /                             \
                                      v                               v
                       +-----------------------------+   +----------------------------+
                       | Stage 5: Threat Intelligence|   | Discovered Pool: Rejected  |
                       | Analysis & Entity Extraction|   | Audit Log Item Persisted   |
                       +-----------------------------+   +----------------------------+
                                      |
                                      v
                       +-----------------------------+
                       | Stage 6: High-Fidelity PDF  |
                       | & Pristine HTML Generation  |
                       +-----------------------------+
                                      |
                                      v
                       +-----------------------------+
                       | Stage 7: Ingestion Switch   |
                       | (Auto-Ingest vs Review Queue|
                       +-----------------------------+
                                     /             \
                       Auto-Ingest = true       Auto-Ingest = false
                                   /                 \
                                  v                   v
                     +----------------------+  +---------------------+
                     | Finalized CTI Report |  | Awaiting Approval   |
                     | Indexed & Published  |  | In Discovery Queue  |
                     +----------------------+  +---------------------+
                                  |
                                  v
                     +----------------------+
                     | STIX 2.1 Export &    |
                     | SIEM / TIP Feed Sync |
                     +----------------------+
```

### Key Source Code Module Map

| Module Path | Primary Responsibility | Key Functions & Symbols |
| :--- | :--- | :--- |
| `src/lib/aie/crawler.ts` | Orchestration, Frontier Queue, Lifecycle, Pipeline Stages | `executeCrawlJob`, `createAndRunCrawlJob`, `cancelJob`, `getOrCreateCrawlConfig` |
| `src/lib/aie/discovery.ts` | Graph Citation Extraction, Outlink Parsing, Domain Trust Scoring | `extractOutlinksAndCitations`, `evaluateDomainTrust`, `isBlacklistedDomain`, `generateSearchQueries`, `DISCOVERY_KNOWLEDGE_POOL` |
| `src/lib/aie/qualification.ts` | Content Scoring, Noise Rejection, Classification, ResourceKind | `qualifyContent`, `isCandidateResourceUrl`, `ResourceClassification`, `QualificationResult` |
| `src/lib/aie/extract.ts` | Cryptographic Hashes, IOC Harvesting, DOM Stripping, Entity Decoding | `sha256Hex`, `canonicalizeUrl`, `htmlToText`, `harvestIocs`, `scoreQuality`, `decodeEntities` |
| `src/lib/aie/feeds.ts` | Continuous Syndication Feed Parsing (RSS 2.0 & Atom 1.0) | `parseRssOrAtomXml`, `FeedArticle` |
| `src/lib/aie/attack-chain.ts` | Adversary Attribution, ATT&CK Matrix Mapping, Detection Engineering | `analyzeThreatIntelligence`, `extractStructuredEntities`, `TACTIC_TECHNIQUE_MAP` |
| `src/lib/aie/pdf.ts` | Pristine Document Layout Engine, Print CSS, Typographic Synthesis | `buildPristineDocumentHtml`, `extractMainContentHtml`, `DocumentPrintMetadata` |
| `src/lib/aie/catalog.ts` | Authoritative Seed Source Catalog & Pre-Configured Sources | `SOURCE_SEED`, `CATALOG_ITEMS` |
| `src/lib/aie/server.ts` | TanStack Start RPC Endpoints & API Server Functions | `getCrawlerState`, `updateCrawlerConfig`, `triggerCrawlJob`, `cancelCrawlJob`, `exportSTIXBundle` |
| `src/lib/mongodb/repository.server.ts` | Unified MongoDB Atlas Persistence, Indexing & Aggregations | `mongoGetCrawlerState`, `mongoInsertReport`, `mongoUpsertDiscoveredResource`, `ensureMongoIndexes` |
| `src/routes/ingest.tsx` | Operational Console, Live Controls, Audit Logs, Discovery Queue | `IngestPage`, `VIEWS` (Crawler, Queue, Graph, Audit, Settings, Manual, Catalog) |

---

## 2. Domain Models & Data Schemas

The engine enforces strict TypeScript typings and schema contracts across all storage tiers.

### 2.1 Core Entities (`src/lib/aie/types.ts`)

#### 1. `CrawlConfig`
Controls runtime behavior, throttles, strictness thresholds, and discovery features:
```typescript
export type CrawlConfig = {
  id: string;                         // Unique configuration ID (e.g. "cfg_default")
  enabled: boolean;                    // Master automation switch
  paused: boolean;                     // Pauses active processing
  frequencyMinutes: number;            // Polling/scheduler interval (e.g. 360 min)
  startHour: string;                   // Scheduled daily execution window (e.g. "09:00")
  maxResourcesPerRun: number;          // Hard cap on total articles per crawl run
  maxResourcesPerJob?: number;         // Overriding cap for targeted jobs
  maxResourcesPerDomain: number;       // Anti-trap limit per domain (default: 8-12)
  maxDepth: number;                    // Outlink exploration depth (1 to 5)
  discoveryBreadth: "focused" | "balanced" | "wide";
  allowExternalDomains: boolean;       // Expand beyond predefined seed domains
  domainAllowlist: string[];           // Explicit allowed domains
  domainBlocklist: string[];           // Explicit blocked domains
  rateLimitMs: number;                 // Polite delay between outbound HTTP fetches (ms)
  concurrency: number;                 // Concurrency of parallel fetch workers
  maxPdfDownloads: number;             // Maximum raw PDFs downloaded per run
  autoIngest: boolean;                 // Directly publish or send to approval queue
  autoAnalyze: boolean;                // Execute heuristic ATT&CK analysis
  generatePdf: boolean;                // Synthesize printable PDF/HTML dossier
  rssDiscovery: boolean;               // Enable continuous RSS/Atom syndication
  htmlDiscovery: boolean;              // Enable seed homepage scraping
  searchDiscovery: boolean;            // Enable live DuckDuckGo CTI search
  recursiveDiscovery: boolean;         // Enable citation outlink exploration
  keywords: string;                    // Target threat keywords (comma-separated)
  noiseKeywords: string;               // Excluded marketing terms (comma-separated)
  minQualityScore: number;             // Quality hurdle score (0.00 to 1.00, default: 0.35-0.40)
  minWordCount: number;                // Minimum body words (default: 100-120)
  strictnessMode: "permissive" | "balanced" | "strict";
  requireIocs: boolean;                // Require presence of CVEs/hashes/IPs
  requireAttck: boolean;               // Require explicit MITRE technique IDs
  rejectMarketingNoise: boolean;       // Reject vendor press releases and pricing
  dedupMethod: "canonical_url" | "content_hash" | "both" | "smart_hybrid";
  activeSources: string[];             // Substring or ID filter for enabled seed sources
  targetResourceTypes: ResourceKind[]; // Whitelisted resource kinds
  dateRangeDays: number | null;        // Maximum age in days of acquired reports
  lastRunAt: string | null;
  nextRunAt: string | null;
};
```

#### 2. `CrawlJob` & `CrawlJobItem`
Represents an execution instance and its individual URL audit line items:
```typescript
export type CrawlTrigger = "MANUAL" | "SCHEDULED" | "API" | "AGENT" | "SEARCH" | "EXPANSION";
export type CrawlJobStatus = "queued" | "running" | "paused" | "completed" | "failed" | "cancelled";
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
};

export type CrawlJobItem = {
  id: string;
  jobId: string;
  sourceId: string | null;
  url: string;
  canonicalUrl: string;
  title: string;
  classification: string;
  decision: "INGESTED" | "REJECTED" | "DUPLICATE" | "FAILED" | "AWAITING_APPROVAL";
  reason: string;
  stage?: CrawlPipelineStage;
  discoveryMethod: string;
  discoveryQuery: string;
  parentUrl: string | null;
  depth: number;
  publisher: string;
  qualityScore?: number;
  resourceKind?: ResourceKind;
  discoveryPath?: string[];
  createdAt: string;
};
```

#### 3. `ReportRecord` (Ingested Threat Intelligence Dossier)
The canonical threat report ingested and stored in the database:
```typescript
export type ReportRecord = {
  id: string;                          // Unique ID with prefix "rpt_"
  sourceId: string;                    // Originating source seed ID
  sourceName?: string;                 // Human-readable source name
  title: string;                       // Document title
  url: string;                         // Original fetch URL
  canonicalUrl: string;                // Normalized canonical URL
  publishedAt: string | null;          // Publication timestamp (ISO YYYY-MM-DD)
  contentType: string;                 // MIME type (text/html or application/pdf)
  status: "acquired" | "rejected" | "duplicate" | "failed";
  rawHash: string;                     // SHA-256 of raw bytes or response text
  textHash: string;                    // SHA-256 of normalized text content
  qualityScore: number;                // Calculated quality score (0.00 to 1.00)
  qualityReasons: QualityReason[];     // Score breakdown with positive/negative deltas
  wordCount: number;                   // Word count of clean extracted text
  extractedText: string;               // Plain text stripped of markup and UI
  iocs: IocHit[];                      // Harvested cryptographic and network IOCs
  ingestOrigin: IngestOrigin;          // "crawl" | "citation_expansion" | "seed" | etc.
  ingestedAt: string;                  // Timestamp of ingestion
  publisher: string;                   // Research organization or blog domain
  author: string;                      // Document author
  classification: string;              // Granular threat classification
  resourceKind?: ResourceKind;         // Strategic kind (e.g. FULL_ATTACK_CHAIN)
  extractedEntities?: ExtractedEntities; // Extracted TTPs, procedures, Sigma rules
  sourceDomain: string;                // FQDN of the originating domain
  version: number;                     // Document schema version
  rawHtml?: string;                    // Pristine reconstructed HTML dossier
  pdfUrl?: string;                     // Storage path/URL to compiled PDF
  analysis: IntelAnalysis | null;      // Structured ATT&CK and attribution matrix
  discoveryPath?: string[];            // Provenance chain of URLs leading here
};
```

#### 4. `DiscoveredResource`, `DiscoveredSourceRecord` & `DiscoveryGraphEdge`
Entities capturing the graph expansion outside initial seeds:
```typescript
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
  parentSource: string;
  parentUrl?: string | null;
  sourceDomain: string;
  contentType: string;
  status: "discovered" | "evaluated" | "qualified" | "rejected" | "ingested" | "awaiting_approval";
  rejectReason: string;
  qualityScore: number | null;
  reportId: string | null;
  discoveryPath?: string[];
  domainTrustScore?: number;
  isNewSource?: boolean;
  createdAt: string;
};

export type DiscoveredSourceRecord = {
  id: string;
  domain: string;
  name: string;
  homepageUrl: string;
  parentSource: string;
  parentUrl?: string;
  discoveryPath: string[];
  trustScore: number;                  // Domain reputation score (0.00 to 1.00)
  resourceCount: number;
  status: "discovered" | "evaluated" | "approved" | "ignored";
  firstDiscoveredAt: string;
  lastSeenAt: string;
};

export type DiscoveryGraphEdge = {
  id: string;
  from: string;                        // Source URL
  to: string;                          // Target URL
  relationship: "CITES" | "LINKS_TO" | "DERIVED_FROM" | "DISCOVERED_SOURCE" | "DOWNLOADS_PDF" | "REFERENCES_REPO" | "USES_TTP";
  label: string;                       // Anchor text context
  jobId?: string;
  createdAt: string;
};
```

---

## 3. End-to-End Pipeline Execution Lifecycle

The execution loop lives in `src/lib/aie/crawler.ts` under `executeCrawlJob()`. It runs asynchronously to avoid blocking the HTTP server thread.

```
+-----------------------------------------------------------------------------------+
|                        CRAWL JOB EXECUTION TIMELINE                               |
+-----------------------------------------------------------------------------------+
| [0.0s] Job Record Created: status='running', stage='discovered'                   |
| [0.1s] Storage Indexes Ensured & Catalog Seeds Hydrated                           |
| [0.2s] Deduplication Sets Loaded (storedCanonicalUrls, storedHashes)              |
| [0.3s] Phase A: Feed Ingestion (Parallel RSS/Atom fetch & parse)                  |
| [1.5s] Phase B: Homepage Permalinks (Outlink & citation extraction)               |
| [2.5s] Phase C: Live CTI Web Search & Knowledge Pool Seeding                      |
| [3.0s] Frontier Priority Queue Populated & Sorted (Highest Priority First)        |
|        ------------------------------------------------------------------         |
|        WHILE (frontierQueue.length > 0 && evaluatedCount < maxResources):         |
|          1. Pop item with highest priorityScore                                   |
|          2. Domain rate-limiting & visit cap check                                |
|          3. Deduplication check (Canonical URL & Text Hash)                       |
|             -> If duplicate: run Deep Citation Expansion on cached HTML           |
|          4. Fetch full content if text < 300 words                                |
|          5. Recursive Outlink & Citation Extraction (push children into queue)   |
|          6. Heuristic Qualification (reject noise / categories / low-signal)      |
|          7. Structured Entity Extraction & ATT&CK Mapping                         |
|          8. Pristine PDF/HTML Dossier Generation                                  |
|          9. Persistence (Auto-Ingest to MongoDB/SQL OR hold in Discovery Queue)   |
|        ------------------------------------------------------------------         |
| [Done] Finalize Job: status='completed', stage='indexed', update nextRunAt        |
+-----------------------------------------------------------------------------------+
```

### Detailed Lifecycle Phases

#### Phase 0: Initialization & Hydration
1. A unique job ID is generated (`job_...`) and saved to MongoDB/SQL with status `running`.
2. A cancellation token `{ cancel: false, pause: false }` is registered in `activeJobs` (`Map<string, JobControl>`).
3. Seed sources from `SOURCE_SEED` are merged with database records. If `activeSources` is configured, non-matching sources are excluded.
4. Existing canonical URLs and text hashes are pre-loaded into fast in-memory `Set<string>` collections (`storedCanonicalUrls`, `storedHashes`) to enable $O(1)$ deduplication checks.

#### Phase 1: Multi-Vector Discovery (Frontier Population)
- **RSS/Atom Syndication**: Iterates through enabled seed sources with a 4500ms timeout. Parsed articles receive `priorityScore = 0.90` and `depth = 0`.
- **Homepage Crawling**: Fetches root pages, parses all `<a>` tags, eliminates boilerplate links (terms, privacy, login, careers), and enqueues candidate articles with `depth = 1`.
- **Search Expansion**: If search is enabled or a `targetedQuery` was provided, DuckDuckGo HTML is queried. Extracted outbound URLs are filtered against social media/search engine blacklists and enqueued with `priorityScore = 0.99`.
- **Curated Knowledge Pool**: Enqueues fallback verified CTI articles with `priorityScore = 0.95`.

#### Phase 2: Priority Frontier Processing Loop
Items in `frontierQueue` are processed in order of descending `priorityScore`:
$$\text{Dequeued Item} = \arg\max_{i} (\text{item}_i.\text{priorityScore})$$

Per-domain throttling ensures no single domain monopolizes the crawl run. If `domainVisitCounts.get(domain) >= maxPerDomain` and `item.depth > 0`, the item is discarded unless discovered via search expansion.

#### Phase 3: Deduplication & Deep Expansion
If the item's canonical URL exists in `storedCanonicalUrls`:
1. It is marked as `DUPLICATE` in `crawl_job_items`.
2. **Deep Graph Expansion**: If `recursiveDiscovery` is enabled and `depth < maxDepth`, the engine fetches the *previously cached* HTML for that report and extracts outbound citations. Even though the primary report was already ingested, any *new external research papers, advisory links, or repositories* referenced inside it are harvested and added to the frontier.

#### Phase 4: Content Acquisition
If the preloaded content has fewer than 300 words, a full HTTP fetch is dispatched:
- Enforces `rateLimitMs` polite delay.
- User-Agent: `AIE-Autonomous-Threat-Crawler/3.0 (+research; public-cti; threat-emulation-engine)`.
- Respects 8000ms timeout.
- Content-Type handling: strips HTML scripts, styles, and chrome, extracting clean markdown-compatible text. Preserves raw binary for `.pdf`.

#### Phase 5: Recursive Citation Expansion
Extracts outbound hyperlinks from the newly fetched HTML body:
- Identifies external research domains, PDF whitepapers, and GitHub exploit repos.
- Calculates domain trust for new domains.
- Discovers and persists new sources (`DiscoveredSourceRecord`) and citation graph edges (`DiscoveryGraphEdge`).
- Enqueues child items with `depth = current.depth + 1`.

#### Phase 6: Multi-Dimensional Qualification
Evaluates content against path patterns, word counts, marketing noise filters, and threat telemetry keywords. Unqualified items are recorded in `discovered_resources` with status `rejected` and their exact rejection reason.

#### Phase 7: Threat Analysis & Structured Entity Extraction
Qualified items undergo automated heuristic CTI analysis:
- Attribution across 25+ threat actor families.
- Tool/malware family detection.
- MITRE ATT&CK technique matching across 12 tactics.
- Generation of Sigma detection rules, hunting queries, and Atomic Red Team procedures.

#### Phase 8: Pristine PDF Dossier Synthesis
Compiles a publication-quality HTML document incorporating:
- Executive metadata header with SHA-256 hashes and quality badges.
- ATT&CK attack chain visualization.
- Tabular IOC matrix.
- Clean typographic representation of the article body with resolved relative images.

#### Phase 9: Ingestion vs Review Queue
- **`autoIngest === true`**: The report is saved to `reports` (status: `acquired`) and indexed in `discovered_resources` (status: `ingested`).
- **`autoIngest === false`**: The report is held in `discovered_resources` (status: `awaiting_approval`) for analyst inspection in the Discovery Queue.

#### Phase 10: Finalization
Metrics are aggregated (discovered, evaluated, qualified, ingested, duplicates, failed, rejected). The job record is updated to `status: "completed"`. `nextRunAt` is scheduled based on `frequencyMinutes`.

---

## 4. Multi-Vector Discovery Subsystem

The crawler implements three concurrent discovery vectors to ensure both depth and breadth:

```
+-----------------------------------------------------------------------------------+
|                        MULTI-VECTOR DISCOVERY MATRIX                              |
+-----------------------------------------------------------------------------------+
| Vector A: Syndication (RSS / Atom)                                                |
|   Target: Authoritative blogs with established syndication feeds                  |
|   Latency: Real-time (pulls newest publications on each interval)                 |
|   Depth: Depth 0 (Direct permalinks)                                              |
|   Priority: High (0.90)                                                           |
+-----------------------------------------------------------------------------------+
| Vector B: Seed Homepage Exploration                                               |
|   Target: Root landing pages & archive indices of CTI research teams              |
|   Latency: Scheduled polling                                                      |
|   Depth: Depth 1 (Navigates from homepage into recent article permalinks)         |
|   Priority: Medium-High (0.75 - 0.85)                                             |
+-----------------------------------------------------------------------------------+
| Vector C: Real-Time Web & Graph Search Discovery                                  |
|   Target: Open Web (via DuckDuckGo CTI search indices)                            |
|   Latency: On-demand / Targeted hunt queries                                      |
|   Depth: Depth 0 (Direct search results) -> Expands to Depth 1-3                  |
|   Priority: Maximum (0.99)                                                        |
+-----------------------------------------------------------------------------------+
```

### 4.1 RSS 2.0 & Atom 1.0 Syndication (`src/lib/aie/feeds.ts`)

The parser detects XML standards without external heavy dependencies:
- **RSS 2.0**: Matches `<item>` containers. Extracts `<link>`, `<guid isPermaLink="true">`, `<title>`, `<pubDate>`, `<dc:creator>`, `<content:encoded>`, and `<description>`.
- **Atom 1.0**: Matches `<entry>` containers. Extracts `<link rel="alternate" href="...">`, `<title>`, `<published>`, `<updated>`, `<author><name>`, `<content>`, and `<summary>`.
- **CDATA Handling**: Strips or decodes `<![CDATA[...]]>` blocks cleanly.
- **HTML Entity Decoding**: Unescapes XML/HTML entities (`&amp;`, `&lt;`, `&quot;`, `&#x27;`, etc.).
- **URL Validation**: Verifies permalink structure via `isCandidateResourceUrl(link, true)`.

### 4.2 Real-Time Web & Graph Search Discovery (`src/lib/aie/discovery.ts`)

When an analyst triggers a targeted hunt (e.g. `Akira Ransomware ActiveMQ exploitation`) or general search discovery runs, queries are synthesized using structured templates:
- `"${keywords}" threat intelligence technical analysis`
- `"${keywords}" attack chain indicators of compromise`
- `${keywords} cve technical writeup advisory filetype:html OR filetype:pdf`

The crawler dispatches requests to search engine backends, extracts DuckDuckGo encoded redirect targets (`/l/?kh=-1&uddg=(URL)`), strips tracking parameters, tests against the domain blacklist, and injects candidate resource links into the frontier.

---

## 5. Graph Expansion & Domain Trust Scoring Engine

One of the crawling engine's most advanced capabilities is **autonomous citation expansion**. Adversary threat reports frequently reference third-party research: an advisory from CISA might reference a detailed reverse-engineering teardown on *SentinelLABS*, a forensic timeline on *The DFIR Report*, or an exploit proof-of-concept on *GitHub*.

### 5.1 Outlink & Citation Extraction (`extractOutlinksAndCitations`)

The engine parses all `<a>` tags in fetched HTML:
1. Resolves relative URLs (`/posts/123`) against base URLs (`https://unit42.paloaltonetworks.com/article`) using `new URL(rawHref, baseUrl)`.
2. Strips URL fragments (`#section-2`) and marketing tracking parameters:
   `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`, `utm_term`, `ref`, `share`, `fbclid`, `gclid`, `msclkid`.
3. Categorizes the relationship and outlink kind:
   - **`pdf_document`** (`DOWNLOADS_PDF`): Target URL ends with `.pdf`.
   - **`repository`** (`REFERENCES_REPO`): Target domain is `github.com` or `gitlab.com`.
   - **`research_paper`** (`CITES`): Target domain is `arxiv.org`, `researchgate.net`, or `.edu`.
   - **`citation`** (`CITES`): Any external domain.
   - **`internal_article`** (`LINKS_TO`): Internal permalink within the same source domain.

### 5.2 Domain Trust Evaluation Matrix

Every newly encountered domain is evaluated via `evaluateDomainTrust(domain)`:

| Domain Criteria | Trust Score | Classification Reason | Known CTI? |
| :--- | :--- | :--- | :--- |
| **Strict Blacklist** (Social, Video, Generic Search, Ad Networks) | `0.00` | Blacklisted non-technical / social domain | No |
| **Official Government & CERTs** (`.gov`, `.mil`, `cert.*`, `cert-*`) | `0.95` | Official government or CERT / CSIRT domain | Yes |
| **Verified CTI Authorities** (`thedfirreport.com`, `mandiant.com`, `cisa.gov`, etc.) | `0.92` | Verified authoritative CTI & threat research domain | Yes |
| **Academic Repositories** (`arxiv.org`, `.edu`, `researchgate`) | `0.88` | Academic research / preprint repository | No |
| **Technical Code Repositories** (`github.com`, `*.github.io`) | `0.82` | Technical repository / open-source security research | No |
| **Multi-Keyword CTI Domains** ($\ge 2$ terms: `security`, `threat`, `dfir`, `soc`, `labs`) | `0.78` | Domain contains multiple security telemetry terms | Yes |
| **Single-Keyword CTI Domains** ($1$ term: `malware`, `intel`, `cyber`, etc.) | `0.65` | Domain contains security research keywords | No |
| **Unverified External Domains** | `0.45` | Unverified external domain | No |

If an external domain achieves a trust score $\ge 0.60$, the crawler registers it as a **`DiscoveredSourceRecord`** in MongoDB/SQL, allowing analysts to review and approve newly discovered CTI blogs into the permanent seed catalog.

---

## 6. Dual-Tier Deduplication & Content Integrity

To prevent database bloat and redundant processing, the engine utilizes a **dual-tier deduplication architecture**:

```
                              Incoming Resource Candidate
                                          |
                                          v
                         +---------------------------------+
                         |  Tier 1: Canonical URL Matching |
                         +---------------------------------+
                                    /           \
                               Matched        Unmatched
                                 /                 \
                                v                   v
                  +-----------------------+    +-----------------------+
                  | Duplicate by URL      |    | Acquire & Clean Text  |
                  | Trigger Deep Outlink  |    +-----------------------+
                  | Citation Expansion    |                 |
                  +-----------------------+                 v
                                               +---------------------------------+
                                               | Tier 2: Cryptographic SHA-256   |
                                               | Normalized Text Hash Matching   |
                                               +---------------------------------+
                                                          /           \
                                                      Matched        Unmatched
                                                        /                 \
                                                       v                   v
                                         +---------------------+   +---------------------+
                                         | Duplicate Content   |   | Verified Unique:    |
                                         | Discard / Audit     |   | Proceed to Qualify  |
                                         +---------------------+   +---------------------+
```

### 6.1 Tier 1: Canonical URL Normalization (`canonicalizeUrl`)
- Trims whitespace.
- Strips URL hashes/anchors (`#heading-1`).
- Removes trailing slashes on root paths.
- Lowercases hostname.
- Strips query string tracking identifiers.

### 6.2 Tier 2: Cryptographic SHA-256 Content Hash (`sha256Hex`)
The engine implements a pure TypeScript, zero-dependency SHA-256 hashing algorithm operating on `Uint8Array` byte buffers or UTF-8 strings. It computes two distinct hashes:
- **`rawHash`**: SHA-256 of raw HTTP response bytes (cryptographic proof of original wire data).
- **`textHash`**: SHA-256 of normalized plain text content (whitespace collapsed, entities decoded, headers/footers removed).

If `config.dedupMethod` is set to `"smart_hybrid"` (default):
1. Checks canonical URL against `storedCanonicalUrls`.
2. Checks computed `textHash` against `storedHashes`.
3. If an article is syndicated across multiple URLs (e.g., cross-posted from Substack to Medium), the content hash catches the collision.

---

## 7. Content Acquisition & Network Resilience Engine

Web crawling in the threat intelligence domain faces numerous challenges: aggressive Cloudflare protections, dynamic JavaScript rendering, truncated RSS excerpts, and network timeouts.

### 7.1 Polite Fetch & Concurrency Safeguards
- **Adjustable Rate Limiting (`rateLimitMs`)**: Inserts an asynchronous sleep between requests to the same domain (default: 150ms).
- **Timeouts via `AbortController`**: Hard-capped timeouts prevent hanging worker loops:
  - Feed fetches: 4,500ms
  - Search queries: 6,000ms
  - Full article fetches: 8,000ms
- **Research User-Agent**: Identifies the crawler politely and transparently:
  `AIE-Autonomous-Threat-Crawler/3.0 (+research; public-cti; threat-emulation-engine)`

### 7.2 DOM Cleaning & High-Fidelity Text Stripping (`htmlToText`)
When acquiring HTML:
- Removes non-substantive tags: `<script>`, `<style>`, `<noscript>`, `<iframe>`, `<svg>`, `<nav>`, `<header>`, `<footer>`, `<aside>`, `<form>`.
- Preserves semantic line breaks: converts `<br>` and closing tags of `<p>`, `<div>`, `<h1>`-`<h6>`, `<li>`, `<tr>` to standard newlines.
- Converts lists: transforms `<li>` to bullet characters (`• `).
- Collapses consecutive whitespace while preserving paragraph structure.

### 7.3 Binary PDF Handling
If the server responds with `application/pdf` or the URL ends with `.pdf`:
- Raw binary is preserved in an `ArrayBuffer` / `Uint8Array`.
- A cryptographic hash of the PDF payload is calculated.
- Text representation is initialized with PDF evidentiary markers and stored for downstream indexing.

---

## 8. Multi-Dimensional Qualification & Noise Elimination Engine

Generic news, vendor marketing, product sales pitches, and website navigation links pollute threat intelligence pipelines. The crawler implements a rigorous multi-stage qualification engine (`src/lib/aie/qualification.ts`).

### 8.1 URL Pattern Filtering (`isCandidateResourceUrl`)

#### Rejected Path Patterns (Generic / Non-Resource URLs)
```regex
/^\/?$/                                                          # Root domain
/^\/(reports|news|blog|articles|posts|feed|archive|category)/    # Index pages
/\/category\/[^\/]+\/?$/                                         # Category listings
/\/tag\/[^\/]+\/?$/                                              # Tag listings
/\/author\/[^\/]+\/?$/                                           # Author profile pages
/\/wp-json\//                                                    # WordPress REST API
/\/privacy-policy|\/terms-of-service|\/contact-?us?|\/about/    # Corporate boilerplate
/\/login|\/signup|\/register|\/auth/                             # Authentication endpoints
/\/careers|\/pricing|\/cart|\/checkout|\/webinars?/             # Commercial pages
```

#### Accepted Permalinks (High-Probability CTI Resources)
```regex
/\/\d{4}\/\d{2}\/[a-z0-9_-]+/i                                  # e.g. /2026/04/article-slug
/\/(reports|blog|posts|threat-intel|research)\/[a-z0-9_-]{6,}/i  # Long slugs
/\/[a-z0-9_-]+-(ransomware|malware|intrusion|apt\d+|cve-\d+)/i  # Threat slug markers
/\.pdf$/i                                                        # Direct PDF whitepapers
```

### 8.2 Content Qualification & Scoring Algorithm (`qualifyContent`)

Every article is evaluated against a dynamic scoring model:

$$\text{Base Score} = \begin{cases} 0.50 & \text{if originated from verified RSS/Atom feed} \\ 0.38 & \text{if discovered via HTML outlink / web crawl} \end{cases}$$

$$\text{Final Score} = \text{Base Score} + \sum \Delta_{\text{criteria}}$$

#### Score Adjustments ($\Delta$)

| Evaluation Metric | Condition | Score Adjustment ($\Delta$) |
| :--- | :--- | :--- |
| **Substantial Word Count** | $\ge 1,000$ words | $+0.22$ |
| **Moderate Word Count** | $\ge 400$ words | $+0.12$ |
| **High Threat Vocabulary Density** | $\ge 6$ high-signal CTI terms | $+0.28$ |
| **Moderate Threat Vocabulary Density** | $\ge 3$ high-signal CTI terms | $+0.16$ |
| **Low Threat Vocabulary Density** | $\ge 1$ high-signal CTI terms | $+0.08$ |
| **ATT&CK Technique Detection** | Regex `\bT1\d{3}(?:\.\d{3})?\b` matched | $+0.12$ |
| **Vulnerability Detection** | Regex `\bCVE-\d{4}-\d{4,7}\b` matched | $+0.12$ |
| **Cryptographic / Network IOCs** | Hashes (MD5/SHA256) or IPv4 matched | $+0.10$ |

#### Rejection Conditions (Early Exits)
1. **Length Floor**: Under `minWordCount` (default: 100-120 words) **unless** it contains an explicit `CVE` or cryptographic hash (allowing concise emergency zero-day advisories).
2. **Marketing Noise Floor**: Matches $\ge 3$ generic noise terms (`market trends`, `cyber insurance`, `gartner magic quadrant`, `webinar registration`, `product launch`) and $\le 1$ technical terms.
3. **Score Threshold**: Final score below `minQualityScore` (default: 0.35 - 0.40).

### 8.3 Strictness Modes

| Mode | Minimum Score Required | Specific Qualification Rules |
| :--- | :--- | :--- |
| **Permissive** | $\ge 0.30$ | At least 1 technical term, CVE, or IOC hit, or direct feed origin. |
| **Balanced** (Default) | $\ge \text{minQualityScore}$ ($0.35-0.40$) | Minimum score met + at least 1 technical term, CVE, or IOC hit. |
| **Strict** | $\ge 0.65$ (or $\ge 0.50$ with $\ge 2$ terms) | High threat term density mandatory. Non-technical articles discarded. |

### 8.4 Automated Classification & `ResourceKind` Mapping

The engine categorizes qualified reports into 16 distinct classifications and 7 strategic resource kinds:

```
+-----------------------------------------------------------------------------------------+
| Classification: ADVERSARY_EMULATION | PURPLE_TEAM                                      |
| Criteria: Matches 'adversary emulation', 'emulation plan', 'caldera', 'atomic red team' |
| ResourceKind: PROCEDURE_DEEPDIVE                                                        |
+-----------------------------------------------------------------------------------------+
| Classification: ATTACK_CHAIN_REPORT | INTRUSION_REPORT                                  |
| Criteria: Matches 'attack chain', 'infection chain', 'lateral movement', 'timeline'     |
| ResourceKind: FULL_ATTACK_CHAIN                                                         |
+-----------------------------------------------------------------------------------------+
| Classification: MALWARE_ANALYSIS                                                        |
| Criteria: Matches 'reverse engineering', 'payload', 'loader', 'infostealer', 'c2'       |
| ResourceKind: MALWARE_ANALYSIS                                                          |
+-----------------------------------------------------------------------------------------+
| Classification: DETECTION_RESEARCH                                                      |
| Criteria: Matches 'sigma rule', 'yara rule', 'detection engineering', 'hunting query'   |
| ResourceKind: DETECTION_GUIDANCE                                                        |
+-----------------------------------------------------------------------------------------+
| Classification: VULNERABILITY_REPORT                                                    |
| Criteria: Matches CVE identifiers, 'zero-day', 'proof of concept', 'exploit analysis'   |
| ResourceKind: VULNERABILITY_ADVISORY                                                    |
+-----------------------------------------------------------------------------------------+
| Classification: THREAT_ACTOR_REPORT                                                     |
| Criteria: Matches named actors (APT28, Sandworm, Scattered Spider, Volt Typhoon, etc.)  |
| ResourceKind: THREAT_ACTOR_DOSSIER                                                      |
+-----------------------------------------------------------------------------------------+
```

---

## 9. Adversary Threat Modeling & Structured Entity Extraction

Once qualified, the document enters the **Adversary Threat Intelligence & ATT&CK Modeling Engine** (`src/lib/aie/attack-chain.ts`).

### 9.1 Threat Actor Attribution
The engine matches against an expansive catalog of state-sponsored and cybercrime actors, including aliased identifiers:
- **Nation-State**: APT28 (Fancy Bear), APT29 (Cozy Bear / Midnight Blizzard / NOBELIUM), APT38 / Lazarus Group, Sandworm (APT44 / TeleBots), Volt Typhoon (Vanguard Panda), Flax Typhoon, etc.
- **Ransomware & Cybercrime**: LockBit / LockBit 3.0, BlackCat (ALPHV), Akira, Scattered Spider (UNC3944), Black Basta, CL0P (FIN11), Rhysida, BianLian, Play Ransomware.

### 9.2 Tool & Malware Family Detection
Identifies dual-use administration tools and custom malware:
- *Post-Exploitation & C2*: Cobalt Strike, Sliver, Havoc C2, Brute Ratel, Bumblebee, Qakbot, AdaptixC2.
- *Credential Dumping*: Mimikatz, Procdump, LaZagne, Rubeus, Certify.
- *Tunneling & Pivoting*: Chisel, Ligolo-ng, Ngrok, SystemBC.
- *Discovery & AD Mapping*: BloodHound, SharpHound, AdFind, PowerView.
- *Exfiltration*: Rclone, MegaSync, 7-Zip.

### 9.3 MITRE ATT&CK Matrix Mapping & Attack Step Sequencing

The engine matches regex patterns across 12 ATT&CK tactics:

```
[1. Initial Access]    T1190 (Exploit Public-Facing App), T1566 (Spearphishing), T1078 (Valid Accounts)
        |
[2. Execution]         T1059.001 (PowerShell), T1059.003 (CMD), T1047 (WMI), T1204 (User Execution)
        |
[3. Persistence]       T1547.001 (Registry Run Keys), T1053.005 (Scheduled Tasks), T1543.003 (Services)
        |
[4. Privilege Escal.]  T1068 (Exploitation for Priv Escalation), T1548.002 (Bypass UAC)
        |
[5. Defense Evasion]   T1562.001 (Disable Tools/EDR), T1070.001 (Clear Event Logs), T1055 (Process Inject)
        |
[6. Credential Access] T1003.001 (LSASS Dump), T1003.003 (NTDS.dit), T1558.003 (Kerberoasting)
        |
[7. Discovery]         T1087.002 (Domain Accounts), T1018 (Remote Systems), T1069.002 (Domain Groups)
        |
[8. Lateral Movement]  T1021.001 (RDP), T1021.002 (SMB/Admin Shares/PsExec), T1570 (Tool Transfer)
        |
[9. Collection]        T1560.001 (Archive via Utility), T1005 (Data from Local System)
        |
[10. Command & Control]T1071.001 (Web Protocols/HTTPS), T1572 (Tunneling), T1105 (Ingress Tool Transfer)
        |
[11. Exfiltration]     T1567.002 (Cloud Storage Exfil via Rclone), T1048 (Alternative Protocol)
        |
[12. Impact]           T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery/Delete Shadows)
```

The engine generates ordered **`AttackStep`** objects reflecting observed intrusion phases, mapping exact technique IDs to summaries and Indicators of Attack (IOAs).

### 9.4 Automated Detection & Emulation Engineering
From identified TTPs, the engine dynamically generates actionable blue/purple team artifacts:
- **Sigma Rules**: e.g., `Sigma: LSASS Memory Access and Dump Creation (Sysmon EventID 10 / CallTrace comsvcs)`.
- **Hunting Queries**: e.g., `Hunting: Correlate EventID 4624 (Logon Type 3) followed by administrative file writes in ADMIN$ or C$`.
- **Atomic Red Team Emulations**: e.g., `Atomic Test: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Write-Host 'Emulated Execution'"`.

### 9.5 Structured Entity Harvesting (`extractStructuredEntities`)
Extracts command-line procedures (e.g. `vssadmin.exe delete shadows /all /quiet`, `nltest /dclist:`, `mimikatz sekurlsa::logonpasswords`), defensive mitigations, and inferred campaign names.

---

## 10. High-Fidelity PDF & HTML Synthesis Engine

Raw scraped text loses formatting, tables, figures, and visual authority. The engine features a **custom typographic synthesis engine** (`src/lib/aie/pdf.ts`) that compiles publication-grade HTML dossiers optimized for A4 portrait printing and executive distribution.

```
+-----------------------------------------------------------------------------------+
|                        SYNTHESIZED DOSSIER STRUCTURE                              |
+-----------------------------------------------------------------------------------+
| [1. Executive Header Banner]                                                      |
|     - Title, Classification Badge, ResourceKind Badge, Quality Score Gauge        |
|     - Publisher, Author, Publication Date, Ingestion Timestamp                    |
|     - Canonical URL link, Cryptographic Raw SHA-256 & Text SHA-256 Hashes        |
+-----------------------------------------------------------------------------------+
| [2. Executive Threat Intelligence Matrix]                                         |
|     - Attributed Threat Actors (Badge Array)                                      |
|     - Identified Malware & Dual-Use Tools (Badge Array)                           |
|     - Identified CVE Vulnerabilities (Badge Array)                                |
+-----------------------------------------------------------------------------------+
| [3. Reconstructed Attack Chain & Intrusion Timeline]                              |
|     - Step cards: Step Number, MITRE ATT&CK Tactic Name                           |
|     - Tactical Phase Summary, Technique Badges (ID + Name)                        |
+-----------------------------------------------------------------------------------+
| [4. Indicators of Compromise (IOC) Evidentiary Table]                             |
|     - Kind (CVE, Technique, SHA-256, MD5, IPv4) & Value (Monospace)               |
+-----------------------------------------------------------------------------------+
| [5. Detection Engineering & Adversary Emulation Plan]                             |
|     - Sigma Detection Rules, Threat Hunting Queries, Atomic Red Team Commands     |
+-----------------------------------------------------------------------------------+
| [6. Cleaned Substantive Article Body]                                             |
|     - Extracted from <main>, <article>, or .entry-content                         |
|     - Relative links and images resolved to absolute URLs                         |
|     - Scripts, styles, and marketing trackers completely stripped                 |
+-----------------------------------------------------------------------------------+
```

### Key Technical Implementations
- **Substantive Container Extraction (`extractMainContentHtml`)**: Scores DOM containers (`<main>`, `<article>`, `.entry-content`, `.gh-content`, `.post-body`) by clean text volume, picking the deepest substantive container and ignoring site chrome.
- **Truncation Defense**: If extracted HTML contains $< 25\%$ of known word counts, it falls back to decoding plain text and wrapping into clean `<p>` tags to guarantee zero content loss.
- **Print Optimization (`@page { size: A4 portrait; margin: 1.6cm 1.4cm 1.8cm 1.4cm; }`)**: Enforces page-break controls (`break-inside: avoid`), monochrome-friendly border contrast, and automated bottom-right page numbering.

---

## 11. Dual-Storage Persistence Architecture (MongoDB Atlas & PostgreSQL)

The engine implements a **dual-database persistence layer**:
- **Primary Tier**: MongoDB Atlas (Single-Collection Multi-Document Architecture with rich indexing).
- **Secondary / Local Tier**: PostgreSQL (or embedded PGlite via `@/lib/db.ts`) for zero-configuration fallback.

```
                           Storage Routing Switch
                                     |
                         isMongoConfigured() ?
                                   /   \
                             Yes  /     \  No
                                 v       v
                       +---------------+ +-------------------+
                       | MongoDB Atlas | | PostgreSQL /      |
                       | (threat_intel)| | PGlite Store      |
                       +---------------+ +-------------------+
```

### 11.1 MongoDB Atlas Schema & Document Types

All threat intelligence documents reside within a single collection (`threat_intel`), distinguished by the `docType` property:

| `docType` | Purpose | Key Fields |
| :--- | :--- | :--- |
| **`crawl_config`** | Singleton configuration | `enabled`, `paused`, `frequencyMinutes`, `maxDepth`, `strictnessMode`, `targetResourceTypes` |
| **`crawl_job`** | Execution record | `id`, `status`, `triggerType`, `discoveredCount`, `qualifiedCount`, `ingestedCount`, `errorSummary` |
| **`crawl_job_item`** | Line-item audit log | `jobId`, `url`, `canonicalUrl`, `decision`, `reason`, `qualityScore`, `stage`, `depth` |
| **`report`** | Ingested threat dossier | `id`, `title`, `canonicalUrl`, `rawHash`, `textHash`, `extractedText`, `iocs`, `analysis`, `rawHtml` |
| **`discovered_resource`** | URL discovery pool | `canonicalUrl`, `status` (`discovered`, `qualified`, `rejected`, `ingested`, `awaiting_approval`) |
| **`discovered_source`** | Newly discovered domains | `domain`, `trustScore`, `resourceCount`, `parentSource`, `status` |
| **`graph_edge`** | Citation graph edge | `from`, `to`, `relationship` (`CITES`, `DOWNLOADS_PDF`, `REFERENCES_REPO`), `label` |
| **`source`** | Active seed source | `id`, `name`, `slug`, `homepageUrl`, `feedUrl`, `trustLevel`, `enabled`, `lastIngestAt` |
| **`ingest_event`** | Chronological timeline event | `reportId`, `url`, `outcome`, `detail`, `createdAt` |

#### Indexing Strategy (`ensureMongoIndexes`)
- `{ docType: 1, id: 1 }` (Unique compound index)
- `{ docType: 1, canonicalUrl: 1 }` (Unique partial index for `docType: "report"`)
- `{ docType: 1, ingestedAt: -1 }` (Reverse chronological sort for report feed)
- `{ docType: 1, classification: 1 }` (Granular classification filtering)
- `{ docType: 1, resourceKind: 1 }` (Strategic resource kind filtering)
- `{ docType: 1, status: 1 }` (Job and resource status filtering)
- `{ docType: 1, priority: 1 }` (Source priority ordering)
- `{ docType: 1, createdAt: -1 }` (Audit and event streaming)

---

## 12. Server Function API & RPC Specification

The crawling engine exposes type-safe server RPC functions via TanStack Start (`src/lib/aie/server.ts`):

### 1. `getCrawlerState`
- **Method**: `GET`
- **Returns**: `Promise<CrawlerState>`
- **Payload**: Full state bundle containing runtime `config`, `activeJob`, recent `jobs` (10), recent audit `items` (25), `discovered` queue items (40), `discoveredSources`, and `sourceStats`.

### 2. `triggerCrawlJob`
- **Method**: `POST`
- **Input**:
  ```typescript
  {
    triggerType?: "MANUAL" | "SCHEDULED" | "SEARCH" | "API" | "AGENT";
    customQuery?: string;
  }
  ```
- **Returns**: `{ ok: true, job: CrawlJob }`
- **Description**: Spawns an asynchronous crawling job in the background and immediately returns the initial running job state.

### 3. `cancelCrawlJob`
- **Method**: `POST`
- **Input**: `{ jobId: string }`
- **Returns**: `{ ok: boolean }`
- **Description**: Signals the in-memory cancellation token to cooperatively stop the active frontier loop.

### 4. `updateCrawlerConfig`
- **Method**: `POST`
- **Input**: `Partial<CrawlConfig>` (Validated with Zod schema)
- **Returns**: `{ ok: true, config: CrawlConfig }`
- **Description**: Dynamically updates crawler parameters at runtime.

### 5. `ingestDiscoveredUrl`
- **Method**: `POST`
- **Input**: `{ discoveredId: string }`
- **Returns**: `Promise<IngestResult>`
- **Description**: Manually approves and ingests a resource held in the Discovery Queue.

### 6. `exportSTIXBundle`
- **Method**: `GET`
- **Returns**: STIX 2.1 JSON Bundle containing all ingested reports formatted as STIX `report` SDOs with custom MITRE ATT&CK extensions (`x_adversary_*`).

---

## 13. Analyst Console & Operational Workflows

The front-end user interface is located at `/ingest` (`src/routes/ingest.tsx`) and provides seven specialized views:

```
+-----------------------------------------------------------------------------------+
|                        ANALYST OPERATIONAL CONSOLE VIEWS                          |
+-----------------------------------------------------------------------------------+
| 1. Autonomous Crawler Console (Bot)                                               |
|    - Real-time job telemetry: stage badges, progress bars, active URL ticker      |
|    - Live KPIs: Discovered, Evaluated, Qualified, Ingested, Duplicates, Rejected   |
|    - Targeted Threat Hunt Dispatch: input topic to launch live search & expansion |
|    - Controls: "Run Frontier Crawl Now", "Pause Crawler", "Cancel Job"            |
+-----------------------------------------------------------------------------------+
| 2. Discovery Queue (Compass)                                                      |
|    - Review holding pool for resources awaiting approval (when autoIngest=false)  |
|    - Filtering by status: Qualified, Awaiting Approval, Rejected, Ingested        |
|    - Action buttons: "Approve & Ingest", "Batch Ingest", "Reject", "Purge Queue"   |
+-----------------------------------------------------------------------------------+
| 3. Discovery Graph & Sources (Network)                                            |
|    - Interactive topology visualization of CTI knowledge expansion                |
|    - Discovered external domains with automated domain trust scores               |
|    - Graph edge inspection: CITES, DOWNLOADS_PDF, REFERENCES_REPO relationships   |
|    - Action: "Approve Source" promotes discovered domain into active seed catalog |
+-----------------------------------------------------------------------------------+
| 4. Pipeline Audit Log (Activity)                                                  |
|    - Real-time stream of all evaluated URLs and engine decisions                 |
|    - Detailed rejection reasoning: "Too short (<100 words)", "Marketing noise"   |
+-----------------------------------------------------------------------------------+
| 5. Crawler Controls (Settings)                                                    |
|    - Granular runtime configuration sliders and toggles                           |
|    - Strictness mode: Permissive, Balanced, Strict                                |
|    - Throttles: Concurrency, Rate Limit (ms), Max Depth, Max Resources Per Run    |
|    - Feature flags: Auto-Ingest, Auto-Analyze, PDF Generation, RSS/HTML/Search    |
+-----------------------------------------------------------------------------------+
| 6. Manual Ingest (Upload)                                                         |
|    - Direct single URL fetch or raw markdown/text paste with immediate analysis   |
+-----------------------------------------------------------------------------------+
| 7. Curated Catalog (Database)                                                     |
|    - Management table of pre-seeded sources: enable/disable, priority, last ingest|
+-----------------------------------------------------------------------------------+
```

---

## 14. Failure Modes, Fault Tolerance & Error Recovery

| Failure Mode | Root Cause | Engine Defense & Recovery Mechanism |
| :--- | :--- | :--- |
| **Hanging Network Connection** | Unresponsive remote web server | `AbortController` enforces hard cutoffs (4.5s feed, 6s search, 8s article). Worker gracefully aborts without crashing job. |
| **Site Navigation Loop (Crawler Trap)** | Infinite pagination or dynamic calendar archives | `maxResourcesPerDomain` caps visits to any single domain (default: 8-12). `isCandidateResourceUrl` rejects calendar/archive URL patterns. |
| **Database Disconnection** | Network glitch to MongoDB Atlas cluster | Graceful fallback to local SQL storage (`getSql()`). Warnings logged without dropping in-memory frontier queue. |
| **Server Crash / Restart Mid-Crawl** | Container hibernation or revival | Revived server restarts dev server via `/workspace/startup.sh`. In-flight jobs transition to `failed` or resume via scheduler `nextRunAt`. |
| **Content Truncation** | Imperfect DOM selector on custom CMS | Dual-tier fallback: if `<main>` or `<article>` selector yields $< 25\%$ of expected words, engine falls back to `<body>` text wrapping. |
| **Duplicate Attack Reports** | Identical campaign reports syndicated across multiple domains | Smart Hybrid Deduplication: matches canonical URL first; on miss, matches cryptographic SHA-256 text hash. |
| **Job Interruption** | Analyst clicks "Stop/Cancel" in UI | `activeJobs.get(jobId).cancel = true` cooperatively breaks the while-loop. Job status set to `cancelled` with partial metrics preserved. |

---

## 15. Reviewer & AI Agent Checklist

When evaluating the crawling engine during code reviews, security audits, or autonomous subagent passes, verify the following invariants:

1. **Frontier Loop Safety**:
   - [ ] Is `maxTotalResources` strictly bounded to prevent infinite crawling?
   - [ ] Is `maxResourcesPerDomain` enforced on depth $> 0$ seed crawls to prevent spider traps?
   - [ ] Are social media, search engine, and advertising domains blocked in `isBlacklistedDomain`?
2. **Deduplication Correctness**:
   - [ ] Are URL tracking parameters (`utm_*`, `fbclid`, `ref`) stripped before canonical checking?
   - [ ] Does content hashing use normalized text rather than volatile raw HTML with dynamic timestamps?
3. **Qualification Integrity**:
   - [ ] Does `qualifyContent` reject vendor press releases and non-technical business articles?
   - [ ] Is the minimum word count bypass for explicit CVE/hash advisories operating properly?
4. **Network & Operational Politeness**:
   - [ ] Is `rateLimitMs` honored before full-article HTTP fetches?
   - [ ] Is an identifying, respectful User-Agent string passed on every outbound request?
   - [ ] Are all outbound fetches bounded by `AbortController` timeouts?
5. **Data Layer Resilience**:
   - [ ] Does every MongoDB update support graceful fallback to SQL when unconfigured?
   - [ ] Are indexes ensured prior to executing large queries?
   - [ ] Does `autoIngest === false` reliably route items to `awaiting_approval` in the Discovery Queue?
6. **STIX 2.1 Compliance**:
   - [ ] Does `exportSTIXBundle` produce valid STIX 2.1 SDOs with standard external references and confidence scores?
