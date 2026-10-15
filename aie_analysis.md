# Comprehensive End-to-End Audit of Retrieval & Intelligence Preparation Layer

**Target System**: Adversary Intelligence Engine (AIE) / Advisory Threat Intelligence Platform  
**Target Repository**: `/home/havox/dev/Advisory-Threat-Intelligence`  
**Audit Objective**: Determine whether the current retrieval and intelligence layer provides sufficient fidelity, structure, provenance, and context to support the downstream lifecycle:  
$$\text{CTI} \longrightarrow \text{Threat Intelligence} \longrightarrow \text{Advisory Context} \longrightarrow \text{Attack Chain} \longrightarrow \text{Emulation Planning} \longrightarrow \text{Detection Validation}$$  
**Audit Scope**: Retrieval, Ingestion, Deduplication, Qualification, Entity & TTP Extraction, Evidence & Provenance Preservation, ATT&CK Mapping, and Advisory Readiness.

---

## Executive Summary

An exhaustive code audit of the retrieval and intelligence preparation layer reveals a platform with an **ambitious, well-engineered frontier crawling, deduplication, and domain discovery infrastructure**, but with **fundamental semantic, relational, and provenance deficiencies** that currently break the downstream transition to **Advisory Context**, **Emulation Planning**, and **Detection Validation**.

### Key High-Level Findings:
1. **Bag-of-Words Entity Extraction Without Inter-Entity Relationships**: The engine extracts threat actors, tools, CVEs, techniques, procedures, and IOCs as independent, flat lists of strings (`threatActors: string[]`, `procedures: string[]`, `iocs: IocHit[]`). There is zero relational linkage connecting an actor to a specific tool, a tool to a technique, a technique to a concrete procedure command line, or a command line to an observable IOC.
2. **Artificial, Non-Chronological Attack Chains in Automated Pipeline**: During automated crawling and ingestion, the generated `attackChain` (`src/lib/aie/attack-chain.ts`) iterates over the 12 tactics of a static JavaScript object map (`TACTIC_TECHNIQUE_MAP`) in hardcoded order (Initial Access $\rightarrow$ Execution $\rightarrow$ Persistence $\rightarrow \dots \rightarrow$ Impact). It does not reconstruct the empirical sequence of events observed during the actual intrusion.
3. **Loss of Fact-Level Provenance and Evidence Grounding**: Provenance is tracked only at the coarse document level (source URL, canonical URL, SHA-256 hash, discovery hop path). There is zero intra-document sentence, paragraph, or byte-offset grounding. The platform cannot reliably answer: *"Why did we conclude that this actor used this technique?"* beyond pointing to an entire multi-thousand-word document.
4. **Complete Absence of Advisory Targeting Context**: The current ingestion schemas (`ReportRecord`, `IntelAnalysis`, `ExtractedEntities`) store zero metadata for **victim organization industry/sector**, **geographic targeting**, **targeted operating platforms/technologies** (e.g., Windows AD, Azure/Entra ID, AWS, Linux, VMware ESXi), or **adversary strategic objectives** (e.g., financial extortion, espionage, destruction). The dashboard analytics displays for target industries and countries are hardcoded static templates (`KNOWN_ACTOR_PROFILES`, `threatFlows`, `threatRegions` in `dashboard-analytics.ts`) rather than intelligence extracted from collected reports.
5. **Brittle Heuristic ATT&CK Mapping and Defensive Keyword Leakage**: The heuristic extraction covers only 39 hardcoded ATT&CK techniques using naive regexes that frequently trigger on defensive mitigation text (e.g., *"administrators should audit LSASS"* triggers `T1003.001 - OS Credential Dumping`). When the AI Agent evaluation adds techniques, their tactic is hardcoded to `"Execution"` (`crawler.ts#L1684`).
6. **Defanged IOC and Network Infrastructure Blind Spots**: The IOC harvester (`extract.ts`) does not match defanged network indicators (`[.]`, `hxxp`) and never extracts malicious domains or URLs into `iocs` (despite `"domain"` being defined in `IocKind`), discarding critical C2 infrastructure.

---

## A. Current Retrieval Architecture

### 1. What We Currently Retrieve

#### Supported Sources
The platform ingests from three primary source classes:
- **19 Curated Seed Sources** (`src/lib/aie/catalog.ts:SOURCE_SEED`): Authoritative CTI research blogs including *The DFIR Report*, *Unit 42*, *SentinelLABS*, *Huntress*, *Google Threat Intelligence (Mandiant)*, *Microsoft Security*, *Cisco Talos*, *CISA Advisories*, *MITRE ATT&CK Medium*, *SpecterOps*, *Red Canary*, *BleepingComputer*, *Trend Micro*, *AhnLab ASEC*, *Check Point Research*, *SANS ISC*, *Sophos X-Ops*, *Sekoia.io*, and *WeLiveSecurity (ESET)*.
- **Continuous Syndication Feeds**: RSS 2.0 and Atom 1.0 XML feeds specified per source in `SOURCE_SEED[].feedUrl`.
- **Open-Web Search Discovery**: DuckDuckGo HTML scraping using keyword templates (`"threat intelligence technical analysis"`, `"attack chain indicators of compromise"`).
- **Curated Offline Knowledge Pool**: 7 pre-seeded verified incident reports in `discovery.ts:DISCOVERY_KNOWLEDGE_POOL`.

#### Documents, Pages, and Reports Collected
- Technical incident response reports, malware analysis teardowns, intrusion timelines, vulnerability advisories, and threat actor profiling blogs.
- Formats handled:
  - **HTML Web Pages**: Handled via `safeFetchResource` (`security.ts`) and stripped to plain text via `htmlToText` (`extract.ts`).
  - **PDF Documents**: Handled via `extractTextFromPdfBuffer` (`pdf.ts`) using a cascade of `pdf-parse`, `pypdf`, and raw stream regex.
  - **Binary Binaries / Malware Samples**: Explicitly blocked or ignored; only textual analysis is collected.

#### Captured Metadata
The engine captures and persists the following metadata fields on `ReportRecord` (`src/lib/aie/types.ts#L88-L136`):
- `id`: Unique identifier with prefix `rpt_` (e.g. `rpt_...`).
- `sourceId` & `sourceName`: Originating source identifier (e.g. `src_dfir`) and human-readable name.
- `title`: Extracted from HTML `<article> <h1>`, `<meta property="og:title">`, or `<title>`.
- `url` & `canonicalUrl`: Wire URL and normalized URL stripped of tracking parameters.
- `publishedAt`: Publication date extracted from JSON-LD schema, `<meta property="article:published_time">`, or RSS `<pubDate>`.
- `publisher` & `author`: Extracted from JSON-LD schema, `<meta name="author">`, or `extractHtmlMetadata`.
- `contentType`: MIME type (`text/html` or `application/pdf`).
- `wordCount`: Word count of cleaned plain text.
- `qualityScore`: Calculated score (0.00 to 1.00) based on signal terms, word count, and anchors.
- `qualityReasons`: Array of score delta breakdowns (`{ label, delta }`).
- `ingestOrigin`: `"crawl"` | `"citation_expansion"` | `"seed"` | `"live"`.
- `ingestedAt`: ISO timestamp of ingestion.
- `discoveryMethod`: `"rss_feed"` | `"seed_source"` | `"search_expansion"` | `"outlink_citation"`.
- `discoveryPath`: Array of parent URLs forming the traversal ancestry chain.
- `version`: Document revision number.

#### Raw Evidence Preservation & Information Loss
- **Are source URLs, dates, authors, vendors, and titles retained?**  
  **Yes**. All are explicitly retained in `ReportRecord` and MongoDB Atlas.
- **Are documents stored in their original form?**  
  **No**. The original raw HTTP response HTML wire payload is **permanently discarded**. The field `rawHtml` in `ReportRecord` does NOT store the original page; it stores a *synthetically generated HTML dossier* synthesized by `buildPristineDocumentHtml()` (`pdf.ts#L48-L620`). Only the cryptographic SHA-256 hash of the wire payload (`rawHash`) is stored.
- **What information is lost during ingestion or parsing?**
  - All original HTML DOM structure, tables, figures, images, inline code blocks with syntax highlighting, and footnotes are stripped by `htmlToText()` (`extract.ts#L92-L157`).
  - In PDFs, multi-column layout coordinates, embedded tables, diagrams, and figures are lost; only linear plain text is extracted.
  - HTTP headers (ETag, Last-Modified, Cache-Control, server response headers) are discarded and not stored in `ReportRecord`.
- **Complete documents vs. relevant fragments**:
  - The crawler retrieves the complete substantive body if `currentWordCount < 300` triggers a full article fetch (`crawler.ts#L1160-L1224`).
  - However, in RSS feeds with truncated descriptions, if a feed item has $\ge 300$ words of excerpt, the engine skips the full article fetch, retaining only the feed excerpt.
  - Downstream AI analysis in `synthesizeThreatIntelligenceWithAI` (`attack-chain.ts#L360`) and `runUnifiedResourceEvaluation` (`ai-manager.ts#L571`) slices the text to the first **4,500 to 4,800 characters**, discarding the remainder of long-form reports.

---

### 2. How Retrieval Works

```
                                  RETRIEVAL & INGESTION ARCHITECTURE
                                  
   +---------------------------------------------------------------------------------------+
   | DISCOVERY LAYER                                                                       |
   |                                                                                       |
   |  Vector 1: Feeds (feeds.ts)      Vector 2: HTML Permalinks      Vector 3: Search      |
   |  - 19 Seed Sources (catalog.ts)  - Homepage scraping            - DuckDuckGo HTML     |
   |  - RSS 2.0 / Atom 1.0 XML        - Research archive subpaths    - Targeted hunt terms |
   |  - 4500ms timeout via AbortCtrl  - Scoped crawlPattern check    - Knowledge pool (7)  |
   +---------------------------------------------------------------------------------------+
                                              |
                                              v
   +---------------------------------------------------------------------------------------+
   | FRONTIER QUEUE & DEDUPLICATION (crawler.ts)                                           |
   |                                                                                       |
   |  - Priority Queue (frontierQueue sorted by priorityScore descending: 0.99 to 0.45)    |
   |  - Candidate Resource Filter (isCandidateResourceUrl: rejects /category, /tags, etc.) |
   |  - Scope Guard (matchesCrawlPattern: rejects paths outside source crawlPattern)       |
   |  - Tier 1 Dedup: Canonical URL matching against storedCanonicalUrls Set               |
   |  - Tier 2 Dedup: Text SHA-256 hash matching against storedHashes Set                  |
   |  - Tier 3 Dedup: 64-bit SimHash Hamming Distance <= 3 (syndication/cross-post)        |
   +---------------------------------------------------------------------------------------+
                                              |
                                              v
   +---------------------------------------------------------------------------------------+
   | CONTENT ACQUISITION (crawler.ts#L1162 & security.ts:safeFetchResource)                |
   |                                                                                       |
   |  - SSRF Protection (validateSafePublicUrl: blocks private RFC 1918 / loopback / cloud)|
   |  - Rate Limiting: per-domain polite delay (config.rateLimitMs, 150-300ms)             |
   |  - Timeouts: 4500ms (feed), 6000ms (search), 4500ms (article fetch)                   |
   |  - Formats: HTML (htmlToText, extractHtmlMetadata) or PDF (extractTextFromPdfBuffer)  |
   +---------------------------------------------------------------------------------------+
                                              |
                                              v
   +---------------------------------------------------------------------------------------+
   | RECURSIVE EXPANSION (discovery.ts:extractOutlinksAndCitations)                        |
   |                                                                                       |
   |  - Extracts all <a href> outbound links from acquired HTML body                       |
   |  - Classifies relationship: CITES, DOWNLOADS_PDF, REFERENCES_REPO, LINKS_TO          |
   |  - Evaluates target domain reputation (evaluateDomainTrust: 0.00 to 0.95)             |
   |  - Creates DiscoveredSourceRecord (trust >= 0.60) & DiscoveryGraphEdge                |
   |  - Enqueues child links at depth = current.depth + 1 (capped by maxDepth)             |
   +---------------------------------------------------------------------------------------+
                                              |
                                              v
   +---------------------------------------------------------------------------------------+
   | MULTI-TIER QUALIFICATION (qualification.ts:qualifyContent)                            |
   |                                                                                       |
   |  - Length floor: minWordCount (default 200 words, bypassed if CVE/command/IOC exists) |
   |  - Noise filter: detectMarketingNoiseCluster (commercial sales terms)                 |
   |  - Technical Anchor Check: requires >= 1 command, registry key, Event ID, CVE, IOC    |
   |  - Emerging Technique Detector (BYOVD, unhooking, direct syscalls, PRT theft)         |
   |  - Heuristic Scoring: 0.00 to 1.00 (minQualityScore hurdle: 0.35 - 0.40)              |
   |  - Optional 5D Cognitive AI Validation (runUnifiedResourceEvaluation, passScore >= 50)|
   +---------------------------------------------------------------------------------------+
                                     /                 \
                       Qualified (Score >= Min)      Disqualified (< Min / Noise)
                                   /                     \
                                  v                       v
   +---------------------------------------+   +-------------------------------------------+
   | ENTITY & TTP EXTRACTION               |   | DISCOVERY POOL: REJECTED                  |
   |                                       |   |                                           |
   | - Cryptographic Hashes (extract.ts)   |   | - Persisted in discovered_resources       |
   | - IOCs (harvestIocs)                  |   | - Logged in crawl_job_items with reason   |
   | - Actors (KNOWN_ACTORS regex)         |   +-------------------------------------------+
   | - Malware (KNOWN_TOOLS regex)         |
   | - ATT&CK Tactics (TACTIC_TECHNIQUE_MAP|
   | - Procedures (COMMAND_REGEX, <=130ch) |
   | - Sigma / Hunting rules (static text) |
   +---------------------------------------+
                      |
                      v
   +---------------------------------------------------------------------------------------+
   | SYNTHESIS & INGESTION (pdf.ts, crawler.ts, repository.server.ts)                      |
   |                                                                                       |
   |  - Reconstructed HTML Dossier (buildPristineDocumentHtml: metadata banner, tables)   |
   |  - Auto-Ingest Gate:                                                                  |
   |      • autoIngest=true  --> Persist ReportRecord to reports collection (acquired)     |
   |      • autoIngest=false --> Persist DiscoveredResource (awaiting_approval queue)      |
   +---------------------------------------------------------------------------------------+
```

- **Source Discovery**:
  - Seed catalog (`SOURCE_SEED`) hydrates active sources into MongoDB Atlas collection `threat_intel` (`docType: "source"`).
  - External domains encountered in outlinks are evaluated via `evaluateDomainTrust(domain)`. If `trustScore >= 0.60`, the domain is created as a `DiscoveredSourceRecord` (`docType: "discovered_source"`).
- **URL Collection**:
  - RSS feeds parsed for `<link>` or `<guid isPermaLink="true">`.
  - HTML homepages and research archives parsed via regex `/<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a>/gi`.
  - DuckDuckGo search results extracted from redirect URLs `/l/?kh=-1&uddg=(URL)`.
- **Content Fetching**:
  - Executed via `safeFetchResource` in `security.ts#L35-L80` using Node.js native `fetch()`.
  - Enforces `validateSafePublicUrl` to protect against SSRF.
  - Passes user-agent `Mozilla/5.0 ... (compatible; AIE-Threat-Crawler/3.0)`.
- **Content Extraction**:
  - Non-substantive elements stripped (`<script>`, `<style>`, `<nav>`, `<header>`, `<footer>`, `<aside>`, `<form>`, `<svg>`, `<iframe>`).
  - Prioritizes `<article>` or `<main>` containers if length $> 400$ characters (`extract.ts#L125-L133`).
- **Duplicate Handling**:
  - **URL level**: `canonicalizeUrl()` strips tracking parameters and anchors, checked against in-memory `storedCanonicalUrls` Set.
  - **Content level**: SHA-256 hash of normalized plain text checked against `storedHashes` Set.
  - **Syndication level**: 64-bit SimHash with 2-word shingles. If Hamming distance $\le 3$, rejected as near-duplicate syndication (`crawler.ts#L1269-L1302`).
- **Crawling Depth and Scope Control**:
  - `depth` incremented per hop (`depth = current.depth + 1`), capped by `config.maxDepth` (default 2, max 5).
  - Scope controlled by `matchesCrawlPattern()` (`qualification.ts#L203-L278`): only URLs matching the source's crawlPattern prefix (e.g. `https://www.sentinelone.com/labs/*`) are accepted.
  - Anti-trap visit cap per domain (`maxResourcesPerDomain`, default 6–8).
- **Relevant Content Selection**:
  - Negative regex filter (`GENERIC_PATH_PATTERNS`) rejects homepages, author pages, categories, tags, podcasts, webinars, pricing, legal.
  - Permissive anchor check: requires at least one execution command, registry key, Event ID, CVE, or IOC hit (`qualification.ts#L705-L715`).
- **Retrieval Paradigm**:
  - **Hybrid**: Structural URL regex pre-filtering + keyword and heuristic anchor scoring + optional 5-dimensional LLM agent evaluation (`runUnifiedResourceEvaluation`).
- **Citation Following & Document Relationships**:
  - **Yes**, the engine extracts outbound citations via `extractOutlinksAndCitations()` (`discovery.ts#L212`).
  - Graph edges are recorded in `DiscoveryGraphEdge` (`docType: "graph_edge"`) with relationships `CITES`, `DOWNLOADS_PDF`, `REFERENCES_REPO`, `LINKS_TO`.
  - **However**, these relationships exist only as metadata edges in the discovery graph; they are **not synthesized into multi-stage attack chains or campaign narratives**.

---

## B. Current Capabilities (Detailed Verification)

The following capabilities are fully implemented, verified, and operational in the codebase:

1. **Multi-Vector Discovery Frontier Queue**:
   - Supports 3 simultaneous intake vectors (RSS/Atom, HTML seed scraping, DuckDuckGo CTI search).
   - Priority-based scheduling queue (`frontierQueue`) ordered by dynamic `priorityScore` (`crawler.ts#L1002-L1025`).
2. **Three-Tier Deduplication Architecture**:
   - Canonical URL normalization (`extract.ts#L82-L90`).
   - Pure TypeScript zero-dependency cryptographic SHA-256 text hashing (`extract.ts#L10-L80`).
   - 64-bit SimHash locality-sensitive hashing for near-duplicate syndication detection (`extract.ts#L401-L450`).
3. **Outlink Graph Expansion & Domain Trust Scoring**:
   - Traverses outbound hyperlinks from ingested documents (`discovery.ts#L212`).
   - Evaluates domain reputation on a 0.00–0.95 scale based on CERT, government, academic, code repo, and CTI vocabulary markers (`evaluateDomainTrust`).
   - Generates persistent discovery graph edges (`docType: "graph_edge"`).
4. **Strict URL Path Scoping (CrawlPattern Guard)**:
   - Validates candidate URLs against glob and path patterns (`matchesCrawlPattern` in `qualification.ts#L203-L278`), successfully preventing the crawler from straying into vendor marketing, pricing, or product sales pages.
5. **Network Politeness & SSRF Defense**:
   - Hard SSRF blocking of private RFC 1918 subnets, loopback, and cloud metadata (`security.ts#L20-L33`).
   - Polite per-host delay (`rateLimitMs`) with host-aware concurrency dispatch (`crawler.ts#L959-L1025`).
   - Hard abort timeouts on all outbound requests (4.5s to 6.0s).
6. **Multi-Engine PDF Layout Extraction**:
   - Triple-fallback PDF processing engine (`pdf.ts#L873-L891`): `pdf-parse` $\rightarrow$ `pypdf` subprocess $\rightarrow$ raw stream regex.
7. **Pristine Document Synthesis**:
   - Generates self-contained, publication-grade HTML dossiers with executive metadata headers, ATT&CK cards, IOC tables, and A4 print CSS (`pdf.ts#L48-L620`).
8. **Dual-Database Persistence Engine**:
   - Primary single-collection MongoDB Atlas architecture with compound indexes, with automatic zero-configuration fallback to PostgreSQL / embedded PGlite (`repository.server.ts` & `src/lib/db.ts`).

---

## C. Partial Capabilities (Exists but Incomplete or Unreliable)

1. **Threat Actor Extraction**:
   - Regex matches against 25 hardcoded actors in `KNOWN_ACTORS` (`attack-chain.ts#L8-L31`), or flat string extraction in LLM evaluation (`ai-manager.ts#L608`).
   - Disjoint flat string array; no actor alias resolution, attribution criteria, motivation, or confidence score.
2. **Campaign Identification**:
   - Regex matching on document title only (`attack-chain.ts#L324`). Ignores campaign references in body text. Defaults to `null` if title does not contain "Campaign" or "Operation".
3. **Malware and Tool Extraction**:
   - Regex matches against 33 hardcoded tools in `KNOWN_MALWARE_AND_TOOLS` (`attack-chain.ts#L33-L66`) or LLM array `malwareFamilies: string[]`.
   - Disjoint flat string array without functional classification (loader vs. C2 vs. LOLBin vs. ransomware) or hash association.
4. **ATT&CK Tactic and Technique Identification**:
   - Covers only 39 hardcoded techniques across 12 tactics via `TACTIC_TECHNIQUE_MAP` in `attack-chain.ts#L68-L133` ($< 7\%$ of MITRE ATT&CK).
   - In `crawler.ts#L1684`, techniques added via AI evaluation are hardcoded to `tactic: "Execution"`.
5. **Observed Adversary Procedures**:
   - CLI regex matching commands up to 130 characters (`attack-chain.ts#L275-L285`).
   - Truncated at 130 characters; stored as detached strings completely severed from techniques, actors, and host platforms.
6. **Attack Chain Sequencing**:
   - `analyzeThreatIntelligence` (`attack-chain.ts#L161-L214`) assigns step numbers based on the static key order of `TACTIC_TECHNIQUE_MAP` (Initial Access $\rightarrow$ Execution $\rightarrow$ Persistence $\dots \rightarrow$ Impact).
   - Fails to reflect empirical incident timelines or narrative order.
7. **Indicator of Compromise (IOC) Harvesting**:
   - `harvestIocs` (`extract.ts#L270-L294`) extracts CVEs, technique IDs, SHA-256, MD5, and IPv4.
   - Fails on defanged indicators (`185.220.101[.]44`, `hxxps://...`). Never extracts domains or URLs (despite `IocHit.kind = "domain"`). Lacks IOC role tagging.

---

## D. Missing Capabilities & 26-Item Extraction Classification

### Threat Intelligence Extraction Capability Matrix

Every capability requested in the audit specification has been inspected against the codebase and classified:

| Capability Item | Implementation Classification | Evidence in Codebase / Implementation Analysis |
| :--- | :---: | :--- |
| **1. Threat actors** | **PARTIALLY IMPLEMENTED** | Regex matched against 25 actors (`attack-chain.ts#L8-L31`) or LLM array. Flat strings, no alias resolution or confidence. |
| **2. Campaigns** | **PARTIALLY IMPLEMENTED** | Title-only regex (`attack-chain.ts#L324`). Ignores body text; defaults to `null` if title lacks "Campaign". |
| **3. Malware/tools** | **PARTIALLY IMPLEMENTED** | Regex matched against 33 tools (`attack-chain.ts#L33-L66`) or LLM array. Flat strings without functional roles. |
| **4. Victim/target information** | **NOT IMPLEMENTED** | Zero extraction. `ReportRecord` has no schema fields for victim profile, organization size, or revenue. |
| **5. Industries** | **NOT IMPLEMENTED** | Zero extraction from reports. (Static hardcoded sectors exist in `dashboard-analytics.ts:KNOWN_ACTOR_PROFILES`, but not extracted from CTI). |
| **6. Countries/regions** | **NOT IMPLEMENTED** | Zero extraction from reports. (Static mock regions exist in `dashboard-analytics.ts:threatRegions`, but not extracted from CTI). |
| **7. Initial access** | **PARTIALLY IMPLEMENTED** | Extracted via 5 regexes in `TACTIC_TECHNIQUE_MAP["Initial Access"]` (`attack-chain.ts#L69-L75`). Lacks lure/vector details. |
| **8. Execution** | **PARTIALLY IMPLEMENTED** | Extracted via 5 regexes in `TACTIC_TECHNIQUE_MAP["Execution"]` (`attack-chain.ts#L76-L82`). Commands stored in unlinked array. |
| **9. Persistence** | **PARTIALLY IMPLEMENTED** | Extracted via 4 regexes in `TACTIC_TECHNIQUE_MAP["Persistence"]` (`attack-chain.ts#L83-L88`). Lacks trigger/path parameters. |
| **10. Privilege escalation** | **PARTIALLY IMPLEMENTED** | Extracted via 3 regexes in `TACTIC_TECHNIQUE_MAP["Privilege Escalation"]` (`attack-chain.ts#L89-L93`). Lacks token/UAC details. |
| **11. Defense evasion** | **PARTIALLY IMPLEMENTED** | Extracted via 4 regexes in `TACTIC_TECHNIQUE_MAP["Defense Evasion"]` (`attack-chain.ts#L94-L99`) and emerging patterns in qualification. |
| **12. Credential access** | **PARTIALLY IMPLEMENTED** | Extracted via 4 regexes in `TACTIC_TECHNIQUE_MAP["Credential Access"]` (`attack-chain.ts#L100-L105`). Lacks credential types. |
| **13. Discovery** | **PARTIALLY IMPLEMENTED** | Extracted via 3 regexes in `TACTIC_TECHNIQUE_MAP["Discovery"]` (`attack-chain.ts#L106-L110`). Lacks target network scope. |
| **14. Lateral movement** | **PARTIALLY IMPLEMENTED** | Extracted via 3 regexes in `TACTIC_TECHNIQUE_MAP["Lateral Movement"]` (`attack-chain.ts#L111-L115`). Lacks pivoting hop graph. |
| **15. Collection** | **PARTIALLY IMPLEMENTED** | Extracted via 2 regexes in `TACTIC_TECHNIQUE_MAP["Collection"]` (`attack-chain.ts#L116-L119`). Lacks staging directories. |
| **16. Command and control** | **PARTIALLY IMPLEMENTED** | Extracted via 3 regexes in `TACTIC_TECHNIQUE_MAP["Command and Control"]` (`attack-chain.ts#L120-L124`). Lacks beacon profiles. |
| **17. Exfiltration** | **PARTIALLY IMPLEMENTED** | Extracted via 2 regexes in `TACTIC_TECHNIQUE_MAP["Exfiltration"]` (`attack-chain.ts#L125-L128`). Exfil sinks not structured. |
| **18. Impact** | **PARTIALLY IMPLEMENTED** | Extracted via 2 regexes in `TACTIC_TECHNIQUE_MAP["Impact"]` (`attack-chain.ts#L129-L132`). Only ransomware & shadow copy deletion. |
| **19. Infrastructure** | **NOT IMPLEMENTED** | Domains/URLs never harvested into `iocs` (`extract.ts#L270-L294`). No C2 vs victim IP role classification. |
| **20. IOCs** | **PARTIALLY IMPLEMENTED** | Regex extracts CVE, technique, SHA-256, MD5, IPv4. Drops defanged indicators, domains, SHA-1, registry keys, and file paths. |
| **21. Observed procedures** | **PARTIALLY IMPLEMENTED** | Regex extracts CLI prefixes up to 130 chars (`attack-chain.ts#L275-L285`). Truncated and severed from techniques/actors. |
| **22. MITRE ATT&CK techniques**| **PARTIALLY IMPLEMENTED** | Heuristics match 39 techniques. Matrix view maps reports via loose keyword matching (`mitre-matrix.ts#L8068-L8095`). |
| **23. ATT&CK technique IDs** | **IMPLEMENTED** | Valid technique IDs (`T1059.001`, `T1190`, etc.) preserved across `IocHit`, `analysis.ttps`, and `extractedEntities.techniques`. |
| **24. Relationships between techniques** | **NOT IMPLEMENTED** | Zero graph structures or DAG edges representing predecessor/successor relationships between techniques. |
| **25. Attack sequence/order** | **PARTIALLY IMPLEMENTED** | Heuristic ordering is 100% artificial (static tactic object iteration order). LLM re-ordering only exists on manual UI button click. |
| **26. Evidence supporting each extracted fact** | **NOT IMPLEMENTED** | Zero intra-document sentence, paragraph, or byte-offset pointers. Cannot cite exact text supporting an attribution. |

---

## E. Evidence & Provenance Gaps (Traceability Analysis)

An advisory emulation system must be capable of answering the fundamental purple-team question:  
$$\textbf{"Why did we conclude that this threat actor uses this technique, and what exact command did they run?"}$$

### Current Traceability Failure Path

```
Desired Traceability Chain:
Threat Actor  ──►  Source Document  ──►  Exact Evidence Excerpt  ──►  Extracted Statement  ──►  ATT&CK Technique & Procedure
[Volt Typhoon]     [cisa-aa26-088a]      ["the actors executed        ["Volt Typhoon uses       [T1059.001: powershell.exe
                                          powershell.exe -enc..."]      PowerShell for C2"]       -enc W3Zpc3R..."]

ACTUAL CURRENT CODE REALITY:
[Volt Typhoon]     [cisa-aa26-088a]             [NONE]                        [NONE]            [T1059.001] (Flat List)
(Found anywhere    (Full 5,000 word text)    (No paragraph,               (No assertion         (Tactic hardcoded to
in document via    (Raw wire HTML was        sentence, or offset          object or             "Execution" or static
actor keyword)     discarded)                pointer preserved)           confidence)           iteration order)
                                                                                                      |
                                                                                                [procedures] (Flat List)
                                                                                                ["powershell.exe -enc..."]
                                                                                                (NOT linked to T1059.001 or
                                                                                                 to Volt Typhoon!)
```

### Exact Points Where Provenance Is Lost in Code:

1. **Loss of Raw Wire Content**:
   - In `crawler.ts#L1592-L1610` and `pdf.ts#L48-L620`, the original raw HTTP response HTML is transformed into a synthesized HTML dossier via `buildPristineDocumentHtml()`.
   - The original wire HTML is never persisted. Only the computed `rawHash` (SHA-256) is stored. Any structural context, DOM hierarchy, original tables, or inline figure captions present in the original page are permanently discarded.
2. **Whole-Document Bag-of-Words Regex Matching**:
   - In `attack-chain.ts#L138-L178`, `analyzeThreatIntelligence` runs regex searches against the concatenated string `${title}\n${text}`.
   - If an article discusses two unrelated topics (e.g. *"Volt Typhoon compromised a utility using valid accounts. In a separate incident, an unknown actor deployed Akira Ransomware using PowerShell"*):
     - `analysis.threatActors` records `["Volt Typhoon", "Akira"]`
     - `analysis.ttps` records `["T1078.002", "T1059.001", "T1486"]`
     - The system has **no data structure** recording which actor used which technique. In the UI and downstream planning, Volt Typhoon is falsely associated with Akira Ransomware and PowerShell.
3. **Disjoint Entity Arrays in Storage**:
   - `ExtractedEntities` (`types.ts#L76-L86`) defines `techniques: Array<{ id, name, tactic }>` and `procedures: string[]`.
   - There is no foreign key or object reference linking `procedures[0]` to `techniques[0]` or `threatActors[0]`. Traceability between procedures and techniques is 100% broken at the schema level.
4. **No Text Span or Offset Anchors**:
   - Neither `IocHit`, `AttackStep`, nor `ExtractedEntities` stores character offsets (`startOffset`, `endOffset`), paragraph numbers, or verbatim sentence quotes indicating where in `extractedText` the fact was discovered.

---

## F. Advisory Readiness Gaps

The primary goal of this platform is to inform **Advisory Simulation**. An advisory is an actionable operational scenario that answers:  
*"How would Threat Actor $X$ or Campaign $Y$ execute an attack against an organization with Technology Profile $Z$, and how can we emulate and validate detections against it?"*

### Evaluation of Advisory Dimensions in Current Code:

| Advisory Context Dimension | Required for Advisory Simulation | Current Retrieval Implementation | Readiness Status |
| :--- | :--- | :--- | :---: |
| **Threat Actor Context** | Sophistication, motivation, origin, aliases, typical targets. | Only actor name string; no motivation or origin in report record. | **BLOCKED** |
| **Campaign Context** | Named operation, attack window, objectives. | Regex on document title only; defaults to `null` if title lacks "Campaign". | **BLOCKED** |
| **Target Industry** | Financial, Healthcare, Critical Infrastructure, SaaS, Defense. | Zero extraction. `ReportRecord` has no industry field. | **BLOCKED** |
| **Target Geography** | Country, region (US, EMEA, APAC). | Zero extraction. Hardcoded mock displays in dashboard analytics. | **BLOCKED** |
| **Target Technology Stack** | Windows Server, Active Directory, Azure/Entra ID, Linux, ESXi. | Zero extraction. No platform field on `ReportRecord`. | **BLOCKED** |
| **Attack Objectives** | Financial ransom, data exfiltration, wiper sabotage, espionage. | Only coarse `classification` string. | **BLOCKED** |
| **Observed Attack Chain** | Chronological progression with branch conditions and dwell times. | Static tactic iteration order (1 to 12) during automated crawling. | **BLOCKED** |
| **Technique Precision** | Exact sub-technique ID (e.g. `T1059.001`, `T1547.001`). | Partially supported (39 hardcoded regexes or flat AI string IDs). | **PARTIAL** |
| **Concrete Procedures** | Verbatim command lines with execution context. | Regex CLI matches truncated at 130 chars, unlinked from techniques. | **PARTIAL** |
| **Infrastructure & C2** | Domains, IPs, ports, protocols, hosting ASN. | IPs extracted (if un-defanged); domains NOT extracted; roles missing. | **PARTIAL** |
| **Intrusion Timeline** | Duration, elapsed time between access and exfiltration. | Zero intrusion timeline; only document publication date. | **BLOCKED** |
| **Evidence & Provenance** | Verbatim text quote supporting each technique and procedure. | Zero sentence/offset grounding. Bag-of-words document attribution. | **BLOCKED** |
| **Source Reliability** | Source credibility and assertion confidence level. | Source has `trustLevel`, but no per-fact confidence score. | **PARTIAL** |

### Verdict on Advisory Simulation Readiness:
> [!CAUTION]
> The current retrieval layer **CANNOT** properly support the subsequent stages of **Advisory Context**, **Emulation Planning**, and **Detection Validation**.  
> If an operator attempts to plan an adversary emulation from the current intelligence store, the system can only supply:
> 1. A raw article title and stripped body text.
> 2. An artificial, statically-ordered list of tactics.
> 3. Disconnected CLI fragments that may have been run by defenders or unrelated actors.
> 4. Hallucinated emulation commands and Sigma rules generated by prompting an LLM with only the title and technique IDs (`attack-chain.ts#L489-L663`), with zero grounding in what actually happened.

---

## G. Architecture Improvements & Retrieval Gap Analysis

### Concrete Gap Analysis (Mandatory 7-Field Specification)

#### Gap 1: Disjoint Flat Entity Architecture
- **Current behavior**: Threat actors, tools, CVEs, techniques, procedures, and IOCs are stored as independent, flat string arrays in `ReportRecord` and `ExtractedEntities`.
- **Why it matters**: Adversary emulation requires knowing *which* actor ran *which* tool using *which* technique and *which* command line.
- **Impact on advisory simulation**: Emulation planning cannot generate accurate multi-stage playbooks without inventing or hallucinating the missing relationships.
- **Recommended improvement**: Refactor `ExtractedEntities` and `IntelAnalysis` into a relational model where each `EmulationProcedure` object explicitly binds a command line to its parent ATT&CK technique ID, tool, and attributed actor.
- **Priority**: **P0**
- **Relevant code/module**: [`src/lib/aie/types.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/types.ts#L76-L86), [`src/lib/aie/attack-chain.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/attack-chain.ts#L268-L338).

#### Gap 2: Artificial Static Attack Chain Ordering
- **Current behavior**: In automated crawling, `analyzeThreatIntelligence` iterates through the static keys of `TACTIC_TECHNIQUE_MAP`, numbering steps 1 to 12 strictly by tactic order (Initial Access $\rightarrow$ Execution $\rightarrow$ Persistence $\dots \rightarrow$ Impact).
- **Why it matters**: Real intrusions do not follow a rigid linear textbook order. Attackers frequently dump credentials before establishing persistence, or execute discovery prior to lateral movement.
- **Impact on advisory simulation**: Produces unrealistic emulation playbooks that fail to replay the adversary's actual sequence of actions.
- **Recommended improvement**: Implement narrative intrusion timeline extraction that orders stages based on chronological markers in the report text (e.g. "Stage 1", "Initial Access occurred at", "Following lateral movement").
- **Priority**: **P0**
- **Relevant code/module**: [`src/lib/aie/attack-chain.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/attack-chain.ts#L161-L214).

#### Gap 3: Zero Fact-Level Evidence Grounding (Loss of Traceability)
- **Current behavior**: Provenance is recorded only at the document level (`canonicalUrl`, `sourceId`, `rawHash`). Individual facts (actors, techniques, commands) have no text-span anchors or verbatim quotes.
- **Why it matters**: Security analysts, red teams, and detection engineers cannot verify why a technique was assigned without reading the entire document.
- **Impact on advisory simulation**: Emulation engineers cannot trust generated atomic tests or detection rules because they cannot verify the underlying empirical evidence.
- **Recommended improvement**: Attach an `evidenceAnchor: { verbatimQuote: string, startOffset: number, endOffset: number, confidence: number }` to every extracted procedure, technique, and IOC.
- **Priority**: **P0**
- **Relevant code/module**: [`src/lib/aie/types.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/types.ts#L42-L86), [`src/lib/aie/attack-chain.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/attack-chain.ts#L161-L338).

#### Gap 4: Missing Advisory Targeting Context
- **Current behavior**: Ingestion schemas capture zero data on victim industry, geography, operating environment, or attack objectives.
- **Why it matters**: Organizations cannot filter threat intelligence by relevance to their industry (e.g., "Show me threats targeting Financial Services in APAC on AWS").
- **Impact on advisory simulation**: Cannot generate targeted, threat-informed emulation scenarios relevant to the organization's specific tech stack and risk profile.
- **Recommended improvement**: Introduce `AdvisoryContext` in `types.ts` capturing `targetIndustries[]`, `targetGeographies[]`, `targetedPlatforms[]`, and `adversaryObjectives[]`, populated during qualification and extraction.
- **Priority**: **P0**
- **Relevant code/module**: [`src/lib/aie/types.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/types.ts#L88-L136), [`src/lib/aie/qualification.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/qualification.ts#L500-L750), [`src/lib/aie/ai-manager.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/ai-manager.ts#L564-L640).

#### Gap 5: Defanged IOC Loss & Domain Blindness
- **Current behavior**: `harvestIocs` regexes fail to match defanged indicators (`185.220.101[.]44`, `hxxps://...`) and never extract domains or URLs.
- **Why it matters**: Authoritative CTI sources mandate defanging to prevent accidental execution. The engine discards the majority of network C2 indicators.
- **Impact on advisory simulation**: Red teams cannot emulate realistic C2 egress or configure network boundary indicators because C2 domains and IPs are omitted.
- **Recommended improvement**: Add a pre-extraction `refangText()` pipeline step and implement domain/URL harvesting with role tagging (`c2_server`, `payload_delivery`, `staging`).
- **Priority**: **P1**
- **Relevant code/module**: [`src/lib/aie/extract.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/extract.ts#L264-L294).

#### Gap 6: Hardcoded "Execution" Tactic Bug
- **Current behavior**: In `crawler.ts#L1684`, when techniques are extracted by the AI Agent, their tactic is hardcoded:
  ```typescript
  extractedEntities.techniques.push({ id: techId, name: techId, tactic: "Execution" });
  ```
- **Why it matters**: Misclassifies Initial Access (T1190), Credential Access (T1003), and Impact (T1486) as "Execution".
- **Impact on advisory simulation**: Corrupts MITRE ATT&CK matrix analytics and generates invalid kill-chain stage assignments.
- **Recommended improvement**: Lookup the authoritative ATT&CK tactic from `mitre-matrix.ts:MITRE_TACTICS_DATA` based on the technique ID.
- **Priority**: **P1**
- **Relevant code/module**: [`src/lib/aie/crawler.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/crawler.ts#L1684).

#### Gap 7: Defensive Mitigation Keyword Leakage
- **Current behavior**: Heuristic regexes in `attack-chain.ts` match technique keywords regardless of linguistic context (e.g. *"to prevent credential dumping, restrict LSASS"* matches `T1003.001`).
- **Why it matters**: Defensive recommendations are ingested as adversary offensive tradecraft.
- **Impact on advisory simulation**: Generates false-positive emulation objectives where defender advice is emulated as attacker actions.
- **Recommended improvement**: Add negative lookbehind assertions or use small language model (SLM) parsing to verify offensive intent before technique attribution.
- **Priority**: **P1**
- **Relevant code/module**: [`src/lib/aie/attack-chain.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/attack-chain.ts#L68-L133).

#### Gap 8: Discarded Raw Wire HTML
- **Current behavior**: Original fetched HTML bytes are discarded; only stripped text and synthesized printable HTML are retained.
- **Why it matters**: Cannot re-parse original tables, figures, or DOM structures if extraction logic improves.
- **Impact on advisory simulation**: Prevents re-extracting complex forensic tables, execution diagrams, or code blocks that were lost in the initial regex pass.
- **Recommended improvement**: Store compressed raw HTML payload (e.g. Gzip in S3/MongoDB GridFS or raw text column) alongside synthesized dossier.
- **Priority**: **P2**
- **Relevant code/module**: [`src/lib/aie/crawler.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/crawler.ts#L1592-L1610), [`src/lib/aie/pdf.ts`](file:///home/havox/dev/Advisory-Threat-Intelligence/src/lib/aie/pdf.ts#L48-L620).

---

## H. Priority Classification & Retrieval Quality Evaluation

### 1. Retrieval Quality Pitfall Evaluation

| Pitfall | Architectural Status in Current System | Analysis & Where Architecture Prevents or Allows |
| :--- | :---: | :--- |
| **Hallucinated intelligence** | **ALLOWED (in on-demand AI mode)** | Automated heuristic crawling does not hallucinate facts from thin air, but on-demand synthesis (`synthesizeThreatIntelligenceWithAI` in `attack-chain.ts#L349`) and emulation planning (`generateEmulationPlanWithAI` in `attack-chain.ts#L579`) prompt the LLM with only the title and flat technique IDs over a truncated 4.8k snippet, encouraging the model to hallucinate commands and stages not present in the text. |
| **Unsupported ATT&CK mappings** | **ALLOWED (High Frequency)** | Allowed by naive regex keyword matching in `attack-chain.ts#L68-L133` which triggers on defensive mitigations (e.g., auditing LSASS, disabling PowerShell), and by loose keyword matching in `mitre-matrix.ts#L8068-L8095` where generic words like "scanning" assign reports to T1595. |
| **Duplicate intelligence** | **PREVENTED** | Well-guarded by three-tier deduplication: canonical URL normalization, cryptographic SHA-256 text hash, and 64-bit SimHash Hamming distance $\le 3$ for syndication cross-posts (`crawler.ts#L1268-L1302`). |
| **Outdated intelligence treated as current** | **ALLOWED** | Allowed by default. While `publishedAt` is captured, the crawler does not enforce a publication age cutoff unless `config.dateRangeDays` is explicitly configured. An article from 2018 discovered via citation outlink is ingested and weighted identically to a zero-day advisory from 2026. |
| **Loss of source context** | **ALLOWED** | The original wire HTML is discarded; only stripped text and a synthesized printable layout are preserved. Original inline diagrams, tables, and DOM hierarchies are lost. |
| **Loss of evidence** | **ALLOWED** | Intra-document evidence is 100% lost. No sentence, paragraph, or byte offsets connect extracted actors, techniques, or procedures to their source text. |
| **Incorrect actor/technique relationships** | **ALLOWED** | All entities in an article are extracted into disjoint flat arrays. If an article mentions two actors and four techniques, the system binds all techniques to all actors simultaneously. |
| **Fragmented attack chains** | **ALLOWED** | Multi-report intrusions covering different phases of the same campaign are stored as disconnected reports; the system lacks a campaign graph merger. |
| **False relationships caused by unrelated documents** | **ALLOWED** | Outlink extraction (`discovery.ts#L242-L330`) parses all `<a>` tags in the HTML, including blogroll sidebars, "popular posts" widgets, and footer links, generating false `CITES` graph edges to unrelated sites. |
| **Over-reliance on a single source** | **ALLOWED** | The system ingests single reports without verifying assertions against secondary sources or calculating cross-source consensus confidence. |

---

### 2. Consolidated Priority Triage

- **P0 — Blocks the Advisory Workflow**:
  1. *Disjoint Flat Entity Architecture*: Unlinked actors, techniques, and procedures prevent building valid emulation scenarios (`types.ts`, `attack-chain.ts`).
  2. *Artificial Static Attack Chains*: Hardcoded tactic key iteration order produces fake kill chains (`attack-chain.ts`).
  3. *Zero Fact-Level Evidence Grounding*: Inability to cite supporting source sentences destroys verification and trust (`types.ts`, `attack-chain.ts`).
  4. *Zero Advisory Targeting Context*: Absence of industry, geography, platform, and objective metadata blocks threat-informed emulation scoping (`types.ts`, `qualification.ts`, `ai-manager.ts`).

- **P1 — Major Quality & Reliability Issues**:
  1. *Defanged IOC Loss & Domain Blindness*: Regexes discard defanged indicators and malicious domains (`extract.ts`).
  2. *Hardcoded "Execution" Tactic Bug*: AI-discovered techniques default to Execution tactic, corrupting the MITRE matrix (`crawler.ts#L1684`).
  3. *Defensive Mitigation Keyword Leakage*: Defender advice is ingested as adversary techniques (`attack-chain.ts`).
  4. *Loose Keyword Matching in Matrix View*: Matrix false-positive assignments (`mitre-matrix.ts#L8068`).

- **P2 — Important Improvements**:
  1. *Preserve Original Wire HTML*: Retain original HTML payload for table/figure re-extraction (`crawler.ts`, `pdf.ts`).
  2. *Body-Text Campaign Extraction*: Extract campaign names from article body, not title only (`attack-chain.ts`).
  3. *Dynamic Dashboard Analytics*: Replace hardcoded mock arrays with real database aggregations (`dashboard-analytics.ts`).

- **P3 — Future Enhancements**:
  1. *Multi-Source Campaign Graph Fusion*: Corroborating multiple reports into a unified campaign DAG (`discovery.ts`).
  2. *Sitemap & Historical Wayback Backfill*: Traversal of historical threat archives (`crawler.ts`).

---

## I. Recommended Retrieval Contract (The Next-Stage Guarantee)

Before the platform proceeds to **Advisory Context Generation**, **Attack Chain Synthesis**, and **Advisory Emulation Planning**, the retrieval and intelligence preparation layer must guarantee a strict, typed intermediate object contract for every ingested threat intelligence entity.

### Standard Machine-Readable Contract Schema

```typescript
export interface StandardAdvisoryIntelligenceContract {
  // 1. Provenance & Cryptographic Ingestion Audit
  provenance: {
    reportId: string;                  // Canonical ID (rpt_...)
    sourceId: string;                  // Originating seed or discovered source ID
    sourceName: string;                // e.g. "The DFIR Report", "CISA"
    sourceUrl: string;                 // Exact wire fetch URL
    canonicalUrl: string;              // Normalized URL (tracking stripped)
    sourceDomain: string;              // FQDN of publisher
    sourceTrustScore: number;          // 0.00 to 1.00 domain trust
    publishedAt: string | null;        // Document publication date (YYYY-MM-DD)
    ingestedAt: string;                // ISO timestamp of ingestion
    discoveryPath: string[];           // Provenance ancestry hop chain
    rawSha256: string;                 // Hash of raw wire payload
    textSha256: string;                // Hash of normalized body text
    simhash64: string;                 // 64-bit structural similarity fingerprint
    extractionMethod: "heuristic" | "llm_agent" | "hybrid";
    overallQualityScore: number;       // 0.00 to 1.00
  };

  // 2. Advisory Context & Targeting Relevance
  advisoryContext: {
    targetIndustries: Array<{
      sector: string;                  // e.g. "Energy", "Healthcare", "Financial Services"
      evidenceQuote?: string;          // Verbatim supporting text excerpt
    }>;
    targetGeographies: Array<{
      countryOrRegion: string;         // e.g. "United States", "Taiwan", "EMEA"
      evidenceQuote?: string;
    }>;
    targetedPlatforms: Array<{
      platform: "windows" | "linux" | "macos" | "cloud" | "identity" | "ot_scada" | "network";
      environment?: string;            // e.g. "Active Directory", "Azure Entra ID", "VMware ESXi"
      evidenceQuote?: string;
    }>;
    adversaryObjectives: Array<"ransomware" | "data_exfiltration" | "espionage" | "wiper_sabotage" | "credential_theft">;
    campaign: {
      name: string | null;             // e.g. "2026 Ivanti Connect Secure Mass Exploitation"
      observedTimeframe?: {
        startDate?: string;
        endDate?: string;
        dwellTimeDays?: number;
      };
      evidenceQuote?: string;
    };
  };

  // 3. Attributed Adversary Entities
  entities: {
    threatActors: Array<{
      canonicalName: string;           // e.g. "Volt Typhoon"
      aliases: string[];               // e.g. ["Vanguard Panda", "Bronze Silhouette"]
      attributionConfidence: number;   // 0.00 to 1.00
      evidenceQuote: string;           // Excerpt demonstrating attribution in document
    }>;
    malwareAndTools: Array<{
      name: string;                    // e.g. "Cobalt Strike", "Chisel", "Mimikatz"
      category: "c2_agent" | "loader" | "credential_dumper" | "tunneling" | "lolbin" | "ransomware" | "wiper";
      isCustomMalware: boolean;
      evidenceQuote: string;
    }>;
    vulnerabilities: Array<{
      cveId: string;                   // e.g. "CVE-2023-46805"
      vendorProduct?: string;          // e.g. "Ivanti Policy Secure"
      isZeroDay: boolean;
      evidenceQuote: string;
    }>;
  };

  // 4. Grounded, Chronological Attack Progression (Relational Graph)
  attackProgression: {
    stages: Array<{
      stageNumber: number;             // Chronological order (1, 2, 3...)
      stageName: string;               // e.g. "Perimeter Gateway Exploitation"
      primaryTactic: string;           // MITRE ATT&CK Tactic Name
      tacticId: string;                // e.g. "TA0001"
      summary: string;
      procedures: Array<{
        techniqueId: string;           // e.g. "T1190"
        techniqueName: string;         // e.g. "Exploit Public-Facing Application"
        subTechniqueId?: string;       // e.g. "T1059.001"
        commandLine?: string;          // Verbatim command line executed by adversary
        executionPlatform: "windows" | "linux" | "macos" | "network" | "cloud";
        requiredPrivileges?: "user" | "admin" | "system";
        associatedTool?: string;       // e.g. "curl", "PowerShell"
        observableTelemetry: {
          eventIds: string[];          // e.g. ["Sysmon 1", "Security 4688"]
          filePathsWritten: string[];  // e.g. ["C:\\Windows\\Temp\\loader.exe"]
          registryKeysModified: string[]; // e.g. ["HKLM\\Software\\...\\Run"]
          c2Endpoints: string[];       // e.g. ["185.220.101.44:443", "update-service-cdn.com"]
        };
        evidenceAnchor: {
          verbatimQuote: string;       // Exact sentence from source document
          startOffset: number;         // Character offset in extracted text
          endOffset: number;
          confidence: number;          // 0.00 to 1.00
        };
      }>;
    }>;
    transitionEdges: Array<{
      fromStage: number;
      toStage: number;
      transitionDescription: string;   // e.g. "Loader retrieves C2 beacon and spawns injection target"
    }>;
  };

  // 5. Normalized Technical Indicators
  indicators: Array<{
    kind: "ipv4" | "ipv6" | "domain" | "url" | "sha256" | "md5" | "sha1";
    value: string;                     // Fully refanged indicator
    rawDefangedValue?: string;         // Original defanged string (e.g. "185.220.101[.]44")
    role: "c2" | "payload_hash" | "stager" | "compromised_host" | "exfil_sink";
    evidenceQuote: string;
  }>;

  // 6. Actionable Purple-Team Emulation Specifications
  emulationEngineering: {
    atomicEmulationCommands: Array<{
      techniqueId: string;
      testName: string;
      executor: "powershell" | "cmd" | "bash" | "sh";
      safeReplayCommand: string;       // Safe, non-destructive test command
      cleanupCommand?: string;
      validationCriteria: string;      // What detection log proves coverage
    }>;
    detectionRules: Array<{
      ruleType: "sigma" | "yara" | "hunting_kql" | "hunting_spl";
      title: string;
      ruleContent: string;             // Valid Sigma YAML or YARA syntax
      mitreTag: string;                // e.g. "attack.t1059.001"
    }>;
  };
}
```

---

## Conclusion

The current retrieval layer possesses a **strong engineering foundation for web discovery, politeness, crawling boundaries, and dual-database storage**. However, because it extracts threat data as **disconnected flat string arrays**, uses an **artificial tactic-ordered sequence instead of true chronological intrusion chains**, **omits all advisory targeting dimensions (industry, geography, platform, objectives)**, and **drops evidence provenance at the sentence level**, it currently fails to provide the necessary information required for downstream **Advisory Context**, **Emulation Planning**, and **Detection Validation**.

Implementing the schema refactoring and relational extraction improvements defined in this audit will elevate the platform from a generic CTI document scraper into a true **Adversary Emulation Intelligence Engine**.
