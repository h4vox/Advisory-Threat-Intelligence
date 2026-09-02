# Adversary Intelligence Engine (AIE)
## Proof-of-Concept Plan – High-Level Technical & Product Documentation

**Version:** 0.1 (POC)  
**Status:** Research → POC Design  
**Target Users:** Red Teamers, Purple Teams, Adversary Simulation / Emulation Platforms, Detection Engineers  
**Core Focus:** Transform real-world adversary threat analysis reports into structured, ATT&CK-mapped infection chains and environment-aware simulation plans.

---

## 1. Vision

Build a high-context platform that continuously ingests premium adversary analysis reports from leading public sources, automatically reconstructs clear infection chains with technical depth, applies default MITRE ATT&CK mapping, and combines this knowledge with organization-specific context to generate realistic multi-level simulation paths and executable plans.

The system exists to eliminate the manual work of reading reports, mapping TTPs, reconstructing attack chains, and writing simulation plans. It turns scattered high-quality threat research into a living, queryable, simulation-ready knowledge base.

---

## 2. Problem Statement

Current state of adversary simulation and red teaming:

- High-quality technical reports (Unit 42, SentinelLABS, Mandiant, Huntress, Seqrite, Microsoft TI, etc.) contain rich infection chains, stage-by-stage technical analysis, infrastructure details, attribution signals, and IOCs.
- These reports remain largely unstructured and high-level for operational use.
- Manual mapping to MITRE ATT&CK is time-consuming and inconsistent.
- There is no unified system that:
  - Maintains a continuously updated library of real infection chains
  - Applies reliable default ATT&CK mappings
  - Overlays organization context (critical assets, tech stack, controls, detection gaps)
  - Generates multi-difficulty simulation paths and ready-to-use plans
- Existing tools (ATT&CK Navigator, Atomic Red Team, CALDERA, commercial CTI platforms) solve only parts of this problem. None combine continuous high-quality report ingestion + automatic chain reconstruction + default ATT&CK mapping + organization-aware path generation in one coherent system.

Result: Red teams and simulation operators still spend excessive time on knowledge collection, mapping, and plan writing instead of execution and analysis.

---

## 3. Solution Overview

**Adversary Intelligence Engine (AIE)** is a modular platform with two primary layers:

1. **Adversary Knowledge Layer**  
   Continuous ingestion → structured extraction of infection chains → default MITRE ATT&CK mapping → living knowledge graph of real-world TTPs, stages, tools, infrastructure, and IOCs.

2. **Simulation Planning Layer**  
   Organization context model + powerful mapping/path engine → automated and manual generation of multi-level (beginner → advanced) simulation plans that are directly usable by operators or simulation frameworks.

The platform is designed as both a standalone knowledge & planning system and an API-first engine that existing simulation tools can consume.

---

## 4. POC Scope

### In Scope for POC
- Ingestion pipeline for a prioritized set of high-quality sources
- Structured extraction of infection chains, named stages, technical analysis, tools, infrastructure/attribution signals, and IOCs
- Default MITRE ATT&CK (Enterprise) mapping with confidence scoring
- Knowledge graph foundation storing reports, chains, techniques, and relationships
- Basic organization context model (critical assets + technology stack + simple feasibility scoring)
- Simulation path generation engine (objective-driven, multi-difficulty)
- Automated plan generation with export to structured formats (JSON + human-readable Markdown)
- Simple web or CLI interface for exploration and plan creation
- Feedback capture mechanism (manual for POC)

### Out of Scope for POC (Future)
- Full production-scale crawling of all sources
- Advanced multi-tenancy and collaboration features
- Deep integration with every simulation framework
- Fully automated continuous emulation scheduling
- Community contribution / shared knowledge mode
- Executive risk dashboards

---

## 5. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Source Layer                                 │
│  Seqrite | Unit 42 | SentinelLABS | Proofpoint | Huntress |         │
│  Mandiant/GTIG | Microsoft TI | ESET | Talos | (extensible)         │
└────────────────────────────┬────────────────────────────────────────┘
                             │ Crawl / Poll / API
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Ingestion Layer                                 │
│  - Source registry & prioritization                                 │
│  - Content download & raw storage                                   │
│  - Deduplication & quality filtering                                │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Extraction & Structuring Engine                        │
│  - Hybrid (rules + LLM/NLP) extraction                              │
│  - Infection chain reconstruction                                   │
│  - Stage naming + technical analysis extraction                     │
│  - IOC normalization + attribution signals                          │
│  - Confidence scoring + evidence linking                            │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│           Default MITRE ATT&CK Mapping Engine                       │
│  - Semantic + keyword + LLM-assisted mapping                        │
│  - Tactic / Technique / Sub-technique assignment                    │
│  - Confidence + evidence for every mapping                          │
│  - Report-level coverage summary                                    │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Knowledge Graph                                    │
│  Nodes: Report, Stage, Technique, Tool, IOC, Actor, Infrastructure  │
│  Edges: ordered chains, mappings, relationships, provenance         │
└────────────┬───────────────────────────────┬────────────────────────┘
             │                               │
             ▼                               ▼
┌────────────────────────────┐   ┌────────────────────────────────────┐
│  Organization Context      │   │  Mapping & Path Generation Engine  │
│  - Critical assets         │   │  - Objective → real TTP matching   │
│  - Tech stack & controls   │   │  - Multi-difficulty path building  │
│  - Feasibility scoring     │   │  - Organization-aware ranking      │
│  - Detection gap awareness │   │  - Variant generation              │
└────────────┬───────────────┘   └───────────────┬────────────────────┘
             │                                   │
             └───────────────┬───────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Plan Generation & Export                               │
│  - Automated full plans                                             │
│  - Manual plan builder support                                      │
│  - Runbook-level detail (procedures, expected artifacts, cleanup)   │
│  - Export: JSON (machine), Markdown/PDF (human), simulator formats  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Module Specifications & Algorithms

### 6.1 Source Ingestion Layer

**Purpose**  
Reliably collect high-value adversary analysis content from prioritized sources.

**Prioritized Sources**
| Priority | Source                        | Content Focus                              |
|----------|-------------------------------|--------------------------------------------|
| 1        | Seqrite Technical Archive     | Detailed malware / infection-chain ops     |
| 1        | Unit 42                       | Technical attack-chain investigations      |
| 1        | SentinelLABS                  | Deep malware + TTP technical analysis      |
| 2        | Proofpoint Threat Insight     | Campaigns + initial-access chains          |
| 2        | Huntress                      | Real enterprise intrusion timelines        |
| 2        | Mandiant / GTIG               | Full adversary operations                  |
| 2        | Microsoft Threat Intelligence | Windows / AD / Entra / cloud attacks       |
| 3        | ESET WeLiveSecurity           | Deep malware / APT research                |
| 3        | Cisco Talos                   | Malware / campaign / infrastructure        |
| Ref      | MITRE ATT&CK                  | TTP normalization baseline                 |

**Algorithm**
1. Maintain a source registry (URL patterns, update frequency, content type, priority, quality weight).
2. Scheduled or event-driven polling/crawling.
3. Detect new or updated documents.
4. Download and store raw content with full metadata (source, URL, title, published date, content hash).
5. Apply quality filters (minimum length, presence of technical indicators, malware/TTP keywords, structure signals).
6. Deduplicate via content hash + semantic similarity.
7. Queue accepted documents for extraction.
8. Log all ingestion events for observability.

---

### 6.2 Extraction & Structuring Engine

**Purpose**  
Convert unstructured reports into a consistent, high-context structured representation of an adversary operation.

**Target Structured Output (per report)**
- Metadata (source, date, title, URL)
- Executive / initial findings summary
- Ordered infection / attack chain
- Named stages with:
  - Stage name / Kill Chain alignment
  - Technical analysis
  - Tools / malware / procedures used
  - Observed artifacts
- Infrastructure & attribution signals
- Normalized IOCs (file hashes, domains, IPs, emails, paths, registry, etc.)
- Victimology / targeting notes
- Timeline (if present)

**Algorithm**
1. Pre-process: clean text, remove boilerplate, segment into logical sections.
2. Hybrid extraction pipeline:
   - Deterministic rules + regex for high-precision elements (IOCs, tool names, CVE references, file paths).
   - LLM / advanced NLP for narrative understanding, stage boundary detection, and technical analysis extraction.
3. Reconstruct ordered infection chain by identifying sequential stages and causal relationships.
4. For each stage extract description, techniques, tools, technical details, and artifacts.
5. Normalize all IOCs into standard schemas.
6. Extract attribution and infrastructure indicators.
7. Assign confidence scores and link evidence snippets to every extracted field.
8. Output a versioned structured document (JSON/YAML).
9. Flag low-confidence extractions for optional human review.

---

### 6.3 Default MITRE ATT&CK Mapping Engine

**Purpose**  
Apply reliable, auditable MITRE ATT&CK mappings to every extracted procedure and stage by default.

**Algorithm**
1. Maintain an up-to-date local copy of MITRE ATT&CK Enterprise (tactics, techniques, sub-techniques, descriptions, examples).
2. For each extracted procedure / technical description:
   - Generate embeddings and perform semantic similarity against ATT&CK technique descriptions.
   - Apply keyword and pattern matching.
   - Use LLM reasoning to propose best-matching technique(s) with explicit justification.
3. Validate candidate mappings against known high-confidence patterns and historical mappings.
4. Attach ATT&CK IDs (tactic + technique + sub-technique where applicable) with confidence score and evidence.
5. Produce a report-level ATT&CK coverage summary.
6. Store all mappings with full provenance.

---

### 6.4 Knowledge Graph

**Purpose**  
Central living repository of adversary knowledge with rich relationships.

**Core Node Types**
- Report
- Stage
- Technique (linked to ATT&CK)
- Tool / Malware
- IOC
- Actor / Group
- Infrastructure

**Core Relationships**
- Report → ordered Stages
- Stage → Techniques / Tools / Artifacts
- Technique → ATT&CK ID
- Cross-report entity resolution (same malware, same C2, same actor)

**Algorithm (Graph Construction)**
1. Ingest structured report.
2. Create or update nodes.
3. Create ordered edges for the infection chain.
4. Link techniques to ATT&CK and tools.
5. Perform entity resolution across the graph.
6. Update aggregate statistics (common chains, frequent techniques per stage, etc.).

---

### 6.5 Organization Context Layer

**Purpose**  
Make knowledge and generated plans relevant to a specific environment.

**Minimum POC Model**
- Critical assets with business impact scores
- Technology stack (OS, identity, cloud, endpoint, network)
- High-level security control presence
- Simple technique feasibility scoring

**Algorithm**
1. Ingest organization profile (manual upload or basic connectors for POC).
2. Tag techniques with applicability / feasibility scores based on the environment.
3. Identify high-value attack paths toward critical assets.
4. Provide filtered and ranked technique sets to the path engine.

---

### 6.6 Mapping & Simulation Path Engine

**Purpose**  
Generate realistic, multi-difficulty simulation paths using real extracted TTPs and organization context.

**Algorithm**
1. Receive objective (e.g., “phishing → credential access → lateral movement to finance systems”, difficulty level, coverage goals).
2. Query knowledge graph for real-world chains and techniques matching the objective.
3. Apply organization context filters and feasibility scores.
4. Construct ordered paths:
   - Respect prerequisite relationships and common real-world sequences observed in reports.
   - Generate variants at different difficulty levels.
5. Attach concrete procedures, tools, and expected artifacts from the knowledge base.
6. Rank paths by realism, organizational relevance, and coverage.
7. Return one or more scored paths.

---

### 6.7 Plan Generation & Export

**Purpose**  
Produce ready-to-use simulation plans.

**Plan Contents**
- Objective and scope
- Ordered stages aligned to infection chain + ATT&CK
- Per-stage: mapped techniques, detailed procedures, tools, expected artifacts, success criteria, cleanup notes
- Organization-specific annotations
- Difficulty level and estimated complexity
- Coverage summary

**Export Formats (POC)**
- Structured JSON (machine-readable)
- Markdown (human operator runbook)
- Basic compatibility lists for Atomic Red Team style tests

**Algorithm**
1. Take selected path(s) from the path engine.
2. Expand each node into detailed executable steps using stored technical analysis.
3. Insert organization context notes.
4. Generate success criteria and logging points.
5. Package into requested formats.
6. Store versioned plan for reuse.

---

## 7. Key Data Model Outline (POC)

```text
Report
├── id, source, title, url, published_at, raw_content_hash
├── summary
├── infection_chain: [Stage]
├── iocs: [IOC]
├── attribution_signals
└── att&ck_coverage

Stage
├── name / kill_chain_phase
├── technical_analysis
├── techniques: [TechniqueMapping]
├── tools
└── artifacts

TechniqueMapping
├── att&ck_id (Txxxx or Txxxx.xxx)
├── confidence
├── evidence
└── procedure_description

OrganizationProfile
├── critical_assets
├── tech_stack
├── controls_summary
└── feasibility_rules

SimulationPlan
├── objective
├── difficulty
├── stages (expanded)
├── organization_annotations
└── export_artifacts
```

---

## 8. Suggested Technology Direction (POC)

- **Ingestion**: Python-based crawlers + scheduled jobs (Scrapy / custom + Playwright for JS-heavy sites where needed)
- **Extraction & Mapping**: Hybrid deterministic + LLM pipeline (structured output via function calling / JSON mode)
- **Knowledge Store**: Graph database (Neo4j or equivalent) + document store for raw/structured reports
- **Search**: Vector embeddings for semantic search + structured queries
- **API**: FastAPI or equivalent
- **Interface**: Simple web UI (or CLI-first for pure POC) for browsing chains and generating plans
- **Export**: JSON Schema + Markdown templating

Exact library choices can be finalized during implementation; the architecture remains technology-agnostic at the logical level.

---

## 9. POC Implementation Roadmap

### Phase 0 – Foundation (1–2 weeks)
- Project structure, source registry, raw storage
- Basic ingestion for 2–3 Tier-1 sources
- ATT&CK data loading

### Phase 1 – Extraction & Mapping Core (3–5 weeks)
- Hybrid extraction pipeline for infection chains and IOCs
- Default ATT&CK mapping with confidence
- Structured output schema and validation
- Initial knowledge graph population

### Phase 2 – Context + Path Engine (2–3 weeks)
- Organization context model
- Path generation algorithm (objective → ranked paths)
- Basic multi-difficulty support

### Phase 3 – Plan Generation & Interface (2–3 weeks)
- Automated plan packaging (JSON + Markdown)
- Simple exploration + plan generation UI or CLI
- Manual feedback capture for extraction quality

### Phase 4 – Evaluation & Hardening (1–2 weeks)
- Quality evaluation on held-out reports
- Confidence calibration
- Documentation and demo scenarios

**Total estimated POC duration**: 9–15 weeks depending on team size and LLM infrastructure maturity.

---

## 10. Success Criteria for POC

- Successfully ingest and structure ≥ 30 high-quality reports from Tier-1/2 sources with usable infection chains.
- Achieve acceptable ATT&CK mapping precision (target: high confidence on majority of clear technical procedures).
- Demonstrate generation of multi-stage simulation plans for at least 3 distinct objectives at two difficulty levels.
- Show organization context influencing path ranking (e.g., different plans for different tech stacks).
- Export plans that a red team operator can follow without additional research.
- Clear evidence that extraction quality and mapping confidence are measurable and improvable.

---

## 11. Key Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|----------|
| Inconsistent extraction quality across sources | High | Hybrid approach + confidence scoring + human review queue + continuous evaluation set |
| LLM hallucination on technical details | High | Evidence linking, deterministic IOC extraction, validation against known patterns |
| Source access / scraping fragility | Medium | Prioritize sources with stable structures; implement robust monitoring and fallback |
| Organization context too shallow | Medium | Start simple but design schema for rapid enrichment |
| Overlap with existing tools | Medium | Focus on the unique combination: real infection chains + default mapping + org-aware planning |

---

## 12. High-Value Extensions (Post-POC)

- Detection opportunity mapping (Sigma / YARA / KQL suggestions per technique)
- Threat actor & campaign clustering over time
- Interactive LLM planning assistant (“Build me an intermediate plan for …”)
- Synthetic procedure variation for increased realism
- Rich attack path visualization and coverage heatmaps
- Deeper simulation framework integrations (CALDERA, Atomic, Attack Flow)
- Feedback loop from real execution results
- Emerging technique detection (procedures that do not map cleanly to current ATT&CK)

---

## 13. Positioning Statement

AIE is not another threat intelligence platform or another ATT&CK navigator.  
It is a **simulation-oriented adversary knowledge engine** that turns the best public technical analyses into structured, mapped, organization-aware infection chains and ready-to-execute simulation plans — minimizing the manual process that currently consumes red team and adversary simulation effort.

---

**Document Control**  
This README serves as the single source of truth for the POC plan.  
All major design decisions, module boundaries, and success criteria are defined here.  
Implementation details (exact schemas, prompts, evaluation metrics) will be refined in subsequent technical design documents.
Here are high-quality source reports and archives that typically contain clear infection chains, initial findings, named stages, technical analysis of each stage, infrastructure/attribution, IOCs, and ATT&CK mapping.
Best Source Archives (Start Here)









































PrioritySourceArchive / Main HubWhy It’s Excellent🥇Seqrite Technical Archivehttps://www.seqrite.com/blog/category/technical/Almost every post has explicit sections: Infection Chain, Initial Findings, Technical Analysis Stage 1 / Stage 2 / Stage 3…, Infrastructure & Attribution, IOCs, MITRE ATT&CK🥇Unit 42https://unit42.paloaltonetworks.com/Strong infection-chain diagrams, stage-by-stage breakdowns, ATT&CK mapping, IOCs, and infrastructure analysis🥇SentinelLABShttps://www.sentinelone.com/labs/Deep technical analysis, modular malware breakdowns, attribution, IOCs🥈Huntresshttps://www.huntress.com/blogReal enterprise intrusion timelines with ordered stages and ATT&CK mapping🥈Mandiant / Google Threat Intelligencehttps://cloud.google.com/blog/topics/threat-intelligenceFull adversary operations, ATT&CK tables, detailed TTPs

Concrete High-Quality Example Reports
Seqrite (best structured for your use case)

Browse the Technical category above — recent posts consistently follow this exact structure:
Infection Chain
Initial Findings
Looking into the Decoy Document
Technical Analysis → Stage 1, Stage 2, Stage 3…
Infrastructure & Attribution
IOCs
MITRE ATT&CK


Unit 42

XCSSET v40 Infection Chain Analysis (explicit 4-stage chain + modules)
Search on Unit 42 site for “XCSSET v40” (published ~Aug 2026)
Cascading Shadows: An Attack Chain Approach
https://unit42.paloaltonetworks.com/phishing-campaign-with-complex-attack-chain/
Large-Scale Cloud Extortion Operation (ATT&CK-mapped stages)
https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/

SentinelLABS

Follow the Smoke – China-nexus ShadowPad activity (detailed intrusion chains)
https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/
ShadowPad technical deep-dive (modular analysis)
https://www.sentinelone.com/labs/shadowpad-a-masterpiece-of-privately-sold-malware-in-chinese-espionage/

Huntress

Real intrusion write-ups with chronological timelines + ATT&CK tables
Example style: https://www.huntress.com/blog/untold-tales-from-tactical-response

Additional Useful Repositories

Unit 42 IOC repository (supporting many public reports):
https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information
Older Unit 42 IOCs archive:
https://github.com/pan-unit42/iocs


Recommendation for Your POC

Primary focus → Seqrite Technical Archive (most consistent structure matching exactly what you described).
Secondary → Unit 42 (excellent diagrams + ATT&CK) and SentinelLABS (deep technical depth).
Use Huntress for real-world enterprise timeline examples.
---

