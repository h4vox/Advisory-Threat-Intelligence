# Adversary Intelligence Engine (AIE)
## Master Development Plan – Practical, Phased & Workable

**Version:** 1.0 (Consolidated & Realistic)  
**Date:** 2026-09-01  
**Status:** Ready for Execution  
**Audience:** Solo founder / small technical team  

---

## 1. Vision (One Sentence)

Turn high-quality public adversary reports into structured, ATT&CK-mapped attack chains and organization-aware simulation plans that red/purple teams can actually use.

---

## 2. Core Principles (Non-Negotiable)

1. **Evidence first** – Every extracted fact must link back to source text.
2. **Observed → Equivalent → Simulated** – Never claim a simulation is the exact real procedure.
3. **Attack Flow is primary** – Sequence (Action → Condition → Action) matters more than a flat list of Txxxx.
4. **Workable every phase** – Each phase must produce something you can demo and use.
5. **Ruthless prioritization** – Cut everything that is not required for the next usable increment.

---

## 3. Recommended Architecture (Practical Version)

```
┌─────────────────────────────────────────────────────────────┐
│                    SOURCE LAYER                             │
│  DFIR Report | Unit 42 | Seqrite | SentinelLABS | Huntress  │
│  Mandiant | Microsoft TI | (manual + semi-automated)        │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                 INGESTION + STORAGE                         │
│  Raw HTML/PDF → Clean Text → Content Hash → Metadata       │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              EXTRACTION ENGINE (Hybrid)                     │
│  Rules + Regex (IOCs, tools, CVEs)                          │
│  LLM (stages, attack flow, technical analysis)              │
│  Evidence linking + Confidence scoring                      │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│            STRUCTURED KNOWLEDGE                             │
│  Report → Ordered Stages → Techniques → Evidence            │
│  Attack Flow Graph                                          │
│  IOCs / Tools / Actors                                      │
└────────────┬───────────────────────────────┬────────────────┘
             │                               │
             ▼                               ▼
┌──────────────────────────┐    ┌──────────────────────────────┐
│  ORGANIZATION CONTEXT    │    │  SIMULATION PLANNING         │
│  Assets + Tech Stack     │    │  Path generation             │
│  Feasibility scoring     │    │  Multi-difficulty plans      │
└────────────┬─────────────┘    └──────────────┬───────────────┘
             │                                 │
             └────────────────┬────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    OUTPUT LAYER                             │
│  Structured JSON + Human Markdown Runbooks                  │
│  Simple Web / CLI Interface                                 │
└─────────────────────────────────────────────────────────────┘
```

**Key Design Decision:**  
Keep the system as a knowledge + planning engine first.  
Do **not** build full execution orchestration, real-time telemetry ingestion, or multi-tenant SaaS in the early phases.

---

## 4. Phased Development Roadmap

### Phase 0 – Foundation (1–2 weeks)
**Goal:** Project skeleton + basic data storage that works.

**Deliverables:**
- Clean project structure (Python preferred)
- Source registry (YAML or JSON)
- Raw document storage (local filesystem or S3-compatible)
- Content hashing + basic deduplication
- Simple CLI to add a report manually
- Local ATT&CK Enterprise data loaded (JSON from MITRE)

**Success Criteria:**
- You can add a report URL or file and store it with metadata.
- ATT&CK techniques are queryable locally.

**Workable Output:** CLI command that ingests a local report file and stores it.

---

### Phase 1 – Core Extraction (3–5 weeks)
**Goal:** Turn unstructured reports into usable structured infection chains.

**Focus Sources (start narrow):**
1. The DFIR Report (excellent timelines)
2. Unit 42 (strong stage + ATT&CK content)
3. Seqrite Technical posts (very structured format)

**Deliverables:**
- Hybrid extraction pipeline:
  - Deterministic extraction for IOCs, tool names, CVEs, file paths, commands
  - LLM-based extraction for:
    - Ordered infection / attack stages
    - Technical analysis per stage
    - Tools / malware used
    - Attribution signals
- Evidence linking (every field stores source snippet + confidence)
- Structured output schema (JSON)
- Basic validation + human review queue for low-confidence items

**Success Criteria:**
- Successfully process ≥ 15 high-quality reports
- Majority of clear technical procedures have usable stages
- Every extracted item has evidence + confidence

**Workable Output:**  
Given a report → produces a clean JSON with ordered stages, techniques candidates, IOCs, and evidence.

---

### Phase 2 – ATT&CK Mapping + Knowledge Graph (2–3 weeks)
**Goal:** Reliable default mapping + queryable knowledge.

**Deliverables:**
- ATT&CK mapping engine (semantic + keyword + LLM justification)
- Confidence + evidence for every mapping
- Simple knowledge graph (Neo4j or even PostgreSQL + relations for POC)
- Ability to query:
  - All reports using T1059.001
  - Common attack chains
  - Techniques by stage

**Success Criteria:**
- High-confidence mappings on clear procedures
- You can ask “show me all credential access → lateral movement chains” and get results

**Workable Output:**  
Searchable knowledge base of real attack chains with ATT&CK IDs.

---

### Phase 3 – Organization Context + Path Generation (2–3 weeks)
**Goal:** Make plans relevant to a specific environment.

**Deliverables:**
- Simple Organization Profile model:
  - Critical assets
  - Technology stack (OS, identity, cloud, endpoint)
  - High-level controls
- Feasibility scoring of techniques against the profile
- Path generation engine:
  - Objective-driven (e.g. “reach domain controller”)
  - Multi-difficulty variants
  - Ranking by realism + organizational relevance

**Success Criteria:**
- Different organization profiles produce different recommended paths
- At least 3 distinct objectives generate usable multi-stage paths

**Workable Output:**  
“Generate simulation paths for this environment and objective” → ranked paths.

---

### Phase 4 – Plan Generation & Interface (2–3 weeks)
**Goal:** Produce ready-to-use plans.

**Deliverables:**
- Automated plan generator (JSON + clean Markdown runbook)
- Plan contents:
  - Objective
  - Ordered stages
  - Mapped techniques
  - Procedures / expected artifacts
  - Success criteria
  - Cleanup notes
  - Organization-specific notes
- Simple interface (CLI first, then basic web UI)
- Manual feedback capture (thumbs up/down + comments on extraction quality)

**Success Criteria:**
- Operator can generate a plan and follow it without reading the original report
- Plans export cleanly

**Workable Output:**  
End-to-end: Report → Structured Chain → Organization-aware Simulation Plan (Markdown + JSON)

---

### Phase 5 – Hardening & Evaluation (1–2 weeks)
**Goal:** Measure quality and prepare for real use.

**Deliverables:**
- Evaluation set of held-out reports
- Metrics: extraction completeness, mapping precision, plan usability
- Confidence calibration
- Documentation + demo scenarios
- Basic monitoring / logging

**Success Criteria:**
- Clear numbers on quality
- Demo that impresses a red/purple team lead

---

## 5. What to Explicitly Defer (Do Not Build Yet)

- Full autonomous crawling of dozens of sources
- Emerging Behavior Engine (interesting but later)
- Full Attack Flow visual composer
- Execution orchestrator + adapters (Atomic, CALDERA, etc.)
- Real-time telemetry & detection validation loop
- Multi-tenancy / collaboration features
- Advanced knowledge graph analytics
- Production-grade web application

These become Phase 6+ only after the core loop works reliably.

---

## 6. Recommended Data Model (Minimal but Sufficient)

```text
Report
├── id, source, title, url, published_at, content_hash
├── summary
├── infection_chain: [Stage]
├── iocs: [IOC]
├── actors / campaigns (optional)
└── attck_coverage

Stage
├── order
├── name / kill_chain_phase
├── description / technical_analysis
├── techniques: [TechniqueMapping]
├── tools
├── artifacts
└── evidence

TechniqueMapping
├── attck_id
├── confidence
├── evidence
└── procedure_text

OrganizationProfile
├── critical_assets
├── tech_stack
├── controls_summary
└── feasibility_rules

SimulationPlan
├── objective
├── difficulty
├── stages (expanded)
├── organization_notes
└── export_artifacts
```

---

## 7. Suggested Technology Choices (POC)

| Layer              | Recommendation                          | Reason |
|--------------------|-----------------------------------------|--------|
| Language           | Python 3.11+                            | Ecosystem + LLM libraries |
| Web Framework      | FastAPI                                 | Fast, modern, good for APIs |
| Storage            | PostgreSQL + JSONB (or SQLite early)    | Simple + powerful |
| Graph (optional)   | Neo4j (or stay relational initially)    | Only if needed |
| LLM                | Structured output / function calling    | Critical for extraction |
| Frontend (later)   | Simple React or even Streamlit/Gradio   | Speed over polish |
| Orchestration      | Local scripts + cron / Prefect          | Keep simple |

---

## 8. Immediate Next Actions (This Week)

1. Create the project repository and basic structure (Phase 0).
2. Manually process 3–5 excellent reports (DFIR Report + Unit 42) into the target JSON schema by hand.  
   → This becomes your gold standard evaluation set.
3. Implement basic ingestion + storage.
4. Build the first hybrid extraction pipeline against those gold reports.
5. Measure extraction quality before adding more sources.

---

## 9. Definition of Done for the Entire POC

You have a working system when:

- You can feed it a high-quality report
- It produces a structured infection chain with evidence
- It maps techniques with confidence
- It generates an organization-aware multi-stage simulation plan in Markdown + JSON
- A red/purple team operator can take that plan and execute/test without reading the original report
- Quality is measurable and improving

---

## 10. Final Advice

Do not try to build the full vision at once.  
The power of this product comes from **high-quality extraction + useful plans**, not from having every module listed in the long documents.

Ship Phase 1–4 solidly.  
Everything else becomes much easier once the core loop works and real users give feedback.

---

**This document is now the single source of truth.**  
Ignore previous overly ambitious versions when making daily decisions.  
Focus only on the next phase that produces something workable.
