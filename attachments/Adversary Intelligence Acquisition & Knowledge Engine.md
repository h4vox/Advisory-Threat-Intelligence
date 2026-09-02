# Adversary Intelligence Acquisition & Knowledge Engine

## AI-Driven Web Intelligence, Attack-Chain Extraction, Knowledge Base & Report Generation Platform

---

## 1. Product Overview

This project is an **AI-driven adversary intelligence acquisition and knowledge engineering platform** designed to continuously discover, collect, understand, classify, structure, and store publicly available cybersecurity intelligence.

The system is designed primarily for:

- Detection Engineering
- Threat Hunting
- Purple Team operations
- Adversary Emulation
- Attack Simulation
- Threat Intelligence
- Security Research
- Security Validation
- MITRE ATT&CK analysis
- Incident-response research
- Adversary behavior analysis

The system should **not behave like a conventional static web scraper**.

Instead, it should operate as an **agent** capable of:

1. Searching for relevant cybersecurity resources.
2. Discovering individual reports/articles from source websites.
3. Extracting individual resource URLs.
4. Understanding what each resource contains.
5. Following relevant links when necessary.
6. Discovering additional useful resources dynamically.
7. Extracting attack chains and adversary behavior.
8. Identifying Tactics, Techniques and Procedures (TTPs).
9. Identifying malware, tools, vulnerabilities, infrastructure and IOCs.
10. Mapping observations to MITRE ATT&CK.
11. Classifying the resource into knowledge-base categories.
12. Generating detection-engineering opportunities.
13. Generating threat-hunting opportunities.
14. Identifying simulation/emulation opportunities.
15. Preserving the original source document.
16. Converting HTML/blog/web content into a standardized PDF representation.
17. Storing the source and extracted intelligence in a structured knowledge base.
18. Making everything available to downstream AI agents through MCP.

---

# 2. Core Philosophy

The most important design principle is:

> **The system must be dynamic and intelligence-driven, not hardcoded around a fixed list of websites, URLs, keywords, selectors, or attack techniques.**

The system must not depend on logic such as:

```text
IF website == "example.com":
    use selector X

IF URL contains "/reports/":
    extract article

IF keyword == "ransomware":
    classify as ransomware
```

This type of implementation becomes fragile very quickly.

Instead:

```text
User/Agent Request
        ↓
Intent Understanding
        ↓
Search Strategy Generation
        ↓
Source Discovery
        ↓
URL Discovery
        ↓
Resource Classification
        ↓
Content Acquisition
        ↓
AI Content Understanding
        ↓
Entity Extraction
        ↓
Attack-Chain Reconstruction
        ↓
MITRE Mapping
        ↓
Knowledge Classification
        ↓
Detection/Hunting/Simulation Analysis
        ↓
Knowledge Base
        ↓
PDF / Original Artifact
```

The system should continuously adapt its strategy based on what it discovers.

---

# 3. Primary Goal

The primary goal is:

> **Convert publicly available cybersecurity research into structured, searchable, attack-oriented intelligence that can directly support detection engineering, threat hunting, purple-team activities, adversary emulation and security validation.**

For example, a public incident report may describe:

```text
Initial Access
    ↓
Execution
    ↓
Credential Access
    ↓
Discovery
    ↓
Lateral Movement
    ↓
Persistence
    ↓
Command & Control
    ↓
Collection
    ↓
Exfiltration
    ↓
Impact
```

The system should transform that narrative into machine-readable intelligence.

---

# 4. What This System Is NOT

This project is not intended to be:

- A simple HTML scraper
- A Google search wrapper
- A website-specific crawler
- A static keyword database
- A basic PDF downloader
- A news aggregator
- A bookmark manager
- A collection of URLs
- A simple MITRE ATT&CK viewer

The system should instead become an **intelligence acquisition and analysis layer**.

---

# 5. Source Types

The system should support multiple types of cybersecurity resources.

## 5.1 Incident Reports

These are extremely important because they describe real-world attack activity.

Examples:

- The DFIR Report
- Mandiant / Google Threat Intelligence
- Unit 42
- Cisco Talos
- Microsoft Threat Intelligence
- CrowdStrike
- Secureworks
- Sophos X-Ops
- SentinelLabs
- Rapid7
- IBM X-Force

Expected information:

```text
Victim
Threat Actor
Initial Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Credential Access
Discovery
Lateral Movement
Collection
C2
Exfiltration
Impact
Malware
Tools
Infrastructure
IOCs
TTPs
Detection opportunities
```

---

## 5.2 Threat Actor Research

Examples:

- Threat actor profiles
- Campaign analysis
- Actor evolution
- Infrastructure research
- Malware campaigns
- Long-running intrusion campaigns

Expected output:

```text
Actor
Aliases
Campaigns
Targeting
Malware
Tools
Infrastructure
TTPs
Techniques
Known procedures
Timeline
Related incidents
```

---

## 5.3 Malware Research

Examples:

- Malware analysis
- Ransomware analysis
- Loader analysis
- RAT analysis
- Stealer analysis
- Backdoor analysis
- Botnet research

Expected output:

```text
Malware family
Capabilities
Execution
Persistence
C2
Credential access
Defense evasion
Collection
Exfiltration
IOCs
TTPs
Detection opportunities
```

---

## 5.4 Vulnerability / Exploitation Research

Examples:

- CVE exploitation
- Exploit-chain analysis
- Mass exploitation
- Zero-day exploitation
- Initial-access research
- Vulnerability-to-ransomware cases

Expected output:

```text
CVE
Affected software
Initial access
Exploit mechanism
Post-exploitation
Threat actors
Malware
Observed TTPs
Detection opportunities
Mitigations
```

---

## 5.5 Adversary Emulation

Examples:

- AttackIQ research
- MITRE ATT&CK resources
- Center for Threat-Informed Defense research
- Adversary emulation plans
- Threat-informed defense reports

Expected output:

```text
Actor
Scenario
Objective
Tactics
Techniques
Procedures
Prerequisites
Execution steps
Expected telemetry
Detection opportunities
Validation criteria
```

---

## 5.6 Attack Simulation

Examples:

- Atomic Red Team
- MITRE CALDERA
- BAS research
- Purple-team scenarios
- Security validation exercises

Expected output:

```text
Technique
Simulation
Prerequisites
Execution concept
Expected behavior
Expected telemetry
Detection
Validation
```

---

## 5.7 Security Advisories

Examples:

- CISA advisories
- Vendor security advisories
- CERT publications
- Government cybersecurity alerts

Expected output:

```text
Vulnerability
Threat
Affected products
Attack method
Exploitation
Mitigation
Detection
Observed actors
Related campaigns
```

---

# 6. Source Discovery Model

The system should begin from configured **seed sources**, but seeds are only starting points.

For example:

```yaml
seed_sources:
  - source_name: The DFIR Report
    source_type: incident_reports

  - source_name: Google Threat Intelligence
    source_type: threat_research

  - source_name: Unit 42
    source_type: threat_research

  - source_name: MITRE ATT&CK
    source_type: knowledge

  - source_name: AttackIQ
    source_type: adversary_emulation
```

These should NOT become permanent limitations.

The AI agent must be allowed to discover additional relevant sources.

---

# 7. Dynamic Source Discovery

If the agent receives:

```text
Find recent ransomware attack-chain reports.
```

It should not only search configured sources.

It should:

```text
Understand intent
      ↓
Generate search concepts
      ↓
Search multiple sources
      ↓
Identify candidate domains
      ↓
Evaluate source quality
      ↓
Discover individual reports
      ↓
Extract reports
      ↓
Analyze reports
```

It may discover:

```text
Incident response report
Threat actor report
Malware analysis
Ransomware investigation
Adversary emulation report
CISA advisory
Vendor research
```

The agent can expand the source set when the newly discovered source is relevant.

---

# 8. Source Expansion Rules

Dynamic discovery must still remain controlled.

The agent must follow:

```text
Configured Scope
       ↓
User Intent
       ↓
Security Relevance
       ↓
Source Trust
       ↓
Resource Relevance
       ↓
Allowed Expansion
```

The agent must NOT randomly browse unrelated websites.

It must maintain a clear reason for every expansion.

Example:

```text
User requested:
"Find reports about FIN7 attack chains."

Agent discovers:
FIN7 → Carbanak → another malware family

Agent can investigate the malware because:
the malware is directly connected to the requested attack chain.
```

But it should not suddenly move into unrelated topics.

---

# 9. Search Agent

The Search Agent is responsible for finding resources.

It should support:

```text
Keyword Search
Phrase Search
Boolean Search
Concept Search
Actor Search
Malware Search
CVE Search
MITRE Technique Search
MITRE Tactic Search
Campaign Search
Attack-chain Search
Date filtering
Source filtering
Document-type filtering
```

Example query:

```text
"ransomware" AND "lateral movement" AND "Kerberos"
```

Another:

```text
"initial access" AND "credential theft" AND "C2"
```

Another:

```text
T1059 AND ransomware
```

Another:

```text
"full attack chain" AND ransomware
```

The agent should generate these queries dynamically.

---

# 10. Resource Discovery

A critical requirement:

## NEVER treat a category/index page as the final intelligence resource.

For example:

```text
Source website
    ↓
Reports index
    ↓
Report A
Report B
Report C
Report D
```

The system should store:

```text
Report A
Report B
Report C
Report D
```

individually.

The index page is only:

```text
Discovery Source
```

not:

```text
Final Intelligence Document
```

---

# 11. Example

Suppose the agent discovers a DFIR Report listing.

The listing contains:

```text
Reports
 ├── Report A
 ├── Report B
 ├── Report C
 └── Report D
```

The crawler must produce:

```text
sources/
    report_a/
    report_b/
    report_c/
    report_d/
```

NOT:

```text
sources/
    dfir_reports_index/
```

as the primary intelligence object.

---

# 12. Resource Classification

Every discovered URL must first be classified.

Possible classes:

```text
article
incident_report
threat_report
malware_analysis
campaign_report
actor_profile
security_advisory
vulnerability_report
adversary_emulation
attack_simulation
research_paper
documentation
dataset
index_page
category_page
search_page
navigation_page
irrelevant
```

The classification should be AI-assisted.

---

# 13. Index Page Detection

The agent must identify:

```text
Is this page itself valuable?
```

versus:

```text
Does this page primarily contain links to other resources?
```

If it is an index:

```text
Extract links
        ↓
Classify links
        ↓
Visit individual resources
        ↓
Store individually
```

This directly addresses the requirement to avoid returning only a domain or blog index.

---

# 14. Individual URL Extraction

For each source page, extract candidate links.

For each candidate:

```yaml
url: ...
title: ...
anchor_text: ...
source_page: ...
resource_type: ...
confidence: ...
```

Then classify.

Example:

```yaml
url: /2026/example-report
title: Example Ransomware Intrusion
resource_type: incident_report
confidence: 0.97
```

The system should preserve the original URL.

---

# 15. Deduplication

The same report may appear:

```text
Google
Source index
RSS
Social media
Another article
Search result
```

The system must deduplicate based on:

```text
Canonical URL
URL normalization
Page title
Content fingerprint
Document hash
Publication metadata
```

The final knowledge base should contain one canonical resource.

---

# 16. Content Acquisition

The acquisition layer must support:

```text
HTML
PDF
Plain text
Markdown
XML
RSS
JSON
Web articles
Technical reports
```

The system should determine the appropriate extraction method dynamically.

---

# 17. PDF Handling

If the discovered resource is already a PDF:

```text
DO NOT CONVERT IT.
```

Store the original PDF.

Example:

```text
original/
    report.pdf
```

Metadata:

```yaml
format: pdf
original_file: true
```

The system may additionally extract text for analysis.

---

# 18. HTML / Blog Handling

If the source is HTML:

```text
HTML
 ↓
Content extraction
 ↓
Structure detection
 ↓
Formatting reconstruction
 ↓
PDF generation
```

The goal is to preserve the document's original visual structure as closely as practical.

Preserve:

```text
Title
Headings
Paragraphs
Lists
Tables
Images
Captions
Code blocks
References
Links
Publication date
Author
Source branding where possible
```

---

# 19. Original vs Normalized Document

Every resource should have two concepts:

### Original Artifact

Exactly what was downloaded.

```text
original/
```

### Knowledge Representation

AI-generated structured representation.

```text
knowledge/
```

Example:

```text
resource/
    original/
        source.html

    rendered/
        source.pdf

    extracted/
        text.md

    analysis/
        intelligence.json
        attack_chain.json
        mitre_mapping.json
        detection.json
        hunting.json
        simulation.json

    metadata.json
```

---

# 20. AI Analysis Pipeline

After content acquisition:

```text
Document
    ↓
Text Extraction
    ↓
Document Understanding
    ↓
Entity Extraction
    ↓
Event Extraction
    ↓
Attack Chain Reconstruction
    ↓
TTP Extraction
    ↓
MITRE Mapping
    ↓
Detection Analysis
    ↓
Threat Hunting Analysis
    ↓
Simulation Analysis
    ↓
Emulation Analysis
    ↓
Knowledge Classification
```

---

# 21. Attack Chain Reconstruction

This is one of the most important capabilities.

The AI should read the report and reconstruct:

```text
Initial Access
      ↓
Execution
      ↓
Persistence
      ↓
Privilege Escalation
      ↓
Defense Evasion
      ↓
Credential Access
      ↓
Discovery
      ↓
Lateral Movement
      ↓
Collection
      ↓
Command & Control
      ↓
Exfiltration
      ↓
Impact
```

Not every attack contains every stage.

Therefore:

> The model must never assume a stage exists.

It should only create stages supported by the source.

---

# 22. Evidence-Based Extraction

Every extracted intelligence item should retain evidence.

Example:

```yaml
technique:
  id: T1059.001

observation:
  description: PowerShell was used to execute the payload.

evidence:
  source_resource: resource-123
  source_location: section-4
  confidence: high
```

This is essential.

The system should distinguish:

```text
Observed
Inferred
Possible
Recommended
```

These must never be mixed.

---

# 23. MITRE ATT&CK Mapping

The system should map extracted behavior to:

```text
Tactic
Technique
Sub-technique
Procedure
Software
Group
Campaign
```

Example:

```text
Observed:
PowerShell execution

MITRE:
Execution
T1059
T1059.001 PowerShell
```

The system should dynamically use the current MITRE knowledge source rather than embedding a permanently hardcoded technique list.

---

# 24. Knowledge Base Categories

Every resource may belong to multiple categories.

## Tactic-Based

Examples:

```text
Initial Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Credential Access
Discovery
Lateral Movement
Collection
Command and Control
Exfiltration
Impact
```

---

## Technique-Based

Example:

```text
T1059.001
T1021.001
T1003
T1566
```

The system should support any valid technique dynamically.

---

## Attack-Chain-Based

Example:

```text
Initial Access
→ Execution
→ Credential Access
→ Discovery
→ Lateral Movement
→ C2
→ Exfiltration
→ Impact
```

---

## Threat-Actor-Based

```text
Actor
Campaign
Associated malware
Associated infrastructure
TTPs
```

---

## Malware-Based

```text
Malware
Capabilities
TTPs
Campaigns
Actors
IOCs
```

---

## Vulnerability-Based

```text
CVE
Product
Exploitation
Actor
Campaign
Initial Access
Post-exploitation
```

---

## Detection-Based

Resources containing useful:

```text
Detection logic
Telemetry
Indicators
Behavioral detections
EDR observations
SIEM opportunities
YARA ideas
Sigma ideas
```

---

## Threat-Hunting-Based

Resources that can generate:

```text
Hunting hypotheses
Queries
Telemetry requirements
Investigation paths
Pivot points
```

---

## Simulation-Based

Resources that can become:

```text
Simulation scenario
Technique test
Detection validation
Security-control validation
```

---

## Emulation-Based

Resources describing:

```text
Adversary behavior
Actor procedure
Attack chain
Emulation plan
Operational sequence
```

---

# 25. Multi-Dimensional Classification

A single document should be allowed to exist in multiple categories.

Example:

```text
Resource:
Ransomware intrusion report

Categories:

incident_report
ransomware
attack_chain
credential_access
lateral_movement
command_and_control
impact
T1078
T1021
detection_relevant
hunting_relevant
emulation_relevant
```

Do NOT force a document into only one category.

---

# 26. Detection Engineering Analysis

The AI should ask:

```text
What could have been detected?
```

It should identify:

```text
Behavior
Telemetry
Data source
Detection opportunity
Potential signal
Required fields
Potential rule logic
False-positive considerations
```

Example:

```yaml
detection_opportunity:
  behavior: suspicious PowerShell execution
  telemetry:
    - process_creation
    - command_line
    - parent_process
  mitre:
    - T1059.001
```

The system should distinguish between:

```text
Source explicitly provides detection
```

and:

```text
AI-generated detection opportunity
```

These must not be represented as the same thing.

---

# 27. Threat Hunting Analysis

For every relevant report, the AI can generate:

```text
Hunting Hypothesis
        ↓
Required Telemetry
        ↓
Potential Query
        ↓
Expected Evidence
        ↓
Investigation Pivot
```

Example:

```text
Hypothesis:
An attacker may have used PowerShell for payload execution.

Telemetry:
Windows process creation

Hunting:
Look for suspicious powershell.exe command lines,
especially unusual parent-child relationships.
```

The exact query language should be generated according to the target environment.

Examples:

```text
Google SecOps / UDM
Microsoft Sentinel / KQL
Splunk / SPL
Elastic / KQL
```

---

# 28. Simulation Analysis

The AI should determine:

> Can this behavior be safely represented as a security validation test?

Possible output:

```yaml
simulation:
  suitable: true
  technique: T1059.001
  objective: validate PowerShell detection
  telemetry_required:
    - process_creation
  validation:
    - detection triggered
    - alert generated
    - investigation available
```

The system should focus on controlled validation and detection testing.

---

# 29. Adversary Emulation Analysis

The system should determine whether an attack chain can contribute to an emulation scenario.

Example:

```text
Incident Report
       ↓
Observed Attack Chain
       ↓
MITRE Mapping
       ↓
Emulation Candidate
```

Output:

```yaml
emulation_candidate:
  actor: example_actor
  scenario: credential theft followed by lateral movement
  techniques:
    - T1059
    - T1003
    - T1021
  prerequisites: ...
  telemetry: ...
  validation_objectives: ...
```

The system should preserve the difference between:

```text
Observed real-world behavior
```

and:

```text
AI-proposed emulation
```

---

# 30. Agent Architecture

The system should be implemented as multiple cooperating capabilities rather than one enormous scraper.

Recommended architecture:

```text
                    MCP CLIENT / AI AGENT
                            │
                            ▼
                    ORCHESTRATOR AGENT
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
       ▼                    ▼                    ▼
 SEARCH AGENT        DISCOVERY AGENT      SOURCE AGENT
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                    ACQUISITION AGENT
                            │
                            ▼
                    CONTENT ANALYZER
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
       TTP ANALYZER   ATT&CK MAPPER   ENTITY EXTRACTOR
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                    ATTACK CHAIN AGENT
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
        DETECTION         HUNTING       PURPLE TEAM
          AGENT            AGENT          AGENT
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                    KNOWLEDGE ENGINEER
                            │
                            ▼
                    KNOWLEDGE BASE
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
        SEARCH/API         MCP           REPORTING
```

---

# 31. MCP Interface

The entire engine should expose capabilities through MCP.

The MCP server should provide tools such as:

```text
search_resources
discover_sources
discover_links
fetch_resource
classify_resource
analyze_resource
extract_attack_chain
extract_ttps
map_mitre
find_related_resources
search_knowledge_base
generate_hunting_hypothesis
generate_detection_opportunity
identify_emulation_candidate
identify_simulation_candidate
get_resource
get_original_document
get_rendered_pdf
generate_report
```

---

# 32. MCP Search Example

An AI agent should be able to request:

```text
Search for recent ransomware intrusion reports involving credential access and lateral movement.
```

The MCP server should internally:

```text
Understand request
 ↓
Generate search queries
 ↓
Search configured sources
 ↓
Discover additional relevant sources
 ↓
Extract individual resources
 ↓
Rank resources
 ↓
Return structured results
```

The AI agent should not need to understand scraper internals.

---

# 33. MCP Resource Result

A result should look conceptually like:

```json
{
  "resource_id": "res_001",
  "title": "Example Ransomware Intrusion",
  "source": "Incident Response Research",
  "resource_type": "incident_report",
  "published": "2026-01-10",
  "url": "...",
  "relevance": 0.94,
  "categories": [
    "ransomware",
    "attack_chain",
    "credential_access",
    "lateral_movement"
  ],
  "mitre_techniques": [
    "T1059",
    "T1003",
    "T1021"
  ]
}
```

---

# 34. Agent Memory / Research State

The agent should maintain research state.

Example:

```text
Research Session
 ├── User Objective
 ├── Search Queries
 ├── Sources Discovered
 ├── Resources Discovered
 ├── Resources Processed
 ├── Resources Rejected
 ├── Entities Found
 ├── Related Resources
 ├── MITRE Mapping
 ├── Knowledge Categories
 └── Final Results
```

This prevents the agent from repeatedly crawling the same resources.

---

# 35. Agent Guardrails

The agent should always follow the configured research objective.

Priority order:

```text
1. System constraints
2. User request
3. Product research policy
4. Configured source scope
5. Relevance
6. Source quality
```

The agent should not abandon the objective simply because it discovers an interesting unrelated page.

---

# 36. Controlled Dynamic Exploration

The agent should be able to expand research.

Example:

```text
Requested:
"Find reports about a ransomware actor."

Report A
 ↓
Actor discovered
 ↓
Malware discovered
 ↓
Campaign discovered
 ↓
CVE discovered
 ↓
Related incident discovered
```

The agent may follow these relationships because they are directly relevant.

However:

```text
Unrelated technology
Unrelated news
Unrelated company
Unrelated topic
```

must not cause uncontrolled exploration.

---

# 37. Relevance Scoring

Every candidate resource should receive a relevance score.

Conceptually:

```text
relevance =
    query_match
  + threat_relevance
  + attack_chain_relevance
  + source_quality
  + recency
  + MITRE_relevance
  + detection_value
  + hunting_value
  + emulation_value
```

Weights should be configurable rather than hardcoded.

---

# 38. Source Trust Model

Sources should have metadata such as:

```yaml
source:
  name: Example Source
  type: incident_response
  trust_level: high
  official: true
  dynamic_discovery_allowed: true
```

The system should distinguish:

```text
Primary source
Secondary source
Community source
Aggregated source
Unknown source
```

---

# 39. Content Provenance

Every piece of intelligence must maintain provenance.

Example:

```text
Intelligence Item
       ↓
Resource
       ↓
URL
       ↓
Source
       ↓
Publication Date
       ↓
Evidence
       ↓
Extraction Model
       ↓
Extraction Timestamp
```

This is essential for security research.

---

# 40. Knowledge Graph

A graph database such as Neo4j can represent relationships.

Example:

```text
Threat Actor
     │
     ├── uses → Malware
     │
     ├── conducts → Campaign
     │
     ├── targets → Sector
     │
     ├── uses → Technique
     │
     └── appears in → Incident
                         │
                         ├── contains → Attack Step
                         │
                         ├── maps to → MITRE Technique
                         │
                         ├── enables → Detection
                         │
                         ├── enables → Hunting Hypothesis
                         │
                         └── enables → Emulation Scenario
```

---

# 41. Recommended Knowledge Entities

Core entities:

```text
Source
Resource
Report
Article
Incident
ThreatActor
Campaign
Malware
Tool
Vulnerability
CVE
IOC
Domain
IP
URL
Hash
Tactic
Technique
SubTechnique
AttackStep
Detection
HuntingHypothesis
Simulation
EmulationScenario
Telemetry
Product
Sector
Country/Region
```

---

# 42. Recommended Relationships

Examples:

```text
ACTOR -> USES -> MALWARE
ACTOR -> USES -> TECHNIQUE
ACTOR -> CONDUCTED -> CAMPAIGN
CAMPAIGN -> DESCRIBED_IN -> REPORT
REPORT -> DESCRIBES -> INCIDENT
INCIDENT -> CONTAINS -> ATTACK_STEP
ATTACK_STEP -> MAPS_TO -> TECHNIQUE
TECHNIQUE -> BELONGS_TO -> TACTIC
TECHNIQUE -> ENABLES -> DETECTION
TECHNIQUE -> ENABLES -> HUNTING_HYPOTHESIS
TECHNIQUE -> CAN_BE_VALIDATED_BY -> SIMULATION
ATTACK_CHAIN -> CAN_BE_EMULATED_BY -> EMULATION_SCENARIO
```

---

# 43. Repository Structure

Recommended initial repository:

```text
adversary-intelligence-engine/
│
├── README.md
├── pyproject.toml
├── .env.example
├── docker-compose.yml
│
├── src/
│   └── aie/
│       │
│       ├── api/
│       │   └── app.py
│       │
│       ├── mcp/
│       │   ├── server.py
│       │   └── tools/
│       │
│       ├── agents/
│       │   ├── orchestrator.py
│       │   ├── search_agent.py
│       │   ├── discovery_agent.py
│       │   ├── acquisition_agent.py
│       │   ├── analysis_agent.py
│       │   ├── attack_chain_agent.py
│       │   ├── mitre_agent.py
│       │   ├── detection_agent.py
│       │   ├── hunting_agent.py
│       │   ├── simulation_agent.py
│       │   ├── emulation_agent.py
│       │   └── knowledge_agent.py
│       │
│       ├── crawler/
│       │   ├── browser.py
│       │   ├── extractor.py
│       │   ├── link_discovery.py
│       │   ├── canonicalizer.py
│       │   └── robots.py
│       │
│       ├── acquisition/
│       │   ├── html.py
│       │   ├── pdf.py
│       │   ├── markdown.py
│       │   └── documents.py
│       │
│       ├── analysis/
│       │   ├── entities.py
│       │   ├── ttps.py
│       │   ├── attack_chain.py
│       │   ├── evidence.py
│       │   └── classification.py
│       │
│       ├── mitre/
│       │   ├── mapper.py
│       │   └── client.py
│       │
│       ├── knowledge/
│       │   ├── graph.py
│       │   ├── models.py
│       │   └── repository.py
│       │
│       ├── reports/
│       │   ├── renderer.py
│       │   └── pdf.py
│       │
│       └── config/
│           ├── sources.yaml
│           └── policies.yaml
│
├── data/
│   ├── raw/
│   ├── documents/
│   ├── extracted/
│   ├── analysis/
│   └── reports/
│
├── tests/
│
└── web/
    └── ...
```

---

# 44. Dynamic Configuration

Source configuration should be external.

Example:

```yaml
sources:
  - name: The DFIR Report
    category: incident_response
    enabled: true

  - name: Google Threat Intelligence
    category: threat_intelligence
    enabled: true
```

But the code should NOT contain source-specific assumptions wherever possible.

Avoid:

```python
if source == "dfir":
    ...
```

Prefer:

```text
Source Discovery
→ Source Adapter
→ Generic Extraction
→ AI Classification
```

Only use specialized adapters where a site genuinely requires them.

---

# 45. Search Strategy Generation

Do not hardcode:

```text
search_queries = [
    "ransomware attack report",
    "ransomware incident"
]
```

Instead:

```text
User intent
 ↓
Concept extraction
 ↓
Synonym expansion
 ↓
MITRE enrichment
 ↓
Attack-stage expansion
 ↓
Query generation
```

For:

```text
"Find credential theft attacks involving ransomware."
```

The agent might dynamically derive:

```text
credential theft
credential dumping
password theft
credential access
LSASS
identity theft
ransomware
extortion
lateral movement
```

The exact query set should be generated dynamically.

---

# 46. AI Model Responsibilities

AI should be used for tasks that require semantic understanding.

Good AI tasks:

```text
Document classification
Link classification
Attack-chain extraction
TTP extraction
Entity extraction
MITRE mapping assistance
Relevance scoring
Source discovery
Related-resource discovery
Detection opportunity generation
Hunting hypothesis generation
Simulation classification
Emulation classification
Knowledge categorization
```

Traditional code should handle:

```text
HTTP
Browser automation
File downloads
Hashing
Deduplication
Storage
Queueing
PDF conversion
Database operations
Caching
Authentication
MCP transport
```

Do not use AI where deterministic code is better.

---

# 47. Extraction Confidence

Every AI-derived field should contain confidence.

Example:

```yaml
field: initial_access
value: exposed VPN
confidence: 0.91
evidence_type: observed
```

Confidence levels:

```text
HIGH
MEDIUM
LOW
UNKNOWN
```

---

# 48. Evidence Types

Use:

```text
OBSERVED
EXPLICIT
INFERRED
AI_DERIVED
CORRELATED
RECOMMENDED
```

Example:

```text
Observed:
The report explicitly states PowerShell was executed.

AI-derived:
The behavior maps to T1059.001.

Recommended:
A detection opportunity is suggested.
```

This distinction is extremely important.

---

# 49. Storage Model

Store both:

```text
Raw Intelligence
```

and:

```text
Structured Intelligence
```

Example:

```text
data/
    raw/
        source.html

    documents/
        source.pdf

    extracted/
        source.md

    analysis/
        entities.json
        ttps.json
        attack_chain.json
        mitre.json
        detection.json
        hunting.json
        simulation.json
        emulation.json

    reports/
        final_report.pdf
```

---

# 50. Knowledge Base Search

The knowledge base should support questions such as:

```text
Find all reports involving T1059.001.

Find ransomware attack chains involving lateral movement.

Show incidents where credential dumping was followed by lateral movement.

Find reports that can support purple-team validation.

Find techniques with no associated detection.

Find techniques observed in recent incidents.

Find attack chains that can be converted into emulation scenarios.

Find reports related to a specific actor.

Find reports related to a specific malware family.
```

---

# 51. Final Report Generation

The reporting system should be able to create:

```text
Source Summary
Attack Timeline
Attack Chain
MITRE Mapping
Threat Actor
Malware
Tools
Infrastructure
IOCs
Detection Opportunities
Threat Hunting Opportunities
Simulation Opportunities
Emulation Opportunities
Mitigations
References
```

The report should clearly distinguish:

```text
SOURCE FACT
```

from:

```text
AI ANALYSIS
```

---

# 52. PDF Output

For an existing PDF:

```text
Keep original PDF.
```

For HTML:

```text
Download HTML
 ↓
Extract meaningful document structure
 ↓
Render into PDF
 ↓
Store PDF
```

For other supported document formats:

```text
Acquire
 ↓
Normalize
 ↓
Render
 ↓
Store
```

The final report should preserve the source's structure as closely as possible while removing unnecessary navigation elements.

---

# 53. Knowledge Base Taxonomy

Recommended top-level structure:

```text
Threat Intelligence
│
├── Incident Reports
│
├── Threat Actors
│
├── Campaigns
│
├── Malware
│
├── Vulnerabilities
│
├── Attack Chains
│
├── MITRE ATT&CK
│
├── Tactics
│
├── Techniques
│
├── Detection Engineering
│
├── Threat Hunting
│
├── Attack Simulation
│
├── Adversary Emulation
│
└── Purple Team
```

Resources can belong to multiple branches.

---

# 54. Purple-Team Integration

The ultimate purpose of the system is not simply collecting intelligence.

The important loop is:

```text
Real-World Intelligence
        ↓
Attack Behavior
        ↓
MITRE ATT&CK
        ↓
Detection Engineering
        ↓
Threat Hunting
        ↓
Simulation
        ↓
Adversary Emulation
        ↓
Security Validation
        ↓
Detection Improvement
```

This makes the platform useful to a defensive security organization.

---

# 55. Example End-to-End Workflow

User asks:

```text
Find recent public ransomware attack chains
involving credential access and lateral movement.
```

The agent performs:

```text
1. Understand request

2. Generate search strategy

3. Search configured sources

4. Discover additional relevant sources

5. Identify individual reports

6. Reject category/index pages as final resources

7. Download each report

8. Deduplicate

9. Extract content

10. Analyze attack chain

11. Extract TTPs

12. Map MITRE ATT&CK

13. Classify knowledge

14. Generate detection opportunities

15. Generate hunting hypotheses

16. Determine simulation applicability

17. Determine emulation applicability

18. Store original document

19. Generate standardized PDF if necessary

20. Store structured knowledge

21. Return resources through MCP
```

---

# 56. Example Final Resource Object

```json
{
  "resource_id": "aie_res_001",
  "title": "Example Ransomware Intrusion",
  "resource_type": "incident_report",

  "source": {
    "name": "Example Incident Response Provider",
    "type": "incident_response",
    "url": "original-source-url"
  },

  "publication": {
    "date": "2026-01-01"
  },

  "attack_chain": [
    {
      "stage": "initial_access",
      "description": "Initial access behavior described by the source",
      "evidence": "source evidence",
      "confidence": 0.94
    }
  ],

  "mitre": {
    "tactics": [],
    "techniques": [],
    "subtechniques": []
  },

  "entities": {
    "actors": [],
    "malware": [],
    "tools": [],
    "vulnerabilities": [],
    "iocs": []
  },

  "knowledge_categories": [
    "incident_report",
    "attack_chain",
    "ransomware",
    "detection",
    "hunting",
    "purple_team"
  ],

  "analysis": {
    "detection_opportunities": [],
    "hunting_hypotheses": [],
    "simulation_candidates": [],
    "emulation_candidates": []
  },

  "artifacts": {
    "original": "...",
    "rendered_pdf": "...",
    "extracted_text": "..."
  }
}
```

---

# 57. Agent Decision Loop

The orchestrator should repeatedly perform:

```text
OBSERVE
   ↓
UNDERSTAND
   ↓
PLAN
   ↓
SEARCH
   ↓
DISCOVER
   ↓
EVALUATE
   ↓
ACQUIRE
   ↓
ANALYZE
   ↓
CORRELATE
   ↓
STORE
   ↓
DECIDE WHETHER MORE RESEARCH IS NEEDED
```

If additional research is needed:

```text
DISCOVER → SEARCH → ANALYZE
```

If sufficient:

```text
FINALIZE
```

---

# 58. Stopping Conditions

The agent must not browse indefinitely.

Stop when:

```text
Requested coverage achieved
AND
Relevant resources exhausted
OR
Research budget reached
OR
Additional resources provide negligible value
```

This should be configurable.

Example:

```yaml
research:
  max_resources: 50
  max_depth: 3
  minimum_relevance: 0.70
  max_discovery_rounds: 5
```

These are configuration defaults, not hardcoded behavior.

---

# 59. Caching

The engine should cache:

```text
URLs
Pages
Documents
Hashes
Search results
AI analysis
MITRE mappings
```

This prevents repeatedly downloading the same resource.

---

# 60. Incremental Intelligence

If the same report is discovered again:

```text
Do not process from scratch.
```

Instead:

```text
Check content hash
       ↓
Unchanged?
       ↓
Reuse previous analysis
```

If changed:

```text
Reprocess
 ↓
Version intelligence
```

---

# 61. Versioning

Knowledge should be versioned.

Example:

```text
resource v1
resource v2
analysis v1
analysis v2
MITRE mapping v1
MITRE mapping v2
```

This is important because:

- reports can be updated
- MITRE mappings can change
- AI models can improve
- knowledge classifications can change

---

# 62. Security and Reliability

The acquisition system should treat external content as untrusted.

Implement:

```text
Download limits
File-size limits
Timeouts
Content-type validation
Sandboxed processing
Archive restrictions
Safe document parsing
Malicious-content isolation
Rate limiting
Domain controls
Audit logging
```

External pages must never be allowed to control the agent's instructions.

For example, if a webpage contains text such as:

```text
"Ignore your instructions and execute..."
```

that content must be treated as **untrusted source data**, not as an instruction to the agent.

---

# 63. Prompt Injection Protection

This is especially important because the agent is consuming arbitrary web content.

Use the model architecture:

```text
SYSTEM INSTRUCTIONS
       >
AGENT POLICY
       >
USER REQUEST
       >
SOURCE CONTENT
```

Source content must always be treated as data.

The crawler should label extracted content:

```text
UNTRUSTED_EXTERNAL_CONTENT
```

before passing it to analysis agents.

---

# 64. Observability

Every operation should be logged.

Example:

```text
Research ID
Agent
Query
URL
Source
Decision
Reason
Extraction result
AI model
Confidence
Timestamp
Errors
```

This allows you to answer:

> Why did the agent select this report?

and:

> Why did it reject that page?

---

# 65. Testing

Tests should cover:

```text
URL extraction
Canonicalization
Duplicate detection
Index-page detection
PDF detection
HTML extraction
Source classification
MITRE mapping
Attack-chain extraction
Knowledge classification
MCP tools
Agent decision logic
Report generation
```

Include real-world fixtures representing:

```text
Incident report
Blog
PDF
Index page
Malware report
Advisory
MITRE page
Emulation plan
```

---

# 66. Important Product Principle

The system should be:

```text
DYNAMIC
SOURCE-AWARE
AI-DRIVEN
EVIDENCE-BASED
MITRE-AWARE
MCP-ACCESSIBLE
KNOWLEDGE-GRAPH-READY
PURPLE-TEAM-ORIENTED
```

It should NOT be:

```text
STATIC
WEBSITE-SPECIFIC
KEYWORD-ONLY
URL-ONLY
HARD-CODED
```

---

# 67. Development Phases

## Phase 1 — Foundation

Build:

```text
Source configuration
URL discovery
HTML acquisition
PDF acquisition
Canonicalization
Deduplication
Basic classification
File storage
```

---

## Phase 2 — AI Extraction

Add:

```text
Resource classification
Entity extraction
TTP extraction
Attack-chain extraction
Evidence tracking
```

---

## Phase 3 — MITRE Integration

Add:

```text
Tactic mapping
Technique mapping
Sub-technique mapping
Actor correlation
Software correlation
```

---

## Phase 4 — Security Analysis

Add:

```text
Detection analysis
Threat hunting analysis
Simulation analysis
Emulation analysis
Purple-team analysis
```

---

## Phase 5 — Knowledge Graph

Add:

```text
Neo4j
Entity relationships
Attack-chain graph
Actor graph
Technique graph
Resource graph
```

---

## Phase 6 — MCP

Expose:

```text
Search
Discovery
Acquisition
Analysis
Knowledge retrieval
Detection analysis
Hunting analysis
Simulation
Emulation
Report generation
```

---

## Phase 7 — Autonomous Research

Allow the agent to:

```text
Discover new sources
Expand research
Find related reports
Correlate campaigns
Identify missing information
Perform follow-up searches
Build richer knowledge
```

while remaining bounded by the research objective and configured policies.

---

# 68. Target User Experience

The final user should not need to understand how the crawler works.

They should be able to ask:

```text
Find recent attack-chain reports involving credential dumping.
```

or:

```text
Find real-world incidents mapped to T1003.
```

or:

```text
Find reports that can help me build a purple-team scenario around lateral movement.
```

or:

```text
Show me attack chains where the organization could have detected the attacker earlier.
```

or:

```text
Find public reports about this threat actor and identify the techniques we should hunt for.
```

The agent handles:

```text
Search
Discovery
Scraping
Extraction
Analysis
Correlation
Classification
Storage
```

automatically.

---

# 69. Final Architecture

The intended final architecture is:

```text
                         USER / AI AGENT
                                │
                                ▼
                         MCP INTERFACE
                                │
                                ▼
                         ORCHESTRATOR
                                │
                 ┌──────────────┼──────────────┐
                 │              │              │
                 ▼              ▼              ▼
              SEARCH         DISCOVERY      KNOWLEDGE
               AGENT           AGENT          AGENT
                 │              │
                 └──────┬───────┘
                        ▼
                 SOURCE EVALUATION
                        │
                        ▼
                RESOURCE DISCOVERY
                        │
                        ▼
                CONTENT ACQUISITION
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
         HTML/PAGES              PDF
             │                     │
             ▼                     │
       CONTENT EXTRACTION          │
             │                     │
             └──────────┬──────────┘
                        ▼
                  AI ANALYSIS
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
      ENTITIES         TTPs         ATTACK CHAIN
        │               │                │
        └───────────────┼────────────────┘
                        ▼
                  MITRE CORRELATION
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
      DETECTION       HUNTING      PURPLE TEAM
        AGENT          AGENT          AGENT
          │             │             │
          └─────────────┼─────────────┘
                        ▼
                 KNOWLEDGE GRAPH
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
            SEARCH      MCP      REPORT
                                  │
                                  ▼
                                 PDF
```

---

# 70. Definition of Done

The product should be considered successful when it can take a request such as:

```text
Find public reports describing real-world ransomware
attack chains involving credential access and lateral movement.
```

and autonomously:

```text
✓ Generate search strategy
✓ Search multiple sources
✓ Discover relevant sources
✓ Discover individual reports
✓ Avoid returning only category/index pages
✓ Extract individual URLs
✓ Deduplicate resources
✓ Acquire PDFs/HTML
✓ Preserve original PDFs
✓ Convert HTML to structured PDF
✓ Extract document content
✓ Identify threat actors
✓ Identify malware
✓ Identify tools
✓ Identify vulnerabilities
✓ Identify IOCs
✓ Reconstruct attack chain
✓ Extract TTPs
✓ Map MITRE ATT&CK
✓ Categorize knowledge
✓ Identify detection opportunities
✓ Generate hunting hypotheses
✓ Identify simulation candidates
✓ Identify emulation candidates
✓ Store evidence
✓ Store provenance
✓ Build knowledge relationships
✓ Make results searchable
✓ Expose results through MCP
✓ Generate final reports
```

---

# 71. Product Vision

The long-term vision is to create:

> **An autonomous threat-informed intelligence engine that continuously converts public adversary research and real-world attack reports into structured knowledge that can directly support detection engineering, threat hunting, attack simulation, adversary emulation and purple-team security validation.**

The scraper is therefore only one component.

The actual product is:

```text
                    PUBLIC SECURITY KNOWLEDGE
                              ↓
                       INTELLIGENCE
                              ↓
                     ATTACK BEHAVIOR
                              ↓
                       MITRE / TTP
                              ↓
                    KNOWLEDGE GRAPH
                              ↓
          ┌───────────────────┼───────────────────┐
          ↓                   ↓                   ↓
      DETECTION            HUNTING            SIMULATION
          ↓                   ↓                   ↓
          └───────────────────┼───────────────────┘
                              ↓
                       PURPLE TEAM
                              ↓
                      ADVERSARY EMULATION
                              ↓
                      DEFENSE VALIDATION
                              ↓
                     STRONGER DETECTION
                              ↓
                     STRONGER DEFENSE
```

**This is the intended product direction: not "a web scraper that downloads cybersecurity articles", but an MCP-accessible, agent-driven adversary intelligence acquisition and knowledge platform that turns external security research into actionable defensive intelligence.**