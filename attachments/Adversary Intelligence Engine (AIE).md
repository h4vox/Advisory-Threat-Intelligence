# Adversary Intelligence Engine (AIE)
## Extended POC Technical & Product Specification
### Simulation Discovery, Scenario Composition & Emerging Adversary Intelligence

**Version:** 0.2  
**Status:** Extension of POC v0.1  
**Target Users:** Adversary Simulation Teams, Purple Teams, Red Teams, Detection Engineers, Threat Hunters, Security Validation Teams  
**Extends:** Existing AIE POC v0.1

---

# 1. Extension Objective

The existing AIE architecture transforms high-quality threat reports into structured, ATT&CK-mapped adversary knowledge and organization-aware simulation plans.

The extended architecture adds the missing operational layer:

> **Help an operator determine what to simulate, where to start, what techniques can be combined, why a sequence is valid, how to convert real-world behavior into a simulation, how to handle newly emerging behaviors before ATT&CK maps them, and how to measure the resulting defensive coverage.**

The extended platform therefore becomes:

```text
REAL-WORLD THREAT INTELLIGENCE
        ↓
REPORT INGESTION
        ↓
EVIDENCE EXTRACTION
        ↓
ATTACK RECONSTRUCTION
        ↓
BEHAVIOR KNOWLEDGE
        ↓
ATT&CK / KILL CHAIN / ATTACK FLOW / OTHER FRAMEWORKS
        ↓
ORGANIZATION CONTEXT
        ↓
SIMULATION DISCOVERY
        ↓
SCENARIO COMPOSITION
        ↓
PLAN GENERATION
        ↓
SIMULATION PROCEDURE RESOLUTION
        ↓
EXECUTION
        ↓
TELEMETRY
        ↓
DETECTION VALIDATION
        ↓
ASSESSMENT
        ↓
KNOWLEDGE + COVERAGE FEEDBACK
        ↓
NEW SIMULATION PRIORITIES
```

---

# 2. New Core Product Capabilities

The extension introduces the following major capabilities.

## 2.1 Simulation Discovery Engine

Automatically recommends:

- where to start
- which tactics are relevant
- which techniques should be prioritized
- which technique combinations are realistic
- which real-world campaigns are relevant
- which paths are feasible against the organization
- which simulations are already available
- which behaviors have no simulation coverage
- which behaviors have weak detection coverage

---

## 2.2 Scenario Composer

Allows users to build:

- single-technique tests
- tactic-level assessments
- contiguous multi-tactic scenarios
- arbitrary technique combinations
- real-world campaign reproductions
- threat-actor emulations
- objective-driven campaigns
- detection-validation scenarios
- custom operator-defined attack flows

---

## 2.3 Attack Flow Engine

Represents the actual adversary sequence as:

```text
Action
→ Condition
→ Action
→ Dependency
→ Action
→ Branch
→ Outcome
```

rather than representing an operation only as a list of ATT&CK IDs.

---

## 2.4 Emerging Behavior Engine

Detects adversary behaviors that:

- are not yet represented in ATT&CK
- represent new procedures for existing techniques
- represent novel combinations
- represent new attack-flow transitions
- appear repeatedly across multiple reports
- are increasing in frequency

These behaviors remain usable by the platform before official ATT&CK mapping exists.

---

## 2.5 ATT&CK Reconciliation Engine

Continuously synchronizes the local ATT&CK knowledge base and automatically compares new/updated ATT&CK content against previously discovered emerging behaviors.

Example:

```text
Emerging Behavior EB-00042
        ↓
Previously unmapped
        ↓
New ATT&CK technique released
        ↓
Candidate semantic match
        ↓
Analyst validation
        ↓
EB-00042 → Txxxx.xxx
```

---

## 2.6 Simulation Procedure Resolver

Converts:

```text
Real-world behavior
        ↓
ATT&CK technique
        ↓
Simulation requirement
```

into an available implementation:

```text
Atomic test
CALDERA ability
Custom simulator
Manual procedure
Cloud simulation
Identity simulation
```

The system must distinguish between:

```text
ObservedProcedure
EquivalentProcedure
SimulationProcedure
```

so that a simulation does not falsely claim to reproduce the original malware or exact actor procedure.

---

## 2.7 Execution & Validation Loop

Adds:

```text
Plan
 ↓
Approval
 ↓
Execution
 ↓
Telemetry
 ↓
Detection
 ↓
Alert
 ↓
Analyst response
 ↓
Coverage result
```

This turns AIE into an assessment platform rather than only a planning system.

---

# 3. Revised AIE Logical Architecture

The original architecture should be extended to:

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         SOURCE LAYER                                │
│ Seqrite | Unit42 | SentinelLABS | Proofpoint | Huntress |          │
│ Mandiant | Microsoft TI | ESET | Talos | Other approved sources    │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                   INGESTION + PROVENANCE                            │
│ Fetch | Parse | Deduplicate | Quality | Version | Evidence         │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                 REPORT UNDERSTANDING ENGINE                         │
│ Metadata | Timeline | Actors | Malware | Tools | Procedures | IOC   │
│ Infrastructure | Artifacts | Detection | Victimology                │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                 ATTACK RECONSTRUCTION ENGINE                        │
│ Actions | Conditions | Dependencies | Branches | Outcomes            │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
                   ┌───────────┴────────────┐
                   ↓                        ↓
┌──────────────────────────────┐  ┌──────────────────────────────────┐
│ BEHAVIOR KNOWLEDGE LAYER     │  │ EMERGING BEHAVIOR ENGINE          │
│ Known behavior/procedures     │  │ Novelty / clustering / discovery │
└──────────────┬───────────────┘  └───────────────┬──────────────────┘
               └───────────────────┬──────────────┘
                                   ↓
┌─────────────────────────────────────────────────────────────────────┐
│                FRAMEWORK NORMALIZATION LAYER                        │
│ ATT&CK | Attack Flow | Kill Chain | STIX | D3FEND | CAPEC | ATLAS   │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                       KNOWLEDGE GRAPH                               │
│ Campaigns | Actors | Actions | Techniques | Procedures | Tools       │
│ Evidence | Assets | Infrastructure | Detections | Simulations      │
└───────────────┬──────────────────────────────┬──────────────────────┘
                ↓                              ↓
┌──────────────────────────────┐   ┌─────────────────────────────────┐
│ ORGANIZATION CONTEXT         │   │ ATT&CK / KNOWLEDGE SYNC          │
│ Assets | Identity | Network  │   │ Versioning | Diff | Reconcile    │
│ Controls | Detection | Cloud │   │ Emerging → Official mapping      │
└──────────────┬───────────────┘   └───────────────┬─────────────────┘
               └───────────────────┬───────────────┘
                                   ↓
┌─────────────────────────────────────────────────────────────────────┐
│             SIMULATION DISCOVERY & RECOMMENDATION                  │
│ Goal | Asset | Actor | Technique | Use Case | Coverage | Threat     │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                    SCENARIO COMPOSER                                │
│ Technique blocks | Tactic ranges | Attack flows | Campaigns         │
│ Objectives | Variants | Constraints | Prerequisites                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                    PATH / CAMPAIGN ENGINE                           │
│ Graph search | Constraint solving | Ranking | Optimization            │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                  SIMULATION PROCEDURE RESOLVER                      │
│ Atomic | CALDERA | Custom | Manual | Cloud | Identity               │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                  EXECUTION ORCHESTRATOR                             │
│ Approval | Scheduling | Execution | Safety | Rollback               │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│              TELEMETRY / DETECTION / VALIDATION                    │
│ EDR | SIEM | NDR | Identity | Cloud | Application | Alerts          │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                    RESULTS & LEARNING                                │
│ Coverage | Detection | Gaps | MTTD | Response | Recommendations     │
└─────────────────────────────────────────────────────────────────────┘
```

---

# 4. Module 6.7 — Simulation Discovery & Recommendation Engine

## Purpose

Solve:

> "There are hundreds of ATT&CK techniques. What should I simulate first?"

The engine must recommend simulation opportunities based on:

- organizational relevance
- critical assets
- current threat landscape
- historical adversary usage
- environment feasibility
- detection gaps
- simulation availability
- threat recency
- technique confidence
- business objectives

---

## 4.1 Entry Modes

Users can start from any of:

```text
Threat Actor
Campaign
Report
Objective
Tactic
Technique
Asset
Business Use Case
Detection Gap
Threat Category
Framework
Emerging Behavior
```

Examples:

```text
"Show ransomware simulations"

"Test Initial Access"

"Test Credential Access → Lateral Movement"

"Show simulations relevant to Domain Controllers"

"Test techniques used by this actor"

"Find untested techniques against critical assets"

"Show emerging behaviors relevant to Windows"
```

---

## 4.2 Recommendation Categories

The system should produce:

### Recommended Starting Simulations

Highest-value simulations to begin with.

### Trending Threats

Recent/high-velocity adversary behaviors.

### Critical Asset Paths

Paths toward high-value assets.

### Detection Gaps

Behaviors that are feasible but poorly detected.

### Untested Techniques

Relevant techniques with no recent assessment.

### New Behaviors

Emerging behaviors not yet fully mapped.

### High-Confidence Real-World Chains

Chains directly supported by high-quality reports.

---

## 4.3 Recommendation Score

Candidate score:

```text
RecommendationScore =
    ThreatRelevance
  * EnvironmentApplicability
  * AssetCriticality
  * DetectionGap
  * HistoricalUsage
  * SimulationReadiness
  * EvidenceConfidence
  * Recency
  / Complexity
```

Each factor should be normalized to `0–1`.

---

## 4.4 Recommendation Explanation

Every recommendation must explain itself.

Example:

```text
Recommended Scenario #1

Initial Access → Execution

Score: 92/100

Why:
- Used in 18 high-quality reports
- Applicable to organization Windows environment
- Critical asset reachable after execution
- Detection coverage is incomplete
- 6 simulation procedures available
- Observed in recent campaigns

Sources:
- Report A
- Report B
- Report C
```

Never show only:

```text
AI recommends Txxxx
```

---

# 5. Module 6.8 — Tactic & Technique Explorer

The ATT&CK matrix becomes an interactive simulation planning interface.

Example:

```text
RECON
18 techniques
42 procedures
12 simulations
7 organization-relevant
3 untested

INITIAL ACCESS
15 techniques
37 procedures
14 simulations
9 organization-relevant
5 untested

EXECUTION
14 techniques
51 procedures
19 simulations
11 organization-relevant
4 untested
```

Every tactic displays:

```text
Technique Count
Procedure Count
Simulation Count
Real-World Report Count
Environment-Relevant Count
Untested Count
Detection Gap Count
Emerging Behavior Count
```

---

## 5.1 Technique Status

Each technique can have:

```text
SUPPORTED
PARTIALLY_SUPPORTED
SIMULATION_AVAILABLE
NO_SIMULATION
UNTESTED
DETECTED
UNDETECTED
EMERGING
NOT_APPLICABLE
```

---

# 6. Module 6.9 — Scenario Composer

## Purpose

Provide an operator with a visual way to construct simulations.

The composer supports three levels.

### Mode A — Guided

```text
Objective
 ↓
Recommendations
 ↓
Select recommended path
 ↓
Generate plan
```

### Mode B — Assisted

```text
Select tactics / techniques
 ↓
System validates sequence
 ↓
Suggests prerequisites / missing stages
 ↓
Generate valid paths
```

### Mode C — Expert

```text
Manual attack-flow creation
```

---

# 7. Scenario Composition Types

AIE must support all of the following independently.

## 7.1 Single Technique

```text
T1059.001
```

Purpose:

- technique validation
- detection test
- atomic validation

---

## 7.2 Single Tactic

```text
Credential Access
```

Automatically returns:

```text
All applicable techniques
Known procedures
Available simulations
Organization-relevant candidates
Detection status
```

---

## 7.3 Tactic Range

Examples:

```text
Recon → Initial Access

Initial Access → Execution

Credential Access → Lateral Movement

Persistence → Defense Evasion

Discovery → Lateral Movement
```

---

## 7.4 Arbitrary Technique Combination

Example:

```text
Recon
+
Initial Access
+
Execution
+
Persistence
```

The system validates:

- dependencies
- prerequisites
- sequencing
- realism
- environment compatibility

---

## 7.5 Real Campaign Recreation

```text
Source campaign
 ↓
Observed attack flow
 ↓
Adapt to organization
 ↓
Replace unsafe/unavailable procedures
 ↓
Simulation plan
```

---

## 7.6 Objective-Driven Scenario

Example:

```text
Objective:
Reach Domain Controller
```

AIE searches for multiple valid paths.

---

# 8. Module 6.10 — Attack Flow Engine

Attack Flow becomes the canonical representation of sequence.

## 8.1 Core Objects

```text
Action
Condition
Relationship
Outcome
Objective
```

---

## 8.2 Relationships

```text
requires
follows
enables
causes
produces
downloads
executes
communicates_with
depends_on
alternative_to
branches_to
leads_to
```

---

## 8.3 Example

```text
Initial Access
      ↓
User Execution
      ↓
Payload Execution
      ↓
Credential Access
      ↓
Condition:
Credential obtained
      ↓
Lateral Movement
      ↓
Discovery
```

Branches:

```text
                 Credential Access
                       │
              ┌────────┴────────┐
              ↓                 ↓
          Credential A      Credential B
              ↓                 ↓
          Path A             Path B
```

---

# 9. Flow Validation Engine

When an operator connects two techniques:

```text
T1555 → T1021
```

the system checks:

```text
Prerequisites?
Historical evidence?
Observed in reports?
Environment possible?
Simulation available?
```

Result:

```text
✓ Valid transition
Observed in 7 campaigns
Environment feasible
Simulation available
```

or:

```text
⚠ Weak transition
No strong historical evidence
Missing prerequisite
```

This prevents users from creating arbitrary, unrealistic ATT&CK chains.

---

# 10. Module 6.11 — Scenario Library

AIE stores reusable scenarios.

```text
Scenario
├── Metadata
├── Objective
├── Entry Condition
├── Exit Condition
├── Difficulty
├── Attack Flow
├── ATT&CK mappings
├── Sources
├── Procedures
├── Prerequisites
├── Organization constraints
├── Detection objectives
├── Safety constraints
└── Variants
```

Example:

```text
SC-0001
Initial Access → Execution

SC-0002
Initial Access → Execution → Persistence

SC-0003
Credential Access → Lateral Movement

SC-0004
Recon → Initial Access → Execution

SC-0005
Persistence → Defense Evasion

SC-0006
Ransomware-style enterprise intrusion
```

---

# 11. Module 6.12 — Simulation Block System

Introduce reusable blocks.

```text
Simulation Block
```

Examples:

```text
INITIAL ACCESS BLOCK
EXECUTION BLOCK
PERSISTENCE BLOCK
CREDENTIAL ACCESS BLOCK
DISCOVERY BLOCK
LATERAL MOVEMENT BLOCK
C2 BLOCK
EXFILTRATION BLOCK
IMPACT BLOCK
```

A block contains:

```text
Applicable techniques
Procedures
Prerequisites
Expected artifacts
Detection objectives
Simulation implementations
```

Operators can compose:

```text
[Initial Access]
        +
[Execution]
        +
[Credential Access]
        +
[Lateral Movement]
```

---

# 12. Module 6.13 — Use-Case Library

Users should not need ATT&CK knowledge to begin.

Provide:

```text
Initial Access Validation
Phishing Validation
Endpoint Execution
Credential Access
Privilege Escalation
Persistence
AD Compromise
Lateral Movement
Identity Compromise
Cloud Identity
Ransomware Readiness
C2 Validation
Exfiltration
EDR Validation
SIEM Validation
Detection Engineering Validation
Full Adversary Emulation
```

Selecting a use case automatically generates relevant candidates.

---

# 13. Module 6.14 — Coverage Objective Engine

Users can specify:

```text
Goal:
Validate Credential Access detection

Environment:
Windows + AD

Constraints:
No destructive actions
No production malware
```

AIE determines the smallest/most useful set of simulations required to provide meaningful coverage.

Output:

```text
Technique
Simulation
Telemetry
Detection
Coverage
```

---

# 14. Module 6.15 — Emerging Behavior & Technique Discovery Engine

## Purpose

Detect important adversary behaviors that aren't adequately represented in existing ATT&CK content.

Pipeline:

```text
New Report
 ↓
Extract Procedures
 ↓
Existing Behavior Comparison
 ↓
ATT&CK Comparison
 ↓
Novelty Detection
 ↓
Behavior Clustering
 ↓
Cross-Source Validation
 ↓
Emerging Behavior
```

---

# 15. Emerging Behavior Classification

Every newly discovered behavior should be classified into one of:

```text
NEW_TECHNIQUE
NEW_PROCEDURE
NEW_IMPLEMENTATION
NEW_SEQUENCE
NEW_COMBINATION
NEW_INFRASTRUCTURE_PATTERN
NEW_CROSS_DOMAIN_BEHAVIOR
```

Example:

```text
Known technique:
PowerShell

New procedure:
Novel PowerShell execution pattern

Classification:
NEW_PROCEDURE
```

versus:

```text
Behavior:
No meaningful ATT&CK equivalent

Classification:
NEW_TECHNIQUE_CANDIDATE
```

---

# 16. Emerging Behavior Object

```yaml
EmergingBehavior:
  id: EB-2026-0001

  name:
  description:

  first_observed:
  last_observed:

  sources:
    - report_id

  actors:
    - actor_id

  campaigns:
    - campaign_id

  affected_platforms:
    - Windows

  behavior_type:
    - NEW_PROCEDURE

  attack_flow:
    - action_id

  current_mapping:
    attck_status: unmapped
    candidate_techniques: []

  evidence:
    - evidence_id

  novelty:
    behavior: 0.91
    implementation: 0.87
    sequence: 0.79

  frequency:
    report_count:
    actor_count:
    campaign_count:

  simulation:
    available: false
    procedures: []

  detection:
    known_telemetry:
    existing_analytics:

  lifecycle:
    status: emerging
```

---

# 17. Emerging Behavior Scoring

Create:

```text
EmergenceScore
```

based on:

```text
Novelty
Cross-source confirmation
Actor diversity
Campaign diversity
Frequency growth
Technical distinctiveness
Impact
Environment relevance
Detection relevance
```

Example:

```text
Emergence Score: 93/100
```

---

# 18. Emerging Behavior Radar

Dedicated interface:

```text
EMERGING BEHAVIOR RADAR

CRITICAL
EB-00041  Novel identity abuse       94
EB-00037  New persistence pattern    91

HIGH
EB-00033  Cloud execution pattern    86
EB-00029  New loader behavior        81

WATCH
EB-00018  Browser data technique     63
```

Selecting a behavior opens:

```text
Reports
 ↓
Evidence
 ↓
Actors
 ↓
Campaigns
 ↓
Attack Flow
 ↓
ATT&CK candidates
 ↓
Organization relevance
 ↓
Detection coverage
 ↓
Simulation readiness
```

---

# 19. Module 6.16 — ATT&CK Synchronization & Reconciliation

AIE maintains a versioned local ATT&CK data set.

The sync service must detect:

```text
New tactic
New technique
New sub-technique
New procedure
Modified technique
Renamed technique
Deprecated technique
Revoked technique
Relationship changes
Detection changes
Mitigation changes
```

---

## 19.1 Reconciliation Workflow

```text
ATT&CK Update
      ↓
Diff Engine
      ↓
New / Changed Objects
      ↓
Compare to Emerging Behaviors
      ↓
Semantic Candidate Mapping
      ↓
Confidence
      ↓
Analyst Approval
      ↓
Knowledge Graph Update
```

---

# 20. Technique Lifecycle

```text
DISCOVERED
    ↓
EXTRACTED
    ↓
CORROBORATED
    ↓
EMERGING
    ↓
CANDIDATE MAPPING
    ↓
ATT&CK MAPPED
    ↓
SIMULATION AVAILABLE
    ↓
SIMULATED
    ↓
DETECTED
    ↓
VALIDATED
    ↓
RETIRED / SUPERSEDED
```

---

# 21. Emerging Behavior → Simulation

A newly discovered behavior should immediately enter simulation assessment.

```text
Emerging Behavior
       ↓
Simulation Feasibility
       ↓
Equivalent behavior available?
       ├── YES
       └── NO
             ↓
      Custom simulation needed
```

The platform should display:

```text
Simulation Readiness

Equivalent safe procedure: YES
Atomic test: NO
CALDERA ability: NO
Custom procedure: YES
Manual procedure: YES
```

This ensures AIE can support behaviors before official ATT&CK adoption.

---

# 22. Module 6.17 — Cross-Framework Mapping

One behavior/action becomes the canonical object.

Example:

```text
ACTION-0421
```

Mappings:

```text
MITRE ATT&CK
Txxxx.xxx

Attack Flow
Action Node 12

Cyber Kill Chain
Execution

D3FEND
Related defensive technique

CAPEC
Related pattern

STIX
Relationship / observable

Detection
Sigma / YARA-L / KQL / vendor analytic

Simulation
Atomic / CALDERA / custom
```

Never make the framework itself the source of truth.

The source of truth is:

```text
Observed behavior
+
Evidence
+
Relationships
+
Procedure
```

---

# 23. Module 6.18 — Real → Equivalent → Simulated Model

This becomes a central abstraction.

```text
REAL INCIDENT
       ↓
Observed Procedure
       ↓
ATT&CK / Internal Behavior
       ↓
Equivalent Behavior
       ↓
Safe Simulation Procedure
       ↓
Execution
       ↓
Telemetry
       ↓
Detection
```

Definitions:

### Observed Procedure

What the real actor actually did.

### Equivalent Procedure

A different implementation producing materially similar behavior.

### Simulation Procedure

The controlled implementation used by the simulation platform.

---

# 24. Module 6.19 — Organization Context Expansion

Existing POC context includes critical assets, technology stack, controls and feasibility.

Expand it to:

```text
Organization
├── Users
├── Identities
├── Devices
├── Servers
├── Applications
├── Cloud
├── SaaS
├── Networks
├── Trust Boundaries
├── Critical Assets
├── Business Processes
├── Security Controls
├── Detection Coverage
├── Administrative Relationships
└── Identity Dependencies
```

---

# 25. Asset Model

```yaml
Asset:
  id:
  name:
  type:
  owner:
  business_criticality:
  confidentiality:
  integrity:
  availability:

  exposure:
  network_zone:

  operating_system:
  identity_dependencies:
  applications:

  security_controls:
  detection_coverage:

  allowed_simulation:
  simulation_constraints:
```

---

# 26. Module 6.20 — Attack Path Engine

Given:

```text
Threat
Objective
Organization
Critical Asset
Constraints
```

find:

```text
Real-world paths
+
Feasible paths
+
Simulation-ready paths
```

The engine must account for:

```text
Prerequisites
Dependencies
Identity relationships
Network reachability
Privileges
Available procedures
Environmental controls
Detection objectives
```

---

# 27. Path Ranking

Candidate paths are scored on:

```text
Realism
Threat relevance
Environment feasibility
Critical asset proximity
Historical observation
Detection value
Simulation availability
Complexity
Safety constraints
```

Output:

```text
PATH 1
Score: 93

PATH 2
Score: 87

PATH 3
Score: 79
```

---

# 28. Module 6.21 — Simulation Procedure Resolver

Input:

```text
Action:
Credential Access

Technique:
Txxxx

Platform:
Windows
```

Resolver searches:

```text
Observed procedures
Equivalent procedures
Atomic tests
CALDERA abilities
Custom implementations
Manual runbooks
```

Output:

```text
Procedure #1
Procedure #2
Procedure #3
```

Each procedure includes:

```text
Prerequisites
Inputs
Execution
Expected behavior
Telemetry
Success criteria
Cleanup
Rollback
Safety classification
```

---

# 29. Module 6.22 — Execution Adapter Layer

Do not couple AIE directly to any simulator.

Create:

```text
Execution Adapter API
```

Adapters:

```text
Atomic Red Team
CALDERA
Custom Emulation Engine
Cloud Simulation Engine
Identity Simulation Engine
Manual Operator
```

The planner generates an abstract procedure.

The adapter translates it into a platform-specific implementation.

---

# 30. Module 6.23 — Simulation Campaign Planner

Campaign types:

```text
Technique Test
Tactic Assessment
Scenario Assessment
Threat Actor Emulation
Campaign Emulation
Detection Validation
Control Validation
Full Purple-Team Exercise
```

Campaign configuration:

```yaml
Campaign:
  id:
  name:

  objective:
  threat_model:
  actor:
  campaign:

  scope:
    assets:
    identities:
    networks:

  attack_flow:

  constraints:
    destructive_actions_allowed:
    production_allowed:
    external_network_allowed:

  detection_goals:
  success_criteria:

  procedures:
  execution_plan:
```

---

# 31. Module 6.24 — Execution Orchestrator

Execution lifecycle:

```text
DRAFT
 ↓
REVIEW
 ↓
APPROVAL
 ↓
SCHEDULED
 ↓
EXECUTING
 ↓
PAUSED / FAILED / COMPLETED
 ↓
VALIDATION
 ↓
ASSESSMENT
```

The orchestrator controls:

```text
Scope
Approval
Prerequisites
Execution order
Timeout
Rollback
Cleanup
Evidence
Operator identity
Execution logs
```

---

# 32. Module 6.25 — Telemetry Expectations

For every simulation action define:

```text
Expected process events
Expected network events
Expected authentication events
Expected file events
Expected registry events
Expected cloud events
Expected identity events
Expected EDR telemetry
Expected SIEM telemetry
```

Example:

```yaml
TelemetryExpectation:
  action_id:
  source:
  event_type:
  expected_fields:
  expected_pattern:
```

---

# 33. Module 6.26 — Detection Validation

For each simulation:

```text
Expected Detection
Actual Detection
Alert Time
Detection Source
Severity
Analyst Response
```

Pipeline:

```text
Simulation
 ↓
Telemetry
 ↓
Detection Analytics
 ↓
Alert
 ↓
Case
 ↓
Analyst
```

AIE should record whether every step worked.

---

# 34. Module 6.27 — Coverage Model

For every technique:

```text
Threat relevance
Environment applicability
Simulation coverage
Telemetry coverage
Detection coverage
Response coverage
```

Example:

```text
Txxxx

Simulation:       YES
Telemetry:        YES
Detection:        NO
Response:         NO

Coverage:         PARTIAL
```

---

# 35. Module 6.28 — Simulation Result

```yaml
SimulationResult:
  id:
  campaign_id:
  scenario_id:

  start_time:
  end_time:

  executed_procedures:
  successful_actions:
  failed_actions:

  telemetry_observed:
  detections_triggered:
  alerts:
  cases:

  detection_latency:
  response_latency:

  coverage_score:
  gaps:

  cleanup_status:
  operator_notes:
```

---

# 36. Module 6.29 — Feedback / Learning Engine

After every simulation:

```text
Execution Result
       ↓
Observed Behavior
       ↓
Detection Result
       ↓
Coverage Result
       ↓
Knowledge Update
```

Examples:

```text
Simulation failed
→ procedure metadata update

Detection missed
→ detection gap

New telemetry found
→ telemetry profile update

New technique behavior observed
→ emerging behavior candidate

Procedure successful
→ readiness score increased
```

---

# 37. Module 6.30 — "What Should We Test Next?" Engine

This is the final recommendation layer.

After an assessment:

```text
Previous simulation
       ↓
Results
       ↓
Gaps
       ↓
Threat intelligence
       ↓
New ATT&CK content
       ↓
Emerging behaviors
       ↓
Next recommendations
```

Example:

```text
NEXT RECOMMENDED SIMULATIONS

1. Credential Access → Lateral Movement
   Reason:
   Detection gap + high organizational relevance

2. New emerging identity behavior
   Reason:
   6 recent reports + no existing detection

3. Persistence technique
   Reason:
   High critical-asset exposure + untested
```

---

# 38. Module 6.31 — Threat-to-Simulation Gap

Create a formal metric:

```text
Threat-to-Simulation Gap
```

Example:

```text
Threat Intelligence:
Known

Organization relevance:
High

ATT&CK mapping:
Available

Simulation:
Unavailable

Detection:
Unavailable
```

Result:

```text
THREAT → SIMULATION GAP
CRITICAL
```

Another:

```text
ATT&CK: ✓
Simulation: ✓
Telemetry: ✓
Detection: ✓
Validation: ✓
```

Result:

```text
GAP = LOW
```

---

# 39. Module 6.32 — Assessment Dashboard

Primary dashboard:

```text
┌─────────────────────────────────────────────────────┐
│ ADVERSARY SIMULATION OVERVIEW                       │
├─────────────────────────────────────────────────────┤
│ Relevant Techniques              127               │
│ Tested Techniques                 61               │
│ Untested Techniques               66               │
│ Detection Gaps                    23               │
│ Emerging Behaviors                 9               │
│ New Since Last Assessment         14               │
├─────────────────────────────────────────────────────┤
│ Coverage                                            │
│ Simulation        ████████████░░░░  68%             │
│ Telemetry         █████████████░░░  74%             │
│ Detection         █████████░░░░░░░  56%             │
│ Response          ██████░░░░░░░░░░  38%             │
└─────────────────────────────────────────────────────┘
```

---

# 40. Module 6.33 — Attack Flow Visualization

The operator should be able to view the same operation through multiple lenses.

## Attack Flow View

```text
Action → Condition → Action → Action
```

## ATT&CK View

```text
Tactic → Technique → Sub-technique
```

## Kill Chain View

```text
Recon → Delivery → Exploitation → C2 → Objective
```

## Simulation View

```text
Procedure → Execution → Telemetry → Detection
```

All four views reference the same underlying operation.

---

# 41. Module 6.34 — Scenario Search

Search should support natural questions:

```text
"Show ransomware paths to domain controllers"

"Show Windows credential access simulations"

"Show initial access techniques used against manufacturing"

"Find recent emerging techniques relevant to Entra"

"Show simulations combining persistence and defense evasion"

"Find untested lateral movement techniques"

"Show real-world procedures for this technique"
```

The result should contain:

```text
Relevant reports
Observed procedures
Attack flows
ATT&CK mappings
Environment relevance
Simulation options
Detection status
```

---

# 42. Module 6.35 — Scenario Templates

Create reusable templates.

```text
Template:
Initial Access Validation

Template:
Windows Credential Access

Template:
Domain Compromise

Template:
Cloud Identity Compromise

Template:
Ransomware Precursor

Template:
C2 Detection Validation

Template:
EDR Validation

Template:
SIEM Detection Validation
```

Templates can contain:

```text
required stages
optional stages
recommended techniques
excluded techniques
environment requirements
detection objectives
```

---

# 43. Module 6.36 — Scenario Variants

AIE should automatically generate variants.

Example:

```text
Base Scenario:
Initial Access → Execution → Persistence
```

Variants:

```text
Variant A:
Phishing → PowerShell → Persistence

Variant B:
Valid Account → Remote Access → Persistence

Variant C:
Public Application Exploit → Web Execution → Persistence
```

All variants remain linked to the same objective.

---

# 44. Module 6.37 — Difficulty Model

Difficulty should be multidimensional:

```text
Technical Difficulty
Operational Complexity
Stealth Requirement
Number of Hosts
Number of Identities
Infrastructure Complexity
Prerequisite Count
Detection Complexity
Cleanup Complexity
```

Levels:

```text
L1 — Single technique
L2 — Multi-technique
L3 — Multi-host
L4 — Identity + lateral movement
L5 — Full adversary operation
```

---

# 45. Extended Data Model

The existing POC model contains Report, Stage, TechniqueMapping, OrganizationProfile and SimulationPlan.

Extend it with:

```text
Report
Actor
Campaign
Incident
Evidence

AttackFlow
AttackFlowNode
AttackFlowRelationship
Condition
Outcome

Action
Stage
Objective

Technique
Tactic
FrameworkMapping

ObservedProcedure
EquivalentProcedure
SimulationProcedure

Tool
Malware
Infrastructure
IOC
Artifact

Asset
Identity
Control
Detection
Analytic

Scenario
ScenarioBlock
ScenarioVariant
SimulationPlan

Execution
ExecutionStep
Observation
Telemetry
Alert
Case

CoverageResult
Gap
Recommendation

EmergingBehavior
TechniqueCandidate
ATTCKVersion
FrameworkVersion
```

---

# 46. Core Relationships

```text
Actor → conducted → Campaign
Campaign → contains → Incident
Incident → described_by → Report
Report → contains → Evidence

Incident → contains → AttackFlow
AttackFlow → contains → Action
Action → follows → Action
Action → requires → Condition
Action → produces → Artifact

Action → mapped_to → Technique
Technique → belongs_to → Tactic

Action → implemented_by → ObservedProcedure
Technique → has_equivalent → EquivalentProcedure
Technique → simulated_by → SimulationProcedure

SimulationProcedure → implemented_by → ExecutionAdapter

Action → detected_by → Detection
Detection → produces → Alert
Alert → becomes → Case

Asset → exposed_to → Technique
Asset → protected_by → Control

EmergingBehavior → supported_by → Evidence
EmergingBehavior → candidate_for → Technique
EmergingBehavior → simulated_by → SimulationProcedure

Simulation → produces → Telemetry
Simulation → produces → CoverageResult
CoverageResult → creates → Gap
Gap → creates → Recommendation
```

---

# 47. API Extensions

## Intelligence

```text
POST /reports/ingest
POST /reports/{id}/extract
GET  /reports/{id}/attack-flow

GET /actors/{id}
GET /campaigns/{id}
GET /behaviors/{id}
GET /emerging-behaviors
```

## Frameworks

```text
POST /frameworks/sync
GET  /frameworks/versions
GET  /techniques/{id}
GET  /techniques/{id}/mappings
```

## Organization

```text
POST /organizations
POST /organizations/assets
POST /organizations/identities
POST /organizations/controls
GET  /organizations/{id}/coverage
```

## Discovery

```text
POST /recommendations
GET  /recommendations
POST /scenarios/discover
```

## Composer

```text
POST /scenarios
POST /scenarios/validate
POST /scenarios/expand
POST /scenarios/variants
GET  /scenarios/{id}/attack-flow
```

## Planning

```text
POST /plans/generate
POST /plans/{id}/approve
GET  /plans/{id}
```

## Execution

```text
POST /executions
POST /executions/{id}/start
POST /executions/{id}/stop
GET  /executions/{id}
```

## Assessment

```text
GET /executions/{id}/telemetry
GET /executions/{id}/detections
GET /executions/{id}/coverage
GET /organizations/{id}/gaps
GET /organizations/{id}/next-recommendations
```

---

# 48. Search / Query Model

The platform should support structured filtering:

```text
Actor
Campaign
Technique
Tactic
Platform
Asset
OS
Cloud
Environment
Difficulty
Detection
Simulation readiness
Evidence grade
Recency
Emergence score
```

Example query:

```text
Tactic = Lateral Movement
Platform = Windows
Environment = AD
Simulation = Available
Detection = Untested
Threat relevance > 0.7
```

---

# 49. Evidence Model

Every important object must preserve provenance.

```yaml
Evidence:
  id:
  report_id:
  source_url:
  section:
  page:
  paragraph:
  text_hash:
  evidence_type:
  extraction_method:
  confidence:
```

A technique mapping must be explainable:

```text
Why Txxxx?

Evidence:
Report X
Section:
Technical Analysis
Paragraph:
184

Observed procedure:
...

Confidence:
0.93
```

---

# 50. AI Architecture

Use AI as a reasoning layer, not as the database authority.

## Deterministic extraction

Use for:

```text
Hashes
IPs
Domains
URLs
Emails
CVE
File paths
Registry keys
Commands
Dates
Tool names
```

## LLM / NLP

Use for:

```text
Stage detection
Cause/effect relationships
Attack-flow reconstruction
Procedure understanding
Novelty analysis
ATT&CK candidate mapping
Scenario summarization
Plan generation
```

## Human validation

Required for:

```text
High-impact mappings
Emerging technique promotion
Attribution
Ambiguous attack-flow relationships
Production execution
```

---

# 51. AI Confidence Architecture

Never use one confidence value.

Store:

```text
ExtractionConfidence
EvidenceConfidence
TechniqueMappingConfidence
TimelineConfidence
AttributionConfidence
NoveltyConfidence
SimulationConfidence
```

Example:

```yaml
mapping:
  technique: Txxxx
  confidence: 0.91

evidence:
  confidence: 0.98

novelty:
  confidence: 0.81
```

---

# 52. Knowledge Quality Gates

A report is allowed into the simulation knowledge base only when:

```text
Source quality threshold
+
Technical depth threshold
+
Evidence available
+
Extraction quality acceptable
```

Individual objects can be marked:

```text
Verified
Probable
Inferred
Unverified
```

---

# 53. Source-to-Simulation Traceability

A generated simulation must always answer:

```text
Why are we running this?
```

Trace:

```text
Simulation Step
 ↓
Simulation Procedure
 ↓
Technique
 ↓
Observed Procedure
 ↓
Attack Flow
 ↓
Campaign
 ↓
Report
 ↓
Evidence
```

This should be visible in the UI.

---

# 54. Example End-to-End User Journey

User selects:

```text
"Test lateral movement to domain controllers."
```

AIE performs:

```text
1. Load organization assets
2. Identify domain controllers
3. Identify relevant identity relationships
4. Identify reachable systems
5. Query historical threat behavior
6. Find relevant ATT&CK techniques
7. Find emerging behaviors
8. Find real-world attack flows
9. Find simulation procedures
10. Rank paths
```

UI displays:

```text
Recommended Paths

Path 1 — Score 94
Credential Access
→ Remote Service
→ Discovery
→ Domain Controller

Path 2 — Score 87
Valid Account
→ Remote Access
→ Discovery
→ Domain Controller
```

User selects Path 1.

AIE:

```text
Validate prerequisites
↓
Replace unavailable procedure
↓
Generate simulation steps
↓
Attach telemetry expectations
↓
Attach detections
↓
Attach cleanup
```

Operator approves.

Execution begins.

Results:

```text
Technique 1 → executed → detected
Technique 2 → executed → NOT detected
Technique 3 → failed
```

AIE produces:

```text
Coverage Gap:
Technique 2

Recommendation:
Create / tune detection

Next Simulation:
Validate alternate lateral movement procedure
```

---

# 55. Recommended UI Structure

## Main Navigation

```text
Dashboard
Threat Intelligence
Reports
Actors
Campaigns
Attack Flows
Techniques
Emerging Behaviors
Organization
Simulation Explorer
Scenario Composer
Plans
Executions
Detection Validation
Coverage
Recommendations
Frameworks
```

---

# 56. Dashboard

Show:

```text
Threat Landscape
Emerging Behaviors
High-Priority Threats
Organization Attack Surface
Simulation Coverage
Detection Coverage
Recent Executions
Critical Gaps
Recommended Next Tests
```

---

# 57. Technique Detail Page

```text
Technique
├── Description
├── ATT&CK
├── Tactic
├── Real-world Reports
├── Observed Procedures
├── Equivalent Procedures
├── Simulation Procedures
├── Attack Flow Position
├── Tools
├── Artifacts
├── Detection
├── Mitigations
├── Organization Relevance
├── Coverage
└── Emerging Variants
```

---

# 58. Emerging Behavior Detail Page

```text
Behavior
├── Name
├── Description
├── First Seen
├── Trend
├── Reports
├── Actors
├── Campaigns
├── Evidence
├── Candidate ATT&CK
├── Related Existing Techniques
├── Attack Flow
├── Simulation Readiness
├── Detection Readiness
└── Organization Impact
```

---

# 59. Scenario Composer UI

```text
LEFT
Technique / Behavior Library

CENTER
Attack Flow Canvas

RIGHT
Properties / Evidence / Validation

BOTTOM
Simulation Resolution

        ↓

[Validate]
[Generate Plan]
[Save Scenario]
[Execute]
```

---

# 60. "Why this?" Panel

For every node:

```text
WHY THIS STEP?

Observed in:
9 reports

Used by:
4 actors

ATT&CK:
Txxxx

Prerequisite:
Credential available

Organization:
High relevance

Simulation:
3 implementations

Detection:
1 analytic

Evidence:
Report X / paragraph Y
```

---

# 61. "What can come next?" Panel

When selecting a technique:

```text
CURRENT:
Initial Access

RECOMMENDED NEXT:
Execution
Credential Access
Persistence

Most observed:
Execution

Most realistic:
Execution

Highest detection gap:
Credential Access

Highest threat relevance:
Persistence
```

This becomes the operator's decision-support mechanism.

---

# 62. "Combine With" Feature

For any selected technique:

```text
Combine With

Most observed:
Execution
Persistence
Credential Access

High-value combinations:
Initial Access + Execution
Initial Access + Credential Access
Execution + Persistence

Organization-relevant:
Initial Access + Execution
Execution + Lateral Movement
```

---

# 63. "Build Scenario from Report"

Every report should provide:

```text
[Create Simulation From Report]
```

The platform extracts:

```text
Observed Attack Flow
```

Then presents:

```text
Original
        ↓
Organization Adaptation
        ↓
Simulation Flow
```

User can remove or replace stages.

---

# 64. "Build Scenario from Threat Actor"

Example:

```text
Actor:
TAxxxx

Known operations:
12

Relevant techniques:
43

Available simulation procedures:
27

Organization-relevant:
19

Generate:
[Full emulation]
[Selected tactic]
[Selected objective]
```

---

# 65. "Build Scenario from Asset"

Example:

```text
Asset:
Domain Controller

Threat paths:
17

Simulation-ready paths:
9

Untested:
6

Detection gaps:
4

Generate attack paths
```

---

# 66. "Build Scenario from Detection Gap"

Example:

```text
Detection gap:
Credential dumping

AIE finds:

Related real-world procedures
Relevant actors
ATT&CK techniques
Simulation procedures
Equivalent procedures
Prerequisite steps
```

Then generates:

```text
Credential Access
→ Post-access action
→ Lateral movement
```

rather than testing the isolated behavior only.

---

# 67. Framework Visualization Strategy

Do not create separate disconnected models.

Use one operation:

```text
Canonical Attack Operation
```

with multiple views:

```text
ATT&CK View
Attack Flow View
Kill Chain View
Simulation View
Detection View
```

---

# 68. Emerging Technology / Technique Watch Pipeline

Continuously monitor:

```text
New research
New threat reports
New incident reports
Vendor research
ATT&CK updates
Actor updates
Malware research
Cloud security research
Identity security research
```

Pipeline:

```text
Source
 ↓
Extract
 ↓
Compare
 ↓
Cluster
 ↓
Score
 ↓
Emerging Behavior
 ↓
Simulation readiness
```

---

# 69. Trend Detection

For every behavior track:

```text
Daily frequency
Weekly frequency
Monthly frequency
Actor count
Campaign count
Source count
Platform count
```

Then detect:

```text
Increasing rapidly
Stable
Declining
New
Reappearing
Rare
```

---

# 70. New ATT&CK Release Impact Analysis

When ATT&CK updates:

```text
New release
 ↓
Compare old/new ontology
 ↓
Identify changed techniques
 ↓
Identify affected scenarios
 ↓
Identify affected plans
 ↓
Identify affected mappings
 ↓
Identify emerging behavior matches
```

Then show:

```text
14 scenarios affected
7 mappings require review
4 emerging behaviors now mapped
3 techniques deprecated
```

---

# 71. Scenario Versioning

Every scenario must be versioned.

```text
SC-0042 v1
SC-0042 v2
SC-0042 v3
```

Track:

```text
Technique changes
Procedure changes
ATT&CK changes
Environment changes
Simulation changes
Detection changes
```

Never silently mutate a historical assessment.

---

# 72. Assessment Reproducibility

Every completed assessment must preserve:

```text
Scenario version
ATT&CK version
Framework versions
Organization profile version
Procedure version
Execution engine version
Detection version
Timestamp
Operator
Results
```

This allows:

```text
Assessment A in August
vs.
Assessment A in November
```

to be compared accurately.

---

# 73. Extended Success Criteria

The existing POC targets at least 30 high-quality reports, ATT&CK mapping, multi-stage plan generation and organization-aware ranking.

Extend success criteria to:

```text
1. ≥30 high-quality reports ingested

2. ≥90% of extracted high-confidence objects traceable to evidence

3. Attack flow reconstructed for ≥80% of qualified reports

4. Technique mappings include confidence + evidence

5. ≥20 reusable simulation scenarios

6. Scenario composer supports:
   - single techniques
   - tactic ranges
   - arbitrary combinations
   - full campaigns

7. At least 3 organization-aware recommendations

8. Emerging behavior detection demonstrated on held-out reports

9. ATT&CK update reconciliation demonstrated

10. At least 5 simulations executed through an adapter

11. Telemetry captured for executed steps

12. Detection coverage measured

13. Assessment generates next-step recommendations

14. Complete source → simulation traceability
```

---

# 74. Revised Implementation Phases

## Phase 0 — Existing Foundation

```text
Source registry
Raw storage
ATT&CK loading
Basic data model
```

Existing POC already covers this.

---

## Phase 1 — Intelligence Core

```text
Extraction
Evidence
Timeline
Procedures
Attack reconstruction
Knowledge graph
```

---

## Phase 2 — Framework & Emerging Intelligence

```text
ATT&CK synchronization
Versioning
Framework normalization
Emerging behavior detection
Candidate mappings
Reconciliation
```

---

## Phase 3 — Organization Intelligence

```text
Assets
Identities
Technology stack
Controls
Detection coverage
Attack surface
```

---

## Phase 4 — Simulation Discovery

```text
Recommendation engine
Technique explorer
Use cases
Coverage objectives
Scenario templates
```

---

## Phase 5 — Attack Flow & Scenario Composer

```text
Attack Flow graph
Scenario blocks
Scenario variants
Flow validation
Prerequisite engine
```

---

## Phase 6 — Plan Generation

```text
Simulation procedure resolution
Adapters
Runbooks
Execution prerequisites
Cleanup
```

---

## Phase 7 — Execution

```text
Execution orchestrator
Approval
Scheduling
Adapters
Telemetry collection
```

---

## Phase 8 — Validation

```text
Detection matching
Alert correlation
Coverage scoring
Gap discovery
```

---

## Phase 9 — Learning Loop

```text
Assessment result
Knowledge update
Emerging behavior update
Recommendation update
Next simulation
```

---

# 75. Revised Product Positioning

The product should no longer be positioned simply as:

> "An intelligence engine that converts reports into simulation plans."

The stronger positioning is:

> **A threat-informed adversary simulation intelligence platform that continuously transforms real-world adversary behavior into evidence-backed attack flows, maps those behaviors across security frameworks, understands organizational exposure, discovers emerging techniques, recommends high-value simulation scenarios, composes multi-stage campaigns, resolves executable simulation procedures, and measures detection and response outcomes.**

---

# 76. Final Product Model

The complete AIE becomes:

```text
                         AIE
                          │
       ┌──────────────────┼──────────────────┐
       ↓                  ↓                  ↓
 Threat Intelligence   Organization      Frameworks
       │                  │                  │
       ↓                  ↓                  ↓
 Reports             Assets / Identity   ATT&CK
 Campaigns            Controls            Attack Flow
 Actors               Detection           Kill Chain
       │                  │                D3FEND
       └──────────────────┼──────────────────┘
                          ↓
                   Knowledge Graph
                          ↓
             ┌────────────┴─────────────┐
             ↓                          ↓
      Known Behavior             Emerging Behavior
             │                          │
             └────────────┬─────────────┘
                          ↓
                   Attack Flow
                          ↓
              Recommendation Engine
                          ↓
                Scenario Composer
                          ↓
                  Path Generator
                          ↓
               Simulation Resolver
                          ↓
                 Execution Engine
                          ↓
                    Telemetry
                          ↓
                    Detection
                          ↓
                    Assessment
                          ↓
                 Coverage / Gaps
                          ↓
                    Recommendations
                          ↓
                 Next Simulation
                          │
                          └───────────────→ continuous loop
```

---

# 77. The Fundamental Design Rule

AIE should always preserve this chain:

```text
REAL WORLD
    ↓
EVIDENCE
    ↓
BEHAVIOR
    ↓
ATTACK FLOW
    ↓
FRAMEWORK MAPPING
    ↓
ORGANIZATION RELEVANCE
    ↓
SCENARIO
    ↓
SIMULATION
    ↓
TELEMETRY
    ↓
DETECTION
    ↓
ASSESSMENT
```

Never collapse these layers into a single "ATT&CK technique" object.

That separation is what allows the system to support:

```text
Known ATT&CK techniques
+
New/emerging techniques
+
Real campaigns
+
Custom scenarios
+
Single-technique testing
+
Multi-technique testing
+
Full adversary emulation
+
Detection validation
+
Organization-specific planning
```

---

# 78. Final Recommended Core Modules

The complete product should ultimately contain:

```text
01 Source Intelligence
02 Ingestion
03 Provenance & Evidence
04 Report Understanding
05 Attack Reconstruction
06 Behavior Knowledge
07 Emerging Behavior Intelligence
08 ATT&CK Synchronization
09 Framework Normalization
10 Knowledge Graph
11 Organization Context
12 Environment Attack Graph
13 Simulation Discovery
14 Technique Explorer
15 Use-Case Engine
16 Scenario Library
17 Scenario Composer
18 Attack Flow Engine
19 Path Generation
20 Simulation Procedure Resolver
21 Execution Adapters
22 Campaign Planner
23 Execution Orchestrator
24 Telemetry Expectations
25 Detection Validation
26 Coverage Engine
27 Assessment Engine
28 Threat-to-Simulation Gap
29 Recommendation Engine
30 Feedback / Learning Engine
31 Reporting
32 API
33 Versioning / Audit
34 Safety / Execution Governance
35 Search / Semantic Retrieval
```

The original POC already contains the beginnings of modules for ingestion, extraction, ATT&CK mapping, graph storage, organization context, path generation and plan export. This extension turns those foundations into the **full operational loop from threat intelligence to continuous adversary simulation and defensive validation**.