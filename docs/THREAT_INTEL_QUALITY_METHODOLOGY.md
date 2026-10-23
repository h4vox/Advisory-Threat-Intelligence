# Threat Intelligence Quality Methodology & Adversary Emulation Standards

> **Document Version**: 2.0  
> **Target System**: Adversary Intelligence Engine (AIE)  
> **Scope**: Advisory Threat Intelligence & Autonomous Adversary Emulation  
> **Maintenance**: Enforced autonomously across crawler pipelines, ingestion gates, and library storage.

---

## 1. Operating Charter & Scope

The Adversary Intelligence Engine (AIE) is purpose-built to collect, analyze, structure, and synthesize **actionable technical cyber threat intelligence (CTI)**. Its primary mission is to empower:

1. **Adversary Emulation & Simulation**: Constructing realistic adversary playbooks, atomic unit tests, Caldera scenarios, and infection chain replays.
2. **Threat Advisory & Tradecraft Intelligence**: Delivering deep, procedure-level intelligence dossiers on threat actors, campaigns, and zero-day vulnerabilities to security operations centers (SOCs) and detection engineering teams.
3. **Detection & Purple Team Engineering**: Validating detection coverage against real-world execution commands, LOLBins, registry persistence, and defensive telemetry (Sysmon, Windows Event Logs, EDR telemetry).

### Scope Invariant
> [!IMPORTANT]
> The AIE Library exists **solely** to house high-fidelity, procedure-level threat intelligence. It is **not** a general infosec news aggregator, commercial marketing repository, or general IT blog directory. Every resource retained in the library must contribute directly to adversary emulation or actionable threat defense.

---

## 2. Strict Qualification Rubric

Before any scraped or discovered resource is ingested into the library, it must pass a dual-tier gate: **URL Structural Filtering** and **Technical Anchor Verification**.

### 2.1 URL Structural Filtering (Tier 1 Gate)

Candidate URLs must point to a deep technical article permalink. The ingestion pipeline enforces the following structural rules:

```
[Candidate URL]
      │
      ├── Match Generic / Non-Resource Pattern? ──► REJECT (Index / Category / Multimedia)
      │
      ├── Blacklisted Non-CTI Host? ──────────────► REJECT (Immigration, Civil Admin, Social)
      │
      ├── Path Depth < 2 & No Article Slug? ─────► REJECT (Shallow Path / Apex Root)
      │
      └── Verified Deep Article Permalink ───────► Proceed to Tier 2 (Content Qualification)
```

#### Hard-Rejected Patterns (Zero Tolerance)
- **Homepages & Locale Roots**: `/`, `/en`, `/en-us`, `/en_us`, `/index.html`
- **Aggregators & Navigation**: `/category/*`, `/tags/*`, `/topics/*`, `/authors/*`, `/archive/*`, `/page/*`
- **Administrative & Index Endpoints**: `/all-news-updates`, `/latest-publications`, `/resources`, `/white-papers`, `/tips-advice`, `/business-security`, `/eset-research` (without slug)
- **Multimedia & Podcasts**: `/podcasts/*`, `/webinars/*`, `/videos/*`, `/interviews/*`, `/events/*`, `*talos_takes*`
- **Corporate, Legal & Policy Pages**: `/privacy-policy`, `/terms-of-service`, `/disclosure-policy`, `/careers`, `/pricing`, `/contact-us`, `/about-us`, `/sitemap*`
- **Non-CTI Civil Administrative Hosts**: `uscis.gov`, `ice.gov`, `e-verify.gov`, `dhs.gov` (non-CISA portals), `irs.gov`, `state.gov`, `treasury.gov`

---

### 2.2 Technical Depth (Tier 2 Gate)

`src/lib/aie/technical-depth.ts` reads the article prose only: lines that are nothing but links
(menus, footers, "related reports" lists) are dropped first, because a vendor footer linking to
"Threat Intel and Incident Response Services" once passed a product page as an intrusion report.
A document passes when it has at least one technical anchor:

| Anchor | Minimum | Examples |
|---|---|---|
| **ATT&CK technique IDs** | 1 | `T1059.001`, `T1566.002` |
| **Indicators** | 2 distinct | SHA-256/SHA-1/MD5 hashes, public IPv4 (defanged counts; private and version-like numbers do not), defanged domains, `hxxp` URLs |
| **Attacker commands** | 2 | `powershell -enc`, `rundll32`, `vssadmin delete shadows`, `certutil -urlcache` |
| **Described attacker activity** | named actor + 5 behaviours, or 8 behaviours | "the actor sent spear-phishing e-mails… used scheduled tasks for persistence… exfiltrated archives" |
| **Exploited-CVE advisory** | 1 CVE with exploitation wording | only from a CERT or government publisher (cisa.gov, cyber.gov.au, ncsc.gov.uk, cert.pl, …) |

Without an anchor, the document is rejected and the reason names what it is: a product or marketing
page, a strategic or trends piece, guidance or opinion, news without technical detail (news
publishers), or a document with no technical detail. The AI reviewer may rescue a thin document but
is never asked to overturn the other verdicts.

The Library gate (`src/lib/aie/library-gate.ts`, version 3) applies the same check to stored
reports on the next Library visit and hides, never deletes, the ones that fail; each shows why, and
Restore brings one back for good.

> [!CAUTION]
> General journalistic news blurbs (e.g., general reporting on ransomware victim statistics, legal lawsuits, or executive appointments) that lack any technical execution commands or IOCs are **strictly disqualified**.

### 2.3 Reports in Other Languages

A report is judged in English. When the crawler finds a page in another language
(`detectLanguage`: script, diacritics, several distinct function words, never one ambiguous word):

1. **The publisher's English edition.** A `hreflang="en"` alternate or a language switcher to the
   same path under `/en/` is followed instead. A localized copy whose path without the language
   segment (`/blog/ja/topics/x` → `/blog/topics/x`) is already in the library, or queued in the same
   crawl, is recorded as a duplicate.
2. **AI translation.** Otherwise the active AI provider (REST API or the AGY agent) translates the
   text in parts of up to 6,000 characters, 24,000 per report; the rest of a longer report is kept in
   the original so its indicator appendix is still extracted. Every part is checked: all indicators
   and identifiers (hashes, IPs, defanged domains, CVE and ATT&CK IDs) kept, none invented, a
   plausible length, English output. Any failed part fails the translation.
3. **Held, not rejected.** Without AI, with translation turned off (crawl settings), when the
   translation fails its checks, or when the run's translation budget (12 reports, 10 minutes) is
   used, the page is recorded as *Held*. Later crawls evaluate it again.

The translated report stores the English text as `extractedText` and the original title and text
under `translation`; the report page shows "Translated from …" and the original. Dedup fingerprints
stay on the published text, so a re-crawl matches it, and a changed page is translated again before
its new version is stored.

---

## 3. The 5-Dimensional Tradecraft Evaluation Rubric

When autonomous AI evaluation is enabled, resources are evaluated on a 100-point scale across 5 dimensions:

```mermaid
pie title 5-Dimensional Adversary Emulation Rubric (100 Points)
    "Procedural Density & Commands" : 25
    "Attack Chain Completeness" : 25
    "Detection & Telemetry Fidelity" : 20
    "IOC & Threat Attribution" : 15
    "Tradecraft Novelty" : 15
```

### Dimension Breakdown
1. **Procedural Density & Commands (25 Points)**:
   - Presence of raw execution commands, scripts, LOLBins, process injection techniques, or binary flags.
2. **Attack Chain Completeness (25 Points)**:
   - Clear multi-stage intrusion progression: Dropper $\rightarrow$ Loader $\rightarrow$ Execution $\rightarrow$ Persistence $\rightarrow$ Lateral Movement $\rightarrow$ C2 $\rightarrow$ Impact.
3. **Detection & Telemetry Fidelity (20 Points)**:
   - Sigma rules, YARA signatures, EDR telemetry patterns, Windows Event IDs (4688, 4624, 7045), Sysmon telemetry.
4. **IOC & Threat Attribution (15 Points)**:
   - Defanged network indicators, file hashes, named threat actors (e.g. APT29, Volt Typhoon, Lazarus, FIN7), targeted sectors.
5. **Tradecraft Novelty (15 Points)**:
   - Emerging adversary techniques: BYOVD (Bring Your Own Vulnerable Driver), direct syscalls, EDR unhooking, AMSI/ETW patching, living-off-the-cloud.

**Qualification Threshold**: Documents scoring $\ge 50$ points are approved. Documents scoring $< 50$ points are rejected.

---

## 4. Library Classification Taxonomy

Retained documents are classified into structured threat intelligence categories:

| Resource Classification | Resource Kind | Primary Engineering Use Case |
|---|---|---|
| `ATTACK_CHAIN_REPORT` | `FULL_ATTACK_CHAIN` | End-to-end intrusion flows for multi-stage scenario simulation |
| `ADVERSARY_EMULATION` | `PROCEDURE_DEEPDIVE` | Atomic unit tests, Caldera blueprints, and red team execution playbooks |
| `PURPLE_TEAM` | `PROCEDURE_DEEPDIVE` | Joint offensive emulation and defensive detection validation |
| `INTRUSION_REPORT` | `FULL_ATTACK_CHAIN` | Chronological incident response timeline for breach replication |
| `MALWARE_ANALYSIS` | `MALWARE_ANALYSIS` | Reverse engineering, unpacking, and payload behavior modeling |
| `DETECTION_RESEARCH` | `DETECTION_GUIDANCE` | Hunting queries, Sigma/YARA engineering, and detection gap analysis |
| `VULNERABILITY_REPORT`| `VULNERABILITY_ADVISORY` | Zero-day exploitation, PoC analysis, and patch diffing |
| `THREAT_ACTOR_REPORT` | `THREAT_ACTOR_DOSSIER` | Nation-state / cybercrime profiling, TTP heatmaps, targeting analysis |

---

## 5. Continuous Audit & Maintenance Protocol

To prevent scope creep and maintain library integrity over continuous multi-day crawler runs, the engineering team maintains automated audit tools:

### Operator CLI Commands

```bash
# Perform a dry-run audit of all library documents against CTI standards
npm run aie library audit

# Execute live pruning of all unqualified or low-signal documents from MongoDB
npm run aie library prune

# Execute deep cognitive AI audit using containerized AGY agent (5-dimensional rubric)
npm run aie library ai-audit --limit 10

# Execute deep cognitive AI audit with automatic pruning of AI-rejected non-threat records
npm run aie library ai-audit --prune --limit 25
```

### Automated Audit Scripts
- **Structural Audit & Pruning**: [`scripts/audit-and-prune-library.mjs`](file:///mnt/c/Users/AbishekPonmudi/Downloads/EIsj5xs92ARrG3Bd-grok-workspace/scripts/audit-and-prune-library.mjs)
- **Cognitive AI Agent Audit**: [`scripts/cognitive-ai-audit.mjs`](file:///mnt/c/Users/AbishekPonmudi/Downloads/EIsj5xs92ARrG3Bd-grok-workspace/scripts/cognitive-ai-audit.mjs)
- **Audit Log Artifacts**:
  - [`docs/library-audit-log.json`](file:///mnt/c/Users/AbishekPonmudi/Downloads/EIsj5xs92ARrG3Bd-grok-workspace/docs/library-audit-log.json)
  - [`docs/cognitive-ai-audit-log.json`](file:///mnt/c/Users/AbishekPonmudi/Downloads/EIsj5xs92ARrG3Bd-grok-workspace/docs/cognitive-ai-audit-log.json)
- **Frequency**: Automatically scheduled or triggered post-crawl to preserve a 100% high-signal repository.

---

## 6. Cognitive AI Tradecraft Rubric (AGY Container)

The autonomous AI approval gate executes inside `aie-agent-sandbox` via `agy` without any fallback to mock approvals or superficial heuristics:

| Dimension | Points | Core Criteria Evaluated by AI Agent |
|---|---|---|
| **1. Procedural Depth** | 0 – 30 | Concrete execution commands (PowerShell, cmd, LOLBins, bash), API call sequences, registry keys, process injection, DLL sideloading, or driver tampering. |
| **2. Attack Progression & Chain** | 0 – 25 | Multi-stage sequential intrusion flow (Initial Access -> Loader -> Execution -> Lateral Movement -> C2 -> Impact). |
| **3. Attribution & Context** | 0 – 15 | Identified threat actor (APT, cybercrime syndicate), campaign timeline, targeted sectors, or weaponized CVE references. |
| **4. Emulation & Detection Utility** | 0 – 20 | Direct utility for purple teams/SOC: Sigma rules, YARA rules, EDR/Sysmon telemetry queries, or Atomic Red Team / Caldera replay commands. |
| **5. IOC & Telemetry Verifiability** | 0 – 10 | Defanged network indicators (C2 IPs, domains), file hashes (SHA256), Windows Event IDs, Sysmon events. |

**Strict Cognitive Thresholds**:
- **Score $\ge 50$** AND **Classification $\ne$ "OTHER" / "GENERIC_NEWS"**: Approved (`status: "acquired"`, `aiVerified: true`).
- **Score $< 50$** OR **Classification $=$ "OTHER" / "GENERIC_NEWS"**: Rejected (`status: "rejected"`, `aiVerified: false`), permanently pruned if `--prune` / `autoPruneJunk` is active.

---

## 7. Engineering Verification Checklist

Before releasing or expanding crawler pipelines, engineers must verify:

- [x] Crawl frontier queue strictly validates `isCandidateResourceUrl` before enqueueing.
- [x] Root domains and index pages cannot be scheduled or fetched.
- [x] RSS/Atom feed entries are subjected to negative path and technical anchor filters.
- [x] Non-CTI government administrative hosts (`.gov` civil agencies) are blocked in `STRICT_BLOCKED_DOMAINS`.
- [x] Every retained document contains at least one verified procedural anchor (command, ATT&CK ID, IOC, or CVE).
- [x] Fake AI approval fallbacks (hardcoded 80-score mocks) are completely removed from `ai-manager.ts` and `repository.server.ts`.
- [x] The `aie library ai-audit` command executes live against the containerized AGY agent.
- [x] Misleading heuristic flags have been purged; `aiVerified: true` is strictly reserved for reports evaluated and approved by the LLM agent.
- [x] The `aie library audit` command reports 0% structural junk resources.
