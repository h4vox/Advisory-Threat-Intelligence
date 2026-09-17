---
name: domain-resource-discovery-intel
description: >-
  Autonomously discovers high-value cyber threat intelligence domains, research endpoints, and
  executes coordinated multi-resource extraction from target domains, followed by 5-dimensional
  adversary emulation and tradecraft validation scoring.
---

# Domain Resource Discovery & Validation Intelligence Skill

This skill defines the autonomous operational doctrine for discovering new CTI research domains, harvesting all technical intelligence resources coordinated across target domains, and performing strict 5-dimensional post-crawl validation and scoring.

---

## 1. Autonomous Domain & Endpoint Discovery Doctrine

When hunting for new intelligence domains or responding to discovery queries:
1. **Target Authoritative Technical Research Labs**:
   - Specialized vendor research labs (e.g., Check Point Research, Elastic Security Labs, Huntress Labs, Volexity, Sophos X-Ops, Red Canary, SentinelOne Labs, Sygnia, Group-IB).
   - Independent DFIR and reverse engineering collectives (e.g., The DFIR Report, Outflank, SpecterOps, TrustedSec).
   - Threat intelligence and CSIRT advisory hubs (e.g., CISA Cybersecurity Advisories, NCSC, JPCERT/CC, Talos Intelligence).
   - Emulation and threat-informed repositories (e.g., MITRE Center for Threat-Informed Defense, Atomic Red Team, Scythe, Caldera).

2. **Crawl Endpoint Normalization**:
   - Do NOT register root marketing homepages (e.g., `https://huntress.com/`).
   - Extract the exact technical research subpath where research reports live:
     - `https://www.huntress.com/blog/*`
     - `https://research.checkpoint.com/*`
     - `https://www.elastic.co/security-labs/*`
     - `https://news.sophos.com/en-us/category/threat-research/*`
   - Always append `/*` to denote a recursive research boundary.
   - Do NOT output single-article dated permalinks as source crawl patterns.

---

## 2. Coordinated Multi-Resource Domain Extraction

When a target domain is supplied (or newly discovered), do NOT merely scrape the entry page. Execute coordinated multi-resource discovery:
1. **Sitemap & Archive Probing**:
   - Identify `/sitemap.xml`, `/sitemap-posts.xml`, or `/blog-sitemap.xml`.
   - Identify dedicated category feeds (e.g., `/category/threat-research/`, `/category/malware-analysis/`, `/tag/incident-response/`).
2. **Article Permalink Disambiguation**:
   - Differentiate high-signal technical research articles from pagination, author archives, corporate announcements, and marketing noise.
   - Look for permalink structures containing year/month dates (`/2026/03/...`), research slugs (`/threat-research/...`), or adversary identifiers (`/apt...`, `/ransomware...`, `/cve-...`).
3. **Coordinated Batch Delivery**:
   - Output candidate URLs with extracted titles, estimated publish dates, and initial technical relevance indicators so the crawler engine can enqueue them simultaneously.

---

## 3. Post-Crawl 5-Dimensional AI Validation & Scoring Rubric

Every crawled resource must undergo rigorous, objective evaluation against this standard 5-dimensional rubric:

### Dimension 1: Procedural Depth (Weight: 30%, 0–30 pts)
Measures the density of concrete adversary tradecraft, commands, and low-level OS mechanics:
- **25–30 pts**: Verbatim command lines (`powershell.exe`, LOLBins, `rundll32`, `certutil`), API call sequences (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`), registry modifications (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`), or direct syscall/driver manipulation.
- **15–24 pts**: Specific tool usage with sub-commands, parameters, or forensic artifact paths.
- **5–14 pts**: High-level mentions of tools without exact command-line syntax.
- **0–4 pts**: Abstract descriptions ("the attackers executed a script") without technical evidence.

### Dimension 2: Attack Progression & Chain Completeness (Weight: 25%, 0–25 pts)
Measures the chronological, multi-stage structure of the intrusion:
- **21–25 pts**: Complete end-to-end multi-stage intrusion flow (Initial Access → Loader/Execution → Defense Evasion → Credential Access → Lateral Movement → C2 → Impact/Exfiltration).
- **13–20 pts**: At least 3 contiguous phases clearly linked (e.g., Phishing Dropper → DLL Sideloading → C2 Beacon).
- **6–12 pts**: Isolated stage analysis (e.g., standalone loader reverse engineering).
- **0–5 pts**: Single point-in-time snapshot or vulnerability notice with no progression.

### Dimension 3: Attribution & Threat Context (Weight: 15%, 0–15 pts)
Measures actor attribution, campaign tracking, and vulnerability context:
- **12–15 pts**: Confirmed or cluster-attributed threat actor (APT, ransomware syndicate), campaign timeline, targeted industries/geographies, or weaponized CVE references.
- **7–11 pts**: Unnamed sophisticated cluster with consistent telemetry or general campaign overview.
- **0–6 pts**: Generic background with no attribution or campaign context.

### Dimension 4: Emulation & Detection Engineering Utility (Weight: 20%, 0–20 pts)
Measures direct applicability to purple-team exercises and blue-team detections:
- **17–20 pts**: Includes Sigma rules, YARA rules, Suricata/Snort signatures, EDR/Sysmon telemetry queries (Event ID 4688, Sysmon 1/3/7/10), or step-by-step Atomic Red Team/Caldera replay commands.
- **10–16 pts**: Clear detection opportunities, behavioral indicators of attack (IOAs), and forensic hunting guidance.
- **4–9 pts**: Static indicators only (file hashes, IP addresses) without detection logic.
- **0–3 pts**: Zero detection or emulation utility.

### Dimension 5: IOC & Telemetry Verifiability (Weight: 10%, 0–10 pts)
Measures presence and quality of verifiable technical indicators:
- **8–10 pts**: Defanged network infrastructure (C2 IPs, domains, URIs) and cryptographic file hashes (SHA256) with detailed artifact context.
- **4–7 pts**: Partial IOC tables or unconfirmed telemetry.
- **0–3 pts**: No verifiable technical IOCs.

---

## 4. Score Calculation & Decision Thresholds

The Total Score is calculated as:
$$\text{Total Score} = \text{Procedural} (0-30) + \text{Progression} (0-25) + \text{Attribution} (0-15) + \text{Emulation} (0-20) + \text{IOC} (0-10)$$

### Decision Matrix:
- **$\ge 75$ Points — Tier-1 Adversary Emulation Resource**:
  - `recommendApproval: true`
  - Approved ResourceKind: `FULL_ATTACK_CHAIN` or `PROCEDURE_DEEPDIVE`
  - Auto-ingest eligible when enabled in configuration.
- **$50 - 74$ Points — Tier-2 Threat Intelligence Report**:
  - `recommendApproval: true`
  - Approved ResourceKind: `CAMPAIGN_INTEL`, `MALWARE_ANALYSIS`, or `DETECTION_GUIDANCE`
- **$< 50$ Points — Rejection**:
  - `recommendApproval: false`
  - Automatically rejected from primary library.
  - Reason explicitly documents which dimensions fell below minimum viable depth.

---

## 5. Standard Output Schema

The Agent must return structured JSON matching this schema:
```json
{
  "isRelevant": true,
  "passScore": 86,
  "recommendApproval": true,
  "classification": "ATTACK_CHAIN_REPORT",
  "resourceKind": "FULL_ATTACK_CHAIN",
  "threatActors": ["Scattered Spider", "UNC3944"],
  "malwareFamilies": ["Sliver", "BlackCat"],
  "cves": ["CVE-2024-21762"],
  "mitreTechniques": ["T1566.001", "T1059.001", "T1055.012", "T1071.001"],
  "stages": [
    "Initial Access: SMS Phishing to Helpdesk",
    "Execution: PowerShell staging script",
    "Persistence: Azure AD OAuth application",
    "Lateral Movement: Remote Desktop Protocol",
    "Impact: Data staging and exfiltration via Rclone"
  ],
  "scoreBreakdown": {
    "proceduralDepth": 26,
    "attackProgression": 24,
    "attributionContext": 13,
    "emulationUtility": 15,
    "iocVerifiability": 8,
    "totalScore": 86
  },
  "rationale": "High-fidelity incident response report featuring full chronological intrusion progression, verbatim PowerShell and Rclone command execution, and EDR hunting queries."
}
```
