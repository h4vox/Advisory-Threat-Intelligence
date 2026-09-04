---
name: adversary-emulation-intel
description: >-
  Autonomously discovers, collects, and structures high-value cyber threat intelligence, multi-stage
  infection chains, attack flows, intrusion timelines, and adversary emulation playbooks into
  standard machine-readable JSON format for adversary emulation and purple-team engineering.
---

# Adversary Emulation Intelligence Skill

Use this skill to autonomously discover, harvest, and structure real-world infection chains, attack flows, and emulation playbooks without requiring explicit queries.

## Autonomous Discovery Engine
When requested to collect $N$ resources:
1. Autonomously query and explore preferred threat research domains:
   - **Intrusion Timelines & Chains**: `thedfirreport.com`, `unit42.paloaltonetworks.com`, `sentinelone.com/labs`, `securelist.com`, `crowdstrike.com/blog`, `seqrite.com/blog`, `huntress.com/blog`, `research.checkpoint.com`, `elastic.co/security-labs`, `blog.talosintelligence.com`, `redcanary.com`
   - **Government & Cloud Advisories**: `cloud.google.com/blog/topics/threat-intelligence`, `microsoft.com/en-us/security/blog`, `cisa.gov`, `zscaler.com/blogs/security-research`, `welivesecurity.com`, `sophos.com`, `volexity.com`
   - **Emulation Repositories & Tests**: `attack.mitre.org`, `center-for-threat-informed-defense.github.io`, `atomicredteam.io`, `caldera.mitre.org`
2. Search combinations of:
   - `"infection chain"`, `"attack chain"`, `"intrusion chain"`, `"attack flow"`, `"multi-stage"`, `"stage 1"`, `"stage 2"`, `"technical analysis"`, `"MITRE ATT&CK"`, `"adversary emulation"`, `"adversary simulation"`, `"campaign analysis"`, `"intrusion timeline"`
3. For each unique intrusion discovered, extract:
   - **Title & Source**: Exact article title and publisher name
   - **URL & Date**: Source link and release date
   - **Type**: Infection Chain, Attack Chain, Intrusion Timeline, etc.
   - **Named Stages**: Chronological list of stages (Stage 1 to Impact)
   - **Detailed Stages**: Specific technical breakdown, tools/loaders/RATs, procedures, C2/infrastructure
   - **MITRE ATT&CK Mappings**: Tactic, technique ID, technique name, procedure description
   - **Notable IOCs**: Hashes, C2 IPs/domains, paths, Sigma/detection rules
   - **Emulation Utility**: Concrete step-by-step emulation engineering guide
4. Return pure JSON matching the `AdversaryEmulationReport` schema or collection list.
