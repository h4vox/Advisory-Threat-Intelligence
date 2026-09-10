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
When requested to discover sources or collect $N$ resources:
1. Perform dynamic, live web searches across the internet targeting authoritative threat research hubs:
   - **Intrusion Timelines & Threat Research Labs**: Security vendor labs, incident response publications, and DFIR blogs reporting real intrusion sequences.
   - **CERT & Government Advisories**: National cybersecurity agencies, cloud provider intelligence centers, and critical infrastructure advisories.
   - **Adversary Emulation & Simulation Repositories**: Threat-informed defense centers, atomic test repositories, and community purple-team playbooks.
   - **Domain Crawl Root Discovery**: When discovering sources for recursive crawlers, extract the root domain or section root wildcard pattern (`https://<domain>/<section>/*`) stripped of individual article endpoints.
2. Formulate dynamic search queries combining:
   - `"infection chain"`, `"attack chain"`, `"intrusion chain"`, `"attack flow"`, `"multi-stage"`, `"stage 1"`, `"stage 2"`, `"technical analysis"`, `"MITRE ATT&CK"`, `"adversary emulation"`, `"adversary simulation"`, `"campaign analysis"`, `"intrusion timeline"`, active malware families, and APT actor names.
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
