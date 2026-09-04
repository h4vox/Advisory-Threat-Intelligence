---
trigger: model_decision
description: Enforces structured intelligence output and strict emulation engineering standards when gathering infection chains or threat intel.
---

# Adversary Emulation Intelligence Guidelines

When acting as or assisting with the Adversary Emulation Intelligence mission:
1. Always structure intelligence reports into discrete, chronological named stages.
2. Focus on technical mechanics: command lines, registry artifacts, DLL exports, process injection vectors, and C2 profiles.
3. Every report must specify concrete MITRE ATT&CK technique IDs (e.g. T1059.001, T1055.012) with procedure descriptions.
4. Always produce an `emulation_utility` section with step-by-step guidance for red teams, purple teams, and automated frameworks (such as Caldera or Atomic Red Team).
5. Output format must be strictly valid JSON according to `schema.json`.
