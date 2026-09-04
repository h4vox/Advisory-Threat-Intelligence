"""
Schema definition and Pydantic models for Adversary Emulation Intelligence Agent.
Defines models for multi-stage attack chains, MITRE ATT&CK mappings, IOCs, and emulation plans.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import json

class AttackStage(BaseModel):
    stage_number: int = Field(..., description="Chronological sequence number of the stage, starting from 1")
    stage_name: str = Field(..., description="Name of the stage (e.g. Stage 1: Initial Access / Malicious LNK)")
    description: str = Field(..., description="Technical breakdown and analysis of actions observed in this stage")
    key_techniques: List[str] = Field(default_factory=list, description="Primary attack techniques employed in this stage")
    tools_and_artifacts: List[str] = Field(
        default_factory=list, 
        description="Loaders, malware, RATs, native utilities (LOLBins), scripts, or tools used"
    )
    procedures: str = Field(..., description="Granular procedure execution details (commands run, registry modified, etc.)")
    infrastructure_c2: Optional[str] = Field(
        default=None, 
        description="Associated IP, domain, protocol, port, user-agent, or beaconing profile if relevant"
    )

class MitreAttackMapping(BaseModel):
    tactic: str = Field(..., description="MITRE ATT&CK Tactic (e.g. TA0001 - Initial Access)")
    technique_id: str = Field(..., description="MITRE ATT&CK Technique ID (e.g. T1566.001)")
    technique_name: str = Field(..., description="MITRE ATT&CK Technique Name (e.g. Spearphishing Attachment)")
    procedure_description: str = Field(..., description="Specific procedure or implementation observed in the campaign")

class NotableIOCs(BaseModel):
    file_hashes: List[str] = Field(default_factory=list, description="SHA256, MD5, SHA1 hashes of payloads or artifacts")
    domains: List[str] = Field(default_factory=list, description="Associated C2 or staging domain names")
    ip_addresses: List[str] = Field(default_factory=list, description="Associated IP addresses")
    c2_servers: List[str] = Field(default_factory=list, description="C2 URLs, ports, or listener configs")
    file_paths_or_registry: List[str] = Field(
        default_factory=list, 
        description="Notable dropper paths, persistence keys, or artifact filesystem locations"
    )
    detection_rules: List[str] = Field(
        default_factory=list, 
        description="References to YARA, Sigma, or Snort detection rules"
    )

class AdversaryEmulationReport(BaseModel):
    title: str = Field(..., description="Title of the research report or threat intelligence analysis")
    source: str = Field(..., description="Source organization or blog (e.g. The DFIR Report, Unit 42, SentinelOne Labs)")
    url: str = Field(..., description="Original URL or citation for the intelligence")
    date: str = Field(..., description="Publication date or intrusion discovery date (YYYY-MM-DD or formatted string)")
    type: str = Field(
        ..., 
        description="Type of resource (Infection Chain, Attack Chain, Intrusion Timeline, Technique Deep Dive, Emulation Playbook, Simulation Scenario)"
    )
    threat_actor_or_malware: List[str] = Field(
        default_factory=list, 
        description="Named threat groups, APTs, ransomware affiliates, or malware families involved"
    )
    named_stages: List[str] = Field(
        ..., 
        description="List of stage names in order (e.g. ['Stage 1: Phishing & Malicious ISO', 'Stage 2: Loader Execution'])"
    )
    stages: List[AttackStage] = Field(
        ..., 
        description="Detailed technical breakdown of each attack stage"
    )
    attack_flow_diagram: Optional[str] = Field(
        default=None, 
        description="Mermaid diagram or structured ASCII/text diagram illustrating the end-to-end chain"
    )
    mitre_attack_mappings: List[MitreAttackMapping] = Field(
        default_factory=list, 
        description="Granular MITRE ATT&CK tactic, technique, and procedure mappings"
    )
    notable_iocs: NotableIOCs = Field(
        default_factory=NotableIOCs, 
        description="Structured Indicators of Compromise (hashes, IPs, domains, paths)"
    )
    summary: str = Field(..., description="Concise narrative summary of the intrusion from initial access to final objective")
    emulation_utility: str = Field(
        ..., 
        description="Strategic analysis on how this chain can be converted into an adversary emulation plan, Atomic Red Team tests, or Caldera abilities"
    )

def get_json_schema() -> Dict[str, Any]:
    """Returns the JSON Schema dictionary suitable for enforcing output via agy CLI or API."""
    return AdversaryEmulationReport.model_json_schema()

def get_json_schema_string() -> str:
    """Returns the JSON Schema as a formatted string."""
    return json.dumps(get_json_schema(), indent=2)

if __name__ == "__main__":
    print(get_json_schema_string())
