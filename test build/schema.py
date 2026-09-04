"""
Schema definition and Pydantic models for Adversary Emulation Intelligence Agent.
Defines resilient models for multi-stage attack chains, MITRE ATT&CK mappings, IOCs, and emulation plans.
"""

from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field
import json
import re

def sanitize_filename(name: str, max_length: int = 120) -> str:
    """Sanitize title and source into a clean, safe filename across Windows and Linux."""
    # Remove characters invalid in Windows/Linux filenames: \ / : * ? " < > |
    sanitized = re.sub(r'[\\/*?:"<>|]', '', name)
    # Replace newlines and tabs with spaces
    sanitized = re.sub(r'[\r\n\t]+', ' ', sanitized)
    # Collapse multiple spaces
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length].rstrip()
    return sanitized

def make_filename_from_title(title: str, source: Optional[str] = None) -> str:
    """Creates a standardized filename matching '<Source> - <Title>.json' or '<Title>.json'."""
    clean_title = sanitize_filename(title, max_length=90)
    if source:
        clean_source = sanitize_filename(source, max_length=40)
        return f"{clean_source} - {clean_title}.json"
    return f"{clean_title}.json"

class AttackStage(BaseModel):
    stage_number: int = Field(..., description="Chronological sequence number of the stage, starting from 1")
    stage_name: str = Field(..., description="Name of the stage (e.g. Stage 1: Initial Access / Malicious LNK)")
    description: str = Field(..., description="Technical breakdown and analysis of actions observed in this stage")
    key_techniques: List[str] = Field(default_factory=list, description="Primary attack techniques employed in this stage")
    tools_and_artifacts: Union[List[str], Dict[str, Any], str] = Field(
        default_factory=list, 
        description="Loaders, malware, RATs, native utilities (LOLBins), scripts, or tools used"
    )
    procedures: Union[str, List[str]] = Field(
        ..., 
        description="Granular procedure execution details (commands run, registry modified, etc.)"
    )
    infrastructure_c2: Optional[Union[str, List[str]]] = Field(
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
    threat_actor_or_malware: Union[List[str], Dict[str, Any], str] = Field(
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
    notable_iocs: Union[NotableIOCs, Dict[str, Any]] = Field(
        default_factory=NotableIOCs, 
        description="Structured Indicators of Compromise (hashes, IPs, domains, paths)"
    )
    summary: str = Field(..., description="Concise narrative summary of the intrusion from initial access to final objective")
    emulation_utility: Union[str, Dict[str, Any]] = Field(
        ..., 
        description="Strategic analysis on how this chain can be converted into an adversary emulation plan, Atomic Red Team tests, or Caldera abilities"
    )

    def get_filename(self) -> str:
        """Returns the appropriate filename based on source and title."""
        return make_filename_from_title(title=self.title, source=self.source)

class AdversaryEmulationCollection(BaseModel):
    collection_title: str = Field(
        default="Adversary Emulation Intelligence Batch",
        description="Batch collection title"
    )
    total_count: int = Field(..., description="Total number of structured reports in this batch")
    reports: List[AdversaryEmulationReport] = Field(..., description="List of structured emulation reports")

def get_json_schema() -> Dict[str, Any]:
    """Returns the JSON Schema dictionary suitable for enforcing output via agy CLI or API."""
    return AdversaryEmulationReport.model_json_schema()

def get_collection_json_schema() -> Dict[str, Any]:
    """Returns the JSON Schema for batch/multiple reports."""
    return AdversaryEmulationCollection.model_json_schema()

if __name__ == "__main__":
    print(json.dumps(get_json_schema(), indent=2))
