"""
Schema definition and Pydantic models for Adversary Emulation Intelligence Agent.
Defines universally resilient models for multi-stage attack chains, MITRE ATT&CK mappings, IOCs, and emulation plans.
"""

from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field, model_validator
import json
import re

def sanitize_filename(name: str, max_length: int = 120) -> str:
    """Sanitize title and source into a clean, safe filename across Windows and Linux."""
    sanitized = re.sub(r'[\\/*?:"<>|]', '', name)
    sanitized = re.sub(r'[\r\n\t]+', ' ', sanitized)
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
    stage_number: int = Field(default=1, description="Chronological sequence number")
    stage_name: str = Field(default="Stage", description="Name of the stage")
    description: Union[str, List[Any], Dict[str, Any]] = Field(default="", description="Technical analysis")
    key_techniques: List[Union[str, Dict[str, Any]]] = Field(default_factory=list, description="Techniques employed")
    tools_and_artifacts: Union[List[Any], Dict[str, Any], str] = Field(default_factory=list, description="Tools/Malware")
    procedures: Union[str, List[Any], Dict[str, Any]] = Field(default="", description="Granular procedures/commands")
    infrastructure_c2: Optional[Union[str, List[Any], Dict[str, Any]]] = Field(default=None, description="C2 Details")

    @model_validator(mode="before")
    @classmethod
    def normalize_stage(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Map alternate field names
            if "description" not in data:
                data["description"] = data.get("technical_analysis") or data.get("summary") or data.get("details") or ""
            if "procedures" not in data:
                data["procedures"] = data.get("procedures_and_commands") or data.get("commands") or data.get("actions") or data.get("description") or ""
            if "tools_and_artifacts" not in data:
                data["tools_and_artifacts"] = data.get("tools_and_malware") or data.get("tools") or []
            if "infrastructure_c2" not in data:
                data["infrastructure_c2"] = data.get("infrastructure") or data.get("c2") or None
            if "key_techniques" not in data:
                data["key_techniques"] = data.get("mitre_techniques") or []
        return data

class MitreAttackMapping(BaseModel):
    tactic: str = Field(default="Enterprise ATT&CK", description="MITRE Tactic")
    technique_id: str = Field(default="T0000", description="Technique ID")
    technique_name: str = Field(default="Unknown", description="Technique Name")
    procedure_description: Union[str, List[Any], Dict[str, Any]] = Field(default="", description="Procedure notes")

    @model_validator(mode="before")
    @classmethod
    def normalize_mapping(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "technique_id" not in data:
                data["technique_id"] = data.get("id") or data.get("techniqueId") or "T0000"
            if "technique_name" not in data:
                data["technique_name"] = data.get("name") or data.get("techniqueName") or "Technique"
            if "procedure_description" not in data:
                data["procedure_description"] = data.get("procedure") or data.get("description") or ""
        return data

class NotableIOCs(BaseModel):
    file_hashes: List[Any] = Field(default_factory=list)
    domains: List[Any] = Field(default_factory=list)
    ip_addresses: List[Any] = Field(default_factory=list)
    c2_servers: List[Any] = Field(default_factory=list)
    file_paths_or_registry: List[Any] = Field(default_factory=list)
    detection_rules: List[Any] = Field(default_factory=list)

class AdversaryEmulationReport(BaseModel):
    title: str = Field(default="Untitled Threat Report")
    source: str = Field(default="Threat Intelligence Research")
    url: str = Field(default="")
    date: str = Field(default="")
    type: str = Field(default="Infection Chain")
    threat_actor_or_malware: Union[List[Any], Dict[str, Any], str] = Field(default_factory=list)
    named_stages: List[str] = Field(default_factory=list)
    stages: List[AttackStage] = Field(default_factory=list)
    attack_flow_diagram: Optional[Union[str, Dict[str, Any]]] = None
    mitre_attack_mappings: List[MitreAttackMapping] = Field(default_factory=list)
    notable_iocs: Union[NotableIOCs, Dict[str, Any], List[Any]] = Field(default_factory=dict)
    summary: Union[str, List[Any], Dict[str, Any]] = Field(default="")
    emulation_utility: Union[str, Dict[str, Any], List[Any]] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def normalize_report(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("named_stages") and "stages" in data and isinstance(data["stages"], list):
                data["named_stages"] = [
                    s.get("stage_name", f"Stage {i+1}") if isinstance(s, dict) else f"Stage {i+1}"
                    for i, s in enumerate(data["stages"])
                ]
            if not data.get("summary"):
                data["summary"] = data.get("executive_summary") or data.get("description") or ""
        return data

    def get_filename(self) -> str:
        """Returns the appropriate filename based on source and title."""
        return make_filename_from_title(title=self.title, source=self.source)

class AdversaryEmulationCollection(BaseModel):
    collection_title: str = Field(default="Adversary Emulation Intelligence Batch")
    total_count: int = Field(default=0)
    reports: List[AdversaryEmulationReport] = Field(default_factory=list)

def get_json_schema() -> Dict[str, Any]:
    return AdversaryEmulationReport.model_json_schema()

def get_collection_json_schema() -> Dict[str, Any]:
    return AdversaryEmulationCollection.model_json_schema()

# --- Source Hunter Models ---

class ThreatSourceItem(BaseModel):
    title: str = Field(default="Untitled Threat Source", description="Title of the research paper or advisory")
    source: str = Field(default="Threat Intelligence Research", description="Publisher or threat intelligence organization")
    url: str = Field(default="", description="Direct URL to the technical report")
    date: str = Field(default="", description="Publication date or timeline (YYYY-MM-DD or formatted string)")
    threat_actor_or_malware: List[str] = Field(default_factory=list, description="Threat groups or malware families covered")
    attack_chain_type: str = Field(default="Infection Chain", description="Type of attack chain or intrusion flow")
    summary: str = Field(default="", description="Executive summary of the attack chain and technical scope")
    key_stages: List[str] = Field(default_factory=list, description="Sequential stages in the attack flow")
    relevance_for_emulation: str = Field(default="", description="Why this source is valuable for adversary emulation/simulation")

    @model_validator(mode="before")
    @classmethod
    def normalize_source_item(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "threat_actor_or_malware" in data:
                if isinstance(data["threat_actor_or_malware"], str):
                    data["threat_actor_or_malware"] = [data["threat_actor_or_malware"]]
                elif isinstance(data["threat_actor_or_malware"], dict):
                    vals = []
                    for v in data["threat_actor_or_malware"].values():
                        if isinstance(v, list):
                            vals.extend(str(x) for x in v)
                        elif v:
                            vals.append(str(v))
                    data["threat_actor_or_malware"] = vals
            if "key_stages" in data and isinstance(data["key_stages"], dict):
                data["key_stages"] = [f"{k}: {v}" for k, v in data["key_stages"].items()]
        return data

    def get_filename(self) -> str:
        return make_filename_from_title(title=self.title, source=self.source)

class ThreatSourceCollection(BaseModel):
    total_sources: int = Field(default=0, description="Total number of sources discovered")
    sources: List[ThreatSourceItem] = Field(default_factory=list, description="Discovered technical sources")

def get_sources_json_schema() -> Dict[str, Any]:
    return ThreatSourceCollection.model_json_schema()
