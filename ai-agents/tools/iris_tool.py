"""
DFIR-IRIS Tool — create and manage incident cases, add evidence, IOCs, and timeline events.
"""
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import os
import json
import requests
import urllib3

urllib3.disable_warnings()


def _iris_headers():
    return {
        "Authorization": f"Bearer {os.getenv('IRIS_API_KEY', '')}",
        "Content-Type": "application/json",
    }


IRIS_BASE = lambda: os.getenv("IRIS_URL", "http://dfir-iris:8000")


class IRISCreateCaseInput(BaseModel):
    title: str = Field(..., description="Case title, e.g. 'Ransomware on HOST-01'")
    description: str = Field(..., description="Incident description and initial findings")
    severity: int = Field(default=3, description="1=Informational 2=Low 3=Medium 4=High 5=Critical")
    owner: str = Field(default="SOC-AI-Agent", description="Case owner name")
    tags: list[str] = Field(default=[], description="Case tags")


class IRISCreateCaseTool(BaseTool):
    name: str = "iris_create_case"
    description: str = (
        "Create a new incident response case in DFIR-IRIS. Use when a confirmed security incident "
        "requires formal tracking: ransomware, data breach, credential theft, APT activity. "
        "Returns case ID for subsequent evidence and IOC additions."
    )
    args_schema: type[BaseModel] = IRISCreateCaseInput

    def _run(self, title: str, description: str, severity: int = 3,
             owner: str = "SOC-AI-Agent", tags: list = []) -> str:
        payload = {
            "case_name": title,
            "case_description": description,
            "case_customer": 1,
            "case_severity_id": severity,
            "case_classification_id": 1,
            "custom_attributes": {},
        }
        try:
            r = requests.post(f"{IRIS_BASE()}/api/v1/cases/add",
                              json=payload, headers=_iris_headers(), verify=False, timeout=15)
            r.raise_for_status()
            data = r.json()
            case_id = data.get("data", {}).get("case_id")
            return json.dumps({"status": "created", "case_id": case_id,
                               "url": f"{IRIS_BASE()}/case?cid={case_id}"})
        except Exception as e:
            return json.dumps({"error": str(e)})


class IRISAddEvidenceInput(BaseModel):
    case_id: int = Field(..., description="IRIS case ID to attach evidence to")
    filename: str = Field(..., description="Evidence filename or label")
    description: str = Field(..., description="What this evidence shows")
    ioc_value: str = Field(default="", description="IOC value if applicable (IP, hash, domain)")
    ioc_type: str = Field(default="", description="IOC type: ip, domain, md5, sha256")


class IRISAddEvidenceTool(BaseTool):
    name: str = "iris_add_evidence"
    description: str = (
        "Add forensic evidence or IOC to an existing DFIR-IRIS case. "
        "Use after collecting artifacts via Velociraptor or manual collection."
    )
    args_schema: type[BaseModel] = IRISAddEvidenceInput

    def _run(self, case_id: int, filename: str, description: str,
             ioc_value: str = "", ioc_type: str = "") -> str:
        # Add note as evidence
        note_payload = {
            "note_title": filename,
            "note_content": description,
            "custom_attributes": {},
            "cid": case_id,
        }
        try:
            r = requests.post(f"{IRIS_BASE()}/api/v1/case/notes/add",
                              json=note_payload, headers=_iris_headers(),
                              params={"cid": case_id}, verify=False, timeout=15)
            r.raise_for_status()
            result = {"evidence_added": filename, "case_id": case_id}

            # Add IOC if provided
            if ioc_value and ioc_type:
                ioc_payload = {
                    "ioc_value": ioc_value,
                    "ioc_type_id": {"ip": 76, "domain": 6, "md5": 23, "sha256": 24}.get(ioc_type, 1),
                    "ioc_tlp_id": 2,  # TLP:AMBER
                    "ioc_description": description,
                    "custom_attributes": {},
                    "cid": case_id,
                }
                ri = requests.post(f"{IRIS_BASE()}/api/v1/case/ioc/add",
                                   json=ioc_payload, headers=_iris_headers(),
                                   params={"cid": case_id}, verify=False, timeout=15)
                result["ioc_added"] = ioc_value

            return json.dumps(result)
        except Exception as e:
            return json.dumps({"error": str(e)})


class IRISTimelineInput(BaseModel):
    case_id: int = Field(..., description="Case ID")
    title: str = Field(..., description="Timeline event title")
    content: str = Field(..., description="Detailed description of what happened")
    start_time: str = Field(..., description="ISO 8601 datetime, e.g. '2024-01-15T10:30:00'")
    category: str = Field(default="Network", description="Category: Network, Endpoint, User, Malware")


class IRISAddTimelineTool(BaseTool):
    name: str = "iris_add_timeline"
    description: str = (
        "Add a timeline event to a DFIR-IRIS case to reconstruct the attack chain. "
        "Use for each discovered attacker action: initial access, execution, lateral movement, exfiltration."
    )
    args_schema: type[BaseModel] = IRISTimelineInput

    def _run(self, case_id: int, title: str, content: str,
             start_time: str, category: str = "Network") -> str:
        payload = {
            "title": title,
            "content": content,
            "raw_data": "",
            "start_date": start_time,
            "parent_id": None,
            "cid": case_id,
        }
        try:
            r = requests.post(f"{IRIS_BASE()}/api/v1/case/timeline/events/add",
                              json=payload, headers=_iris_headers(),
                              params={"cid": case_id}, verify=False, timeout=15)
            r.raise_for_status()
            return json.dumps({"status": "timeline_event_added", "case_id": case_id, "title": title})
        except Exception as e:
            return json.dumps({"error": str(e)})
