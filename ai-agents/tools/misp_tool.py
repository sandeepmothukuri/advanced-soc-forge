"""
MISP Tool — query Threat Intelligence Platform for IOCs, events, and attribute enrichment.
"""
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import os
import json
import requests
import urllib3

urllib3.disable_warnings()


class MISPSearchInput(BaseModel):
    value: str = Field(..., description="IOC value to search: IP, domain, hash, URL, email")
    ioc_type: str = Field(default="auto", description="Type: ip-dst, domain, md5, sha256, url, email-src, or 'auto'")


class MISPSearchTool(BaseTool):
    name: str = "misp_search_ioc"
    description: str = (
        "Search MISP threat intelligence platform for an IOC (IP, domain, file hash, URL). "
        "Returns matching threat events, tags, MITRE techniques, and confidence levels. "
        "Use this to enrich any suspicious indicator found in alerts."
    )
    args_schema: type[BaseModel] = MISPSearchInput

    def _run(self, value: str, ioc_type: str = "auto") -> str:
        base = os.getenv("MISP_URL", "http://misp:80")
        key  = os.getenv("MISP_KEY", "")
        headers = {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}

        payload = {"returnFormat": "json", "value": value, "limit": 20, "includeEventTags": True}
        if ioc_type != "auto":
            payload["type"] = ioc_type

        try:
            r = requests.post(f"{base}/attributes/restSearch", json=payload,
                              headers=headers, verify=False, timeout=15)
            r.raise_for_status()
            data = r.json()
            attrs = data.get("response", {}).get("Attribute", [])
            results = []
            for a in attrs:
                results.append({
                    "event_id": a.get("event_id"),
                    "type": a.get("type"),
                    "value": a.get("value"),
                    "category": a.get("category"),
                    "to_ids": a.get("to_ids"),
                    "tags": [t.get("name") for t in a.get("Tag", [])],
                    "timestamp": a.get("timestamp"),
                })
            return json.dumps({
                "ioc": value,
                "matches": len(results),
                "threat_intel": results,
                "verdict": "MALICIOUS" if results else "UNKNOWN",
            }, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e), "ioc": value})


class MISPCreateEventInput(BaseModel):
    title: str = Field(..., description="Event title/description")
    iocs: list[str] = Field(..., description="List of IOC values to attach (IPs, hashes, domains)")
    threat_level: int = Field(default=2, description="1=High, 2=Medium, 3=Low, 4=Undefined")
    tags: list[str] = Field(default=[], description="Tags to apply, e.g. ['tlp:amber', 'mitre-attack:T1059']")


class MISPCreateEventTool(BaseTool):
    name: str = "misp_create_event"
    description: str = (
        "Create a new threat intelligence event in MISP with IOCs extracted during an incident. "
        "This shares the intelligence with the SOC team and enriches future detections."
    )
    args_schema: type[BaseModel] = MISPCreateEventInput

    def _run(self, title: str, iocs: list, threat_level: int = 2, tags: list = []) -> str:
        base = os.getenv("MISP_URL", "http://misp:80")
        key  = os.getenv("MISP_KEY", "")
        headers = {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}

        event_payload = {
            "Event": {
                "info": title,
                "threat_level_id": str(threat_level),
                "analysis": "1",
                "distribution": "0",
                "Attribute": [{"type": "text", "value": ioc, "category": "External analysis"} for ioc in iocs],
            }
        }
        try:
            r = requests.post(f"{base}/events/add", json=event_payload,
                              headers=headers, verify=False, timeout=15)
            r.raise_for_status()
            event = r.json().get("Event", {})
            return json.dumps({"status": "created", "event_id": event.get("id"), "uuid": event.get("uuid")})
        except Exception as e:
            return json.dumps({"error": str(e)})
