#!/usr/bin/env python3
"""StackStorm action: create DFIR-IRIS incident case."""
import os
import json
import requests
import urllib3
urllib3.disable_warnings()
from st2common.runners.base_action import Action


class CreateIncidentAction(Action):
    def run(self, title, description, severity=3, source_ip="",
            hostname="", mitre_technique="", trigger_ai=True):
        iris_url = os.getenv("IRIS_URL", "http://dfir-iris:8000")
        iris_key = os.getenv("IRIS_API_KEY", "")
        headers = {"Authorization": f"Bearer {iris_key}", "Content-Type": "application/json"}

        payload = {
            "case_name": title,
            "case_description": (
                f"{description}\n\n"
                f"Source IP: {source_ip or 'N/A'}\n"
                f"Hostname: {hostname or 'N/A'}\n"
                f"MITRE Technique: {mitre_technique or 'N/A'}"
            ),
            "case_customer": 1,
            "case_severity_id": severity,
            "case_classification_id": 1,
            "custom_attributes": {},
        }
        try:
            r = requests.post(f"{iris_url}/api/v1/cases/add",
                              json=payload, headers=headers, verify=False, timeout=15)
            r.raise_for_status()
            case_id = r.json().get("data", {}).get("case_id")

            # Optionally trigger AI agent
            if trigger_ai and case_id:
                try:
                    ai_payload = {
                        "alert_type": mitre_technique or title,
                        "source_ip": source_ip,
                        "hostname": hostname,
                        "severity": ["", "low", "low", "medium", "high", "critical"][severity],
                        "mission": "incident_response",
                    }
                    requests.post("http://crewai-soc:8000/analyze/alert",
                                  json=ai_payload, timeout=5)
                except Exception:
                    pass

            return (True, {"case_id": case_id, "url": f"{iris_url}/case?cid={case_id}"})
        except Exception as e:
            return (False, {"error": str(e)})
