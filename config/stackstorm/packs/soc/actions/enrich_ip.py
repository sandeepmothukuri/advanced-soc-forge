#!/usr/bin/env python3
"""StackStorm action: enrich IP via MISP."""
import os
import json
import requests
import urllib3
urllib3.disable_warnings()
from st2common.runners.base_action import Action


class EnrichIPAction(Action):
    def run(self, ip_address, check_misp=True, check_abuseipdb=False):
        result = {"ip": ip_address, "threat_score": 0, "verdict": "UNKNOWN",
                  "tags": [], "sources": []}

        if check_misp:
            try:
                misp_url = os.getenv("MISP_URL", "http://misp:80")
                misp_key = os.getenv("MISP_KEY", "")
                headers = {"Authorization": misp_key, "Accept": "application/json",
                           "Content-Type": "application/json"}
                r = requests.post(f"{misp_url}/attributes/restSearch",
                                  json={"returnFormat": "json", "value": ip_address, "limit": 10},
                                  headers=headers, verify=False, timeout=10)
                if r.ok:
                    attrs = r.json().get("response", {}).get("Attribute", [])
                    if attrs:
                        result["threat_score"] += min(len(attrs) * 2, 10)
                        result["tags"] += [t["name"] for a in attrs for t in a.get("Tag", [])]
                        result["sources"].append("misp")
            except Exception as e:
                self.logger.warning(f"MISP enrichment failed: {e}")

        result["verdict"] = "MALICIOUS" if result["threat_score"] >= 5 else \
                            "SUSPICIOUS" if result["threat_score"] >= 2 else "CLEAN"
        return (True, result)
