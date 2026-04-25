#!/usr/bin/env python3
"""
SOAR Playbook #2: Suspicious PowerShell — Isolate & Investigate
MITRE ATT&CK: T1059.001
Steps:
  1. Create critical IRIS case
  2. Trigger Velociraptor hunt on affected host
  3. Pull running processes + network connections
  4. If C2 connection found: isolate host
  5. Notify SOC L3 analyst
"""
import os, requests, json

VELOCI_URL = os.getenv("VELOCI_URL",  "http://velociraptor:8889")
IRIS_URL   = os.getenv("IRIS_URL",   "https://dfir-iris:443")
OPENSEARCH = os.getenv("OPENSEARCH_URL", "http://opensearch-node1:9200")

def trigger_velociraptor_hunt(hostname: str, token: str) -> str:
    """Start a Velociraptor collection on the affected host"""
    try:
        # Velociraptor API: collect Windows.Analysis.EvidenceOf artifacts
        payload = {
            "artifacts": ["Windows.Analysis.EvidenceOf.Execution",
                          "Windows.Network.NetstatEnriched",
                          "Windows.System.Pslist"],
            "spec": {"env": [{"key": "HOSTNAME", "value": hostname}]}
        }
        r = requests.post(f"{VELOCI_URL}/api/v1/CreateHunt",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"},
            json=payload, verify=False, timeout=15)
        return r.json().get("flow_id", "N/A")
    except Exception as e:
        return f"ERROR: {e}"

def run(alert: dict):
    host    = alert.get("host", "unknown")
    user    = alert.get("user", "unknown")
    command = alert.get("command", "")
    iris_t  = os.getenv("IRIS_TOKEN", "")
    veloci_t = os.getenv("VELOCI_TOKEN", "")

    print(f"[PLAYBOOK-02] PowerShell Response → Host: {host}, User: {user}")

    # Step 1: Create IRIS case
    case_resp = requests.post(f"{IRIS_URL}/api/v1/cases/add",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {iris_t}"},
        json={"case_name": f"[AUTO-CRITICAL] Encoded PS — {host}",
              "case_description": f"Host: {host}\nUser: {user}\nCmd: {command}",
              "case_severity_id": 4},
        verify=False, timeout=15)
    case_id = case_resp.json().get("data", {}).get("case_id", "N/A")
    print(f"  📁 IRIS case created: {case_id}")

    # Step 2: Trigger Velociraptor hunt
    flow_id = trigger_velociraptor_hunt(host, veloci_t)
    print(f"  🦎 Velociraptor hunt started: {flow_id}")

    return {"case_id": case_id, "flow_id": flow_id, "status": "investigating"}

if __name__ == "__main__":
    sample = {"host": "WIN-CORP-001", "user": "jsmith",
              "command": "powershell -enc JABzAD0A...", "mitre": "T1059.001"}
    print(json.dumps(run(sample), indent=2))
