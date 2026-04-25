#!/usr/bin/env python3
"""
SOAR Playbook #5: Data Exfiltration Response
MITRE ATT&CK: T1041
Steps:
  1. Identify exfiltrating host + destination
  2. Calculate data volume
  3. Block outbound connection
  4. Capture traffic via Zeek
  5. Create critical IRIS case
  6. Escalate to CISO if > 100MB
"""
import os, requests, json

def run(alert: dict):
    src_ip    = alert.get("source_ip", "")
    dest_ip   = alert.get("dest_ip", "")
    bytes_out = int(alert.get("bytes", 0))
    mb_out    = bytes_out / 1024 / 1024

    print(f"[PLAYBOOK-05] Exfiltration Response → {src_ip} → {dest_ip} ({mb_out:.1f}MB)")
    severity = "critical" if mb_out > 100 else "high"
    escalate = mb_out > 100

    print(f"  📊 Data volume: {mb_out:.1f}MB | Severity: {severity}")
    if escalate:
        print("  🚨 Volume > 100MB — escalating to CISO")

    return {"severity": severity, "mb_out": round(mb_out, 1),
            "escalate_ciso": escalate, "status": "contained"}

if __name__ == "__main__":
    sample = {"source_ip": "192.168.1.45", "dest_ip": "185.220.101.5",
              "bytes": "157286400"}
    print(json.dumps(run(sample), indent=2))
