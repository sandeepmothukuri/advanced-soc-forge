#!/usr/bin/env python3
"""StackStorm action: launch Velociraptor forensic hunt."""
import os
import json
import requests
import urllib3
urllib3.disable_warnings()
from st2common.runners.base_action import Action

ARTIFACTS = {
    "process_list": "Windows.System.Pslist",
    "network": "Windows.Network.NetstatEnriched",
    "evidence": "Windows.Analysis.EvidenceOf.Execution",
    "scheduled_tasks": "Windows.System.ScheduledTasks",
    "services": "Windows.System.Services",
    "registry_run": "Windows.Registry.Sysinternals.Autoruns",
    "event_logs": "Windows.EventLogs.Evtx",
    "yara_memory": "Windows.Memory.Acquisition",
    "linux_processes": "Linux.Sys.Pslist",
    "linux_network": "Linux.Network.Netstat",
    "linux_bash": "Linux.Sys.BashHistory",
}

class VelociraptorHuntAction(Action):
    def run(self, hostname, artifact, case_id=0):
        artifact_name = ARTIFACTS.get(artifact, artifact)
        vr_url = os.getenv("VELOCIRAPTOR_URL", "http://velociraptor:8889")
        vr_key = os.getenv("VELOCIRAPTOR_API_KEY", "")
        headers = {"Authorization": f"Bearer {vr_key}"}

        payload = {
            "artifacts": [artifact_name],
            "condition": f"Host.Fqdn =~ '{hostname}'",
        }
        try:
            r = requests.post(f"{vr_url}/api/v1/CreateHunt",
                              json=payload, headers=headers, verify=False, timeout=20)
            hunt_id = r.json().get("hunt_id", "unknown") if r.ok else "failed"
            return (r.ok, {"hunt_id": hunt_id, "artifact": artifact_name,
                           "target": hostname, "case_id": case_id})
        except Exception as e:
            return (False, {"error": str(e)})
