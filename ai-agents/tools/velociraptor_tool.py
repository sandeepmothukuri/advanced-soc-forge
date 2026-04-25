"""
Velociraptor Tool — launch live endpoint forensics hunts and collect artifacts.
"""
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import os
import json
import requests
import urllib3

urllib3.disable_warnings()


VR_BASE = lambda: os.getenv("VELOCIRAPTOR_URL", "http://velociraptor:8889")
VR_API  = lambda: os.getenv("VELOCIRAPTOR_API_KEY", "")


HUNT_ARTIFACTS = {
    "process_list":    "Windows.System.Pslist",
    "network":         "Windows.Network.NetstatEnriched",
    "evidence":        "Windows.Analysis.EvidenceOf.Execution",
    "prefetch":        "Windows.Forensics.Prefetch",
    "scheduled_tasks": "Windows.System.ScheduledTasks",
    "services":        "Windows.System.Services",
    "registry_run":    "Windows.Registry.Sysinternals.Autoruns",
    "yara_memory":     "Windows.Memory.Acquisition",
    "browser_history": "Windows.Forensics.BrowserHistory",
    "usb_history":     "Windows.Forensics.USB",
    "event_logs":      "Windows.EventLogs.Evtx",
    "lsass_handles":   "Windows.System.HandleDuplication",
    "dns_cache":       "Windows.Network.DNS",
    # Linux artifacts
    "linux_processes": "Linux.Sys.Pslist",
    "linux_network":   "Linux.Network.Netstat",
    "linux_bash":      "Linux.Sys.BashHistory",
    "linux_cron":      "Linux.Sys.Crontab",
}


class VelociraptorHuntInput(BaseModel):
    hostname: str = Field(..., description="Target hostname or IP to hunt on")
    artifact: str = Field(..., description=(
        "Artifact key or full Velociraptor artifact name. "
        "Keys: process_list, network, evidence, prefetch, scheduled_tasks, "
        "services, registry_run, yara_memory, event_logs, lsass_handles, dns_cache, "
        "linux_processes, linux_network, linux_bash, linux_cron"
    ))
    parameters: dict = Field(default={}, description="Optional artifact parameters as key-value pairs")


class VelociraptorHuntTool(BaseTool):
    name: str = "velociraptor_hunt"
    description: str = (
        "Launch a live forensics hunt on a specific endpoint using Velociraptor. "
        "Collects forensic artifacts: running processes, network connections, execution evidence, "
        "prefetch files, scheduled tasks, registry autoruns, memory dumps, event logs. "
        "Returns hunt ID and initial collection status."
    )
    args_schema: type[BaseModel] = VelociraptorHuntInput

    def _run(self, hostname: str, artifact: str, parameters: dict = {}) -> str:
        # Resolve friendly key to full artifact name
        artifact_name = HUNT_ARTIFACTS.get(artifact, artifact)

        payload = {
            "artifacts": [artifact_name],
            "condition": f"Host.Fqdn =~ '{hostname}'",
            "parameters": {"env": [{"key": k, "value": v} for k, v in parameters.items()]},
        }
        try:
            r = requests.post(f"{VR_BASE()}/api/v1/CreateHunt",
                              json=payload,
                              headers={"Authorization": f"Bearer {VR_API()}"},
                              verify=False, timeout=20)
            r.raise_for_status()
            data = r.json()
            hunt_id = data.get("hunt_id", "unknown")
            return json.dumps({
                "status": "hunt_launched",
                "hunt_id": hunt_id,
                "artifact": artifact_name,
                "target": hostname,
                "collect_url": f"{VR_BASE()}/app/hunts/{hunt_id}",
            })
        except Exception as e:
            # Return simulated response for lab/offline use
            return json.dumps({
                "status": "simulated",
                "hunt_id": f"H.{hash(hostname+artifact) % 999999:06d}",
                "artifact": artifact_name,
                "target": hostname,
                "note": f"Velociraptor offline or error: {str(e)}",
            })


class VelociraptorQueryInput(BaseModel):
    vql: str = Field(..., description="VQL (Velociraptor Query Language) query to execute")
    client_id: str = Field(default="", description="Specific client ID, or empty for server-side VQL")


class VelociraptorVQLTool(BaseTool):
    name: str = "velociraptor_vql"
    description: str = (
        "Execute a raw VQL (Velociraptor Query Language) query for advanced forensics. "
        "Examples: 'SELECT * FROM pslist() WHERE Name =~ \"mimikatz\"', "
        "'SELECT * FROM netstat() WHERE Laddr.Port = 4444'. "
        "Use for targeted, hypothesis-driven forensic investigation."
    )
    args_schema: type[BaseModel] = VelociraptorQueryInput

    def _run(self, vql: str, client_id: str = "") -> str:
        payload = {"query": [{"vql": vql}]}
        if client_id:
            payload["client_id"] = client_id
        try:
            r = requests.post(f"{VR_BASE()}/api/v1/Query",
                              json=payload,
                              headers={"Authorization": f"Bearer {VR_API()}"},
                              verify=False, timeout=20)
            r.raise_for_status()
            return json.dumps(r.json())
        except Exception as e:
            return json.dumps({"error": str(e), "vql": vql})
