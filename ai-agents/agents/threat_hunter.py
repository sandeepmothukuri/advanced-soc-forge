"""
Threat Hunter Agent — proactive hunt for attacker dwell time, living-off-the-land binaries,
lateral movement, and persistence mechanisms across the environment.
"""
from crewai import Agent
from langchain_community.llms import Ollama
from ai_agents.tools import (
    OpenSearchTool, OpenSearchStatsTool,
    VelociraptorHuntTool, VelociraptorVQLTool,
    MISPSearchTool,
)
import os


# Hypothesis-driven hunt VQL templates
HUNT_HYPOTHESES = {
    "lolbins": (
        "Living-off-the-land binary abuse — attackers using built-in Windows tools "
        "(certutil, regsvr32, mshta, wmic, rundll32) to evade detection"
    ),
    "beacon_timing": (
        "C2 beaconing — regular outbound connections to external IPs at fixed intervals "
        "suggesting command-and-control activity"
    ),
    "credential_access": (
        "Credential access — LSASS access patterns, SAM database reads, "
        "Kerberoasting activity in Zeek Kerberos logs"
    ),
    "lateral_movement": (
        "Lateral movement — unusual SMB connections, WMI remote execution, "
        "PsExec artifacts, pass-the-hash indicators"
    ),
    "persistence": (
        "Persistence mechanisms — new scheduled tasks, registry Run key modifications, "
        "new services, startup folder additions"
    ),
    "data_staging": (
        "Data staging for exfiltration — large files written to temp directories, "
        "unusual archive creation (7z, zip, rar) on sensitive file paths"
    ),
    "responder_activity": (
        "LLMNR/NBT-NS poisoning — Responder-style credential capture, "
        "anomalous LLMNR responses on port 5355"
    ),
}


def create_threat_hunter() -> Agent:
    llm = Ollama(
        model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        base_url=os.getenv("OLLAMA_URL", "http://ollama:11434"),
        temperature=0.2,
    )

    hypotheses_str = "\n".join(f"- {k}: {v}" for k, v in HUNT_HYPOTHESES.items())

    return Agent(
        role="Threat Hunter (SOC L3 / Purple Team)",
        goal=(
            "Proactively find attackers hiding in the environment before alerts fire. "
            "Execute hypothesis-driven hunts across endpoints and network. "
            "Identify anomalies that bypass rule-based detections. "
            "Surface attacker dwell time and lateral movement paths."
        ),
        backstory=(
            f"You are an elite threat hunter with purple team experience. You don't wait for alerts — "
            f"you proactively hypothesize attacker behavior and hunt for evidence. "
            f"You know the most common attacker patterns:\n{hypotheses_str}\n\n"
            f"You use OpenSearch for log-based hunting and Velociraptor for live endpoint forensics. "
            f"You think like an attacker: if I were APT28 trying to move laterally, what traces "
            f"would I leave in Zeek conn logs? In Windows event logs? In memory? "
            f"You document every hunt with clear hypothesis, methodology, findings, and recommendations."
        ),
        tools=[
            OpenSearchTool(),
            OpenSearchStatsTool(),
            VelociraptorHuntTool(),
            VelociraptorVQLTool(),
            MISPSearchTool(),
        ],
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=12,
        memory=True,
    )
