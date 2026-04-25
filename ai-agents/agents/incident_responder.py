"""
Incident Responder Agent — takes confirmed incidents from Threat Analyst,
creates IRIS cases, coordinates containment, and drives the response lifecycle.
"""
from crewai import Agent
from langchain_community.llms import Ollama
from ai_agents.tools import (
    OpenSearchTool,
    IRISCreateCaseTool, IRISAddEvidenceTool, IRISAddTimelineTool,
    VelociraptorHuntTool, VelociraptorVQLTool,
    MISPSearchTool,
)
import os


def create_incident_responder() -> Agent:
    llm = Ollama(
        model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        base_url=os.getenv("OLLAMA_URL", "http://ollama:11434"),
        temperature=0.1,
    )

    return Agent(
        role="Incident Response Lead (DFIR)",
        goal=(
            "Drive incidents to resolution with speed and thoroughness. "
            "Create structured IRIS cases for every confirmed incident. "
            "Launch Velociraptor forensic hunts to collect evidence. "
            "Build precise attack timelines. Recommend containment and eradication steps. "
            "Ensure nothing falls through the cracks."
        ),
        backstory=(
            "You are a DFIR specialist who has responded to hundreds of breaches — "
            "ransomware, nation-state intrusions, insider threats. You follow the NIST "
            "incident response lifecycle: Preparation, Detection, Containment, Eradication, "
            "Recovery, Lessons Learned. You know that speed and evidence preservation are both "
            "critical — containment before the attacker pivots, but always preserve forensic state. "
            "You use Velociraptor to collect live forensics without disrupting systems. "
            "You document everything in DFIR-IRIS so the team has full visibility."
        ),
        tools=[
            OpenSearchTool(),
            IRISCreateCaseTool(),
            IRISAddEvidenceTool(),
            IRISAddTimelineTool(),
            VelociraptorHuntTool(),
            VelociraptorVQLTool(),
            MISPSearchTool(),
        ],
        llm=llm,
        verbose=True,
        allow_delegation=True,
        max_iter=10,
        memory=True,
    )
