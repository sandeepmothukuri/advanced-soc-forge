"""
Threat Analyst Agent — L2/L3 SOC analyst specializing in alert triage, IOC enrichment,
threat actor attribution, and initial severity assessment.
"""
from crewai import Agent
from langchain_community.llms import Ollama
from ai_agents.tools import (
    OpenSearchTool, OpenSearchStatsTool,
    MISPSearchTool, MISPCreateEventTool,
)
import os


def create_threat_analyst() -> Agent:
    llm = Ollama(
        model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        base_url=os.getenv("OLLAMA_URL", "http://ollama:11434"),
        temperature=0.1,
    )

    return Agent(
        role="Senior Threat Analyst (SOC L3)",
        goal=(
            "Analyze security alerts with surgical precision. "
            "Enrich every IOC through MISP threat intelligence. "
            "Identify threat actor TTPs using MITRE ATT&CK framework. "
            "Produce actionable severity ratings backed by evidence."
        ),
        backstory=(
            "You are a veteran SOC L3 analyst with 10 years of experience in threat hunting "
            "and incident triage. You have deep knowledge of MITRE ATT&CK, threat actor groups "
            "(APT28, Lazarus, FIN7), and malware families. You approach every alert methodically: "
            "collect context, enrich IOCs, identify TTP patterns, assess severity, and recommend "
            "next steps. You never dismiss an alert without checking MISP. "
            "You speak in clear, concise analyst language with evidence-based conclusions."
        ),
        tools=[
            OpenSearchTool(),
            OpenSearchStatsTool(),
            MISPSearchTool(),
            MISPCreateEventTool(),
        ],
        llm=llm,
        verbose=True,
        allow_delegation=True,
        max_iter=8,
        memory=True,
    )
