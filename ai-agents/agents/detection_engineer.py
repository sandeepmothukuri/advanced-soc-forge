"""
Detection Engineer Agent — analyzes missed detections, gaps in coverage,
and generates new Sigma rules and ElastAlert2 rules to fill them.
"""
from crewai import Agent
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from langchain_community.llms import Ollama
from ai_agents.tools import OpenSearchTool, OpenSearchStatsTool
import os
import json
import yaml
import uuid
from datetime import datetime


# ── Custom tool: Generate Sigma Rule ───────────────────────────────────────────
class SigmaRuleInput(BaseModel):
    title: str = Field(..., description="Rule title")
    description: str = Field(..., description="What the rule detects")
    mitre_technique: str = Field(..., description="MITRE ATT&CK technique ID, e.g. T1059.001")
    mitre_tactic: str = Field(..., description="MITRE tactic, e.g. Execution")
    log_source_product: str = Field(default="windows", description="Log source: windows, linux, zeek, suricata")
    log_source_category: str = Field(default="process_creation", description="Category: process_creation, network_connection, etc.")
    detection_keywords: list[str] = Field(..., description="Key strings, field values, or patterns to detect")
    false_positive_notes: str = Field(default="Legitimate admin activity", description="Known false positive sources")


class SigmaRuleGeneratorTool(BaseTool):
    name: str = "generate_sigma_rule"
    description: str = (
        "Generate a production-ready Sigma detection rule in YAML format based on "
        "observed attacker behavior, MITRE ATT&CK technique, and detection logic. "
        "Returns the YAML rule text that can be added to the detection-rules library."
    )
    args_schema: type[BaseModel] = SigmaRuleInput

    def _run(self, title: str, description: str, mitre_technique: str,
             mitre_tactic: str, log_source_product: str, log_source_category: str,
             detection_keywords: list, false_positive_notes: str) -> str:
        rule_id = str(uuid.uuid4())
        date_str = datetime.utcnow().strftime("%Y/%m/%d")

        # Build detection block dynamically from keywords
        keywords_yaml = "\n            - '|contains': '" + "'\n            - '|contains': '".join(detection_keywords) + "'"

        rule = {
            "title": title,
            "id": rule_id,
            "status": "experimental",
            "description": description,
            "references": [f"https://attack.mitre.org/techniques/{mitre_technique.replace('.', '/')}/"],
            "author": "SOC-AI-Detection-Engineer",
            "date": date_str,
            "tags": [
                f"attack.{mitre_tactic.lower().replace(' ', '_')}",
                f"attack.{mitre_technique.lower()}",
            ],
            "logsource": {
                "product": log_source_product,
                "category": log_source_category,
            },
            "detection": {
                "selection": {
                    "CommandLine|contains": detection_keywords,
                },
                "condition": "selection",
            },
            "fields": ["CommandLine", "ParentImage", "Image", "User"],
            "falsepositives": [false_positive_notes],
            "level": "high",
        }
        return json.dumps({
            "sigma_yaml": yaml.dump(rule, default_flow_style=False, allow_unicode=True),
            "rule_id": rule_id,
            "file_suggestion": f"detection-rules/sigma/{mitre_tactic.lower()}/{mitre_technique}_{title.lower().replace(' ', '_')}.yml",
        }, indent=2)


# ── Custom tool: Coverage Gap Analyzer ────────────────────────────────────────
class CoverageGapInput(BaseModel):
    tactic: str = Field(default="all", description="MITRE tactic to check coverage for, or 'all'")


class CoverageGapTool(BaseTool):
    name: str = "analyze_detection_coverage"
    description: str = (
        "Analyze which MITRE ATT&CK techniques have detection rules vs. which are blind spots. "
        "Returns a gap report showing covered techniques, missing ones, and priority recommendations."
    )
    args_schema: type[BaseModel] = CoverageGapInput

    def _run(self, tactic: str = "all") -> str:
        # Existing coverage from our detection library
        covered = {
            "T1059.001": "ElastAlert + Sigma (Execution)",
            "T1059.003": "Sigma (Execution - cmd.exe)",
            "T1047":     "Sigma (Execution - WMI)",
            "T1053.005": "Sigma (Persistence - Scheduled Task)",
            "T1547.001": "Sigma (Persistence - Registry Run)",
            "T1003.001": "ElastAlert + Sigma (Credential Access - LSASS)",
            "T1110":     "ElastAlert + Sigma (Credential Access - Brute Force)",
            "T1557.001": "ElastAlert + Sigma (Credential Access - LLMNR)",
            "T1021.002": "Sigma (Lateral Movement - SMB)",
            "T1550.002": "Sigma (Lateral Movement - Pass-the-Hash)",
            "T1562.001": "Sigma (Defense Evasion - Defender Disable)",
            "T1046":     "Suricata + Sigma (Discovery - Network Scan)",
            "T1041":     "ElastAlert + Sigma (Exfiltration - C2)",
            "T1071.004": "Sigma (C2 - DNS Tunneling)",
        }

        # Common high-priority gaps
        gaps = {
            "T1055":     "Process Injection — no injection detection rules",
            "T1078":     "Valid Accounts — no impossible travel or off-hours login rules",
            "T1190":     "Exploit Public-Facing App — no web exploit patterns",
            "T1566.001": "Spearphishing Attachment — no email attachment rules",
            "T1486":     "Data Encrypted for Impact — no ransomware file extension rules",
            "T1070.004": "File Deletion — no log clearing detection",
            "T1027":     "Obfuscated Files — no obfuscation pattern detection",
            "T1018":     "Remote System Discovery — no net view / nmap detection",
            "T1136.001": "Local Account Creation — no net user /add detection",
            "T1087":     "Account Discovery — no whoami/net user patterns",
        }

        if tactic != "all":
            tactic_map = {
                "execution": ["T1059.001", "T1059.003", "T1047", "T1055", "T1190"],
                "persistence": ["T1053.005", "T1547.001", "T1078", "T1136.001"],
                "credential-access": ["T1003.001", "T1110", "T1557.001"],
                "lateral-movement": ["T1021.002", "T1550.002"],
                "defense-evasion": ["T1562.001", "T1070.004", "T1027"],
                "discovery": ["T1046", "T1018", "T1087"],
                "exfiltration": ["T1041"],
                "command-and-control": ["T1071.004"],
            }
            relevant = tactic_map.get(tactic.lower(), list(covered.keys()) + list(gaps.keys()))
            covered_filtered = {k: v for k, v in covered.items() if k in relevant}
            gaps_filtered = {k: v for k, v in gaps.items() if k in relevant}
        else:
            covered_filtered = covered
            gaps_filtered = gaps

        return json.dumps({
            "coverage_score": f"{len(covered_filtered)}/{len(covered_filtered)+len(gaps_filtered)} techniques",
            "covered_techniques": covered_filtered,
            "detection_gaps": gaps_filtered,
            "priority_recommendations": list(gaps_filtered.keys())[:3],
        }, indent=2)


def create_detection_engineer() -> Agent:
    llm = Ollama(
        model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        base_url=os.getenv("OLLAMA_URL", "http://ollama:11434"),
        temperature=0.1,
    )

    return Agent(
        role="Detection Engineer",
        goal=(
            "Continuously improve the SOC's detection capability. "
            "Identify gaps in MITRE ATT&CK coverage. "
            "Generate new Sigma and ElastAlert2 rules for uncovered techniques. "
            "Tune existing rules to reduce false positives. "
            "Ensure every red team exercise produces new detections."
        ),
        backstory=(
            "You are a detection engineering specialist who turns attacker TTPs into "
            "reliable, low-noise detections. You think in terms of MITRE ATT&CK coverage "
            "and the detection pyramid: behavioral detections > artifact-based > indicator-based. "
            "After every incident or red team exercise, you analyze what was missed and why. "
            "You write Sigma rules using the vendor-neutral format so they work across SIEM platforms. "
            "You validate rules against real logs in OpenSearch before deploying. "
            "Your mantra: 'A missed detection today is a breach tomorrow.'"
        ),
        tools=[
            OpenSearchTool(),
            OpenSearchStatsTool(),
            SigmaRuleGeneratorTool(),
            CoverageGapTool(),
        ],
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=8,
        memory=True,
    )
