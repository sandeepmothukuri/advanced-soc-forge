"""
SOC Crew — orchestrates all 4 AI agents across different mission types.

Mission types:
  - alert_triage     : Single alert → enrich, assess, recommend
  - incident_response: Confirmed incident → full DFIR lifecycle
  - threat_hunt      : Proactive hypothesis-driven hunt
  - detection_gap    : Analyze coverage gaps, generate new rules
  - full_soc         : All 4 agents working a complex incident
"""
from crewai import Crew, Task, Process
from ai_agents.agents import (
    create_threat_analyst,
    create_incident_responder,
    create_threat_hunter,
    create_detection_engineer,
)
import json
import logging

logger = logging.getLogger(__name__)


# ── Task Builders ──────────────────────────────────────────────────────────────

def _triage_task(agent, context: dict) -> Task:
    return Task(
        description=f"""
Perform a complete Level 3 triage on this security alert:

ALERT CONTEXT:
{json.dumps(context, indent=2)}

Your analysis MUST include:
1. Query OpenSearch for related events (same source IP, same host, last 24h)
2. Check MISP for EVERY IOC (source IP, destination IP, any hashes/domains)
3. Identify the MITRE ATT&CK technique and tactic
4. Map to known threat actor groups if IOCs match
5. Assign severity: CRITICAL/HIGH/MEDIUM/LOW with justification
6. Recommend immediate actions: escalate, investigate, close

Output format:
- Alert Summary
- IOC Enrichment Results (per IOC: CLEAN/MALICIOUS/SUSPICIOUS)
- MITRE Mapping: Tactic → Technique → Sub-technique
- Threat Actor Attribution (if possible)
- Severity: [LEVEL] — [reason]
- Recommended Actions (numbered list)
""",
        agent=agent,
        expected_output="Structured threat analysis report with IOC verdicts, MITRE mapping, severity, and recommended actions",
    )


def _response_task(agent, context: dict, triage_output: str = "") -> Task:
    return Task(
        description=f"""
Lead the incident response for this confirmed security incident:

INCIDENT CONTEXT:
{json.dumps(context, indent=2)}

PRIOR TRIAGE ANALYSIS:
{triage_output or "No prior triage — perform your own initial assessment"}

Your response MUST:
1. Create a formal IRIS incident case with appropriate severity
2. Launch Velociraptor hunts on affected host(s):
   - process_list (what's running)
   - network (active connections)
   - evidence (execution artifacts)
   - scheduled_tasks (persistence check)
3. Add each finding as evidence to the IRIS case
4. Build an attack timeline with timestamps
5. Determine: initial access → execution → persistence → lateral movement → impact
6. Recommend containment steps (isolate host, block IPs, reset credentials)
7. Recommend eradication steps (remove malware, close vulnerability)
8. Recommend recovery steps (restore from backup, validate clean state)

Output: Incident Response Report with IRIS case ID, timeline, and remediation plan
""",
        agent=agent,
        expected_output="Full incident response report: IRIS case ID, forensic findings, attack timeline, and NIST lifecycle remediation plan",
    )


def _hunt_task(agent, hypothesis: str, context: dict = {}) -> Task:
    return Task(
        description=f"""
Execute a proactive threat hunt based on this hypothesis:

HUNT HYPOTHESIS: {hypothesis}

ENVIRONMENT CONTEXT:
{json.dumps(context, indent=2) if context else "Standard SOC lab environment"}

Hunt methodology:
1. State your hypothesis clearly (what attacker behavior you expect to find)
2. Query OpenSearch with at least 3 different search angles
3. Launch at least 2 Velociraptor hunts on relevant endpoints
4. Look for: LOLBINs, anomalous timing patterns, unusual parent-child process trees,
   unexpected network connections, off-hours activity
5. Check MISP for any suspicious indicators found
6. Document: what you searched, what you found, what you ruled out

Output:
- Hypothesis: [your hunt hypothesis]
- Hunt Methodology: searches and hunts executed
- Findings: POSITIVE (attacker found) or NEGATIVE (no evidence)
- Evidence: specific artifacts, logs, timestamps
- Recommendations: new detection rules or remediation actions
""",
        agent=agent,
        expected_output="Threat hunt report: hypothesis, methodology, findings (positive/negative), evidence, and detection recommendations",
    )


def _detection_gap_task(agent, context: dict = {}) -> Task:
    return Task(
        description=f"""
Perform a detection engineering review and generate new rules to fill coverage gaps.

CONTEXT:
{json.dumps(context, indent=2) if context else "Review all MITRE ATT&CK tactics"}

Steps:
1. Run coverage gap analysis for ALL tactics
2. Identify the top 3 highest-priority uncovered techniques
3. For each gap, query OpenSearch to see if the log source data exists
4. Generate a complete Sigma rule for EACH gap technique
5. Note which rules need new log sources vs. existing data

Output format per rule:
- Technique: T[XXXX.XXX] — [Name]
- Gap Risk: Why this matters (what attacker action it would miss)
- Sigma Rule: [complete YAML]
- Log Source Required: [product/category]
- Estimated False Positive Rate: Low/Medium/High
""",
        agent=agent,
        expected_output="Detection gap report with 3+ new Sigma rules in YAML format ready for deployment",
    )


# ── Crew Factory ──────────────────────────────────────────────────────────────

def build_crew(mission: str, context: dict = {}, hypothesis: str = "") -> Crew:
    """
    Build and return a configured CrewAI crew for the given mission type.

    Args:
        mission: One of alert_triage, incident_response, threat_hunt,
                 detection_gap, full_soc
        context: Alert/incident/hunt context data
        hypothesis: For threat_hunt missions — the hunt hypothesis string

    Returns:
        Configured Crew ready to kickoff()
    """
    analyst   = create_threat_analyst()
    responder = create_incident_responder()
    hunter    = create_threat_hunter()
    engineer  = create_detection_engineer()

    if mission == "alert_triage":
        tasks = [_triage_task(analyst, context)]
        agents = [analyst]
        process = Process.sequential

    elif mission == "incident_response":
        triage = _triage_task(analyst, context)
        response = _response_task(responder, context)
        response.context = [triage]
        tasks = [triage, response]
        agents = [analyst, responder]
        process = Process.sequential

    elif mission == "threat_hunt":
        hunt_hyp = hypothesis or context.get("hypothesis", "Generic threat hunt — look for anomalies")
        tasks = [_hunt_task(hunter, hunt_hyp, context)]
        agents = [hunter]
        process = Process.sequential

    elif mission == "detection_gap":
        tasks = [_detection_gap_task(engineer, context)]
        agents = [engineer]
        process = Process.sequential

    elif mission == "full_soc":
        # Full crew: triage → response → hunt → detection improvement
        triage_t   = _triage_task(analyst, context)
        response_t = _response_task(responder, context)
        hunt_hyp   = hypothesis or f"Hunt for related activity after: {context.get('alert_type', 'unknown incident')}"
        hunt_t     = _hunt_task(hunter, hunt_hyp, context)
        detect_t   = _detection_gap_task(engineer, context)

        response_t.context = [triage_t]
        hunt_t.context     = [triage_t, response_t]
        detect_t.context   = [triage_t, hunt_t]

        tasks   = [triage_t, response_t, hunt_t, detect_t]
        agents  = [analyst, responder, hunter, engineer]
        process = Process.sequential

    else:
        raise ValueError(f"Unknown mission type: {mission}. "
                         "Choose: alert_triage, incident_response, threat_hunt, detection_gap, full_soc")

    return Crew(
        agents=agents,
        tasks=tasks,
        process=process,
        verbose=True,
        memory=True,
        embedder={
            "provider": "ollama",
            "config": {
                "model": "nomic-embed-text",
                "base_url": "http://ollama:11434",
            },
        },
    )


def run_mission(mission: str, context: dict = {}, hypothesis: str = "") -> str:
    """Run a SOC mission and return the crew's final output."""
    logger.info(f"Starting SOC mission: {mission} | context keys: {list(context.keys())}")
    crew = build_crew(mission, context, hypothesis)
    result = crew.kickoff()
    logger.info(f"Mission {mission} completed")
    return str(result)
