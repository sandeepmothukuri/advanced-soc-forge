"""
FastAPI endpoint — receives webhook alerts from ElastAlert2/StackStorm
and dispatches them to the appropriate CrewAI SOC mission.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
from ai_agents.crews import run_mission
import logging
import asyncio
import uuid
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SOC AI Agent API",
    description="CrewAI-powered autonomous SOC agents for threat analysis, incident response, and threat hunting",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store (use Redis in production)
jobs: Dict[str, Dict] = {}


class AlertRequest(BaseModel):
    alert_type: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    mitre_technique: Optional[str] = None
    severity: Optional[str] = "medium"
    raw_alert: Optional[Dict[str, Any]] = {}
    mission: Optional[str] = "alert_triage"  # alert_triage | incident_response | full_soc


class HuntRequest(BaseModel):
    hypothesis: str
    target_hosts: Optional[list] = []
    time_window_hours: Optional[int] = 24
    tactic_focus: Optional[str] = "all"


class DetectionRequest(BaseModel):
    tactic: Optional[str] = "all"
    recent_incident: Optional[str] = ""


def _run_mission_bg(job_id: str, mission: str, context: dict, hypothesis: str = ""):
    """Background task runner — updates job store when done."""
    jobs[job_id]["status"] = "running"
    jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
    try:
        result = run_mission(mission, context, hypothesis)
        jobs[job_id]["status"] = "completed"
        jobs[job_id]["result"] = result
        jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)
        logger.exception(f"Mission {mission} failed for job {job_id}")


@app.get("/health")
def health():
    return {"status": "healthy", "agents": 4, "version": "2.0.0"}


@app.post("/analyze/alert")
async def analyze_alert(req: AlertRequest, background_tasks: BackgroundTasks):
    """
    Dispatch an alert to the AI agent crew for analysis.
    Returns a job ID for async polling.
    """
    job_id = str(uuid.uuid4())[:8]
    context = {
        "alert_type": req.alert_type,
        "source_ip": req.source_ip,
        "dest_ip": req.dest_ip,
        "hostname": req.hostname,
        "mitre_technique": req.mitre_technique,
        "severity": req.severity,
        **req.raw_alert,
    }
    jobs[job_id] = {"status": "queued", "mission": req.mission, "queued_at": datetime.utcnow().isoformat()}
    background_tasks.add_task(_run_mission_bg, job_id, req.mission, context)
    return {"job_id": job_id, "mission": req.mission, "status": "queued",
            "poll_url": f"/jobs/{job_id}"}


@app.post("/hunt")
async def start_hunt(req: HuntRequest, background_tasks: BackgroundTasks):
    """Launch a proactive threat hunt."""
    job_id = str(uuid.uuid4())[:8]
    context = {
        "target_hosts": req.target_hosts,
        "time_window_hours": req.time_window_hours,
        "tactic_focus": req.tactic_focus,
    }
    jobs[job_id] = {"status": "queued", "mission": "threat_hunt", "queued_at": datetime.utcnow().isoformat()}
    background_tasks.add_task(_run_mission_bg, job_id, "threat_hunt", context, req.hypothesis)
    return {"job_id": job_id, "hypothesis": req.hypothesis, "status": "queued"}


@app.post("/detection/gaps")
async def detection_gaps(req: DetectionRequest, background_tasks: BackgroundTasks):
    """Analyze detection coverage gaps and generate new rules."""
    job_id = str(uuid.uuid4())[:8]
    context = {"tactic": req.tactic, "recent_incident": req.recent_incident}
    jobs[job_id] = {"status": "queued", "mission": "detection_gap", "queued_at": datetime.utcnow().isoformat()}
    background_tasks.add_task(_run_mission_bg, job_id, "detection_gap", context)
    return {"job_id": job_id, "tactic": req.tactic, "status": "queued"}


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    """Poll job status and result."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/jobs")
def list_jobs():
    """List all jobs with status summary."""
    return {
        "total": len(jobs),
        "jobs": [{"id": k, "mission": v.get("mission"), "status": v.get("status"),
                  "queued_at": v.get("queued_at")} for k, v in jobs.items()],
    }


# ElastAlert2 webhook receiver
@app.post("/webhook/elastalert")
async def elastalert_webhook(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    """Receive alerts directly from ElastAlert2 and auto-triage."""
    rule_name = payload.get("rule_name", "unknown")
    # Determine mission type based on severity
    severity = payload.get("severity", "medium")
    mission = "full_soc" if severity in ("critical", "high") else "alert_triage"

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {"status": "queued", "mission": mission, "source": "elastalert2",
                    "rule": rule_name, "queued_at": datetime.utcnow().isoformat()}
    background_tasks.add_task(_run_mission_bg, job_id, mission, payload)
    logger.info(f"ElastAlert2 webhook received: rule={rule_name} mission={mission} job={job_id}")
    return {"received": True, "job_id": job_id, "mission": mission}
