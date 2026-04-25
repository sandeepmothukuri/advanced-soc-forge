#!/usr/bin/env python3
"""
GCP Security Command Center → SOC Lab OpenSearch
Subscribes to a Pub/Sub topic fed by SCC findings and forwards to OpenSearch.

Setup:
  1. GCP Console → Security → Security Command Center → Settings
  2. Continuous Exports → Add Export → Pub/Sub
  3. Topic: projects/YOUR_PROJECT/topics/scc-findings
  4. Subscription: scc-soc-lab
  5. Run: python3 gcp-scc-pubsub.py
"""
import json
import os
import logging
from google.cloud import pubsub_v1
from opensearchpy import OpenSearch
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

PROJECT_ID    = os.getenv("GCP_PROJECT_ID", "your-project-id")
SUBSCRIPTION  = os.getenv("GCP_SCC_SUBSCRIPTION", "scc-soc-lab")
OS_HOST       = os.getenv("OPENSEARCH_HOST", "localhost")
OS_PORT       = int(os.getenv("OPENSEARCH_PORT", "9200"))
OS_USER       = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS       = os.getenv("OPENSEARCH_PASSWORD", "AdminPassword123!")

MITRE_MAP = {
    "INITIAL_ACCESS":          ("T1078.004", "initial-access"),
    "PRIVILEGE_ESCALATION":    ("T1548", "privilege-escalation"),
    "DEFENSE_EVASION":         ("T1562", "defense-evasion"),
    "CREDENTIAL_ACCESS":       ("T1552", "credential-access"),
    "DISCOVERY":               ("T1580", "discovery"),
    "LATERAL_MOVEMENT":        ("T1021.007", "lateral-movement"),
    "EXFILTRATION":            ("T1537", "exfiltration"),
    "MALWARE":                 ("T1204", "execution"),
    "VULNERABILITY":           ("T1190", "initial-access"),
}

os_client = OpenSearch(
    hosts=[{"host": OS_HOST, "port": OS_PORT}],
    http_auth=(OS_USER, OS_PASS),
    use_ssl=False,
    verify_certs=False,
)


def process_finding(message: pubsub_v1.subscriber.message.Message):
    try:
        data = json.loads(message.data.decode("utf-8"))
        finding = data.get("finding", {})
        category = finding.get("category", "UNKNOWN")
        mitre = MITRE_MAP.get(category, ("", ""))

        doc = {
            "@timestamp":      finding.get("createTime", datetime.now(timezone.utc).isoformat()),
            "log_source":      "gcp_scc",
            "sensor_type":     "cloud",
            "cloud_provider":  "gcp",
            "title":           finding.get("category"),
            "severity":        finding.get("severity", "MEDIUM").lower(),
            "state":           finding.get("state"),
            "resource":        data.get("resource", {}).get("name", ""),
            "resource_type":   data.get("resource", {}).get("type", ""),
            "project":         finding.get("parent", ""),
            "mitre_technique": mitre[0],
            "mitre_tactic":    mitre[1],
            "message":         f"GCP SCC: {category} on {data.get('resource',{}).get('name','')}",
            "raw":             finding,
        }

        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        os_client.index(index=f"soc-logs-gcp-{today}", body=doc)
        log.info(f"Indexed GCP SCC finding: {category} severity={doc['severity']}")
        message.ack()
    except Exception as e:
        log.error(f"Failed to process SCC finding: {e}")
        message.nack()


def main():
    subscriber = pubsub_v1.SubscriberClient()
    sub_path   = subscriber.subscription_path(PROJECT_ID, SUBSCRIPTION)
    log.info(f"Listening to GCP SCC findings: {sub_path}")
    log.info(f"Forwarding to OpenSearch: {OS_HOST}:{OS_PORT}")

    future = subscriber.subscribe(sub_path, callback=process_finding)
    try:
        future.result()
    except KeyboardInterrupt:
        future.cancel()
        log.info("Shutting down GCP SCC subscriber")


if __name__ == "__main__":
    main()
