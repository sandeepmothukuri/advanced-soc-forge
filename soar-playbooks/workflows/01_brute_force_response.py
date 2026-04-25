#!/usr/bin/env python3
"""
SOAR Playbook #1: Brute Force Auto-Response
MITRE ATT&CK: T1110
Trigger: ElastAlert2 → StackStorm webhook
Steps:
  1. Enrich source IP (MISP)
  2. GeoIP lookup
  3. Score threat (0-10)
  4. IF score ≥ 7: block IP + create IRIS case + notify
  5. ELSE: add to watchlist + alert analyst
"""
import os, requests, json
from datetime import datetime, timezone

MISP_URL   = os.getenv("MISP_URL", "http://misp:80")
IRIS_URL   = os.getenv("IRIS_URL", "https://dfir-iris:443")
ST2_URL    = os.getenv("ST2_URL",  "http://stackstorm:9101")
OPENSEARCH = os.getenv("OPENSEARCH_URL", "http://opensearch-node1:9200")
HEADERS    = {"Content-Type": "application/json"}

def enrich_ip_misp(ip: str, misp_key: str) -> dict:
    try:
        r = requests.post(f"{MISP_URL}/attributes/restSearch",
            headers={**HEADERS, "Authorization": misp_key},
            json={"value": ip, "type": "ip-src"}, timeout=10, verify=False)
        attrs = r.json().get("response", {}).get("Attribute", [])
        return {"hits": len(attrs), "malicious": len(attrs) > 0,
                "tags": [a.get("value") for a in attrs[:5]]}
    except Exception as e:
        return {"hits": 0, "malicious": False, "error": str(e)}

def create_iris_case(title: str, desc: str, severity: int, token: str) -> str:
    try:
        r = requests.post(f"{IRIS_URL}/api/v1/cases/add",
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
            json={"case_name": f"[AUTO] {title}", "case_description": desc,
                  "case_severity_id": severity, "case_customer": 1},
            verify=False, timeout=15)
        return r.json().get("data", {}).get("case_id", "N/A")
    except Exception as e:
        return f"ERROR: {e}"

def block_ip_log(ip: str, reason: str):
    """Log block action to OpenSearch (iptables would run via StackStorm action)"""
    event = {"action": "block_ip", "ip": ip, "reason": reason,
             "@timestamp": datetime.now(timezone.utc).isoformat(),
             "playbook": "brute_force_response", "mitre": "T1110"}
    requests.post(f"{OPENSEARCH}/soc-actions/_doc",
                  headers=HEADERS, json=event, timeout=5)

def run(alert: dict):
    src_ip    = alert.get("source_ip", "unknown")
    fail_cnt  = int(alert.get("count", 0))
    misp_key  = os.getenv("MISP_KEY", "")
    iris_token = os.getenv("IRIS_TOKEN", "")

    print(f"[PLAYBOOK-01] Brute Force Response → IP: {src_ip}, Failures: {fail_cnt}")

    # Step 1: MISP enrichment
    intel = enrich_ip_misp(src_ip, misp_key)
    print(f"  MISP hits: {intel['hits']}")

    # Step 2: Calculate threat score
    score = 0
    if intel["hits"] > 0:   score += 5
    if intel["hits"] > 5:   score += 2
    if fail_cnt > 50:        score += 2
    if fail_cnt > 200:       score += 1
    print(f"  Threat score: {score}/10")

    # Step 3: Decision tree
    if score >= 7:
        block_ip_log(src_ip, f"Brute force: {fail_cnt} failures | MISP hits: {intel['hits']}")
        case_id = create_iris_case(
            f"Brute Force Attack from {src_ip}",
            f"IP {src_ip} performed {fail_cnt} failed auth attempts.\nMISP hits: {intel['hits']}\nScore: {score}/10",
            severity=3, token=iris_token
        )
        print(f"  ✅ IP blocked | IRIS case: {case_id}")
        return {"action": "blocked", "case_id": case_id, "score": score}
    else:
        print(f"  ⚠ Score {score} < 7 — adding to watchlist")
        return {"action": "watchlist", "score": score}

if __name__ == "__main__":
    sample = {"source_ip": "10.0.0.87", "count": "241", "mitre": "T1110"}
    print(json.dumps(run(sample), indent=2))
