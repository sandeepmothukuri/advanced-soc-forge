"""
OpenSearch Tool — query the SOC SIEM for alerts, events, and threat data.
Used by all 4 CrewAI agents.
"""
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from opensearchpy import OpenSearch
from datetime import datetime, timedelta
import os
import json


class OpenSearchQueryInput(BaseModel):
    query: str = Field(..., description="Lucene/KQL query string, e.g. 'event_type:alert AND severity:high'")
    index: str = Field(default="soc-logs-*", description="Index pattern to search")
    hours_back: int = Field(default=24, description="Look-back window in hours")
    size: int = Field(default=20, description="Max results to return")


class OpenSearchTool(BaseTool):
    name: str = "opensearch_query"
    description: str = (
        "Search the SOC SIEM (OpenSearch) for security alerts, events, Zeek logs, "
        "Suricata alerts, Windows Sysmon events, and audit logs. "
        "Returns JSON hits with MITRE ATT&CK tags, source IPs, destinations, and timestamps."
    )
    args_schema: type[BaseModel] = OpenSearchQueryInput

    def _run(self, query: str, index: str = "soc-logs-*",
             hours_back: int = 24, size: int = 20) -> str:
        host = os.getenv("OPENSEARCH_HOST", "opensearch-node1")
        port = int(os.getenv("OPENSEARCH_PORT", "9200"))
        user = os.getenv("OPENSEARCH_USER", "admin")
        pwd  = os.getenv("OPENSEARCH_PASSWORD", "AdminPassword123!")

        client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_auth=(user, pwd),
            use_ssl=False,
            verify_certs=False,
        )

        since = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat() + "Z"
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query}}],
                    "filter": [{"range": {"@timestamp": {"gte": since}}}],
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size,
        }

        try:
            resp = client.search(index=index, body=body)
            hits = resp["hits"]["hits"]
            results = []
            for h in hits:
                src = h["_source"]
                results.append({
                    "timestamp": src.get("@timestamp"),
                    "mitre_tactic": src.get("mitre_tactic"),
                    "mitre_technique": src.get("mitre_technique"),
                    "event_type": src.get("event_type"),
                    "source_ip": src.get("src_ip") or src.get("source", {}).get("ip"),
                    "dest_ip": src.get("dest_ip") or src.get("destination", {}).get("ip"),
                    "hostname": src.get("hostname") or src.get("host", {}).get("name"),
                    "process": src.get("process", {}).get("name") or src.get("Image"),
                    "message": src.get("message") or src.get("alert", {}).get("signature"),
                    "severity": src.get("severity") or src.get("alert", {}).get("severity"),
                })
            summary = {
                "total_hits": resp["hits"]["total"]["value"],
                "returned": len(results),
                "query": query,
                "window_hours": hours_back,
                "results": results,
            }
            return json.dumps(summary, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e), "query": query})


class OpenSearchStatsInput(BaseModel):
    hours_back: int = Field(default=1, description="Stats window in hours")


class OpenSearchStatsTool(BaseTool):
    name: str = "opensearch_stats"
    description: str = (
        "Get real-time SOC statistics: alert counts by severity, top source IPs, "
        "top MITRE techniques, and active incidents in the last N hours."
    )
    args_schema: type[BaseModel] = OpenSearchStatsInput

    def _run(self, hours_back: int = 1) -> str:
        host = os.getenv("OPENSEARCH_HOST", "opensearch-node1")
        port = int(os.getenv("OPENSEARCH_PORT", "9200"))
        user = os.getenv("OPENSEARCH_USER", "admin")
        pwd  = os.getenv("OPENSEARCH_PASSWORD", "AdminPassword123!")

        client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_auth=(user, pwd),
            use_ssl=False,
            verify_certs=False,
        )

        since = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat() + "Z"
        body = {
            "query": {"range": {"@timestamp": {"gte": since}}},
            "aggs": {
                "by_severity": {"terms": {"field": "severity.keyword", "size": 5}},
                "by_mitre": {"terms": {"field": "mitre_technique.keyword", "size": 10}},
                "by_src_ip": {"terms": {"field": "src_ip.keyword", "size": 10}},
                "by_sensor": {"terms": {"field": "sensor_type.keyword", "size": 5}},
            },
            "size": 0,
        }
        try:
            resp = client.search(index="soc-logs-*", body=body)
            aggs = resp.get("aggregations", {})
            return json.dumps({
                "total_events": resp["hits"]["total"]["value"],
                "window_hours": hours_back,
                "by_severity": {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])},
                "top_mitre_techniques": {b["key"]: b["doc_count"] for b in aggs.get("by_mitre", {}).get("buckets", [])},
                "top_source_ips": {b["key"]: b["doc_count"] for b in aggs.get("by_src_ip", {}).get("buckets", [])},
                "by_sensor": {b["key"]: b["doc_count"] for b in aggs.get("by_sensor", {}).get("buckets", [])},
            }, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})
