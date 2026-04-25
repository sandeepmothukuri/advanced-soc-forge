#!/usr/bin/env python3
"""
Real-time WebSocket Alert Streamer
Polls OpenSearch every 5 seconds, pushes new alerts to all connected dashboard clients.
Used by the SOC Overview and all HTML dashboards for live alert feeds.
"""
import asyncio
import websockets
import json
import os
import logging
from datetime import datetime, timedelta, timezone
from opensearchpy import OpenSearch, OpenSearchException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WS-STREAMER] %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)

# Config from env
OS_HOST   = os.getenv("OPENSEARCH_HOST", "opensearch-node1")
OS_PORT   = int(os.getenv("OPENSEARCH_PORT", "9200"))
OS_USER   = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS   = os.getenv("OPENSEARCH_PASSWORD", "AdminPassword123!")
WS_HOST   = os.getenv("WS_HOST", "0.0.0.0")
WS_PORT   = int(os.getenv("WS_PORT", "8765"))
POLL_SECS = int(os.getenv("POLL_INTERVAL_SECS", "5"))

# Connected client registry
CLIENTS: set = set()

# Watermark — only push events newer than this
last_seen_ts: str = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()


def get_os_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": OS_HOST, "port": OS_PORT}],
        http_auth=(OS_USER, OS_PASS),
        use_ssl=False,
        verify_certs=False,
        retry_on_timeout=True,
    )


def fetch_new_alerts(client: OpenSearch) -> list[dict]:
    """Poll OpenSearch for alerts newer than last_seen_ts."""
    global last_seen_ts
    body = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gt": last_seen_ts}}},
                ],
                "should": [
                    {"exists": {"field": "mitre_technique"}},
                    {"term": {"event_type.keyword": "alert"}},
                    {"term": {"log_type.keyword": "suricata"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": 50,
    }
    try:
        resp = client.search(index="soc-logs-*", body=body)
        hits = resp["hits"]["hits"]
        alerts = []
        for h in hits:
            s = h["_source"]
            alerts.append({
                "id": h["_id"],
                "timestamp": s.get("@timestamp"),
                "type": s.get("event_type") or s.get("log_type") or "event",
                "mitre_tactic": s.get("mitre_tactic", ""),
                "mitre_technique": s.get("mitre_technique", ""),
                "severity": s.get("severity") or (s.get("alert") or {}).get("severity", "medium"),
                "src_ip": s.get("src_ip") or (s.get("source") or {}).get("ip", ""),
                "dest_ip": s.get("dest_ip") or (s.get("destination") or {}).get("ip", ""),
                "hostname": s.get("hostname") or (s.get("host") or {}).get("name", ""),
                "message": s.get("message") or (s.get("alert") or {}).get("signature", ""),
                "sensor": s.get("sensor_type", "unknown"),
            })
        if alerts:
            last_seen_ts = alerts[-1]["timestamp"]
            log.info(f"Fetched {len(alerts)} new alerts")
        return alerts
    except OpenSearchException as e:
        log.warning(f"OpenSearch poll error: {e}")
        return []


async def broadcast(message: str):
    """Send message to all connected WebSocket clients."""
    if not CLIENTS:
        return
    dead = set()
    for ws in CLIENTS.copy():
        try:
            await ws.send(message)
        except websockets.exceptions.ConnectionClosed:
            dead.add(ws)
    CLIENTS -= dead


async def poll_loop():
    """Background task: poll OpenSearch and broadcast new alerts."""
    client = None
    while True:
        await asyncio.sleep(POLL_SECS)
        try:
            if client is None:
                client = get_os_client()
            alerts = fetch_new_alerts(client)
            if alerts:
                payload = json.dumps({
                    "type": "alerts",
                    "count": len(alerts),
                    "alerts": alerts,
                    "server_time": datetime.now(timezone.utc).isoformat(),
                })
                await broadcast(payload)
        except Exception as e:
            log.error(f"Poll loop error: {e}")
            client = None  # force reconnect


async def heartbeat_loop():
    """Send heartbeat every 30s so dashboards know the stream is alive."""
    while True:
        await asyncio.sleep(30)
        hb = json.dumps({
            "type": "heartbeat",
            "server_time": datetime.now(timezone.utc).isoformat(),
            "connected_clients": len(CLIENTS),
        })
        await broadcast(hb)


async def handler(websocket):
    """Handle new WebSocket connection."""
    client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
    log.info(f"Client connected: {client_ip} | total: {len(CLIENTS)+1}")
    CLIENTS.add(websocket)

    # Send welcome + stats burst
    try:
        os_client = get_os_client()
        # Last 1h stats
        resp = os_client.count(index="soc-logs-*", body={
            "query": {"range": {"@timestamp": {"gte": "now-1h"}}}
        })
        welcome = json.dumps({
            "type": "welcome",
            "message": "Connected to SOC Alert Stream",
            "events_last_1h": resp.get("count", 0),
            "server_time": datetime.now(timezone.utc).isoformat(),
        })
        await websocket.send(welcome)
    except Exception:
        pass

    try:
        async for _ in websocket:
            pass  # clients can send pings; we don't process commands
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        CLIENTS.discard(websocket)
        log.info(f"Client disconnected: {client_ip} | total: {len(CLIENTS)}")


async def main():
    log.info(f"SOC WebSocket Streamer starting on {WS_HOST}:{WS_PORT}")
    log.info(f"OpenSearch: {OS_HOST}:{OS_PORT} | Poll interval: {POLL_SECS}s")

    async with websockets.serve(handler, WS_HOST, WS_PORT):
        await asyncio.gather(
            poll_loop(),
            heartbeat_loop(),
        )


if __name__ == "__main__":
    asyncio.run(main())
