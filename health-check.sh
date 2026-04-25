#!/usr/bin/env bash
# =============================================================================
# Advanced SOC Lab v2.0 — Health Check
# Validates all services and reports status.
# =============================================================================
set -euo pipefail

C_RESET='\033[0m'; C_BOLD='\033[1m'
C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'; C_DIM='\033[2m'

PASS=0; FAIL=0; WARN=0

pass() { echo -e "  ${C_GREEN}✔${C_RESET}  ${C_BOLD}$1${C_RESET} — $2"; ((PASS++)); }
fail() { echo -e "  ${C_RED}✗${C_RESET}  ${C_BOLD}$1${C_RESET} — $2"; ((FAIL++)); }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET}  ${C_BOLD}$1${C_RESET} — $2"; ((WARN++)); }

http_check() {
  local name="$1" url="$2" expected="${3:-200}"
  local code
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
  if [[ "$code" == "$expected" || "$code" == "200" || "$code" == "302" || "$code" == "301" ]]; then
    pass "$name" "HTTP $code — $url"
  else
    fail "$name" "HTTP $code (expected $expected) — $url"
  fi
}

container_check() {
  local name="$1" container="$2"
  local status
  status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
  if [[ "$status" == "running" ]]; then
    pass "$name" "container running"
  else
    fail "$name" "container status: $status"
  fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "\n${C_BOLD}${C_CYAN}  Advanced SOC Lab v2.0 — Health Check${C_RESET}"
echo -e "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')\n"

# ── Load .env ─────────────────────────────────────────────────────────────────
OPENSEARCH_PASSWORD=""
if [[ -f .env ]]; then
  OPENSEARCH_PASSWORD=$(grep '^OPENSEARCH_PASSWORD=' .env | cut -d= -f2)
fi

# ── Services ──────────────────────────────────────────────────────────────────
echo -e "  ${C_BOLD}Core Infrastructure${C_RESET}"

# OpenSearch
if [[ -n "$OPENSEARCH_PASSWORD" ]]; then
  STATUS=$(curl -sk -u "admin:${OPENSEARCH_PASSWORD}" \
    http://localhost:9200/_cluster/health 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "error")
  DOC_COUNT=$(curl -sk -u "admin:${OPENSEARCH_PASSWORD}" \
    "http://localhost:9200/soc-logs-*/_count" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "?")
  if [[ "$STATUS" == "green" || "$STATUS" == "yellow" ]]; then
    pass "OpenSearch" "cluster:${STATUS} · ${DOC_COUNT} documents"
  else
    fail "OpenSearch" "cluster:${STATUS}"
  fi
else
  http_check "OpenSearch" "http://localhost:9200" "401"
fi

container_check "OpenSearch Node 1" "opensearch-node1"
container_check "OpenSearch Node 2" "opensearch-node2"
http_check      "OpenSearch Dashboards" "http://localhost:5601"
container_check "Vector Pipeline" "vector"

echo
echo -e "  ${C_BOLD}Security Tools${C_RESET}"
http_check      "DFIR-IRIS"    "http://localhost:4460"
http_check      "MISP"         "http://localhost:4000"
http_check      "Velociraptor" "http://localhost:8889"
http_check      "StackStorm"   "http://localhost:9000"
container_check "ElastAlert2"  "elastalert2"

echo
echo -e "  ${C_BOLD}Attack Simulation & AI${C_RESET}"
http_check      "MITRE Caldera" "http://localhost:8888"
http_check      "AI Agents API" "http://localhost:8000/health"
http_check      "Ollama LLM"    "http://localhost:11434"
container_check "WebSocket Streamer" "ws-streamer"

echo
echo -e "  ${C_BOLD}Red Team (optional — requires --profile redteam)${C_RESET}"
RESP_STATUS=$(docker inspect --format='{{.State.Status}}' responder 2>/dev/null || echo "not started")
if [[ "$RESP_STATUS" == "running" ]]; then
  pass "Responder" "container running"
else
  warn "Responder" "not running — start with: docker compose --profile redteam up -d"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + WARN))
echo
echo -e "  ${C_BOLD}Results: ${C_GREEN}${PASS} passed${C_RESET}  ${C_RED}${FAIL} failed${C_RESET}  ${C_YELLOW}${WARN} warnings${C_RESET}  (${TOTAL} checks)"
echo

if [[ $FAIL -gt 0 ]]; then
  echo -e "  ${C_YELLOW}Common fixes:${C_RESET}"
  echo -e "  ${C_DIM}OpenSearch not responding:${C_RESET}  sysctl -w vm.max_map_count=262144"
  echo -e "  ${C_DIM}Service not running:${C_RESET}        docker compose up -d <service-name>"
  echo -e "  ${C_DIM}View logs:${C_RESET}                  docker compose logs -f <service-name>"
  echo
  exit 1
else
  echo -e "  ${C_GREEN}${C_BOLD}All critical services healthy.${C_RESET}"
  echo
fi
