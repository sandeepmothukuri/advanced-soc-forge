#!/usr/bin/env bash
# =============================================================================
# Advanced SOC Lab v2.0 — Setup Script
# Deploys all 12 open-source SOC tools via Docker Compose.
# =============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'
C_CYAN='\033[0;36m'
C_DIM='\033[2m'

ok()   { echo -e "${C_GREEN}  ✔${C_RESET}  $*"; }
info() { echo -e "${C_CYAN}  →${C_RESET}  $*"; }
warn() { echo -e "${C_YELLOW}  ⚠${C_RESET}  $*"; }
fail() { echo -e "${C_RED}  ✗${C_RESET}  $*" >&2; exit 1; }
step() { echo -e "\n${C_BOLD}${C_CYAN}── $* ──${C_RESET}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${C_BOLD}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║     Advanced SOC Lab v2.0 — Setup               ║"
echo "  ║     12 tools · 100% free · MITRE ATT&CK v14     ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${C_RESET}"

# ── Preflight checks ──────────────────────────────────────────────────────────
step "Preflight checks"

# Docker
if ! command -v docker &>/dev/null; then
  fail "Docker not found. Install from https://docs.docker.com/get-docker/"
fi
ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

# Docker Compose v2
if ! docker compose version &>/dev/null; then
  fail "Docker Compose v2 not found. Upgrade Docker or install the plugin."
fi
ok "Docker Compose $(docker compose version --short)"

# RAM check
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))
if [[ $TOTAL_RAM_GB -lt 14 ]]; then
  warn "Only ${TOTAL_RAM_GB}GB RAM detected. 16 GB minimum recommended."
  warn "OpenSearch may fail to start. Consider closing other applications."
else
  ok "${TOTAL_RAM_GB}GB RAM available"
fi

# Disk space check
FREE_GB=$(df -BG . | awk 'NR==2 {gsub(/G/,"",$4); print $4}')
if [[ ${FREE_GB:-0} -lt 20 ]]; then
  warn "Low disk space: ${FREE_GB}GB free. 50 GB recommended."
else
  ok "${FREE_GB}GB disk space available"
fi

# ── Environment file ──────────────────────────────────────────────────────────
step "Environment configuration"

if [[ ! -f .env ]]; then
  info "Generating .env from template..."
  cp .env.example .env

  # Auto-generate secure random values
  sed -i "s/OPENSEARCH_PASSWORD=.*/OPENSEARCH_PASSWORD=$(openssl rand -hex 16)/" .env
  sed -i "s/IRIS_SECRET_KEY=.*/IRIS_SECRET_KEY=$(openssl rand -hex 32)/" .env
  sed -i "s/MISP_KEY=.*/MISP_KEY=$(openssl rand -hex 6)/" .env
  sed -i "s/ST2_AUTH_TOKEN=.*/ST2_AUTH_TOKEN=$(openssl rand -hex 20)/" .env

  ok ".env created with generated credentials"
  warn "Review .env and set CALDERA_RED_PASSWORD, CALDERA_BLUE_PASSWORD before use"
else
  ok ".env already exists"
fi

# ── Kernel tuning ─────────────────────────────────────────────────────────────
step "Kernel parameters"

CURRENT_MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [[ $CURRENT_MAP -lt 262144 ]]; then
  info "Setting vm.max_map_count=262144 (required for OpenSearch)"
  sysctl -w vm.max_map_count=262144 >/dev/null
  echo "vm.max_map_count=262144" | tee -a /etc/sysctl.conf >/dev/null 2>&1 || true
  ok "vm.max_map_count=262144"
else
  ok "vm.max_map_count=${CURRENT_MAP} (already sufficient)"
fi

# ── Create data directories ───────────────────────────────────────────────────
step "Data directories"
DIRS=(
  data/opensearch-node1 data/opensearch-node2
  data/misp data/iris data/velociraptor
  data/stackstorm data/caldera logs
)
for d in "${DIRS[@]}"; do
  mkdir -p "$d"
done
ok "Created ${#DIRS[@]} data directories"

# ── Pull images ───────────────────────────────────────────────────────────────
step "Pulling Docker images"
info "This may take several minutes on first run..."
docker compose pull --quiet 2>&1 | grep -E "Pulled|already" | sed 's/^/    /' || true
ok "Images ready"

# ── Stage 1: Core infrastructure ──────────────────────────────────────────────
step "Stage 1/4 — Core infrastructure (OpenSearch, Vector)"
docker compose up -d opensearch-node1 opensearch-node2

info "Waiting for OpenSearch cluster to become healthy..."
for i in $(seq 1 60); do
  STATUS=$(curl -sk -u "admin:$(grep OPENSEARCH_PASSWORD .env | cut -d= -f2)" \
    http://localhost:9200/_cluster/health 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','red'))" 2>/dev/null || echo "red")
  if [[ "$STATUS" == "green" || "$STATUS" == "yellow" ]]; then
    ok "OpenSearch cluster: ${STATUS}"
    break
  fi
  printf "\r  ${C_DIM}  Waiting… ${i}/60s${C_RESET}"
  sleep 1
done
echo

# Apply index template
info "Applying soc-logs index template..."
curl -sk -X PUT \
  -u "admin:$(grep OPENSEARCH_PASSWORD .env | cut -d= -f2)" \
  "http://localhost:9200/_index_template/soc-logs" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["soc-logs-*"],
    "template": {
      "settings": { "number_of_shards": 1, "number_of_replicas": 1 },
      "mappings": {
        "properties": {
          "@timestamp":        { "type": "date" },
          "severity":          { "type": "keyword" },
          "mitre_technique":   { "type": "keyword" },
          "mitre_tactic":      { "type": "keyword" },
          "src_ip":            { "type": "ip" },
          "dst_ip":            { "type": "ip" },
          "rule_name":         { "type": "keyword" },
          "sensor":            { "type": "keyword" },
          "host.name":         { "type": "keyword" }
        }
      }
    }
  }' >/dev/null 2>&1 && ok "Index template applied" || warn "Index template: check manually at http://localhost:9200"

docker compose up -d vector
ok "Vector log pipeline started"

# ── Stage 2: Security tools ────────────────────────────────────────────────────
step "Stage 2/4 — Security tools (MISP, IRIS, Velociraptor)"
docker compose up -d misp iris velociraptor
info "Waiting 20s for services to initialise..."
sleep 20
ok "Security tools started"

# ── Stage 3: SOAR + Detection ─────────────────────────────────────────────────
step "Stage 3/4 — SOAR + Detection (StackStorm, ElastAlert2)"
docker compose up -d stackstorm elastalert2
sleep 15
ok "SOAR + detection engine started"

# ── Stage 4: AI + Simulation ──────────────────────────────────────────────────
step "Stage 4/4 — AI agents + Attack simulation (Ollama, CrewAI, Caldera)"
docker compose up -d ollama
info "Pulling Ollama model llama3.2:3b (first run: ~2 GB download)..."
docker exec ollama ollama pull llama3.2:3b 2>/dev/null || warn "Ollama model pull failed — run manually: docker exec ollama ollama pull llama3.2:3b"

docker compose up -d ai-agents caldera ws-streamer opensearch-dashboards nginx
sleep 10
ok "All services started"

# ── Health check ──────────────────────────────────────────────────────────────
step "Validating deployment"
bash health-check.sh

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo -e "${C_BOLD}${C_GREEN}  SOC Lab v2.0 is ready!${C_RESET}"
echo
echo -e "  ${C_BOLD}Dashboards${C_RESET}"
echo -e "  Portal              ${C_CYAN}dashboards/index.html${C_RESET}"
echo -e "  OpenSearch          ${C_CYAN}http://localhost:5601${C_RESET}"
echo -e "  DFIR-IRIS           ${C_CYAN}http://localhost:4460${C_RESET}"
echo -e "  Caldera             ${C_CYAN}http://localhost:8888${C_RESET}"
echo -e "  Velociraptor        ${C_CYAN}http://localhost:8889${C_RESET}"
echo -e "  MISP                ${C_CYAN}http://localhost:4000${C_RESET}"
echo -e "  AI Agents API Docs  ${C_CYAN}http://localhost:8000/docs${C_RESET}"
echo
echo -e "  ${C_BOLD}Next steps${C_RESET}"
echo -e "  Run attack sim      ${C_DIM}./simulate-attack.sh apt29${C_RESET}"
echo -e "  Check health        ${C_DIM}./health-check.sh${C_RESET}"
echo -e "  Start red team      ${C_DIM}docker compose --profile redteam up -d${C_RESET}"
echo -e "  View logs           ${C_DIM}docker compose logs -f${C_RESET}"
echo
