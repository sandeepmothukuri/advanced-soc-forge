#!/usr/bin/env bash
# SOC Lab Linux Agent Installer — Auditd + Filebeat
# Usage: sudo ./install-agent.sh [VECTOR_HOST]
# Example: sudo ./install-agent.sh 192.168.10.30

set -euo pipefail

VECTOR_HOST="${1:-${SOC_VECTOR_HOST:-192.168.10.30}}"
SOC_DIR="/opt/soc-lab"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "${CYAN}[SOC-AGENT]${NC} $1"; }
ok()  { echo -e "${GREEN}  ✅ $1${NC}"; }
err() { echo -e "${RED}  ❌ $1${NC}"; exit 1; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo $0 $@"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   SOC Lab Linux Agent Installer v2.0                ║${NC}"
echo -e "${CYAN}║   Auditd + Filebeat → Vector @ $VECTOR_HOST       ${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

mkdir -p "$SOC_DIR"

# Detect distro
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt-get"
    INSTALL="apt-get install -y -q"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
    INSTALL="yum install -y -q"
else
    err "Unsupported package manager"
fi

# ── Step 1: Auditd ───────────────────────────────────────────────────────────
log "[1/4] Installing auditd..."
$INSTALL auditd audispd-plugins 2>/dev/null || $INSTALL audit 2>/dev/null
systemctl enable auditd --now 2>/dev/null || service auditd start

# Deploy SOC rules
curl -fsSL "http://$VECTOR_HOST:8686/configs/auditd.rules" -o /etc/audit/rules.d/soc-lab.rules 2>/dev/null || {
    log "Config server unreachable — deploying embedded minimal rules"
    cat > /etc/audit/rules.d/soc-lab.rules << 'EOF'
-D
-b 8192
-a always,exit -F arch=b64 -S execve -k execution
-w /etc/passwd -p wa -k identity_change
-w /etc/sudoers -p wa -k privilege_escalation
-a always,exit -F path=/etc/shadow -F perm=r -k credential_access
EOF
}
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/soc-lab.rules
ok "Auditd installed and rules loaded"

# ── Step 2: Filebeat ─────────────────────────────────────────────────────────
log "[2/4] Installing Filebeat..."
if ! command -v filebeat &>/dev/null; then
    if [[ "$PKG_MGR" == "apt-get" ]]; then
        curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
        echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
            > /etc/apt/sources.list.d/elastic.list
        apt-get update -q
        $INSTALL filebeat
    else
        rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
        cat > /etc/yum.repos.d/elastic.repo << 'EOF'
[elasticsearch]
name=Elasticsearch repository
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
EOF
        $INSTALL filebeat
    fi
fi
ok "Filebeat installed"

# ── Step 3: Deploy Filebeat config ───────────────────────────────────────────
log "[3/4] Configuring Filebeat..."
cat > /etc/filebeat/filebeat.yml << FBEOF
filebeat.inputs:
  - type: log
    paths: [/var/log/audit/audit.log]
    fields: {log_source: linux_auditd, sensor_type: endpoint}
    fields_under_root: true
  - type: log
    paths: [/var/log/auth.log, /var/log/secure]
    fields: {log_source: linux_auth, sensor_type: endpoint}
    fields_under_root: true
  - type: log
    paths: [/var/log/syslog, /var/log/messages]
    fields: {log_source: linux_syslog, sensor_type: endpoint}
    fields_under_root: true

processors:
  - add_host_metadata: ~

output.logstash:
  hosts: ["$VECTOR_HOST:5044"]

logging.level: warning
FBEOF

systemctl enable filebeat --now
ok "Filebeat configured and started"

# ── Step 4: Validate ─────────────────────────────────────────────────────────
log "[4/4] Validating..."
sleep 3
AUDITD_OK=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
FILEBEAT_OK=$(systemctl is-active filebeat 2>/dev/null || echo "inactive")

echo ""
echo -e "${CYAN}══════════════════ DEPLOYMENT SUMMARY ══════════════════${NC}"
echo -e " Host:     $(hostname -f)"
echo -e " Vector:   $VECTOR_HOST:5044"
echo -e " Auditd:   $([ "$AUDITD_OK" = "active" ] && echo -e "${GREEN}✅ Running${NC}" || echo -e "${RED}❌ $AUDITD_OK${NC}")"
echo -e " Filebeat: $([ "$FILEBEAT_OK" = "active" ] && echo -e "${GREEN}✅ Running${NC}" || echo -e "${RED}❌ $FILEBEAT_OK${NC}")"
echo -e "${CYAN}═════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}🔍 Verify: OpenSearch → soc-logs-* | host.name: $(hostname)${NC}"
