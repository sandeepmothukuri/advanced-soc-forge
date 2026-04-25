#!/usr/bin/env bash
# =============================================================================
# Advanced SOC Lab v2.0 — Attack Simulation
# Injects realistic events into OpenSearch for SOC analyst training.
# Usage: ./simulate-attack.sh [apt29|bruteforce|insider|verify]
# =============================================================================
set -euo pipefail

C_RESET='\033[0m'; C_BOLD='\033[1m'
C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'; C_DIM='\033[2m'

ok()   { echo -e "  ${C_GREEN}✔${C_RESET}  $*"; }
info() { echo -e "  ${C_CYAN}→${C_RESET}  $*"; }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET}  $*"; }
fail() { echo -e "  ${C_RED}✗${C_RESET}  $*" >&2; exit 1; }
step() { echo -e "\n${C_BOLD}${C_CYAN}── $* ──${C_RESET}"; }

SCENARIO="${1:-apt29}"
OS_PASS="${OPENSEARCH_PASSWORD:-}"

# Load password from .env if not in environment
if [[ -z "$OS_PASS" && -f .env ]]; then
  OS_PASS=$(grep '^OPENSEARCH_PASSWORD=' .env | cut -d= -f2 || true)
fi

OS_URL="http://localhost:9200"
OS_AUTH=""
if [[ -n "$OS_PASS" ]]; then
  OS_AUTH="-u admin:${OS_PASS}"
fi

# ── Helper: inject a single event ─────────────────────────────────────────────
inject_event() {
  local label="$1"
  local payload="$2"
  local index="soc-logs-$(date -u +%Y.%m.%d)"

  if curl -sk $OS_AUTH -X POST "${OS_URL}/${index}/_doc" \
      -H "Content-Type: application/json" \
      -d "$payload" >/dev/null 2>&1; then
    ok "$label"
  else
    warn "$label (inject failed — is OpenSearch running?)"
  fi
  sleep 0.5
}

# =============================================================================
# Scenario 1: APT-29 Cozy Bear — 13-step kill chain
# =============================================================================
run_apt29() {
  step "APT-29 Simulation — 13 MITRE ATT&CK techniques"
  info "Injecting kill chain events into OpenSearch index soc-logs-*"
  echo

  inject_event "T1566.001 · Spearphishing attachment" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1566.001","mitre_tactic":"initial-access",
    "severity":"high","sensor":"email-gateway",
    "src_ip":"185.220.101.45","dst_ip":"10.0.1.50",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1566_spearphish_attachment",
    "description":"Malicious Office macro attachment delivered to finance@corp.local"}'

  inject_event "T1059.001 · PowerShell execution" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1059.001","mitre_tactic":"execution",
    "severity":"high","sensor":"sysmon",
    "src_ip":"10.0.1.50","dst_ip":"185.220.101.45",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1059_powershell_encoded",
    "description":"Encoded PowerShell command executed: IEX (New-Object Net.WebClient).DownloadString"}'

  inject_event "T1053.005 · Scheduled task persistence" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1053.005","mitre_tactic":"persistence",
    "severity":"medium","sensor":"sysmon",
    "src_ip":"10.0.1.50",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1053_scheduled_task_created",
    "description":"New scheduled task WindowsUpdaterSvc created running C:\\ProgramData\\svc.exe"}'

  inject_event "T1547.001 · Registry run key" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1547.001","mitre_tactic":"persistence",
    "severity":"medium","sensor":"sysmon",
    "src_ip":"10.0.1.50",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1547_registry_run_key",
    "description":"Registry key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified"}'

  inject_event "T1003.001 · LSASS memory dump" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1003.001","mitre_tactic":"credential-access",
    "severity":"critical","sensor":"sysmon",
    "src_ip":"10.0.1.50",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1003_lsass_dump",
    "description":"Process lsass.exe accessed by rundll32.exe — credential dumping suspected"}'

  inject_event "T1110.001 · Brute force — password spray" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1110.001","mitre_tactic":"credential-access",
    "severity":"high","sensor":"windows-security",
    "src_ip":"10.0.1.50","dst_ip":"10.0.0.10",
    "host.name":"DC-CORP-01",
    "rule_name":"T1110_password_spray",
    "description":"247 failed logon attempts (EventID 4625) across 38 accounts in 60 seconds"}'

  inject_event "T1557.001 · LLMNR/NBT-NS poisoning" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1557.001","mitre_tactic":"credential-access",
    "severity":"high","sensor":"zeek",
    "src_ip":"10.0.1.200","dst_ip":"10.0.1.50",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1557_llmnr_poisoning",
    "description":"LLMNR query response spoofed — NTLMv2 hash captured from CORP\\jsmith"}'

  inject_event "T1021.002 · SMB lateral movement" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1021.002","mitre_tactic":"lateral-movement",
    "severity":"critical","sensor":"zeek",
    "src_ip":"10.0.1.50","dst_ip":"10.0.2.20",
    "host.name":"SRV-HR-02",
    "rule_name":"T1021_smb_lateral",
    "description":"Authenticated SMB connection to ADMIN$ share on SRV-HR-02 using stolen credentials"}'

  inject_event "T1550.002 · Pass-the-Hash" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1550.002","mitre_tactic":"lateral-movement",
    "severity":"critical","sensor":"windows-security",
    "src_ip":"10.0.1.50","dst_ip":"10.0.0.10",
    "host.name":"DC-CORP-01",
    "rule_name":"T1550_pass_the_hash",
    "description":"NTLM pass-the-hash detected — LogonType 3 with NTLMv2 from non-domain workstation"}'

  inject_event "T1046 · Network port scan" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1046","mitre_tactic":"discovery",
    "severity":"medium","sensor":"suricata",
    "src_ip":"10.0.1.50","dst_ip":"10.0.0.0/24",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1046_port_scan",
    "description":"SYN scan detected — 1024 ports probed across /24 subnet in 8 seconds"}'

  inject_event "T1041 · Exfiltration over C2" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1041","mitre_tactic":"exfiltration",
    "severity":"critical","sensor":"zeek",
    "src_ip":"10.0.1.50","dst_ip":"185.220.101.45",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1041_c2_exfil",
    "description":"4.2 GB data transfer to known Tor exit node over HTTPS (port 443)"}'

  inject_event "T1071.004 · DNS tunneling" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1071.004","mitre_tactic":"command-and-control",
    "severity":"high","sensor":"zeek",
    "src_ip":"10.0.1.50","dst_ip":"8.8.8.8",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1071_dns_tunnel",
    "description":"High-entropy DNS TXT queries to c2.malicious-apt.net — DNS tunneling C2 channel"}'

  inject_event "T1562.001 · Disable Windows Defender" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1562.001","mitre_tactic":"defense-evasion",
    "severity":"critical","sensor":"sysmon",
    "src_ip":"10.0.1.50",
    "host.name":"WKSTN-FINANCE-01",
    "rule_name":"T1562_disable_defender",
    "description":"Set-MpPreference -DisableRealtimeMonitoring $true executed via PowerShell"}'

  echo
  ok "APT-29 simulation complete — 13 events injected"
  info "Open http://localhost:5601 to view events in OpenSearch Dashboards"
}

# =============================================================================
# Scenario 2: Brute Force / Password Spray
# =============================================================================
run_bruteforce() {
  step "Brute Force Simulation — 12 failed logon events + lockout"
  info "Simulating password spray across 12 accounts"
  echo

  local accounts=("jsmith" "mjohnson" "alee" "bwilliams" "cjones" "ddavis"
                  "ewilson" "ftaylor" "gbrown" "hmartin" "ithompson" "jgarcia")

  for acct in "${accounts[@]}"; do
    inject_event "T1110 · Failed logon — ${acct}" '{
      "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
      "mitre_technique":"T1110.001","mitre_tactic":"credential-access",
      "severity":"medium","sensor":"windows-security",
      "src_ip":"10.0.99.15","dst_ip":"10.0.0.10",
      "host.name":"DC-CORP-01",
      "username":"CORP\\'"${acct}"'",
      "event_id":4625,
      "rule_name":"T1110_brute_force",
      "description":"Failed logon attempt — invalid password for '"${acct}"'@corp.local"}'
  done

  inject_event "T1110 · Account lockout triggered" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1110.001","mitre_tactic":"credential-access",
    "severity":"high","sensor":"windows-security",
    "src_ip":"10.0.99.15","dst_ip":"10.0.0.10",
    "host.name":"DC-CORP-01",
    "event_id":4740,
    "rule_name":"T1110_account_lockout",
    "description":"Account lockout triggered for 3 accounts after threshold exceeded"}'

  echo
  ok "Brute force simulation complete — 13 events injected"
}

# =============================================================================
# Scenario 3: Insider Threat
# =============================================================================
run_insider() {
  step "Insider Threat Simulation — data staging and exfiltration"
  info "Simulating malicious insider activity"
  echo

  inject_event "Insider · Bulk file access" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1039","mitre_tactic":"collection",
    "severity":"medium","sensor":"file-audit",
    "src_ip":"10.0.3.45",
    "host.name":"WKSTN-LEGAL-05",
    "username":"CORP\\rchen",
    "rule_name":"insider_bulk_access",
    "description":"User rchen accessed 847 files in \\\\fileserver\\legal\\contracts in 4 minutes"}'

  inject_event "Insider · Archive creation" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1560.001","mitre_tactic":"collection",
    "severity":"high","sensor":"sysmon",
    "src_ip":"10.0.3.45",
    "host.name":"WKSTN-LEGAL-05",
    "rule_name":"insider_archive_create",
    "description":"7-Zip archive created: C:\\Users\\rchen\\Desktop\\contracts_backup.7z (2.1 GB)"}'

  inject_event "Insider · USB device connected" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1052.001","mitre_tactic":"exfiltration",
    "severity":"high","sensor":"windows-security",
    "host.name":"WKSTN-LEGAL-05",
    "rule_name":"insider_usb_connect",
    "description":"Removable storage device connected — SanDisk 128GB (S/N: 4C530012345)"}'

  inject_event "Insider · Large upload to cloud storage" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1567.002","mitre_tactic":"exfiltration",
    "severity":"critical","sensor":"proxy",
    "src_ip":"10.0.3.45","dst_ip":"dropbox.com",
    "host.name":"WKSTN-LEGAL-05",
    "rule_name":"insider_cloud_upload",
    "description":"2.3 GB uploaded to dropbox.com — exceeds DLP policy threshold by 2200%"}'

  inject_event "Insider · After-hours access" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1078","mitre_tactic":"defense-evasion",
    "severity":"medium","sensor":"windows-security",
    "src_ip":"10.0.3.45","dst_ip":"10.0.0.10",
    "host.name":"DC-CORP-01",
    "rule_name":"insider_afterhours",
    "description":"Logon at 02:34 UTC on Saturday — anomalous for user rchen (typical 08:00-18:00 M-F)"}'

  inject_event "Insider · Email forward rule created" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1114.003","mitre_tactic":"collection",
    "severity":"high","sensor":"o365-audit",
    "host.name":"EXCHANGE-01",
    "rule_name":"insider_forward_rule",
    "description":"Inbox forwarding rule created — all mail forwarded to rchen.personal@gmail.com"}'

  inject_event "Insider · VPN from unusual country" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1133","mitre_tactic":"initial-access",
    "severity":"high","sensor":"vpn-gateway",
    "src_ip":"45.132.227.89","dst_ip":"10.0.0.1",
    "host.name":"VPN-GW-01",
    "rule_name":"insider_geo_anomaly",
    "description":"VPN login from Romania (user rchen last login from US) — impossible travel alert"}'

  inject_event "Insider · Sensitive DB query" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1213","mitre_tactic":"collection",
    "severity":"critical","sensor":"db-audit",
    "src_ip":"10.0.3.45","dst_ip":"10.0.5.10",
    "host.name":"DB-PROD-01",
    "rule_name":"insider_bulk_db_query",
    "description":"SELECT * from customers — 127,445 rows returned; query outside normal job function"}'

  inject_event "Insider · Evidence deletion" '{
    "@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "mitre_technique":"T1070.004","mitre_tactic":"defense-evasion",
    "severity":"critical","sensor":"sysmon",
    "host.name":"WKSTN-LEGAL-05",
    "rule_name":"insider_log_wipe",
    "description":"Windows Event Log cleared (EventID 1102) and browser history deleted by rchen"}'

  echo
  ok "Insider threat simulation complete — 9 events injected"
}

# =============================================================================
# Scenario 4: Verify injected events
# =============================================================================
run_verify() {
  step "Verification — querying injected events"
  echo

  local techniques=(
    "T1566" "T1059" "T1003" "T1110" "T1557"
    "T1021" "T1046" "T1041" "T1071" "T1562"
  )

  for tech in "${techniques[@]}"; do
    COUNT=$(curl -sk $OS_AUTH \
      "${OS_URL}/soc-logs-*/_count?q=mitre_technique:${tech}*" 2>/dev/null \
      | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "?")
    if [[ "$COUNT" =~ ^[0-9]+$ && "$COUNT" -gt 0 ]]; then
      ok "${tech} — ${COUNT} event(s) found"
    else
      warn "${tech} — 0 events (run ./simulate-attack.sh apt29 first)"
    fi
  done

  TOTAL=$(curl -sk $OS_AUTH \
    "${OS_URL}/soc-logs-*/_count" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "?")
  echo
  ok "Total documents in soc-logs-*: ${TOTAL}"
  info "View in OpenSearch Dashboards: http://localhost:5601"
}

# =============================================================================
# Dispatch
# =============================================================================
echo -e "\n${C_BOLD}${C_CYAN}  Advanced SOC Lab v2.0 — Attack Simulation${C_RESET}"
echo -e "  Scenario: ${C_BOLD}${SCENARIO}${C_RESET}\n"

case "$SCENARIO" in
  apt29)       run_apt29 ;;
  bruteforce)  run_bruteforce ;;
  insider)     run_insider ;;
  verify)      run_verify ;;
  all)
    run_apt29
    run_bruteforce
    run_insider
    run_verify
    ;;
  *)
    echo -e "  ${C_RED}Unknown scenario: ${SCENARIO}${C_RESET}"
    echo -e "  Usage: $0 [apt29|bruteforce|insider|verify|all]"
    exit 1
    ;;
esac

echo
