# Security Onion — Full VM Installation Guide
## SOC Lab Integration: Network Security Monitoring Layer

---

## Overview
Security Onion 2.4 is a free, open-source Linux distro for threat hunting, enterprise security monitoring, and log management. It bundles Zeek, Suricata, Elastic Stack (or OpenSearch), and more.

In this SOC lab we run Zeek and Suricata as **Docker containers** (Task #7), but this guide shows how to set up Security Onion as a VM and integrate it with our OpenSearch cluster.

---

## Architecture Options

### Option A — Docker Mode (Used in this lab)
```
SOC Lab Docker Stack
├── zeek container       → /var/log/zeek/ → Vector → OpenSearch
└── suricata container   → /var/log/suricata/eve.json → Vector → OpenSearch
```

### Option B — Security Onion VM (This guide)
```
Security Onion VM (standalone)
├── Zeek (built-in)      → Zeek logs → forward to SOC OpenSearch
├── Suricata (built-in)  → EVE JSON → forward to SOC OpenSearch
└── Beats/Logstash        → ship logs to external OpenSearch
```

---

## Step 1 — Download Security Onion 2.4

```bash
# Download ISO (4GB)
wget https://github.com/Security-Onion-Solutions/securityonion/releases/download/2.4.60-20240101/securityonion-2.4.60-20240101.iso

# Verify checksum
sha256sum securityonion-2.4.60-20240101.iso
# Compare with: https://github.com/Security-Onion-Solutions/securityonion/releases
```

---

## Step 2 — VM Hardware Requirements

| Resource | Minimum | Recommended for Lab |
|----------|---------|---------------------|
| RAM      | 16 GB   | 32 GB               |
| CPU      | 4 cores | 8 cores             |
| Disk     | 200 GB  | 500 GB SSD          |
| NICs     | 2       | 2 (mgmt + monitor)  |

**VMware/VirtualBox NIC Setup:**
- NIC 1 (eth0): Host-only / NAT — management
- NIC 2 (eth1): Promiscuous / Bridged — packet capture (SPAN port)

```
VMware: VM Settings → Network Adapter 2 → Promiscuous Mode: Allow All
VirtualBox: Settings → Network → Adapter 2 → Promiscuous Mode: Allow All VMs
```

---

## Step 3 — Install Security Onion

Boot from ISO, then:

```bash
# At the setup wizard, choose:
# Installation type: EVAL (single-node for lab)
# Management NIC: eth0 (your host-only adapter)
# Monitor NIC: eth1 (promiscuous adapter)
# Username: admin
# Password: SoCL@bAdmin2024!

# Wait ~20 minutes for installation
```

---

## Step 4 — Post-Install Configuration

```bash
# SSH to Security Onion VM
ssh admin@<SO_VM_IP>

# Check all services running
sudo so-status

# Access web UI
# https://<SO_VM_IP>
# Username: admin@<domain>
# Password: set during install
```

---

## Step 5 — Forward Logs to SOC Lab OpenSearch

### Method A: Filebeat (recommended)

```bash
# On Security Onion VM — install Filebeat
sudo apt-get install filebeat -y

# Configure to forward to SOC Lab Vector/OpenSearch
sudo cat > /etc/filebeat/filebeat.yml << 'FBEOF'
filebeat.inputs:
  # Zeek logs
  - type: log
    paths: [/nsm/zeek/logs/current/*.log]
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_source: zeek
      sensor_type: security-onion-layer
      sensor_host: "${SO_HOSTNAME}"
    fields_under_root: true

  # Suricata EVE JSON
  - type: log
    paths: [/nsm/suricata/eve.json]
    json.keys_under_root: true
    fields:
      log_source: suricata
      sensor_type: security-onion-layer
    fields_under_root: true

output.elasticsearch:
  hosts: ["http://SOC_LAB_IP:9200"]
  username: "admin"
  password: "AdminPassword123!"
  index: "soc-logs-so-%{+yyyy.MM.dd}"

setup.template.name: "soc-logs-so"
setup.template.pattern: "soc-logs-so-*"
FBEOF

sudo systemctl enable filebeat --now
```

### Method B: Direct OpenSearch output (Security Onion 2.4+)

```bash
# Edit Security Onion's Logstash pipeline
sudo so-logstash-config-edit

# Add OpenSearch output:
output {
  elasticsearch {
    hosts => ["http://SOC_LAB_IP:9200"]
    user => "admin"
    password => "AdminPassword123!"
    index => "soc-logs-so-%{+YYYY.MM.dd}"
  }
}
```

---

## Step 6 — SPAN Port / Network Tap Setup

### Physical Network
```
Switch SPAN port → Security Onion monitor NIC
```

### Virtual Lab (VMware vSwitch)
```
VMware vSphere → vSwitch → Port Group → Promiscuous Mode: Accept
Security Onion VM → NIC 2 → Connect to that port group
```

### Virtual Lab (VirtualBox)
```bash
# On VirtualBox host
VBoxManage modifyvm "Security-Onion-VM" --nic2 bridged
VBoxManage modifyvm "Security-Onion-VM" --nicpromisc2 allow-all
VBoxManage modifyvm "Security-Onion-VM" --bridgeadapter2 "eth0"
```

---

## Step 7 — Tune Zeek for SOC Lab

```bash
# Edit Zeek local policy
sudo nano /opt/so/saltstack/local/salt/zeek/local.zeek

# Add to enable all SOC-relevant logs:
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/smb
@load base/protocols/kerberos
@load policy/protocols/smb/log-cmds
@load policy/frameworks/notice/community-id
redef LogAscii::use_json = T;

# Restart Zeek
sudo so-zeek-restart
```

---

## Step 8 — Import SOC Suricata Rules

```bash
# Copy custom rules to Security Onion
scp detection-rules/suricata/soc_custom.rules admin@SO_VM_IP:/tmp/

# On Security Onion VM
sudo cp /tmp/soc_custom.rules /opt/so/rules/local.rules
sudo so-suricata-update
sudo so-suricata-restart
```

---

## Step 9 — Verify Integration

```bash
# Generate test traffic
curl http://testmyids.com  # Should trigger Suricata

# Check logs arrive in SOC OpenSearch
curl -s "http://SOC_LAB_IP:9200/soc-logs-so-*/_search?q=sensor_type:security-onion-layer&size=5" \
  -u admin:AdminPassword123! | python3 -m json.tool
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| No logs in OpenSearch | Check `systemctl status filebeat` on SO VM |
| Zeek not capturing | Verify NIC in promiscuous mode; check `so-zeek-status` |
| Suricata rules not loading | Run `sudo so-suricata-update && so-suricata-restart` |
| Web UI unreachable | `sudo so-firewall-apply` |
| High CPU on Zeek | Tune `zeekctl.cfg` → `lb_method=pf_ring` for high traffic |
