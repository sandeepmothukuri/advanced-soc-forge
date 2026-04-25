# Threat Hunt: Credential Access
## Hypotheses & OpenSearch KQL Queries

---

### HUNT-01: LSASS Memory Access (T1003.001)
**Hypothesis:** Attacker used credential dumping tool (mimikatz, procdump) targeting lsass.exe

**KQL:**
```
event_id:10 AND TargetImage:*lsass.exe AND NOT (
  SourceImage:*wininit.exe OR
  SourceImage:*services.exe OR
  SourceImage:*MsMpEng.exe OR
  SourceImage:*csrss.exe
)
```

**Suspicious GrantedAccess values:**
```
event_id:10 AND TargetImage:*lsass.exe AND (
  GrantedAccess:0x1010 OR
  GrantedAccess:0x1410 OR
  GrantedAccess:0x147a OR
  GrantedAccess:0x1fffff
)
```

**Velociraptor VQL:**
```sql
SELECT * FROM handles() WHERE Name =~ "lsass" AND Type = "Process"
```

---

### HUNT-02: LLMNR/NBT-NS Poisoning — Responder (T1557.001)
**Hypothesis:** Attacker ran Responder to capture NTLMv2 hashes on the LAN

**KQL — Zeek LLMNR traffic:**
```
log_type:zeek AND proto:udp AND (resp_p:5355 OR resp_p:137)
```

**KQL — Multiple NTLMv2 responses from one host:**
```
log_type:zeek AND proto:udp AND resp_p:5355
| aggregation: count by id.orig_h
| filter count > 5
```

**Suricata alert:**
```
alert.signature:*LLMNR* OR alert.signature:*Responder* OR alert.signature:*NBT-NS*
```

---

### HUNT-03: Kerberoasting (T1558.003)
**Hypothesis:** Attacker requested service tickets for offline cracking

**KQL — Zeek Kerberos:**
```
log_type:zeek AND service:kerberos AND request_type:TGS AND cipher:*rc4*
```

**Windows Security Event:**
```
event_id:4769 AND TicketEncryptionType:0x17 AND NOT ServiceName:*$
```

**Velociraptor VQL:**
```sql
SELECT * FROM parse_evtx(filename="Security.evtx")
WHERE EventID = 4769 AND get(item=EventData, field="TicketEncryptionType") = "0x17"
```

---

### HUNT-04: Password Spraying (T1110.003)
**Hypothesis:** Low-and-slow brute force against multiple accounts from one source

**KQL — multiple accounts, single source:**
```
event_id:4625 AND LogonType:3
| aggregation: count by IpAddress, TargetUserName
| filter count > 3 and unique_users > 5
```

**KQL — spray pattern (one failure per user):**
```
event_id:4625 AND NOT SubStatus:"0xc0000072"
| timechart: count by IpAddress span=5m
| filter count > 10
```
