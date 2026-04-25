# Threat Hunt: Lateral Movement
## Hypotheses & OpenSearch KQL Queries

---

### HUNT-05: Pass-the-Hash (T1550.002)
**Hypothesis:** Attacker reusing NTLM hash captured via Responder for lateral movement

**KQL — PtH signature (LogonType 3 + NTLM + no password hash length):**
```
event_id:4624 AND LogonType:3 AND
AuthenticationPackageName:NTLM AND KeyLength:0 AND
NOT TargetUserName:*$ AND NOT WorkstationName:"-"
```

**KQL — Impossible travel (same user, different source, <5min):**
```
event_id:4624 AND LogonType:3
| timechart: by SubjectUserName, IpAddress span=5m
| filter unique_ips_per_user > 2
```

---

### HUNT-06: SMB Lateral Movement — PsExec style (T1021.002)
**Hypothesis:** Attacker using SMB (port 445) to copy and execute payloads laterally

**KQL — Zeek SMB execution pattern:**
```
log_type:zeek AND service:smb AND (
  smb.command:*EXEC* OR
  smb.filename:*PSEXESVC* OR
  smb.filename:*PAEXEC* OR
  smb.filename:*.exe AND smb.path:*admin$*
)
```

**KQL — Windows event lateral execution:**
```
event_id:7045 AND ServiceFileName:(*ADMIN$* OR *C$*)
```

**KQL — Sysmon network + lateral tools:**
```
event_id:3 AND DestinationPort:445 AND
NOT (Image:*explorer.exe OR Image:*svchost.exe)
```

---

### HUNT-07: WMI Remote Execution (T1047)
**Hypothesis:** Attacker using WMIC for remote process creation

**KQL:**
```
event_id:1 AND (
  Image:*wmic.exe AND CommandLine:*/node:* AND CommandLine:*process*call*create*
) OR (
  ParentImage:*WmiPrvSE.exe AND NOT Image:*WmiPrvSE.exe
)
```

**Velociraptor VQL:**
```sql
SELECT * FROM wmi(query="SELECT * FROM Win32_Process WHERE ParentProcessId IN (
  SELECT ProcessId FROM Win32_Process WHERE Name = 'WmiPrvSE.exe'
)")
```

---

### HUNT-08: Living-off-the-Land Binaries (T1218)
**Hypothesis:** Attacker abusing signed Windows binaries to evade AV

**KQL — LOLBINs making network connections:**
```
event_id:3 AND Image:(
  *certutil.exe OR *mshta.exe OR *wscript.exe OR
  *cscript.exe OR *regsvr32.exe OR *rundll32.exe OR
  *odbcconf.exe OR *mavinject.exe
) AND NOT DestinationIp:127.0.0.1
```

**KQL — certutil decode (T1140):**
```
event_id:1 AND Image:*certutil.exe AND (
  CommandLine:*-decode* OR
  CommandLine:*-urlcache* OR
  CommandLine:*-split*
)
```
