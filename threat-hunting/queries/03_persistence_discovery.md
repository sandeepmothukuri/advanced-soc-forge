# Threat Hunt: Persistence & Discovery
## Hypotheses & OpenSearch KQL Queries

---

### HUNT-09: Registry Run Key Persistence (T1547.001)
**KQL:**
```
event_id:(12 OR 13) AND TargetObject:(
  *\SOFTWARE\Microsoft\Windows\CurrentVersion\Run* OR
  *\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce* OR
  *\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon*
) AND NOT (
  Details:*Microsoft* OR
  Details:*Program Files*
)
```

---

### HUNT-10: Scheduled Task Persistence (T1053.005)
**KQL:**
```
event_id:4698 AND NOT (
  SubjectUserName:SYSTEM OR
  TaskName:*Microsoft*
)
```

**KQL — Sysmon scheduled task via command line:**
```
event_id:1 AND Image:*schtasks.exe AND CommandLine:*/create* AND (
  CommandLine:*powershell* OR
  CommandLine:*cmd* OR
  CommandLine:*wscript* OR
  CommandLine:*mshta*
)
```

---

### HUNT-11: Service Creation Persistence (T1543.003)
**KQL:**
```
event_id:7045 AND NOT (
  ServiceFileName:*Windows* OR
  ServiceFileName:*Program Files*
)
```

**KQL — New service with suspicious path:**
```
event_id:7045 AND ServiceFileName:(*Temp* OR *AppData* OR *ProgramData*)
```

---

### HUNT-12: Network Scanning (T1046)
**Hypothesis:** Attacker enumerating network before lateral movement

**KQL — Zeek scan detection:**
```
log_type:zeek AND note:*Scan* AND (
  note:*Port_Scan* OR
  note:*Address_Scan*
)
```

**KQL — High connection count from single host:**
```
log_type:zeek AND service:"-"
| aggregation: count by id.orig_h, id.resp_p
| filter count > 50 AND unique_dests > 20
```

**KQL — PowerShell network scan pattern:**
```
event_id:1 AND Image:*powershell.exe AND CommandLine:(
  *Test-NetConnection* OR
  *Net.Sockets.TcpClient* OR
  *Net.NetworkInformation.Ping*
)
```
