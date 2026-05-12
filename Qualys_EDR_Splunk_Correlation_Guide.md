# Qualys EDR — Splunk Correlation Search & Notable Event Guide

---

## Table of Contents

1. [Overview & Architecture](#overview)
2. [Data Model & Field Reference](#data-model)
3. [Source Type Schemas](#sourcetype-schemas)
4. [Correlation Search Fundamentals](#fundamentals)
5. [Process Sourcetype — Correlation Searches](#process-searches)
6. [File Sourcetype — Correlation Searches](#file-searches)
7. [Network Sourcetype — Correlation Searches](#network-searches)
8. [Registry Sourcetype — Correlation Searches](#registry-searches)
9. [Cross-Sourcetype Correlation Searches](#cross-sourcetype)
10. [Notable Event Creation](#notable-events)
11. [Risk-Based Alerting (RBA) Integration](#rba)
12. [Tuning & Suppression](#tuning)
13. [Dashboard & Triage Workflow](#dashboard)

---

## 1. Overview & Architecture <a name="overview"></a>

Qualys EDR telemetry is ingested into Splunk across four primary sourcetypes. Correlation searches detect threat patterns across these sourcetypes, and Splunk Enterprise Security (ES) generates notable events that feed into the SOC triage workflow.

```
Qualys EDR Agent
       │
       ▼
Qualys EDR Platform (Cloud)
       │
       ▼ (Syslog / HEC / API)
Splunk Heavy Forwarder / HEC
       │
       ├── sourcetype=qualys:edr:process
       ├── sourcetype=qualys:edr:file
       ├── sourcetype=qualys:edr:network
       └── sourcetype=qualys:edr:registry
       │
       ▼
Splunk Indexer Cluster
       │
       ▼
Splunk ES Correlation Searches → Notable Events → Incident Review
```

### Prerequisites

- Splunk Enterprise Security (ES) 7.x+
- Qualys EDR App for Splunk (or manual index/sourcetype config)
- CIM (Common Information Model) Add-on
- Recommended index: `index=edr` (or `qualys_edr`)

---

## 2. Data Model & Field Reference <a name="data-model"></a>

Map Qualys EDR fields to Splunk CIM for ES compatibility.

### CIM Mapping Table

| CIM Data Model | Qualys EDR Sourcetype | Key CIM Fields |
|---|---|---|
| Endpoint.Processes | qualys:edr:process | process, process_id, parent_process, user, dest |
| Endpoint.Filesystem | qualys:edr:file | file_name, file_path, action, user, dest |
| Network_Traffic | qualys:edr:network | src_ip, dest_ip, dest_port, protocol, bytes |
| Endpoint.Registry | qualys:edr:registry | registry_path, registry_key_name, registry_value_data |

### Common Fields Across All Sourcetypes

| Field | Description | Example |
|---|---|---|
| `host` | Endpoint hostname | `WORKSTATION-01` |
| `dest` | Target/destination host | `WORKSTATION-01` |
| `user` | Executing user account | `DOMAIN\jsmith` |
| `asset_id` | Qualys asset ID | `12345678` |
| `severity` | Qualys severity score | `HIGH`, `CRITICAL` |
| `event_type` | EDR event category | `PROCESS_START` |
| `sensor_id` | Qualys sensor identifier | `sensor-abc123` |
| `_time` | Event timestamp | epoch |

---

## 3. Source Type Schemas <a name="sourcetype-schemas"></a>

### 3.1 qualys:edr:process

```
_time, host, user, dest, process, process_id, process_path, process_hash_md5,
process_hash_sha256, parent_process, parent_process_id, parent_process_path,
command_line, process_integrity_level, process_elevated, event_type
```

### 3.2 qualys:edr:file

```
_time, host, user, dest, file_name, file_path, file_hash_md5, file_hash_sha256,
action (CREATE/MODIFY/DELETE/RENAME), file_size, file_extension,
target_file_path, target_file_name (for renames)
```

### 3.3 qualys:edr:network

```
_time, host, user, dest, src_ip, dest_ip, src_port, dest_port, protocol,
bytes_in, bytes_out, direction, transport, process, process_id,
dns_query, dns_answer, connection_state
```

### 3.4 qualys:edr:registry

```
_time, host, user, dest, registry_path, registry_key_name, registry_value_name,
registry_value_data, registry_value_type, action (CREATE/MODIFY/DELETE),
process, process_id
```

---

## 4. Correlation Search Fundamentals <a name="fundamentals"></a>

### 4.1 Correlation Search Anatomy in ES

Every ES correlation search has these core components:

```
Search Query  →  Trigger Threshold  →  Notable Event Config  →  Response Actions
```

### 4.2 Search Scheduling Best Practices

| Severity | Cron Schedule | Earliest | Latest |
|---|---|---|---|
| Critical | `*/5 * * * *` | `-6m` | `-1m` |
| High | `*/15 * * * *` | `-20m` | `-5m` |
| Medium | `0 * * * *` | `-65m` | `-5m` |
| Low | `0 */4 * * *` | `-245m` | `-5m` |

### 4.3 Standard Search Header Pattern

Apply this pattern consistently across all correlation searches:

```spl
index=edr sourcetype="qualys:edr:*"
| eval dest=coalesce(dest, host)
| eval user=lower(user)
| fields - _raw
```

### 4.4 Throttling Configuration

Always set throttling to prevent alert storms:

- **Throttle field**: `dest` or `user` (depending on search)
- **Throttle window**: 300–3600 seconds (use lower for Critical)

---

## 5. Process Sourcetype — Correlation Searches <a name="process-searches"></a>

### CS-PROC-001 — Suspicious Child Process from Office Applications

Detects macro or script execution spawned from Office processes — a common initial access technique.

```spl
index=edr sourcetype="qualys:edr:process"
| eval parent=lower(parent_process)
| eval child=lower(process)
| where match(parent, "(winword|excel|powerpnt|outlook|onenote)\.exe")
  AND match(child, "(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(command_line) as command_lines
    values(child) as child_processes
    by dest user parent
| where count >= 1
| eval severity="high"
| eval mitre_technique="T1566.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Notable Event Fields**: `dest`, `user`, `parent`, `child_processes`, `command_lines`
**Trigger**: Per result
**Throttle**: `dest` / 600s

---

### CS-PROC-002 — PowerShell Encoded Command Execution

Detects PowerShell with Base64-encoded commands, a common obfuscation technique.

```spl
index=edr sourcetype="qualys:edr:process"
  process="*powershell*"
| eval cmd_lower=lower(command_line)
| where match(cmd_lower, "(-enc|-encodedcommand|-e\s)")
  OR match(cmd_lower, "[A-Za-z0-9+/]{50,}={0,2}")
| eval base64_detected=if(match(cmd_lower, "[A-Za-z0-9+/]{100,}={0,2}"), "YES", "POSSIBLE")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(command_line) as command_lines
    by dest user process base64_detected
| eval severity="high"
| eval mitre_technique="T1059.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-PROC-003 — Living-off-the-Land Binary (LOLBin) Abuse

Monitors known LOLBins executing suspicious actions.

```spl
index=edr sourcetype="qualys:edr:process"
| eval proc=lower(process)
| eval cmd=lower(command_line)
| eval lolbin_match=case(
    match(proc, "certutil\.exe") AND match(cmd, "(-urlcache|-decode|-encode|http)"), "certutil download/encode",
    match(proc, "mshta\.exe") AND match(cmd, "(http|vbscript|javascript)"), "mshta remote script",
    match(proc, "regsvr32\.exe") AND match(cmd, "(/s|scrobj|http)"), "regsvr32 squiblydoo",
    match(proc, "rundll32\.exe") AND match(cmd, "(javascript|http|shell32)"), "rundll32 abuse",
    match(proc, "bitsadmin\.exe") AND match(cmd, "(transfer|http|download)"), "bitsadmin download",
    match(proc, "wmic\.exe") AND match(cmd, "(process call create|/node|http)"), "wmic lateral/exec",
    match(proc, "msiexec\.exe") AND match(cmd, "(http|/q|/i)"), "msiexec remote install",
    1==1, null()
  )
| where isnotnull(lolbin_match)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(command_line) as command_lines
    values(lolbin_match) as techniques
    by dest user proc
| eval severity="high"
| eval mitre_technique="T1218"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-PROC-004 — Process Injection Indicators (Suspicious Parent-Child PID Mismatch)

Detects processes where the parent PID doesn't correspond to the expected parent process name.

```spl
index=edr sourcetype="qualys:edr:process"
| eval expected_parent=case(
    match(lower(process), "svchost\.exe"), "services.exe",
    match(lower(process), "taskhost\.exe"), "svchost.exe",
    match(lower(process), "lsass\.exe"), "wininit.exe",
    1==1, null()
  )
| where isnotnull(expected_parent)
  AND lower(parent_process) != expected_parent
  AND NOT match(lower(parent_process), "(system|smss\.exe)")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(parent_process) as parent_processes
    values(process_path) as process_paths
    by dest user process expected_parent
| eval severity="critical"
| eval mitre_technique="T1055"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-PROC-005 — Suspicious Process Execution from Temp/User Writable Paths

```spl
index=edr sourcetype="qualys:edr:process"
| eval path_lower=lower(process_path)
| where match(path_lower, "(\\temp\\|\\tmp\\|\\appdata\\local\\temp|\\downloads\\|\\public\\|\\programdata\\)")
  AND match(lower(process), "\.(exe|dll|bat|cmd|ps1|vbs|js|hta)$")
  AND NOT match(lower(process), "(setup|install|update|patch)\.exe")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(process_path) as paths
    values(command_line) as commands
    by dest user process
| eval severity="medium"
| eval mitre_technique="T1059"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-PROC-006 — Credential Dumping Tool Execution

Detects execution of known credential harvesting tools.

```spl
index=edr sourcetype="qualys:edr:process"
| eval proc=lower(process)
| eval cmd=lower(command_line)
| eval hash=lower(process_hash_sha256)
| eval cred_indicator=case(
    match(proc, "(mimikatz|mimilib|mimidump)"), "Mimikatz",
    match(cmd, "(sekurlsa|lsadump|kerberos::)"), "Mimikatz command",
    match(proc, "procdump") AND match(cmd, "lsass"), "ProcDump LSASS",
    match(cmd, "lsass\.exe") AND match(proc, "(taskmgr|rundll32|ntdsutil)"), "LSASS Access",
    match(proc, "ntdsutil") AND match(cmd, "(snapshot|activate|ac)"), "NTDS Dump",
    match(cmd, "(gsecdump|pwdump|wce\.exe|fgdump)"), "Password Dumper",
    1==1, null()
  )
| where isnotnull(cred_indicator)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(command_line) as command_lines
    by dest user proc cred_indicator
| eval severity="critical"
| eval mitre_technique="T1003"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-PROC-007 — Abnormal Process Execution Frequency (Beaconing Pattern)

```spl
index=edr sourcetype="qualys:edr:process"
| bin _time span=5m
| stats count by dest process _time
| stats avg(count) as avg_exec stdev(count) as stdev_exec values(_time) as times
    by dest process
| where stdev_exec < 1 AND avg_exec > 3
| eval beacon_score=round(avg_exec / (stdev_exec + 0.001), 2)
| where beacon_score > 100
| eval severity="medium"
| eval mitre_technique="T1543"
```

---

## 6. File Sourcetype — Correlation Searches <a name="file-searches"></a>

### CS-FILE-001 — Ransomware File Extension Activity

Detects mass file renames/modifications consistent with ransomware encryption.

```spl
index=edr sourcetype="qualys:edr:file"
  action IN ("RENAME","MODIFY","CREATE")
| eval file_ext=lower(mvindex(split(file_name, "."), -1))
| eval ransomware_ext=case(
    match(file_ext, "(locky|cerber|zepto|odin|aesir|thor|zzzzz|encrypted|enc|crypt|locked|crypto|crypz|cryp1)"), "Known Ransomware Extension",
    match(file_ext, "(wncry|wncryt|wcry)"), "WannaCry Extension",
    match(file_ext, "(ryuk|conti|revil|maze|egregor|darkside|blackcat|alphv)"), "Named Ransomware Group",
    1==1, null()
  )
| where isnotnull(ransomware_ext)
| stats count min(_time) as firstTime max(_time) as lastTime
    dc(file_name) as unique_files
    values(file_name) as file_names
    by dest user ransomware_ext
| where count >= 3
| eval severity="critical"
| eval mitre_technique="T1486"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-FILE-002 — Mass File Deletion Activity

Detects bulk file deletions which may indicate ransomware, sabotage, or anti-forensics.

```spl
index=edr sourcetype="qualys:edr:file"
  action="DELETE"
| bin _time span=5m
| stats count dc(file_path) as unique_paths
    min(_time) as firstTime max(_time) as lastTime
    values(file_path) as paths
    by dest user _time
| where unique_paths >= 50
| eval severity="high"
| eval mitre_technique="T1485"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-FILE-003 — Executable Dropped in Suspicious Location

```spl
index=edr sourcetype="qualys:edr:file"
  action IN ("CREATE","MODIFY")
| eval path_lower=lower(file_path)
| eval ext_lower=lower(mvindex(split(file_name,"."), -1))
| where match(ext_lower, "(exe|dll|sys|drv|ocx|scr|bat|cmd|ps1|vbs|hta|jar)")
  AND match(path_lower, "(\\temp\\|\\appdata\\|\\public\\|\\programdata\\|\\windows\\temp|\\recycle)")
  AND NOT match(path_lower, "(\\windows\\installer|\\windows\\softwaredistribution)")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(file_path) as file_paths
    values(file_hash_sha256) as sha256_hashes
    by dest user file_name ext_lower
| eval severity="high"
| eval mitre_technique="T1204.002"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-FILE-004 — Known Malicious Hash Detected (Threat Intel Match)

> Requires a threat intel lookup file: `malicious_hashes.csv` with field `sha256`

```spl
index=edr sourcetype="qualys:edr:file"
| eval hash=lower(file_hash_sha256)
| lookup malicious_hashes.csv sha256 AS hash OUTPUT threat_name confidence source
| where isnotnull(threat_name)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(file_path) as file_paths
    values(threat_name) as threats
    by dest user hash confidence
| eval severity="critical"
| eval mitre_technique="T1204"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-FILE-005 — Sensitive File Access (Credential Stores, Certificates)

```spl
index=edr sourcetype="qualys:edr:file"
| eval path_lower=lower(file_path)
| eval sensitive_match=case(
    match(path_lower, "(\\sam$|\\ntds\.dit|\\security$|\\system$)"), "Registry Hive / SAM",
    match(path_lower, "(\.pfx$|\.p12$|\.pem$|\.key$|\.cer$)"), "Certificate / Key File",
    match(path_lower, "(\\\.ssh\\|known_hosts|authorized_keys|id_rsa)"), "SSH Key",
    match(path_lower, "(credentials|credential manager|windows credentials)"), "Windows Credentials",
    match(path_lower, "(\.kdbx$|keepass|\.kwallet$)"), "Password Manager DB",
    1==1, null()
  )
| where isnotnull(sensitive_match)
  AND NOT match(lower(process), "(antivirus|defender|qualys)")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(file_path) as files
    by dest user sensitive_match
| eval severity="high"
| eval mitre_technique="T1552"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

## 7. Network Sourcetype — Correlation Searches <a name="network-searches"></a>

### CS-NET-001 — DNS Beaconing Detection

Detects high-frequency DNS queries to a single domain (C2 beaconing pattern).

```spl
index=edr sourcetype="qualys:edr:network"
  dns_query=*
| eval domain=lower(dns_query)
| where NOT match(domain, "(microsoft|windows|office|windowsupdate|qualys|google|amazon)")
| bin _time span=1h
| stats count dc(src_ip) as src_count
    min(_time) as firstTime max(_time) as lastTime
    by dest domain _time
| where count >= 100 AND src_count <= 2
| eval beacon_rate=round(count/60, 2)
| eval severity=case(count >= 500, "critical", count >= 200, "high", 1==1, "medium")
| eval mitre_technique="T1071.004"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-NET-002 — Connection to Known Malicious IP (Threat Intel)

> Requires threat intel lookup: `malicious_ips.csv` with field `ip`

```spl
index=edr sourcetype="qualys:edr:network"
| eval dest_ip_norm=lower(dest_ip)
| lookup malicious_ips.csv ip AS dest_ip OUTPUT threat_category confidence indicator_source
| where isnotnull(threat_category)
| stats count min(_time) as firstTime max(_time) as lastTime
    sum(bytes_out) as total_bytes_out
    values(dest_port) as ports
    values(protocol) as protocols
    by dest src_ip dest_ip threat_category indicator_source
| eval severity="critical"
| eval mitre_technique="T1071"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-NET-003 — Unusual Outbound Port Usage

Detects connections to uncommon high ports that may indicate tunneling or C2 activity.

```spl
index=edr sourcetype="qualys:edr:network"
  direction="outbound"
| eval dest_port=tonumber(dest_port)
| where NOT dest_port IN (80, 443, 8080, 8443, 53, 22, 25, 587, 465, 110, 995, 143, 993, 21, 3389, 1433, 5985, 5986)
  AND dest_port > 1024
  AND dest_port < 65535
| where NOT match(lower(dest_ip), "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
| stats count dc(dest_ip) as unique_dests
    min(_time) as firstTime max(_time) as lastTime
    values(dest_ip) as dest_ips
    values(process) as processes
    by dest src_ip dest_port protocol
| where count >= 5
| eval severity="medium"
| eval mitre_technique="T1571"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-NET-004 — Data Exfiltration via Large Outbound Transfer

```spl
index=edr sourcetype="qualys:edr:network"
  direction="outbound"
| where NOT match(lower(dest_ip), "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
| bin _time span=1h
| stats sum(bytes_out) as total_bytes_out dc(dest_ip) as unique_dests
    min(_time) as firstTime max(_time) as lastTime
    by dest user _time
| eval total_mb=round(total_bytes_out/1024/1024, 2)
| where total_mb >= 500
| eval severity=case(total_mb >= 5000, "critical", total_mb >= 1000, "high", 1==1, "medium")
| eval mitre_technique="T1041"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-NET-005 — Lateral Movement via SMB / WMI / RDP

```spl
index=edr sourcetype="qualys:edr:network"
| eval is_lateral=case(
    dest_port IN (445, 139) AND NOT match(lower(dest_ip), "^(10\.|172\.|192\.168\.)"), "External SMB",
    dest_port IN (445, 139) AND match(lower(dest_ip), "^(10\.|172\.|192\.168\.)"), "Internal SMB",
    dest_port=5985 OR dest_port=5986, "WinRM",
    dest_port=3389, "RDP",
    dest_port=135 OR (dest_port > 49000 AND dest_port < 65535), "RPC/WMI",
    1==1, null()
  )
| where isnotnull(is_lateral)
| stats count dc(dest_ip) as unique_targets
    min(_time) as firstTime max(_time) as lastTime
    values(dest_ip) as targets
    by dest user src_ip is_lateral dest_port
| where unique_targets >= 3
| eval severity=case(unique_targets >= 10, "critical", unique_targets >= 5, "high", 1==1, "medium")
| eval mitre_technique="T1021"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-NET-006 — DNS Tunneling Detection (Long/Randomized Subdomains)

```spl
index=edr sourcetype="qualys:edr:network"
  dns_query=*
| eval domain=lower(dns_query)
| eval subdomain=mvindex(split(domain, "."), 0)
| eval sub_length=len(subdomain)
| eval is_random=if(match(subdomain, "^[a-z0-9]{20,}$"), 1, 0)
| where sub_length >= 20 OR is_random=1
| stats count dc(domain) as unique_domains
    min(_time) as firstTime max(_time) as lastTime
    values(domain) as domains
    by dest user
| where count >= 10
| eval severity="high"
| eval mitre_technique="T1071.004"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

## 8. Registry Sourcetype — Correlation Searches <a name="registry-searches"></a>

### CS-REG-001 — Persistence via Run Key Modification

```spl
index=edr sourcetype="qualys:edr:registry"
  action IN ("CREATE","MODIFY")
| eval reg_lower=lower(registry_path)
| where match(reg_lower,
    "(\\software\\microsoft\\windows\\currentversion\\run|\\software\\microsoft\\windows\\currentversion\\runonce|\\software\\wow6432node\\microsoft\\windows\\currentversion\\run|\\currentversion\\policies\\explorer\\run)")
| where NOT match(lower(registry_value_data), "(windows defender|qualys|splunk|microsoft|symantec|crowdstrike)")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(registry_path) as reg_paths
    values(registry_value_data) as reg_values
    values(process) as processes
    by dest user
| eval severity="high"
| eval mitre_technique="T1547.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-REG-002 — Security Tool Tampering via Registry

```spl
index=edr sourcetype="qualys:edr:registry"
  action IN ("MODIFY","DELETE")
| eval reg_lower=lower(registry_path)
| eval tamper_match=case(
    match(reg_lower, "\\windows defender\\"), "Windows Defender",
    match(reg_lower, "\\currentversion\\policies\\system") AND match(lower(registry_value_name), "(enablelua|consentenabled|uac)"), "UAC Disabled",
    match(reg_lower, "\\software\\microsoft\\windows nt\\currentversion\\winlogon") AND match(lower(registry_value_name), "(userinit|shell)"), "Winlogon Hijack",
    match(reg_lower, "\\system\\currentcontrolset\\services") AND match(lower(registry_value_data), "(disabled|4)"), "Service Disabled",
    match(reg_lower, "\\lsa\\") AND match(lower(registry_value_name), "(lmcompatibilitylevel|nodefaultadminowner)"), "LSA Weakening",
    1==1, null()
  )
| where isnotnull(tamper_match)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(registry_path) as paths
    values(registry_value_data) as values
    by dest user tamper_match
| eval severity="critical"
| eval mitre_technique="T1562.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-REG-003 — COM Object Hijacking

```spl
index=edr sourcetype="qualys:edr:registry"
  action IN ("CREATE","MODIFY")
| eval reg_lower=lower(registry_path)
| where match(reg_lower, "\\software\\classes\\clsid\\")
  AND match(reg_lower, "(\\inprocserver32|\\localserver32)")
  AND NOT match(lower(registry_value_data), "(system32|syswow64|program files)")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(registry_path) as paths
    values(registry_value_data) as values
    values(process) as processes
    by dest user
| eval severity="high"
| eval mitre_technique="T1546.015"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-REG-004 — Boot/Startup Persistence via Registry

```spl
index=edr sourcetype="qualys:edr:registry"
  action IN ("CREATE","MODIFY")
| eval reg_lower=lower(registry_path)
| eval persist_type=case(
    match(reg_lower, "\\currentversion\\run"), "AutoRun Key",
    match(reg_lower, "\\currentversion\\runservicesonce"), "RunServicesOnce",
    match(reg_lower, "\\currentversion\\runservices"), "RunServices",
    match(reg_lower, "\\active setup\\installed components"), "Active Setup",
    match(reg_lower, "\\appinit_dlls"), "AppInit DLL",
    match(reg_lower, "\\boot execute"), "Boot Execute",
    match(reg_lower, "\\image file execution options") AND match(lower(registry_value_name), "debugger"), "IFEO Debugger Hijack",
    1==1, null()
  )
| where isnotnull(persist_type)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(registry_path) as paths
    values(registry_value_data) as values
    by dest user persist_type
| eval severity="high"
| eval mitre_technique="T1547"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

## 9. Cross-Sourcetype Correlation Searches <a name="cross-sourcetype"></a>

These are the most powerful searches — they correlate events across multiple sourcetypes to detect multi-stage attack chains.

### CS-CROSS-001 — Process then Network: C2 after Suspicious Execution

Detects a suspicious process execution followed within 10 minutes by outbound C2-like network activity from the same host.

```spl
| tstats count min(_time) as proc_time
    FROM datamodel=Endpoint.Processes
    WHERE index=edr sourcetype="qualys:edr:process"
          (process="*powershell*" OR process="*wscript*" OR process="*mshta*")
    BY dest user process
| eval window_start=proc_time, window_end=proc_time+600
| join type=inner dest [
    | tstats count sum(bytes_out) as total_bytes min(_time) as net_time
          FROM datamodel=Network_Traffic
          WHERE index=edr sourcetype="qualys:edr:network"
                dest_port IN (443, 8443, 80, 8080)
          BY dest src_ip dest_ip dest_port
  ]
| where net_time >= window_start AND net_time <= window_end
| stats count min(proc_time) as firstTime max(net_time) as lastTime
    values(process) as processes values(dest_ip) as c2_ips
    by dest user
| eval severity="high"
| eval mitre_technique="T1059,T1071"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-CROSS-002 — File Drop then Execution Chain

Detects a file write to a suspicious location immediately followed by execution of that same file.

```spl
index=edr (sourcetype="qualys:edr:file" OR sourcetype="qualys:edr:process")
| eval event_source=sourcetype
| eval file_name_norm=lower(coalesce(file_name, process))
| eval path_norm=lower(coalesce(file_path, process_path))
| stats values(event_source) as sources
    min(eval(if(sourcetype="qualys:edr:file", _time, null()))) as file_time
    min(eval(if(sourcetype="qualys:edr:process", _time, null()))) as exec_time
    values(eval(if(sourcetype="qualys:edr:file", file_hash_sha256, null()))) as file_hashes
    values(eval(if(sourcetype="qualys:edr:process", command_line, null()))) as commands
    by dest user file_name_norm
| where isnotnull(file_time) AND isnotnull(exec_time)
  AND exec_time >= file_time
  AND (exec_time - file_time) <= 300
| eval time_to_exec_seconds=exec_time - file_time
| eval severity="high"
| eval mitre_technique="T1204.002,T1059"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(file_time) ctime(exec_time)
```

---

### CS-CROSS-003 — Registry Persistence + Network C2 (Full Kill Chain)

Detects a persistence mechanism being established, then an outbound connection, on the same host within 30 minutes.

```spl
index=edr sourcetype="qualys:edr:registry"
  action IN ("CREATE","MODIFY")
| eval reg_lower=lower(registry_path)
| where match(reg_lower, "(\\run\\|\\runonce\\|\\services\\|appinit)")
| eval persist_time=_time
| join type=inner dest [
    search index=edr sourcetype="qualys:edr:network"
    | where NOT match(lower(dest_ip), "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
    | eval net_time=_time
    | table dest net_time dest_ip dest_port bytes_out
  ]
| where net_time >= persist_time AND (net_time - persist_time) <= 1800
| stats count min(persist_time) as firstTime max(net_time) as lastTime
    values(registry_path) as persist_paths
    values(dest_ip) as c2_candidates
    by dest user
| eval severity="critical"
| eval mitre_technique="T1547,T1071"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

### CS-CROSS-004 — Ransomware Kill Chain (Process + File + Registry)

```spl
index=edr
| eval src=sourcetype
| eval is_proc_suspicious=if(src="qualys:edr:process"
    AND match(lower(command_line), "(vssadmin|bcdedit|wbadmin|shadowcopy|delete shadow)"), 1, 0)
| eval is_file_encrypt=if(src="qualys:edr:file"
    AND action="RENAME"
    AND match(lower(file_name), "\.(encrypted|locked|crypt|enc|wncryt)$"), 1, 0)
| eval is_reg_tamper=if(src="qualys:edr:registry"
    AND match(lower(registry_path), "(\\run\\|\\defender\\|recoveryenabled)"), 1, 0)
| bin _time span=10m
| stats sum(is_proc_suspicious) as proc_hits
         sum(is_file_encrypt) as file_hits
         sum(is_reg_tamper) as reg_hits
         min(_time) as firstTime max(_time) as lastTime
    by dest user _time
| where proc_hits >= 1 AND (file_hits >= 5 OR reg_hits >= 1)
| eval ransomware_score=proc_hits + (file_hits*2) + (reg_hits*3)
| eval severity="critical"
| eval mitre_technique="T1486,T1490,T1562"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

## 10. Notable Event Creation <a name="notable-events"></a>

### 10.1 Standard Notable Event Configuration

For each correlation search in Splunk ES, configure the notable event with the following fields:

#### Required Settings

| Setting | Recommended Value |
|---|---|
| Name | `[CS-ID] - Search Name - $dest$` |
| Description | Dynamic: `$mitre_technique$ detected on $dest$ by $user$` |
| Security Domain | `Endpoint` (Process/File/Registry), `Network` (Network searches) |
| Severity | Mapped from `severity` field in search |
| Default Owner | Unassigned (queue for SOC) |
| Default Status | `New` |

#### Notable Event Field Mapping

```
Event Name:        $dest$ - [CS-ID] Alert
Drill-down Search: index=edr (sourcetype="qualys:edr:*") dest="$dest$" earliest=$firstTime$ latest=$lastTime$
Drill-down Name:   Investigate on $dest$
```

### 10.2 Adaptive Response Actions

Configure for high/critical severities:

```
1. Run Script: qualys_edr_isolate_host.py (host isolation)
2. Add to Threat Intel: Mark src_ip/dest_ip as suspicious
3. Splunk Phantom/SOAR: Trigger playbook "EDR_Triage_v2"
4. Email: SOC Alert Distribution List
```

### 10.3 Notable Event Field Extractions

Add these to your `transforms.conf` or ES field extractions:

```ini
[qualys_edr_notable_fields]
LOOKUP-mitre_desc = mitre_technique_lookup technique_id AS mitre_technique OUTPUT technique_name tactic
FIELDALIAS-dest_for_notable = host AS dest
EVAL-risk_score = case(severity="critical", 80, severity="high", 60, severity="medium", 40, severity="low", 20, 1==1, 10)
```

### 10.4 ES Notable Event Workflow

```
New Notable Event
      │
      ▼
Triage (Analyst reviews)
      │
      ├── False Positive → Close + Add Suppression
      ├── Needs More Info → Escalate to Tier 2
      └── Confirmed Threat
                │
                ▼
         Incident Created
                │
                ├── Isolate Host (via Qualys EDR)
                ├── Preserve Evidence (memory/disk)
                └── Full IR Workflow
```

---

## 11. Risk-Based Alerting (RBA) Integration <a name="rba"></a>

### 11.1 Risk Score Configuration

Map each correlation search to a risk modifier:

```spl
| makeresults
| eval rule_name="CS-PROC-001"
| eval risk_score=60
| eval risk_object=$dest$
| eval risk_object_type="system"
| eval threat_object=$user$
| eval threat_object_type="user"
| eval mitre_technique_id="T1566.001"
| outputlookup append=true risk_events
```

### 11.2 Risk Threshold Notable

Create a risk aggregation search that fires when cumulative risk exceeds a threshold:

```spl
index=risk sourcetype=stash
| tstats sum(risk_score) as total_risk
    count as event_count
    dc(rule_name) as unique_rules
    values(mitre_technique_id) as techniques
    min(_time) as firstTime max(_time) as lastTime
    by risk_object risk_object_type
| where total_risk >= 200
| eval severity=case(total_risk >= 500, "critical", total_risk >= 300, "high", 1==1, "medium")
| eval mitre_technique=mvjoin(techniques, ",")
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

---

## 12. Tuning & Suppression <a name="tuning"></a>

### 12.1 Suppression Rules Template

In Splunk ES, create suppressions using:

```
Name:       SUPPRESS-[CS-ID]-[Reason]
Search:     dest="*" user IN ("svc_qualys","svc_splunk","NT AUTHORITY\\SYSTEM")
Expiration: 90 days (review before renewal)
```

### 12.2 Allowlist Lookups

Maintain these CSV lookups and reference them in your searches:

```
approved_lolbin_use.csv     → dest, process, approved_use, approver
approved_run_keys.csv       → dest, registry_value_name, approved_value
approved_network_paths.csv  → dest, dest_ip, dest_port, approved_use
trusted_file_hashes.csv     → sha256, product_name, vendor
```

**Usage pattern in a search:**

```spl
| lookup approved_lolbin_use.csv dest process OUTPUT approved_use
| where isnull(approved_use)
```

### 12.3 Baseline-Based Suppression

For proc/network frequency searches, establish baselines using summarize:

```spl
index=edr sourcetype="qualys:edr:process"
| bucket _time span=1d
| stats count by dest process _time
| outputlookup process_baseline.csv append=true
```

Then reference in the detection:

```spl
| lookup process_baseline.csv dest process OUTPUT avg_daily_count
| eval deviation=abs(count - avg_daily_count) / (avg_daily_count + 1)
| where deviation >= 3
```

---

## 13. Dashboard & Triage Workflow <a name="dashboard"></a>

### 13.1 SOC Triage Dashboard — Key Panels

**Panel 1: Active Notable Events by Severity**
```spl
index=notable source=*es_notable*
| stats count by urgency rule_name
| sort -count
```

**Panel 2: MITRE ATT&CK Coverage Heatmap**
```spl
index=edr sourcetype="qualys:edr:*"
| stats count by mitre_technique
| lookup mitre_technique_lookup technique_id AS mitre_technique OUTPUT tactic technique_name
| chart count over tactic by technique_name
```

**Panel 3: Top Alerting Hosts (Last 24h)**
```spl
index=notable earliest=-24h
| stats count by dest
| sort -count
| head 20
```

**Panel 4: Alert Trend Over Time**
```spl
index=notable sourcetype=stash
| timechart span=1h count by urgency
```

**Panel 5: Qualys EDR Event Volume by Sourcetype**
```spl
index=edr sourcetype="qualys:edr:*"
| timechart span=1h count by sourcetype
```

### 13.2 Analyst Triage Checklist

When reviewing a notable event:

1. **Verify host context** — Is the host a server, workstation, or critical asset?
2. **Check user context** — Is the user privileged? Service account? Recently created?
3. **Review timeline** — Run the drill-down search; look for precursor events
4. **Cross-reference sourcetypes** — Process → File → Network → Registry for kill chain
5. **Check Qualys asset risk score** — High vulnerability score = higher priority
6. **Consult threat intel** — Look up any IPs, hashes, or domains in your TIP
7. **Determine scope** — Is this isolated to one host or spreading laterally?
8. **Take action** — Isolate / escalate / suppress as appropriate

---

## Appendix: Quick Reference — Search IDs & MITRE Mapping

| Search ID | Name | MITRE Technique | Severity |
|---|---|---|---|
| CS-PROC-001 | Suspicious Child Process from Office | T1566.001 | High |
| CS-PROC-002 | PowerShell Encoded Command | T1059.001 | High |
| CS-PROC-003 | LOLBin Abuse | T1218 | High |
| CS-PROC-004 | Process Injection Indicators | T1055 | Critical |
| CS-PROC-005 | Exec from Temp/Writable Path | T1059 | Medium |
| CS-PROC-006 | Credential Dumping Tools | T1003 | Critical |
| CS-PROC-007 | Abnormal Process Frequency | T1543 | Medium |
| CS-FILE-001 | Ransomware File Extension | T1486 | Critical |
| CS-FILE-002 | Mass File Deletion | T1485 | High |
| CS-FILE-003 | Executable Dropped in Temp | T1204.002 | High |
| CS-FILE-004 | Malicious Hash Match | T1204 | Critical |
| CS-FILE-005 | Sensitive File Access | T1552 | High |
| CS-NET-001 | DNS Beaconing | T1071.004 | Medium-Critical |
| CS-NET-002 | Connection to Malicious IP | T1071 | Critical |
| CS-NET-003 | Unusual Outbound Port | T1571 | Medium |
| CS-NET-004 | Large Outbound Transfer | T1041 | Medium-Critical |
| CS-NET-005 | Lateral Movement (SMB/RDP/WMI) | T1021 | Medium-Critical |
| CS-NET-006 | DNS Tunneling | T1071.004 | High |
| CS-REG-001 | Run Key Persistence | T1547.001 | High |
| CS-REG-002 | Security Tool Tampering | T1562.001 | Critical |
| CS-REG-003 | COM Object Hijacking | T1546.015 | High |
| CS-REG-004 | Boot/Startup Persistence | T1547 | High |
| CS-CROSS-001 | Suspicious Exec + C2 Network | T1059,T1071 | High |
| CS-CROSS-002 | File Drop + Execution | T1204.002,T1059 | High |
| CS-CROSS-003 | Registry Persist + C2 | T1547,T1071 | Critical |
| CS-CROSS-004 | Ransomware Kill Chain | T1486,T1490,T1562 | Critical |
