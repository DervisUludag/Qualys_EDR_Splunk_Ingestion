# Qualys EDR in Splunk — Beginner's Complete Guide
## Correlation Searches & Notable Events (Alarms) — Step by Step

---

> **Who this guide is for:** Security analysts and Splunk administrators who are new to
> Splunk Enterprise Security (ES) and want to build detections using Qualys EDR log data.
> No prior Splunk ES experience is required. Everything is explained from first principles.

---

## Table of Contents

1. [Understanding the Big Picture](#big-picture)
2. [Key Concepts Explained](#concepts)
3. [Your Data — What Qualys EDR Sends to Splunk](#your-data)
4. [How to Read SPL (Splunk Search Language)](#spl-basics)
5. [PART 1 — Creating Your First Correlation Search (Step by Step)](#part1)
6. [PART 2 — Creating Notable Events (Alarms) for Each Search](#part2)
7. [Process Searches — With Full Explanations](#process)
8. [File Searches — With Full Explanations](#file)
9. [Network Searches — With Full Explanations](#network)
10. [Registry Searches — With Full Explanations](#registry)
11. [Cross-Sourcetype Searches — Connecting the Dots](#cross)
12. [Testing & Validating Your Searches](#testing)
13. [Tuning — Reducing False Alarms](#tuning)
14. [Glossary](#glossary)

---

## 1. Understanding the Big Picture <a name="big-picture"></a>

### What is happening, and why does it matter?

Qualys EDR (Endpoint Detection & Response) is a security agent installed on every endpoint
in your organization. It records everything that happens on each computer:
- Which programs ran, and who started them
- Which files were created, changed, or deleted
- Which network connections were made
- Which registry keys were changed

All of this data is sent to Splunk, which stores it in searchable logs.

**The problem:** Splunk receives millions of events per day. You cannot manually read them all.
You need automated rules that watch for suspicious patterns and create an alarm when something
dangerous is detected.

**The solution:** Correlation Searches + Notable Events.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HOW IT ALL FITS TOGETHER                     │
│                                                                     │
│  Qualys EDR Agent          Splunk                  You (Analyst)   │
│  (on each computer)        (Security Platform)                      │
│                                                                     │
│  Sees: powershell.exe  →   Stores the log    →  Correlation Search  │
│  running with -enc flag    in index=edr           detects pattern   │
│                                                        │            │
│                                                        ▼            │
│                                                   Notable Event     │
│                                                   (Alarm) created   │
│                                                        │            │
│                                                        ▼            │
│                                                   You investigate   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Concepts Explained <a name="concepts"></a>

### What is a Correlation Search?

A **Correlation Search** is an automated SPL (Splunk search query) that runs on a schedule
(e.g., every 5 minutes). It looks for suspicious patterns in your log data. If the pattern
is found, it triggers an action — usually creating a **Notable Event** (an alarm).

Think of it like a smoke detector: it runs constantly in the background, and when it detects
something matching its rule (smoke = suspicious pattern), it triggers an alert.

### What is a Notable Event (Alarm)?

A **Notable Event** is an alarm that appears in the **Incident Review** dashboard in
Splunk Enterprise Security. It captures:
- What was detected (rule name + description)
- Where it happened (which computer/host)
- Who was involved (which user)
- When it happened (timestamp)
- How urgent it is (severity: Critical, High, Medium, Low)

Analysts review Notable Events in the Incident Review queue and decide whether each one
is a real threat or a false positive.

### What is Splunk Enterprise Security (ES)?

Splunk ES is a premium Splunk application built on top of standard Splunk. It adds:
- The **Correlation Search** editor (where you build detection rules)
- The **Incident Review** dashboard (where Notable Events appear)
- **Risk-Based Alerting** (cumulative risk scoring)
- Pre-built security frameworks (MITRE ATT&CK, CIM)

### What is a Sourcetype?

A **sourcetype** tells Splunk what format the log is in and where it came from. Your
Qualys EDR data arrives in four sourcetypes:

| Sourcetype | What it contains |
|---|---|
| `qualys:edr:process` | Every program that started or stopped on an endpoint |
| `qualys:edr:file` | Every file that was created, modified, deleted, or renamed |
| `qualys:edr:network` | Every network connection made from an endpoint |
| `qualys:edr:registry` | Every Windows registry key that was read, created, or changed |

### What is SPL?

SPL = **Splunk Processing Language**. It is the query language you use to search and
analyze your log data. It reads left to right, and each step is separated by a pipe `|`.

---

## 3. Your Data — What Qualys EDR Sends to Splunk <a name="your-data"></a>

Before building searches, it's important to understand exactly what fields exist in
your logs. Run these discovery queries in Splunk to explore your data.

### Step 1 — Confirm your data is arriving

Open Splunk → Click **Search & Reporting** → Paste this:

```spl
index=edr sourcetype="qualys:edr:process"
| head 5
```

> **What this does:** Looks in the `edr` index for process events and shows the 5 most
> recent ones. If you see results, your data is flowing correctly.
> If you see nothing, check your index name with your Splunk admin — it may be different
> (e.g., `qualys_edr`, `edr_logs`).

### Step 2 — See all available fields

```spl
index=edr sourcetype="qualys:edr:process"
| fieldsummary
| table field count distinct_count
| sort -count
```

> **What this does:** Lists every field in your process logs, how many events have that
> field, and how many unique values exist. This helps you understand what data you have.

### Step 3 — Explore a single event in detail

```spl
index=edr sourcetype="qualys:edr:process"
| head 1
| transpose
```

> **What this does:** Takes one single event and shows all its field names and values in
> a vertical table — like reading one row of a spreadsheet with labels on the left.

### Key Fields You Will Use in Every Search

| Field Name | What it means | Example Value |
|---|---|---|
| `dest` or `host` | The computer where the event happened | `WORKSTATION-01` |
| `user` | The Windows account that performed the action | `DOMAIN\jsmith` |
| `_time` | When the event occurred | `2024-01-15 14:32:11` |
| `process` | The executable that ran (process sourcetype) | `powershell.exe` |
| `process_path` | Full path to the executable | `C:\Windows\System32\powershell.exe` |
| `command_line` | The full command including arguments | `powershell.exe -enc SGVsbG8=` |
| `parent_process` | The program that launched this process | `winword.exe` |
| `file_name` | Name of the file affected (file sourcetype) | `malware.exe` |
| `file_path` | Full path to the file | `C:\Temp\malware.exe` |
| `action` | What happened to the file or registry key | `CREATE`, `MODIFY`, `DELETE` |
| `dest_ip` | IP address connected to (network sourcetype) | `185.220.101.5` |
| `dest_port` | Port connected to | `4444` |
| `registry_path` | Full Windows registry path changed | `HKLM\SOFTWARE\...\Run` |
| `severity` | Qualys-assigned severity of the event | `HIGH`, `CRITICAL` |

---

## 4. How to Read SPL (Splunk Search Language) <a name="spl-basics"></a>

Every search in this guide follows the same pattern. Once you understand it,
all the searches will make sense.

### SPL is a Pipeline

Each line starting with `|` is a new step that transforms the data:

```
index=edr sourcetype="qualys:edr:process"   ← STEP 1: Get the raw data
| where match(lower(process), "powershell")  ← STEP 2: Filter to only matching rows
| eval cmd=lower(command_line)               ← STEP 3: Create/transform a field
| stats count by dest user                   ← STEP 4: Summarize/aggregate
| where count >= 3                           ← STEP 5: Apply a threshold
```

### Common SPL Commands Explained

**`index=edr`** — Selects which bucket of data to search (like choosing a database table).

**`sourcetype="qualys:edr:process"`** — Filters to only one type of log.

**`| where`** — Filters rows, like a SQL WHERE clause. Only rows matching the condition pass through.

**`| eval`** — Creates a new field or modifies an existing one. Example:
`| eval cmd=lower(command_line)` creates a new field called `cmd` that is the
`command_line` field converted to lowercase (so matching is case-insensitive).

**`| stats count by dest user`** — Counts events and groups them by computer and user.
This turns millions of raw events into a summary table.

**`| match(field, "pattern")`** — Checks if a field matches a regular expression pattern.
Example: `match(process, "(cmd|powershell)")` matches any process containing "cmd" or "powershell".

**`| convert ctime(firstTime)`** — Converts a raw epoch timestamp number into a
human-readable date string like `2024-01-15T14:32:11`.

**`min(_time) as firstTime max(_time) as lastTime`** — Finds the earliest and latest
event time in the results.

**`values(field)`** — Collects all unique values of a field into a list.

---

## 5. PART 1 — Creating Your First Correlation Search (Step by Step) <a name="part1"></a>

This section walks you through the Splunk ES user interface to create a correlation search.
We will use **CS-PROC-001** (Suspicious Child Process from Office) as the example.

---

### Step 1 — Open Splunk Enterprise Security

1. Log in to Splunk.
2. In the top navigation bar, click on the **app selector** (the grid icon or app name).
3. Click **Enterprise Security**.
4. You are now in the ES home screen.

---

### Step 2 — Navigate to Correlation Searches

1. In the ES top menu bar, click **Configure**.
2. In the dropdown, click **Content Management**.
3. You will see a list of all existing correlation searches.
4. Click the green **Create New Content** button in the top right.
5. Select **Correlation Search** from the dropdown.

---

### Step 3 — Fill in the General Information Tab

You will see a form with several tabs. Start on the **General** tab:

| Field | What to type | Example for CS-PROC-001 |
|---|---|---|
| **Name** | Short unique ID + description | `CS-PROC-001 - Suspicious Child Process from Office Apps` |
| **Description** | What this detects and why it matters | `Detects cmd, powershell, or scripting engines spawned by Office applications. This is a strong indicator of malicious macro execution (phishing stage).` |
| **App Context** | Leave default | `SplunkEnterpriseSecuritySuite` |
| **Search Type** | Leave as | `Real-time` or `Scheduled` |

---

### Step 4 — Enter the Search Query

Still on the General tab, find the large **Search** text box. Paste your SPL here:

```spl
index=edr sourcetype="qualys:edr:process"
| eval parent=lower(parent_process)
| eval child=lower(process)
| where match(parent, "(winword|excel|powerpnt|outlook|onenote)\.exe")
  AND match(child, "(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe")
| stats count
    min(_time) as firstTime
    max(_time) as lastTime
    values(command_line) as command_lines
    values(child) as child_processes
    by dest user parent
| where count >= 1
| eval severity="high"
| eval mitre_technique="T1566.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Line-by-line explanation of this search:**

```
index=edr sourcetype="qualys:edr:process"
```
→ Pull data from the EDR index, process events only.

```
| eval parent=lower(parent_process)
```
→ Take the `parent_process` field, convert it to lowercase, store in `parent`.
  We use lowercase so that "WINWORD.EXE" and "winword.exe" both match.

```
| eval child=lower(process)
```
→ Same thing for the child process (the one that was launched).

```
| where match(parent, "(winword|excel|powerpnt|outlook|onenote)\.exe")
```
→ Keep only events where the parent was an Office application.
  The `\.` is regex for a literal dot (because `.` alone means "any character").

```
  AND match(child, "(cmd|powershell|wscript|cscript|mshta|rundll32|...)\.exe")
```
→ AND the child process must be a known dangerous executable.
  These are programs attackers commonly use after exploiting a macro.

```
| stats count min(_time) as firstTime max(_time) as lastTime
    values(command_line) as command_lines
    values(child) as child_processes
    by dest user parent
```
→ Summarize: for each unique combination of (computer + user + parent process),
  count how many times this happened, find the first and last time,
  and collect all the command lines and child process names seen.

```
| where count >= 1
```
→ Trigger even on a single occurrence (this is a high-confidence indicator;
  even one occurrence warrants investigation).

```
| eval severity="high"
| eval mitre_technique="T1566.001"
```
→ Tag the result with a severity level and MITRE ATT&CK technique ID.
  These fields will appear in the Notable Event.

```
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```
→ Convert the epoch time numbers (like 1705329131) into readable strings.

---

### Step 5 — Set the Schedule

Scroll down on the General tab to find **Schedule**:

| Setting | Value | Why |
|---|---|---|
| **Cron Expression** | `*/15 * * * *` | Runs every 15 minutes |
| **Earliest Time** | `-20m` | Looks back 20 minutes |
| **Latest Time** | `-5m` | Up to 5 minutes ago (gives Splunk time to index) |

> **Cron Cheat Sheet:**
> - `*/5 * * * *` = Every 5 minutes (Critical searches)
> - `*/15 * * * *` = Every 15 minutes (High searches)
> - `0 * * * *` = Every hour (Medium searches)

---

### Step 6 — Set the Trigger Condition

Still scrolling down, find **Trigger Conditions**:

| Setting | Value |
|---|---|
| **Trigger Alert** | `For each result` |
| **Throttle** | Check the "Throttle" checkbox |
| **Throttle field** | `dest` |
| **Throttle window** | `600` (seconds = 10 minutes) |

> **What throttling does:** If the same computer (`dest`) triggers this search multiple
> times within 10 minutes, only ONE notable event is created. This prevents you from
> getting 50 identical alarms for the same incident.

---

### Step 7 — Configure the Notable Event (Alarm)

Click the **Adaptive Response Actions** tab. Then click **Add New Response Action**
and select **Notable Event**.

Fill in the Notable Event fields:

| Field | What to enter | Example |
|---|---|---|
| **Title** | Dynamic name using `$field$` syntax | `Suspicious Child Process on $dest$ by $user$` |
| **Security Domain** | Category of this threat | `Endpoint` |
| **Severity** | Maps from your `severity` field | Select `$severity$` |
| **Default Status** | Where it starts in the queue | `New` |
| **Default Owner** | Who gets it first | `Unassigned` |
| **Drill-down Name** | Label for the investigation link | `Investigate $dest$ in EDR logs` |
| **Drill-down Search** | SPL to run when analyst clicks | (see below) |

**Drill-down Search** (pastes into Incident Review for the analyst):
```spl
index=edr (sourcetype="qualys:edr:process" OR sourcetype="qualys:edr:file")
dest="$dest$"
earliest="$firstTime$" latest="$lastTime$"
| table _time user process parent_process command_line file_path action
| sort _time
```

> **What drill-down does:** When an analyst clicks "Investigate" in the Incident Review
> dashboard, this search automatically runs with the specific computer name and time range
> pre-filled. The analyst sees exactly what happened on that machine during the incident.

---

### Step 8 — Save and Enable

1. Scroll to the bottom and click **Save**.
2. You will be taken back to the Content Management list.
3. Find your new search in the list.
4. Toggle the **Enabled** switch to ON (green).
5. Your correlation search is now live and will run on its next scheduled interval.

---

### Step 9 — Test It Manually

1. Go back to your correlation search in Content Management.
2. Click the **Run** button (play icon) next to your search.
3. Splunk will run it immediately and show you results (if any exist in your data).
4. If results appear, click **Create Notable Event** to manually fire a test alarm.

---

## 6. PART 2 — Understanding Notable Event Fields in Detail <a name="part2"></a>

### The Incident Review Dashboard

After creating notable events, you find them at:
**ES Menu → Incident Review**

The dashboard shows:

```
┌────────────────────────────────────────────────────────────────────────┐
│  INCIDENT REVIEW                                                        │
├──────────┬────────────────────────┬──────────┬────────┬────────────────┤
│  Time    │  Title                 │  Urgency │ Status │  Owner         │
├──────────┼────────────────────────┼──────────┼────────┼────────────────┤
│ 14:32:11 │ Suspicious Child Proc  │  HIGH    │  New   │  Unassigned    │
│          │ on WORKSTATION-01 by   │          │        │                │
│          │ DOMAIN\jsmith          │          │        │                │
├──────────┼────────────────────────┼──────────┼────────┼────────────────┤
│ 14:28:05 │ PowerShell Encoded Cmd │ CRITICAL │  New   │  Unassigned    │
│          │ on SERVER-02           │          │        │                │
└──────────┴────────────────────────┴──────────┴────────┴────────────────┘
```

### Notable Event Status Workflow

```
NEW → ASSIGNED → IN PROGRESS → RESOLVED (True Positive)
                             → CLOSED   (False Positive)
```

When you click on a notable event, you can:
- **Assign** it to an analyst
- **Add comments** documenting your investigation
- **Change status** as you investigate
- **Run the drill-down search** to see raw events
- **Create an Incident** if it's a real threat

---

## 7. Process Searches — With Full Explanations <a name="process"></a>

---

### CS-PROC-001 — Suspicious Child Process from Office Applications

**What threat does this detect?**
When an attacker sends a malicious Word or Excel document with an embedded macro (VBA code),
and the victim opens it and enables macros, the macro can silently launch dangerous programs
like `cmd.exe` or `powershell.exe`. This is one of the most common phishing attack techniques.

**Why is this suspicious?**
Microsoft Word should NEVER need to open a command prompt or PowerShell window under normal
business operations. If you see `winword.exe` spawning `cmd.exe`, something is very wrong.

**MITRE ATT&CK Technique:** T1566.001 — Phishing: Spearphishing Attachment

**Step-by-step creation:**

1. Go to ES → Configure → Content Management → Create New Content → Correlation Search
2. **Name:** `CS-PROC-001 - Suspicious Child Process from Office Applications`
3. **Description:** `Detects command shells or scripting engines launched by Microsoft Office processes. Indicates likely malicious macro execution from a phishing document.`
4. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:process"

| eval parent=lower(parent_process)
| eval child=lower(process)

| where match(parent, "(winword|excel|powerpnt|outlook|onenote)\.exe")
  AND match(child, "(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe")

| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(command_line) as command_lines
    values(child) as child_processes
    by dest user parent

| where count >= 1
| eval severity="high"
| eval mitre_technique="T1566.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

5. **Schedule:** Cron `*/15 * * * *` | Earliest `-20m` | Latest `-5m`
6. **Trigger:** For each result | Throttle on `dest` for `600` seconds
7. **Notable Event:**
   - Title: `CS-PROC-001: Office App Spawned Shell on $dest$ by $user$`
   - Severity: `High`
   - Domain: `Endpoint`
8. **Save and Enable.**

**What a real alert looks like:**

```
dest:         WORKSTATION-04
user:         DOMAIN\marketing.mgr
parent:       winword.exe
child:        powershell.exe
command_line: powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdA...
firstTime:    2024-01-15T09:14:22
lastTime:     2024-01-15T09:14:22
```

**How to investigate:** Check if the user recently received an email with a Word attachment.
Look at the base64-encoded command (the `-enc` flag value) — decode it to see what it does.
Check if any files were written to disk immediately after (`CS-FILE-003` may also fire).

---

### CS-PROC-002 — PowerShell Encoded Command Execution

**What threat does this detect?**
Attackers frequently use PowerShell because it is a powerful, built-in Windows tool.
To hide what their code does, they Base64-encode the commands so they appear as
random-looking strings. The `-EncodedCommand` (or `-enc`) flag tells PowerShell to
decode and run a Base64 string. Legitimate scripts rarely need to do this.

**MITRE ATT&CK Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Step-by-step creation:**

1. Go to ES → Configure → Content Management → Create New Content → Correlation Search
2. **Name:** `CS-PROC-002 - PowerShell Encoded Command Execution`
3. **Description:** `Detects PowerShell launched with Base64-encoded commands (-enc/-EncodedCommand), a common obfuscation technique used by malware and post-exploitation frameworks like Cobalt Strike and Metasploit.`
4. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:process"
  process="*powershell*"

| eval cmd_lower=lower(command_line)

| where match(cmd_lower, "(-enc\s|-encodedcommand\s|-e\s[A-Za-z])")
   OR  (len(cmd_lower) > 500 AND match(cmd_lower, "[A-Za-z0-9+/]{50,}={0,2}"))

| eval base64_detected=if(match(cmd_lower, "[A-Za-z0-9+/]{100,}={0,2}"), "YES", "POSSIBLE")

| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(command_line) as command_lines
    by dest user process base64_detected

| eval severity="high"
| eval mitre_technique="T1059.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Explanation of the filter logic:**

```
match(cmd_lower, "(-enc\s|-encodedcommand\s|-e\s[A-Za-z])")
```
→ Catches the explicit `-EncodedCommand` flag (and its common abbreviations `-enc`, `-e`).
  The `\s` means "followed by a space" (so `-encrypt` won't accidentally match).

```
OR (len(cmd_lower) > 500 AND match(cmd_lower, "[A-Za-z0-9+/]{50,}={0,2}"))
```
→ Also catches very long commands containing what looks like Base64 (50+ consecutive
  Base64 characters). The `={0,2}` is the Base64 padding at the end.

```
| eval base64_detected=if(..., "YES", "POSSIBLE")
```
→ Creates a field telling the analyst how confident we are.

5. **Schedule:** `*/15 * * * *` | `-20m` to `-5m`
6. **Trigger:** For each result | Throttle `dest` for `300` seconds
7. **Notable Event:**
   - Title: `CS-PROC-002: PowerShell Encoded Command on $dest$ by $user$`
   - Severity: `High`
8. **Save and Enable.**

---

### CS-PROC-003 — Living-off-the-Land Binary (LOLBin) Abuse

**What threat does this detect?**
"Living off the Land" means attackers use legitimate Windows tools instead of malware,
because security software often allows them. For example, `certutil.exe` is a certificate
management tool — but attackers use it to download malware from the internet. This search
detects these tools being used in suspicious ways.

**MITRE ATT&CK Technique:** T1218 — System Binary Proxy Execution

**Step-by-step creation:**

1. Go to ES → Configure → Content Management → Create New Content → Correlation Search
2. **Name:** `CS-PROC-003 - LOLBin Abuse Detection`
3. **Description:** `Detects Windows built-in tools (certutil, mshta, regsvr32, etc.) being used in ways consistent with malware delivery or execution. These are 'Living off the Land' techniques where attackers abuse legitimate system binaries.`
4. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:process"

| eval proc=lower(process)
| eval cmd=lower(command_line)

| eval lolbin_match=case(
    match(proc, "certutil\.exe")
      AND match(cmd, "(-urlcache|-decode|-encode|http)"),
      "certutil: Download or encode/decode operation",

    match(proc, "mshta\.exe")
      AND match(cmd, "(http|vbscript|javascript)"),
      "mshta: Executing remote or inline script",

    match(proc, "regsvr32\.exe")
      AND match(cmd, "(/s|scrobj|http)"),
      "regsvr32: Squiblydoo technique (remote DLL registration)",

    match(proc, "rundll32\.exe")
      AND match(cmd, "(javascript|http|shell32)"),
      "rundll32: Executing script or remote content",

    match(proc, "bitsadmin\.exe")
      AND match(cmd, "(transfer|/download|http)"),
      "bitsadmin: File download via BITS service",

    match(proc, "wmic\.exe")
      AND match(cmd, "(process call create|/node|http)"),
      "wmic: Remote execution or download",

    match(proc, "msiexec\.exe")
      AND match(cmd, "(http|/q|/i.+http)"),
      "msiexec: Silent remote installer",

    1==1, null()
  )

| where isnotnull(lolbin_match)

| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(command_line) as command_lines
    values(lolbin_match) as techniques
    by dest user proc

| eval severity="high"
| eval mitre_technique="T1218"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Explanation of `eval lolbin_match=case(...)`:**

The `case()` function works like a series of if/else checks. It evaluates each condition
from top to bottom. When a condition is true, it assigns that text as the value.
If nothing matches, `null()` is returned (meaning this event is not a LOLBin alert).

The `| where isnotnull(lolbin_match)` then filters out all rows where nothing matched.

5. **Schedule:** `*/15 * * * *` | `-20m` to `-5m`
6. **Trigger:** For each result | Throttle `dest` for `600` seconds
7. **Notable Event:**
   - Title: `CS-PROC-003: LOLBin Abuse - $proc$ on $dest$ by $user$`
   - Severity: `High`
8. **Save and Enable.**

---

### CS-PROC-004 — Credential Dumping Tool Execution

**What threat does this detect?**
After gaining initial access, attackers try to steal passwords stored in memory.
The most famous tool for this is **Mimikatz**, which can extract passwords from
the Windows LSASS process. This search looks for Mimikatz by name, by its known
commands, and by other tools that access LSASS memory.

**MITRE ATT&CK Technique:** T1003 — OS Credential Dumping

**Step-by-step creation:**

1. Go to ES → Configure → Content Management → Create New Content → Correlation Search
2. **Name:** `CS-PROC-004 - Credential Dumping Tool Execution`
3. **Description:** `Detects execution of Mimikatz and other credential harvesting tools. Also detects LSASS memory access via legitimate tools like ProcDump. Credentials stolen here are used for lateral movement.`
4. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:process"

| eval proc=lower(process)
| eval cmd=lower(command_line)

| eval cred_indicator=case(
    match(proc, "(mimikatz|mimilib|mimidump)"),
      "Mimikatz binary executed",

    match(cmd, "(sekurlsa::|lsadump::|kerberos::)"),
      "Mimikatz module command detected in command line",

    match(proc, "procdump") AND match(cmd, "lsass"),
      "ProcDump targeting LSASS process (credential dump)",

    match(cmd, "lsass\.exe") AND match(proc, "(taskmgr|rundll32|ntdsutil)"),
      "Suspicious LSASS access via unexpected process",

    match(proc, "ntdsutil") AND match(cmd, "(snapshot|activate|ac i)"),
      "NTDS.dit database dump attempt (Active Directory credentials)",

    match(cmd, "(gsecdump|pwdump|wce\.exe|fgdump|samdump)"),
      "Known password dumping utility",

    1==1, null()
  )

| where isnotnull(cred_indicator)

| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(command_line) as command_lines
    by dest user proc cred_indicator

| eval severity="critical"
| eval mitre_technique="T1003"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

5. **Schedule:** `*/5 * * * *` | `-6m` to `-1m`

> For **Critical** severity searches, run every 5 minutes so you catch attacks fast.

6. **Trigger:** For each result | Throttle `dest` for `300` seconds
7. **Notable Event:**
   - Title: `CRITICAL: Credential Dump Attempted on $dest$ by $user$`
   - Severity: `Critical`
   - Default Owner: Assign to your senior analyst or IR team
8. **Save and Enable.**

---

### CS-PROC-005 — Suspicious Process Execution from Temp/Writable Directories

**What threat does this detect?**
Legitimate software is almost always installed in `C:\Program Files` or `C:\Windows`.
Malware, on the other hand, is often dropped into world-writable locations like `C:\Temp`,
`C:\Users\...\AppData\Local\Temp`, or `C:\ProgramData` — places where any user can write
files without needing administrator privileges. Executing programs from these locations
is very suspicious.

**MITRE ATT&CK Technique:** T1059 — Command and Scripting Interpreter

**Step-by-step creation:**

1. **Name:** `CS-PROC-005 - Executable Launched from Temp or Writable Directory`
2. **Description:** `Detects executables, scripts, or DLLs running from non-standard, user-writable locations. Malware commonly drops itself to Temp or AppData directories to avoid detection and bypass restrictions on Program Files.`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:process"

| eval path_lower=lower(process_path)
| eval proc_lower=lower(process)

| where match(path_lower,
    "(\\temp\\|\\tmp\\|\\appdata\\local\\temp\\|\\downloads\\|\\public\\|\\programdata\\[^\\]+\\[^\\]+\.exe)")
  AND match(proc_lower, "\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr|pif)$")
  AND NOT match(proc_lower, "(installer|setup|update|patch|msiexec)")
  AND NOT match(lower(user), "(system|service|nt authority)")

| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(process_path) as execution_paths
    values(command_line) as commands
    by dest user process

| eval severity="medium"
| eval mitre_technique="T1059"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Key exclusion explained:**

```
AND NOT match(proc_lower, "(installer|setup|update|patch|msiexec)")
```
→ Legitimate software installers do run from Temp directories. Excluding them reduces
  false positives from normal software installations and Windows Update.

```
AND NOT match(lower(user), "(system|service|nt authority)")
```
→ Some Windows system services legitimately run from non-standard paths. Excluding
  SYSTEM and service accounts reduces noise.

4. **Schedule:** `0 * * * *` (hourly) | `-65m` to `-5m`
5. **Trigger:** For each result | Throttle `dest,user` for `1800` seconds
6. **Notable Event:**
   - Title: `CS-PROC-005: Process from Suspicious Location on $dest$ by $user$`
   - Severity: `Medium`
7. **Save and Enable.**

---

## 8. File Sourcetype — Correlation Searches <a name="file"></a>

---

### CS-FILE-001 — Ransomware File Extension Activity

**What threat does this detect?**
Ransomware works by encrypting your files and renaming them with a new extension (e.g.,
`document.docx` becomes `document.docx.wncry`). This search watches for mass file
renames where the new extension matches known ransomware families. Even catching
a few renames can alert you before all files are encrypted.

**MITRE ATT&CK Technique:** T1486 — Data Encrypted for Impact

**Step-by-step creation:**

1. **Name:** `CS-FILE-001 - Ransomware File Extension Detected`
2. **Description:** `Detects file rename or create operations resulting in extensions matching known ransomware families (WannaCry, Ryuk, Conti, etc.). Triggering on 3+ events catches early-stage encryption before full damage occurs.`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:file"
  action IN ("RENAME", "MODIFY", "CREATE")

| eval new_ext=lower(mvindex(split(file_name, "."), -1))

| eval ransomware_family=case(
    match(new_ext, "(wncry|wncryt|wcry)"),
      "WannaCry",

    match(new_ext, "(locky|zepto|odin|osiris|aesir|thor|zzzzz)"),
      "Locky Family",

    match(new_ext, "(cerber|cerber2|cerber3)"),
      "Cerber",

    match(new_ext, "(encrypted|enc|crypt|locked|crypto|cryp1|crypz)"),
      "Generic Ransomware Encryption Extension",

    match(new_ext, "(ryuk|ryk)"),
      "Ryuk",

    match(new_ext, "(conti|conto)"),
      "Conti",

    match(new_ext, "(revil|sodinokibi|sodin)"),
      "REvil / Sodinokibi",

    1==1, null()
  )

| where isnotnull(ransomware_family)

| stats
    count
    dc(file_name) as unique_files_affected
    min(_time) as firstTime
    max(_time) as lastTime
    values(file_name) as sample_files
    by dest user ransomware_family

| where count >= 3

| eval severity="critical"
| eval mitre_technique="T1486"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Key logic explained:**

```
| eval new_ext=lower(mvindex(split(file_name, "."), -1))
```
→ `split(file_name, ".")` splits the filename into parts by the dot.
  `mvindex(..., -1)` takes the LAST part (the extension).
  Example: `"report.docx.wncry"` → split gives `["report", "docx", "wncry"]` → last is `"wncry"`.

```
| where count >= 3
```
→ Require at least 3 files to match before firing. This prevents a single accidental
  file rename from creating a false alarm.

4. **Schedule:** `*/5 * * * *` | `-6m` to `-1m`
5. **Trigger:** For each result | Throttle `dest` for `300` seconds
6. **Notable Event:**
   - Title: `CRITICAL: Ransomware Activity Detected on $dest$ - $ransomware_family$`
   - Severity: `Critical`
7. **Save and Enable.**

---

### CS-FILE-002 — Mass File Deletion

**What threat does this detect?**
Deleting many files rapidly can indicate ransomware (deleting originals after encryption),
an insider threat destroying data, or an attacker covering their tracks. Fifty or more
unique file paths deleted within 5 minutes is highly abnormal for any regular user.

**MITRE ATT&CK Technique:** T1485 — Data Destruction

**Step-by-step creation:**

1. **Name:** `CS-FILE-002 - Mass File Deletion Activity`
2. **Description:** `Detects 50 or more unique file deletions from a single user on a single host within a 5-minute window. Indicates possible ransomware, sabotage, or anti-forensic cleanup.`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:file"
  action="DELETE"

| bin _time span=5m

| stats
    count
    dc(file_path) as unique_paths_deleted
    min(_time) as firstTime
    max(_time) as lastTime
    values(file_path) as sample_paths
    by dest user _time

| where unique_paths_deleted >= 50

| eval severity=case(
    unique_paths_deleted >= 500, "critical",
    unique_paths_deleted >= 200, "high",
    1==1, "medium"
  )

| eval mitre_technique="T1485"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Key logic explained:**

```
| bin _time span=5m
```
→ Groups events into 5-minute buckets. All events within the same 5-minute window
  are counted together. This prevents a slow deletion spread over hours from triggering,
  while catching rapid mass deletion.

```
| eval severity=case(
    unique_paths_deleted >= 500, "critical",
    unique_paths_deleted >= 200, "high",
    1==1, "medium"
  )
```
→ Dynamic severity: the more files deleted, the higher the urgency.

4. **Schedule:** `*/5 * * * *` | `-6m` to `-1m`
5. **Trigger:** For each result | Throttle `dest` for `300` seconds
6. **Notable Event:**
   - Title: `CS-FILE-002: Mass Deletion on $dest$ - $unique_paths_deleted$ Files Deleted`
   - Severity: `$severity$`
7. **Save and Enable.**

---

### CS-FILE-003 — Executable Dropped in Suspicious Location

**What threat does this detect?**
When malware is delivered, it often saves itself (or secondary payloads) to writable
directories. This search detects when executable files (`.exe`, `.dll`, `.ps1`, etc.)
are CREATED or MODIFIED in locations that regular software should not be writing programs to.

**MITRE ATT&CK Technique:** T1204.002 — User Execution: Malicious File

**Step-by-step creation:**

1. **Name:** `CS-FILE-003 - Executable Dropped in Suspicious Directory`
2. **Description:** `Detects creation or modification of executable files, scripts, or DLLs in Temp, AppData, or other non-standard locations. Malware commonly stages itself in these writable directories to evade AV and gain persistence.`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:file"
  action IN ("CREATE", "MODIFY")

| eval path_lower=lower(file_path)
| eval ext_lower=lower(mvindex(split(file_name, "."), -1))

| where match(ext_lower, "(exe|dll|sys|drv|ocx|scr|bat|cmd|ps1|vbs|hta|jar|py)")
  AND match(path_lower,
      "(\\temp\\|\\appdata\\local\\temp|\\appdata\\roaming\\|\\public\\|\\programdata\\|\\windows\\temp|\\recycle\.bin)")
  AND NOT match(path_lower,
      "(\\windows\\installer\\|\\windows\\softwaredistribution\\|splunk|qualys|defender)")

| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(file_path) as suspicious_paths
    values(file_hash_sha256) as sha256_hashes
    by dest user file_name ext_lower

| eval severity="high"
| eval mitre_technique="T1204.002"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

4. **Schedule:** `*/15 * * * *` | `-20m` to `-5m`
5. **Trigger:** For each result | Throttle `dest,file_name` for `3600` seconds

> Throttle on BOTH `dest` AND `file_name` so the same file being written on the same
> machine only creates one alert, but the same file on a different machine DOES alert.

6. **Notable Event:**
   - Title: `CS-FILE-003: Suspicious Executable Dropped on $dest$ - $file_name$`
   - Severity: `High`
7. **Save and Enable.**

---

## 9. Network Sourcetype — Correlation Searches <a name="network"></a>

---

### CS-NET-001 — DNS Beaconing Detection

**What threat does this detect?**
After infecting a machine, malware needs to communicate with its command-and-control (C2)
server. One method is DNS beaconing: the malware sends DNS queries to a domain it controls
at regular intervals (like a heartbeat). High-frequency DNS queries to the same domain,
especially one not in your allowlist, is a strong C2 indicator.

**MITRE ATT&CK Technique:** T1071.004 — Application Layer Protocol: DNS

**Step-by-step creation:**

1. **Name:** `CS-NET-001 - DNS Beaconing Detection`
2. **Description:** `Detects an endpoint making 100 or more DNS queries to the same domain within one hour, consistent with C2 beaconing via DNS. Excludes common legitimate domains (Microsoft, Google, AWS, etc.).`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:network"
  dns_query=*

| eval domain=lower(dns_query)

| where NOT match(domain,
    "(\.microsoft\.com|\.windows\.com|\.office\.com|\.live\.com|\.msftncsi\.com|
      \.google\.com|\.googleapis\.com|\.gstatic\.com|
      \.amazon\.com|\.amazonaws\.com|\.cloudfront\.net|
      \.qualys\.com|\.splunk\.com|\.windowsupdate\.com)")

| bin _time span=1h

| stats
    count as query_count
    dc(src_ip) as source_ip_count
    min(_time) as firstTime
    max(_time) as lastTime
    by dest domain _time

| where query_count >= 100 AND source_ip_count <= 2

| eval beacon_rate_per_minute=round(query_count/60, 2)

| eval severity=case(
    query_count >= 500, "critical",
    query_count >= 200, "high",
    1==1, "medium"
  )

| eval mitre_technique="T1071.004"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Key logic explained:**

```
| where query_count >= 100 AND source_ip_count <= 2
```
→ We want HIGH volume from FEW sources. If 100 DNS queries for the same domain come
  from 50 different IPs, that's normal (many people using a popular service). But if
  100 queries come from just 1–2 machines, that's beaconing behavior.

```
| eval beacon_rate_per_minute=round(query_count/60, 2)
```
→ Calculates the average queries per minute, making it easier for analysts to visualize
  the beacon interval (e.g., 2.0 queries/min = one query every 30 seconds).

4. **Schedule:** `0 * * * *` | `-65m` to `-5m`
5. **Trigger:** For each result | Throttle `dest,domain` for `3600` seconds
6. **Notable Event:**
   - Title: `CS-NET-001: DNS Beaconing from $dest$ to $domain$ ($query_count$ queries)`
   - Severity: `$severity$`
7. **Save and Enable.**

---

### CS-NET-002 — Lateral Movement (SMB/RDP/WMI to Multiple Hosts)

**What threat does this detect?**
After compromising one machine, attackers move to other machines (lateral movement).
They commonly use SMB (file sharing, port 445), RDP (remote desktop, port 3389), or
WMI/WinRM. Connecting to many internal hosts in a short time from one machine is
a strong indicator of lateral movement — normal users don't connect to 3+ machines
simultaneously this way.

**MITRE ATT&CK Technique:** T1021 — Remote Services

**Step-by-step creation:**

1. **Name:** `CS-NET-002 - Lateral Movement via Remote Services`
2. **Description:** `Detects a single host connecting to 3 or more internal machines via SMB, RDP, WinRM, or RPC within a short window. Indicates attacker-style lateral movement after initial compromise.`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:network"
  direction="outbound"

| eval dest_port=tonumber(dest_port)

| eval lateral_type=case(
    dest_port IN (445, 139), "SMB (File Share / Pass-the-Hash)",
    dest_port=3389,           "RDP (Remote Desktop)",
    dest_port IN (5985, 5986), "WinRM (Windows Remote Management)",
    dest_port=135,             "RPC Endpoint Mapper",
    1==1, null()
  )

| where isnotnull(lateral_type)
  AND match(lower(dest_ip), "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")

| bin _time span=30m

| stats
    count as connection_count
    dc(dest_ip) as unique_targets
    min(_time) as firstTime
    max(_time) as lastTime
    values(dest_ip) as target_machines
    values(lateral_type) as methods_used
    by dest user _time

| where unique_targets >= 3

| eval severity=case(
    unique_targets >= 10, "critical",
    unique_targets >= 5, "high",
    1==1, "medium"
  )

| eval mitre_technique="T1021"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Key logic explained:**

```
AND match(lower(dest_ip), "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
```
→ This regex matches only RFC 1918 private IP addresses (your internal network).
  We want lateral movement within the network, not outbound to the internet.
  `10.*` = Class A private, `172.16-31.*` = Class B private, `192.168.*` = Class C private.

```
| bin _time span=30m
```
→ Groups into 30-minute windows. An attacker scanning many hosts rapidly will hit
  the threshold within one window.

4. **Schedule:** `*/15 * * * *` | `-20m` to `-5m`
5. **Trigger:** For each result | Throttle `dest` for `1800` seconds
6. **Notable Event:**
   - Title: `CS-NET-002: Lateral Movement from $dest$ to $unique_targets$ Internal Hosts`
   - Severity: `$severity$`
7. **Save and Enable.**

---

### CS-NET-003 — Large Outbound Data Transfer (Exfiltration)

**What threat does this detect?**
Data exfiltration is when an attacker copies your data out to an external server.
This search detects a single machine sending large amounts of data to the internet
within one hour. While some legitimate applications do this (backups, cloud sync),
these can be allowlisted once identified.

**MITRE ATT&CK Technique:** T1041 — Exfiltration Over C2 Channel

**Step-by-step creation:**

1. **Name:** `CS-NET-003 - Large Outbound Data Transfer (Possible Exfiltration)`
2. **Description:** `Detects a host transferring 500MB or more of data to external IP addresses within one hour. Possible data exfiltration. Tune threshold based on legitimate backup/sync traffic in your environment.`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:network"
  direction="outbound"

| where NOT match(lower(dest_ip),
    "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)")

| bin _time span=1h

| stats
    sum(bytes_out) as total_bytes_out
    dc(dest_ip) as unique_external_dests
    min(_time) as firstTime
    max(_time) as lastTime
    values(dest_ip) as destinations
    by dest user _time

| eval total_mb=round(total_bytes_out/1024/1024, 2)
| eval total_gb=round(total_mb/1024, 2)

| where total_mb >= 500

| eval severity=case(
    total_mb >= 10000, "critical",
    total_mb >= 2000, "high",
    1==1, "medium"
  )

| eval size_human=if(total_gb >= 1,
    tostring(total_gb) + " GB",
    tostring(total_mb) + " MB"
  )

| eval mitre_technique="T1041"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Key logic explained:**

```
| where NOT match(lower(dest_ip), "^(10\.|172\...|192\.168\.|127\.)")
```
→ We only care about transfers to the INTERNET, not internal file shares.
  `127.*` is also excluded (localhost).

```
| eval total_mb=round(total_bytes_out/1024/1024, 2)
```
→ Converts bytes to megabytes: bytes ÷ 1024 = KB, ÷ 1024 again = MB.

```
| eval size_human=if(total_gb >= 1, ...)
```
→ Creates a human-readable size string (e.g., "1.5 GB" or "750 MB") for the
  Notable Event title so the analyst immediately understands the scale.

4. **Schedule:** `0 * * * *` | `-65m` to `-5m`
5. **Trigger:** For each result | Throttle `dest` for `3600` seconds
6. **Notable Event:**
   - Title: `CS-NET-003: Large Outbound Transfer from $dest$ - $size_human$ to $unique_external_dests$ External IPs`
   - Severity: `$severity$`
7. **Save and Enable.**

---

## 10. Registry Sourcetype — Correlation Searches <a name="registry"></a>

---

### CS-REG-001 — Persistence via Registry Run Keys

**What threat does this detect?**
Windows automatically runs any program listed in the "Run" registry keys when a user
logs in. Attackers add their malware to these keys to survive reboots — this is called
"persistence." Detecting NEW entries in Run keys that aren't from known software
is a strong malware indicator.

**MITRE ATT&CK Technique:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

**Step-by-step creation:**

1. **Name:** `CS-REG-001 - Persistence via Registry Run Key`
2. **Description:** `Detects creation or modification of Windows AutoRun registry keys used by malware to persist across reboots. Excludes known legitimate software vendors. Any unrecognized entry should be investigated.`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:registry"
  action IN ("CREATE", "MODIFY")

| eval reg_lower=lower(registry_path)
| eval value_lower=lower(registry_value_data)

| where match(reg_lower,
    "(\\software\\microsoft\\windows\\currentversion\\run$|
      \\software\\microsoft\\windows\\currentversion\\runonce$|
      \\software\\wow6432node\\microsoft\\windows\\currentversion\\run$|
      \\currentversion\\policies\\explorer\\run$|
      \\software\\microsoft\\windows nt\\currentversion\\winlogon)")

| where NOT match(value_lower,
    "(\\windows\\system32|\\program files\\|\\program files (x86)\\|
      windows defender|qualys|splunk|microsoft office|
      onedrive|teams|zoom|cisco|mcafee|symantec|crowdstrike|
      \\windows\\explorer\.exe)")

| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(registry_path) as registry_paths
    values(registry_value_name) as value_names
    values(registry_value_data) as value_data
    values(process) as writing_processes
    by dest user

| eval severity="high"
| eval mitre_technique="T1547.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Key logic explained:**

```
| where NOT match(value_lower, "(\\windows\\system32|\\program files\\|...)")
```
→ This is your allowlist. Known good software (from System32, Program Files, known vendors)
  is excluded. The goal is to only alert on UNKNOWN programs in the Run keys.
  **You should expand this list with software common in your environment.**

```
values(registry_value_data) as value_data
```
→ Collects the actual command that will run on startup. This is critical for triage:
  if the value data points to `C:\Temp\svchost32.exe`, that's malware trying to
  look like a legitimate Windows process.

4. **Schedule:** `*/15 * * * *` | `-20m` to `-5m`
5. **Trigger:** For each result | Throttle `dest,registry_value_name` for `3600` seconds
6. **Notable Event:**
   - Title: `CS-REG-001: Suspicious Run Key on $dest$ by $user$ - $value_names$`
   - Severity: `High`
7. **Save and Enable.**

---

### CS-REG-002 — Security Tool Tampering via Registry

**What threat does this detect?**
Sophisticated malware often disables security tools (Windows Defender, UAC, etc.)
by modifying registry settings before executing its main payload. This is a critical
indicator that an attacker has escalated privileges and is actively trying to blind
your defenses.

**MITRE ATT&CK Technique:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Step-by-step creation:**

1. **Name:** `CS-REG-002 - Security Tool Tampering via Registry`
2. **Description:** `Detects registry modifications that disable Windows Defender, UAC, Windows Firewall, or manipulate the Winlogon process. This is a critical pre-attack step indicating an attacker is actively disabling your defenses.`
3. **Search Query:**

```spl
index=edr sourcetype="qualys:edr:registry"
  action IN ("MODIFY", "DELETE", "CREATE")

| eval reg_lower=lower(registry_path)
| eval val_name_lower=lower(registry_value_name)
| eval val_data_lower=lower(registry_value_data)

| eval tamper_type=case(

    match(reg_lower, "\\windows defender\\") AND
    match(val_name_lower, "(disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection)") AND
    val_data_lower="1",
      "Windows Defender Real-Time Protection DISABLED",

    match(reg_lower, "\\currentversion\\policies\\system") AND
    match(val_name_lower, "enablelua") AND val_data_lower="0",
      "UAC (User Account Control) DISABLED",

    match(reg_lower, "\\system\\currentcontrolset\\services\\sharedaccess") AND
    match(val_name_lower, "start") AND val_data_lower="4",
      "Windows Firewall Service DISABLED",

    match(reg_lower, "\\software\\microsoft\\windows nt\\currentversion\\winlogon") AND
    match(val_name_lower, "(userinit|shell)") AND
    NOT match(val_data_lower, "(userinit\.exe|explorer\.exe)"),
      "Winlogon Hijack - Non-standard shell or userinit",

    match(reg_lower, "\\lsa\\") AND
    match(val_name_lower, "lmcompatibilitylevel") AND
    val_data_lower IN ("0","1"),
      "NTLM Downgrade Attack - Weak authentication enabled",

    1==1, null()
  )

| where isnotnull(tamper_type)

| stats
    count
    min(_time) as firstTime
    max(_time) as lastTime
    values(registry_path) as paths
    values(registry_value_data) as new_values
    values(process) as modifying_process
    by dest user tamper_type

| eval severity="critical"
| eval mitre_technique="T1562.001"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

4. **Schedule:** `*/5 * * * *` | `-6m` to `-1m`
5. **Trigger:** For each result | Throttle `dest,tamper_type` for `600` seconds
6. **Notable Event:**
   - Title: `CRITICAL: Security Tool Tampering on $dest$ - $tamper_type$`
   - Severity: `Critical`
7. **Save and Enable.**

---

## 11. Cross-Sourcetype Searches — Connecting the Dots <a name="cross"></a>

Cross-sourcetype searches are the most powerful — they look for patterns that span
multiple log types to detect multi-stage attack chains. They are harder to tune but
produce very high-fidelity alerts.

---

### CS-CROSS-001 — File Dropped Then Executed (Two-Stage Delivery)

**What threat does this detect?**
A common malware delivery pattern:
1. A file is WRITTEN to disk (e.g., by a browser downloading a file, or a macro saving a payload)
2. That SAME file is EXECUTED within a few minutes

Seeing both events together for the same filename on the same host within a short
window is strong evidence of malware execution.

**MITRE ATT&CK Techniques:** T1204.002 (User Execution) + T1059 (Command Interpreter)

**Step-by-step creation:**

1. **Name:** `CS-CROSS-001 - File Drop Followed by Execution`
2. **Description:** `Correlates file creation/write events with process execution events. Detects when a newly dropped file (executable, script) is run within 5 minutes on the same host. Classic two-stage malware delivery pattern.`
3. **Search Query:**

```spl
index=edr (sourcetype="qualys:edr:file" OR sourcetype="qualys:edr:process")

| eval src=sourcetype
| eval filename_norm=lower(coalesce(file_name, process))
| eval path_norm=lower(coalesce(file_path, process_path))

| where match(filename_norm, "\.(exe|dll|ps1|bat|cmd|vbs|hta|js|jar|py|scr)$")
  AND match(path_norm,
      "(\\temp\\|\\appdata\\|\\downloads\\|\\public\\|\\programdata\\)")

| stats
    values(src) as event_sources
    min(eval(if(sourcetype="qualys:edr:file",    _time, null()))) as file_drop_time
    min(eval(if(sourcetype="qualys:edr:process", _time, null()))) as execution_time
    values(eval(if(sourcetype="qualys:edr:file", file_hash_sha256, null()))) as file_hashes
    values(eval(if(sourcetype="qualys:edr:process", command_line, null()))) as exec_commands
    by dest user filename_norm

| where isnotnull(file_drop_time) AND isnotnull(execution_time)
  AND execution_time >= file_drop_time
  AND (execution_time - file_drop_time) <= 300

| eval seconds_to_execution=execution_time - file_drop_time

| eval severity="high"
| eval mitre_technique="T1204.002,T1059"
| convert timeformat="%Y-%m-%dT%H:%M:%S"
    ctime(file_drop_time) ctime(execution_time)
```

**Key logic explained:**

```
min(eval(if(sourcetype="qualys:edr:file", _time, null()))) as file_drop_time
```
→ This is a conditional aggregate: for each row, if the sourcetype is a file event,
  use its `_time`, otherwise use `null`. Then `min()` picks the earliest file event time.
  The result: `file_drop_time` = the time the file was first written.

```
| where isnotnull(file_drop_time) AND isnotnull(execution_time)
```
→ Only keep rows where BOTH events were seen (file was written AND executed).

```
AND (execution_time - file_drop_time) <= 300
```
→ Execution must happen within 300 seconds (5 minutes) of the file being written.
  Legitimate files installed by installers are typically not run within seconds of creation.

4. **Schedule:** `*/15 * * * *` | `-20m` to `-5m`
5. **Trigger:** For each result | Throttle `dest,filename_norm` for `3600` seconds
6. **Notable Event:**
   - Title: `CS-CROSS-001: File Dropped and Executed on $dest$ - $filename_norm$ ($seconds_to_execution$ seconds between drop and run)`
   - Severity: `High`
7. **Save and Enable.**

---

### CS-CROSS-002 — Ransomware Kill Chain (Process + File + Registry)

**What threat does this detect?**
Real ransomware attacks follow a pattern before encrypting files:
1. **Process:** Runs commands to delete shadow copies (`vssadmin delete shadows`) — prevents recovery
2. **File:** Starts renaming/creating files with ransomware extensions
3. **Registry:** Modifies persistence or security keys

Seeing all three activity types from the same host within 10 minutes is a critical
ransomware indicator that warrants IMMEDIATE response.

**MITRE ATT&CK Techniques:** T1486 (Encrypt), T1490 (Delete Shadow Copies), T1562 (Disable Defenses)

**Step-by-step creation:**

1. **Name:** `CS-CROSS-002 - Ransomware Kill Chain Detected`
2. **Description:** `Detects multi-stage ransomware behavior: shadow copy deletion, file encryption (renamed with ransomware extensions), and registry tampering — all occurring on the same host within 10 minutes. IMMEDIATE RESPONSE REQUIRED.`
3. **Search Query:**

```spl
index=edr

| eval is_shadow_delete=if(
    sourcetype="qualys:edr:process"
    AND match(lower(command_line), "(vssadmin.+delete|bcdedit.+recoveryenabled|wbadmin.+delete|shadowcopy.+delete)"),
    1, 0)

| eval is_file_encrypt=if(
    sourcetype="qualys:edr:file"
    AND action="RENAME"
    AND match(lower(file_name), "\.(encrypted|locked|crypt|enc|wncry|ryuk|conti|sodinokibi)$"),
    1, 0)

| eval is_security_tamper=if(
    sourcetype="qualys:edr:registry"
    AND action IN ("MODIFY","DELETE")
    AND match(lower(registry_path), "(\\defender\\|recoveryenabled|\\run\\)"),
    1, 0)

| bin _time span=10m

| stats
    sum(is_shadow_delete) as shadow_delete_count
    sum(is_file_encrypt) as encrypted_file_count
    sum(is_security_tamper) as tamper_count
    min(_time) as firstTime
    max(_time) as lastTime
    by dest user _time

| where shadow_delete_count >= 1
  AND (encrypted_file_count >= 3 OR tamper_count >= 1)

| eval attack_stages_detected=mvappend(
    if(shadow_delete_count >= 1, "Shadow Copy Deletion (" + tostring(shadow_delete_count) + " events)", null()),
    if(encrypted_file_count >= 1, "File Encryption (" + tostring(encrypted_file_count) + " files)", null()),
    if(tamper_count >= 1, "Security Tampering (" + tostring(tamper_count) + " changes)", null())
  )

| eval severity="critical"
| eval mitre_technique="T1486,T1490,T1562"
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

4. **Schedule:** `*/5 * * * *` | `-11m` to `-1m`
5. **Trigger:** For each result | Throttle `dest` for `300` seconds
6. **Notable Event:**
   - Title: `!!! RANSOMWARE KILL CHAIN ON $dest$ - ISOLATE IMMEDIATELY !!!`
   - Severity: `Critical`
   - Consider adding an **Adaptive Response Action** to automatically isolate the host
     via the Qualys EDR API if your Splunk SOAR is integrated.
7. **Save and Enable.**

---

## 12. Testing & Validating Your Searches <a name="testing"></a>

### Method 1 — Validate the Search Finds Something

Before enabling any search, first confirm it actually finds data in your environment:

1. Go to **Search & Reporting** (regular Splunk, not ES).
2. Paste the search query.
3. Change the time range to **Last 30 days**.
4. Run it.

If results appear: your data has these events. Tune the thresholds if there are too many.
If no results: your fields may have different names. Use `| fieldsummary` to check.

### Method 2 — Check Field Names Match Your Data

If a search returns nothing, run this to compare field names:

```spl
index=edr sourcetype="qualys:edr:process"
| head 100
| stats values(process) as proc_values
         values(parent_process) as parent_values
         count
```

If `process` returns null but you see values under `proc_name`, update your search
to use the correct field name.

### Method 3 — Fire a Test Notable Event

1. In ES → Configure → Content Management, find your search.
2. Click the **Run** button (arrow icon).
3. If results appear, click one result row.
4. Click **Create Notable Event** to manually generate a test alarm.
5. Go to **Incident Review** and confirm your test alarm appears.

### Method 4 — Validate the Schedule is Working

1. In ES → Configure → Content Management.
2. Find your search.
3. Look at the **Last Run** column — it should update every time the cron fires.
4. Look at **Last Result Count** — confirm it's running and returning expected counts.

---

## 13. Tuning — Reducing False Alarms <a name="tuning"></a>

New correlation searches almost always generate false positives at first.
Here is a systematic approach to tuning them down without breaking detection.

### Step 1 — Identify the False Positive Source

When you close a notable event as a false positive, record:
- Which **host** generated it (`dest`)
- Which **user** triggered it
- Which **process** or **file** caused it
- What was the **legitimate business reason**?

### Step 2 — Add Exclusions to the Search

**Option A — Exclude a specific host:**
```spl
| where dest != "BACKUP-SERVER-01"
```

**Option B — Exclude a list of hosts (use a lookup):**
```spl
| lookup excluded_hosts.csv dest OUTPUT is_excluded
| where isnull(is_excluded)
```

**Option C — Exclude a specific process:**
```spl
AND NOT match(lower(process), "(backup_agent|veeam|commvault)")
```

**Option D — Exclude a specific user account:**
```spl
AND NOT match(lower(user), "(svc_backup|svc_splunk|svc_qualys)")
```

### Step 3 — Use ES Suppressions (Preferred Method)

ES has a built-in suppression system that is cleaner than editing search queries:

1. Go to a notable event in Incident Review.
2. Click **Actions → Create Suppression**.
3. Fill in:
   - **Name:** e.g., `SUPPRESS-CS-PROC-003-veeam-backup`
   - **Search:** e.g., `dest="BACKUP-SERVER-01" proc="certutil.exe"`
   - **Expiration:** 90 days (always set an expiration — review regularly)
4. Save. Splunk will automatically suppress future matching notable events.

### Step 4 — Adjust Thresholds

If a search triggers too often, raise the count threshold:
- Change `| where count >= 1` to `| where count >= 3`
- Change `| where unique_paths_deleted >= 50` to `| where unique_paths_deleted >= 100`

Always document WHY you changed a threshold in the search description field.

---

## 14. Glossary <a name="glossary"></a>

| Term | Plain English Explanation |
|---|---|
| **Correlation Search** | An automated detection rule that runs on a schedule and generates alarms |
| **Notable Event** | An alarm/alert that appears in the Incident Review queue in Splunk ES |
| **Sourcetype** | The type/format of log data (e.g., process logs, file logs) |
| **SPL** | Splunk Processing Language — the query language used to search logs |
| **Index** | A named bucket where Splunk stores log data (like a database) |
| **MITRE ATT&CK** | A publicly available framework cataloging attacker tactics and techniques |
| **Throttle** | A setting that prevents duplicate alarms for the same event within a time window |
| **LOLBin** | "Living off the Land Binary" — a legitimate Windows tool abused by attackers |
| **C2 / Command & Control** | A server run by attackers that communicates with infected machines |
| **Lateral Movement** | An attacker moving from one compromised machine to other machines |
| **Persistence** | An attacker's method of surviving reboots (e.g., registry Run keys) |
| **Exfiltration** | Stealing data out of your network to an attacker-controlled server |
| **CIM** | Common Information Model — Splunk's standard field naming schema |
| **Drill-down** | A pre-built investigation search that runs when an analyst clicks into a notable event |
| **Suppression** | A rule that tells Splunk ES to silently ignore specific matching notable events |
| **False Positive** | An alarm that fires but turns out to be legitimate, non-malicious activity |
| **True Positive** | An alarm that fires and correctly identifies real malicious activity |
| **LSASS** | Windows Local Security Authority Subsystem — stores password hashes in memory |
| **Shadow Copy** | Windows backup snapshots — ransomware deletes these to prevent recovery |
| **Beacon / Beaconing** | Regular, periodic network communication from malware to its C2 server |
| **Base64** | An encoding scheme attackers use to hide commands in plain text |
| **RFC 1918** | Standard defining private IP address ranges (10.x, 172.16-31.x, 192.168.x) |
| **Cron** | A scheduling format used to define when a search runs automatically |
| **Epoch time** | The number of seconds since Jan 1, 1970 — how Splunk stores timestamps internally |

---

*Guide Version 2.0 — Qualys EDR + Splunk ES Integration*
*Covers: Process, File, Network, Registry sourcetypes | 15 Correlation Searches | Notable Event creation step by step*
