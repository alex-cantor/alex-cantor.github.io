---
title: Incident Response & Investigation - SEC504.1
parent: SEC504
grand_parent: SANS
great_grand_parent: Categories
nav_order: 1
layout: default
---

# Incident Response & Investigation (Inspired by SANS SEC504.1)

This post summarizes key insights and best practices learned through my study of the first section of SANS SEC504: Hacker Tools, Techniques, Exploits, and Incident Handling. These notes reflect my own understanding and rewording of the material and are not a reproduction of SANS intellectual property. Credit to SANS Institute for delivering excellent training.

---

## Understanding Incident Response

Incident response is more than a checklist — it's an evolving and iterative process requiring coordination, evidence collection, and thoughtful decision-making. Two complementary models frame this process:

### Classic Incident Response Lifecycle (PICERL)

1. **Preparation**

   * Define security policies and operational procedures
   * Set up logging and visibility tools
   * Train the response team

2. **Detection and Identification**

   * Recognize suspicious activity via alerts, logs, or user reports
   * Confirm an incident is occurring

3. **Containment**

   * Short-term: isolate compromised assets
   * Long-term: block ongoing attacker access

4. **Eradication**

   * Remove malware, attacker accounts, and fix exploited flaws

5. **Recovery**

   * Bring affected systems back online safely
   * Monitor to prevent reinfection

6. **Lessons Learned**

   * Review the incident
   * Identify what failed and what worked
   * Update plans and controls

> *Common pitfalls include insufficient preparation and poorly executed containment strategies.*

### Dynamic Incident Response (DAIR Model)

While PICERL is foundational, incident response often requires revisiting earlier steps. DAIR emphasizes the **iterative nature** of investigating, responding, and learning.

---

## Deep Dive: Key Response Phases

### Preparation

* Understand critical assets and risks
* Map logging and alerting capabilities
* Build response playbooks and train responders

### Detection

* Collect data from detection sources like SIEM, EDR, logs, and threat intelligence
* Look for Indicators of Attack (IoAs) and Events of Interest (EoIs)
* Active threat hunting enhances detection speed

### Verification & Triage

* Confirm if detected events are real threats
* Determine business impact and response urgency
* Coordinate with leadership to prioritize efforts

### Scoping the Incident

* Identify how far and wide the compromise has spread
* Use IoCs (IP addresses, registry keys, file hashes) to pivot
* Data sources: EDR, SIEM, system configs, threat intel

### Containment Tactics

* Isolate affected machines (e.g., VLAN, firewall blocks)
* Modify DNS or access controls
* Disable compromised user accounts
* Ensure evidence preservation (logs, memory dumps)

### Eradication

* Remove malicious files, user accounts, persistence mechanisms
* Patch exploited vulnerabilities
* Perform system-wide scans

### Recovery

* Rebuild from clean backups
* Verify remediations
* Closely monitor reintroduced systems for re-compromise

### Debrief & Review

* Summarize the full response effort
* Document insights and areas for improvement
* Update procedures and tools

---

## PowerShell-Based Live Investigation (Windows)

### Process Analysis

```powershell
Get-Process
Get-Process 'powershell' | Select-Object *
Get-CimInstance -Class Win32_Process | Select-Object ProcessId, ProcessName, CommandLine
```

### Network Connections

```powershell
Get-NetTCPConnection
Get-NetTCPConnection -RemoteAddress 10.10.75.1
```

### Services & Persistence

```powershell
Get-Service
Get-CimInstance -Class Win32_Service | Format-List Name, PathName
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
```

### Users & Groups

```powershell
Get-LocalUser
Get-LocalGroupMember Administrators
```

### Scheduled Tasks

```powershell
Get-ScheduledTask
Export-ScheduledTask -TaskName 'AvastUpdate'
```

### Log Analysis

```powershell
Get-WinEvent -LogName System | Where-Object Id -EQ 7045
```

### Differential Analysis

```powershell
Compare-Object -ReferenceObject $baseline -DifferenceObject $current
```

---

## Core Analysis Tools (Windows)

* **Process Explorer / Monitor**: Inspect real-time activity
* **Autoruns**: Identify autostart mechanisms
* **Sysmon**: Collect rich telemetry
* **Procdump**: Capture memory dumps

---

## Network Traffic Analysis with tcpdump

```bash
tcpdump -i eth0 -w capture.pcap
tcpdump -r capture.pcap -n
```

Use **BPF filters** to isolate traffic:

```bash
tcpdump 'tcp port 443 and host 192.168.1.1'
```

---

## Memory Forensics with Volatility

Capture memory using WinPmem, then analyze with Volatility 3:

```bash
vol -f memory.raw windows.pslist.PsList
vol -f memory.raw windows.netscan.NetScan
vol -f memory.raw windows.cmdline.CmdLine
```

Volatility Modules:

* `dlllist`, `svcscan`, `hashdump`, `envars`, `dumpfiles`, etc
* Extract registry keys, process trees, services, loaded DLLs, and more

---

## Malware Investigation Basics

### Static Analysis

```powershell
Get-FileHash file.exe
strings file.exe
```

### Dynamic Monitoring Strategy

1. Snapshot VM (if used)
2. Enable monitoring tools (e.g. Procmon)
3. Run sample
4. Analyze collected data

### Tools

* **Regshot**: Compare registry before/after
* **Procmon**: Record system activity
* **Sandbox Services**: VirusTotal, Hybrid Analysis

> **Always analyze malware in isolated, disposable environments.**

---

## Using Generative AI in IR

LLMs like GPT can assist in:

* Explaining logs or attack techniques
* Summarizing long alerts
* Drafting reports

### Prompt Tips

* Be specific and iterative
* Use delimiters and clear instructions
* Guide toward structured output (e.g., JSON or tables)

Example:

```text
"Explain the significance of Event ID 4625 in under 100 words."
```

---

## Final Thoughts

Incident response is an evolving practice that blends planning, analysis, and decisive action. Training from SANS has greatly improved my understanding of how to handle real-world incidents in a structured, yet flexible way.

*This article reflects my personal learning and interpretation. SANS is the definitive source for full course content.*
