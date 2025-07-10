---
title: Penetration Testing Foundations - SEC560.1
parent: SEC560
grand_parent: SANS
great_grand_parent: Categories
nav_order: 1
layout: default
---

# Penetration Testing Foundations (Inspired by SANS SEC560.1)

This guide captures my personal interpretation and rewording of content studied in SANS SEC560: Network Penetration Testing and Ethical Hacking. It is not a substitute for the official course, but a reference point for myself and others interested in learning how to conduct responsible, effective penetration tests. Credit to SANS for the excellent instruction.

---

## Core Concepts and Terminology

### Understanding Risk Components

* **Threat**: An entity or event that could cause harm to systems or data.
* **Vulnerability**: A weakness that a threat might exploit.
* **Risk**: The overlap of threat and vulnerability.
* **Exploit**: A specific method or tool used to take advantage of a vulnerability.

A penetration tester's mission is to emulate real attackers, safely exploit identified weaknesses, and recommend security improvements based on business risk.

### Types of Security Engagements

While terms like "ethical hacking," "red teaming," and "security audits" are often used interchangeably, each has distinct goals:

* **Penetration Testing**: Simulates attacks to identify exploitable vulnerabilities.
* **Red Teaming**: Focuses on stealth, persistence, and testing detection/response.
* **Purple Teaming**: Collaborative effort between offensive and defensive teams to strengthen security posture.
* **Vulnerability Assessment**: Broad vulnerability discovery without exploitation.
* **Security Audit**: Compliance-focused evaluation using structured checklists.

### What is Ethical Hacking?

Ethical hacking involves applying offensive techniques—with permission—to uncover weaknesses and improve defenses. Ethical hackers ("white hats") operate within legal and professional boundaries, unlike malicious actors ("black hats").

### Penetration Testing Defined

Penetration testing simulates real-world attacks using techniques similar to adversaries, but under controlled conditions. It aims to:

* Identify and safely exploit vulnerabilities
* Gauge real-world business impact
* Provide practical remediation guidance

Pen testing is a subset of ethical hacking.

### Red vs. Purple vs. Blue

* **Red Teams** simulate adversaries, aiming for stealth and goal-oriented exploits.
* **Purple Teams** blend offensive and defensive roles to foster collaboration.
* **Blue Teams** focus on monitoring, detection, and response.

### Ethical Hacking Motivation

Reasons to test proactively:

* Uncover flaws before attackers do
* Help organizations manage and reduce risk
* Demonstrate urgency to leadership through proof-of-concept exploits

---

## Pen Test Categories

### Common Test Types

* **Network Services Testing**
* **Web Application Testing**
* **Wireless Testing**
* **Social Engineering (Email/Phone)**
* **Assumed Breach Exercises**
* **Physical Security Testing**
* **Cryptanalysis & DRM Testing**

Pen tests often follow a general attack lifecycle: Reconnaissance → Scanning → Exploitation → Post-exploitation.

---

## Methodologies and Standards

Several well-established frameworks offer structure for penetration tests:

* **[OSSTMM](https://www.isecom.org/osstmm/)** – Broad methodology for various domains
* **[PTES](http://www.pentest-standard.org/)** – Covers scoping, recon, exploitation, and reporting
* **[NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)** – Technical guidance for assessment and validation
* **[OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)** – Web-focused testing
* **Penetration Testing Framework** – A practical collection of tools and techniques

These resources help define the scope, execution, and documentation of tests.

---

## Building a Testing Infrastructure

### Operating Systems

* Use both Linux and Windows for flexibility.
* macOS is acceptable for host system, but virtualize Linux and Windows.

### Virtualization Tools

* VMware, VirtualBox, Hyper-V are widely used.
* Use bridged networking for realistic testing scenarios.

### Testing Hardware

* **Attack Machines**: Pen tester's systems
* **Target Machines**: Systems under evaluation
* Use isolated, dedicated systems—avoid overlap between clients.

### Network Considerations

* Avoid filtering and firewalls on the tester's network.
* Test in lab environments when possible.
* ISP must allow unfiltered traffic if conducting external scans.

### Security of Test Systems

* Harden test machines: disable unneeded services, increase local security.
* Use disk encryption: BitLocker, FileVault, dm-crypt, LUKS.
* Scrub machines between engagements and avoid data leakage.

### Free and Commercial Tools

Popular free tools:

* **Exploit-DB**: [https://www.exploit-db.com](https://www.exploit-db.com)
* **PacketStorm**: [https://packetstormsecurity.org](https://packetstormsecurity.org)
* **Seebug**: [https://www.seebug.org](https://www.seebug.org)

Common commercial tools:

* Nessus, Nexpose, Metasploit Pro
* CORE Impact, Immunity CANVAS, SAINT
* Fortify WebInspect, IBM AppScan

Pen testers also often create custom tools and scripts to automate or streamline workflows.

---

## Engagement Setup

### The Pen Test Process

1. **Preparation**: NDA, scope, permissions, team assignments
2. **Execution**: Perform test according to RoE
3. **Conclusion**: Analyze, retest, report findings

### Rules of Engagement (RoE)

Defines how testing is conducted:

* Contact info exchange
* Encryption methods for report delivery
* Daily sync calls and timelines
* Whether test is announced or stealth
* Permissions for dangerous or DoS testing

### Scoping

Defines what gets tested and how:

* Domain names, IP ranges, applications
* Avoid scope creep
* Explicit third-party/cloud permissions required
* Define test vs production environment targets
* Determine if internal access is provided or simulated (e.g., dropboxes, VPN)

---

## Reporting

### Report Structure

1. **Executive Summary**: Business-focused overview
2. **Introduction**: Who, what, when, where
3. **Findings**: Each vulnerability detailed by risk level
4. **Methodology**: Tools and steps taken
5. **Conclusion**: Summary and future recommendations
6. **Appendices**: Supporting evidence, tool outputs

### Recommendations

Provide:

* Root cause insights
* Short- and long-term mitigations
* Clear verification steps

Avoid dumping scanner output. Validate findings and tailor language to the target’s environment.

### Screenshots & Redaction

* Use high-quality, focused visuals
* Highlight important areas
* Use tools like Snagit, Greenshot, or Shutter
* Redact sensitive info with opaque overlays

---

## Reconnaissance

### Passive Information Gathering

* Analyze document metadata (usernames, software used)
* Tools: `exiftool`, `strings`

### Whois & DNS

* Use `whois`, `dig`, `nslookup`
* Look for domain ownership, IP block assignments, zone transfers

### Open Source Intelligence (OSINT)

* Search company websites, job boards, and social media
* Use directives like `site:`, `intitle:`, `filetype:`
* Leverage Google Hacking Database (GHDB) at [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)

### Tools for Recon

* **Recon-ng**: OSINT and automation framework (Metasploit-style)
* **SearchDiggity**: Windows-based recon suite for search engine dorks and sensitive info

---

## Final Thoughts

Ethical hacking demands professionalism, precision, and continuous learning. The best testers align technical findings with business risk and communicate clearly.

This summary reflects my experience learning from SANS SEC560 and practicing the art of ethical hacking. For complete training and labs, consider attending a SANS course or exploring the frameworks referenced above.

*This guide reflects personal learning and rephrased interpretation. All credit for course design belongs to SANS Institute.*
