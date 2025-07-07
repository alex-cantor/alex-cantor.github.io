# Recon, Scanning, and Enumeration (Inspired by SANS SEC504.2)

This post distills essential practices and tools from my exploration of the second section of SANS SEC504. The insights shared are based on my study and reformulated for public reference. This content is educational in nature and not a direct copy of SANS materials. Full credit to SANS Institute for their excellent instruction.

---

## Overview of Reconnaissance Techniques

Reconnaissance is the first step of the adversary lifecycle. It involves gathering information about a target without active engagement — until scanning and enumeration come into play. Here’s how attackers and defenders approach it.

### Why Understanding Attacks Matters

* Helps defenders anticipate and prepare for common tactics
* Encourages the design of better detection and response mechanisms

> Always have explicit, documented authorization before scanning or testing any systems.

### MITRE ATT\&CK Framework Integration

* ATT\&CK organizes real-world adversary behaviors into tactics, techniques, and procedures (TTPs)
* Maps security events to standardized identifiers for analysis and communication
* SEC504 aligns many examples to ATT\&CK to build repeatable workflows for real-world environments

---

## DNS and Subdomain Enumeration

Attackers often begin with a domain and expand their view:

* Subdomains
* Partner/third-party resources
* Dev/test infrastructure

### Common Tools & Techniques

* `dig ANY domain.com`
* Zone transfers: `dig @nameserver AXFR domain.com`
* Brute force DNS enumeration with `nmap`:

  ```bash
  sudo nmap --script dns-brute --script-args dns-brute.domain=domain.com,dns-brute.threads=6,dns-brute.hostlist=namelist.txt -sS -p 53
  ```
* Certificate transparency logs: Discover new hosts by monitoring issued certs
* Subfinder: Tool for automated subdomain enumeration

### Defensive Measures

* Block unauthorized zone transfers
* Use split-horizon DNS
* Monitor for excessive or unusual queries

---

## Web-Based Reconnaissance

### Manual Discovery

* Inspect websites directly

  * Email addresses, metadata, files, links
  * Use browser developer tools

### Tools

* **CeWL**: Crawl target website to build wordlists

  ```bash
  cewl.rb -m 8 -w out.txt -a --meta_file meta.txt -e --email_file emails.txt https://example.com
  ```
* **ExifTool**: Inspect metadata in downloaded files

  ```bash
  exiftool filename.docx
  ```
* **AADInternals**: Azure AD reconnaissance

  ```powershell
  Invoke-AADIntReconAsOutsider -Domain example.com
  ```

### OSINT Resources

* [Have I Been Pwned](https://haveibeenpwned.com)
* [DeHashed](https://dehashed.com)
* [OSINT Framework](https://osintframework.com)

### Defending Web Recon

* Minimize exposed metadata
* Use robots.txt wisely (don't accidentally highlight sensitive files)
* Include OSINT assessment in your own CTI pipeline

---

## Network Discovery with Nmap

Nmap is a flexible, powerful tool used by attackers and defenders.

### Host Discovery

```bash
sudo nmap -sn 192.168.1.1-254
```

### Port Scanning

```bash
sudo nmap -sS -p- 192.168.1.5
```

### Common Scan Types

| Scan Type         | Flag | Notes                     |
| ----------------- | ---- | ------------------------- |
| Ping/ARP          | -sn  | Basic discovery           |
| TCP Connect       | -sT  | Full TCP handshake        |
| SYN Scan          | -sS  | Stealth scan              |
| UDP Scan          | -sU  | Unreliable but useful     |
| Service Detection | -sV  | Identify service versions |

### NSE Scripts

```bash
nmap -sC target.com
nmap --script smb* target.com
```

---

## Cloud Infrastructure Scanning

### Why It’s Different

* Public cloud address space is huge
* Target attribution is more difficult
* Useful for finding unmanaged cloud assets

### Tools and Tips

* Get cloud IP ranges:

  ```bash
  wget -qO- https://ip-ranges.amazonaws.com/ip-ranges.json | jq '.prefixes[] | .ip_prefix' -r
  ```
* Use **masscan** for high-speed scanning:

  ```bash
  masscan -iL aws-ips.txt -p 443 --rate 100000 -oL results.txt
  ```
* Use `openssl` to extract cert info for attribution:

  ```bash
  openssl s_client -connect <ip>:443 2>/dev/null | openssl x509 -text | grep Subject:
  ```
* Use **TLS-Scan** for full cert and cipher info

### Other Tools

* **EyeWitness**: Screenshots of RDP, VNC, HTTP services
* Useful for detecting vulnerable web apps, exposed management portals

---

## SMB Reconnaissance and Attacks

### Why SMB is a Risk

* Common across internal environments
* Complex, legacy protocol
* Attackers exploit it for enumeration, lateral movement, and data access

### Information Gathering

```powershell
Get-CimInstance -Class win32_share -ComputerName <ip>
net view \\<ip> /all
```

* Use `smbclient` to list and access shares

```bash
smbclient -L //<ip> -U user
smbclient //<ip>/share -U user
```

* Use `rpcclient` for deeper info:

```bash
rpcclient -U user <ip>
> enumdomusers
> srvinfo
```

### Offensive Tooling

* **SMBeagle**: Fast enumeration of shares and access
* **Copernic Desktop Search**: Harvest files from mounted shares

### Password Attacks

```powershell
New-SmbMapping -LocalPath Y: -RemotePath \\<ip>\share -UserName user -Password password
```

---

## Defensive SMB Strategies

* Block SMB ports across untrusted boundaries

  * TCP/445, UDP/137–138, TCP/139
* Use Private VLANs to reduce lateral movement
* Monitor event logs and session usage:

```powershell
Get-SmbSession
Close-SmbSession -ClientComputerName <ip>
```

---

## Detection with Sigma + Hayabusa

### Sigma

* Rule format for normalizing detection logic across SIEMs
* Think: YARA for logs

### Hayabusa

* Lightweight parser for Windows event logs
* Applies Sigma rules to identify attacker activity
* Output can be used for timelines and reports

Useful Links:

* [SigmaHQ GitHub](https://github.com/SigmaHQ)
* [Hayabusa GitHub](https://github.com/Yamato-Security/hayabusa)

---

## Final Thoughts

Understanding recon and enumeration techniques equips defenders to monitor and disrupt adversary behavior early in the kill chain. From DNS reconnaissance to SMB enumeration and high-speed scanning in the cloud, every phase presents both risks and opportunities for defenders.

*These notes are drawn from my studies of SANS SEC504 and adapted for learning and reflection.*
