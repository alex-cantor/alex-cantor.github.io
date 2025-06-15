# Pwn / Binary Exploitation Approach

This file serves as the ultimate guide to approaching pwn (binary exploitation) challenges.

## Terms

- **GOT**: Global Offset Table, acts as a lookup table for dynamically linked functions in a binary
- **RELRO**: Relocation Read-Only, tells you about the writability of the GOT
- **SSP / Stack Canary**: Stack Smashing Protector; checks for stack-based buffer overflows
- **NX**: No-eXecute; prevents execution from non-code memory regions
- **PIE**: Position Independent Executable; randomizes binary base addresses
- **Symbols**: Function and variable names; aid in reverse engineering
- **FORTIFY**: Compiler runtime checks for common unsafe functions
- **RPATH/RUNPATH**: Paths hardcoded for dynamic library loading
- **Arch**: Architecture type — 32-bit vs. 64-bit, little-endian vs. big-endian

---

## Approach

1. **Start** by determining the security measures in place.
2. **Run** `checksec <binary>` to display the binary's protections.
3. **Analyze** based on the output.

---

## Summary Table

| Field        | Secure Value    | Insecure Value         | Attack Possibilities                                  |
| ------------ | --------------- | ---------------------- | ----------------------------------------------------- |
| **Arch**     | amd64 / i386     | -                      | Determines word size (ROP chain size, syscall ABI)     |
| **RELRO**    | Full RELRO       | No / Partial RELRO     | [GOT overwrite](guides/got_overwrite.md)                  |
| **Canary**   | Canary found     | No canary found        | [Leak canary + Buffer Overflow](guides/canary_bypass.md)  |
| **NX**       | NX enabled       | NX disabled            | [ROP or Shellcode](guides/rop_shellcode.md)               |
| **PIE**      | PIE enabled      | No PIE                 | [Infoleak to find base](guides/infoleak.md)               |
| **Symbols**  | No (stripped)    | Yes                    | Easier RE if symbols are present                      |
| **FORTIFY**  | Yes              | No                     | [Exploiting unsafe libc functions](guides/fortify_bypass.md) |
| **RPATH**    | No RPATH         | RPATH present          | [Library hijacking](guides/library_hijack.md)             |
| **RUNPATH**  | No RUNPATH       | RUNPATH present        | Same as RPATH                                          |

---

## In Depth

### **Arch**

| Arch             | Meaning                                                      | Practical Impact                                      |
| ---------------- | ------------------------------------------------------------ | ----------------------------------------------------- |
| i386-32-little    | 32-bit, little endian                                       | 4-byte addresses, stack args, simpler ROP chains      |
| amd64-64-little   | 64-bit, little endian                                       | 8-byte addresses, register args, 16-byte stack align  |

---

### **RELRO**

| RELRO         | Lazy Binding | Attack Possibility          |
| ------------- | ------------ | --------------------------- |
| No RELRO      | Yes          | GOT overwrite (easy win) — [Guide](guides/got_overwrite.md) |
| Partial RELRO | Yes          | GOT overwrite (still possible) |
| Full RELRO    | No           | GOT protected — no GOT hijacking |

---

### **[Stack] Canary**

| Canary         | Description                                                   |
| -------------- | ------------------------------------------------------------- |
| No canary found| Easy to do buffer overflow                                     |
| Canary found   | [Leak canary](guides/canary_bypass.md) required before overflow    |

---

### **NX (No-eXecute)**

| NX Status     | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| NX enabled    | [ROP chain / ret2libc](guides/rop_shellcode.md)                     |
| NX disabled   | Inject and jump to shellcode (easy win)                         |

---

### **PIE (Position Independent Executable)**

| PIE Status    | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| No PIE        | Binary has fixed base — hardcode addresses                     |
| PIE enabled   | [Leak address to defeat PIE](guides/infoleak.md)                   |

---

### **Symbols**

| Symbols       | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| Yes           | Easier to reverse engineer with names                          |
| No            | Stripped — harder to reverse                                   |

---

### **FORTIFY**

| FORTIFY Status| Description                                                    |
| ------------- | -------------------------------------------------------------- |
| No            | Dangerous libc functions unchecked — [classic overflows](guides/fortify_bypass.md) |
| Yes           | Checked — overflow harder                                      |

---

## Attack Techniques Based on Protections

| Protection     | Present     | Absent      | Attack Options                               |
| -------------- | ----------- | ----------- | -------------------------------------------- |
| RELRO          | Full        | Partial/No  | [GOT overwrite](guides/got_overwrite.md)        |
| Canary         | Yes         | No          | [Leak canary](guides/canary_bypass.md)          |
| NX             | Enabled     | Disabled    | [ROP chain / ret2libc](guides/rop_shellcode.md) |
| PIE            | Enabled     | Disabled    | [Leak base address](guides/infoleak.md)         |
| Symbols        | No          | Yes         | Static analysis easier if not stripped      |
| FORTIFY        | Yes         | No          | [Exploit unsafe libc calls](guides/fortify_bypass.md) |

---

## Example Scenarios

- **No Canary + NX Disabled + No PIE**: [Shellcode injection](guides/rop_shellcode.md)
- **Canary Present + NX Enabled + No PIE**: [Canary leak + ROP chain](guides/canary_bypass.md)
- **Canary Present + NX Enabled + PIE Enabled**: [Canary leak + PIE leak + ROP chain](guides/infoleak.md)
- **Full RELRO + PIE + Canary + NX**: Leak libc, compute system/binsh, [ret2libc](guides/rop_shellcode.md)

---

## Memory Leak Methods (Infoleaks)

- Format string vulnerability
- Buffer overreads (off-by-one, off-by-N)
- Uninitialized memory leaks
- Leaking GOT / PLT entries
- Heap leak (House of Spirit / fastbin attack)

More in [Infoleak Techniques](guides/infoleak.md)

---

## General Exploitation Strategy

1. **Identify protections**: `checksec binary`
2. **Find vulnerabilities**:
   - Buffer overflow?
   - Format string?
   - Use-after-free?
   - Double free?
3. **Develop leak**:
   - Leak canary if needed.
   - Leak libc base if PIE or ASLR active.
4. **ROP chain / Shellcode**:
   - ROP to system / execve.
   - Inject shellcode if NX disabled.
5. **Win**:
   - Spawn shell.
   - Redirect execution.

---

## Helpful GDB Commands

- `checksec` (with gef / peda)
- `info proc mappings`
- `vmmap`
- `x/20xw <addr>`
- `x/s <addr>`

---

## Notes

- **32-bit**: Simpler — stack-based arguments, no 16-byte alignment.
- **64-bit**: Larger address space, more secure (better ASLR).
- **Full RELRO + PIE + NX + Canary** — common in modern binaries.
- Always check libc version — leak or match known libc.
