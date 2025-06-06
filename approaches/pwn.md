# Pwn / Binary Exploitation Approach

This file serves as the ultimate guide to approching pwn (binary exploitation) challenges.

## Terms

- GOT: Global Offset Table, acts as a lookup table for dynamically linked functions in a binary
- RELRO: Relocation Read-Only tells you about the vulnerability of the GOT

## Approach

1. Begin by determining the security measures in place. We can do that with `checksec <binary>`. After running the command, we'll see values for certain fields.

**In Depth**
- **RELRO**: Standing for Relocation Read-Only, RELRO tells you about the writability of the GOT.
| RELRO         | Lazy Binding | Attack Possibility          |
| ------------- | ------------ | --------------------------- |
| No RELRO      | Yes          | GOT overwrite (easy win)     |
| Partial RELRO | Yes          | GOT overwrite (still win)    |
| Full RELRO    | No           | No GOT overwrite (harder)    |
- **[Stack] Canary**: When there is a stack canary, a canary address is put before the return address on the stack. When a function returns, it checks if this canary value has been changed. If so, the program crashes. Why does this matter?
    - `No canary found`: Easy to do buffer overflow
    - `Canary found`: You need a memory leak (to leak the canary value) to bypass it
- **NX**: No execute (data execution prevention) determines whether certain memory regions are marked as non-executable:
    - `NX disabled`: Stack and heap are executable — you can inject shellcode directly.
    - `NX enabled`: You cannot run injected shellcode directly — you must use ROP chains or ret2libc
- **PIE**: Position Independent Executable, when enabled, randomizes the base address at load time
    - `No PIE`: Fixed load address (like 0x400000) — easy for exploits, you can predict where functions are. You can hardcode addresses of functions like `system`, `puts`, etc
    - `PIE enabled`: The entire binary is randomized at runtime — every run is at a different base address. You must leak a memory address at runtime to calculate offsets
- **Symbols**: Symbols are *things* like function names and variable names
    - `Yes`: Symbols are present — it’s easier to find the address of main, puts, etc. in Ghidra, IDA, or objdump
    - `No`: Stripped — harder. You'll have to reverse from raw addresses and assembly
- `FORTIFY`: Compiler feature to add checks against dangerous functions like strcpy, sprintf
    - `No`: No FORTIFY protections — vulnerable to classic overflows. Functions like strcpy(buf, user_input) can be exploited
    - `Yes`: Some added security. Harder to misuse certain libc functions