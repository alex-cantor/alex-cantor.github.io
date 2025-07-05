---
title: Infoleak Techniques
parent: Protection Bypass
grand_parent: Pwn
great_grand_parent: Categories
nav_order: 4
---

# Infoleak Techniques

Leaking memory addresses is critical for defeating PIE (Position Independent Executable) and ASLR (Address Space Layout Randomization).

---

## Why Leak Addresses?

- **PIE binaries** randomize the base address of code.
- **ASLR** randomizes memory mappings (stack, heap, libc).
- To exploit reliably, we need known addresses — leaks allow this.

---

## Techniques for Memory Leaks

### 1. Format String Vulnerability

If user input is passed to `printf` without format restrictions:

```c
printf(user_input); // dangerous
```

You can leak stack addresses:
```
%p        // leak pointer
%x        // leak raw hex
```

Example:
```
printf("%7$p"); // might leak libc or stack address
```

Format string fuzzing:
```python
for i in range(1, 50):
    print(f"%{i}$p")
```

---

### 2. Buffer Overread

Out-of-bounds read vulnerabilities can leak adjacent memory.

Example:
```c
char buf[32];
gets(buf); // no size check
printf("%s", buf);
```

Overflow can print out-of-bounds data — potentially leaking canary, libc addresses.

---

### 3. GOT/PLT Address Leak

You can leak addresses stored in the GOT:

```c
puts(puts@got);
```

If `puts@got` is not randomized, this can reveal the libc base address.

In GDB:
```
info address puts
```

---

### 4. Uninitialized Memory Leak

If a struct or variable is not initialized before being sent back to the user, it may contain pointers:

```c
struct info {
    char name[20];
    void* ptr;
} user_info;
```

If `ptr` is not zeroed, it could leak memory.

---

### 5. Heap Address Leaks

Heap exploitation primitives like:
- Use-after-free (UAF)
- Double free

Can lead to leaking heap addresses.

House of Spirit technique can fake chunk pointers and leak heap layout.

---

## Leak to Bypass PIE

If the binary is compiled with PIE:

1. Leak an address from the binary (e.g., puts@plt).
2. Calculate the binary base address:
```python
binary_base = leaked_address - offset_to_leaked_function
```

Example:
```python
leaked_puts = 0x7ffff7a5e000
puts_offset = 0x0800 // Example offset
binary_base = leaked_puts - puts_offset
```

---

## Leak to Bypass libc ASLR

1. Leak a libc address (e.g., puts@got).
2. Calculate libc base:
```python
libc_base = leaked_puts - puts_offset_in_libc
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset
```

Find libc offsets with tools:
- `libc-database`
- `one_gadget`
- `libcsearch`

---

## Tools

- `pwntools` — for scripting leaks:
```python
from pwn import *
p = process('./vuln')
p.sendline('%7$p')
leak = int(p.recvline(), 16)
log.info(f"Leaked address: {hex(leak)}")
```
- `libc-database` — find libc versions.
- `one_gadget` — find one-gadget RCE possibilities.

---

## Notes

- Leaking **stack** addresses can help bypass canaries.
- Leaking **GOT/PLT** can help bypass PIE.
- Leaking **libc** addresses helps to perform ret2libc.
- Sometimes multiple leaks are needed for full exploitation.

For examples on building payloads after leaking, see [ROP Chains and Shellcode](rop_shellcode.md).
