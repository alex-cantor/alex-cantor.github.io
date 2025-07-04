---
title: GOT Overwrite
parent: Protection Bypass
grand_parent: pwn
great_grand_parent: Knowledge Base
nav_order: 1
---

# GOT Overwrite Attack

## What is the GOT?

- GOT = Global Offset Table
- Holds function addresses at runtime (e.g., puts, printf).

## When can we overwrite?

- **No RELRO**: GOT is writable.
- **Partial RELRO**: GOT is writable (but less safe at other places).
- **Full RELRO**: GOT is read-only — no overwrite.

## Exploit Strategy

1. Leak a GOT address (optional).
2. Overwrite GOT entry of `printf`, `exit`, etc., with `system`.
3. Call the function.

### Example

Assume:
- `puts@got = 0x601018`
- `system@plt = 0x400560`

Payload:
```python
payload = b"A" * offset
payload += p64(puts_got)  # Address to overwrite
payload += p64(system_plt) # Address to write
