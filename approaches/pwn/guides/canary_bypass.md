# Stack Canary Bypass

## What is a stack canary?

- A random value placed before saved RIP.
- Checked before function returns — if modified, crash.

## How to bypass?

1. **Leak canary** (infoleak or format string):
   - Example: `printf("%15$p")` — leak 15th stack element (might be canary).
2. **Overflow up to canary**.
3. **Write exact canary**.
4. **Continue overflow to RIP**.

### Example Layout (64-bit)

```
[ buffer (overflow) ] [ canary (unchanged) ] [ padding ] [ RIP ]
```

### Exploit Tips

- Canary often starts with `00` (to catch `strcpy`).
- In GDB: `x/gx $rsp` to view canary.
- Brute-forcing is infeasible — always leak!
