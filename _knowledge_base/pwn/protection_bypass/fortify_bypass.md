---
title: FORTIFY_SOURCE Bypass
parent: Protection Bypass
grand_parent: pwn
great_grand_parent: Knowledge Base
nav_order: 1
---

# Bypassing FORTIFY_SOURCE

## What is FORTIFY_SOURCE?

- A compiler feature that adds runtime checks for certain unsafe functions.
- Functions like `strcpy`, `sprintf`, `gets` are replaced with safer versions.
- Common compile flag:
```
-D_FORTIFY_SOURCE=2
```
- If a size check fails at runtime, the program crashes.

---

## When is it Active?

- Must be compiled with optimization flags (`-O1` or higher).
- Functions must have known buffer sizes at compile time to insert checks.

Example with FORTIFY:
```c
char buf[16];
strcpy(buf, input); // Checked version inserted
```

---

## How to Bypass?

### 1. Target Functions Not Protected

FORTIFY only protects known unsafe functions. Other functions like:
- `memcpy`
- `read`
- `recv`

May not be protected if used manually. Attack those instead.

Example:
```c
char buf[32];
read(0, buf, 128); // No fortify check
```

---

### 2. Use Non-Size Checked Calls

If the function does not know the destination size at compile time, the check may not be inserted:
```c
char* buf = malloc(16);
strcpy(buf, input); // No compile-time check
```

---

### 3. Attack Other Bugs

If classic buffer overflows are prevented:
- Look for use-after-free.
- Look for format string vulnerabilities.
- Look for double-free or heap overflows.

---

## Example

If `strcpy` is protected:
```c
char buf[16];
strcpy(buf, input);
```

Instead attack `read`:
```c
char buf[16];
read(0, buf, 128); // Overflow possible
```

---

## Summary

- FORTIFY_SOURCE adds extra checks for unsafe functions.
- Only certain libc functions are protected.
- Look for other input functions without size checks.
- Heap-related bugs often bypass fortify easily.

If FORTIFY is enabled and you can't overflow the stack, check heap-based vulnerabilities or format string issues.
