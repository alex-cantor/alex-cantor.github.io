# Pwn

This is my ultimate knowledge base of Pwn / Binary Exploitation

## What is Pwn

Pwn is essentially just the competitive offshoot of Binary Exploitation, where one tries to exploit vulnerabilities in compiled programs (binaries) to achieve some unintended behavior, often gain access to a flag.

---

## My Background

As of beginning to study pwn (6/8/2025), I began learning to code 10 years ago at CodeNinjas. I learned multiple programming languages (Python, JavaScript, C#) which prepared me for future college classes I would end up taking (notably, C++ and C). However, I, at this point, do not remember most of it. I am beginning my journey of getting as good as I can get at pwn.

---

## My Gameplan

As I first begin to learn pwn, I have prompted ChatGPT for good video resources for learning pwn in an engaging and effective way. With that, I have constructed a gameplan for the next 10 weeks:

### Week 1: Pwn Basics

#### Day 1

I began watching the LiveOverflow series and took the following notes (most of the initial stuff below is adapted from or nearly identical to content on the sockpuppet.org website).

- **Visualizing memory**: The memory, or RAM, can be imagined as a piece of paper. On the paper, you can write instructions line by line. Each line has a number assigned, from 0 to n (incrementing by 1 each new line). Similar to each line's number (eg. line 4195803), in memory, each instruction (which is actually an assembly instruction) has an address in hex (eg. address 0x4005db).
- **Stack**: The stack is just the bottom part of the memory
    - The stack starts from the very bottom of memory, and grows upwards (starts at the highest index)
- **Registers**: You are given 8-32 global variables (like any programming language) of fixed size to work with, called "registers"
    - The number of registers depends on the OS
    - The size of the register also depends on the OS: a 32bit OS will have registers that are 32 bits in width. Same thing for 64 bits. To store a number larger than the allocated size, you can write a bit more code to use multiple registers (and split up the number between the registers)
- **Special Registers**: Some of the registers are special registers
    - The most important of these is the **Program Counter** (aka PC, EIP, IP, or RIP, depending on OS) is advanced each time an instruction is executed. The Program Counter points to the line that is executed next.
    - Another is the **Stack Pointer** (SP, ESP, RSP). This pointer points to the top of the stack.
- Virtually all computation is expressed in terms of simple operations on registers
- Real programs need many more than 32 1-byte variables to work with, so what doesn't fit in registers lives in memory. Memory is accessed either with loads and stores at addresses, as if it were a big array, or through PUSH and POP operations on a stack
- Control flow is done via **GOTOs** (jumps, branches, calls). The effect of these instructions alters the program counter directly
    - A jump is just an unconditional GOTO
- Commands such as `mov eax, 5` is actually `B8050000`. A disassembler reads the `B8050000` and turns it into human-readable code

1st: [LiveOverflow: Binary Exploitation / Memory Corruption [YouTube Playlist]](https://www.youtube.com/watch?v=6jSKldt7Eqs&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=5)
2nd: [OpenSecurityTraining — Intro to x86]()
3rd: [Ropper’s Guide to pwning]()
4th: [Protostar (exploit-exercises) + Video Walkthroughs]()
