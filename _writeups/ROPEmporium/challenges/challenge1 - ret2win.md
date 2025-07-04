---
title: Challenge 1 - ret2win
nav_order: 1
has_children: true
parent: ROPEmporium
great_parent: Writeups
---

# Challenge 1: ret2win

Link: https://ropemporium.com/challenge/ret2win.html
Description: ret2win means "return here to win" and it's recommended you start with this challenge. Visit the challenge page by clicking this card to learn more.

## Initial Findings

As always, the first thing I did was run `checksec` on the binary: `checksec ret2win`. From this, we see:
```
[*] '/path/to/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

