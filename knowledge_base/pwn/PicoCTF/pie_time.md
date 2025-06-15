# PIE TIME

Level: Easy

## Initial Thoughts
This challenge is called PIE TIME, so right away I am thinking PIE is likely enabled, but nothing else --- seeing as this is an Easy level challenge.

This thought was solidified further after reading the description:
```
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
2. Determine the address of win
3. Jump to win and, well, win!

Since step 1 is literally given to us, the next thing we need to try to do is determine the address of win. We can't just grab it once because PIE is enabled, so it is always going to change. But, here's the key, what about finding the relative offset between main and win?!? Since ASLR isn't enabled, that offset is always going to be the same. Let's find the relative offset real quick, and then it should be easy-peasy to exploit the code.

Let's fire up gdb with the program binary.
```sh
$ gdb ./vuln
...
[ TODO ]
```

Voiala. From that, we see we have the address 0x... for main and 0x... for win. We can subtract these and we get 0x49 (something like that). Perfect. Now we know what the relative offset is.

Let's run the service and see if this works:
```
$ nc rescued-float.picoctf.net <port>
... [show the output, along with provided main]
... [mention how we do the math real quick locally]
... give the correct address
```

Awesome, but now let's automate it! We can use `pwntools` for this:

```python
from pwn import *

...

```