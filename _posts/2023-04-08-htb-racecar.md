---
layout: post
title: "RaceCar (HTB pwn)"
subtitle: "a raw printf on attacker input, format string with everything else locked down"
date: 2023-04-08
tags: [htb, pwn, format-string]
category: writeups
kind: challenge
tldr: "All the usual mitigations are on (Full RELRO, canary, NX, PIE), but the binary passes user input straight to printf as the format string. Format-string primitives read and write around the mitigations to reach the flag."
---

## the bug

Protections are maxed:

```
Arch: i386-32-little
RELRO: Full RELRO   Stack: Canary   NX: enabled   PIE: enabled
```

But the winner-announcement path prints your input directly:

```c
read(0, __format, 0x170);
printf(__format);          // format string
```

With PIE and Full RELRO, the GOT is not the target. Use the format string to leak stack and code pointers first (defeating PIE and locating the canary), then a targeted `%n` write, or simply read the flag out of memory if it is resident, to finish. The uncontrolled `printf` is the entire game.
