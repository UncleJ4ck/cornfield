---
layout: post
title: "PwnHunting (HTB pwn)"
subtitle: "the flag is moved to a random page and the disk copy wiped, so the shellcode has to hunt it down in memory under seccomp"
date: 2023-02-02
tags: [htb, ctf, pwn, shellcode, seccomp, egghunter]
category: writeups
kind: challenge
os: Linux
tldr: "A 32-bit PIE binary relocates its own flag string to a randomly chosen page, zeroes the .data copy, installs a seccomp filter that kills open/openat/creat/execve/fork, then mmaps a RWX page and runs 60 bytes of my shellcode. open is dead and the address is random, so the solve is an egghunter that walks memory for the HTB{ egg and writes it to stdout."
---

## the challenge

PwnHunting hands over a single file, `hunting`, and a remote instance. My old notes said to load it in Ghidra, find the `HTB{...}` string sitting at a fixed address, and "redirect execution to a win function." That premise is wrong. There is no overflow, no win function, and no leak. The flag is referenced from `main`, which always runs, and `main` deliberately erases the disk copy and hides the live copy at a random address before it ever hands control to me. The name is the hint. The flag is already in memory, somewhere, and the job is to hunt it down.

## recon

```text
hunting: ELF 32-bit LSB pie executable, Intel i386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2,
BuildID[sha1]=801f10407444c1390cae5755d9e952f3feadf3eb,
for GNU/Linux 3.2.0, stripped
```

32-bit, PIE, and stripped. The mitigations:

```text
RELRO:      Full RELRO
Stack:      No canary found
PIE:        PIE enabled
```

pwntools also printed `NX unknown - GNU_STACK missing`, but that is a parsing quirk. `readelf -l` shows the stack segment is present and marked executable:

```text
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
```

The executable stack does not matter here, because `main` builds its own `RWX` page to run code out of. The strings give the shape of the challenge up front:

```text
prctl(PR_SET_NO_NEW_PRIVS)
prctl(PR_SET_SECCOMP)
/dev/urandom
HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

So the binary seeds itself from `/dev/urandom`, installs a seccomp filter, and ships the flag inline. The distributed binary carries a placeholder where the flag goes: 36 bytes reading `HTB{` then 31 `X` and a closing brace. The hexdump puts it in `.data` at virtual address `0x4020`:

```text
00003020: 4854 427b 5858 5858 5858 5858 5858 5858  HTB{XXXXXXXXXXXX
00003030: 5858 5858 5858 5858 5858 5858 5858 5858  XXXXXXXXXXXXXXXX
00003040: 5858 587d 0000 0000 0000 0000 0000 0000  XXX}............
```

## what main does

The PIE entry point passes a `main` pointer loaded from `[ebx+0x50]`. That slot holds a relative relocation, and its addend settles the address:

```text
$ xxd -s 0x2ff8 -l 4 hunting
00002ff8: 6014 0000                                `...
```

`main` is at `0x1460`. Reading it top to bottom, it does six things in order. First it builds a random page address, through the helper at `0x13d0`:

```asm
13e9: push   0x0
13eb: lea    eax,[ebx-0x1f6f]          ; "/dev/urandom"
13f2: call   1180 <open@plt>
...
1409: call   1130 <read@plt>           ; read(fd, &seed, 8)
1429: call   1190 <srand@plt>          ; srand(seed)
...
143a: call   11e0 <rand@plt>
143f: shl    eax,0x10                   ; rand() << 16, so 64K-aligned
1445: cmp    DWORD PTR [ebp-0xc],0x5fffffff
144c: jle    143a                       ; signed: regenerate if <= 0x5fffffff
1451: cmp    eax,0xf7000000
1456: ja     143a                       ; regenerate if > 0xf7000000
```

The value is `rand()` shifted left 16, so the low 16 bits are zero and the result is 64K-aligned. The `jle` at `0x144c` is a signed compare, so any candidate with the top bit set reads as negative, falls under `0x5fffffff`, and gets thrown back. That caps the accepted window at the 2GB line. The address that survives both checks lands in `0x60000000` to `0x7fff0000`, 64K-aligned.

Back in `main`, that random address becomes a fixed mapping, and the flag is copied into it:

```asm
14b0: push   0x0                        ; offset
14b2: push   0xffffffff                 ; fd = -1
14b4: push   0x31                       ; MAP_SHARED|MAP_FIXED|MAP_ANONYMOUS
14b6: push   0x3                        ; PROT_READ|PROT_WRITE
14b8: push   0x1000
14bd: push   eax                        ; addr = the random address
14be: call   11a0 <mmap@plt>
...
14dc: lea    eax,[ebx+0x78]             ; 0x4020 = the flag in .data
14e3: push   DWORD PTR [ebp-0x10]       ; dest = the random RW page
14e6: call   1170 <strcpy@plt>          ; strcpy(page, flag)
14f1: push   0x25                       ; 37 bytes
14f3: push   0x0
14f5: lea    eax,[ebx+0x78]             ; 0x4020 again
14fc: call   11c0 <memset@plt>          ; memset(flag_in_.data, 0, 37)
```

This is the whole trick. The flag is `strcpy`'d from `0x4020` into the random page, then the original `.data` copy is zeroed with `memset(..., 0, 0x25)`. After `main` runs, the only copy of the flag in the process is sitting at an address I was never told. Then the sandbox goes up, via the helper at `0x133d`:

```asm
136d: push   0x26                       ; PR_SET_NO_NEW_PRIVS
136f: call   11d0 <prctl@plt>
...
139e: push   0x2                        ; SECCOMP_MODE_FILTER
13a0: push   0x16                       ; PR_SET_SECCOMP
13a2: call   11d0 <prctl@plt>
```

Finally `main` maps a `RWX` page, reads 60 bytes of my input into it, and jumps to it:

```asm
1517: push   0x21                       ; MAP_SHARED|MAP_ANONYMOUS
1519: push   0x7                        ; PROT_READ|PROT_WRITE|PROT_EXEC
151b: push   0x1000
1522: call   11a0 <mmap@plt>            ; mmap(0, 0x1000, RWX, ...)
...
1530: push   0x3c                       ; 60
1532: push   DWORD PTR [ebp-0x14]       ; the RWX page
1535: push   0x0                        ; fd = stdin
1537: call   1130 <read@plt>            ; read(0, page, 60)
...
1547: mov    eax,DWORD PTR [ebp-0x14]
154a: call   eax                        ; run the shellcode
```

There is also a `signal(SIGALRM, exit)` and `alarm(10)` near the top of `main`. The relocation table confirms the handler slot at `0x3ff4` resolves to `exit`, so the process self-terminates after ten seconds. It is an anti-hang timeout, nothing more.

## the seccomp filter

The filter is a 14-entry BPF program in `.data` at `0x4060`. It loads the syscall number and kills a blacklist, letting everything else through. Decoding the `sock_filter` entries (`JEQ nr ? KILL`) against the i386 syscall table:

```text
code  k        syscall (i386)
JGE   40000000 x32 / high range   -> KILL
JEQ   0b (11)  execve             -> KILL
JEQ   166(358) execveat           -> KILL
JEQ   127(295) openat             -> KILL
JEQ   05 (5)   open               -> KILL
JEQ   06 (6)   close              -> KILL
JEQ   08 (8)   creat              -> KILL
JEQ   56 (86)  uselib             -> KILL
JEQ   02 (2)   fork               -> KILL
JEQ   be (190) vfork              -> KILL
                (fall through)    -> ALLOW
```

It is a "no new files, no new processes" sandbox. Every way to open a file descriptor is gone (`open`, `openat`, `creat`), so I cannot re-read the flag off disk, and the `.data` copy is already zeroed anyway. Every way to spawn a process is gone (`execve`, `execveat`, `fork`, `vfork`), so there is no shell. What is left is enough: `read`, `write`, `mmap`, and `exit` all fall through to `ALLOW`. So does `access` (syscall 33), which matters for the scan.

## the solve

The flag is already mapped and readable. I just do not know where. So the shellcode is an egghunter: walk memory looking for the four-byte egg `48 54 42 7b` (`HTB{`, the little-endian dword `0x7b425448`), and when it hits, `write` the 37 bytes starting there to stdout.

The constants all come from the binary:

- the egg is `HTB{`, bytes `48 54 42 7b`, from the `.data` hexdump at `0x4020`.
- the flag is 37 bytes (36 plus the terminator), from `push 0x25` before the `memset` at `0x14f1`.
- the shellcode budget is 60 bytes, from `push 0x3c` before the `read` at `0x1530`.
- `write` is allowed and `open`/`openat`/`creat` are killed, from the filter above.

The one wrinkle is that a blind linear scan across `0x60000000` upward will dereference unmapped pages and eat a `SIGSEGV` long before it reaches the flag. The usual fix is a syscall that returns `EFAULT` on a bad pointer instead of faulting, used to validate each page before touching it. `access` survives the filter, so probing each candidate page with `access(addr, ...)` and checking for `EFAULT` gives a safe walk. Once a page validates, scan it for the egg, then `write(1, hit, 37)`.

## the flag

Against the distributed binary there is nothing real to recover. The `strcpy` relocates the placeholder, so an egghunter run locally finds and prints `HTB{` followed by the 31 `X` the file ships with, which the hexdump above already shows. On the live instance the placeholder is swapped for the real flag before the binary is built, and the same egghunter writes those 37 bytes back over the connection. The flag itself is not in anything I was given, so I am not going to invent one. The interesting part of this challenge was never the string. It was that `main` quietly moves the flag to a random page and wipes the original, turning a "read the flag" problem into a memory hunt under a syscall sandbox.