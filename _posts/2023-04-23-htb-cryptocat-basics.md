---
layout: post
title: "CryptCat Basics (HTB pwn)"
subtitle: "gets() into a 16-byte buffer, where the overflow lands on a saved register instead of the return slot"
date: 2023-04-23
os: Linux
tags: [htb, pwn, buffer-overflow, gets, executable-stack, stack-pivot]
category: writeups
kind: challenge
tldr: "A 32-bit no-PIE binary reads into a 16-byte stack buffer with gets(). No canary, executable stack. But the force-aligned epilogue restores esp from a saved register before returning, so the overflow gives esp control at offset 16 rather than a clean return-address overwrite. I mapped the frame from the disassembly; the binary imports only gets, so there is no leak to turn that pivot into a known address."
---

## the challenge

The target was a single 32-bit Linux ELF named `vuln` and an instance to feed input to, `192.168.1.167:5000`. The source that ships with it is four lines:

```c
#include <stdio.h>
#include <string.h>

int main(void)
{
    char buffer[16];
    gets(buffer);
}
```

The shipped source listing includes a `Give me data plz:` prompt written with `printf`, but the binary I was handed imports neither `printf` nor `puts`, so nothing in it can print that prompt. `gets` is the whole program.

First I checked the file and the mitigations.

```text
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, ... not stripped
```

```text
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX unknown - GNU_STACK missing
PIE:      No PIE (0x8048000)
Stack:    Executable
RWX:      Has RWX segments
```

`pwn checksec` prints that odd `NX unknown - GNU_STACK missing` line, but the program headers settle it:

```text
GNU_STACK  0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
```

`RWE` on the stack segment means the stack is readable, writable, and executable, so shellcode placed there will run. No canary means nothing guards the saved frame. No PIE pins the image at `0x8048000`, so every address in the binary is fixed. That readout is the easy half.

The hard half is the import table:

```text
__libc_start_main@GLIBC_2.34
gets@GLIBC_2.0
```

Two symbols. There is no `puts`, no `printf`, no `system`, no `win` or `flag` function in the symbol table, and `strings` turns up no `/bin/sh` or flag-shaped text. So there is nothing to return into for a quick win, and nothing that prints a value back to leak an address.

## the bug

`gets` reads a line with no length argument, and the destination is a 16-byte stack buffer. The disassembly of `main` shows the frame:

```asm
08049176 <main>:
 8049176: lea    ecx,[esp+0x4]
 804917a: and    esp,0xfffffff0
 804917d: push   DWORD PTR [ecx-0x4]
 8049180: push   ebp
 8049181: mov    ebp,esp
 8049183: push   ebx
 8049184: push   ecx
 8049185: sub    esp,0x10
 ...
 8049195: lea    edx,[ebp-0x18]        ; buffer
 8049198: push   edx
 804919b: call   8049050 <gets@plt>
 ...
 80491a8: lea    esp,[ebp-0x8]
 80491ab: pop    ecx
 80491ac: pop    ebx
 80491ad: pop    ebp
 80491ae: lea    esp,[ecx-0x4]
 80491b1: ret
```

The buffer is passed as `[ebp-0x18]`, so it sits 24 bytes below saved `EBP`. Anything past 16 bytes of input keeps writing up the stack into the saved registers.

## the epilogue that changes the offset

The reflex on a `gets` overflow is "buffer + saved EBP + 4 to the return address." That math does not hold here, because this `main` was compiled with a force-aligned stack frame, and the epilogue does not return through `[ebp+4]`.

Read the prologue. `lea ecx,[esp+0x4]` captures a pointer just above the original return address, then `and esp,0xfffffff0` aligns the stack, then `push DWORD PTR [ecx-0x4]` copies the original return address onto the aligned frame. `push ebx` and `push ecx` then save those registers, so the saved `ECX` lands at `[ebp-0x8]`.

Now the epilogue:

```asm
 80491a8: lea    esp,[ebp-0x8]   ; esp -> saved-ecx slot
 80491ab: pop    ecx             ; ecx = [ebp-0x8]
 80491ac: pop    ebx
 80491ad: pop    ebp
 80491ae: lea    esp,[ecx-0x4]   ; esp = ecx - 4
 80491b1: ret                    ; eip = [esp] = [ecx-0x4]
```

`esp` is rebuilt from whatever `pop ecx` just loaded, and the final `ret` reads `EIP` from `[ecx-0x4]`. The copy of the return address sitting at `[ebp+0x4]` is never read. Control flow goes through the saved `ECX`, not the saved return slot.

The saved `ECX` is at `[ebp-0x8]`, and the buffer starts at `[ebp-0x18]`. The distance between them is `0x18 - 0x8 = 16` bytes. So the first 16 bytes fill the buffer exactly, and bytes 17 through 20 overwrite the saved `ECX`. What that buys is not a return-address overwrite, it is `esp` control: `lea esp,[ecx-0x4]` pivots the stack to `ecx-4`, and the `ret` then jumps to whatever that new stack top points at. The overflow hands over a stack pivot at offset 16.

## finding the offset

I drove the binary under gdb-peda and reached for the usual cyclic-pattern method: `break main`, `pattern create`, `run`, then `p/x $eip` to read which four pattern bytes ended up in the instruction pointer, and `pattern offset` to look them up. On a normal frame that converges in a few commands.

It cannot converge on this one, and the epilogue above is why. With a pattern in the buffer, `pop ecx` loads four pattern bytes, `lea esp,[ecx-0x4]` points `esp` at an unmapped address, and the `ret` faults on the read before any pattern byte reaches `EIP`. The fault lands on the `ret` at `0x80491b1`, so `$eip` holds that address, not a pattern dword, and there is nothing for `pattern offset` to resolve. The gdb history matches a method that did not land cleanly: a range of `pattern create` sizes (200, 2000, 5000, 6000, then 20 and 30), repeated runs, and long stretches of stepping through `main` with `n` to read the registers by hand.

The offset that matters comes off the disassembly, not the pattern: 16 bytes to the saved `ECX`, which is the `esp` pivot.

## where the record ends

The shape of the solve is forced by the constraints. The stack is executable, so shellcode in the buffer is runnable. The pivot at offset 16 lets me point `esp` wherever I want, which means I can aim the post-`ret` stack at the shellcode I just wrote. The missing piece is an address: the pivot target has to be a concrete stack location, and the binary imports only `gets`, with no `puts` or `printf` to print one back. There is no leak primitive in the image, so turning the pivot into a working exploit needs a stack address known ahead of time, which on a local instance means ASLR disabled.

The recorded work covers the analysis through that point: the bug, the mitigation profile, the force-aligned epilogue, and the `esp` control it yields at offset 16. I do not have the finished exploit or the flag captured in these notes, so the writeup stops where the evidence does.