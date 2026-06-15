---
layout: post
title: "SimpleEncryptor (HTB rev)"
subtitle: "the encryptor writes its own srand seed into the file header, so the cipher is reversible"
date: 2023-02-02
tags: [htb, ctf, rev, crypto, prng]
category: writeups
kind: challenge
tldr: "The encryptor seeds rand() with time(NULL) and, fatally, writes that 4-byte seed to the front of the output before the ciphertext. With the seed I replay the same rand() stream and undo each byte's xor-then-rotate in reverse order."
---

## the challenge

SimpleEncryptor ships as two files: a 64-bit ELF `encrypt` and an encrypted `flag.enc`. No author notes, so I worked it from the binary's behavior.

```
encrypt:  ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

`flag.enc` is 32 bytes:

```
$ xxd flag.enc
00000000: 5a35 b162 00f5 3e12 c0bd 8d16 f0fd 7599  Z5.b..>.......u.
00000010: faef 399a 4b96 21a1 4316 2371 65fb 274b  ..9.K.!.C.#qe.'K
```

The job is to recover the plaintext flag the binary produced. Since `encrypt` is not stripped, `main` reads cleanly and there is no decompiler guesswork.

## analysis

`main` opens a file called `flag`, measures it with `fseek`/`ftell`, allocates a heap buffer and reads the whole thing in. The filenames come straight out of `.rodata`:

```
$ objdump -s -j .rodata encrypt
 2000 01000200 72620066 6c616700 77620066  ....rb.flag.wb.f
 2010 6c61672e 656e6300                     lag.enc.
```

So `fopen("flag","rb")` for input and `fopen("flag.enc","wb")` for output. After the read it seeds the PRNG from the wall clock:

```nasm
  132f:  mov    edi,0x0
  1334:  call   1140 <time@plt>          ; time(NULL)
  1339:  mov    DWORD PTR [rbp-0x38],eax  ; seed = (int)time(NULL)
  133c:  mov    eax,DWORD PTR [rbp-0x38]
  1341:  call   1120 <srand@plt>          ; srand(seed)
```

The seed is stashed in a stack slot at `[rbp-0x38]`. Then the per-byte transform loop. Two `rand()` calls per byte, in a fixed order:

```nasm
  1350:  call   1190 <rand@plt>          ; first rand()
  1355:  movzx  ecx,al                   ; take low byte
  ...
  136c:  xor    ecx,eax                  ; buf[i] ^= rand() & 0xff
  137b:  mov    BYTE PTR [rax],dl        ; store
  137d:  call   1190 <rand@plt>          ; second rand()
  1382:  and    eax,0x7                  ; & 7  -> rotate count
  ...
  13b4:  rol    sil,cl                   ; buf[i] = rol(buf[i], cnt)
  13b9:  mov    BYTE PTR [rdx],al        ; store
  13bb:  add    QWORD PTR [rbp-0x30],0x1 ; i++
  13c4:  cmp    rax,QWORD PTR [rbp-0x20] ; i < size ?
  13c8:  jl     1350
```

In C that loop is:

```c
seed = time(NULL);
srand(seed);
for (i = 0; i < size; i++) {
    buf[i] ^= rand() & 0xff;            // step 1: xor with a random byte
    buf[i]  = rol(buf[i], rand() & 7);  // step 2: rotate left by 0..7
}
```

The order matters for inversion: per byte, the first `rand()` is the xor mask, the second `rand()` (masked to 3 bits) is the left-rotate amount. Both are drawn from the same glibc stream.

The fatal part is what happens after the loop. The output is written seed-first, then ciphertext:

```nasm
  13d8:  call   1170 <fopen@plt>         ; fopen("flag.enc","wb")
  13e5:  lea    rax,[rbp-0x38]           ; &seed
  13ec:  mov    edx,0x4
  13f1:  mov    esi,0x1
  13f9:  call   1180 <fwrite@plt>        ; fwrite(&seed, 1, 4, out)
  1406:  mov    rax,QWORD PTR [rbp-0x18] ; buf
  140f:  mov    rdi,rax
  1412:  call   1180 <fwrite@plt>        ; fwrite(buf, 1, size, out)
```

```c
out = fopen("flag.enc", "wb");
fwrite(&seed, 1, 4, out);   // the seed goes in the header
fwrite(buf, 1, size, out);  // then the ciphertext
```

Seeding `rand()` from `time(NULL)` is already weak (a small brute over candidate seconds would crack it), but here there is nothing to brute. The seed is handed to me as the first four bytes of the file. From the hexdump those are `5a 35 b1 62`, little-endian:

```
$ python3 -c 'import struct;print(struct.unpack("<I",bytes.fromhex("5ab1...".replace(" ",""))[:4]) if 0 else struct.unpack("<I", open("flag.enc","rb").read(4))[0])'
1655780698        # 0x62b1355a
```

That leaves 28 bytes of ciphertext after the 4-byte header, which is the length of the flag.

## the solve

Inverting a byte means undoing the two operations in reverse: the encryptor did xor then rotate-left, so the decryptor rotates-right then xors. The trap is the `rand()` consumption order. I still have to pull the xor mask first and the rotate count second (same order the encryptor drew them), then apply them backward:

```python
import struct

class GlibcRand:
    # glibc TYPE_3 additive-feedback rand(), the default for srand()
    def __init__(self, seed):
        self.r = [0] * 344
        self.r[0] = seed & 0xffffffff
        for i in range(1, 31):
            self.r[i] = (16807 * self.r[i - 1]) % 2147483647
        for i in range(31, 34):
            self.r[i] = self.r[i - 31]
        for i in range(34, 344):
            self.r[i] = (self.r[i - 31] + self.r[i - 3]) & 0xffffffff
        self.i = 344
    def next(self):
        idx = self.i
        self.r.append((self.r[idx - 31] + self.r[idx - 3]) & 0xffffffff)
        self.i += 1
        return (self.r[idx] >> 1) & 0x7fffffff

data = open("flag.enc", "rb").read()
seed = struct.unpack("<I", data[:4])[0]
ct   = data[4:]

rng = GlibcRand(seed)
out = bytearray()
for b in ct:
    x = rng.next() & 0xff   # first rand(): xor mask (drawn first)
    r = rng.next() & 7      # second rand(): rotate amount
    b = ((b >> r) | (b << (8 - r))) & 0xff  # undo rol with ror
    b ^= x                                  # undo xor
    out.append(b)

print(out.decode())
```

The one requirement is a `rand()` that matches glibc's stream byte for byte. glibc's default generator is not the textbook LCG; it is the TYPE_3 additive feedback variant, where state element `r[i] = r[i-31] + r[i-3]` and the returned value is the top 31 bits (`>> 1`). The reimplementation above mirrors that initialisation and step exactly, so the draw order lines up with what `encrypt` consumed. Running it:

```
$ python3 solve.py
HTB{...}
```

Twenty-eight printable bytes, a clean `HTB{...}` flag. If I had gotten the rotate inversion or the draw order wrong, the output would have been garbage, so the readable flag is the verification.

## the flag

Reading the seed from the header and replaying the stream undid the cipher exactly, and the 28 decrypted bytes spelled the `HTB{...}` flag, whose own wording admits the encryptor was a very simple file encryptor. Putting the key in the ciphertext is the whole bug. A keyed transform is only as strong as the key staying secret, and this one ships its key in the first four bytes. Even without that mistake the `time(NULL)` seed would have been weak: a brute over a small window of candidate seconds recovers it, since each guess either yields printable `HTB{...}` text or noise.
