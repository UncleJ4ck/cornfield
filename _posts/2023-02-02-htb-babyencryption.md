---
layout: post
title: "BabyEncryption (HTB crypto)"
subtitle: "an affine byte cipher inverted by brute-forcing the printable range"
date: 2023-02-02
tags: [htb, ctf, crypto, affine]
category: writeups
kind: challenge
tldr: "The challenge encrypts each plaintext byte with the affine map (123*p + 18) mod 256 and stores the result as hex. Since the keyspace per byte is tiny, I recovered every byte by brute-forcing the printable ASCII range against the ciphertext."
---

## the challenge

I got two files: the encryptor `chall.py` and the ciphertext `msg.enc`. The encryptor walks the secret message byte by byte and pushes each through one arithmetic step:

```python
import string
from secret import MSG

def encryption(msg):
    ct = []
    for char in msg:
        ct.append((123 * char + 18) % 256)
    return bytes(ct)

ct = encryption(MSG)
f = open('./msg.enc','w')
f.write(ct.hex())
f.close()
```

`char` here is an int (iterating a `bytes` yields ints), so the math runs on the raw byte value. The output is hex-encoded into `msg.enc`:

```text
6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921
```

That hex is 160 characters, so 80 ciphertext bytes, meaning an 80-byte plaintext.

## the bug

This is a textbook affine cipher over `Z_256`: `c = (a*p + b) mod 256` with `a = 123` and `b = 18`. Both constants are hardcoded in the source, there is no key file, no padding, no chaining. Every byte is encrypted independently with the same map.

The map is a bijection because `a = 123` is odd and therefore coprime to `256 = 2^8`. `gcd(123, 256) = 1` means multiplication by `123` is a permutation of `Z_256`, so each ciphertext byte has exactly one plaintext byte preimage. That is what makes it invertible.

The clean inverse comes from rearranging the equation:

```text
c       ≡ 123*p + 18   (mod 256)
c - 18  ≡ 123*p        (mod 256)
p       ≡ 123^-1 * (c - 18)  (mod 256)
```

The modular inverse of `123` mod `256` is `179`, since `123 * 179 = 22017 = 86*256 + 1`, so `123 * 179 ≡ 1 (mod 256)`. That gives the direct decrypt:

```text
p = 179 * (c - 18) mod 256
```

I did not bother computing that inverse to solve it, though. The plaintext is printable text and the printable ASCII range is only about 93 values, so per byte I could just try every printable candidate and keep the one whose forward encryption matched the ciphertext byte. Same result, no inverse needed.

## the solve

`decode.py` reads the hex, converts it back to bytes, and for each ciphertext byte loops over printable values `33..125`, re-applying the exact forward formula until it lands on a match:

```python
import string
import sys

fd = open('msg.enc','r')

secret = fd.read()
ct = bytes.fromhex(secret)

decrypted_str = ""

for char in ct:
    for brute_val in range(33, 126):
        if ((123 * brute_val + 18) % 256) == char:
            decrypted_str += chr(brute_val)
            break

print(decrypted_str)
```

The inner loop is the trick: for each ciphertext byte it tests every printable byte `brute_val`, runs the same `(123*brute_val + 18) % 256` the encryptor used, and breaks on the first value that reproduces the ciphertext byte. Because the map is a bijection there is exactly one such value, so the first hit is the answer.

Running it printed the message in one pass:

```text
$ python3 decode.py
Th3nucl34rw1ll4rr1v30nfr1d4y.HTB{...}
```

The plaintext was a short sentence followed by the flag in `HTB{...}` form, all of it leetspeak. One detail: the brute-force range is `33..125`, which excludes the space (`0x20`, 32) and the newline (`0x0a`, 10) that are in the real plaintext. Those bytes have no candidate in `33..126`, so the loop finds no match and silently skips them, collapsing the output into a run-on string with no gaps. The flag itself is intact because flags have no spaces, but the surrounding sentence loses its word breaks. The clean inverse keeps them:

```python
ai = pow(123, -1, 256)          # 179
ct = bytes.fromhex(open('msg.enc').read())
pt = bytes(((ai * (c - 18)) % 256) for c in ct)
print(pt)
# b'Th3 nucl34r w1ll 4rr1v3 0n fr1d4y.\nHTB{...}'   spaces and newline preserved
```

## the flag

The flag dropped straight out of either approach in the `HTB{...}` form. Inverting a per-byte affine map is trivial when the alphabet is this small. Even without computing `123^-1 mod 256 = 179`, brute-forcing the printable range recovers every byte in one pass, with the only cost being the few non-printable bytes the narrow range skips.
