---
layout: post
title: "RsaCtfTool (HTB crypto)"
subtitle: "an RSA modulus that is a prime cube, so phi comes straight from the single prime"
date: 2023-07-28
tags: [htb, ctf, crypto, rsa, prime-power]
category: writeups
kind: challenge
tldr: "The public modulus n is a prime cube p^3, which breaks the usual two-prime phi formula. With p from the integer cube root (or factordb) I computed phi = p^2*(p-1), recovered d, decrypted the RSA-wrapped AES key, then AES-ECB decrypted flag.txt.aes."
---

## the challenge

I had three files: a public key `pubkey.pem`, an RSA-encrypted `key`, and `flag.txt.aes`. The chain was a wrapped-key scheme. `key` is an AES key encrypted under the RSA public key, and `flag.txt.aes` is the flag encrypted with AES-ECB under that AES key. So the order of operations was fixed: break RSA, decrypt `key` to recover the AES key, then AES-decrypt the flag.

Loading the public key gave me `n` and `e`:

```python
from Crypto.PublicKey import RSA
pub = RSA.importKey(open('pubkey.pem').read())
n, e = pub.n, pub.e
# e = 65537   (the usual 0x10001)
# n is 1535 bits
```

`e` was the standard `65537`. `n` came out at 1535 bits, which is the first oddity. A normal two-prime RSA-1536 modulus would be very close to 1536 bits. A number landing one bit short of a round size hints that it is not a product of two same-size primes but something with a different factor structure.

## analysis

The modulus is not the product of two distinct primes. It is a prime power, `n = p^3`. Two things give it away. Pasting `n` into factordb returns a single base raised to the third power instead of two cofactors. And taking the integer cube root of `n` succeeds exactly: the cube root is a whole number, and cubing it reproduces `n`.

```python
def iroot(x, k):           # integer k-th root by binary search
    hi = 1
    while hi ** k < x:
        hi *= 2
    lo = hi // 2
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** k < x:
            lo = mid + 1
        else:
            hi = mid
    return lo

p = iroot(n, 3)
assert p ** 3 == n         # holds: n really is p^3
# p is 512 bits, so p^3 is ~1535 bits, which explains the modulus size
```

So `p` is a single 512-bit prime and `n = p^3`. That is what changes the totient. For two distinct primes you would use `phi = (p-1)*(q-1)`, but there is no second prime here. The Euler totient of a prime power is:

```text
phi(p^k) = p^k - p^(k-1) = p^(k-1) * (p - 1)
```

For the cube, `k = 3`:

```text
phi(p^3) = p^3 - p^2 = p^2 * (p - 1)
```

So the right totient is `phi = p^2 * (p - 1)`, which is `p*p*(p-1)`. This is the part people get wrong. It is not `p*(p-1)^2`. The structure of the multiplicative group `(Z/p^3 Z)*` has order `p^2 * (p - 1)`, and that exact value is what `e` must be inverted against.

Why the totient even works for decryption: the wrapped AES key `m` is a 16-byte integer, far smaller than the 512-bit `p`, so `gcd(m, n) = 1`. For any unit `m`, `m^(phi) ≡ 1 (mod n)`, so picking `d` with `e*d ≡ 1 (mod phi)` gives `m^(e*d) ≡ m (mod n)`. The whole break is then a single modular inverse:

```text
d = e^-1 mod phi
```

## the solve

`exp.py` imports the public key, recovers `p` (cube root, or pulled straight from factordb), builds the prime-cube totient, inverts `e`, and decrypts the wrapped key. Then it runs AES-ECB on the flag ciphertext:

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES

pub = RSA.importKey(open('pubkey.pem', 'r').read())
n = pub.n
e = pub.e

# p is the 512-bit prime, the integer cube root of n (also on factordb)
p = 10410080216253956216713537817182443360779235033823514652866757961082890116671874771565125457104853470727423173827404139905383330210096904014560996952285911
assert p ** 3 == n

phi = p * p * (p - 1)          # phi(p^3) = p^2 * (p - 1)
d = pow(e, -1, phi)

key = int(open('key', 'r').read(), 16)
key_decrypted = long_to_bytes(pow(key, d, n))   # undo the RSA wrap

cipher = AES.new(key_decrypted, AES.MODE_ECB)
ct = open('flag.txt.aes', 'rb').read()
print(cipher.decrypt(ct[:-1]))
```

Walking through it:

- `key` is read as a hex string and parsed to an int. `pow(key, d, n)` is the RSA decrypt, and `long_to_bytes` turns the result into bytes. It comes out as a 16-byte value, the AES-128 key: `b'secretkey\x96\x1dW\xbe\xc09<'`.
- `flag.txt.aes` is 33 bytes on disk. AES-ECB needs a multiple of 16, so the script trims the last byte with `ct[:-1]`. That last byte is a trailing newline (`0x0a`), not padding. Dropping it leaves 32 bytes, two clean 16-byte ECB blocks.
- `cipher.decrypt(ct[:-1])` decrypts both blocks and prints the flag.

Running it printed the flag in the `HTB{...}` form straight out of the AES decrypt:

```text
$ python3 exp.py
b'HTB{...}'
```

The challenge is named after `RsaCtfTool`, and the tool would have solved it without any of this. Its prime-power attack detects `n = p^k`, recovers `p`, and reconstructs the private key directly:

```bash
RsaCtfTool.py --publickey pubkey.pem --uncipherfile key
```

## the flag

The AES-ECB decrypt printed the flag in `HTB{...}` form. The whole break hinged on spotting that `n` was a prime cube rather than a semiprime. Taking the cube root, building `phi = p^2 * (p - 1)`, and inverting `e` gave a `d` that actually undid the RSA wrap. Using the two-prime `(p-1)*(q-1)` would have meant inventing a second prime that does not exist, producing the wrong totient and a useless key. Once the totient matched the prime-power structure, the rest was one modular inverse and one AES decrypt.
