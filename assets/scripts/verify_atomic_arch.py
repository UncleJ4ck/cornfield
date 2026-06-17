#!/usr/bin/env python3
"""Re-derive every load-bearing Atomic Arch IOC from the five samples, read-only.
Usage: verify_atomic_arch.py deps jsdigest_deps.bin bin_linux.elf bin_linux_v2.elf stock/monero-wallet-gui"""
import sys, hashlib, zlib, struct

deps, jsd, v1, v2, stock = sys.argv[1:6]
ONION = b"olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion"
rd = lambda p: open(p, "rb").read()
ok = bad = 0
def check(label, got, exp):
    global ok, bad
    hit = got == exp; ok += hit; bad += not hit
    print(f"  [{'OK ' if hit else 'XXX'}] {label:42} {got if got==exp else f'{got!r} != {exp!r}'}")

check("deps sha256",      hashlib.sha256(rd(deps)).hexdigest()[:16], "6144d433f8a03168")
check("js-digest sha256", hashlib.sha256(rd(jsd)).hexdigest()[:16],  "7883bda1ff15425f")

def onion(p, koff, coff):
    d = rd(p); k = d[koff:koff+32]; c = d[coff:coff+62]
    return bytes(c[i] ^ k[i % 32] for i in range(62))
check("deps onion @key0x1AA60/ct0x2DA96",   onion(deps, 0x1AA60, 0x2DA96), ONION)
check("js-digest onion @key0x1CBA0/ct0x32BCB", onion(jsd, 0x1CBA0, 0x32BCB), ONION)
check("deps cleartext-onion count",      rd(deps).count(ONION), 0)
check("js-digest cleartext-onion count", rd(jsd).count(ONION),  0)

def carve_bpf(p):
    d = rd(p); i = 0
    while (i := d.find(b"\x7fELF", i)) >= 0:
        if struct.unpack_from("<H", d, i+18)[0] == 247:
            shoff = struct.unpack_from("<Q", d, i+0x28)[0]
            n = struct.unpack_from("<H", d, i+0x3C)[0]
            sz = shoff + n*64
            return i, sz, hashlib.sha256(d[i:i+sz]).hexdigest()[:16]
        i += 1
check("deps bpf @offset/size",      carve_bpf(deps)[:2], (0x324f9, 52776))
check("js-digest bpf @offset/size", carve_bpf(jsd)[:2],  (0x37d91, 52776))
check("bpf object byte-identical",  carve_bpf(deps)[2] == carve_bpf(jsd)[2], True)
check("bpf object sha256",          carve_bpf(deps)[2], "3607de2597f8955f")

jd = rd(jsd)
check("GPG argline literal @",   jd.find(b"--batch --no-tty --list-keys"), 0x29c9b)
check("X-Vault-Token header @",  jd.find(b"X-Vault-Token:"),                0x29cd5)
check("/.vault-token path @",    jd.find(b"/.vault-token"),                 0x2c537)

e = rd(v1)
check("865BH8 drain addr in v1 ELF", e.count(b"865BH8"), 0)
check("createTxAll raw symbol hits (sample)", e.count(b"createTransactionAllAsync"), 9)
check("createTxAll raw symbol hits (stock)",  rd(stock).count(b"createTransactionAllAsync"), 2)

def main_qml(p):
    d = rd(p)
    for i in range(len(d)-1):
        if d[i] == 0x78 and d[i+1] in (0x01, 0x9c, 0xda):
            try: dec = zlib.decompressobj().decompress(d[i:i+0x60000])
            except Exception: continue
            if b"onHeightRefreshed" in dec and (b"865BH8" in dec or b"createTransactionAllAsync" in dec):
                return i, dec
def drain_block(q):
    s = q.find(b"if (walletSynced"); depth = 0; started = False; j = s
    while j < len(q):
        if q[j:j+1] == b"{": depth += 1; started = True
        elif q[j:j+1] == b"}":
            depth -= 1
            if started and not depth: return q[s:j+1]
        j += 1
for tag, p, off, usize, sha, calls in [
    ("v1",    v1,    0xc4194a, 97914, "ce8ecab937cf7109", 2),
    ("v2",    v2,    0xc4194a, 97914, "ce8ecab937cf7109", 2),
    ("stock", stock, 0x7df0c8, 97241, "5007f0bb9b579176", 1)]:
    o, q = main_qml(p)
    check(f"{tag} main.qml @offset",  o, off)
    check(f"{tag} main.qml usize",    len(q), usize)
    check(f"{tag} main.qml sha256",   hashlib.sha256(q).hexdigest()[:16], sha)
    check(f"{tag} createTxAll QML call sites", q.count(b"createTransactionAllAsync"), calls)
b = drain_block(main_qml(v1)[1])
check("drain block length",  len(b), 663)
check("drain block sha256",  hashlib.sha256(b).hexdigest()[:16], "488699593ea4bfe4")

check("v2 == sha256(v1[:15933790])", hashlib.sha256(e[:15933790]).hexdigest()[:16], "6e4b611243aa2d26")
check("v3 == sha256(v1[:20516912])", hashlib.sha256(e[:20516912]).hexdigest()[:16], "92c40b92e909cd3d")
shoff = struct.unpack_from("<Q", e, 0x28)[0]; n = struct.unpack_from("<H", e, 0x3C)[0]
check("v1 e_shoff + 36*64 == filesize", shoff + n*64, 27787328)
check("drain zlib stream < both truncations", 0xc4194a < 15933790, True)

print(f"\n  {ok} checks reproduced, {bad} failed")
