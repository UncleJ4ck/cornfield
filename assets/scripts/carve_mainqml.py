#!/usr/bin/env python3
"""Carve main.qml out of each wallet ELF and extract the drain block. Read-only.
Pass the sample(s) then stock: carve_mainqml.py v1 v2 stock"""
import sys, zlib, hashlib

def main_qml(path):
    d = open(path, "rb").read()
    for i in range(len(d) - 1):
        if d[i] == 0x78 and d[i+1] in (0x01, 0x9c, 0xda):
            try:
                dec = zlib.decompressobj().decompress(d[i:i + 0x60000])
            except Exception:
                continue
            if b"onHeightRefreshed" in dec and (b"865BH8" in dec or b"createTransactionAllAsync" in dec):
                return i, dec
    return None, None

def drain_block(q):
    s = q.find(b"if (walletSynced")
    if s < 0:
        return None
    depth = 0
    for j in range(s, len(q)):
        if q[j] == 0x7b:
            depth += 1
        elif q[j] == 0x7d:
            depth -= 1
            if depth == 0:
                return q[s:j + 1]

first_qml = first_drain = None
for path in sys.argv[1:]:
    name = path.rsplit("/", 1)[-1]
    size = len(open(path, "rb").read())
    off, q = main_qml(path)
    qsha = hashlib.sha256(q).hexdigest()
    qdup = "   (byte-identical to v1)" if qsha == first_qml else ""
    first_qml = first_qml or qsha
    print(f"\n### {name}  ({size:,} bytes)")
    print(f"  main.qml zlib@{off:#x} usize={len(q)} sha256={qsha}{qdup}")
    print(f"           has_865BH8={b'865BH8' in q}  n_createTxAll={q.count(b'createTransactionAllAsync')}")
    blk = drain_block(q)
    if blk:
        bsha = hashlib.sha256(blk).hexdigest()
        bdup = "   (byte-identical to v1)" if bsha == first_drain else ""
        first_drain = first_drain or bsha
        print(f"  drain block (if(walletSynced)...close): len={len(blk)} sha256={bsha}{bdup}")
