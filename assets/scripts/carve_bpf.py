#!/usr/bin/env python3
"""Carve the embedded eBPF object out of each stealer ELF and hash it. Read-only."""
import sys, struct, hashlib

def carve(path):
    d = open(path, "rb").read()
    i = d.find(b"\x7fELF")
    while i >= 0:
        if struct.unpack_from("<H", d, i + 18)[0] == 247:
            etype = struct.unpack_from("<H", d, i + 0x10)[0]
            shoff = struct.unpack_from("<Q", d, i + 0x28)[0]
            shnum = struct.unpack_from("<H", d, i + 0x3c)[0]
            size = shoff + shnum * 64
            return i, etype, shnum, size, hashlib.sha256(d[i:i + size]).hexdigest()
        i = d.find(b"\x7fELF", i + 1)
    sys.exit(f"no BPF object in {path}")

first = None
for path in sys.argv[1:]:
    name = path.rsplit("/", 1)[-1]
    off, etype, shnum, size, sha = carve(path)
    if first is None:
        first = (name, sha)
        et = "REL" if etype == 1 else str(etype)
        print(f"{name:<17} @ file {off:#x} : ELF e_machine=247 (BPF), e_type={et}, {shnum} sections, {size} B")
    else:
        print(f"{name:<17} @ file {off:#x} : ELF e_machine=247 (BPF), {size} B")
    tag = f"   (BYTE-IDENTICAL to {first[0]})" if sha == first[1] and name != first[0] else ""
    print(f"{'':<17}   sha256 = {sha}{tag}")
