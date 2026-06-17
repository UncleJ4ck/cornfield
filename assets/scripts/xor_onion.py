#!/usr/bin/env python3
"""Decode the C2 onion from a stealer ELF (repeating-key XOR). --js for the js-digest build."""
import sys

DEPS = {"key_off": 0x1AA60, "key_len": 32, "ct_off": 0x2DA96, "ct_len": 62}
JS   = {"key_off": 0x1CBA0, "key_len": 32, "ct_off": 0x32BCB, "ct_len": 62}

def decode(path, p):
    b = open(path, "rb").read()
    key = b[p["key_off"]:p["key_off"] + p["key_len"]]
    ct  = b[p["ct_off"]:p["ct_off"] + p["ct_len"]]
    plain = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
    print(f"key  @0x{p['key_off']:X} : {key.hex()}")
    print(f"ct   @0x{p['ct_off']:X} ({len(ct)} bytes)")
    print(f"loop : ct[i] ^ key[i % {len(key)}]")
    print(f"plain: {plain.decode('ascii', 'replace')}")

args = [a for a in sys.argv[1:] if a != "--js"]
decode(args[0], JS if "--js" in sys.argv else DEPS)
