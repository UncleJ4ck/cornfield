#!/usr/bin/env python3
"""Reimplement the proxy's obfuscator.io string decoder (custom-alphabet base64, no RC4)
and round-trip the raw array against _strings.json. Usage: verify_proxy_decoder.py <dir>"""
import json, base64, re, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
CUSTOM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
STD    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
XLAT = str.maketrans(CUSTOM, STD)

def deob_decode(s):
    std = s.translate(XLAT)
    raw = base64.b64decode(std + '=' * ((-len(std)) % 4))
    return raw.decode('utf-8')

src = open(f"{ROOT}/index.beautified.js", encoding="utf-8", errors="replace").read()
m = re.search(r"function _0x3da7\(\)\s*\{\s*const _0x1fa417 = \[(.*?)\];", src, re.S)
if not m:
    print("FAIL: could not locate _0x1fa417 array"); sys.exit(2)
items = re.findall(r"'([^']*)'", m.group(1))
print(f"raw array entries parsed: {len(items)}")

decoded = {}
fails = []
for i, it in enumerate(items):
    try:
        decoded[str(i)] = deob_decode(it)
    except Exception as e:
        fails.append((i, it, str(e)))

ref = json.load(open(f"{ROOT}/_strings.json"))
match = miss = mismatch = 0
mism_samples = []
for k, v in ref.items():
    if k not in decoded:
        miss += 1; continue
    if decoded[k] == v:
        match += 1
    else:
        mismatch += 1
        if len(mism_samples) < 8:
            mism_samples.append((k, v, decoded[k]))

print(f"decode exceptions: {len(fails)}")
print(f"_strings.json entries: {len(ref)}  match: {match}  mismatch: {mismatch}  missing: {miss}")
if mism_samples:
    print("--- mismatches (idx | ref | mine) ---")
    for k, v, d in mism_samples:
        print(repr(k), repr(v), "||", repr(d))

print("\n--- anchor spot-checks (independent decode) ---")
for k in ["0", "3", "39", "18", "49", "66", "53"]:
    print(f"[{k}] -> {decoded.get(k)!r}")

verdict = "BASE64-ONLY (no RC4): reimplementation reproduces the array" if (mismatch == 0 and miss == 0 and not fails) else "DISCREPANCY"
print("\nVERDICT:", verdict)
