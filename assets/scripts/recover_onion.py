#!/usr/bin/env python3
"""Sweep a stealer ELF for the C2 onion stored as repeating-key XOR (any key length 1..61)."""
import sys, numpy as np

PATH = sys.argv[1]
ONION = b"olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion"
data = np.frombuffer(open(PATH, "rb").read(), dtype=np.uint8)
n = len(ONION)
plain = np.frombuffer(ONION, dtype=np.uint8)
win = np.lib.stride_tricks.sliding_window_view(data, n)
D = win ^ plain
found = False
for L in range(1, n):
    idx = np.where(np.all(D[:, L:] == D[:, :-L], axis=1))[0]
    if len(idx):
        for off in idx[:3]:
            print(f"HIT file_off=0x{off:x} keylen={L} key={bytes(D[off, :L].tolist()).hex()}")
        found = True
        break
if not found:
    print("no repeating-XOR onion (keylen 1..61) found in this binary")
