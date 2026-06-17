#!/usr/bin/env python3
"""Decode and validate a Monero base58 address. Usage: decode_xmr_addr.py <address>"""
import sys

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BLOCK_LEN = [0, 0, 1, 2, 0, 3, 4, 5, 0, 6, 7, 8]

def b58_decode(s):
    out = bytearray()
    for i in range(0, len(s), 11):
        block = s[i:i + 11]
        n = 0
        for ch in block:
            n = n * 58 + ALPHABET.index(ch)
        out += n.to_bytes(BLOCK_LEN[len(block)], "big")
    return bytes(out)

def keccak256(msg):
    RC = [0x1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,
          0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,
          0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
          0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,
          0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
    R = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
    rol = lambda x, n: ((x << n) | (x >> (64 - n))) & (2**64 - 1)
    st = [[0]*5 for _ in range(5)]
    m = bytearray(msg) + b"\x01"
    while len(m) % 136:
        m.append(0)
    m[-1] ^= 0x80
    for off in range(0, len(m), 136):
        for i in range(17):
            st[i % 5][i // 5] ^= int.from_bytes(m[off+i*8:off+i*8+8], "little")
        for rc in RC:
            C = [st[x][0]^st[x][1]^st[x][2]^st[x][3]^st[x][4] for x in range(5)]
            D = [C[(x-1)%5] ^ rol(C[(x+1)%5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    st[x][y] ^= D[x]
            B = [[0]*5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    B[y][(2*x+3*y)%5] = rol(st[x][y], R[x][y])
            for x in range(5):
                for y in range(5):
                    st[x][y] = B[x][y] ^ ((~B[(x+1)%5][y]) & B[(x+2)%5][y])
            st[0][0] ^= rc
    return b"".join(st[i%5][i//5].to_bytes(8, "little") for i in range(4))[:32]

NET = {0: "Monero MAINNET standard", 42: "Monero MAINNET subaddress",
       18: "Monero MAINNET integrated", 53: "Monero TESTNET standard"}

raw = b58_decode(sys.argv[1])
net, spend, view, chk = raw[0], raw[1:33], raw[33:65], raw[65:69]
calc = keccak256(raw[:65])[:4]
print(f"net byte     : {net:<25}(0x{net:02x} = {NET.get(net, 'unknown')})")
print(f"spend pubkey : {spend.hex()}")
print(f"view  pubkey : {view.hex()}")
print(f"checksum     : {chk.hex()}")
print(f"keccak256(first 65 bytes)[:4] : {calc.hex()}   -> {'VALID' if calc == chk else 'INVALID'}")
