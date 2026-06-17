#!/usr/bin/env python3
"""BIP39 -> BIP32 -> secp256k1 -> BTC/ETH derivation, stdlib only. Public addresses only.
Validates against the canonical 'abandon...about' vector before the attacker mnemonic."""
import hashlib, hmac

P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
def inv(a,m=P): return pow(a,m-2,m)
def padd(p,q):
    if p is None: return q
    if q is None: return p
    if p[0]==q[0] and (p[1]+q[1])%P==0: return None
    if p==q: l=(3*p[0]*p[0])*inv(2*p[1])%P
    else:    l=(q[1]-p[1])*inv((q[0]-p[0])%P)%P
    x=(l*l-p[0]-q[0])%P; y=(l*(p[0]-x)-p[1])%P; return (x,y)
def pmul(k,p=(Gx,Gy)):
    r=None
    while k:
        if k&1: r=padd(r,p)
        p=padd(p,p); k>>=1
    return r
def ser_pub(pt):
    x,y=pt; return (b'\x03' if y&1 else b'\x02')+x.to_bytes(32,'big')

def seed_from_mnemonic(m, passphrase=""):
    return hashlib.pbkdf2_hmac("sha512", m.encode(), ("mnemonic"+passphrase).encode(), 2048, 64)

def master(seed):
    I=hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest(); return I[:32], I[32:]
def ckd(kpar, cpar, idx):
    if idx & 0x80000000:
        data=b'\x00'+kpar+idx.to_bytes(4,'big')
    else:
        data=ser_pub(pmul(int.from_bytes(kpar,'big')))+idx.to_bytes(4,'big')
    I=hmac.new(cpar, data, hashlib.sha512).digest()
    ki=(int.from_bytes(I[:32],'big')+int.from_bytes(kpar,'big'))%N
    return ki.to_bytes(32,'big'), I[32:]
def derive(seed, path):
    k,c=master(seed)
    for idx in path: k,c=ckd(k,c,idx)
    return k,c
H=0x80000000

def b58c(payload):
    chk=hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n=int.from_bytes(payload+chk,'big'); s=b''
    alpha=b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while n>0: n,r=divmod(n,58); s=alpha[r:r+1]+s
    return (b'1'*(len(payload)-len(payload.lstrip(b'\x00')))+s).decode()
def hash160(b): return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()
def btc_p2pkh(pub): return b58c(b'\x00'+hash160(pub))
def btc_p2sh_p2wpkh(pub):
    redeem=b'\x00\x14'+hash160(pub)
    return b58c(b'\x05'+hash160(redeem))

def keccak256(msg):
    RC=[0x1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
    R=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
    def rol(x,n): return ((x<<n)|(x>>(64-n)))&(2**64-1)
    st=[[0]*5 for _ in range(5)]; rate=136
    msg=bytearray(msg); msg.append(0x01)
    while len(msg)%rate: msg.append(0)
    msg[-1]^=0x80
    for off in range(0,len(msg),rate):
        blk=msg[off:off+rate]
        for i in range(rate//8):
            x,y=i%5,i//5; st[x][y]^=int.from_bytes(blk[i*8:i*8+8],'little')
        for rc in RC:
            C=[st[x][0]^st[x][1]^st[x][2]^st[x][3]^st[x][4] for x in range(5)]
            D=[C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
            for x in range(5):
                for y in range(5): st[x][y]^=D[x]
            B=[[0]*5 for _ in range(5)]
            for x in range(5):
                for y in range(5): B[y][(2*x+3*y)%5]=rol(st[x][y],R[x][y])
            for x in range(5):
                for y in range(5): st[x][y]=B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y])
            st[0][0]^=rc
    out=b''
    for i in range(4):
        x,y=i%5,i//5; out+=st[x][y].to_bytes(8,'little')
    return out[:32]
def eth_addr(pub_pt):
    raw=pub_pt[0].to_bytes(32,'big')+pub_pt[1].to_bytes(32,'big')
    return '0x'+keccak256(raw).hex()[-40:]

def derive_all(m, label):
    seed=seed_from_mnemonic(m)
    print(f"\n=== {label} ===")
    print("  seed:", seed.hex())
    for coin,cidx in [("BTC",0),("ETH",60)]:
        k,c=derive(seed,[44|H, cidx|H, 0|H, 0, 0])
        pt=pmul(int.from_bytes(k,'big'))
        if coin=="BTC": print("  BTC m/44'/0'/0'/0/0 :", btc_p2pkh(ser_pub(pt)))
        else:           print("  ETH m/44'/60'/0'/0/0:", eth_addr(pt))
    k,c=derive(seed,[49|H, 0|H, 0|H, 0, 0])
    print("  BTC m/49'/0'/0'/0/0 :", btc_p2sh_p2wpkh(ser_pub(pmul(int.from_bytes(k,'big')))))

tv="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
KNOWN_SEED="5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e9"
KNOWN_ETH="0x9858effd232b4033e47d90003d41ec34ecaeda94"
s=seed_from_mnemonic(tv)
print("SENTINEL seed match:", s.hex()==KNOWN_SEED)
k,c=derive(s,[44|H,60|H,0|H,0,0]); pt=pmul(int.from_bytes(k,'big'))
got_eth=eth_addr(pt)
print("SENTINEL ETH match :", got_eth==KNOWN_ETH, "(got", got_eth+")")
print("SENTINEL BTC addr  :", btc_p2pkh(ser_pub(pmul(int.from_bytes(derive(s,[44|H,0|H,0|H,0,0])[0],'big')))))

derive_all("bench crane defense corn wheel trial news abuse finish better paddle slush", "ATTACKER-EMBEDDED MNEMONIC")
