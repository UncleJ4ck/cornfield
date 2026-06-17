#!/usr/bin/env python3
"""Offset-independent QML/JS diff of two wallet ELFs: inflate every zlib stream,
keep the QML/JS, compare the sets. Read-only. Usage: qml_fulldiff.py stock sample"""
import sys, zlib, re, difflib

def streams(path):
    data = open(path, "rb").read()
    out = {}
    i = data.find(b"\x78")
    while i >= 0:
        if data[i + 1] in (0x01, 0x9c, 0xda):
            try:
                raw = zlib.decompressobj().decompress(data[i:i + 5_000_000])
            except Exception:
                raw = b""
            if b"import Qt" in raw or b"import Monero" in raw or b".pragma library" in raw:
                txt = raw.decode("utf-8", "replace")
                if sum(c.isprintable() or c in "\n\r\t" for c in txt) / max(1, len(txt)) > 0.95 and len(txt) > 40:
                    norm = re.sub(r"\n+", "\n", re.sub(r"[ \t]+", " ", txt)).strip()
                    out[norm] = txt
        i = data.find(b"\x78", i + 1)
    return out

def anchor(txt):
    imp = next((l.strip() for l in txt.splitlines() if l.strip().startswith("import ")), "")
    m = re.search(r"\b(id:\s*\w+|function\s+\w+)", txt)
    return f"({imp} / {m.group(1) if m else '?'})"

DRAIN = ("createTransactionAllAsync", "balanceAll", "865BH8")
stock_p, sample_p = sys.argv[1], sys.argv[2]
stock = streams(stock_p)
sample = streams(sample_p)
print(f"[*] scanning STOCK : {stock_p:<24} -> {len(stock)} distinct QML/JS streams")
print(f"[*] scanning SAMPLE: {sample_p:<24} -> {len(sample)} distinct QML/JS streams")

changed = [t for norm, t in sample.items() if norm not in stock]
print(f"[*] streams in SAMPLE not byte-matching any STOCK stream: {len(changed)}")
for n, t in enumerate(sorted(changed, key=len), 1):
    print("=" * 78)
    print(f"CHANGED STREAM #{n}  {anchor(t)}")
    print(f"  contains drain signature (createTransactionAllAsync + balanceAll + 865BH8): "
          f"{all(k in t for k in DRAIN)}")
    best = max(stock.values(), key=lambda s: difflib.SequenceMatcher(None, s, t).quick_ratio(), default="")
    ratio = difflib.SequenceMatcher(None, best, t).ratio()
    diff = list(difflib.unified_diff(best.splitlines(), t.splitlines(), lineterm="", n=0))
    added = [l for l in diff if l.startswith("+") and not l.startswith("+++")]
    removed = [l for l in diff if l.startswith("-") and not l.startswith("---")]
    print(f"  closest stock stream similarity: {ratio:.3f}")
    print(f"  lines added in sample: {len(added)} | removed: {len(removed)}")
    for l in added:
        print("    " + l)
