#!/usr/bin/env python3
"""Histogram the helper calls in a compiled eBPF object. Read-only.
--exfil-check confirms no egress / persistence helper is present."""
import sys, struct

HELPERS = {
    1:   ("bpf_map_lookup_elem",      "is this pid / inode / name on a hide list"),
    2:   ("bpf_map_update_elem",      "add to a hide list or scratch state"),
    3:   ("bpf_map_delete_elem",      "drop scratch state"),
    14:  ("bpf_get_current_pid_tgid", "whose syscall is this"),
    16:  ("bpf_get_current_comm",     "the name-based self-hide on exec"),
    36:  ("bpf_probe_write_user",     "rewrite it: splice dirents, zero /proc lines"),
    109: ("bpf_send_signal",          "the one SIGKILL, fired at a tracer"),
    112: ("bpf_probe_read_user",      "read the kernel's buffer before tampering"),
    181: ("bpf_loop",                 "bounded walk over a netlink or read buffer"),
}

EXFIL = [
    (25,  "bpf_perf_event_output", "no userspace send channel"),
    (130, "bpf_ringbuf_output",    "no ringbuf egress"),
    (9,   "bpf_skb_store_bytes",   "no packet crafting"),
    (6,   "bpf_trace_printk",      "not even a debug log path"),
    (51,  "bpf_sk_storage_get",    ""),
]

def exec_sections(d):
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    shentsize = struct.unpack_from("<H", d, 0x3a)[0]
    shnum = struct.unpack_from("<H", d, 0x3c)[0]
    for k in range(shnum):
        sh = shoff + k * shentsize
        sh_type = struct.unpack_from("<I", d, sh + 4)[0]
        sh_flags = struct.unpack_from("<Q", d, sh + 8)[0]
        sh_off = struct.unpack_from("<Q", d, sh + 24)[0]
        sh_size = struct.unpack_from("<Q", d, sh + 32)[0]
        if sh_type == 1 and (sh_flags & 0x4):
            yield d[sh_off:sh_off + sh_size]

args = sys.argv[1:]
exfil = "--exfil-check" in args
args = [a for a in args if a != "--exfil-check"]
d = open(args[0], "rb").read()
hist = {}
b2b = 0
for code in exec_sections(d):
    i = 0
    while i + 8 <= len(code):
        op = code[i]
        if op == 0x18:
            i += 16
            continue
        if op == 0x85:
            src = (code[i + 1] >> 4) & 0xf
            imm = struct.unpack_from("<i", code, i + 4)[0]
            if src == 0:
                hist[imm] = hist.get(imm, 0) + 1
            else:
                b2b += 1
        i += 8
total = sum(hist.values())

if exfil:
    ids = " ".join(str(h) for h in sorted(hist))
    print(f"distinct helper IDs called : {ids}   ({len(hist)}, == the histogram; {total} calls + {b2b} bpf-to-bpf)")
    print("absent (the egress / persistence helpers a stealer would need):")
    for hid, name, note in EXFIL:
        status = "not called" if hid not in hist else f"called {hist[hid]}x"
        line = f"  {'#'+str(hid):<5}{name:<25}{status}"
        if note:
            line += f"      <- {note}"
        print(line)
    print("verdict: intercept-and-rewrite only; no helper that can send, craft, or persist data")
else:
    for hid, count in sorted(hist.items(), key=lambda kv: (-kv[1], kv[0])):
        name, note = HELPERS.get(hid, (f"helper_{hid}", ""))
        print(f"{count:>6}  {'#'+str(hid):<6}{name:<27}{note}")
    print(f"{'':<41}{total} helper calls, {len(hist)} distinct helpers (+{b2b} bpf-to-bpf)")
