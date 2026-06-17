# Atomic Arch analysis scripts

Every script the writeup runs. All read-only: they parse bytes, run a repeating-XOR,
inflate zlib streams, walk eBPF bytecode, or derive public addresses. None executes a
malware sample and none touches the network. Standard library only, except
`recover_onion.py` (numpy).

## stage one: the deps stealer

| script | what it does |
|---|---|
| `xor_onion.py` | Decode the C2 onion from a stealer ELF at the known offsets (`--js` for the js-digest build): `ct[i] ^ key[i % 32]`. |
| `recover_onion.py` | Sweep a stealer ELF for the onion when you do not have the offsets yet: finds a repeating-key XOR of the onion string for any key length 1..61. |
| `carve_bpf.py` | Carve the embedded eBPF object (`e_machine` 247) out of each stealer, size it from the section-header table, and hash it. Proves both stealers ship the same object. |
| `bpf_helpers.py` | Histogram the helper calls in the carved eBPF object: walk every `call` (opcode `0x85`) and split helper calls (src 0) from bpf-to-bpf (src 1). |

## second stage: the wallet drainer

| script | what it does |
|---|---|
| `qml_fulldiff.py` | Offset-independent QML/JS diff of two `monero-wallet-gui` ELFs: inflate every zlib stream, keep the QML/JS, compare the sets. Reports the one changed stream. |
| `carve_mainqml.py` | Carve `main.qml` out of each wallet ELF's Qt resource bundle, hash it, count `createTransactionAllAsync` call sites, and extract the injected drain block. |
| `decode_xmr_addr.py` | Decode and validate the drain Monero address: network byte, spend/view keys, and the keccak-256 checksum. |

## attribution and proxy side-op

| script | what it does |
|---|---|
| `derive_mnemonic_addrs.py` | Pure-stdlib BIP39 -> BIP32 -> secp256k1 -> BTC/ETH derivation for the embedded mnemonic (m/44 ETH, m/44 + m/49 BTC). Sentinel-validates against the canonical `abandon...about` vector first. |
| `verify_proxy_decoder.py` | Independent reimplementation of the C2 proxy's obfuscator.io string decoder (custom-alphabet base64, no RC4). Round-trips the raw array against the sandboxed output as the control. |
| `decode_argo.py` | Decode the proxy's cloudflared tunnel token (base64url JSON). Prints the AccountTag and TunnelID (takedown anchors); the reusable secret is redacted and the token is not bundled here. |

## everything at once

| script | what it does |
|---|---|
| `verify_atomic_arch.py` | Re-derive every load-bearing IOC from the five samples (stage-one hashes, the XOR onion at both keys with the cleartext negative control, the byte-identical eBPF object, the harvest-string offsets, the `main.qml` carve and the 663-byte drain block, and the proof the "three builds" are one truncated binary). Prints `34 checks reproduced, 0 failed`. |

## usage

```
# stage one + eBPF
python3 xor_onion.py deps                       # --js for jsdigest_deps.bin
python3 recover_onion.py deps
python3 carve_bpf.py deps jsdigest_deps.bin
python3 bpf_helpers.py ebpf_rootkit.o           # the object carve_bpf carved

# second stage (v1, the truncated v2, and stock as the negative control)
python3 qml_fulldiff.py stock/monero-wallet-gui bin_linux.elf
python3 carve_mainqml.py bin_linux.elf bin_linux_v2.elf stock/monero-wallet-gui
python3 decode_xmr_addr.py 865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C

# attribution + proxy
python3 derive_mnemonic_addrs.py
python3 verify_proxy_decoder.py ./nodejs-argo   # dir with index.beautified.js + _strings.json
python3 decode_argo.py "$ARGO_AUTH"             # token not bundled; pass it in

# all load-bearing IOCs in one pass
python3 verify_atomic_arch.py deps jsdigest_deps.bin bin_linux.elf bin_linux_v2.elf stock/monero-wallet-gui
```
