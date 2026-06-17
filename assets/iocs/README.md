# Atomic Arch indicators and detection content

Machine-readable companions to the writeup, all derived from the post.

| file | what |
|---|---|
| `atomic-arch-iocs.csv` | every indicator: file hashes, BuildIDs, fuzzy hashes, network, host artifacts, crypto/attribution, packages and accounts. The `classification` column flags `clean-reference` (negative-control hashes, do NOT block), `access-credential-withheld` (the reusable Cloudflare tunnel secret is not published), and `not-ioc` (impersonated or innocent names). |
| `atomic-arch.yar` | two YARA rules: the QML drainer (run against the DECOMPRESSED `main.qml`, not the ELF, where the strings are zlib-compressed) and the stage-1 stealer ELF. |
| `atomic-arch.sigma.yml` | four Sigma rules for the host behaviours YARA cannot see: the wallet binary swap, stealer execution + systemd persistence, eBPF pin maps, and Vault token theft to the local Vault API. |

The reusable cloudflared tunnel secret is deliberately omitted. It is an access credential, not an indicator. The AccountTag and TunnelID stay as Cloudflare takedown anchors.
