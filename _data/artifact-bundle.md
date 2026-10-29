---
# Artifact bundle manifest for the AMSI research trilogy.
# Lives under /artifacts/ on the published blog once the operator stages
# the files from the lab tree below into assets/artifacts/.
---

## Bundle targets

- `/artifacts/shedskin/` for the lead post
- `/artifacts/exact-32768/` for the SMA.dll result-check post
- `/artifacts/clr-amsi-slot/` for the clr.dll slot post

## shedskin/ contents

| path | source on this host | ships |
|---|---|---|
| `prior-art-queries.jsonl` | `~/Desktop/Now/free-time/mws/new-era/amb/iter20/evidence/prior-art-queries.jsonl` | yes |
| `RECEIPT-v1.json` through `RECEIPT-v6.json` | `~/Desktop/Now/free-time/mws/new-era/amb/iter20/receipts/` | yes |
| `extended-loader.ps1` | `~/Desktop/Now/free-time/mws/new-era/amb/iter20/corpus/extended-loader.ps1` | yes |
| `payload-plain.ps1`, `payload-cmd.ps1` | `~/Desktop/Now/free-time/mws/new-era/amb/iter20/corpus/` | yes |
| `AmsiDevProvider.dll` + source | `~/Desktop/Now/free-time/mws/new-era/amb/iter19/corpus/out/AmsiDevProvider.dll`, `src/amsi-dev-provider.c` | yes |
| `mpengine-static-chain.txt` | radare2 dump of `fcn.18032458c` + VA table | yes |
| `event-1116-*.evtx` | `C:\Windows\System32\winevt\Logs\...` extracts captured during P1-P7 | yes |
| `three-state-transcript.log` | `C:\Users\<lab>\Desktop\three-state-transcript.log` | yes |
| `provider-chain-capture.log` | this host, `scratchpad/lab-captures/02-provider-chain-run.ps1` output 2026-10-29 | yes |
| `provider-chain-probe.exe` + source | `scratchpad/lab-captures/chain-probe.c` | yes |

## exact-32768/ contents

| path | source | ships |
|---|---|---|
| `mpoav-hunt.csv` | 8-payload sample table | yes |
| `dnfile_find_psc.py` | `scratchpad/dnfile_find_psc.py` (works against dnfile 0.18.0) | yes |
| `perform-security-checks.il` | dnlib dump of RVA 0x941d4 on SMA.dll v10.0.26100.7920 | yes |
| `dummy-provider-stub.c` | iter19 corpus `amsi-dev-provider.c` | yes |
| `register-provider.ps1` | iter19 corpus `register-dev-provider.ps1` | yes |
| `three-arm-logs/` | `A_shedskin-only.log`, `B_shedskin+provider.log`, `C_shedskin+provider+nonce.log` | yes |

## clr-amsi-slot/ contents

| path | source | ships |
|---|---|---|
| `live-run.log` | `C:\Users\...\Desktop\clr-slot-capture.txt` from 2026-10-29 | yes |
| `radare2-session.log` | three-query derivation of slot RVA on clr.dll 4.8.9345.0 | yes |
| `shedskin-clr-slot.c` | native primitive source, in-post listing | yes |
| `coreclr-slot-note.md` | sibling-measurement sketch for `.NET 5/6/7/8+` | pending (not re-measured this round) |

## Shipping steps for the operator

1. Pull the files listed above from the lab guest and this host's scratchpad into `~/Desktop/Now/free-time/dev/my-blog/assets/artifacts/<section>/`.
2. Jekyll will serve them under `/assets/artifacts/<section>/<file>`.
3. Add `/artifacts/<section>/` landing pages that index the files; update the posts' top-of-page status boxes to point at the live URLs and drop the "pending publication" line.

## Known gaps (lab-dependent, flagged in-post)

- The `coreclr` sibling measurement for the CLR slot post is not in this round.
- The pwsh end-to-end IEX measurement (pwsh scanning a Mimikatz-pattern IEX under its own `PowerShell_...pwsh.exe...` appname) is gated by Defender's outer-script block on the literal; a payload-delivery shape that passes the outer scan is pending.
- The per-provider trace that would retire the arm-C joint-verdict claim in shedskin's second-order section still needs an ETW provider-call event or in-process Detours hook on `IAmsiProvider::Scan`; the 2026-10-29 three-arm capture only has aggregator-only values.
