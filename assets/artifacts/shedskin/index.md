---
layout: page
title: "shedskin, artifact bundle"
permalink: /artifacts/shedskin/
---

Files for the lead post. Each one is a raw research artifact; sanitize before quoting.

- [`chain-probe.c`]({{ '/assets/artifacts/shedskin/chain-probe.c' | relative_url }}), [`chain-probe.exe`]({{ '/assets/artifacts/shedskin/chain-probe.exe' | relative_url }}), native three-arm probe used for the 2026-10-29 provider-chain capture
- [`provider-chain-run.ps1`]({{ '/assets/artifacts/shedskin/provider-chain-run.ps1' | relative_url }}), PowerShell wrapper for the probe
- [`provider-chain-2026-10-29.log`]({{ '/assets/artifacts/shedskin/provider-chain-2026-10-29.log' | relative_url }}), raw capture (arm A/B/C result values + oracle controls)
- [`amsi-dev-provider.c`]({{ '/assets/artifacts/shedskin/amsi-dev-provider.c' | relative_url }}), [`AmsiDevProvider.dll`]({{ '/assets/artifacts/shedskin/AmsiDevProvider.dll' | relative_url }}), [`register-dev-provider.ps1`]({{ '/assets/artifacts/shedskin/register-dev-provider.ps1' | relative_url }}), the iter19 CRT-free AMSI provider used to produce the arm-B 32769 result
- [`pwsh-appname-2026-10-29.log`]({{ '/assets/artifacts/shedskin/pwsh-appname-2026-10-29.log' | relative_url }}), captured ETW event-1101 `appname` field from live `pwsh.exe` 7.4.21
- [`shedskin-cycle-launcher.ps1`]({{ '/assets/artifacts/shedskin/shedskin-cycle-launcher.ps1' | relative_url }}), the XOR-obfuscated outer-pass launcher that produced the live end-to-end P1/P2/P3 cycle
- [`end-to-end-cycle-2026-10-29.log`]({{ '/assets/artifacts/shedskin/end-to-end-cycle-2026-10-29.log' | relative_url }}), raw transcript of the Mimikatz-pattern BLOCK (pre-shedskin) to EXEC (post-shedskin) differential, EICAR controls fire 32768 both ends
