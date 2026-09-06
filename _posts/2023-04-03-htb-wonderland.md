---
layout: post
title: "HTB: Wonderland"
subtitle: "follow the rabbit through fuzzed paths, alice's creds, then PwnKit and a Python import hijack"
date: 2023-04-03
tags: [htb, linux, fuzzing, cve-2021-4034, python-hijack, privesc]
category: writeups
kind: machine
tldr: "Content discovery is the whole early game: keep fuzzing the r/a/b/b/i/t path to find alice's credentials. Escalation stacks two tricks, a Python library hijack on the random module for a lateral step, and CVE-2021-4034 (PwnKit) against the old sudo/polkit stack for root."
---

## foothold

Hints hide in page images, and the path spells out `r a b b i t` one segment at a time. Keep fuzzing each level rather than assuming a dead end. That trail hands over:

```
alice : HowDothTheLittleCrocodileImproveHisShiningTail
```

## escalation

Two moves:

- **Python import hijack.** A script alice can trigger imports `random` from a directory she controls. Drop a malicious `random.py` and the next run executes your code as the next user.
- **PwnKit (CVE-2021-4034).** The box carries a vulnerable polkit. `pkexec` local privesc pops a root shell straight away.

```
CVEs Check -> Vulnerable to CVE-2021-4034
```

The lesson that stuck: keep fuzzing the path, and check the polkit version before anything fancier.
