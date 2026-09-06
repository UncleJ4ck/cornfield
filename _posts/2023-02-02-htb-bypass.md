---
layout: post
title: "Bypass (HTB rev)"
subtitle: "a .NET binary, read it back to source and defeat the check"
date: 2023-02-02
tags: [htb, reversing, dotnet]
category: writeups
kind: challenge
tldr: "strings on the binary shows it is a .NET assembly. .NET decompiles cleanly to near-source with dnSpy or ILSpy, so read the licence/auth check, understand the comparison, and satisfy or patch it to reveal the flag."
---

## triage

```
$ strings bypass | grep -i mscoree   # .NET marker
```

It is a managed .NET assembly, which means it decompiles back to readable C# with dnSpy or ILSpy rather than the assembly slog of a native binary.

## the check

Open it in a .NET decompiler, find the routine that validates the input or a licence key, and read the comparison directly from the IL-to-C# output. From there either feed the value it wants or patch the branch, and the flag falls out. .NET reversing is a source-reading exercise, not a disassembly one.
