---
layout: post
title: "HTB: Dancing"
subtitle: "anonymous SMB share, grab the flag off WorkShares"
date: 2023-05-14
tags: [htb, windows, smb, starting-point, easy]
category: writeups
kind: machine
tldr: "A Starting Point Windows box. SMB allows a null session, one of the shares (WorkShares) is readable anonymously, and the flag sits in a user folder inside it."
---

## recon

Standard Windows surface: RPC, NetBIOS, SMB on 445, and WinRM on 5985.

```
135,139,445  Microsoft Windows RPC / netbios-ssn / SMB
5985         WinRM (Microsoft HTTPAPI 2.0)
```

## smb

List shares with a null session:

```
$ smbclient --no-pass -L 10.129.1.12
Sharename    Type    Comment
ADMIN$       Disk    Remote Admin
C$           Disk    Default share
IPC$         IPC     Remote IPC
WorkShares   Disk
```

`ADMIN$` and `C$` are admin-only, but `WorkShares` is a custom share and answers to an anonymous connection.

```
$ smbclient //10.129.1.12/WorkShares -U Anonymous --no-pass
```

Browse into the per-user directories and pull the flag. No exploitation, this one is a null-session reading lesson.
