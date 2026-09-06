---
layout: post
title: "HTB: Squashed"
subtitle: "NFS with no root squash control, match the exported UID to read and write as the owner"
date: 2023-04-08
tags: [htb, linux, nfs, uid, privesc]
category: writeups
kind: machine
tldr: "Two NFS exports are world-mountable. Files are owned by UID 2017 and by a web UID, and NFS trusts the client's UID. Create a local user with the matching UID (or chown as root locally), mount the share, and you inherit the owner's access, first to read a home, then to plant into the web root."
---

## recon

```
22    OpenSSH 8.2p1
80    Apache 2.4.41   "Built Better"
111   rpcbind
2049  NFS
```

Port 80 is a dead end. NFS is the way in.

## NFS UID matching

Two exports:

```
/home/ross     *
/var/www/html  *
```

Mounting shows files owned by UID 2017 and by the web user, and NFS authorises by the client-supplied UID. Make a local user (or remap one) to UID 2017:

```
$ sudo usermod -u 2017 dummy
$ su dummy
$ find /mnt -ls        # now readable as the owner
```

As UID 2017 you read ross's home. Repeat the trick with the web UID on `/var/www/html` to drop a PHP shell into the served directory and execute it, which lands the interactive foothold.
