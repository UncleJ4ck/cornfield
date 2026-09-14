---
layout: post
title: "HTB: Squashed"
subtitle: "NFS exports trust the client UID, so align a local account to the web-root owner for a PHP shell, then read ross's home for an X11 cookie into the root session"
date: 2023-04-08
tags: [htb, linux, nfs, uid-mapping, x11]
category: writeups
kind: machine
os: Linux
tldr: "Two NFS exports are open to any client, and the server authenticates with AUTH_SYS, trusting whatever UID the client sends. The web root /var/www/html is owned by UID 2017, so a local account remapped to that UID can write a PHP shell into the served directory for a foothold. The other export is ross's home; reading it the same way yields an X11 authority cookie, which attaches to the root-owned display to screenshot the root session."
---

## the box

Squashed comes down to one idea: an NFS server that authenticates by UID and exports two directories to any client. SSH and a static Apache site are the only other ports, and the site leads nowhere. The server trusts whatever UID a mounting client claims, so matching a local account to the owner of an exported file grants that owner's access. One export is the web root, owned by UID 2017, and that is enough to write a PHP shell and get a shell. The other is ross's home, which holds the X11 cookie for the root session.

## recon

A full port sweep and a service scan returned SSH, Apache, and the RPC stack behind NFS:

```
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs_acl  3 (RPC #100227)
37305/tcp open  mountd   1-3 (RPC #100005)
39127/tcp open  nlockmgr 1-4 (RPC #100021)
51849/tcp open  mountd   1-3 (RPC #100005)
60173/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux
```

OpenSSH 8.2p1 on the Ubuntu `4ubuntu0.5` package puts the box on 20.04 focal. Port 80 was a static site titled "Built Better" with nothing behind it. `rpcbind` on 111 and the `mountd`/`nlockmgr`/`nfs_acl` services point at NFS on 2049, which is the way in.

## foothold

Listing the exports showed two shares open to any client:

```
/home/ross    *
/var/www/html *
```

The `*` means any host may mount, and NFS here uses AUTH_SYS: the server trusts the UID the client sends rather than authenticating the user behind it. A file owned by UID 2017 on the server is readable and writable by any process running as UID 2017 on a machine I control.

I mounted `/var/www/html` and listed it:

```
find /mnt -ls
   133456      4 drwxr-xr--   5 2017     http         4096 Apr  8 02:55 /mnt
find: '/mnt/index.html': Permission denied
find: '/mnt/images': Permission denied
find: '/mnt/css': Permission denied
find: '/mnt/js': Permission denied
```

The share is the web root, owned by UID 2017, group `http`, and my current UID could not read into it. The fix is to become UID 2017 locally, so I remapped a throwaway account to that UID:

```bash
$ sudo usermod -u 2017 dummy
```

Switching to that account made the mount mine. The directory is owner-writable, so I wrote a PHP shell into the served root and called it through Apache. That landed an interactive foothold, and the user flag was readable from the shell.

## root

The other export is ross's home, and it yields root by the same UID trick. Align a local account to the home's owner, mount it, and the files read back. The one that matters is the X11 authority cookie. The box runs a desktop session as root, and access to that display is gated only by the cookie. With ross's `.Xauthority`, an X client attaches to the root-owned display and a screen capture shows the session. The root flag is on it, read and submitted.

## takeaway

NFS with AUTH_SYS trusts the client's UID, and both exports were open to the world, so the only control on the files was a number the attacker sets. Owning the web root gave code execution, and the home on the second export gave an X11 cookie, which is as good as a seat at root's desktop. Exporting a home and a web root to `*` without mapping remote UIDs hands each owner's access to anyone who mounts.