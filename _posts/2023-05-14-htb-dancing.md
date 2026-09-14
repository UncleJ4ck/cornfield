---
layout: post
title: "HTB: Dancing"
subtitle: "An anonymous SMB session reads the WorkShares share, flag in a user folder"
date: 2023-05-14
tags: [htb, windows, smb, null-session, starting-point]
category: writeups
kind: machine
os: Windows
tldr: "A Starting Point Windows box. SMB on 445 accepts a null session for listing shares, and the custom WorkShares share answers to an anonymous login. Browsing the per-user folders inside it gives up the flag with no exploitation."
---

## the box

Dancing is a Starting Point Windows box at 10.129.1.12. No web app, no exploit. SMB on 445 accepts a null session for listing shares, and one of those shares, a custom WorkShares, answers to an anonymous login. The flag sits in a user folder inside it.

## recon

Full TCP sweep, then a service scan on what answered:

```bash
$ nmap -p- --min-rate 10000 10.129.1.12
$ nmap -p 135,139,445,5985,47001,49664-49669 -sCV --reason 10.129.1.12
```

```
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

The TTL of 127 and the service labels put this on Windows: RPC on 135, NetBIOS on 139, SMB on 445, and two Microsoft HTTPAPI 2.0 listeners on 5985 and 47001, 5985 being the WinRM port. The 49664 to 49669 range is the usual dynamic RPC. Nothing here needs WinRM, so SMB is the surface.

## smb

List shares with a null session, no credentials:

```
$ smbclient --no-pass -L 10.129.1.12
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	WorkShares      Disk
```

`ADMIN$` and `C$` are the built-in administrative shares and need admin credentials to open. `WorkShares` is custom and carries no comment, which makes it the one worth trying. It answered to an anonymous connection:

```
$ smbclient //10.129.1.12/WorkShares -U Anonymous -p 445 --no-pass
```

Inside are per-user folders. Browsing into them and pulling the files down handed over the flag, and that was the box.

## takeaway

The whole box is a null session reading an anonymously exposed share. The built-in shares stay locked, but a custom share left world-readable hands a file read to an unauthenticated client, which is all this one asks for.