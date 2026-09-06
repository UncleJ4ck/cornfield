---
layout: post
title: "HTB: Phantom Troupe"
subtitle: "anonymous FTP leak, base64 creds, and a hidden secret area"
date: 2023-02-02
tags: [htb, linux, ftp, web, enumeration]
category: writeups
kind: machine
tldr: "vsftpd allows anonymous login and hands over backup.txt and flag.txt. The web root leaks robots.txt and directories, a base64 blob decodes to eddie@eddie.com:eddie, and content discovery turns up a /secretarea path that carries the flow forward."
---

## recon

Three services, and FTP is the loud one:

```
21  vsftpd 3.0.3   anonymous login allowed
22  OpenSSH 8.2p1
80  Apache 2.4.41  title "The Phantom Troup", robots.txt disallows /enum.txt
```

## ftp

Anonymous FTP is open and lists files right away:

```
ftp-anon: Anonymous FTP login allowed
-rw-r--r-- backup.txt
-rw-r--r-- flag.txt
```

Pull both. `backup.txt` seeds the web enumeration.

## web

`robots.txt` points at `/enum.txt`, gobuster surfaces `/Members` and `/javascript`, and a base64 string decodes to a working credential:

```
ZWRkaWVAZWRkaWUuY29tOmVkZGll  ->  eddie@eddie.com:eddie
```

Content discovery then turns up `/secretarea`, the next step in the chain.
