---
layout: post
title: "HTB: Phantom Troupe"
subtitle: "Anonymous FTP hands over the flag, a base64 backup leaks creds, and admin/admin opens the secret area"
date: 2023-02-02
tags: [htb, linux, ftp, anonymous-ftp, base64, enumeration]
category: writeups
kind: machine
os: Linux
tldr: "vsftpd 3.0.3 allows anonymous login and serves backup.txt and flag.txt, so the flag comes straight off FTP. backup.txt base64-decodes to eddie@eddie.com:eddie. On the web, robots.txt disallows /enum.txt, a wordlist bust turns up /Members, /javascript and /secretarea, and the login there took admin/admin."
---

## the box

Phantom Troupe is a small Linux box. Three services answer: anonymous FTP, OpenSSH, and an Apache site. The FTP share carries the flag outright, so the box falls on the first login. The web side is the intended route, built on a base64 backup and a wordlist bust that uncovers a members area and a hidden login.

## recon

A version and default-script scan (`nmap -sCV`) returned three open ports:

```
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: The Phantom Troup
| http-robots.txt: 1 disallowed entry 
|_/enum.txt/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

FTP allowed anonymous login, robots.txt disallowed one path, and the Apache banner plus the `Service Info` line put the host on Ubuntu.

## ftp

The anon check fired on the FTP script output, and the listing came back with two files:

```
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              29 Jul 18 14:01 backup.txt
|_-rw-r--r--    1 0        0              40 Jul 21 12:19 flag.txt
```

`ftp-syst` confirmed the login as the `ftp` user over a plaintext control channel:

```
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.2.130
|      Logged in as ftp
|      Control connection is plain text
|      vsFTPd 3.0.3 - secure, fast, stable
```

I pulled both files. `flag.txt` was the flag, sitting in the anonymous share:

```bash
$ get backup.txt
$ get flag.txt
$ cat flag.txt
# flag1{516d2390af74af666e6cf01207bdec00}
```

`backup.txt` was a single base64 line. It decoded to an email and password pair:

```bash
$ base64 -d backup.txt
# eddie@eddie.com:eddie
```

## web

robots.txt named one disallowed path:

```
/enum.txt/
```

Content discovery used the wordlist on hand. gobuster turned up a members area and the bootstrap javascript directory:

```bash
$ gobuster dir -u http://10.10.56.250 -w list.txt
```

```
/Members              (Status: 301) [Size: 314] [--> http://10.10.56.250/Members/]
/javascript           (Status: 301) [Size: 317] [--> http://10.10.56.250/javascript/]
```

`secretarea` is a literal entry in that wordlist, and the bust surfaced it as a live path:

```
http://10.10.60.63/secretarea
```

The login there took `admin`/`admin`. The body I posted to the form:

```
username=admin+&password=admin
```

Between the decoded `eddie@eddie.com:eddie` pair from the backup and the weak admin login, the web side lines up behind the same weakness the FTP share already gave away.

## takeaway

An anonymous FTP share is readable by anyone who connects, so anything dropped in it is public. Here that was the flag and a base64 credential. The web path (a robots hint, a wordlist bust to a members area and a hidden login, then admin/admin) is the intended exercise, but the FTP share hands over the answer before any of it matters.