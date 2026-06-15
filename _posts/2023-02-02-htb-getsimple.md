---
layout: post
title: "HTB: GetSimple"
subtitle: "world-readable admin SHA-1 that is just admin, authenticated theme-edit RCE (CVE-2019-11231), then sudo php to root"
date: 2023-02-02
tags: [htb, linux, getsimple-cms, cve-2019-11231, gtfobins]
category: writeups
kind: machine
tldr: "GetSimple CMS 3.3.15 stores its users as flat XML, and /data/users/admin.xml was served with no auth. The PWD field is an unsalted SHA-1 that is the digest of the word admin, so the creds were admin:admin. From the dashboard I used the authenticated theme-edit RCE (CVE-2019-11231) to drop a PHP reverse shell as www-data, which could run /usr/bin/php under sudo NOPASSWD, a one-line GTFOBins root."
---

## the box

GetSimple is an easy Linux box, and a Getting Started / module-style target rather than a seasonal machine, so there is no 0xdf box writeup for it. The whole thing lives on port `80`: a GetSimple CMS install whose flat-file design leaks the admin hash, an authenticated theme-editor RCE that is catalogued as CVE-2019-11231, and a trivial `sudo php` privesc. SSH is open but had nothing for me.

## recon

```bash
nmap -p- --min-rate 10000 10.129.87.63
nmap -p22,80 -sCV 10.129.87.63
```

```
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http  Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome to GetSimple! - gettingstarted
| http-robots.txt: 1 disallowed entry
|_/admin/
```

OpenSSH 8.2p1 is Ubuntu 20.04. Port 80 is Apache 2.4.41 serving a GetSimple CMS, and the title gives away the hostname `gettingstarted`. nmap's `http-robots.txt` script already flagged the one disallowed path, `/admin/`, which is a useful hint, not a wall.

GetSimple is a database-free CMS: it keeps everything in XML files under `/data/`. That design is the box. Directory brute forcing laid out the standard layout, and the directories were browsable:

```
[301] /admin    -> /admin/
[200] /admin/index.php
[301] /backups  -> /backups/
[301] /data     -> /data/
[200] /data/
[200] /data/cache/
[301] /plugins  -> /plugins/
[301] /theme    -> /theme/
[200] /readme.txt
[200] /robots.txt
```

`/data/` is the interesting one. Because GetSimple stores users as flat XML and Apache served the directory with no access control, I could read the user database directly. The version was 3.3.15 (visible in `/readme.txt` and the admin footer), which matters: 3.3.x through 3.3.15 carry the theme-editor RCE.

I also pulled the plugin manifest to see what was loaded:

```bash
curl -s http://10.129.87.63/data/other/plugins.xml | xmllint --format - | grep ">"
```

```xml
<channel>
  <item><plugin>anonymous_data.php</plugin><enabled>true</enabled></item>
  <item><plugin>InnovationPlugin.php</plugin><enabled>true</enabled></item>
</channel>
```

Nothing exploitable in the plugins, but it confirmed the data directory was wide open. The real find was the admin record:

```bash
curl -s http://10.129.87.63/data/users/admin.xml
```

```xml
<item>
  <USR>admin</USR>
  <NAME/>
  <PWD>d033e22ae348aeb5660fc2140aec35850c4da997</PWD>
  <EMAIL>admin@gettingstarted.com</EMAIL>
  <HTMLEDITOR>1</HTMLEDITOR>
  <TIMEZONE/>
  <LANG>en_US</LANG>
</item>
```

That `PWD` value is an unsalted SHA-1, which GetSimple uses for password storage. `d033e22ae348aeb5660fc2140aec35850c4da997` is the SHA-1 of the literal string `admin`. It is a well-known digest, so no cracking is even needed, but a quick lookup or a one-line check confirms it:

```bash
echo -n admin | sha1sum
# d033e22ae348aeb5660fc2140aec35850c4da997
```

So the credentials were `admin:admin`, and they logged straight into `/admin/`. There is a documented unauthenticated angle to this too: CVE-2019-11231 notes that on a default Apache config the `data/other/authorization.xml` API key is reachable, and the admin cookie is forgeable as `sha1(username + apikey)`, so auth can be bypassed entirely without the hash. Here the hash being a dictionary word made the front door simpler.

## foothold

GetSimple 3.3.x through 3.3.15 has an authenticated RCE in the theme editor, CVE-2019-11231. The handler is `admin/theme-edit.php`, and on save it writes the posted content straight into a theme template file with no extension or content validation:

```php
if (isset($_POST['submitsave'])) {
    // nonce check only
    $SavedFile    = $_POST['edited_file'];
    $FileContents = get_magic_quotes_gpc() ? stripslashes($_POST['content']) : $_POST['content'];
    $fh = fopen(GSTHEMESPATH . $SavedFile, 'w') or die("can't open file");
    fwrite($fh, $FileContents);
    fclose($fh);
}
```

The template is a `.php` file under the themes path, and GetSimple includes it to render pages. So an authenticated admin can paste arbitrary PHP into a template, save it, and the server executes whatever was written when that template loads. The `Cardinal` theme was installed, and its `template.php` is fetched on the front end (browsing the file directly says "you can't load this page directly", but it is included during normal rendering). I edited it through the dashboard editor at:

```
http://10.129.87.63/admin/theme-edit.php?t=Cardinal&f=template.php
```

I pasted a PHP reverse shell into the template body and saved it (the save posts `submitsave`, `edited_file=template.php`, and the PHP in `content` along with the CSRF `nonce`). Then I triggered the template by loading the front end and caught the callback. The shell landed as `www-data`. Metasploit ships a module for this CVE (`exploit/multi/http/getsimplecms_unauth_code_exec`), but editing the template by hand is cleaner and shows exactly what the bug is.

## user

The www-data shell already had read access to the user flag, so user fell out of the foothold step. The home directory belonged to `mrb3n`, and the flag was readable from there.

## root

First move on a www-data shell, `sudo -l`:

```
User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

`php` runnable as root with no password is a clean GTFOBins entry. PHP's `system()` inside a root-run interpreter spawns a root shell:

```bash
sudo php -r "system('/bin/bash');"
```

That returned a root shell and the root flag.

## takeaway

Two avoidable mistakes stacked. The user database XML was served by the web server with no access control, and the password was an unsalted SHA-1 of a dictionary word. Either alone is bad; together they hand you admin without touching a cracker. After that the box is the authenticated theme-edit RCE (CVE-2019-11231), which exists because the editor writes attacker content into an executed `.php` template with no validation, then a textbook GTFOBins sudo abuse. `php` should never sit in a NOPASSWD rule, and a CMS should never serve its own credential store as a static file.
