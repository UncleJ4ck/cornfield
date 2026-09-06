---
layout: post
title: "PetPet (HTB web)"
subtitle: "double-extension upload bypass into a Pillow / Ghostscript RCE (CVE-2018-16509)"
date: 2023-04-16
tags: [htb, web, file-upload, ghostscript, cve-2018-16509, pillow]
category: writeups
kind: challenge
tldr: "A Flask petpet-gif maker checks the extension with rsplit('.',1), so file.php.png passes while the server still treats the leading part as it likes. The real kill is that Pillow hands the image to Ghostscript, so a crafted EPS triggers CVE-2018-16509 for code execution and reads /app/flag."
---

## upload filter bypass

The allowlist check only looks at the last extension:

```python
ALLOWED = {'png','jpg','jpeg'}
"file.php.png".rsplit('.',1)[1].lower() in ALLOWED   # True
"file.php".rsplit('.',1)[1].lower()     in ALLOWED   # False
```

So `file.php.png` sails through the extension gate. On its own that only gets a file in, because the app converts uploads into a GIF.

## the real bug: Ghostscript via Pillow

The conversion runs through Pillow, which shells out to Ghostscript for certain formats. That opens CVE-2018-16509, the `-dSAFER` bypass. Feed a crafted EPS/PostScript payload (see farisv's PIL-RCE-Ghostscript PoC), the conversion executes it, and you run commands on the box.

```
/app/flag                          flag location
/app/application/static/petpets/*  where the generated GIFs land
```

Read `/app/flag` through the Ghostscript command execution.
