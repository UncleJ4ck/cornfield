---
layout: post
title: "Reminiscent (HTB forensics)"
subtitle: "a phishing .eml, a dropped payload, and a memory image in Volatility"
date: 2023-04-12
tags: [htb, forensics, volatility, email]
category: writeups
kind: challenge
tldr: "A forensics challenge built around a phishing email and a memory dump. Read the .eml to recover the lure and the dropped artifact, then work the memory image in Volatility to pull the malicious process and the zip it left behind."
---

## the mail

The `.eml` sets the scene (viewing it through a mail viewer such as the encryptomatic viewer makes the headers readable):

```
sender:   bloodworm@madlab.lcl  (Brain Loodworm)
receiver: flounder@madlab.lcl
```

It carries a dropped payload referenced under the `madlab.lcl-flounder@madlab.lcl` name, including a zip.

## the memory image

Move to Volatility on the provided image. Enumerate processes, spot the injected or suspicious one from the phishing chain, and dump the artifact (the referenced zip) out of memory. That extracted content carries the flag.
