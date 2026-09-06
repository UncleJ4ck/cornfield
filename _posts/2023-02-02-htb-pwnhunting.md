---
layout: post
title: "PwnHunting (HTB pwn)"
subtitle: "the flag is already in the binary, get the program to print it"
date: 2023-02-02
tags: [htb, pwn, ghidra]
category: writeups
kind: challenge
tldr: "Short one. Ghidra shows the HTB{...} flag resident in the binary at a fixed address. The exploit is just steering execution (or the leak primitive the binary hands you) to that address so it prints back."
---

## triage

Load it in Ghidra and the flag string is right there in the data, referenced from a function that never runs on the normal path:

```
HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXX}  @ <fixed address>
```

The job is to redirect the binary to read or print that address, through whatever primitive it exposes (an overflow to the win function, or a leak that dereferences the string). Once execution reaches it, the flag prints over the connection.
