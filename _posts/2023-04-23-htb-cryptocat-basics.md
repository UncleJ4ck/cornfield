---
layout: post
title: "CryptCat Basics (HTB pwn)"
subtitle: "gets() into a 16-byte buffer, the textbook stack smash"
date: 2023-04-23
tags: [htb, pwn, buffer-overflow, gets]
category: writeups
kind: challenge
tldr: "A tiny remote service reads into a 16-byte stack buffer with gets(). No bound, no canary in the way of the plan: overflow past the buffer to redirect execution to the win path."
---

## the bug

The whole program is the vulnerability:

```c
int main(void) {
    char buffer[16];
    printf("Give me data plz: \n");
    gets(buffer);
    return 0;
}
```

`gets` has no length argument, so anything past 16 bytes runs off the buffer and into the saved registers. Find the offset to the return address with a cyclic pattern, then overwrite it to reach the win function (or a one-gadget, depending on protections), and the flag prints back over the socket.
