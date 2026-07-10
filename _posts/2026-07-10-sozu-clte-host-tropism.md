---
layout: post
title: "The host it could not infect"
subtitle: "eight proxies came back clean because I had built the differential blind on one side, and the bug that was already in my logs turned into an unauthenticated auth bypass in sozu"
date: 2026-07-10
tags: [http-request-smuggling, desync, sozu, transfer-encoding, fuzzing, regression, research]
category: research
published: false
tldr: "I ran an evolutionary fuzzer at eight reverse proxies hunting an HTTP request smuggling desync and got nothing back. The reason was not that the proxies were safe. It was that I held the backend fixed at one strict parser, and a desync is a disagreement between two parsers. The moment I added a backend that disagrees, a request sozu had been forwarding all along became a working, unauthenticated Basic-auth bypass. It is a regression of a 2021 sozu issue that did not survive the rewrite onto the kawa parser, live on the latest release and on current main. This is the whole thing, including the parts that cap it below critical, the prior art that already owns the method, and the fact that the trigger is not new."
---

## the thing that bugged me

I want to start with the failure, because the failure is the whole reason this exists.

I had spent about a week pointing an evolutionary HTTP fuzzer at eight reverse proxies. HAProxy, nginx, Caddy, Envoy, Apache Traffic Server, sozu, OpenLiteSpeed, Apache httpd. The target class was request smuggling in the HTTP/3 and HTTP/2 to HTTP/1.1 downgrade, the part where a proxy takes a modern framed request and re-serializes it as HTTP/1.1 for an origin that only speaks HTTP/1.1. Every run came back clean. The oracle was positive controlled, the sentinels fired on a known-vulnerable build, the labs were real Docker with real backends. Clean, clean, clean.

The bug was in my capture logs the whole time. I had built the test so it could never see it.

That sentence is the post. Everything below is how I got there and what fell out of it.

---

## what already exists, and why the method is not mine

I did the homework before I wrote a line about methodology, because the worst thing you can do in this genre is dress up a known technique as a discovery. The differential-fuzzing-for-smuggling space is not empty. It is well tilled, and two papers own the ground I was standing on.

- **T-Reqs** (Jabiyev et al., CCS 2021) is the grammar-based differential HTTP fuzzer. They generated mutated requests, ran ten server, proxy and CDN technologies in pairs, and found the pairs that disagree on message boundaries. Panel-pair differential fuzzing for HRS is theirs.
- **The HTTP Garden** (2024) is the one that should have saved me a week. Its whole thesis, stated in the abstract, is that not all parsing-discrepancy vulnerabilities are visible from a gateway's output alone, so you have to examine how the origin interprets the bytes too. That is exactly the mistake I was about to make, written down and published two years before I made it.

So the method here is not new. What I did wrong, and then fixed, is a re-derivation of the HTTP Garden's central point. The trigger I ended up with is older still. I will get to that. I am flagging it up front so the rest of the post has some credibility: the value is in one specific, current, unpatched implementation bug and the honest walk to it, not in a technique.

The fuzzer is called Phage. The name carries the lesson, so let me use it.

---

## the host it could not infect

A bacteriophage does not infect life in general. It infects one host, sometimes one strain, because the fit between the phage tail fiber and the host's surface receptor is specific. Wrong pair, nothing happens. The virus bounces off the cell and drifts away.

A request smuggling vector has the same shape. It is not a property of a proxy. It is a property of a pair: a front end that draws the message boundary one way, and a back end that draws it another. The bug lives in the disagreement, not in either parser alone. CWE-444 even says so in its name, inconsistent interpretation.

Here is what I got wrong. I varied the front end eight ways and held the back end fixed at one strict HTTP/1.1 parser that framed strictly by `Content-Length`. Eight fronts, one host. If a front emitted a message that only a different kind of backend would misread, my one backend read it the same way the front intended, the two agreed, and the oracle counted a single request. Every front looked clean because the single immune host made every front look harmless. I had a panel, and I told myself it was diverse. It was diverse on the one axis that could not produce a hit.

---

## grepping my own logs

I stopped fuzzing and did the least clever thing available. I wrote a twenty-line parser and walked every byte my fronts had already forwarded to the backend across all those clean runs, looking only for framing ambiguity: a request carrying both `Content-Length` and `Transfer-Encoding`, a chunk size that did not match, a duplicate header. One hit came back, from sozu:

```
GET /admin HTTP/1.1
Host: lab
Content-Length: 40
Transfer-Encoding: chunked, identity
X-Forwarded-For: 172.46.0.1
Sozu-Id: 01KX...
```

Both framing headers on one request. sozu had added its own `Sozu-Id`, so this was sozu's output, not my input echoed back at me. And the smuggled request that followed in the body carried no `Sozu-Id`, which meant sozu never parsed it as a request. sozu framed the whole thing by `Content-Length`, swallowed the trailing bytes as an opaque body, and forwarded the `Transfer-Encoding` header along with them, untouched. My strict backend also framed by `Content-Length`, agreed, and the smuggle stayed invisible.

A backend that honors the `Transfer-Encoding` instead would split it in two. I added one Go `net/http` backend to the panel and the whole thing lit up on the first request.

---

## the trigger is old, the bug is back

The value sozu choked on is `Transfer-Encoding: chunked` with a trailing tab. Send that plus a `Content-Length`, and sozu does not recognize the tab-suffixed token as chunked, so it frames by `Content-Length` and forwards both headers. Go trims the trailing tab, sees `chunked`, frames by `Transfer-Encoding`, reads the empty terminating chunk, and treats the bytes after it as a fresh request. Textbook CL.TE.

Here is the part that made me laugh and then wince. This exact trigger is in sozu's own issue tracker, #726, reported in 2021 out of a BuckeyeCTF challenge. It was fixed then by a patch that trimmed linear whitespace from the header value. Then sozu 2.0 rewrote its HTTP layer onto a parser crate called kawa, and the trim did not come along. The fix regressed.

The root cause is four lines in kawa's HTTP/1 parser:

```rust
const CHUNKED: &[u8] = b"chunked";
if val.len() >= CHUNKED.len()
    && compare_no_case(&val[val.len() - CHUNKED.len()..], CHUNKED)
{ /* elide content-length, frame as chunked */ }
```

It checks whether the last seven bytes equal `chunked`. No trailing-whitespace trim, no handling of a transfer-parameter like `chunked;a=b`, no check that chunked is the final coding in a list. When the check fails it keeps `Content-Length` and never strips the `Transfer-Encoding` it did not understand, so both go out. RFC 9112 section 6.1 says an intermediary must not forward both.

And the reason nobody caught the regression: sozu's own smuggling test sends a well-formed `Transfer-Encoding: chunked`, which passes the suffix check and is handled correctly. The test never sends a malformed value, so the regression landed exactly in the blind spot of the test written to prevent it. I confirmed it on the latest tagged release (2.1.0) and on current `main` (2.1.1), over both a plain HTTP frontend and a TLS-terminating one, since the parser runs after the TLS decrypt.

---

## how far it actually goes

This is where I have to be careful, because the fun half of a smuggling writeup is the impact and the honest half is usually smaller.

The primitive is clean: I can deliver a request to the backend that sozu never parsed, routed, filtered, or logged. What that is worth depends entirely on what the backend trusts. The strongest thing I could demonstrate end to end is an authentication bypass, and it needed a feature sozu did not have in 2021.

sozu 2.x added per-frontend HTTP Basic auth. So I set up two frontends on one backend cluster: `/public` open, `/admin` gated on Basic auth. A direct `GET /admin/secret` returns 401. Then an unauthenticated `GET /public/x` carrier with `GET /admin/secret` smuggled in its body made the backend serve the gated endpoint with no `Authorization` header at all, and a follow-up request on the same keep-alive connection read the gated response back. Drop the one `Transfer-Encoding` header and the whole thing collapses to two boring public requests. That negative control is the finding.

The precondition rides with the severity and I am not going to bury it: this needs auth on one route while an attacker-reachable route shares the same backend. Gate the whole frontend and the carrier itself needs auth, and the bypass dies. So this is high, conditional on topology, not a flat high. I scored it CVSS 7.5, `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L`.

What I could not do is hijack another user. I checked sozu's connection model twice, once by watching backend source ports and once by reading the source. sozu binds one backend connection per client connection and never hands it to a different client. Four separate clients get four backend ports. A poisoned connection is the attacker's own, closed when they leave. That kills the cross-user version of this, which is the version that would make it critical. I went looking for a way around it through a shared cache, and the two caches people actually deploy, nginx `proxy_cache` and Varnish, both reject the trigger outright. Only Go-based caches like Souin honor it, and I did not choreograph the full store-and-serve. So: real, demonstrable, high-conditional, and honestly not critical. The one-to-one connection model is a genuinely good design choice, and I am not going to pretend it away because a bigger number would read better.

---

## the parser is the unit, not the product

Then I mapped which backends make the pair fire. Go `net/http`, of course. But also Puma, uvicorn under `--http h11`, and Hypercorn. Three more ecosystems, all live behind sozu. And one result stopped me.

uvicorn is a single server, one version, and it smuggles under `--http h11` and is safe under its default `--http httptools`. Same server, same version, opposite verdict by one flag.

We track HTTP security by product and version. An advisory says it affects nginx 1.2 through 1.4. That granularity is wrong. The security boundary is the parser, and one product ships several. h11 and httptools are two Python packages doing the same job with opposite answers, and no advisory database has a column for which one you loaded. If you run an ASGI app, the honest answer to "am I exposed to this class" is not which server you run, it is which parser flag you passed, and most people cannot tell you.

That is the part I would keep if the sozu bug got patched tomorrow. Audit parsers, not products.

---

## handing it back to the fuzzer

The last thing I did was give it back to Phage, because a finding a human dug out by hand is only half a tool result. I added the tab-suffixed `Transfer-Encoding` to the mutation gene pool and the Go backend to the panel, and let the engine run its own mutations against the live pair. From a smuggle-shaped seed it evaluated 150 genomes and its differential oracle flagged two of them, whose triggering values were exactly `chunked` with a trailing tab and `chunked` with a trailing space, and cleared the obfuscations that get rejected. The tool rediscovered the bug I had found by hand, which is the only kind of tool result I trust.

The honest note on that: a blind search over the full operator set is too sparse to assemble this three-part payload in a reasonable number of generations. I had to bias the campaign toward the framing genes, which is how you actually hunt a known class rather than a novelty. The engine did the discrimination, which is the part that matters. It is the difference between a fuzzer that emits `chunked\t` and a fuzzer that can tell you `chunked\t` splits sozu from Go while `chunked;a=b` does not.

---

## where it stands

Reported privately to CleverCloud as a regression of #726, with the ask to fix it at the class, not the trigger. The defect is forwarding both `Content-Length` and `Transfer-Encoding` at all. Trim the tab and `chunked, identity` still slips through, and Werkzeug's dev server honors that one. The fix is to reject or normalize whenever a `Transfer-Encoding` is present but does not resolve to a valid final `chunked`, never to fall back to `Content-Length` and forward the header you did not understand.

No new technique. The trigger is from 2019, the bug is a regression of a 2021 report, and the method belongs to two papers I cited up top. What was worth the week is smaller and more useful than a technique: a differential is only as strong as the diversity on both sides of it, one immune host makes every attacker look harmless, and the moment I added a host that disagrees, a request that had been sitting in my logs for days became an auth bypass. This post goes up after the fix.

## references

- [T-Reqs: HTTP Request Smuggling with Differential Fuzzing](https://dl.acm.org/doi/10.1145/3460120.3485384) (CCS 2021)
- [The HTTP Garden](https://arxiv.org/abs/2405.17737) (2024)
- [PortSwigger: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- sozu-proxy/sozu issue #726 (2021)
- RFC 9112 section 6.1 (Transfer-Encoding and Content-Length)
