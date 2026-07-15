---
layout: post
title: "declaw"
subtitle: "unpinning Android TLS across OkHttp, Flutter, and cronet, and what you do when anti-tamper kills every injection: a hardware breakpoint and a two-instruction write into a live process"
date: 2026-07-15
tags: [ssl-unpinning, android, boringssl, anti-tamper, mempatch, hardware-breakpoints, frida, research]
category: research
tldr: "The first time I flipped an app's certificate check in memory, watched the write land, and still got hung up on, I assumed I had the wrong offset. I had the right offset. I had patched the wrong function. That is how declaw ended up covering four rungs instead of one. Repackage the APK for the easy stacks. Log the session keys off the unmodified app when it hard-pins its own BoringSSL. And when the app ships anti-tamper that detects a re-signed APK and crashes on the first inline hook, stop injecting anything at all: read the TLS keys out of the running process with a CPU hardware breakpoint, or flip the live cert verifier through /proc/pid/mem with no file change, no frida, and no ptrace-attach. This is the whole ladder, the decoy function that eats a naive patch, the negative controls, and the arm64 rig I had to build to prove any of it on real silicon-shaped hardware. Targets are anonymized by stack, not named."
---

The first time I flipped an app's certificate check in memory, watched the eight bytes land, and still got a `certificate_unknown` in my proxy log, I assumed I had a stale offset. I re-pulled the library, re-ran the finder, got the same address, wrote it again. Same hang-up.

The offset was right. The function was wrong. BoringSSL ships two things that look almost identical from the outside: `ssl_verify_peer_cert`, the one that actually runs on the handshake, and `ssl_reverify_peer_cert`, a session-resumption path that in a fresh handshake never executes. Patch the second one and everything reports success. The bytes change, the verifier returns "trusted", and the app keeps rejecting your cert, because the code you edited was never on the path. It is the cleanest false positive I have hit in a while: a patch that takes, verifies, and does nothing.

That is the whole reason `declaw` is not a one-trick script. Android TLS pinning is not one mechanism, it is four or five, and the tool that beats the easy one dies on the next. This is the ladder I ended up building, from the rung that needs no root to the rung that reads keys out of a process you are not allowed to touch.

## what "pinning" actually means here

There is no single thing to defeat. An Android app can refuse your proxy at several independent layers, and a real app stacks them.

- **System trust.** The plain case. The app trusts the OS CA store, and modern Android does not trust a user-installed CA for app traffic by default. Fixed with a network security config that opts the app back into user CAs.
- **OkHttp pinning.** The app pins in Java or Kotlin with `CertificatePinner`, TrustKit, or a homegrown `X509TrustManager`. You have to reach into the app's own trust logic.
- **Flutter.** The Dart engine carries its own BoringSSL statically and does its own verification, so nothing in the Java layer matters. Worse, it ignores the Android system proxy entirely, so even after you win the cert argument the traffic never comes to you.
- **cronet.** Chromium's network stack, statically linked, hard-pins its own servers, and speaks HTTP/2 and increasingly HTTP/3. The CA-and-config trick is rejected at the source and the handshake aborts.
- **Anti-tamper packers.** PairIP, DexGuard, and friends verify the APK signature at runtime and detect instrumentation. A re-signed patched APK is spotted and killed, and a Frida agent is spotted at spawn. This layer does not care how good your unpinning is; it never lets your modified app run in the first place.

Each rung below exists because the rung above it hits one of these and stops.

## rung 1: repackage the APK, no root

The default path, and the one that covers most apps. Given a package or a local APK, declaw pulls the base and every split, decodes the base with apktool, and rewrites it:

- a `network_security_config.xml` that trusts user CAs,
- the manifest flags flipped so the app is debuggable and accepts cleartext,
- the Frida gadget dropped into every ABI's `lib/` directory, with a universal unpinning script beside it, and the Application class's smali `<clinit>` patched to `System.loadLibrary` the gadget at process start.

The unpinning script is the public [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) bundle: certificate unpinning, the OkHttp and TrustKit hooks, the Flutter BoringSSL patcher, and the one piece that makes Flutter reachable at all, a native `connect()` hook that redirects the app's outbound TCP to your proxy. That hook is the answer to "the app ignores the system proxy". You are not asking it politely to use your proxy. You are rewriting the destination of every socket it opens.

Then repack, re-sign the base and every split in parallel, and install. Non-root, works on a stock device, and for an OkHttp or Flutter app it is usually the end of the story.

It has two hard edges. cronet rejects it, because the CA patch does not reach a statically linked BoringSSL that pins its own roots. And anti-tamper rejects it, because re-signing is exactly what those packers are built to catch. For those you have to stop modifying the APK.

## rung 2: stop sitting in the middle

If you cannot make the app trust your cert, do not try. Leave the app completely unmodified and read the keys instead.

declaw's capture mode runs [friTap](https://github.com/fkie-cad/friTap) against the original installed app. friTap hooks the app's own BoringSSL and logs the TLS session secrets as they are generated. There is no proxy in the path, no cert to trust, and nothing for a pin to reject, because the traffic is never intercepted; it is decrypted afterward from the key log and a packet capture. This is what beats cronet over HTTP/2: the pin is intact and satisfied, and you are reading the plaintext out of the side.

On a rooted arm64 device this captures cleanly. Against a cronet app I pulled real TLS secrets and decrypted the app's GraphQL and web hosts, all of which hard-pin and fail a normal CA man-in-the-middle. It needs root, because friTap drives a `frida-server` on the device, and that is the seam the next wall attacks.

## the wall: anti-tamper

Here is where the easy answers run out. A VM-based anti-tamper packer like PairIP does two things that break every rung above. It detects a Frida agent at spawn, so the gadget path and the friTap path both die before they start. And it runs a code-integrity check that crashes the process the moment you place an inline hook on the TLS library, so even if you get an agent in, the first hook you set is the last thing the app does.

Every injection-based approach shares one assumption: that you can put your code, or your hook, inside the target. Anti-tamper's whole job is to make that assumption false. So the move is to stop making it.

## rung 3: read the keys with a hardware breakpoint

A CPU hardware breakpoint is not code. It is a value the kernel writes into the ARM debug registers, and it fires when the core executes a chosen address, with nothing loaded into the target and no instruction changed. There is no agent to detect and no hook to trip an integrity check, because from the app's point of view its own bytes are untouched.

declaw's `hwbp` mode arms a `perf_event_open` execute-breakpoint on BoringSSL's `ssl_log_secret` in every thread of the target, samples `x0..x3` when it fires, and reads the label and the secret out of the process with `/proc/pid/mem`. `ssl_log_secret` is where BoringSSL emits its own key-log, so catching it gives you exactly the bytes the library would have written to `SSLKEYLOGFILE`, assembled into standard NSS key-log lines.

Two details cost me time and are worth stating. Hardware breakpoints are per-task: the debug registers swap per thread on context switch, so arming only the main pid catches nothing, because the app runs its TLS on worker threads. You arm every thread and rescan for new ones. And Android tags heap pointers in the top byte, so the pointer you read back is not a valid `/proc/pid/mem` offset until you mask the tag off. Until I masked it, the label read fine (rodata, untagged) and every heap read failed, which looks exactly like a broken offset and is not.

Proven on the rig against a live, unmodified, uninjected cronet app: the monitor pulls real TLS 1.3 secrets with the correct BoringSSL labels and full key-log lines including `client_random`, entirely out of the app's memory, with zero injection. It is a root-and-emulator-tier capability, not a stock-phone one, and I will come back to why.

## rung 4: flip the verifier in the running process

The hardware breakpoint reads. Sometimes you want to write, once, and let the app talk to your proxy normally instead of decrypting from a capture. That is `mempatch`, and it is the rung the decoy story at the top belongs to.

The idea is small. Find `ssl_verify_peer_cert` in the running process, and overwrite its first instructions through `/proc/pid/mem` with a stub that forces the return and exits. Two instructions, `mov w0, #0 ; ret`, where `0` is BoringSSL's `ssl_verify_ok`. No file on disk is changed, no frida is loaded, and there is no `ptrace`-attach for an anti-debug check to see; a write to `/proc/pid/mem` is not a `PTRACE_ATTACH`. The APK on disk still passes its own signature check because the APK on disk was never touched. The integrity check has nothing to find, and the app keeps running while its TLS quietly accepts your certificate.

For cronet this is the same function. Chromium registers its `net::CertVerifier` through BoringSSL's `SSL_set_custom_verify`, and `ssl_verify_peer_cert` is what calls that callback, so flipping it defeats cronet's pin over TCP. HTTP/3 is the exception and an honest one: a cronet HTTP/3 request rides QUIC over UDP, which a TCP proxy cannot see at all, so for HTTP/3 you go back to the key-log path regardless of what you patched.

And you have to patch the right function, which is the entire problem I opened with. `declaw`'s `find_verify` disassembles both candidates and picks the live `ssl_verify_peer_cert` over the `ssl_reverify_peer_cert` decoy by their AArch64 prologues, because the decoy patches just as cleanly and buys you nothing.

The negative control is the part I care about most, because "the app loaded" is not evidence the bypass worked. Against a PairIP-hardened, certificate-pinned app: unpatched, the app dropped the connection with `certificate_unknown` the instant my proxy presented its cert. After the in-memory flip, the same app emitted `POST https://<its API host>/graphql/...` in the clear, through the same proxy, with nothing else changed. The thing that flipped was eight bytes in a function, and the difference was a rejected handshake becoming readable plaintext. That is the control I trust: turn the one variable off and the plaintext goes away.

## you cannot prove this on an x86 emulator

Every rung past the first leans on the same thing: root, arm64, and the app's real BoringSSL loaded in a real process. The standard x86_64 Android emulator gives you none of it cleanly. It cannot run arm-only builds, and its ARM translation layer breaks Frida's native hooks with an agent SIGSEGV. mempatch and the hardware-breakpoint finder are arm64-only by construction. So to test any of this honestly I needed a rooted arm64 Android that I fully controlled, and on an x86 laptop that is not something you can just download.

So I built [declaw-lab](https://github.com/UncleJ4ck/declaw-lab). Two backends, one entrypoint.

![the rooted lab device, an Android guest driven entirely over adb]({{ '/assets/img/posts/declaw-lab-device.png' | relative_url }})

The **qemu** backend boots a real aarch64 Android under `qemu-system-aarch64`. Both the 64-bit and 32-bit ARM instruction sets execute as guest code; it is not an x86 image with a native bridge. On an x86 host the CPU is necessarily QEMU TCG software translation, not physical ARM silicon and not KVM, and I am not going to pretend otherwise. What you can do is make TCG hurt less. It runs with multi-threaded TCG spreading the guest vCPUs across host cores, `pauth-impdef` so pointer-authentication emulation stops being a tax, a gigabyte of translation-block cache, and the vCPU threads pinned to physical cores. It is the only backend that runs declaw's arm64 primitives, which is the whole reason it exists.

The **avd** backend is the fast lane: a rooted x86_64 Google emulator on KVM, for the OkHttp, network-security-config, and static-Flutter work that does not need real ARM. Fast, except it was throwing away its own boot every time.

![measured warm boot after enabling the snapshot]({{ '/assets/img/posts/declaw-quickboot.png' | relative_url }})

The emulator was launched with `-no-snapshot`, which disables quick-boot completely, so every single run paid a full cold boot. The fix was one flag with a caveat I had to check by hand: `-writable-system` is why quick-boot was turned off in the first place, because a writable system image can invalidate the snapshot, and older emulators refused the combination outright. On the current emulator it does not. So the lab now boots cold once, saves a rooted snapshot, and every later run restores it with `-no-snapshot-save`: cold boot 26 seconds, warm boot 8, and it comes back already root. Measured, not guessed, and it never overwrites the saved snapshot, so each run still starts from the same clean state.

Everything folds into one command. Point the backend at a patched APK and it boots the device, installs, redirects that app's 443 to a host MITM, and opens a scrcpy window, and because a declawed app accepts any cert there is no device CA to install, which is the whole point.

![the lab entrypoint, both backends behind one command]({{ '/assets/img/posts/declaw-lab-cli.png' | relative_url }})

## what does not work, on purpose stated

A tool writeup that only lists wins is a sales page. Here is where it stops.

- **32-bit apps on the rig.** The arm64 backend runs a `zygote64_32` build and will launch a 32-bit process, but declaw's mempatch and hardware-breakpoint helpers are arm64-only today. Proving a 32-bit app installs and runs does not mean I can instrument its TLS. The 32-bit key-offset path is proven on a controlled target, not yet against a live 32-bit app.
- **HTTP/3.** Anything a target sends over QUIC is invisible to a TCP proxy, so mempatch buys you nothing there. Use the key-log path and read it in Wireshark.
- **The hardest integrity checks.** PairIP's code-integrity check still crashes on the first inline hook of the TLS library, so friTap against the most hardened apps yields a capture with no keys. That is exactly the case mempatch and the hardware breakpoint exist for, because neither one places a hook. But it is per-build reverse engineering, not a button.
- **Stock non-rooted phones for the zero-injection rungs.** Cross-process `perf_event_open` and another process's `/proc/pid/mem` both require `ptrace_may_access` to pass, which off a rooted device means same-uid or `CAP_SYS_PTRACE`, and stock Android ships `perf_event_paranoid=3` with SELinux enforcing on top. The hardware-breakpoint and mempatch rungs are a rooted-or-emulator capability. On a stock phone the answer is still the repackage path.

## the repos

- **declaw**, the tool: [github.com/UncleJ4ck/declaw](https://github.com/UncleJ4ck/declaw). Patch, capture, hwbp, and mempatch, with `auto` picking the rung from the app's own stack.
- **declaw-lab**, the rig: [github.com/UncleJ4ck/declaw-lab](https://github.com/UncleJ4ck/declaw-lab). The arm64 QEMU guest and the fast x86 emulator, one command to a rooted device decrypting an app into Burp.

The unpinning hooks come straight from httptoolkit's [frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning), the key-log extraction from [friTap](https://github.com/fkie-cad/friTap), and the repackaging from [apktool](https://ibotpeaches.github.io/Apktool/) and [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer). The rungs past injection are the part I had to figure out the hard way, one wrong function at a time.
