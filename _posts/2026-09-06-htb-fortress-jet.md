---
layout: post
title: "HTB Fortress: Jet"
subtitle: "eleven flags, sealed. paste one to read up to where you reached."
date: 2026-09-06
tags: [htb, fortress, pwn, heap, house-of-orange, rsa, wiener, sqli, rce, xor]
category: writeups
kind: fortress
tldr: "A locked fortress writeup. Paste any Jet flag and it unseals every checkpoint up to and including the one you own, all decrypted in your browser with the flag as the key. The higher the flag, the more you read."
---

<style>
/* Jet fortress gate: leans on the house .prose styles; only the mechanism is bespoke.
   Restraint per DESIGN.md: flat surfaces, one accent, glow only as a faint text-shadow. */
.jet-hero{border:1px solid #1e1f14;border-radius:4px;background:#14150e;padding:1.15rem 1.25rem;margin:0 0 1.75rem}
.jet-hero .k{color:#767e22;font-size:.72rem;letter-spacing:.04em}
.jet-hero .t{color:#e2ddcd;font-size:1.5rem;font-weight:800;margin:.15rem 0 .3rem;letter-spacing:.02em}
.jet-hero .t b{color:#b3bd33}
.jet-hero .m{color:#514f43;font-size:.78rem;line-height:1.7}
.jet-hero .m span{color:#989484}
.jet-gate{border:1px solid #2e3020;border-radius:4px;background:#14150e;padding:1.15rem 1.25rem;margin:1.9rem 0}
.jet-gate h3{margin:0 0 .45rem;color:#e2ddcd;font-weight:700;font-size:1rem;border:0;padding:0}
.jet-gate h3::before{content:"> ";color:#767e22;font-weight:400}
.jet-gate .lead{margin:.2rem 0 0;color:#989484;font-size:.82rem;line-height:1.7}
.jet-gate .lead code{color:#b3bd33}
.jet-row{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.95rem}
.jet-row input{flex:1;min-width:230px;padding:.6rem .75rem;border-radius:3px;border:1px solid #2e3020;background:#0b0c07;color:#e2ddcd;font-family:inherit;font-size:.85rem}
.jet-row input:focus{outline:none;border-color:#767e22}
.jet-row button{padding:.6rem 1.2rem;border-radius:3px;border:1px solid #767e22;background:rgba(179,189,51,.07);color:#ccd45c;cursor:pointer;font-weight:700;font-family:inherit;font-size:.85rem;transition:background 150ms}
.jet-row button:hover{background:rgba(179,189,51,.14)}
#jet-status{margin-top:.65rem;font-size:.8rem;min-height:1.1em;color:#514f43}
.jet-ok{color:#ccd45c!important;text-shadow:0 0 12px rgba(179,189,51,.35)}
.jet-bad{color:#c86a4a!important}
.jet-prog{display:flex;gap:.25rem;margin-top:.85rem;flex-wrap:wrap}
.jet-pip{width:20px;height:5px;border-radius:2px;background:#0b0c07;border:1px solid #2e3020;transition:background 150ms,border-color 150ms}
.jet-pip.on{background:#767e22;border-color:#b3bd33}
.jet-locked{color:#514f43;font-size:.8rem;margin:1.5rem 0 0;border-top:1px dashed #1e1f14;padding-top:.85rem}
.jet-locked::before{content:"[ sealed ] ";color:#767e22}
.jet-note{background:#14150e;border:1px solid #1e1f14;border-left:3px solid #b3bd33;border-radius:0 4px 4px 0;padding:.8rem 1rem;margin:1.6rem 0;color:#989484;font-size:.8rem;line-height:1.7}
.jet-note b{color:#e2ddcd}
.jet-flagline{margin:1.4rem 0 .3rem;padding:.5rem .75rem;border:1px dashed #767e22;border-radius:3px;color:#ccd45c;font-family:inherit;font-size:.82rem;background:#0e0f09;word-break:break-all}
.jet-flagline::before{content:"flag  ";color:#514f43}
.jet-tier{border-top:1px solid #1e1f14;margin-top:2rem;padding-top:.3rem}
.jet-tier:first-child{border-top:0;margin-top:.5rem}
.jet-fin{margin-top:1.4rem;color:#ccd45c;font-style:italic}
</style>

<div class="jet-hero">
  <div class="k">// hackthebox fortress</div>
  <div class="t"><b>Jet</b></div>
  <div class="m">11 checkpoints &middot; <span>10.13.37.10</span> &middot; web &rarr; www-data &rarr; alex, two 2017 heap binaries, one RSA detour</div>
</div>

Jet is billed as an intro fortress, but it fans out wider than that: a web chain (reverse DNS, obfuscated JS, SQL injection, a `preg_replace /e` RCE), a leaky SUID overflow, repeating-key XOR, an RSA Wiener attack, and two hand-written glibc-2.23 heap services that want House of Orange and a fastbin-to-one_gadget chain. Everything below the gate is AES-encrypted in this page. Paste a flag and it unseals every checkpoint up to the one you hold.

## the surface

| port | service | what it gates |
|---|---|---|
| 53 | BIND | reverse DNS names the real vhost |
| 80 | nginx | obfuscated JS, SQLi, `/e` RCE |
| 5555 | membermanager | House of Orange heap pwn |
| 7777 | memo | fastbin + one_gadget heap pwn |
| 9201 | fake ES | data-leak checkpoint |

<div class="jet-note"><b>One infra trap worth the warning.</b> The named vhost took requests and returned nothing over ~1200 bytes. Not a WAF, not a crash: a path-MTU black hole on the VPN tunnel. DF pings pin the real MTU at ~1330, a Range request proves the cliff (401 bytes back, 1201 hangs). Lowering tun0 MTU to 1300 clears it. If large HTTP responses vanish on a fortress, suspect this before the app.</div>


<p style="color:#767e22;font-size:.85rem;margin:1.6rem 0 .4rem;font-family:JetBrains Mono,monospace">// the chain, end to end</p>

```mermaid
flowchart TD
  A[nginx default: HTML comment] --> B[DNS reverse: www.securewebinc.jet]
  B --> C[secure.js fromCharCode: admin dir]
  C --> D[SQLi dump: admin creds]
  D --> E[preg_replace /e RCE: www-data]
  E --> F[leak SUID ret2shellcode: alex]
  E --> G[XOR crypter: key securewebincrocks]
  G --> H[zip: membermanager + memo]
  H --> I[5555 House of Orange: membermanager]
  H --> J[7777 fastbin + one_gadget: memo]
  F --> K[tony RSA Wiener: secret.enc]
```


<div class="jet">

<div class="jet-gate">
  <h3>unseal</h3>
  <p class="lead">Paste any Jet flag. Braces optional, <code>JET{...}</code> or the inner text both work. Each flag reveals its checkpoint and every one before it, so the further you got, the more you read. Nothing leaves your browser, the flag is the AES key.</p>
  <div class="jet-row">
    <input id="jet-flag" type="text" placeholder="paste a JET{...} flag" autocomplete="off" spellcheck="false">
    <button id="jet-go">unseal</button>
  </div>
  <div id="jet-status"></div>
  <div class="jet-prog" id="jet-prog" aria-hidden="true"></div>
</div>

<div id="jet-sections"></div>
<div id="jet-lockmsg" class="jet-locked" hidden></div>

</div>

<script type="text/plain" id="jet-b1">U2FsdGVkX1+RHvypZ6rgpqyIrYqOI5zR7gbBaC1vauhyzz/OPVh19EKbVusZGFrtM4OXYE0xOEeZg8Y4LJk6RwQqVGGPIDcIbE9gAGmYzvcS8pYuQI7BqQg8PiHcPP8bN8xuyH1GCUXTu7YBVMe+LknVtBWs4xcv/CtiyV6qlo7+MkxjDSreeQSaQ3EFDiPUiO93R15ynuDTIysztzeogvJ8f+igTfTguvle+dFhcK/bclXaxk1mlJ8lQL7cQPjRC22tqu/SucFlpsOTjExVMZ4N5vDBLoouE+8JCxVwD4FCZU9jA1/VedSGzkeP2r/nK6fwWtLKuxSoO3H/v2BK5BY6ISBt/gJjIkO35jbe7afqDDMnbZ6HOULfQzJ54dyb6ZMzmSf6vzXFtdmbdvM0eYdyDSMtqaOqDayMu0/Igp9pv9OgwLJLmLIe6UHw2Eo2hEiWIsW9kvG6X+a7gNhuEUHN9qPRScq//dV12JM5twfFPPZltFHzxKl30QYYKMvKoqwbQW46efcku8luNk4xKUhGtUsM39Mvoj2Ax71TqPAY34XvLHtOylI19/aG0nXadA+94jvBeNS/aam40AQ2/eYv5Fu06SvPj0U7ashYnOmlKnJyIMiUywAUxQWZrQ0nDdNYV5rxnxQEKn9Zj/xDwprm8MUsfIhPZVvUnbD+aOg/HEp5yiyaNCkKux1It86w1jvFAHvyQXprF85s5kTrNtnL0/vq7ltzXVMG75u76v/vR4ohv8f3QIYmVFEHuGYCEBexX4TbspwzsBE85GdlPk0DgGJtBtHIn7B5G4fkAcyVzPLpMVF/tZAOsO1uJy9ve3BV/4SMFP0u7KUM7hhAFsmxf5FpTyvVEhCECZmOOOHe+fE4Jf/yDtZFFBja8WhZVQAHf+2y445RY7TuGGGcU7Yvz2JbtmzxSFmY6iw4bqzdYnjrNy38G29FoHwGVlwQWCGJCBLcenxnGHZIzDhh5xF61ZkHfVxwBrhvk+qAr9A40Ze0pTNoz13tm5Dwn0u7NrAepiJfh+oGnSO4291EpfpXlB04BT4CQs7LwemCc/erTb6Juy3Pqh9cQfE2yTZQKSsRE2nGY3k8Jw4KhgG6dc7dKwCgXQ6qs4vsuIJrDSu/R1z++x8xogThSGbf28MJE7DpHRK1BkAKeaA2aaTDOO3+S9w8FjoI3KtmD+V6FiuDvvPsSq4X5TsMwsyB0s7AhFuCcNeVw23fIuWZTJYUTGvl2DBq67zjok8dZQM6X7iOqA/Pyjl6BHz3N8zwEQGtJJAoFKD4RtIUBgLxSBBcnAlIwzviURf2TjFdhZuXUymBmwf7iUuLUmC2oRqmmgv52EK9DZCKX2736GSa6dICefyH41ct5apbrAl2Z+QM3Ythp38qZcySqTo7Ees7sugR4OunJApgcflTdYGd64cpKAQ3wOR+MsifhNiaTvlRt+nW7CigSG64MpC+cxll6GtctOhWa2Q3hwTQm0E0SrSMBYCxo2ngLroiug++KRD4d8awN4ZxXZRAGsWPTD0vJPOy3Q3L/zxCAE1HWIKBGEycKvMw5XUzLPIZgyDOp2i/Ad2Yir6HYVzebD8VzQ69/OKqKe87y5qeidHaZWaRx72scFg8oUhC9b1PcZsorRsDOZV/iEvy4Ql9sw2Tqn25/L1OqYTpdUyxKKQll+GWE9++qxMAjl3OSs1l8NaIq1nXEp5A+WPQK2+x7IM3wBcjILBd/JZtxDLMUrzrUifYi8mclx9xlI5QfApPvek0SuOAnxdYViMGchVBk9BH6yA2xourIsxQL8zCM5tTG6OgkJZ0LGSPROaH5LCkCn4D1MZ0cWboRRLLr6c1EPOuexO+GHc3B/5RFOfbspXto3fLAOgOBg==</script>
<script type="text/plain" id="jet-b2">U2FsdGVkX19FwA/3uOxjljtcSQlFMgYXjzdrQcinkOI4a5Cg5PcRHLIq2oEatU/JpqrorDMMvg52i1YfGKbbO2LnbYEvx2Nh1+4HaiKOzLQiIdkO2xpDv4iFroU+XEdtCnxoce4Tm6eU6xvDoarBwbJxfTLhNPowQW1zDZgt8ARa0ex2zrtJ4enFywD18On5W2r6Ucgu139UehLiO+mf3rEtRXwvDwbeK2nMiJJyjsMI/fIVyw0hXKd4qwYKBKnhURR047j1B2CWmA2QL0FWuaSPr0RF7HgTabmhRnm+39Dp5WPyr+Zdb3+fnXfAIyoFbA/Q5FhNY3rYFwkkSgbF939kX1fhyE63k0I91ASb0BDppYeqOQcIokURlD7SGUTLpFL6gPyGgHo4l02Sxc8UNRiTlZQGsbJRF2k6d+fOtYieHJjuVbrweViRYbnENbHZNaq8B6cMYVdhDY0sBJMMOfTb9XHjASCpBHgPv3inlRR4KDQlBo6tk68iYFkUw6W17ZBebCqxRcu1hKEV/sHfJ7CzonsVS7f/RXm4HpF9wW+yVrqbh2oro4nas6qmyTVCQZEIARXiEi+6V3/9YQy6oMXu+nZzS3lpC89NTmnVOyVwVCh6eFev75NA26IAz6woq4Dij9bJOfMJVIM7DeiHTDI45ZJsXJrX2zPKORyU580hBuplReBOF1rHcWo3FquMJLbYCW6RMGBr9tybISbETRadOM2cxL6mFlDrjVLheNSI4kTCdNBAx8FLIH4d32gwPIvLCBG8PqdnV65pqHIaWfrweV1Qem0wWW6kwMy9ypbiDBaVl/ne5I+5hwKH6wZz8UDiTWI8HHoZfGIG7a7yECj/FJWaoUwYvARIQ1zdKQH0/lFlvucZ4+P2ALTKDadEH2J5kAYoKaT19IAwyeJBS5+hOD1qwNi9RlQeAawSQnJKp9eES/ypP593KG65VJ6QRr0UE9a5XH7aGPwBTqSADQ==</script>
<script type="text/plain" id="jet-b3">U2FsdGVkX1+GpU+Xrvsezb9K+/Kcp7FKTpLp+F99hqjY8ZFiDICH3ugazra19Vf+14IH+6R2haVRUjTW8vdPeonBnnjGNUQ8dykVLPrWGcZX+4UYnAtsnJqLE7jFdy/zMmC7vigJeXAr74fWfdcRrZE1yiz6nQjLcUjV9Oa01s+agO2+hXqFj1rYLrZ3AVHFBcnwKPBS88k34J/7Li7l4UjBy3yReJarcYuS3NcHCSejKQmeM8AKvxtGlEkNgIqwE47pht/VaAE0YIGgYrGbxF7SK+6yMtAdXRjNpPBw3gBbw9+4ADHT2KHvEgkHO3e+PGV1FZCEFrnDixIMxypnzq7yVrMd4JW9ZUVqph0kL/oaYLqMY5qbGtDhNpfusFqKMXs4IDef3iCetcI/rP3maAJ8MzTD1lacW8x1liu0k534rXvQQNIFxPGX64Rf3B5bRwr9BZRzTwXyZTlf6mk0Q46Gg4gOcO2QjT3ioOeU0OyCJ4A4P2g2xDg634AD557n0w64McxHhxYhrmr3eJXDH727+sXKssroMh+Iq5DHfAH4S1tgjMwB3XH6n4LlqgxBFQPlOX+vvVEzA46v0a0xBpYjDOVvCO0/mV3TAJ2mZ7t6Cgw+RxRrZ1wOxCLPSKvRS+ryl1Tj3+hShpYvisKqQ5BSvuRlNbDjJXSGp2x679e79Z46bJXJNuvyx2H9YuKpcdcJi+1tgHDyFzFjAyQi43hvUY16OCj6ZwITmlxin46XnYlLbnLNgbg5v9Rnybg3PVPwjvwbg1KoxWIUtxLBoOuZWSp/ao5cVUyXzZImxXM+3NgNCOJ5nZOVSTC0LcHzU2vZhBTMN/DEZ/mnNPB/99D0NNPsAiGdG+CZ92nRZppbQhNLxaPNbWE5i6a8qKJXllUS5z+hhMBONIJdMJoSzuUOrlQkXwfbSMwWnq+fexRvI00ZUn+b3tnYyaCjemVCdnO2XfNmF8PUhXNI/mp92r2e7+6nk8BYUQGEH8vz2bVkYy0dFfatzLUkR6Ls8p4FX3nUf7KOWzdQULQtaChT5tkhYcj6Jy47rhZ33WU+lzKNQKj05MslNEfn5GiwXxhiyobcElQAP1e7MQB/YQASZ2IyYxR9d9XBNq3Ml/C+KmM=</script>
<script type="text/plain" id="jet-b4">U2FsdGVkX19Y4GYjLDC5YU/vg+sOGdCK7B7QukLg8Hb+Bip3PzKvJ+NDPGJUw3IQ02mHlcFjjL5YeXG8KPxaVnxV3bxTp9wAOq3WJ5AJ4xvVACCBxxesB4jo/0rocmoWuAlVw6qdwepacaPIo/KIoJ599EOFrqjlZhu6PILRazHOKlUmMmd3d3y5961mFJcyZKUga7JqZoI4NlY+09FjwsxnUpeWYf1+qEj2ZFB4Dzei09OE1tqggn0d2c/bPUyD+JBntnCpiDYvGc3ENk8fC6MaXheaJSaZ92m/TVF4d1Cz6sPibKwy9EY60pgjBvqGB7ILKcWyyCIjJNt0Fk4Y2yG2NGohnx37v6ZtzrfuI6sRjozf1rlMvMHhgEfobTq5Z6YEdejgRt84ODHP65Os3140gsqoHdVlsd4MhKQtdse9Mddgof3BeE+SgVXapBtP9LLVe8KjrfRczcbckjK+78CxCn+BFQbxFuJCzgVPBdJWvgVbtlYxMi73YYjtalI2YS6TXMT/thv56TE7lCJbP5180rInteDKpQRwz9vB3eCPhr0C3pCWKNPn1LQnz9KWBsZY9SX7X3cpRLg+jJ3jXGBnRT7rLi+whqZqe7FwMD7EsAvKqGfWoYiBMCrRFNcThovb+GG19xwq+UvQzEErxnmwzZxY00Tr18bKJX6MqSIyhBUzzLo0PuXhEBbbtBSt4JZSNQDCBFfG4EyPW3vQfyZvGNnHB5B2z2pn3zGHxMFv11ledymVsrcnZ82qER3XiMSA24/mbSAtcPrQvjJEmHayB8jVp7TvfxAXaDL8A8lok5vKsrWyIJcCY9fan3ROCJDk+sJ1TfxTjHWuuXCZBqygS7fmQaU4E09DWVjsoLb7Wf/o8aK8YHXynY1sEcASG5nvP1scrwlLM5RnO1xugwpjn1IDwoj2xN6m3/d+GKSWdbZgbq87ooJoL9/I2IN4S9MQe7k3fZWyQMKdSUWJtQoz1zf7xwTLMuPJqJZpwRXVSPh9p+cs3xIJaJLN84WnKgfQ8xNplMgQ9JKJs8NQOvPAiCtwcSg5vFx/GV+YKwF4xHmaowf53CdaWrmdTcE8dq+sFsmdZeCqSEwaLSA1zK9RN3j/xSR45YcGZvPik1cTu0DZBmpCH9CwKK+QBuW2VX5fPCSsdZG/NJLA4khSAnlXP64+ilV+F/aSDwYdL9SwCDzHKVz81cX2SRBFXrUQriFjJvDRDgSK3zGH5hN8SK6nyrvsYTg1XciYT1N5Vnc0VtZ3LQpVtqAIKck2F8KDjWPMVCqqFylmP4tmEEThB2nOTFHrwsYuoizScx6aGvrOAlP7hZopCv1V5vCTf0vqmlfNYvB1pfGPQpAjEzJPK9yCQCD5BLwsz0opSTB+e1GeIlUfMNsnIt3MTgBZTkqABFZyw7AtmYZ1jywolktLDEGjPxDJgfeXiUEXTnWYYuh1WwmWXdHWB/0oicKyLbQHQB667uMUJwBLCXykX8+1nmw/qIl1TqvH+dlBbwfbinFRX34uyPSm64m0Q1SBxmTEgWkTX0/EiQpWxNUM4QtuwQ==</script>
<script type="text/plain" id="jet-b5">U2FsdGVkX19H5zbpDzb/zCi3fsMtmFMI8k5v7ke4pnF8iboY8s38F6Ejk2QEV4WUv3Wgc3oeOQ4lVL2BYofbJL14D1PMV+5YXqk4hp+NwPkaC8lizpLOCNFl9tYD+PvPH33FUJR4fqMHsFojMAmoUulZ67hWlIqH0J/nIf2XrEApH8OwIeAvCVSwmPLeyB4KpP3iY4tS4DglKplH/b3Vg6RDC/HLy/puMbIGpLmm3GOQd/nlTygQp4P1tKrrBD+2IkbMIMLkRxrbC9NV1892XaZJVi+47Fxtf2W+MS3+f/VuCnN9JtIOkZIfMUoEZqHFoaMaigrbkSbcSVl2fIngCGuOyKuahdIy5LnQBmnymyYltQBYGmKUAqTsJma3Xtkm5YAeUP01fGZMBPRdvZY2vmnXnvFSXkLtvE+yQKx9sS2GughwxTQD/DKwUn0RAWo1FrleUsnzSEfc+Mhaqqpau5LoAgSR4jNjdYNRRk0ErmlazP4+Ct+Ch6QqdB/ruBXB/+yM5oCCjkt0zeKnpLxoanAL7+/tBQnJu26hYMY1QHUskHbZ04peUmJfGctORMK+v5C0/ELt+LkHg3TJN8TRyE6kYrcULlALWhJkneAv4WSTxzzVaiHY/Qjy4P44paSA0B9Fint/1IPkvDhAGd2bCQQl6Qf/bTsE2W5cKR73Cz+AdNcLaX5hikId/3wGlbRUsVvlOA4/v8wpnSKV3IIFpUPdi9/sC2Alq6bqfzZOjBdaPffIMa7q7kYAttDdYjYN5tMlKOmIqe9qj0cL70o/nHoJAapSAnyvjaoE7gfZ2qLvULsPl4f7eNsNYbkkFrTs+7P8g4nFkZ4HCqt4x4c7emdDjUM5Ev8Tr1mXbUuBcxOhoz3aLUqi3kMGkEV4Fs8WGO4nLqdx2vYyaiCPdLQn0w2XCVh7gV+t3IkcRrYW7lNDgtNzwZ83OShSOfeNIAHj0zr0pnzGrF8P0zvrDpSsACTVeTfKWFUnPELvHAlUR3lhzHuqH6USVZrB8waT8mjkQc3qs1sCyzQ1BIRbYm/2FyS5EBdzFW3/64GMBkIjh+JroWk5V6zKxQzqvGfdvjYMr0o+K6mN4P9UVmvqgNQ+vVozI88eC8HQgHsQB9cK8yhe+2Bcm1za8prc5INqGugOx/eFRWAnAFDlDbduBf3IyoEIqVhGfckUHRLSbW8KUNgiMIRnRCAPylX+gijf5MywKbt4Nqhl7R+CIWFrsIAylwhhdYzgSRmw4JTttmETZRNjGUiYIr9v8Ln4IissmkMindjwt2tx/59h0deMZENRefZ1rdCpcVa31DUJxS5VLyk=</script>
<script type="text/plain" id="jet-b6">U2FsdGVkX19K/cGfWZmvhtG7xAMcI3RqqcGxOQpgpO6BxyuUOyq6D+owyysn9AEF/EnxXataIgdBoOEl60RRrapV2JynxkgpOHZCIeV/D6xFSuDVGoiyogbKn5Nf5Jq4xO80TEEw8qBr8Aqk2tGgofethvjZn1/6BDktE/i0hXdRW9AYchXu0O/2H24Ky9w8t5B/iuDNkECqjtmtJLMVmbIay1B7oM6Ei6ew5RUgy+XOYG8tatGCjwoQbLUBkK+BskrA4NBsAEFW5u+qGSv8iK9o+gnz5cvPDxaqaYgSdUgRWImkWB88tuxbNQnMQd0VHj4DeTiMkyNjnZQ4htn50XoVC4i7owzLN4QqMeIpe/yS2tci34/es99gslyymM6PJ8ehMgdiaUqd09tyhXfsI8amzDkW6mEjtzdlex5roVatTWLKJ1tuPBChouvN6hqb8fscRaAM5JLpMAtjl3KOQo1iiEuk+GnscwZwSDuSSCpUSfKFT5EtIudbDzULtP5++iXlSxyLPSfEpv3Ll8aTx1Pvz1O44+vGVJCoUx7xWY7YvrNTe+EfEbqCfdtGufIX9Bc/wH27YDEMC0GHBJe0nUJsl8CUtIc083NM3CKZz27MJJkJ+ecIyHYCFctMmPCCwFfbW28cUD5eqJ1QawGFkdR658mGXlhpICYqbLEgu0RXG7vrKJ7CN5e2p7PSIVVUyp1tpwcS3PpsSqFvethpGNgF8MKP63V+ghFrix2Jn3RWK1RkE5Sf1cXID/3GOeLwo9AURBO1+UsedM49XbXAS+Rj/NPmOgL8o8+4VGSC+ZZ4aVHLzhwRldtDb9DHwPahMKqPPTvWiUrIyqlqoVnCovV1pR4VZaPGZc1/HbsL3E+nohTaLhl/X3ZppgRGrgFIL9bhwm/6wGv7l1hrqdxvMbIv6Lrj8dFtqs9EHVkh9l4E0k4FSnIp0L81xU94oPzeXtN+Sz3gS3aqMdLQGzMiwrlVK5JznMOjhPC0GARjBDxrfvo7iIvgowCjMBk6YGiw4rr3Le0KEd7YZC2OOAvQtgGatUUUGIySLz8hRHCsWoOH1EUfSMaW8waqtbqbRdkIvXqncDfwqrNRSJKSMPBFtKNhRM6h3Vnw4X2MTMnB/xNMKa3JFq7H0yhe7RlxGYMT1xWEL4tKzsnfic+1+vG8Uveq2LlI980ERgSluJHB0qh6w8cwMFpSMDtTa3oOxmzqBotxAvsidJm7a99qXF5SUSwGvHc3oqqxQLM7JfqcGV1qckOlmG2vv4Hr42Mm++gMFV6cy905SBdLSIeA7REk+wDKj1qS7aS9TxZSEWoTg070GH76GdS2KcVnB9ZT++w0FU2aTgaNUdDIwLkl1gD9xKcUCkouen4FEmvaGaJxF0UVNmHfvfBPbjc+MUwZvp+vq1Fr7hlqR7Zhc5TAHO5zWG16WwDk+z7HTC6+/XqpsZ1+sS8VIFOt2430O/N9U2iTqSTBUDODgHqzINjlq+iID2P+OQP/igzns9eDQyqq2+Lhahh5X0ZCzjApBcMK5mj1xf/2p8KuNo/p18H1aOg9NAH2oS8d0edAJMmTFgNTIU4MpfLmU8FkzrIt2fvnGJq38WiEfxdlI6ofxp5kVWOrvN4XB8ueA54uVDFxWhbYvyrnEPdXdFKMrfRk96wvh4Jvmk8LyqaEMnTsv29Cfakb3WwCFyB3LH18Qt3pyRRRO2fu0lN85qNbYCjoR161xw56XgPGrBPWSRGXkffRmvyu5Q==</script>
<script type="text/plain" id="jet-b7">U2FsdGVkX1+jkwN0VmhEt7kI7KpHlCKbC6F2nGgoWsthV3lkTKNaR6J8h1FsktdNyLef0YZuGxdkEmpqqbDLS+Kr0UVxPVkVGfDJifKsBbYjhSS8GdfBlzAKA01OBEyZ+v3prse756yOlRwldkAIY8DPPMfM23wK+rE/kYpVQEETYCrsZts+zwozwJtNiLtO8Nr1Kqip5aYRs8RzBPEB96Uog5EHpN+3yGFs6pS/OUuuRQPatDplqvD2UdJZOsvDSEtQxAQ1eLncbQjEvl8UWohM2XgZpvqqUzwKs2tTEzpgw3lJhJoyMp3+x9VxRVM3JBE4MjIJrLHIRawgEKSZMrQXJz/iDln1Nk+u+EcXw6Cj7DE3QFfNticuIEWWdp3ea8hnJdfHeaZUdZPYF3FGpKKd4y7qQ8kG0l8k30TMpgB37XGxQQVS0ARyp2CaPNCzZIR6nAYQxY6JvlHT6AIjLVYHAMIYpBB+Bs58n5Gfd979xI/+2U/vZe8mBVbhYgNNr3FCgXnkuFEkOaEk1AR+ROrnyjlqdZ4FdNUp8mGJcZb5RWq5iuv2A53MmzGRl+bnVQXaDAeHWVhjm6gsQGHPvW2FZF1zLAGmlQgY/5nCpbiNggsjVpwdh4s1+KcvfchkWWzyAB3xnWfRp/IOoDdmL7DRgBUkxiyU7uOzt5lCyK06bo95ipE4xJH9wNHI5ZaVNeLLtYcuDGxBVUiIgy7ZpV7PvRMAXF/W1jMBFXxYHQw2HGa22ED3Ujm738n6v/ys0i8FqvF4glcOXzlP5OSLAxz0D+aQl9B43ODwNLeRXjBE8PFo3Hyy1QfEZ392WXDerXh8enEimYBKH7N2RFAaAa7SWblcVWiAH/ZIZ1OvaqZ8sOgb7kMebtf64EsbmrwMXB4qsNPMfktovmdui0mVI3KVfO6AviCiyTqBBtk4pLkeqiTgSUk8hR1zmQfbso/qvDAnv5FJDg/aZqPgiAWd2ZnXnsC7IQWqVVamtGSKDvKXLdJm4IIX9QlZPE32/YxghxqC/gv9hq3E6rmVDlkuO4nOIBRTNNw+BP3ML/mUyrzl3XzV3wzuNNWdluXJQanwjR8ioOpaGUgK4EUxy2f79lYmBWNmEuAkgvZOzNmMKbae5jvWkcW0q8oTDdqIFUTfhf5aNYzgilktKR7ogVjzTmxXrBQ7xGwzjQnJiMq8/qU=</script>
<script type="text/plain" id="jet-b8">U2FsdGVkX19bx8Ua0qlic7tFeT3F41+tYZNJhiy3dkXUBAJ7RuvnPh9aht7InLkXi7YlkbhUQuy63350S7XCSIbYaGvdi/bmjpm1CjYuwiAzL7tlt6wyY8gVvbGS2CCKFKNwGRE9PFxtm8IYIMuf1hKNMR4iuTynXDyojeqmR537UwL8KD4mo8nU2N2WQFQO0dev42hWGrstC6rTgduL1WOif7dK2Y1xR2446yl4t6LrG/BZkgWBG3sk1bKFt0xrc8MZFXL2vybCtM2wfatAiRbDWgRxafrV3MpBMwmhN/fCXFnc2IlLbV+BGEXioc9bqwRIETZbT/Fq+Ah6ue4OAJfizzPVUT1XVNBtSQaVJTn2tygBgb+oxS2hnGz2P+meCZ8qgolquCw3P57QKRBUM77RrIxnxVZ9tPtbmEcpZvfI1uXQpiw2X3Ng2U+LeTqHmOZGaECH7zub61pPOi8bXalPYbQjWJb9oHB7rPG5TcHcHCQepKioDP32Jy5G75r2omn5nJpGnXRPVxny1yY6tTwXAsCeXi8Dpih0jVBF501wTdHFwxp6MOWCwgoG7iF+vXETnJSo6pS1VguD+3SaXI11InPK2rR9pIHS0NWEuSLV47Ik/kv/62oYCtfDZOwohsnb1it6t0sjzlSC1nUr3UP9kopTV5hzxsmuYpCZvZJ0mBcOuijMiB4kJiT+TkT/Y2ws78NOMeXNCQbUnRbEPnBFtzJrE+IpD/vzsBofJ01446zC+q+Q33wTJZP/oUikVHK5L66PU0qH3yI/NSYi2Shr9PYQS3ov+sbaHdtcAphuFPPYGfFUKRiJ2dOqhy9aRTM/lurBxt+HOlZvFrj7YQ==</script>
<script type="text/plain" id="jet-b9">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</script>
<script type="text/plain" id="jet-b10">U2FsdGVkX18oaJ1DCsspMup/0RrPwvQGJt/Ychx0HaKBPlk4Msn5wv7uJggGxcU1VqVaGUFt6UraABsSEYsDdJSFdjhEVXV3gJP1IG7fwb3hDeT2Tzc+Vh5hI5TZpAp4CpDWbHmmcwfXcvEDE/ynMqYXbN3bgt+RNBuFEmdax1bTjeZOu+c57YgTHvEtI4jEAM/naxkwHg/A/RxAKtdgoMA/PdnCNSyjNFkAa8qI7C59/i+MN49NPFPcoBWz6tsqYWmxidywMuix+zYRcADyuNiGw8Im0NHL/9BnABtwG68DrP3eOHzqUdrC+JvaJ25Ea7fqQtvkbH36cg/4jMiXM2mO6eiUOWZ52Vu1nvwYUPPTsmG7MwTo/Hr9oXIPgo7tBq81rGUGm9xXuj9a2hJYGm7omcNlH+3dP2pb0IWTi2XrNPgHJhnX8lX3wAZjzb6hJC/R3N3xHm+euYTEj1V1NTmR7hAx3PTVRYgVAJ7txDKy+Bz5a5z8YtAUmEhT/RU8dd2mTPvxSrjgJpPvNmMyPDOagFRiepUd9jSYwzRGVTd4Vb0UFFsQaZ4JlTmWycvD1qsa+6E6QrcoT1SEowQIevXNy7KZHH6LMrtfgHIk7OOyndnukEiyq188ffLO2qU0vJPS7uE3wouSh0FAu/OaeoMCcf9NFp4/P+LTocZNCMFzEwup3N2gfxZ1Xd+kff38/vJV5eAQcDcZURLggI7AoYLgFhkKVN4enWDxcMcblah/VhBiJMUeDFIJNkxy/oR/NJf1icnIxUoZ2T+A1HfoQWlZFeW63KEfBViCOANDPdKhhmeiatgy9hilEsTDaEFkY/DwyOM/6uIRcBNMPWbaImeB5TNISvJSQUtmxzuNyH/b1ML7UogIn0SFPn/0+nMYU3WFsXa1B5LA+fTuCwEheUVJPkM9XQcs1dsfJSkcDrod+cXZWSTw1hTD6ALQyzbh0RADNrCwvr352Ly7uzmIXJSyX055lKvbCuY5yptvLI1MvPDhBVrWqVvqcoAmG+i39Fl6xmjU0oumitRg8AMELgcOBnjg1TFr2+j4RHhkmOe9eId4cwNK0N2+lTrJyqrVpZPozhUBtpvimqBhlOsPSsPleNpI+lKu2g8jkAWDX9BqG4ZjkgJg/xl6Fqxlzu9+OL7bfpzJE59iDH3w7Dzyd5pfTe3sjAs9xyUz9Xn0xagD+iHyrX+rrCIx2RNaGnCmtKjYHjK+0XRY4kapaNuJgB37z/YTTwxX78iBXp7BUpH46hF67kKd/ZzBtDVceRNlslOg6gRKjmm+u/Yxez6Uri0hJ5gxG1prSoITysniEIrxalqlbkz7X3kR87Nrk3LB1NDLprrA6KYpx/IT+R2PTamWub5sbTBWxI20QHw/Ia+yMvrlCGW638NJrnCBFl4RE8HGxqfdlz8WSLRRL02itA==</script>
<script type="text/plain" id="jet-b11">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</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
<script>
(function(){
  var N=11;
  var blobs=[]; for(var i=1;i<=N;i++){var e=document.getElementById('jet-b'+i);blobs.push(e?e.textContent.trim():'');}
  var NAMES=["Connect","Digging in","Going Deeper","Bypassing Authentication","Command","Overflown","Secret Message","Elasticity","Member Manager","More Secrets","Memo"];
  var inp=document.getElementById('jet-flag'),btn=document.getElementById('jet-go'),st=document.getElementById('jet-status');
  var host=document.getElementById('jet-sections'),lock=document.getElementById('jet-lockmsg'),prog=document.getElementById('jet-prog');
  var pips=[]; for(var k=0;k<N;k++){var p=document.createElement('span');p.className='jet-pip';prog.appendChild(p);pips.push(p);}
  function dec(blob,key){try{var w=CryptoJS.AES.decrypt(blob,key);var t=w.toString(CryptoJS.enc.Utf8);return t||null;}catch(e){return null;}}
  function norm(v){return (v||'').trim().replace(/^JET\{/i,'').replace(/^flag\{/i,'').replace(/^HTB\{/i,'').replace(/\}$/,'').trim();}
  // decrypt blob i (0-based) with a raw flag; return {html, prev} or null
  function open1(i,flag){
    var t=dec(blobs[i],flag); if(!t||t.indexOf('OK::')!==0) return null;
    var m=t.match(/^OK::PREV=([^:]*)::/); var prev=m?m[1]:'';
    var html=t.replace(/^OK::PREV=[^:]*::/,'');
    return {html:html,prev:prev};
  }
  function reveal(){
    var raw=norm(inp.value);
    if(!raw){st.textContent='';return;}
    // full form the flags carry the JET{...} wrapper as the AES key, try both raw-inner and wrapped
    var candidates=[ 'JET{'+raw+'}', raw ];
    var matched=-1, key=null;
    outer:
    for(var c=0;c<candidates.length;c++){
      for(var i=N-1;i>=0;i--){ if(open1(i,candidates[c])){matched=i;key=candidates[c];break outer;} }
    }
    if(matched<0){ st.className='jet-bad'; st.textContent='[-] not a Jet flag.'; return; }
    // cascade down from matched using embedded PREV flags
    var parts=[]; var i=matched; var k=key;
    while(i>=0){
      var o=open1(i,k); if(!o) break;
      parts.push({i:i,html:o.html});
      if(!o.prev) break; k=o.prev; i=i-1;
    }
    parts.sort(function(a,b){return a.i-b.i;});
    var out='';
    for(var j=0;j<parts.length;j++){ out+='<section class="jet-tier">'+parts[j].html+'</section>'; }
    host.innerHTML=out;
    for(var z=0;z<N;z++){ pips[z].className='jet-pip'+(z<=matched?' on':''); }
    var count=matched+1;
    st.className='jet-ok';
    st.textContent='[+] '+NAMES[matched]+' accepted. '+count+' / '+N+' checkpoints unsealed.';
    if(count<N){ lock.hidden=false; lock.textContent=(N-count)+' checkpoint'+((N-count>1)?'s':'')+' still sealed. A higher flag reveals more.'; }
    else { lock.hidden=false; lock.className='jet-locked jet-ok'; lock.textContent='every checkpoint unsealed. gg.'; }
    if(host.firstChild){ window.scrollTo({top:host.offsetTop-40,behavior:'smooth'}); }
    // let mermaid render any diagrams inside revealed sections (none by default, but safe)
    if(window.mermaid){try{window.mermaid.run({querySelector:'.jet-tier .mermaid'});}catch(e){}}
  }
  btn.addEventListener('click',reveal);
  inp.addEventListener('keydown',function(e){if(e.key==='Enter')reveal();});
})();

</script>
