---
layout: post
title: "HTB Fortress: Synacktiv"
subtitle: "seven flags, sealed. paste one and it unseals every checkpoint up to the one you hold."
date: 2023-05-24
tags: [htb, fortress, symfony, rce, java-rmi, deserialization, chacha20, squid, erlang, pwnkit]
category: writeups
kind: fortress
difficulty: Insane
os: Linux
tldr: "A locked fortress writeup. Paste any Synacktiv flag and it decrypts every checkpoint up to and including the one you own, in your browser, with the flag as the AES key. The chain: a leaking Symfony profiler to _fragment RCE, a Java-RMI CommonsCollections deserialization, a broken ChaCha20, an inner OpenVPN, a Squid CONNECT tunnel to SSH, a less jailbreak, an Erlang-cookie root, and a PwnKit domain escape."
---

<style>
.syn-hero{border:1px solid #1e1f14;border-radius:4px;background:#14150e;padding:1.15rem 1.25rem;margin:0 0 1.75rem}
.syn-hero .k{color:#767e22;font-size:.72rem;letter-spacing:.04em}
.syn-hero .t{color:#e2ddcd;font-size:1.5rem;font-weight:800;margin:.15rem 0 .3rem}
.syn-hero .t b{color:#b3bd33}
.syn-hero .m{color:#514f43;font-size:.78rem;line-height:1.7}
.syn-hero .m span{color:#989484}
.syn-sub2{color:#767e22;font-size:.72rem;letter-spacing:.06em;text-transform:uppercase;margin:1.4rem 0 .3rem}
.syn-kv{width:100%;border-collapse:collapse;margin:.4rem 0 1rem;font-size:.8rem}
.syn-kv td{border:0;padding:.18rem .6rem .18rem 0;color:#989484;vertical-align:top}
.syn-kv td:first-child{color:#767e22;white-space:nowrap;width:1%}
.syn-gate{border:1px solid #2e3020;border-radius:4px;background:#14150e;padding:1.15rem 1.25rem;margin:1.9rem 0}
.syn-gate h3{margin:0 0 .45rem;color:#e2ddcd;font-weight:700;font-size:1rem;border:0;padding:0}
.syn-gate h3::before{content:"> ";color:#767e22;font-weight:400}
.syn-gate .lead{margin:.2rem 0 0;color:#989484;font-size:.82rem;line-height:1.7}
.syn-gate .lead code{color:#b3bd33}
.syn-row{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.95rem}
.syn-row input{flex:1;min-width:230px;padding:.6rem .75rem;border-radius:3px;border:1px solid #2e3020;background:#0b0c07;color:#e2ddcd;font-family:inherit;font-size:.85rem}
.syn-row input:focus{outline:none;border-color:#767e22}
.syn-row button{padding:.6rem 1.2rem;border-radius:3px;border:1px solid #767e22;background:rgba(179,189,51,.07);color:#ccd45c;cursor:pointer;font-weight:700;font-family:inherit;font-size:.85rem}
.syn-row button:hover{background:rgba(179,189,51,.14)}
#syn-status{margin-top:.65rem;font-size:.8rem;min-height:1.1em;color:#514f43}
.syn-ok{color:#ccd45c!important;text-shadow:0 0 12px rgba(179,189,51,.35)}
.syn-bad{color:#c86a4a!important}
.syn-prog{display:flex;gap:.25rem;margin-top:.85rem;flex-wrap:wrap}
.syn-pip{width:20px;height:5px;border-radius:2px;background:#0b0c07;border:1px solid #2e3020}
.syn-pip.on{background:#767e22;border-color:#b3bd33}
.syn-locked{color:#514f43;font-size:.8rem;margin:1.5rem 0 0;border-top:1px dashed #1e1f14;padding-top:.85rem}
.syn-locked::before{content:"[ sealed ] ";color:#767e22}
.syn-tier{border-top:1px solid #1e1f14;margin-top:2rem;padding-top:.3rem}
.syn-tier:first-child{border-top:0;margin-top:.5rem}
.syn-sub{color:#767e22;font-size:.72rem;letter-spacing:.06em;text-transform:uppercase;margin:1.2rem 0 .5rem;font-weight:700}
.syn-code{background:#0b0c07;border:1px solid #1e1f14;border-radius:4px;padding:.7rem .85rem;overflow-x:auto;font-size:.78rem;line-height:1.55;color:#b8b29d;white-space:pre;margin:.6rem 0}
.syn-flag{margin:1.1rem 0 .3rem;padding:.5rem .75rem;border:1px dashed #767e22;border-radius:3px;color:#ccd45c;font-size:.82rem;background:#0e0f09;word-break:break-all}
.syn-flag::before{content:"flag  ";color:#514f43}
.syn-fig{margin:1.5rem 0;border:1px solid #1e1f14;border-radius:6px;overflow:hidden;background:#0b0c07}
.syn-fig img{display:block;width:100%;height:auto;border-bottom:1px solid #1e1f14}
.syn-fig figcaption{padding:.55rem .85rem;color:#514f43;font-size:.76rem;line-height:1.55}
.syn-fig figcaption b{color:#767e22;font-weight:700}
.syn-note{background:#14150e;border:1px solid #1e1f14;border-left:3px solid #b3bd33;border-radius:0 4px 4px 0;padding:.8rem 1rem;margin:1.4rem 0;color:#989484;font-size:.82rem;line-height:1.7}
.syn-note b{color:#e2ddcd}
.syn-fin{margin-top:1.3rem;color:#ccd45c;font-style:italic}
.syn-step{color:#e2ddcd;font-size:1.03rem;font-weight:700;margin:1.7rem 0 .55rem;border-bottom:1px solid #1e1f14;padding-bottom:.32rem;letter-spacing:.01em}
.syn-step::before{content:"# ";color:#767e22}
.syn-code .p{color:#767e22}
.syn-tier .syn-code .gp{color:#8AE234;font-weight:600}
.syn-tier p{line-height:1.72}
.syn-tier code{color:#b3bd33}
</style>

<div class="syn-sub2">box info</div>
<table class="syn-kv">
<tr><td>target</td><td>10.13.37.13 (fortress, fixed IP), vhosts hackfail.htb + dev.hackfail.htb</td></tr>
<tr><td>entry</td><td>Symfony 5.2.3 profiler &rarr; APP_SECRET &rarr; _fragment RCE (www-data)</td></tr>
<tr><td>pivots</td><td>www-data@blog, monitoring@watcher (RMI), elonmusk inner VPN, network_admin@core01</td></tr>
<tr><td>final</td><td>core01: Squid CONNECT &rarr; SSH &rarr; less &rarr; Erlang cookie (root) &rarr; PwnKit</td></tr>
<tr><td>trap</td><td>double-VPN MTU black hole (tun0 1300 / tun1 1100); a Squid that is a TCP tunnel, not a web gateway</td></tr>
</table>

<div class="syn-sub2">// the chain, end to end</div>

```mermaid
flowchart TD
  A[dev vhost: Symfony profiler] --> B[APP_SECRET + arbitrary read: flag1 via /download]
  B --> C[signed _fragment: RCE www-data]
  C --> D[chisel SOCKS: RMI 1099 monitoring]
  D --> E[CommonsCollections6 deser: flag2 as monitoring]
  C --> F[loot APK + broken ChaCha20: flag3 = app password]
  F --> G[TOTP seed + elonmusk cert: inner OpenVPN]
  G --> H[Squid 4.6 on core01]
  H --> I[CONNECT core01.local:22: SSH network_admin: flag4]
  I --> J[changeLog -> less :e / !: flag5 + shell]
  J --> K[admin_backup leaks .erlang.cookie]
  K --> L[Erlang os:cmd as root: flag6]
  L --> M[SUID pkexec CVE-2021-4034: flag7]
```

<div class="syn-gate">
  <h3>unseal</h3>
  <p class="lead">Paste any Synacktiv flag. Braces optional, <code>SYNACKTIV{...}</code> or the inner text both work. Each flag reveals its checkpoint and every one before it. Nothing leaves your browser, the flag is the AES key.</p>
  <div class="syn-row">
    <input id="syn-flag" type="text" placeholder="paste a SYNACKTIV{...} flag" autocomplete="off" spellcheck="false">
    <button id="syn-go">unseal</button>
  </div>
  <div id="syn-status"></div>
  <div class="syn-prog" id="syn-prog" aria-hidden="true"></div>
</div>

<div id="syn-sections"></div>
<div id="syn-lockmsg" class="syn-locked" hidden></div>

<script type="text/plain" id="syn-b0">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</script>
<script type="text/plain" id="syn-b1">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</script>
<script type="text/plain" id="syn-b2">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</script>
<script type="text/plain" id="syn-b3">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</script>
<script type="text/plain" id="syn-b4">U2FsdGVkX1/OV9XebVQK6NBIeD9L1ioGK+wznMhIi6YBmme15Q1ASdmhBfv6qrM4ZWygr3m66erjCBuaWTNQg3IIj1Gdq4vLX+mjesYMxOl5JYvGNESVWLN8EIEGKe/Uyr+D2r2uooCmvewpyIMjZfL37eN3ojD7IqWeKwY/bDRdhNrX10D7s2lTYIvDgoU19r8sN/kPEbT9vMwBsmzpisSjwgFEdYCmJpucvnPifoRV6TJfCGT7ttJl+zJdqqhImCNabNXWnmUtj1SDKBfvZNNZNFsOr3dPuqqna9WGpOpavuuDwoFvWIXCfzV5Oiw4XNe5mPlPHJV06dDcJgpNgDJp57QaV+ujUHauwyIGRfAlKLjxiRmDnTWYbf5prXZ9grRx/v/MJhJUrMAquMBD0TgxiZdhE2sa1lqgBOC7n6j467cKPq8PDfhePWXg+KCFs/IHJlGW/IuV1W6o+eHy+yS9h6XgSchir4PfL115tUNANzoXVVnlNzM4RyfLGdnCVq0gl/mreoa6e/+i1jfGcME3+kIOFEUC7gL78Lt74q63tSzbNJySKsKCH4haAnwiPlBHhX7IrPQ9QZx6ZdQMIZxuD6TecHTL11k7c4K6WwNfd5URIMo6x2gC4kjN+AQQD5cxNFyxA1WaPuTz1/IVkNU6tiQxba1HJLXNUDHESyOLKvtVeNzSKzlPXB1jdDy91mWJGgY5YPlep+FyD4gZDRcbg/o3uee+UBWboO01+ghysb6UMfPiJlPswK4DEXSZ6lGDwN6lMMME47rghSAmA/wUwP74TVfT4prcT4aTcNXNG4LVzSkkLIalaj7BkGcHxOOO6Dpn3r/XfKbyChsWOi+/NDDik9Vsqe+2v43eWdg7p//6mCWo6GcVB9r2sWC8SxurVOfi+1Qm3Te1V6z/ku0uamPfnbzEAjyFVZ36B1U9V9RvpRnrAr/9V4XIa7k7hYstgMQckcXWgEsKob8X5A52U9GJCc8Pc2Cm/78csMfeJvogCufvBYVGiY3taVf4l49V2W2KggcWsFjP+dDqQgt0Yy6X7/H+OtZLqW4imJ5nGI/L95hk3nEJU0nVLZNQeDTW3VTuNOgP8sX+PNoCWWEnHWn6hmCBVlAAXTbCTGKnhFnuBm9ZjPc2PX0sDA+5J6Wc8xag/xgfU7+8cM1WkF3+gSmvbV5G76mEIXoLfWuy6gJ8eo/uZjW5QbgJO5y8HoY2mKu3LYOxxlYUq36RU5vpGJ35m1C0W5nwuzKJIEkpHjO7ngXPfItMGT+JA1JjyyWNGaKzPC8bp55xQo+l7wsefrHNoSWwtC0P1M7Alf/zm0TrTb4yJUiTFV8z08VHVj8r0OdZdreVtRUTGXaGhuV/pT0dYztc7HYKvEghuVi3bTiX00jgmjvmycF56A1XhOYB1a9b3z9apxCorAjn9QACslt6wr9b7IE4lQ5Ki8nZhenXhGNCm6rCxa71Lm5jIt8IhD6mYE/5TX5fqRfGM6BzIVZnktsnTQFCAosDeLN3WAjsrGYVMnBUSLGKHYiDlftuGw/NBVTSjxxW5zIOxigfLtdDWxsTbScju8QrSnEGiO14f+E5aUCm7ySWWD1Mivt0VaczZntRErtjB89LWn2rx0JOw4Ggg8rzhUB2MEGZUJ8e+CCW10SIDn1I8XvXHYGFUCcbklE+RTs5K5KysZR7sHswb5nacZ2zurE/MmlQIqJpGdXd7qzB8CCl41kOcGCDwiC4Ri3xyrO5nW58wezbkFd21MCUEzN4e4W0CWa2M7byLuu/a2zbHO49J+5kyeG2DMjprlZBS/d9v2jZtwThdcqkajg1ePAtrlCFAh0=</script>
<script type="text/plain" id="syn-b5">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</script>
<script type="text/plain" id="syn-b6">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</script>

<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
<script>
(function(){
  var N=7;
  var blobs=[]; for(var i=0;i<N;i++){var e=document.getElementById('syn-b'+i);blobs.push(e?e.textContent.trim():'');}
  var NAMES=["Fragments","Monitor my gadgets","Cryptofail","Spongebob's neighbour","I want to break free","Muppets love'em","The HTB redemption"];
  var inp=document.getElementById('syn-flag'),btn=document.getElementById('syn-go'),st=document.getElementById('syn-status');
  var host=document.getElementById('syn-sections'),lock=document.getElementById('syn-lockmsg'),prog=document.getElementById('syn-prog');
  var pips=[]; for(var k=0;k<N;k++){var p=document.createElement('span');p.className='syn-pip';prog.appendChild(p);pips.push(p);}
  function dec(blob,key){try{var w=CryptoJS.AES.decrypt(blob,key);var t=w.toString(CryptoJS.enc.Utf8);return t||null;}catch(e){return null;}}
  function norm(v){return (v||'').trim().replace(/^SYNACKTIV\{/i,'').replace(/^flag\{/i,'').replace(/^HTB\{/i,'').replace(/\}$/,'').trim();}
  function open1(i,flag){
    var t=dec(blobs[i],flag); if(!t||t.indexOf('OK::')!==0) return null;
    var m=t.match(/^OK::PREV=([^:]*)::/); var prev=m?m[1]:'';
    var html=t.replace(/^OK::PREV=[^:]*::/,'');
    return {html:html,prev:prev};
  }
  function reveal(){
    var raw=norm(inp.value);
    if(!raw){st.textContent='';return;}
    var candidates=['SYNACKTIV{'+raw+'}', raw];
    var matched=-1,key=null;
    outer:
    for(var c=0;c<candidates.length;c++){
      for(var i=N-1;i>=0;i--){ if(open1(i,candidates[c])){matched=i;key=candidates[c];break outer;} }
    }
    if(matched<0){ st.className='syn-bad'; st.textContent='[-] not a Synacktiv flag.'; return; }
    var parts=[]; var i=matched; var k=key;
    while(i>=0){ var o=open1(i,k); if(!o) break; parts.push({i:i,html:o.html}); if(!o.prev) break; k=o.prev; i=i-1; }
    parts.sort(function(a,b){return a.i-b.i;});
    var out=''; for(var j=0;j<parts.length;j++){ out+='<section class="syn-tier">'+parts[j].html+'</section>'; }
    host.innerHTML=out;
    for(var z=0;z<N;z++){ pips[z].className='syn-pip'+(z<=matched?' on':''); }
    var count=matched+1;
    st.className='syn-ok';
    st.textContent='[+] '+NAMES[matched]+' accepted. '+count+' / '+N+' checkpoints unsealed.';
    if(count<N){ lock.hidden=false; lock.textContent=(N-count)+' checkpoint'+((N-count>1)?'s':'')+' still sealed. A higher flag reveals more.'; }
    else { lock.hidden=false; lock.className='syn-locked syn-ok'; lock.textContent='every checkpoint unsealed. gg.'; }
    if(host.firstChild){ window.scrollTo({top:host.offsetTop-40,behavior:'smooth'}); }
    if(window.mermaid){try{window.mermaid.run({querySelector:'.syn-tier .mermaid'});}catch(e){}}
  }
  btn.addEventListener('click',reveal);
  inp.addEventListener('keydown',function(e){if(e.key==='Enter')reveal();});
})();
</script>
