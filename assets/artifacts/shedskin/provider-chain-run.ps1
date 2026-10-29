$ErrorActionPreference = 'Stop'
if (-not ('W.A' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace W {
  public static class A {
    [DllImport("amsi")] public static extern int AmsiInitialize(string an, out IntPtr ctx);
    [DllImport("amsi")] public static extern int AmsiScanBuffer(IntPtr ctx, byte[] b, uint n, string cn, IntPtr s, out int r);
    [DllImport("amsi")] public static extern int AmsiUninitialize(IntPtr ctx);
  }
}
'@ -Language CSharp
}
function Scan([string]$label, [byte[]]$bytes) {
    $ctx = [IntPtr]::Zero
    [void][W.A]::AmsiInitialize("ch-$label", [ref]$ctx)
    $r = 0
    [void][W.A]::AmsiScanBuffer($ctx, $bytes, [uint32]$bytes.Length, $label, [IntPtr]::Zero, [ref]$r)
    [void][W.A]::AmsiUninitialize($ctx)
    "{0,-24} result={1}" -f $label, $r
}
# Payload bytes as integer sequences so the script source carries no detectable literal.
# marker, mimikatz, eicar, mix constructed at runtime.
$M  = @(65,77,83,73,45,83,73,76,69,78,84,45,65,76,76,79,87,45,77,65,82,75,69,82,45,55,98,99,50,101,49,51,97)
$MK = @(102,117,110,99,116,105,111,110,32,73,110,118,111,107,101,45,77,105,109,105,107,97,116,122,32,123,32,34,115,101,107,117,114,108,115,97,58,58,108,111,103,111,110,112,97,115,115,119,111,114,100,115,34,32,125)
$E  = @(88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42)
$marker   = [byte[]]$M
$mimikatz = [byte[]]$MK
$eicar    = [byte[]]$E
$mix      = $mimikatz + [byte[]](10) + $marker

"=== oracle ctrl_start (EICAR, expect 32768) ==="
Scan 'ctrl_start' $eicar
"=== arm A: Mimikatz-known content ALONE ==="
Scan 'A_mimikatz_alone' $mimikatz
"=== arm B: marker ALONE ==="
Scan 'B_marker_alone' $marker
"=== arm C: Mimikatz + marker, same buffer ==="
Scan 'C_mimi_plus_marker' $mix
"=== oracle ctrl_end (EICAR, expect 32768) ==="
Scan 'ctrl_end' $eicar

"sig   : $((Get-MpComputerStatus).AntivirusSignatureVersion)"
"engine: $((Get-MpComputerStatus).AMEngineVersion)"
"build : $((Get-CimInstance Win32_OperatingSystem).Version)"
"providers:"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' | ForEach-Object { "  " + $_.PSChildName + "  " + ($_.GetValue('')) }
