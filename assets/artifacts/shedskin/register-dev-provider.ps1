# register-dev-provider.ps1
# Register the iter19 lab AMSI dev provider under HKLM. Reversible by
# running with -Unregister. Must run elevated (qemu-guest-agent is SYSTEM
# so winrun.sh satisfies this).

param([switch]$Unregister)

$ErrorActionPreference = 'Stop'
$clsid = '{A1B19999-DEAD-BEEF-CAFE-000000001234}'
$dllPath = 'C:\lab\amb-iter19\AmsiDevProvider.dll'
$classesCLSID = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
$amsiProv    = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$clsid"

if ($Unregister) {
    Remove-Item -Path $classesCLSID -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $amsiProv    -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "UNREG ok"
    exit
}

if (-not (Test-Path $dllPath)) {
    throw "DLL missing: $dllPath"
}

# InprocServer32 subkey points at the DLL
New-Item -Path $classesCLSID -Force | Out-Null
Set-ItemProperty -Path $classesCLSID -Name '(default)' -Value 'AmsiDevProvider iter19'
New-Item -Path "$classesCLSID\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "$classesCLSID\InprocServer32" -Name '(default)' -Value $dllPath
Set-ItemProperty -Path "$classesCLSID\InprocServer32" -Name 'ThreadingModel' -Value 'Both'

# Register as AMSI provider
New-Item -Path $amsiProv -Force | Out-Null
Set-ItemProperty -Path $amsiProv -Name '(default)' -Value 'AmsiDevProvider iter19'

Write-Host "REG ok clsid=$clsid dll=$dllPath"
