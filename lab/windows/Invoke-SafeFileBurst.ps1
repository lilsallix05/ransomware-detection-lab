[CmdletBinding()]
param([switch]$IsolatedLab)
$ErrorActionPreference='Stop'
if (-not $IsolatedLab -or -not (Test-Path 'C:\SelbiLab\LAB-ONLY')) { throw 'Dedicated lab VM and LAB-ONLY marker required.' }
# Creates new plain-text samples in a unique temporary directory only.
# No encryption, deletion, shadow-copy change, Defender change or privilege operation.
$run=Join-Path $env:TEMP ('SelbiSynthetic-' + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $run | Out-Null
for ($i=1;$i -le 24;$i++) {
    $file=Join-Path $run ('sample-{0:d2}.locked' -f $i)
    [System.IO.File]::WriteAllText($file, "SYNTHETIC TEST — harmless plaintext file $i; no encryption was performed.")
    Start-Sleep -Milliseconds 500
}
[System.IO.File]::WriteAllText((Join-Path $run 'HOW_TO_DECRYPT.txt'),'SYNTHETIC TEST NOTE — no files encrypted.')
Write-Output "Created 25 harmless test files in $run. Export Sysmon Event 11 and replay it. Cleanup is manual after evidence capture."
