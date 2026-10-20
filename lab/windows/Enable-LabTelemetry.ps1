#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$SysmonPath,
      [string]$ConfigPath = "$PSScriptRoot\sysmon.xml",
      [string]$StateDir = 'C:\SelbiLab\state',
      [switch]$IsolatedLab)
$ErrorActionPreference='Stop'
if (-not $IsolatedLab -or -not (Test-Path 'C:\SelbiLab\LAB-ONLY')) { throw 'An isolated VM and C:\SelbiLab\LAB-ONLY marker are required.' }
if (Get-Service Sysmon* -ErrorAction SilentlyContinue) { throw 'Existing Sysmon detected. Review its config instead of overwriting it.' }
$signature=Get-AuthenticodeSignature $SysmonPath
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'Supply a valid Microsoft-signed Sysmon executable.' }
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Enable dedicated-lab telemetry and install Sysmon')) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    if (Test-Path "$StateDir\audit-before.csv") { throw 'Existing audit backup found; preserve it before a new run.' }
    & auditpol /backup /file:"$StateDir\audit-before.csv"
    if ($LASTEXITCODE -ne 0) { throw 'auditpol backup failed' }
    # English-language OS names; localized Windows must substitute localized names or approved GUIDs.
    foreach ($subcategory in @('Logon','Process Creation','Kerberos Service Ticket Operations','Detailed File Share')) {
        & auditpol /set /subcategory:$subcategory /success:enable /failure:enable
        if ($LASTEXITCODE -ne 0) { throw "Audit policy failed for $subcategory. Restore audit-before.csv before retrying." }
    }
    $reg='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (Test-Path $reg) { throw 'Existing ScriptBlockLogging policy found; manage through your GPO rather than overwrite.' }
    New-Item -Path $reg -Force | Out-Null
    New-ItemProperty -Path $reg -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 | Out-Null
    & $SysmonPath -accepteula -i $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw 'Sysmon install failed. Revert VM snapshot or follow rollback runbook.' }
    Get-Date -Format o | Set-Content "$StateDir\enabled-at.txt"
    Get-FileHash -Algorithm SHA256 $SysmonPath | ConvertTo-Json | Set-Content "$StateDir\sysmon-binary.json"
    & auditpol /get /category:* | Set-Content "$StateDir\audit-after.txt"
}
