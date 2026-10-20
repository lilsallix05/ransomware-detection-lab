#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][ValidatePattern('^S-1-5-21-\d+-\d+-\d+-\d+$')][string]$LabSourcesGroupSid,[switch]$IsolatedLab)
$ErrorActionPreference='Stop'
if (-not $IsolatedLab -or -not (Test-Path 'C:\SelbiLab\LAB-ONLY')) { throw 'Dedicated collector VM marker and IsolatedLab required' }
$xml=Get-Content "$PSScriptRoot\wef-subscription.xml" -Raw
$xml=$xml.Replace('__LAB_GROUP_SID__',$LabSourcesGroupSid)
$path=Join-Path $env:TEMP ('SelbiWEF-'+[guid]::NewGuid()+'.xml')
$xml | Set-Content $path -Encoding UTF8
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Initialize Windows Event Collector and create Selbi-Lab subscription')) {
    & wecutil qc /q
    if ($LASTEXITCODE -ne 0) { throw 'WEC initialization failed' }
    & wecutil cs $path
    if ($LASTEXITCODE -ne 0) { throw 'Subscription creation failed. Existing subscription is not overwritten.' }
    & wecutil gr Selbi-Lab
}
Write-Output "Review generated subscription: $path"
