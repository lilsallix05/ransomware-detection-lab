[CmdletBinding()]
param([datetime]$StartTime=(Get-Date).AddHours(-1),[datetime]$EndTime=(Get-Date),
      [Parameter(Mandatory)][string]$OutputPath,[int]$MaxEventsPerChannel=50000)
$ErrorActionPreference='Stop'
if ($StartTime -ge $EndTime) { throw 'StartTime must precede EndTime' }
if (Test-Path $OutputPath) { throw 'Output already exists; choose a new evidence path.' }
$channels=@('Security','System','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')
$utf8=New-Object System.Text.UTF8Encoding($false)
$writer=New-Object System.IO.StreamWriter($OutputPath,$false,$utf8)
$manifest=@()
try {
    foreach ($channel in $channels) {
        try {
            $events=@(Get-WinEvent -FilterHashtable @{LogName=$channel;StartTime=$StartTime;EndTime=$EndTime} -MaxEvents $MaxEventsPerChannel -ErrorAction Stop)
            foreach ($event in $events) { $writer.WriteLine($event.ToXml()) }
            $manifest+=@{channel=$channel;records=$events.Count;possibly_truncated=($events.Count -eq $MaxEventsPerChannel);status='collected'}
        } catch { $manifest+=@{channel=$channel;status='failed-or-empty';error=$_.Exception.Message} }
    }
} finally { $writer.Dispose() }
@{computer=$env:COMPUTERNAME;start=$StartTime.ToUniversalTime().ToString('o');end=$EndTime.ToUniversalTime().ToString('o');channels=$manifest;sha256=(Get-FileHash $OutputPath -Algorithm SHA256).Hash;origin='windows-live-export'} | ConvertTo-Json -Depth 6 | Set-Content "$OutputPath.manifest.json"
Write-Output "Exported to $OutputPath; inspect manifest for missing channels or truncation."
