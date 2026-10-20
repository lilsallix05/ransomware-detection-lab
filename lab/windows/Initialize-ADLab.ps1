#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][ValidateSet('DomainController','Member')][string]$Role,
      [ValidateSet('DC01','WS01','WS02')][string]$ComputerName,
      [string]$DomainName='ad.selbi.test',
      [switch]$IsolatedLab)
$ErrorActionPreference='Stop'
if (-not $IsolatedLab -or -not (Test-Path 'C:\SelbiLab\LAB-ONLY')) { throw 'Isolated VM and LAB-ONLY marker required.' }
if ($DomainName -ne 'ad.selbi.test') { throw 'This template only provisions the dedicated ad.selbi.test domain.' }
if (-not $ComputerName) { throw 'Choose DC01, WS01 or WS02 explicitly.' }
if ($Role -eq 'DomainController' -and $ComputerName -ne 'DC01') { throw 'Domain controller name must be DC01.' }
if ($Role -eq 'Member' -and $ComputerName -eq 'DC01') { throw 'Member name must be WS01 or WS02.' }
if ($env:COMPUTERNAME -ne $ComputerName) { throw "Rename-Computer to $ComputerName and reboot first. No other changes made." }
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'This VM already belongs to a domain.' }
if ($PSCmdlet.ShouldProcess($ComputerName,"Initialize $Role for isolated $DomainName domain")) {
    if ($Role -eq 'DomainController') {
        $password=Read-Host 'New directory services restore mode password' -AsSecureString
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
        Import-Module ADDSDeployment
        Install-ADDSForest -DomainName $DomainName -DomainNetbiosName 'SELBI' -InstallDns -SafeModeAdministratorPassword $password -NoRebootOnCompletion:$true
        Write-Output 'Review success and reboot DC01 manually before joining endpoints.'
    } else {
        $credential=Get-Credential -Message 'Use the isolated SELBI domain administrator'
        Add-Computer -DomainName $DomainName -Credential $credential
        Write-Output 'Review join result and reboot this endpoint manually.'
    }
}
