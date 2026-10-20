# Windows AD lab and telemetry path

This path is implemented as scripts/configuration and has **not been executed on Windows** in the build environment. macOS cannot prove Sysmon installation, domain joins, event forwarding or collection fidelity. Use licensed/evaluation VM images and confirm current license terms. No cloud resources are needed.

## Topology

| VM | Role | Host-only address | Suggested starting RAM |
|---|---|---|---|
| DC01 | Windows Server AD DS/DNS + lab WEC | 10.77.10.10 | 4 GiB |
| WS01 | Windows Pro/Enterprise endpoint | 10.77.10.20 | 4 GiB |
| WS02 | Windows Pro/Enterprise endpoint | 10.77.10.21 | 4 GiB |
| LAB-LINUX | Ubuntu replay and SIEM collector; reserved emulation host | 10.77.10.30 | 4–8 GiB |

Use a private host-only switch, no bridge to a business network and no port forwarding. Temporarily add a NAT adapter only for OS updates and approved software downloads, then remove it before the exercise. Set DC01 as the endpoint DNS server, keep VM clocks synchronized, and take a clean snapshot of each VM. These are planning values, not measured resource needs. Linux needs no offensive tooling for this safe exercise.

## Domain setup

On each fresh VM create `C:\SelbiLab\LAB-ONLY` deliberately. Rename the VM to its designated name and reboot. Configure the host-only addresses above in the hypervisor/Windows networking UI; no script changes the physical network. On DC01:

```powershell
.\Initialize-ADLab.ps1 -Role DomainController -ComputerName DC01 -IsolatedLab -WhatIf
.\Initialize-ADLab.ps1 -Role DomainController -ComputerName DC01 -IsolatedLab
```

The script prompts for a secure DSRM password and provisions only `ad.selbi.test`. It does not store credentials or reboot automatically. Reboot after reviewing the output. On WS01 and WS02 run `-Role Member -ComputerName WS01` or `WS02`; supply credentials for this isolated domain only, then reboot. This template rejects machines already joined to a domain.

Create non-production users `analyst` and `approved_admin`, plus a group `SelbiLabSources` containing the three VM computer accounts. Avoid real credentials. Do not configure RC4 or weaken Defender merely to make a detector fire; use synthetic/public records for those cases.

## Sysmon and audit setup

Download Sysmon from Microsoft's official site yourself, verify its Microsoft signature, and inspect the supplied XML. Execute `Sysmon64.exe -s` first and confirm schema `4.90` support against the installed binary. The pack enables process creation, LSASS ProcessAccess, and explicitly listed impact file names. This intentionally focused file scope cannot measure generic encryption or all file changes.

```powershell
.\Enable-LabTelemetry.ps1 -SysmonPath C:\Tools\Sysmon64.exe -IsolatedLab -WhatIf
.\Enable-LabTelemetry.ps1 -SysmonPath C:\Tools\Sysmon64.exe -IsolatedLab
```

Run on all Windows VMs. The script refuses to overwrite an existing Sysmon service or existing PowerShell logging policy, backs up audit policy, enables relevant audit subcategories, and turns on script-block logging. Audit subcategory names assume an English Windows installation. Event 4769 is generated on DC01; collecting only endpoint Security logs leaves Kerberoasting invisible. Process access may be noisy and should be tested for performance.

## WEF

On DC01 obtain the SID for the dedicated source group:

```powershell
(Get-ADGroup SelbiLabSources).SID.Value
.\New-LabWefSubscription.ps1 -LabSourcesGroupSid S-1-5-21-REPLACE-WITH-LAB-SID -IsolatedLab -WhatIf
```

Replace the placeholder with the actual group SID, then run without `-WhatIf`. The script validates the SID format; the literal example is intentionally invalid. In a GPO linked only to the lab computer OU configure **Windows Components → Event Forwarding → Configure target Subscription Manager** as `Server=http://DC01.ad.selbi.test:5985/wsman/SubscriptionManager/WEC,Refresh=60`. Enable WinRM for these domain-only machines; restrict the firewall to the three lab source addresses. Add `NETWORK SERVICE` to the source machines' local **Event Log Readers** group as required to read Security events. Review channel ACLs if Sysmon forwarding fails. Kerberos domain authentication protects the transport payload; do not enable Basic auth or TrustedHosts wildcards. For a non-domain collector use a separately configured HTTPS/certificate design.

Check `wecutil gr Selbi-Lab`, `ForwardedEvents`, and source `Microsoft-Windows-Eventlog-ForwardingPlugin/Operational`. A created subscription without events is a failed collection check, not success. See the [Microsoft WEF guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection).

## Safe local exercise and export

`Invoke-SafeFileBurst.ps1 -IsolatedLab` creates 24 new `.locked` plaintext files and one unmistakably synthetic note in a unique temporary directory. It never encrypts, deletes or changes existing files. Sysmon should produce Event 11 records. Running this script was **not** part of the macOS build verification.

```powershell
.\Invoke-SafeFileBurst.ps1 -IsolatedLab
.\Export-LabTelemetry.ps1 -OutputPath C:\SelbiLab\capture-001.xml
```

The export script reads the four source channels; run on each source VM. It records channel failures and truncation explicitly. A collector export needs `ForwardedEvents` added to its channel list. Preserve the XML and adjacent manifest; transfer them into the local lab package, then run:

```sh
python -m adlab import work/capture-001.xml --out work/capture-001.jsonl
python -m adlab replay work/capture-001.jsonl --out evidence/windows-replay.json
```

The importer accepts XML, JSONL normalized records, Splunk `_raw`/`result` exports and Winlogbeat JSON. It does not parse binary EVTX: use the supplied Windows XML export, not a renamed `.evtx` file.

## Baseline and acceptance checklist

Record at least 14 days of authorized normal operations for operational tuning, with exact host coverage, collection downtime, software inventory and window start/end. The included synthetic 244-record set is **not** such a baseline. Adjudicate alerts independently of rule output and report events, hosts and exposure duration; count repeated events once using stable source record identity.

Acceptance requires evidence of: domain membership/DNS; Sysmon service/config/version; each expected event channel; WEF source count and latency; raw XML hashes; safe-file exercise detection; harmless near-miss; rollback. Native SIEM queries need their own result exports and query engine/version. Preserve actual failures.

## Rollback

Snapshot revert is the preferred full rollback for this dedicated disposable range. Otherwise, save evidence, run `wecutil ds Selbi-Lab` on the collector, unlink only the lab GPO, restore audit policy with `auditpol /restore /file:C:\SelbiLab\state\audit-before.csv`, remove the ScriptBlockLogging policy created by this package (only if no later GPO manages it), and uninstall the lab Sysmon instance using the signed binary's `-u` option. Review these changes manually; no automated broad cleanup script is supplied. The harmless sample directory may be removed only after capture. Domain-controller demotion and DNS restoration need Windows administration; snapshot rollback avoids incomplete cleanup.

## Atomic Red Team / Metasploit source scope

See [Framework integration](emulation.md) for the bundled custom safe Atomic test, exact GUID and module invocation, and a review-only Metasploit resource script. The concrete integrations are provided; their execution on native systems remains unrun. Broad exploit, credential-dumping and destructive ransomware emulation are explicitly omitted. Public independent telemetry is separately labeled.
