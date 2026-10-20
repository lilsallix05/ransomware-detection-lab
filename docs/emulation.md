# Framework integration and controlled evidence

The default workflow does not require an attack framework. The included PowerShell file-creation script and custom Atomic test are harmless telemetry surrogates; they cannot validate credential theft, encryption, exploit success or remote execution.

## Invoke-AtomicRedTeam

Use a reviewed local release of the official [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) PowerShell module on an isolated Windows lab VM. Record its Git commit and SHA256 hashes of the module and this project's custom YAML. Do not use a pipe-to-shell installer or request automatic prerequisites. The packaged definition is at `lab/atomic/T1486/T1486.yaml`, GUID `48550b0e-d60c-47b0-a74f-08f8c7ba569d`.

```powershell
Import-Module C:\Tools\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
$atomics = (Resolve-Path .\lab\atomic).Path
Invoke-AtomicTest T1486 -TestGuids 48550b0e-d60c-47b0-a74f-08f8c7ba569d -PathToAtomicsFolder $atomics -ShowDetails
Invoke-AtomicTest T1486 -TestGuids 48550b0e-d60c-47b0-a74f-08f8c7ba569d -PathToAtomicsFolder $atomics -CheckPrereqs
```

After reviewing those outputs on the dedicated marked VM, the same command without `-ShowDetails` or `-CheckPrereqs` runs the custom surrogate. It writes 25 new plaintext files in a unique temporary directory, never touches existing files, and has no destructive cleanup command. Export Sysmon events with `lab/windows/Export-LabTelemetry.ps1`, preserve raw XML and source hashes, and run the importer/replay commands in the README. This verifies collection and the file-create correlation path if it succeeds; it is not a real ransomware test.

Do not accidentally omit `-PathToAtomicsFolder`: the upstream T1486 catalog contains different tests, and this package authorizes only its custom local surrogate. The GUID and source path are deliberate safeguards. No upstream atomics, dependency installation, or Invoke-AtomicTest execution occurred during this build. YAML structure and the safe command content are checked locally; PowerShell/module compatibility is a separate native acceptance gate.

## Metasploit planning adapter

`lab/metasploit/review-only.rc` is a concrete resource-script integration for an existing local Metasploit installation. It prints version information and searches module metadata, then exits. It contains no target, payload, exploit or execution command:

```sh
msfconsole -q -r lab/metasploit/review-only.rc > work/metasploit-catalog.txt
```

The script was inspected locally but not run because Metasploit is not a prerequisite of the defensive replay. This deliberately stops at framework readiness and catalog review. It does not validate detections by executing an exploit. For separately authorized exercises, an operator must record exact module/version, scope, target snapshot, expected telemetry and rollback outside this package. Existing independently obtained logs can enter the validated XML/JSONL importer without running Metasploit here.

## Record native work

Use a fresh evidence directory per run. Capture OS build, Sysmon version/config hash, framework revision, test GUID, run start/end, command transcript, event export hashes and any failed prerequisite. Keep failed and empty channel exports visible. Add actual outcomes to the evidence record only after review; never replace an explicit `not-run` state with a successful plan.
