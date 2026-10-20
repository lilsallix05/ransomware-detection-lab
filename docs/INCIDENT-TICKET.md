# IR-ADLAB-001 — simulated ransomware precursor chain

**Classification:** synthetic exercise. **Priority:** high investigation priority within the fictional scenario. **Status:** analysis complete; containment and recovery not executed. **Owner:** lab analyst role, unassigned to a real person. **Prepared:** 20 October 2026.

## Summary and scope

The authored event set depicts a sequence on `WS01.selbi.lab` beginning with remote logon and Office-to-shell execution, followed by credential-access and administration signals, recovery-inhibition commands and suspicious file creation. It produces 39 alert objects across 15 detections, including one distinct-file burst correlation. No actual host was compromised, encrypted or contained.

The reviewed set contains 38 positive records. Scope is limited to those records and this fictional host; it cannot establish domain-wide compromise, a source intrusion path, data exfiltration or the success of any command. `192.0.2.50` is a documentation address; `10.77.10.20` is an isolated-lab example, not an observed hostile public endpoint.

## Evidence register

| Item | Origin | Integrity |
|---|---|---|
| fixtures/attack.jsonl | Authored synthetic positive events | SHA256 `0835f189042f293ef9fda70371a32e374dfbf6e7c917678a8bc0f1243cf74eac` |
| fixtures/benign.jsonl | Authored normal and approved-admin cases | SHA256 `6a02601f3ee0fbc09b77aaf6106f44b010f7c8e6fe8beb832082b409202448ab` |
| evidence/replay/alerts.json | Local Python replay output | Source record IDs shown below and in JSON |
| evidence/public-replay.json | Independent one-event Splunk dataset replay | Separate corroboration of RC4 predicate; not part of this incident timeline |

## Timeline (first signal for each detection)

Times are UTC fixture timestamps, not measured response times. Full alert chronology is retained in the JSON and HTML report.

| UTC fixture time | Signal | Source RecordId(s) |
|---|---|---|
| 2026-10-19T01:00:10Z | Remote interactive logon from a network address | attack-0001 |
| 2026-10-19T01:00:20Z | Office application spawns a command interpreter | attack-0002 |
| 2026-10-19T01:00:30Z | Nonstandard process opens LSASS with dump-compatible access | attack-0003 |
| 2026-10-19T01:00:40Z | RC4 service ticket for a non-machine service | attack-0004 |
| 2026-10-19T01:00:50Z | PsExec service installation | attack-0005 |
| 2026-10-19T01:01:00Z | WMI provider spawns a shell | attack-0006 |
| 2026-10-19T01:01:10Z | Shadow copy deletion through vssadmin | attack-0007 |
| 2026-10-19T01:01:20Z | Windows backup catalog deletion | attack-0008 |
| 2026-10-19T01:01:30Z | Boot recovery disabled with bcdedit | attack-0009 |
| 2026-10-19T01:01:40Z | Windows event log cleared using wevtutil | attack-0010 |
| 2026-10-19T01:01:50Z | PowerShell requests Defender real-time protection disablement | attack-0011 |
| 2026-10-19T01:02:00Z | Executable write requested over an administrative share | attack-0012 |
| 2026-10-19T01:02:10Z | File created with a common ransom-note name | attack-0013 |
| 2026-10-19T01:02:20Z | File creation with a ransomware-associated extension | attack-0014 |
| 2026-10-19T01:06:23Z | Burst of distinct files with ransomware-associated extensions | burst-0100, burst-0101, burst-0102, burst-0103, burst-0104, burst-0105, burst-0106, burst-0107, burst-0108, burst-0109, burst-0110, burst-0111, burst-0112, burst-0113, burst-0114, burst-0115, burst-0116, burst-0117, burst-0118, burst-0119 |

## Analysis and confidence

The correlated impact signal is stronger than a single extension match because it counts distinct file paths in an inclusive one-minute window. It still does not establish encryption. The LSASS signal indicates selected process access rights, not a verified memory dump. RC4 service tickets and PsExec can be approved administrative work; the benign set intentionally demonstrates this. Command-line matches are requests or recorded text, not proof that recovery or Defender configuration changed. No email content, network trace, file entropy, memory image or actual AD control state is available.

## Response decision and actions

**No response action was executed.** In an authorized live incident, the proposed next decision would be to preserve source events, confirm endpoint identity and business criticality, verify the parent/account chain and change tickets, and ask the incident owner to authorize isolation of the affected endpoint if corroboration supports compromise. Record requested, applied and observed-effective states separately. Avoid disabling domain accounts or DC networking based solely on this fixture-shaped signal.

Acquire memory/file evidence through the organization's approved process, retain hashes and chain of custody, and confirm recovery-inhibition commands succeeded before describing their effect. Search other hosts for the same source identities and image hashes; these fixtures supply no trustworthy malware hash. Treat log gaps as unknown coverage.

## Recovery and closure criteria

A live case could close only after scope review, approved containment verification, root-cause remediation, clean recovery from verified backups, restored telemetry, affected credential review and monitoring for recurrence. None of those outcomes exists for this synthetic exercise. This ticket closes only the local analysis exercise.

## Tuning follow-up

Review the four benign administrative alerts; preserve accountable exceptions tied to host, signer, source and change window. Collect a genuine baseline with known duration and channel health. Validate queries in the native engine and choose explicit alert suppression for the per-anchor correlation outputs. Keep rule status experimental until that evidence exists.
