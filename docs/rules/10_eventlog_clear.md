# Windows event log cleared using wevtutil

Rule: `2c39e934-3c37-531a-9a35-4365bd2d9854` · Status: experimental

Command-line request to clear a Windows event log. A successful command is not established by process creation.

## Data contract

Source: `{'product': 'windows', 'category': 'process_creation'}`. Required selection fields: `Image`, `CommandLine`. Preserve missing values; never substitute a successful state.

## Tuning

Lab resets and log maintenance. Correlate Security 1102 and Eventlog 104 plus account identity. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0010`. Near miss: `near-0010`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1070/001/
