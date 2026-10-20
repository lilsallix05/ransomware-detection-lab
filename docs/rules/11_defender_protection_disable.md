# PowerShell requests Defender real-time protection disablement

Rule: `e3f1f661-55d9-5dcc-aca7-dec037bd8e32` · Status: experimental

PowerShell script block contains Defender disablement parameters. Tamper Protection may prevent the action; inspect Defender state before claiming success.

## Data contract

Source: `{'product': 'windows', 'service': 'powershell'}`. Required selection fields: `EventID`, `ScriptBlockText`. Preserve missing values; never substitute a successful state.

## Tuning

Approved troubleshooting. Require endpoint owner review; do not allowlist all PowerShell or administrator activity. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0011`. Near miss: `near-0011`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1562/001/
