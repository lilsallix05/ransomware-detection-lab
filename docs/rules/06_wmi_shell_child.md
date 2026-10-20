# WMI provider spawns a shell

Rule: `6196d0e9-5088-56eb-b1bb-46a089609e2a` · Status: experimental

WMI provider shell child. Host process data alone does not establish whether WMI was remote.

## Data contract

Source: `{'product': 'windows', 'category': 'process_creation'}`. Required selection fields: `ParentImage`, `Image`. Preserve missing values; never substitute a successful state.

## Tuning

Configuration-management software. Correlate WMI-Activity operational logs, source logons and management-server identity. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0006`. Near miss: `near-0006`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1047/
