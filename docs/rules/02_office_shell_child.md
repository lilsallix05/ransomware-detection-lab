# Office application spawns a command interpreter

Rule: `e7df34fb-7a1d-5bf0-8aa6-489e67893dcd` · Status: experimental

Office-to-shell process relationship consistent with document execution. Does not inspect the email or prove phishing.

## Data contract

Source: `{'product': 'windows', 'category': 'process_creation'}`. Required selection fields: `ParentImage`, `Image`. Preserve missing values; never substitute a successful state.

## Tuning

Approved document macros or add-ins. Tune exact signed parent/child path and deployment owner after review. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0002`. Near miss: `near-0002`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1204/002/
