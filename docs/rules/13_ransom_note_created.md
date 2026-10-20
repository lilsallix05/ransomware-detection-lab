# File created with a common ransom-note name

Rule: `b969daf7-3a83-5527-b761-8bd09aa58800` · Status: experimental

Creation of one of three explicitly listed ransom-note filenames. Content and successful encryption are not inferred.

## Data contract

Source: `{'product': 'windows', 'category': 'file_event'}`. Required selection fields: `TargetFilename`. Preserve missing values; never substitute a successful state.

## Tuning

Security training or restored backups. Investigate adjacent file bursts, signer and affected shares; names alone are weak. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0013`. Near miss: `near-0013`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1486/
