# Windows backup catalog deletion

Rule: `a60487ac-cd52-5f41-838b-d4ac658ac28a` · Status: experimental

Windows backup catalog deletion can inhibit recovery. Match additional backup tools separately.

## Data contract

Source: `{'product': 'windows', 'category': 'process_creation'}`. Required selection fields: `Image`, `CommandLine`. Preserve missing values; never substitute a successful state.

## Tuning

Backup repair operations approved by storage owner. Preserve the ticket and recovery validation. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0008`. Near miss: `near-0008`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1490/
