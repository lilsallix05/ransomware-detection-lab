# Nonstandard process opens LSASS with dump-compatible access

Rule: `85e7a148-4e57-50b0-ae1e-462d7e171453` · Status: experimental

Sysmon ProcessAccess to LSASS with selected read/full-access masks. Access is a signal, not proof a dump was written.

## Data contract

Source: `{'product': 'windows', 'category': 'process_access'}`. Required selection fields: `TargetImage`, `GrantedAccess`. Preserve missing values; never substitute a successful state.

## Tuning

EDR and diagnostic tools. Match signer, known binary hash and access policy; broad SourceImage exclusions hide attacks. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0003`. Near miss: `near-0003`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1003/001/
