# PsExec service installation

Rule: `95fa0642-eb08-5576-8020-7c3fd01b51fb` · Status: experimental

A service binary contains the conventional PsExec service name. Renamed services evade this signature; use alongside remote share and logon evidence.

## Data contract

Source: `{'product': 'windows', 'service': 'system'}`. Required selection fields: `EventID`, `ImagePath`. Preserve missing values; never substitute a successful state.

## Tuning

Approved helpdesk PsExec usage. Require a change ticket and source endpoint correlation before suppressing. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0005`. Near miss: `near-0005`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1569/002/
