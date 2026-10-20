# Shadow copy deletion through vssadmin

Rule: `168f427a-bb72-5ebd-817e-936edd1a77b0` · Status: experimental

vssadmin command includes deletion of shadow copies. Arguments are recorded text; no command is executed by this lab.

## Data contract

Source: `{'product': 'windows', 'category': 'process_creation'}`. Required selection fields: `Image`, `CommandLine`. Preserve missing values; never substitute a successful state.

## Tuning

Approved backup cleanup. Confirm maintenance ticket, caller identity and recovery policy; never suppress by tool name alone. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0007`. Near miss: `near-0007`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1490/
