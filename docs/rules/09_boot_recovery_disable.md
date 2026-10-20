# Boot recovery disabled with bcdedit

Rule: `dbf82dbb-0113-540e-8f13-3a506bebb4c0` · Status: experimental

Recovery-enabled setting disabled in boot configuration. String selection tolerates spacing but may match quoted commentary.

## Data contract

Source: `{'product': 'windows', 'category': 'process_creation'}`. Required selection fields: `Image`, `CommandLine`. Preserve missing values; never substitute a successful state.

## Tuning

Troubleshooting boot recovery. Require a documented rollback and maintenance approval. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0009`. Near miss: `near-0009`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1490/
