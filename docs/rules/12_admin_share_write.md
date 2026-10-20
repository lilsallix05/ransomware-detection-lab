# Executable write requested over an administrative share

Rule: `b3f2d9c1-d975-57d3-b2f7-f8c7d3df0874` · Status: experimental

Detailed file-share access requests include write access to executable-like names. The listed masks are intentionally bounded and are not a complete Windows bitmask evaluator.

## Data contract

Source: `{'product': 'windows', 'service': 'security'}`. Required selection fields: `EventID`, `ShareName`, `AccessMask`, `RelativeTargetName`. Preserve missing values; never substitute a successful state.

## Tuning

Software deployment and helpdesk copies. Correlate source account, endpoint and change window; do not equate access check with successful copy. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0012`. Near miss: `near-0012`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1021/002/
