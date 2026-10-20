# Remote interactive logon from a network address

Rule: `59c2e095-249a-560e-a1e2-a7cc4c834043` · Status: experimental

Remote interactive logon is an investigation lead; this rule cannot establish exposed RDP or malicious initial access.

## Data contract

Source: `{'product': 'windows', 'service': 'security'}`. Required selection fields: `EventID`, `LogonType`, `IpAddress`. Preserve missing values; never substitute a successful state.

## Tuning

Normal remote administration. Correlate approved source IP, account and access window; do not globally exclude administrators. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0001`. Near miss: `near-0001`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1021/001/
