# RC4 service ticket for a non-machine service

Rule: `fdc3317b-1ae4-5da3-af8c-68fd10f89f79` · Status: experimental

Successful RC4 TGS request for a non-machine/non-krbtgt service. A candidate for Kerberoasting investigation; legacy services are legitimate.

## Data contract

Source: `{'product': 'windows', 'service': 'security'}`. Required selection fields: `EventID`, `TicketEncryptionType`, `Status`, `ServiceName`, `ServiceName`. Preserve missing values; never substitute a successful state.

## Tuning

Legacy service accounts using RC4. Inventory service owners, prioritize AES migration, and correlate unusual request volume. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0004`. Near miss: `near-0004`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1558/003/
