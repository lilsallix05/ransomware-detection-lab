# File creation with a ransomware-associated extension

Rule: `78874254-c831-569c-96ef-82a053cc0b60` · Status: experimental

Candidate file-create event for the burst correlation. Sysmon Event 11 sees file creation/overwrite, not every rename and not file entropy; extensionless encryption is a blind spot.

## Data contract

Source: `{'product': 'windows', 'category': 'file_event'}`. Required selection fields: `TargetFilename`. Preserve missing values; never substitute a successful state.

## Tuning

Archive/test tools can use these extensions. The individual event is a low-confidence signal; prioritize the 20-distinct-file correlation. Alert disposition belongs to the analyst; no global administrator allowlist is provided. Capture 14 days of real normal operations before production thresholds or suppression.

## Replay

Positive: `attack-0014`. Near miss: `near-0014`. Both are authored synthetic records; see `fixtures/cases.json`. Tests also remove required fields and alter logsource to verify fail-closed behavior.

## Investigation

Open the source event, correlate Computer and timestamp with logon, parent process, account owner and change ticket. Preserve source record IDs and hashes. Escalate corroborated behavior; do not label an isolated signature as a confirmed ransomware infection.

## Backend

Generated SPL uses normalized JSON fields in `index=adlab`; KQL uses `SelbiADLab_CL`. See `docs/siem.md` for schema and ingestion. Queries were generated locally, not executed in a SIEM.

Reference: https://attack.mitre.org/techniques/T1486/
