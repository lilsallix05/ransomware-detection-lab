# Splunk, Sentinel and Elastic adapters

All 15 rules have SPL and KQL exports. Fourteen event predicates are generated through the installed pySigma backends. The one-minute distinct-file correlation uses an explicit translator because the pack needs a rolling window. **Generation and local matching were tested; native query execution and ingestion were not performed.**

## Shared event schema

The importer preserves Windows `EventData` names. `EventID` and `LogonType` are numbers; `TimeCreated` is timezone-bearing ISO 8601. Other listed columns are strings or absent. Each record requires `Provider`, `Channel`, `Computer`, `EventID`, `TimeCreated` and a stable `RecordId`. Windows XML imports derive the identity from provider, host, channel, native record ID and time, so overlapping exports cannot silently multiply events. Explicit duplicate IDs cause a recoverable import error. Preserve the original evidence and investigate duplicates before constructing a deduplicated input.

`adlab siem splunk|sentinel input --out payload.json` creates a payload offline. Sending requires `--send`, a fully specified HTTPS endpoint and a token supplied by environment variable. No network upload was executed during the build. Payload batches are bounded; a failed later batch reports what earlier batches were accepted, rather than claiming all-or-nothing success. A successful ingestion response does not prove a detection query ran. Never commit tokens or put them in endpoint URLs.

## Splunk HEC

Install `lab/splunk/indexes.conf` and `props.conf` in a local lab app using your Splunk administrator's process. Create an HEC token restricted to `adlab` and verify TLS with your local CA. The normalized sourcetype is `selbi:adlab`. To review an offline payload:

```sh
python -m adlab siem splunk fixtures/attack.jsonl --out work/splunk-payload.json
```

An authorized operator can set `ADLAB_SIEM_TOKEN` without exposing it in shell history, then add `--send --endpoint https://siem.ad.selbi.test:8088/services/collector/event`. The adapter writes one HEC JSON envelope per line with a numeric event time and checks the HEC acknowledgement code. It does not install searches or silently send data.

Run each query in `queries/splunk/` in the correct lab time range and export result rows. Verify source field extraction before tuning. The correlation prefers `_time` populated by HEC and includes explicit ISO timestamp fallbacks. Check for unparsed timestamps rather than dropping them unnoticed. Splunk streamstats limits and local sort capacity need review for production volumes. Set a limited search window and overlap by at least one minute for scheduled evaluation.

## Microsoft Sentinel / Azure Monitor

The KQL exports deliberately target **`SelbiADLab_CL`**, a custom table with the normalized schema. They do not claim to work unchanged against `SecurityEvent`, ASIM or Defender tables. `lab/sentinel/table.json` provides the table schema; `dcr-template.json` provides a `kind: Direct` Data Collection Rule template so a direct ingestion endpoint can be generated. Replace all uppercase placeholders and have an administrator create these resources in an existing workspace. No resource provisioning occurred here and using a workspace can incur charges.

Configure an Entra application/managed identity with the minimum documented ingestion permission on the DCR. Obtain a token for the Azure Monitor resource through your organization's approved credential flow; the adapter consumes a short-lived token and does not provision identity. The POST endpoint format is:

```text
https://YOUR-INGESTION-ENDPOINT/dataCollectionRules/YOUR-DCR-IMMUTABLE-ID/streams/Custom-SelbiADLab?api-version=2023-01-01
```

Generate a local payload first:

```sh
python -m adlab siem sentinel fixtures/attack.jsonl --out work/sentinel-payload.json
```

With native resources and explicit upload authorization in place, add `--send --endpoint` with the completed endpoint. The adapter sends arrays of typed records and checks HTTP success. It does not obtain tokens or create a DCR. Validate ingestion against table row count and `RecordId`, then run the KQL and export results. Keep receipts, engine version, query text and results separately from local replay evidence.

## Correlation semantics

All backends express at least 20 distinct, case-insensitive file paths from the same host and image in an inclusive 60-second window. **Alert cadence differs:** Python replay emits on a threshold crossing and re-arms after expiry; generated SPL/KQL return every qualifying event anchor. They are candidate predicates, not identical incident counts. Configure native alert suppression/grouping explicitly before comparing alert totals. KQL uses an exact `count_distinct` with an event-time self-join, which is clear for a small lab but expensive at scale. Native limits and inclusive boundary behavior remain to be measured on the target engine. Simultaneous events and ingestion overlap also require native acceptance testing.

`Image` grouping joins separate instances of the same executable; ProcessGuid correlation is a documented future refinement. Sysmon file creation and extension names are impact signals, not entropy analysis or proof of encryption. Do not report coverage of all ransomware behavior.

## Elastic

`lab/elastic/winlogbeat.yml` is a collector configuration for an existing local Elasticsearch endpoint. It requires a valid local CA and an API key. The importer accepts Winlogbeat JSON exports for replay. Native Elasticsearch detection queries and deployment are not implemented; the core requirement is met with the explicit Splunk path, with Sentinel as the second backend. This optional collector path was not executed.

Primary setup references, checked 19–20 October 2026: [Splunk HEC format](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/format-events-for-http-event-collector), [Microsoft Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview), [pySigma Splunk backend](https://github.com/SigmaHQ/pySigma-backend-splunk), [pySigma Kusto backend](https://github.com/AttackIQ/pySigma-backend-kusto).
