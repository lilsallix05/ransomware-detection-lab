# Sources and technical review

Accessed 19–20 October 2026. Primary documentation was used to check interfaces and semantics; documentation access does not establish a native integration was executed.

| Source | Decision supported |
|---|---|
| [Sigma rule basics](https://sigmahq.io/docs/basics/rules.html) | YAML logsource, selections, condition and metadata shape. |
| [Sigma correlation specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md) | Separate `value_count` rule, grouping, timespan and threshold; no obsolete aggregation syntax. |
| [pySigma Splunk backend](https://github.com/SigmaHQ/pySigma-backend-splunk) | `SplunkBackend` generation; package version pinned in lockfile. |
| [pySigma Kusto backend](https://github.com/AttackIQ/pySigma-backend-kusto) | `KustoBackend` generation. Explicit custom-table prefix avoids assuming ASIM field equivalence. |
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Process, process-access and file-create event collection. Native binary/schema validation remains unrun. |
| [Windows Event Forwarding](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection) | Source-initiated collection, event transport and source permissions. |
| [Windows Event 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769) | Domain-controller TGS events, RC4 field, newer event versions. |
| [Splunk HEC format](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/format-events-for-http-event-collector) | HEC envelope and acknowledgement handling. |
| [Splunk streamstats](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/streamstats) | Time-window distinct counts; target-engine limits still require validation. |
| [Azure Monitor Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview) | DCR/table/stream model, endpoint and token-based ingestion. |
| [Kusto count_distinct](https://learn.microsoft.com/en-us/kusto/query/count-distinct-aggregation-function?view=microsoft-fabric) | Exact count rather than approximate dcount. Function documentation labels preview; availability must be checked on the native workspace. |
| [Navigator layer format 4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md) | Portable layer JSON fields. A live Navigator import is not claimed. |
| [Invoke-AtomicRedTeam local execution](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Execute-Atomic-Tests-(Local)) | Explicit custom path and test GUID invocation. |
| [Splunk attack_data](https://github.com/splunk/attack_data) | Independent dataset origin; pinned record/metadata/license URLs are in fixtures/public-dataset.json. |

ATT&CK technique references are included in each rule and are conceptual mappings, not an assertion of full technique coverage. No prevalence, market, legal or compliance statistic is presented as a measured outcome.

The interface uses [IBM Plex Sans](https://github.com/IBM/plex) at weights 400, 500 and 600, sourced from commit `71f558992315a12ca1f06a2215d57962a1992162` under the SIL Open Font License 1.1. The binaries, license and source/hash manifest are in `adlab/assets/` and copied to each report's `assets/` directory. Font data is embedded in the HTML to support offline and `file://` viewing without cross-origin font requests. The fallback is the operating system interface stack; machine values use the local monospace stack.
