# Ransomware in AD: evidence before deployment

**Status:** locally verified detection package. Native AD and SIEM validation is still outstanding.

## Problem

An analyst needs to inspect the logic behind Windows ransomware signals, reproduce detections, see the noise they generate, and explain what the evidence actually establishes. A query that converts successfully does not prove a working collection pipeline, and a synthetic replay is not a production false-positive measurement.

## Implementation

The package contains 14 event-level Sigma rules and one rolling distinct-file correlation. The rules cover remote access and execution, credential-access indicators, lateral movement, recovery inhibition, defense interference and file-impact signals. A Python CLI normalizes XML, JSONL, Splunk and Winlogbeat exports, preserves source provenance, rejects malformed or duplicate identities, runs the bounded rule profile and generates portable results.

The analyst surface is a compact detection queue with source records, benign-signal filtering, query disclosures, a navigable timeline and structured exports. It uses a single-column list/detail flow on small screens. The printed version always contains the full matrix, independent of the selected view. SPL and KQL translations, offline ingestion payload adapters, Windows/Sysmon/WEF scripts, a custom harmless Atomic test and a review-only Metasploit resource script describe concrete native setup paths.

Violet marks selection and actions; amber marks tuning work. Embedded, licensed IBM Plex Sans supports offline review. The burst ruler is calculated from the selected alert's source timestamps and distinct paths: the bundled example shows 20 files across 38 seconds inside its 60-second evaluation window. The same measurements appear as accessible text.

## Measured local results

The replay triggers **15 of 15 rules** on **38 authored positive records**. **4 of 244 authored benign records** generate signals. Those four are approved administrative examples and stay visible as tuning work. The mapped coverage is **11 distinct ATT&CK techniques and sub-techniques**. These are sample-specific counts, not a real capture duration, broad recall or an operational false-positive rate.

A separately generated Splunk public dataset was fetched at a fixed commit, matched to its expected SHA256, normalized and replayed: **one RC4 service-ticket record, one matching rule**. This is independent evidence for that predicate only. It cannot support a claim that all 15 detections generalize to public telemetry. The provenance record is in [`evidence/public-fetch.json`](../evidence/public-fetch.json) and the replay output in [`evidence/public-replay.json`](../evidence/public-replay.json).

No Windows capture, native SIEM result, cloud deployment or attack-framework execution is claimed.

## What testing changed

Testing found that overlapping XML exports needed a stable native identity, ISO timezone handling needed an explicit SPL fallback, and correlation alert cadence differed between the local engine and the backend queries. Those issues were fixed or documented. Report review also removed fixed synthetic labels on custom input, bundled the linked files so a copied report folder still works, and separated the positive and benign event maps so a record in one set cannot replace the other's details.

## Limitations and the next evidence gate

Image-based correlation groups separate processes that share an image path. File-create extension checks miss many renames and extensionless encryption. LSASS access masks and share-access masks are intentionally narrow. WMI parentage alone does not prove remote execution, and command text does not prove a defense change succeeded. All rules remain experimental.

The next gate is a documented run in an isolated Windows lab: raw XML, Sysmon and WEF health, a harmless file-create exercise, a real baseline collection and native Splunk or Sentinel query outputs. The runbooks are in [lab-setup.md](lab-setup.md), [siem.md](siem.md) and [emulation.md](emulation.md).

## Walkthrough of the reasoning

Explain why the RC4 rule fires on an approved legacy account; open the exact benign record, then propose a scoped tuning decision. Show a 20-file burst across a clock-minute boundary and the repeated-filename negative test. Explain why local replay emits threshold crossings while backend queries return each qualifying anchor. Finish with the independent one-event result and the evidence still needed before a production claim.
