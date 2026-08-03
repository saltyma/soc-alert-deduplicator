# Data Research

## Executive Summary

The Phase 2 dataset is a synthetic, normalized alert corpus modeled on the lifecycle and field concepts used by Wazuh, enriched with process context available from Microsoft Sysmon, and labeled with readable detection metadata inspired by Sigma. It is deliberately not a raw export from any one product: the project needs a stable v1 contract that can later accept source-specific adapters without publishing sensitive logs or coupling the deduplicator to a single vendor.

The resulting records are Wazuh-style alerts from a fictional source named `mock-wazuh`. Sysmon supplies realistic endpoint concepts such as process image, parent process, command line, and SHA-256, while Sigma informs concise rule names and a portable severity vocabulary.

## 1. Research Question and Scope

This research answers four questions:

1. What makes a security alert different from a raw event?
2. Which Wazuh and Sysmon concepts are useful for incident-oriented grouping?
3. Which fields belong in a small, explainable v1 schema?
4. How should synthetic data expose edge cases without containing real operational information?

The research is limited to batch JSON input. Installing Wazuh or Sysmon, ingesting live logs, translating Sigma rules, and building source-specific parsers are outside Phase 2.

## 2. Sources Reviewed

Primary sources were preferred and were checked on 2026-08-03:

- [Wazuh alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)
- [Wazuh data analysis workflow](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Sigma rule basics](https://sigmahq.io/docs/basics/rules.html)
- [Sigma rules specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Python `json` module documentation](https://docs.python.org/3/library/json.html)

The project plan and earlier notes were also reviewed:

- [Notion Phase 2 plan](https://app.notion.com/p/379ea4a7d0dd80bd9022f3935343b915)
- [Notion Wazuh alert example](https://app.notion.com/p/355ea4a7d0dd80aa8dedf3da079ab4d4)
- [Notion Sysmon Event ID 1 example](https://app.notion.com/p/355ea4a7d0dd80c9b903dce62fbd6c4d)

## 3. Wazuh Alert Findings

Wazuh distinguishes collected events from alerts. Its analysis engine first decodes logs into structured fields, then evaluates them against rules; matching events become alerts and are written to `alerts.log` and `alerts.json`. This supports three v1 design choices:

- An alert needs a timestamp, source endpoint, detection name, and severity.
- Source-specific nesting such as Wazuh's `rule`, `agent`, and dynamic `data` objects should be flattened behind a normalized contract.
- Rule metadata and event evidence are related but separate. A rule explains why the alert fired; host, user, process, and hash describe what happened.

Wazuh uses numeric rule levels and defaults to storing alerts at level 3 or higher. This project does not pretend that its categorical severities are a lossless Wazuh mapping. A future Wazuh adapter will own that source-specific conversion.

## 4. Sysmon Event Findings

Sysmon records endpoint telemetry; it does not itself decide that activity is malicious. Event ID 1 provides process-creation context including the full command line, parent process, cryptographic hashes, and a Process GUID. Event ID 3 can associate network activity with a process.

For this project, Sysmon is therefore a field-model reference rather than the alert generator. The v1 schema retains:

- `process_name`
- `parent_process_name`
- `command_line`
- `file_hash`

`process_guid` is deferred because exact v1 grouping is meant to collapse repeated alerts about the same activity; a unique per-process identifier would often prevent that collapse. SHA-256 is used whenever a demo alert contains a file hash because it is explicit, fixed-width, and supported by Sysmon.

## 5. Sigma and Detection-Rule Findings

Sigma is a detection-rule format, not an event or alert transport format. Its rules separate a log source, detection logic, and metadata. Useful metadata includes title, description, false-positive guidance, and a five-value level vocabulary: `informational`, `low`, `medium`, `high`, and `critical`.

Phase 2 borrows two ideas:

- `rule_name` should be short and describe the behavior being detected.
- `severity` uses the five lowercase Sigma-style values.

The demo does not claim that its rule names are copied from or compatible with particular Sigma rules.

## 6. JSON Representation Findings

The demo files use a top-level JSON array encoded as UTF-8 without comments or duplicate object keys. Timestamps use ISO 8601 UTC form with a trailing `Z`. Missing optional evidence is represented in three realistic waysâ€”an omitted key, `null`, or a blank stringâ€”so Phase 4 must normalize all three consistently.

No `NaN`, infinity, binary payload, or raw log blob is included. This keeps the files interoperable with strict JSON consumers and safe for public publication.

## 7. Version 1 Normalized Alert Schema

| Field | Type | Required | Origin | Purpose |
|---|---|---:|---|---|
| `alert_id` | string | Yes | Normalized | Stable unique alert reference |
| `timestamp` | string | Yes | Wazuh/SIEM | ISO 8601 UTC occurrence time |
| `source` | string | Yes | Wazuh/SIEM | Producer or source adapter |
| `host` | string | Yes | Wazuh agent/Sysmon host | Affected endpoint |
| `user` | string or null | No | Decoded event/Sysmon | Account associated with activity |
| `event_type` | string | Yes | Normalized category | Broad behavior category |
| `process_name` | string or null | No | Sysmon | Executable name |
| `parent_process_name` | string or null | No | Sysmon | Parent executable context |
| `command_line` | string or null | No | Sysmon | Process execution context |
| `file_hash` | string or null | No | Sysmon | SHA-256 when available |
| `severity` | string | Yes | Rule metadata | Canonical priority label |
| `rule_name` | string | No | Wazuh/Sigma-inspired | Human-readable detection name |
| `description` | string | No | Rule metadata | Short analyst-facing explanation |

Every demo alert supplies the required fields. Optional fields are intentionally absent or empty in selected edge cases.

## 8. Normalization and Grouping Contract

Phase 4 must normalize configured grouping fields as follows:

1. Convert values to strings where appropriate.
2. Trim leading and trailing whitespace.
3. Convert text to lowercase because `case_sensitive` is `false`.
4. Replace an absent key, `null`, or an empty/whitespace-only value with `unknown`.
5. Build the exact grouping tuple in configured order:
   `(host, user, event_type, process_name, file_hash)`.

Only grouping values are canonicalized for the benchmark. Evidence such as the original command line should remain available for analyst display. `rule_name`, `severity`, `source`, parent process, and command line are not in the v1 grouping key.

## 9. Fields Deferred to Later Versions

The following fields are useful but intentionally deferred:

- `source_ip`, `destination_ip`, and `destination_port`
- `process_guid`
- `mitre_technique`
- `rule_id`
- `raw_event`
- source-specific agent and manager identifiers
- a configurable `time_window`
- campaign-level correlation across hosts

Deferral keeps v1 centered on transparent exact grouping. These fields can be added through adapters without invalidating the core contract.

## 10. Data-Source and Privacy Decision

Version 1 uses synthetic Wazuh-style JSON enriched with Sysmon-inspired process fields. The source value `mock-wazuh`, the `.lab` identities, reserved `.invalid` domain, fabricated SHA-256 values, redacted payload marker, hosts, and timestamps are all fictional.

No logs were collected from a real endpoint, no personal IP address is present, and no executable content is embedded. The dataset is safe to publish with the repository.

## 11. Known Limitations and Risks

- Exact matching can split genuinely related activity when one grouping value differs.
- There is no time window, so identical normalized keys could group activity that happened far apart.
- Normalizing missing values to `unknown` can over-group alerts that lack context.
- Host is part of the key, so a shared malware hash on several endpoints becomes separate incidents rather than one campaign.
- Command-line and parent-process differences do not split incidents in v1.
- The flat schema is an educational contract, not a drop-in representation of every Wazuh alert.

These constraints are intentional and make the first implementation explainable and testable.

## Sources

- [Wazuh alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)
- [Wazuh data analysis workflow](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Sigma rule basics](https://sigmahq.io/docs/basics/rules.html)
- [Sigma rules specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Python `json` module](https://docs.python.org/3/library/json.html)
