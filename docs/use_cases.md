# Version 1 Use Cases

## Executive Summary

Version 1 serves two primary actors: a SOC analyst who needs fewer items to triage and a SOC administrator or detection engineer who controls the grouping policy. The default success path is measured against the Phase 2 benchmark: 40 alerts become 17 deterministic incidents without losing any alert reference.

The use cases below define behavior for Phase 4 implementation and Phase 5 testing. They do not add live SIEM integration or fuzzy clustering.

## 1. Actors

| Actor | Goal | Controls |
|---|---|---|
| SOC analyst | Turn a noisy alert file into concise incident summaries | Input path and output path |
| SOC admin/detection engineer | Change which normalized fields define an incident | `config.json` |
| Local filesystem | Supply validated input/config and receive output | File availability and permissions |

## 2. UC-01 — Group a Valid Alert File

**Primary actor:** SOC analyst

**Goal:** Convert a valid JSON alert array into deterministic incident summaries.

**Preconditions:**

- The input and configuration files exist and are readable.
- The configuration passes its contract.
- The output destination is writable.
- The input is a JSON array whose required fields are valid.

**Trigger:** The analyst runs the CLI with input, configuration, and output paths.

**Main flow:**

1. The CLI loads and validates `config.json`.
2. The loader reads and validates the JSON alert array.
3. The normalizer canonicalizes configured grouping values.
4. The deduplicator adds each alert to an ordered exact-key group.
5. The score stage records an exact match of `1.0`.
6. The summarizer calculates severity, time range, alert IDs, and readable text.
7. The writer creates the complete output JSON.
8. The CLI reports the alert and incident counts and exits successfully.

**Postconditions:**

- Every input alert appears in exactly one incident.
- The raw input file remains unchanged.
- No accepted alert disappears from the output.
- Incident and member ordering are deterministic.

**Acceptance criteria:**

- Given `data/demo/raw_alerts.json` and the default config, output equals `data/demo/expected_incidents.json`.
- The summary reports `40 alerts -> 17 incidents`.
- All 40 alert IDs occur exactly once.
- The process exits with status 0.

## 3. UC-02 — Change the Grouping Policy

**Primary actor:** SOC admin or detection engineer

**Goal:** Change incident grouping without editing Python code.

**Preconditions:**

- The alternative `group_by` list contains supported, unique field names.
- Exact matching remains enabled with `minimum_match_score: 1.0`.

**Trigger:** The admin edits `config.json` and runs the same input again.

**Main flow:**

1. The configuration loader validates the new field list.
2. The normalizer builds keys in the new configured order.
3. The deduplicator groups using only those fields.
4. The output records the grouping fields actually used.
5. The CLI reports the new incident count.

**Illustrative result:**

Removing `host` from the Phase 2 default key would merge the repeated payroll-hash groups from WS-003 and WS-004. It would also merge the WS-005 invoice alert into the repeated WS-001 invoice group because their remaining configured values match. The benchmark would therefore change from 17 incidents to 15.

**Postconditions:**

- The original input remains unchanged.
- A changed result is explainable solely by the changed configuration.
- The default expected-output file remains the oracle only for the default config.

**Acceptance criteria:**

- No source-code change is required.
- Unsupported, repeated, or empty grouping fields fail before processing.
- Re-running with the original config reproduces the original 17 incidents.

## 4. UC-03 — Normalize Missing Optional Context

**Primary actor:** SOC analyst

**Goal:** Process sparse alerts without hiding malformed required data.

**Preconditions:**

- Required fields are present and valid.
- One or more optional grouping fields are omitted, `null`, empty, or whitespace-only.

**Main flow:**

1. The loader accepts the record because only optional fields are absent.
2. The normalizer replaces each missing form with `unknown`.
3. The record is grouped using the complete normalized tuple.
4. The incident output shows `unknown` for those grouping fields.

**Acceptance criteria:**

- ALERT-0009 through ALERT-0015 form one failed-login incident despite mixed missing-value representations.
- ALERT-0021 through ALERT-0024 form one WS-003 incident.
- ALERT-0025 through ALERT-0028 form one separate WS-004 incident.
- The program does not crash or silently omit a sparse alert.

## 5. UC-04 — Reject Invalid Input Safely

**Primary actor:** SOC analyst

**Goal:** Receive an actionable error without a misleading partial result.

**Examples:**

- malformed JSON;
- top-level object instead of an array;
- missing `alert_id`, `timestamp`, `source`, `host`, `event_type`, or `severity`;
- duplicate `alert_id`;
- invalid timestamp;
- unsupported severity;
- non-hexadecimal or wrong-length file hash;
- unreadable input or unwritable output path.

**Required flow:**

1. Validation detects the first actionable problem.
2. The CLI reports the file and record context without dumping sensitive evidence.
3. No success message is printed.
4. No partial final output is created.
5. The process exits nonzero.

**Acceptance criteria:**

- Errors identify the record index and alert ID when available.
- JSON decoding errors include line/column when available.
- Full command lines and raw events are not echoed.
- Fixing the input and rerunning succeeds without cleanup of a partial output.

## 6. UC-05 — Keep Similar but Distinct Activity Separate

**Primary actor:** SOC analyst

**Goal:** Avoid false merges when a configured grouping value differs.

**Representative cases:**

| Alert or group | Difference | Expected behavior |
|---|---|---|
| ALERT-0029 versus INC-001 | Different file hash | Separate incident |
| ALERT-0030 versus INC-001 | Different event type | Separate incident |
| ALERT-0031 versus INC-003 | Different file hash | Separate incident |
| INC-004 versus INC-005 | Different host | Separate incidents |
| ALERT-0039 versus INC-003 | Different process and hash | Separate incident |
| ALERT-0040 versus INC-003 | Different user | Separate incident |

**Acceptance criteria:**

- Equality is evaluated after normalization.
- Any difference in a configured field creates a different exact key.
- No fuzzy fallback overrides the exact v1 policy.

## 7. User-Visible CLI Contract

The precise argument parser is implemented in Phase 4, but the user interaction should support:

```text
python -m soc_alert_deduplicator --input <alerts.json> --config <config.json> --output <incidents.json>
```

Successful completion should report only concise operational facts, for example:

```text
Processed 40 alerts into 17 incidents.
Output written to <path>.
```

Failure should be concise, actionable, and nonzero.

## 8. Use-Case Traceability

| Phase 3 requirement | Covered by |
|---|---|
| Analyst runs tool and gets grouped incidents | UC-01 |
| Admin changes config and grouping changes | UC-02 |
| Load → clean → group → score → output | UC-01 main flow |
| Missing optional data does not crash | UC-03 |
| Invalid required data fails safely | UC-04 |
| Different alerts do not merge | UC-05 |
| Phase 2 benchmark remains the oracle | UC-01 acceptance criteria |

## 9. Phase 4 Handoff

Implementation should begin with the default success path, then add failure handling in this order:

1. Load and validate configuration.
2. Load and validate alerts.
3. Normalize configured grouping fields.
4. Build ordered exact-match groups.
5. Summarize and serialize incidents.
6. Add the CLI contract.
7. Compare the actual result with the Phase 2 oracle.

## References

- [Version 1 architecture](architecture.md)
- [Project concept](concept.md)
- [Dataset design](dataset_design.md)
- [Raw Phase 2 alerts](../data/demo/raw_alerts.json)
- [Expected Phase 2 incidents](../data/demo/expected_incidents.json)

