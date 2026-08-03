# Dataset Design

## Executive Summary

The Phase 2 benchmark contains exactly 40 synthetic alerts and a manually specified oracle of 17 expected incidents. Five repeated scenarios account for 28 alerts and collapse into five incidents; the remaining 12 alerts are deliberate singletons. Exact v1 grouping therefore reduces 40 alerts to 17 incident summaries, a 57.5% reduction in items presented for triage.

The dataset tests obvious duplicates, normalized duplicates, near-duplicates, cross-host separation, missing optional evidence, and unrelated activity without requiring a live SIEM.

## 1. Dataset Goal

The dataset must answer a binary question for every pair of records: should these alerts share an incident under the documented v1 key?

It is designed to:

- make the correct output knowable before implementation;
- exercise every normalization rule;
- demonstrate practical alert-noise reduction;
- expose limitations rather than hide them;
- remain safe and understandable in a public portfolio.

## 2. Dataset Size and Files

| Artifact | Count | Purpose |
|---|---:|---|
| `data/demo/raw_alerts.json` | 40 alerts | Phase 4 input |
| `data/demo/expected_incidents.json` | 17 incidents | Manually specified benchmark |
| Repeated groups | 5 | Positive grouping cases |
| Singleton incidents | 12 | Negative and near-duplicate cases |

The size is large enough to make deduplication visible while remaining small enough for a human reviewer to inspect.

## 3. Grouping Oracle

The configured grouping fields are:

```text
host + user + event_type + process_name + file_hash
```

Before comparison, each value is trimmed and lowercased. Missing keys, `null`, empty strings, and whitespace-only strings become `unknown`.

Incident IDs are assigned in order of the first alert's appearance in the input. Within each incident:

- `first_seen` is the earliest member timestamp;
- `last_seen` is the latest member timestamp;
- `alert_ids` preserve input order;
- `severity` is the highest canonical severity among members;
- the output grouping fields contain normalized values.

Canonical severity order for later implementation:

```text
informational < low < medium < high < critical
```

## 4. Alert Scenarios

| Scenario | Representative alerts | Purpose | Expected result |
|---|---|---|---|
| A. Repeated malware detection | 0001–0008 | Obvious duplicates plus case/space variations | One incident |
| B. Repeated failed logins | 0009–0015 | Event grouping when process and hash are unavailable | One incident |
| C. Same host, different process or hash | 0016–0020, 0031–0032, 0039 | Prove that changed grouping evidence prevents false merges | One repeated PowerShell incident plus distinct near-duplicates |
| D. Same hash across multiple hosts | 0021–0028, 0036 | Demonstrate endpoint grouping rather than campaign correlation | Separate incidents for WS-003, WS-004, and WS-005 |
| E. Missing optional fields | 0009–0015, 0021–0028, 0037–0038 | Exercise omitted, `null`, blank, and explicit `unknown` values | No crash; missing values normalize to `unknown` |

The scenarios overlap intentionally: a single alert can test both a security story and a normalization edge case. Together they still produce five repeated groups and twelve singleton incidents.

## 5. Duplicate Groups

| Group | Alert IDs | Scenario | Count | Expected incident |
|---|---|---|---:|---|
| G1 | ALERT-0001â€“ALERT-0008 | Repeated malware on WS-001 | 8 | INC-001 |
| G2 | ALERT-0009â€“ALERT-0015 | Failed logins on SRV-DC-01 | 7 | INC-002 |
| G3 | ALERT-0016â€“ALERT-0020 | Suspicious PowerShell on WS-002 | 5 | INC-003 |
| G4 | ALERT-0021â€“ALERT-0024 | Shared malware hash on WS-003 | 4 | INC-004 |
| G5 | ALERT-0025â€“ALERT-0028 | Shared malware hash on WS-004 | 4 | INC-005 |

G4 and G5 use the same process and SHA-256. They stay separate because `host` is part of the key. That behavior is incident-oriented endpoint grouping, not campaign correlation.

## 6. Near-Duplicate Cases

| Alert | Resembles | Changed grouping field | Expected result |
|---|---|---|---|
| ALERT-0029 | G1 | `file_hash` | New incident |
| ALERT-0030 | G1 | `event_type` | New incident |
| ALERT-0031 | G3 | `file_hash` | New incident |
| ALERT-0036 | G1 | `host` | New incident |
| ALERT-0039 | G3 | `process_name` and `file_hash` | New incident |
| ALERT-0040 | G3 | `user` | New incident |
| G5 | G4 | `host` | Separate repeated group |

These cases prevent a weak implementation from grouping only by hash, only by host, or by an incomplete subset of the configured fields.

## 7. Non-Duplicate Singleton Cases

| Alert | Activity | Separation reason |
|---|---|---|
| ALERT-0029 | Invoice-like malware alert | Different SHA-256 |
| ALERT-0030 | Process creation | Different event type |
| ALERT-0031 | PowerShell script execution | Different SHA-256 |
| ALERT-0032 | Credential access | Different event type, process, and hash |
| ALERT-0033 | Service-account login failure | Different user |
| ALERT-0034 | Outbound network connection | Unique event/process/hash tuple |
| ALERT-0035 | Scheduled backup process | Unique event/process/hash tuple |
| ALERT-0036 | Shared malware on WS-005 | Different host |
| ALERT-0037 | Credential access with missing context | Unique host/event tuple |
| ALERT-0038 | Failed login with missing context | Event type differs from ALERT-0037 |
| ALERT-0039 | PowerShell Core execution | Different process and hash |
| ALERT-0040 | PowerShell by admin.local | Different user |

## 8. Missing-Field and Normalization Coverage

| Behavior | Representative alerts | Expected normalization |
|---|---|---|
| Lower/upper casing | 0002â€“0005, 0012, 0017â€“0018, 0023, 0027 | Lowercase |
| Leading/trailing spaces | 0006, 0008, 0012, 0018, 0020, 0024, 0028 | Trim |
| Explicit `null` | 0009, 0014â€“0015, 0021, 0025, 0033, 0037 | `unknown` |
| Omitted key | 0010, 0013, 0022, 0026, 0037â€“0038 | `unknown` |
| Blank/whitespace string | 0011, 0024, 0028 | `unknown` |
| Same hash, different host | 0021â€“0028 and 0036 | Separate by host |

Required fields are never intentionally missing. Only optional context is malformed or absent.

## 9. Expected Output

The oracle contains 17 incident objects:

- INC-001 through INC-005 represent the five repeated groups.
- INC-006 through INC-017 represent ALERT-0029 through ALERT-0040 as singletons.
- All grouping fields are normalized.
- G3 resolves to `critical` because ALERT-0019 is critical.
- Every input alert ID appears exactly once in the expected output.

Reduction calculation:

```text
(40 raw alerts - 17 expected incidents) / 40 raw alerts = 57.5%
```

This is a correctness benchmark, not a performance benchmark. Phase 4 output should match the expected file structurally.

## 10. Data Quality and Safety Rules

- Alert IDs are unique and sequential.
- Timestamps are valid ISO 8601 UTC strings.
- Present hashes are lowercase or intentionally case-varied 64-character hexadecimal SHA-256 values.
- Case and whitespace defects exist only where documented.
- The `mock-wazuh` source makes the synthetic origin explicit.
- `example.invalid` is reserved for examples and cannot resolve as a normal public domain.
- Encoded PowerShell content is replaced with `<REDACTED_SYNTHETIC_PAYLOAD>`.
- No real IP address, hostname, credential, raw log, or executable is included.

## 11. Known Benchmark Limitations

- No time-window behavior is tested because v1 has no time window.
- Cross-host campaign correlation is intentionally out of scope.
- Command line and parent process provide evidence but do not affect grouping.
- Multiple missing grouping values can cause over-grouping; ALERT-0037 and ALERT-0038 demonstrate that `event_type` still prevents one obvious false merge.
- The oracle assumes input-order incident IDs. A future stable-ID design may choose content-derived identifiers instead.

## References

- [Data research and source rationale](data_research.md)
- [Phase 2 plan](https://app.notion.com/p/379ea4a7d0dd80bd9022f3935343b915)
