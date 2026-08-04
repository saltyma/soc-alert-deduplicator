# Configuration

SMART mode profiles each batch automatically. A configuration file is optional and should be used only when a reviewed operational requirement must override the inferred threshold, time window, evidence count, fields, weights, or candidate cap.

## SMART tuning schema

```json
{
  "threshold": 0.88,
  "time_window_minutes": 20,
  "min_evidence_fields": 3,
  "include_fields": ["command_line"],
  "exclude_fields": ["description"],
  "field_weights": {
    "host": 4.0,
    "file_hash": 7.0,
    "command_line": 2.0
  },
  "max_candidates": 150
}
```

Every property is optional.

| Property | Accepted value | Effect |
|---|---|---|
| `threshold` | number from `0.5` to `1.0` | Minimum weighted match score; higher values reduce merges and increase splits |
| `time_window_minutes` | integer from `1` to `10080` | Maximum inactivity gap between related alerts |
| `min_evidence_fields` | integer from `1` to `8` | Minimum number of meaningfully matching fields unless a strong hash match exists |
| `include_fields` | unique list of supported fields | Keeps fields in the similarity profile even when batch coverage is low |
| `exclude_fields` | unique list of supported fields | Removes fields from similarity scoring |
| `field_weights` | supported field to number from `>0` to `10` | Replaces inferred weights for selected fields |
| `max_candidates` | integer from `10` to `5000` | Caps clusters evaluated per alert; larger values trade speed for recall |

Supported SMART evidence fields:

- `source`
- `host`
- `user`
- `event_type`
- `process_name`
- `target_process_name`
- `parent_process_name`
- `command_line`
- `file_hash`
- `rule_name`
- `description`

The parser rejects unknown properties, unsupported fields, duplicate list items, booleans used as numbers, invalid ranges, non-object documents, malformed JSON, and unreadable files.

Use a tuning file:

```powershell
soc-alert-deduplicator `
  --input alerts.ndjson `
  --config smart-tuning.json `
  --output incidents.json
```

## Interpreting the profile sidecar

Every SMART run writes a `.profile.json` document. Review these sections before approving a tuning change:

- `similarity_fields` and `field_weights`: evidence considered by the scorer;
- `blocking_fields`: high-coverage fields used to narrow candidates;
- `coverage`: populated fraction of each field;
- `distinct_ratio`: field cardinality among populated values;
- `threshold`, `time_window_minutes`, and `min_evidence_fields`;
- `rationale`: short explanations of the inferred decisions;
- `input.sources`: detected formats, mapped fields, record counts, and warnings; and
- `output`: incident count and reduction percentage.

A high reduction percentage is not automatically desirable. Review representative merges and splits, especially when important fields have low coverage.

## Safe tuning procedure

1. Keep the raw input and previous profile immutable.
2. Establish a reviewed sample containing known duplicate and non-duplicate cases.
3. Change one tuning decision at a time.
4. Compare alert preservation, incident count, largest clusters, confidence distribution, and identity variation.
5. Inspect sparse clusters and source warnings.
6. Record the approved tuning file with its dataset and rationale.

Lower thresholds, longer windows, fewer evidence fields, and larger candidate caps can broaden grouping. Excluding identity fields can increase false merges. The engine still enforces host, hash, process, target-process, event, and time safety boundaries where those values are populated.

## Exact-policy mode

Exact mode uses the legacy `config.json` contract:

```json
{
  "group_by": ["host", "user", "event_type", "process_name", "file_hash"],
  "case_sensitive": false,
  "missing_value": "unknown",
  "minimum_match_score": 1.0
}
```

Run it explicitly:

```powershell
soc-alert-deduplicator `
  --mode exact `
  --input normalized-alerts.json `
  --config config.json `
  --output exact-incidents.json
```

`group_by` must be a nonempty unique list of supported normalized fields. Missing, null, or blank values map to `missing_value`; case folding is controlled by `case_sensitive`. Exact mode accepts only a `minimum_match_score` of `1.0`.
