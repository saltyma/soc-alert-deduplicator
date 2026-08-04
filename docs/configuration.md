# Configuration Guide

## Purpose

`config.json` is the versioned grouping policy. It lets a SOC administrator or detection engineer change which normalized alert attributes define an incident without editing Python code.

## Default policy

```json
{
  "group_by": [
    "host",
    "user",
    "event_type",
    "process_name",
    "file_hash"
  ],
  "case_sensitive": false,
  "missing_value": "unknown",
  "minimum_match_score": 1.0
}
```

| Setting | Meaning | Version 1 rule |
|---|---|---|
| `group_by` | Ordered fields used to build the exact group key | Nonempty, unique, supported names |
| `case_sensitive` | Whether text case changes grouping | Boolean |
| `missing_value` | Canonical value for omitted, null, or blank fields | Nonempty string |
| `minimum_match_score` | Threshold reserved for match scoring | Exactly `1.0` |

## Supported grouping fields

- `source`
- `host`
- `user`
- `event_type`
- `process_name`
- `target_process_name`
- `parent_process_name`
- `command_line`
- `file_hash`
- `severity`
- `rule_name`

The order is preserved in each incident's `grouping_fields` evidence, although changing only the order does not change which alerts have identical tuples.

## Normalization

For each configured field, the processor:

1. reads the value without modifying the original alert;
2. maps absent, `null`, or blank values to `missing_value`;
3. converts values to text;
4. trims surrounding whitespace; and
5. applies case folding when `case_sensitive` is `false`.

This means `WS-001`, `ws-001`, and `  WS-001  ` group together under the default policy.

## Tuning examples

### Broader host/event grouping

```json
{
  "group_by": ["host", "event_type"],
  "case_sensitive": false,
  "missing_value": "unknown",
  "minimum_match_score": 1.0
}
```

This produces fewer incidents but increases the chance of grouping unrelated processes or users on one host.

### Strict process-chain grouping

```json
{
  "group_by": [
    "host",
    "user",
    "process_name",
    "target_process_name",
    "parent_process_name",
    "command_line",
    "file_hash"
  ],
  "case_sensitive": false,
  "missing_value": "unknown",
  "minimum_match_score": 1.0
}
```

This reduces false grouping but can fragment activity when command-line arguments differ slightly.

## Safe change procedure

1. Copy the current policy and change one decision at a time.
2. Run the same reviewed demo or a sanitized operational sample.
3. Compare incident count, group evidence, and alert-ID preservation.
4. Inspect groups dominated by `unknown` values.
5. Have an analyst review both unexpected merges and unexpected splits.
6. Version-control the approved policy with a short rationale.

Configuration changes are security-relevant. A syntactically valid policy can still hide distinct activity by grouping too broadly.
