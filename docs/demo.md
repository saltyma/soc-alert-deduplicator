# Demo and Verification

## Adaptive sample

The bundled 40-record sample becomes 17 SMART incidents with no configuration. All 40 alert IDs are preserved exactly once.

```powershell
soc-alert-deduplicator `
  --input data/demo/raw_alerts.json `
  --output output.v2.json
```

Expected output:

```text
Processed 40 alerts into 17 incidents.
Output written to output.v2.json.
SMART profile SP-...: json; 40-minute window.
Profile written to output.v2.profile.json.
```

Review the sidecar to see detected format, field coverage, inferred threshold, selected evidence, time window, warnings, and reduction.

## Desktop walkthrough

```powershell
soc-alert-deduplicator-gui --demo
```

The desktop run demonstrates:

- automatic format and schema detection;
- inferred evidence fields and profile metadata;
- alert, incident, reduction, and severity metrics;
- numeric alert-count and confidence sorting;
- search and severity filtering;
- source/target process context and source IDs;
- JSON output and safe CSV export; and
- collapsible, scrollable controls with responsive queue layout.

![Adaptive desktop dashboard](demo/gui-dashboard-v2.png)

## Exact compatibility oracle

The reviewed exact-policy benchmark remains available for compatibility tests:

```powershell
soc-alert-deduplicator `
  --mode exact `
  --input data/demo/raw_alerts.json `
  --config config.json `
  --output exact-output.json
```

`exact-output.json` must match `data/demo/expected_incidents.json` byte for byte. The suite also verifies that all 40 IDs appear exactly once.

## Scenario coverage

The sample contains repeated detections, casing and whitespace variations, omitted/null/blank optional values, near duplicates that should remain separate, unrelated records, hashes reused across hosts, and the full informational-to-critical severity range.

All sample identities, commands, hostnames, and hashes are fictional. It is a correctness fixture; use [the public raw-telemetry validation](real_data_test.md) for a larger ingestion and performance run.

## Reproduce the screenshot

```powershell
$env:PYTHONPATH = "src"
$env:QT_QPA_PLATFORM = "offscreen"
python -m soc_alert_deduplicator.gui `
  --demo `
  --screenshot docs/demo/gui-dashboard-v2.png
```
