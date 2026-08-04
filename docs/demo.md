# Demo and Verification Guide

## Claim being demonstrated

Under the default grouping policy, 40 public-safe synthetic alerts become 17 deterministic incident summaries, reducing queue items by 57.5% while preserving every source alert ID exactly once.

| Artifact | Role |
|---|---|
| [`data/demo_before.json`](../data/demo_before.json) | Recruiter-friendly before file |
| [`data/demo_after.json`](../data/demo_after.json) | Reviewed after file and test oracle |
| [`data/demo/raw_alerts.json`](../data/demo/raw_alerts.json) | Canonical research dataset |
| [`data/demo/expected_incidents.json`](../data/demo/expected_incidents.json) | Canonical byte-for-byte oracle |

The before/after aliases are exact copies of the canonical files. Tests verify the generated output against the canonical oracle.

## Desktop demo

```powershell
pip install -e .
soc-alert-deduplicator-gui --demo
```

The dashboard loads the verified files, writes `output.json`, and presents:

- raw alert and incident counts;
- queue reduction percentage;
- highest incident severity;
- a searchable, sortable, severity-filtered incident queue;
- source alert IDs and normalized context for the selected incident; and
- JSON and CSV export actions.

![Verified dark dashboard](demo/gui-dashboard.png)

## CLI demo

```powershell
soc-alert-deduplicator `
  --input data/demo_before.json `
  --config config.json `
  --output output.json
```

```text
Processed 40 alerts into 17 incidents.
Output written to output.json.
```

Verify that the output is the reviewed result:

```powershell
Compare-Object `
  (Get-Content output.json) `
  (Get-Content data/demo_after.json)
```

No output means the files match line for line. The automated integration test is stricter and compares bytes directly.

## Scenario coverage

The dataset includes:

- exact duplicates;
- case and surrounding-whitespace variants;
- omitted, null, and blank optional values;
- near duplicates that must remain separate;
- unrelated alerts;
- repeated file hashes on different hosts; and
- informational through critical severities.

All people, hosts, commands, hashes, and detection names are fictional. See [Dataset Design](dataset_design.md) for the scenario-by-scenario oracle.

## Screenshot reproduction

The committed dashboard screenshot is rendered by the application itself:

```powershell
$env:PYTHONPATH = "src"
$env:QT_QPA_PLATFORM = "offscreen"
python -m soc_alert_deduplicator.gui `
  --demo `
  --output docs/demo/gui_demo_output.json `
  --screenshot docs/demo/gui-dashboard.png
```

The screenshot path is optional during normal interactive use.
