# Desktop Interface

## Workflow

The Incident Clarity Console provides one local workflow for input selection, adaptive analysis, queue review, and export:

1. Select or drop one or more telemetry files.
2. Keep **SMART / Automatic** selected, or switch to **Exact / Manual policy**.
3. Optionally select a SMART tuning document or exact policy.
4. Choose the JSON output path and run the analysis.
5. Review the inferred profile, queue metrics, incidents, confidence, evidence, and source IDs.
6. Search, filter, sort, copy a summary, open the JSON, or export CSV.

The profile note shows the inferred profile ID, source formats, threshold, and time window after a SMART run. Evidence-field chips update to show the fields actually selected for scoring.

## Responsive behavior

The interface uses Qt layouts and splitters rather than fixed coordinates.

- The controls area scrolls independently while **Analyze telemetry** remains visible.
- **Controls** collapses or restores the entire sidebar.
- Metric cards use four columns on wide displays and a 2×2 grid when space is limited.
- Queue controls move below the title on compact layouts.
- First/last timestamp columns hide when the queue becomes too narrow.
- Sidebar and dashboard widths can be adjusted with the splitter.
- The window starts within the current screen's available geometry and supports a 900×620 minimum.

## Queue behavior

The table is backed by `QAbstractTableModel` and `QSortFilterProxyModel`. Typed sort values are exposed through a dedicated model role:

- alert count sorts as an integer;
- confidence sorts as a floating-point value;
- severity sorts by the defined informational-to-critical rank; and
- text sorts case-insensitively.

This prevents values such as `10` from appearing before `2` in ascending order. Filtering and sorting affect only the view and never rewrite the incident output.

## Keyboard and pointer controls

- `Ctrl+O`: select telemetry input.
- `Ctrl+R`: run the current analysis.
- Drag and drop: add one or more supported local files.
- Column header: toggle sort order.
- Incident row: show summary, identity context, confidence, and source IDs.

## Visual system

- Neutral near-black surfaces support dense queue review without excessive contrast.
- Mint indicates primary actions and successful local status.
- Severity uses a consistent informational, low, medium, high, and critical palette.
- Segoe UI is used for interface hierarchy; Consolas is reserved for identifiers and evidence.
- Borders, spacing, and typography provide hierarchy without decorative charts or animation.

## Data and process boundary

`gui.py` owns widgets and interaction only. SMART analysis calls `run_smart_pipeline`; exact analysis calls the same validated exact modules used by the CLI. CSV output is derived from the in-memory incident list using the shared safe exporter.

Opening JSON uses the operating system's registered file handler. No telemetry content is sent over the network by the application.

## Screenshot reproduction

```powershell
$env:PYTHONPATH = "src"
$env:QT_QPA_PLATFORM = "offscreen"
python -m soc_alert_deduplicator.gui `
  --demo `
  --screenshot docs/demo/gui-dashboard-v2.png
```

Screenshot mode renders at 1360×850 for stable documentation output and then exits.
