# Desktop Interface

## Workflow

The Incident Clarity Console provides one local workflow for input selection, adaptive analysis, queue review, and export:

1. Select or drop one or more telemetry files.
2. Keep **SMART / Automatic** selected, or switch to **Exact / Manual policy**.
3. Optionally select a SMART tuning document or exact policy.
4. Choose the JSON output path and run the analysis.
5. Read the live severity, host-volume, and alert-activity summaries for the current view.
6. Select an incident for a concise explanation, then double-click it or choose **Open investigation**.
7. Review the Overview, Timeline, Why grouped, and Source alerts tabs; copy a brief, open JSON, or export CSV as needed.

The profile note shows the inferred profile ID, source formats, threshold, and time window after a SMART run. Evidence-field chips update to show the fields actually selected for scoring.

## Responsive behavior

The interface uses Qt layouts and splitters rather than fixed coordinates.

- The controls area scrolls independently while **Analyze telemetry** remains visible.
- **Controls** collapses or restores the entire sidebar.
- Metric cards use four columns on wide displays and a 2×2 grid when space is limited.
- Queue controls move below the title on compact layouts.
- The host-volume panel hides on narrow dashboards while severity and timeline context remain available.
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

The three queue visuals follow the same filters as the table. Their titles and values are painted directly with Qt and also exposed as accessible text, so no color lookup or hover interaction is required to understand a value.

## Investigation workspace

The main queue uses progressive disclosure: the preview answers “what happened?” and “why was it grouped?” without filling the workspace with every raw field. The investigation window then separates deeper evidence into four tasks:

- **Overview** gives the plain-language narrative, cautious risk context, process-to-target relationship, time bounds, host/user context, and recommended checks.
- **Timeline** charts alert volume through the incident window and provides a chronological event table.
- **Why grouped** shows the source-alert-to-incident decision flow, evidence fields, strategy, profile, continuity window, and a reminder that grouping confidence is not maliciousness probability.
- **Source alerts** keeps a virtualized table responsive, then reveals the complete normalized record and retained source provenance for the selected row.

## Keyboard and pointer controls

- `Ctrl+O`: select telemetry input.
- `Ctrl+R`: run the current analysis.
- Drag and drop: add one or more supported local files.
- Column header: toggle sort order.
- Incident row: show a plain-language preview and grouping reason.
- Double-click or Enter on an incident: open the full investigation.

## Visual system

- Neutral near-black surfaces support dense queue review without excessive contrast.
- Mint indicates primary actions and successful local status.
- Severity uses a consistent informational, low, medium, high, and critical palette.
- Segoe UI is used for interface hierarchy; Consolas is reserved for identifiers and evidence.
- Charts use direct labels, restrained color, and meaningful data only; diagrams explain relationships and grouping flow instead of adding decoration.

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
