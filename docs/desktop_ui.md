# Desktop Interface

## Design intent

The desktop application is an analyst console, not a decorative shell. It keeps configuration, queue health, incident evidence, and export actions visible in one offline workflow.

The implementation uses Qt's main-window and model/view patterns through PySide6, the official Qt for Python bindings. Presentation remains separate from the deterministic processing modules.

## Workflow

1. Select or drop a JSON alert file.
2. Select the grouping policy and JSON destination.
3. Run the validated local pipeline.
4. Review alert count, incident count, reduction, and highest severity.
5. Search, sort, or filter the incident queue.
6. Select an incident to inspect its summary, host, user, process, and source IDs.
7. Open the canonical JSON or export a CSV working copy.

## Visual system

- Deep neutral surfaces reduce glare in a dense analyst view.
- Mint is reserved for primary actions and successful offline status.
- Severity uses a consistent informational-to-critical color scale.
- Segoe UI and Consolas provide readable interface and evidence text on Windows.
- Large metric values, compact table rows, and restrained borders create hierarchy without dashboard clutter.

## Interaction details

- `Ctrl+O`: choose an alert file.
- `Ctrl+R`: run analysis.
- Drag and drop: preselect a `.json` alert input.
- Search: matches incident ID, severity, host, user, event type, process, and summary.
- Severity filter: limits the queue without changing the generated output.
- Sorting: available on every table column.

## Architecture boundary

`gui.py` owns widgets and user interaction. It calls the same `load_settings`, `load_alerts`, `group_alerts`, `build_incidents`, and `write_incidents` functions used by the CLI. It does not contain a second grouping implementation.

The incident table uses `QAbstractTableModel` with `QSortFilterProxyModel`, keeping sorting and filtering separate from source incident data.

## Screenshot mode

For reproducible portfolio proof, the GUI can render itself without an interactive display:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m soc_alert_deduplicator.gui --demo --screenshot docs/demo/gui-dashboard.png
```

## Packaging direction

The repository provides `pyproject.toml` console entry points for both CLI and GUI. A future signed Windows executable can be produced with Qt's `pyside6-deploy` workflow after adding release signing and clean-machine verification.

## References

- [Qt for Python](https://doc.qt.io/qtforpython-6/index.html)
- [QMainWindow](https://doc.qt.io/qtforpython-6/PySide6/QtWidgets/QMainWindow.html)
- [Qt model/view table tutorial](https://doc.qt.io/qtforpython-6/tutorials/datavisualize/add_tableview.html)
- [pyside6-deploy](https://doc.qt.io/qtforpython-6/deployment/deployment-pyside6-deploy.html)
