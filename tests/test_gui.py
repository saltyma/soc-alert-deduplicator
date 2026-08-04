from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from soc_alert_deduplicator.gui import (
    IncidentFilterProxy,
    IncidentTableModel,
    MainWindow,
    build_parser,
    discover_project_root,
    highest_severity,
    noise_reduction_percent,
)
from soc_alert_deduplicator.io import Incident

from conftest import DEFAULT_CONFIG, DEMO_ALERTS, EXPECTED_INCIDENTS, PROJECT_ROOT


def benchmark_incidents() -> list[Incident]:
    return json.loads(EXPECTED_INCIDENTS.read_text(encoding="utf-8"))


def test_dashboard_metrics_helpers() -> None:
    incidents = benchmark_incidents()

    assert noise_reduction_percent(40, 17) == 57.49999999999999
    assert noise_reduction_percent(0, 0) == 0.0
    assert noise_reduction_percent(2, 3) == 0.0
    assert highest_severity(incidents) == "critical"
    assert highest_severity([]) == "none"


def test_discover_project_root_finds_demo_checkout(tmp_path: Path) -> None:
    assert discover_project_root(PROJECT_ROOT) == PROJECT_ROOT
    assert discover_project_root(tmp_path) is None


def test_incident_model_exposes_values_headers_and_roles(qtbot: QtBot) -> None:
    model = IncidentTableModel()
    qtbot.addWidget(MainWindow(PROJECT_ROOT))
    model.set_incidents(benchmark_incidents()[:1])

    assert model.rowCount() == 1
    assert model.columnCount() == 8
    assert model.headerData(0, Qt.Orientation.Horizontal) == "Incident"
    assert model.data(model.index(0, 0)) == "INC-001"
    assert model.data(model.index(0, 5)) == "malware detection"
    assert model.data(model.index(0, 1), Qt.ItemDataRole.ForegroundRole).isValid()
    assert model.data(model.index(0, 2), Qt.ItemDataRole.TextAlignmentRole) == (
        Qt.AlignmentFlag.AlignCenter
    )
    assert model.data(model.index(0, 0), Qt.ItemDataRole.UserRole)["alert_count"] == 8


def test_incident_proxy_filters_by_text_and_severity() -> None:
    model = IncidentTableModel()
    model.set_incidents(benchmark_incidents())
    proxy = IncidentFilterProxy()
    proxy.setSourceModel(model)

    proxy.set_query("credential_access")
    assert proxy.rowCount() == 2
    proxy.set_query("")
    proxy.set_severity("critical")
    assert proxy.rowCount() == 2
    proxy.set_query("INC-003")
    assert proxy.rowCount() == 1


def test_incident_proxy_sorts_alert_counts_numerically() -> None:
    incidents = benchmark_incidents()[:2]
    incidents[0]["alert_count"] = 10
    incidents[1]["alert_count"] = 2
    model = IncidentTableModel()
    model.set_incidents(incidents)
    proxy = IncidentFilterProxy()
    proxy.setSourceModel(model)

    proxy.sort(2, Qt.SortOrder.AscendingOrder)

    first = proxy.mapToSource(proxy.index(0, 2))
    second = proxy.mapToSource(proxy.index(1, 2))
    assert model.incident_at(first.row())["alert_count"] == 2
    assert model.incident_at(second.row())["alert_count"] == 10


def test_main_window_runs_demo_filters_and_exports(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = MainWindow(PROJECT_ROOT)
    qtbot.addWidget(window)
    output = tmp_path / "incidents.json"
    window.input_path.setText(str(DEMO_ALERTS))
    window.config_path.setText(str(DEFAULT_CONFIG))
    window.output_path.setText(str(output))

    assert window.analyze(show_dialog=False)
    QApplication.processEvents()

    assert len(window.alerts) == 40
    assert len(window.incidents) == 17
    assert window.model.rowCount() == 17
    assert window.alert_metric.value.text() == "40"
    assert window.incident_metric.value.text() == "17"
    assert window.reduction_metric.value.text() == "57.5%"
    assert window.severity_metric.value.text() == "CRITICAL"
    written = json.loads(output.read_text(encoding="utf-8"))
    grouped_ids = [
        alert_id for incident in written for alert_id in incident["alert_ids"]
    ]
    assert len(grouped_ids) == 40
    assert len(set(grouped_ids)) == 40
    assert all(incident["deduplication"]["engine"] == "SMART" for incident in written)
    assert output.with_suffix(".profile.json").is_file()
    assert window.detail_id.text().startswith("INC-")

    window.search_box.setText("credential_access")
    assert window.proxy.rowCount() == 2
    window.search_box.clear()
    critical_index = window.severity_filter.findData("critical")
    window.severity_filter.setCurrentIndex(critical_index)
    assert window.proxy.rowCount() == 2

    csv_output = tmp_path / "incidents.csv"
    assert window.export_csv(csv_output, show_dialog=False)
    assert csv_output.is_file()


def test_main_window_reports_input_error_without_mutating_queue(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = MainWindow(PROJECT_ROOT)
    qtbot.addWidget(window)
    window.input_path.setText(str(tmp_path / "missing.json"))
    window.config_path.setText(str(DEFAULT_CONFIG))
    window.output_path.setText(str(tmp_path / "output.json"))

    assert not window.analyze(show_dialog=False)
    assert "input file not found" in window.last_error
    assert window.model.rowCount() == 0


def test_main_window_reflows_and_collapses_controls(qtbot: QtBot) -> None:
    window = MainWindow(PROJECT_ROOT)
    qtbot.addWidget(window)
    window.show()

    window.resize(900, 620)
    QApplication.processEvents()
    assert window._metric_columns == 2
    assert window.table.isColumnHidden(6)
    assert window.table.isColumnHidden(7)
    assert window.analyze_button.isVisible()

    window.resize(1360, 850)
    QApplication.processEvents()
    assert window._metric_columns == 4
    assert not window.table.isColumnHidden(6)
    assert not window.table.isColumnHidden(7)

    window.control_toggle.click()
    QApplication.processEvents()
    assert not window.sidebar.isVisible()
    assert window.control_toggle.text() == "Show controls"


def test_gui_parser_accepts_launch_options() -> None:
    args = build_parser().parse_args(
        [
            "--input",
            "alerts.json",
            "--config",
            "policy.json",
            "--output",
            "incidents.json",
            "--demo",
            "--screenshot",
            "dashboard.png",
        ]
    )

    assert args.input == Path("alerts.json")
    assert args.config == Path("policy.json")
    assert args.output == Path("incidents.json")
    assert args.demo is True
    assert args.screenshot == Path("dashboard.png")
