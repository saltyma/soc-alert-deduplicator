from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from soc_alert_deduplicator.insights import TimelineBucket
from soc_alert_deduplicator.investigation import (
    AlertTableModel,
    GroupingDiagram,
    HorizontalBarChart,
    IncidentDetailDialog,
    RelationshipDiagram,
    TimelineChart,
)
from soc_alert_deduplicator.io import Alert, Incident


def incident_and_alerts() -> tuple[Incident, list[Alert]]:
    alerts: list[Alert] = [
        {
            "alert_id": "A-1",
            "timestamp": "2026-06-01T08:15:00Z",
            "source": "sysmon",
            "host": "dc-01",
            "user": "svc.backup",
            "event_type": "sysmon_10_process_access",
            "process_name": "wmiprvse.exe",
            "parent_process_name": "services.exe",
            "target_process_name": "lsass.exe",
            "command_line": "wmiprvse.exe -secured",
            "severity": "critical",
            "description": "Process requested access",
            "source_record": {"EventID": 10},
        },
        {
            "alert_id": "A-2",
            "timestamp": "2026-06-01T08:17:00Z",
            "source": "sysmon",
            "host": "dc-01",
            "user": "svc.backup",
            "event_type": "sysmon_10_process_access",
            "process_name": "wmiprvse.exe",
            "target_process_name": "lsass.exe",
            "severity": "high",
        },
    ]
    incident: Incident = {
        "incident_id": "INC-0001",
        "alert_count": 2,
        "grouping_fields": {"host": "dc-01"},
        "host": "dc-01",
        "user": "svc.backup",
        "event_type": "sysmon_10_process_access",
        "process_name": "wmiprvse.exe",
        "target_process_name": "lsass.exe",
        "file_hash": "unknown",
        "severity": "critical",
        "first_seen": alerts[0]["timestamp"],
        "last_seen": alerts[1]["timestamp"],
        "alert_ids": ["A-1", "A-2"],
        "summary": "Two process-access alerts",
        "source_formats": ["sysmon-xml"],
        "deduplication": {
            "profile_id": "smart-v2-test",
            "match_type": "similar",
            "confidence": 0.94,
            "evidence_fields": ["host", "event_type", "process_name"],
            "time_window_minutes": 5,
        },
    }
    return incident, alerts


def test_native_charts_render_and_expose_accessible_summaries(qtbot: QtBot) -> None:
    bars = HorizontalBarChart("Severity")
    qtbot.addWidget(bars)
    bars.resize(360, 180)
    bars.set_data([("Critical", 4, "#FF5D73"), ("High", 2, "#FF8A4C")])
    bars.show()
    QApplication.processEvents()
    assert bars.data_points[0][1] == 4
    assert "Critical: 4" in bars.accessibleDescription()
    assert not bars.grab().isNull()

    now = datetime(2026, 6, 1, 8, 0, tzinfo=timezone.utc)
    timeline = TimelineChart()
    qtbot.addWidget(timeline)
    timeline.resize(480, 180)
    timeline.set_buckets(
        [
            TimelineBucket("08:00", 2, now, now),
            TimelineBucket("08:05", 5, now, now),
        ]
    )
    timeline.show()
    QApplication.processEvents()
    assert timeline.buckets[-1].count == 5
    assert "08:05: 5" in timeline.accessibleDescription()
    assert not timeline.grab().isNull()


def test_relationship_and_grouping_diagrams_render(qtbot: QtBot) -> None:
    incident, _ = incident_and_alerts()
    relationship = RelationshipDiagram()
    grouping = GroupingDiagram()
    qtbot.addWidget(relationship)
    qtbot.addWidget(grouping)
    relationship.resize(620, 190)
    grouping.resize(620, 190)
    relationship.set_incident(incident)
    grouping.set_incident(incident)
    relationship.show()
    grouping.show()
    QApplication.processEvents()

    assert "wmiprvse.exe" in relationship.accessibleDescription()
    assert "2 source alerts" in grouping.accessibleDescription()
    assert not relationship.grab().isNull()
    assert not grouping.grab().isNull()


def test_alert_table_model_uses_readable_values() -> None:
    _, alerts = incident_and_alerts()
    model = AlertTableModel(alerts)

    assert model.rowCount() == 2
    assert model.columnCount() == 7
    assert model.headerData(3, Qt.Orientation.Horizontal) == "Event"
    assert model.data(model.index(0, 3)) == "Sysmon process access (Event 10)"
    assert model.data(model.index(0, 0)).endswith("UTC")
    assert model.data(model.index(0, 0), Qt.ItemDataRole.UserRole) is alerts[0]
    assert model.data(model.index(0, 1), Qt.ItemDataRole.ForegroundRole).isValid()


def test_investigation_dialog_progressively_discloses_evidence(qtbot: QtBot) -> None:
    incident, alerts = incident_and_alerts()
    dialog = IncidentDetailDialog(incident, alerts)
    qtbot.addWidget(dialog)
    dialog.show()
    QApplication.processEvents()

    assert dialog.tabs.count() == 4
    assert [dialog.tabs.tabText(index) for index in range(4)] == [
        "Overview",
        "Timeline",
        "Why grouped",
        "Source alerts (2)",
    ]
    assert "wmiprvse.exe accessed lsass.exe" in dialog.windowTitle()
    assert dialog.alert_model.rowCount() == 2
    assert dialog.timeline_chart.buckets
    assert "grouping certainty" in dialog.incident_brief()

    dialog.tabs.setCurrentIndex(3)
    dialog.alert_table.selectRow(1)
    QApplication.processEvents()
    assert '"alert_id": "A-2"' in dialog.alert_detail.toPlainText()

    dialog.copy_incident_brief()
    assert "Why it matters" in QApplication.clipboard().text()
    assert dialog.copy_button.text() == "Copied"
