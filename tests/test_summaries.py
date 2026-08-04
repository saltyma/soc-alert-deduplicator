from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from soc_alert_deduplicator.config import Settings
from soc_alert_deduplicator.deduplication import group_alerts
from soc_alert_deduplicator.io import Alert
from soc_alert_deduplicator.summaries import build_incidents


def test_build_incidents_aggregates_group_metadata(
    settings: Settings,
    make_alert: Callable[..., Alert],
) -> None:
    later = make_alert(
        alert_id="A-1",
        timestamp="2026-06-01T10:10:00Z",
        severity="high",
    )
    earlier = make_alert(
        alert_id="A-2",
        timestamp="2026-06-01T10:00:00Z",
        severity="critical",
        rule_name="Escalated Synthetic Detection",
    )

    incidents = build_incidents(group_alerts([later, earlier], settings), settings)

    assert incidents == [
        {
            "incident_id": "INC-001",
            "alert_count": 2,
            "grouping_fields": {
                "host": "ws-001",
                "user": "analyst.lab",
                "event_type": "malware_detection",
                "process_name": "sample.exe",
                "file_hash": "a" * 64,
            },
            "host": "ws-001",
            "user": "analyst.lab",
            "event_type": "malware_detection",
            "process_name": "sample.exe",
            "file_hash": "a" * 64,
            "severity": "critical",
            "first_seen": "2026-06-01T10:00:00Z",
            "last_seen": "2026-06-01T10:10:00Z",
            "alert_ids": ["A-1", "A-2"],
            "summary": (
                "2 malware_detection alerts grouped for host ws-001 "
                "and user analyst.lab."
            ),
        }
    ]


def test_single_alert_summary_uses_singular_noun(
    settings: Settings,
    make_alert: Callable[..., Alert],
) -> None:
    groups = group_alerts([make_alert(alert_id="A-1")], settings)

    incident = build_incidents(groups, settings)[0]

    assert incident["summary"] == (
        "1 malware_detection alert grouped for host ws-001 and user analyst.lab."
    )


def test_non_grouped_context_reports_multiple_values(
    settings: Settings,
    make_alert: Callable[..., Alert],
) -> None:
    event_only = replace(settings, group_by=("event_type",))
    alerts = [
        make_alert(alert_id="A-1", host="WS-001", user="first.lab"),
        make_alert(alert_id="A-2", host="WS-002", user="second.lab"),
    ]

    incident = build_incidents(group_alerts(alerts, event_only), event_only)[0]

    assert incident["grouping_fields"] == {"event_type": "malware_detection"}
    assert incident["host"] == "multiple"
    assert incident["user"] == "multiple"
    assert incident["process_name"] == "sample.exe"


def test_build_incidents_preserves_first_group_order(
    settings: Settings,
    make_alert: Callable[..., Alert],
) -> None:
    alerts = [
        make_alert(alert_id="A-1", host="WS-002"),
        make_alert(alert_id="A-2", host="WS-001"),
    ]

    incidents = build_incidents(group_alerts(alerts, settings), settings)

    assert [incident["incident_id"] for incident in incidents] == [
        "INC-001",
        "INC-002",
    ]
    assert [incident["host"] for incident in incidents] == ["ws-002", "ws-001"]


def test_empty_groups_produce_no_incidents(settings: Settings) -> None:
    assert build_incidents([], settings) == []
