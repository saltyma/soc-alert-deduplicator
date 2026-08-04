from __future__ import annotations

from datetime import timedelta

from soc_alert_deduplicator.insights import (
    alerts_for_incident,
    analyst_view,
    build_narrative,
    format_duration,
    format_timestamp,
    grouping_explanation,
    humanize_event,
    incident_duration,
    incident_story,
    incident_title,
    recommended_actions,
    risk_context,
    severity_distribution,
    timeline_buckets,
    top_hosts,
)
from soc_alert_deduplicator.io import Alert, Incident


def sample_incident(**overrides: object) -> Incident:
    incident: Incident = {
        "incident_id": "INC-0007",
        "alert_count": 3,
        "grouping_fields": {"host": "dc-01", "event_type": "process_access"},
        "host": "dc-01",
        "user": "svc.backup",
        "event_type": "sysmon_10_process_access",
        "process_name": "wmiprvse.exe",
        "target_process_name": "lsass.exe",
        "file_hash": "unknown",
        "severity": "critical",
        "first_seen": "2026-06-01T08:15:00Z",
        "last_seen": "2026-06-01T09:35:00Z",
        "alert_ids": ["A-1", "A-2", "A-3"],
        "summary": "Three source alerts",
        "deduplication": {
            "engine": "SMART",
            "profile_id": "smart-v2-1234",
            "match_type": "mixed",
            "confidence": 0.96,
            "evidence_fields": ["host", "event_type", "process_name"],
            "time_window_minutes": 120,
        },
        "source_formats": ["sysmon-xml"],
    }
    incident.update(overrides)
    return incident


def sample_alert(alert_id: str, timestamp: str) -> Alert:
    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "source": "sysmon",
        "host": "dc-01",
        "event_type": "sysmon_10_process_access",
        "severity": "critical",
    }


def test_event_labels_and_time_formatting_are_readable() -> None:
    assert humanize_event("sysmon_10_process_access") == (
        "Sysmon process access (Event 10)"
    )
    assert humanize_event("failed_login") == "Failed sign-in"
    assert humanize_event("custom-network event") == "Custom network event"
    assert format_timestamp("2026-06-01T08:15:00Z") == "2026-06-01 08:15:00 UTC"
    assert format_timestamp("not-a-time") == "not-a-time"
    assert format_timestamp(None) == "Unknown"


def test_duration_labels_cover_short_and_long_activity() -> None:
    assert format_duration(timedelta()) == "single point in time"
    assert format_duration(timedelta(seconds=12)) == "under 1 minute"
    assert format_duration(timedelta(minutes=1)) == "1 minute"
    assert format_duration(timedelta(minutes=31)) == "31 minutes"
    assert format_duration(timedelta(hours=1)) == "1 hour"
    assert format_duration(timedelta(hours=2, minutes=7)) == "2 hours 7 min"
    assert format_duration(timedelta(days=1)) == "1 day"
    assert format_duration(timedelta(days=2, hours=3)) == "2 days 3 hr"
    assert incident_duration(sample_incident()) == timedelta(hours=1, minutes=20)
    assert incident_duration(sample_incident(first_seen="bad")) == timedelta()
    assert (
        incident_duration(
            sample_incident(
                first_seen="2026-06-01T09:00:00Z",
                last_seen="2026-06-01T08:00:00Z",
            )
        )
        == timedelta()
    )


def test_narrative_explains_activity_risk_and_grouping() -> None:
    incident = sample_incident()

    assert incident_title(incident) == "wmiprvse.exe accessed lsass.exe"
    assert "3 source alerts were grouped" in incident_story(incident)
    assert "1 hour 20 min" in incident_story(incident)
    assert "LSASS" in risk_context(incident)
    assert "96%" in grouping_explanation(incident)
    assert "not the probability" in grouping_explanation(incident)
    assert len(recommended_actions(incident)) == 3

    narrative = build_narrative(incident)
    assert narrative.title == incident_title(incident)
    exported = analyst_view(incident)
    assert exported["title"] == narrative.title
    assert len(exported["recommended_checks"]) == 3


def test_narrative_fallbacks_and_context_specific_checks() -> None:
    generic = sample_incident(
        event_type="network_connection",
        process_name=None,
        target_process_name=None,
        user=None,
        deduplication={},
        grouping_fields={},
    )
    assert incident_title(generic) == "Network connection on dc-01"
    assert "1 source alert" in incident_story(sample_incident(alert_count=1))
    assert "not a threat verdict" in risk_context(generic)
    assert "available alert context" in grouping_explanation(generic)

    authentication = sample_incident(
        event_type="failed_login", process_name="", target_process_name=""
    )
    assert "authentication failures" in risk_context(authentication)
    assert "later success" in recommended_actions(authentication)[0]

    command = sample_incident(
        event_type="process_create",
        process_name="powershell.exe",
        target_process_name="",
    )
    assert incident_title(command) == "powershell.exe started on dc-01"
    assert "Command interpreters" in risk_context(command)
    assert "command line" in recommended_actions(command)[0]

    file_event = sample_incident(
        event_type="file_create",
        process_name="",
        target_process_name="payload.dll",
    )
    assert incident_title(file_event) == "File activity affected payload.dll"
    assert "artifact validation" in risk_context(file_event)
    assert "file hash" in recommended_actions(file_event)[0]


def test_queue_summaries_and_alert_resolution() -> None:
    incidents = [
        sample_incident(),
        sample_incident(
            incident_id="INC-0008",
            severity="high",
            host="ws-02",
            alert_count=2,
            alert_ids=["A-4", "A-5"],
        ),
        sample_incident(
            incident_id="INC-0009",
            severity="critical",
            host="dc-01",
            alert_count=1,
            alert_ids=["A-6"],
        ),
    ]
    assert severity_distribution(incidents) == [("Critical", 2), ("High", 1)]
    assert severity_distribution(incidents, weight_by_alerts=True) == [
        ("Critical", 4),
        ("High", 2),
    ]
    assert top_hosts(incidents) == [("dc-01", 4), ("ws-02", 2)]
    assert top_hosts(incidents, limit=1) == [("dc-01", 4)]

    alerts = [
        sample_alert("A-2", "2026-06-01T08:16:00Z"),
        sample_alert("A-1", "2026-06-01T08:15:00Z"),
    ]
    assert [item["alert_id"] for item in alerts_for_incident(incidents[0], alerts)] == [
        "A-1",
        "A-2",
    ]
    fallback = sample_incident(alert_ids=[], incident_id="I-FALLBACK")
    alerts[0]["incident_id"] = "I-FALLBACK"
    assert alerts_for_incident(fallback, alerts) == [alerts[0]]


def test_timeline_buckets_handle_empty_single_and_ranged_data() -> None:
    assert timeline_buckets([]) == []
    assert timeline_buckets([sample_alert("A-1", "bad")]) == []
    single = timeline_buckets(
        [
            sample_alert("A-1", "2026-06-01T08:15:00Z"),
            sample_alert("A-2", "2026-06-01T08:15:00Z"),
        ]
    )
    assert len(single) == 1
    assert single[0].count == 2

    ranged = timeline_buckets(
        [
            sample_alert("A-1", "2026-06-01T08:00:00Z"),
            sample_alert("A-2", "2026-06-01T08:10:00Z"),
            sample_alert("A-3", "2026-06-01T08:20:00Z"),
            sample_alert("A-4", "2026-06-01T09:00:00Z"),
        ],
        max_buckets=3,
    )
    assert len(ranged) == 2
    assert sum(bucket.count for bucket in ranged) == 4
    assert ranged[-1].count >= 1

    across_days = timeline_buckets(
        [
            sample_alert("A-1", "2026-06-01T23:00:00Z"),
            sample_alert("A-2", "2026-06-02T01:00:00Z"),
        ],
        max_buckets=1,
    )
    assert len(across_days) == 1
