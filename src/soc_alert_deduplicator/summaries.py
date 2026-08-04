"""Incident aggregation for exact alert groups."""

from __future__ import annotations

from .config import Settings
from .deduplication import AlertGroup
from .io import Alert, Incident, parse_timestamp
from .normalization import grouping_fields_from_key, normalize_value

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_SUMMARY_CONTEXT_FIELDS = (
    "host",
    "user",
    "event_type",
    "process_name",
    "file_hash",
)


def _context_value(
    field: str,
    alerts: list[Alert],
    grouping_fields: dict[str, str],
    settings: Settings,
) -> str:
    if field in grouping_fields:
        return grouping_fields[field]

    values = {normalize_value(alert.get(field), settings) for alert in alerts}
    if len(values) == 1:
        return next(iter(values))
    return "multiple"


def _highest_severity(alerts: list[Alert]) -> str:
    return max(
        (alert["severity"] for alert in alerts),
        key=SEVERITY_RANK.__getitem__,
    )


def _timestamp_bounds(alerts: list[Alert]) -> tuple[str, str]:
    first = min(
        alerts,
        key=lambda alert: parse_timestamp(
            alert["timestamp"], alert_id=alert["alert_id"]
        ),
    )
    last = max(
        alerts,
        key=lambda alert: parse_timestamp(
            alert["timestamp"], alert_id=alert["alert_id"]
        ),
    )
    return first["timestamp"], last["timestamp"]


def build_incidents(groups: list[AlertGroup], settings: Settings) -> list[Incident]:
    """Create deterministic incident summaries from ordered alert groups."""

    incidents: list[Incident] = []
    for index, (key, alerts) in enumerate(groups, start=1):
        grouping_fields = grouping_fields_from_key(key, settings)
        context = {
            field: _context_value(field, alerts, grouping_fields, settings)
            for field in _SUMMARY_CONTEXT_FIELDS
        }
        first_seen, last_seen = _timestamp_bounds(alerts)
        alert_count = len(alerts)
        event_type = context["event_type"]
        noun = "alert" if alert_count == 1 else "alerts"

        incident: Incident = {
            "incident_id": f"INC-{index:03d}",
            "alert_count": alert_count,
            "grouping_fields": grouping_fields,
            "host": context["host"],
            "user": context["user"],
            "event_type": event_type,
            "process_name": context["process_name"],
            "file_hash": context["file_hash"],
            "severity": _highest_severity(alerts),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "alert_ids": [alert["alert_id"] for alert in alerts],
            "summary": (
                f"{alert_count} {event_type} {noun} grouped for host "
                f"{context['host']} and user {context['user']}."
            ),
        }
        incidents.append(incident)

    return incidents
