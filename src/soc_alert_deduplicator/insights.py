"""Analyst-facing explanations and summaries for incident data."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from .errors import AlertInputError
from .io import Alert, Incident, parse_timestamp


@dataclass(frozen=True)
class TimelineBucket:
    """A compact, renderer-independent activity bucket."""

    label: str
    count: int
    start: datetime
    end: datetime


@dataclass(frozen=True)
class IncidentNarrative:
    """The plain-language analyst view of an incident."""

    title: str
    story: str
    why_it_matters: str
    why_grouped: str
    recommended_checks: tuple[str, ...]


_EVENT_NAMES = {
    "process_access": "Process access",
    "process_create": "Process creation",
    "process_creation": "Process creation",
    "network_connection": "Network connection",
    "file_create": "File creation",
    "file_creation": "File creation",
    "registry_event": "Registry change",
    "failed_login": "Failed sign-in",
    "failed_logon": "Failed sign-in",
    "successful_login": "Successful sign-in",
    "successful_logon": "Successful sign-in",
    "authentication_failure": "Authentication failure",
    "malware_detection": "Malware detection",
}


def _text(value: Any, fallback: str = "Unknown") -> str:
    if value is None:
        return fallback
    rendered = str(value).strip()
    return rendered or fallback


def _base_event_name(value: Any) -> str:
    raw = _text(value, "activity").strip().lower()
    raw = re.sub(r"^(?:sysmon|windows|security)[_\s-]*\d+[_\s-]*", "", raw)
    raw = re.sub(r"[_\s-]+", "_", raw).strip("_")
    return _EVENT_NAMES.get(raw, raw.replace("_", " ").capitalize())


def humanize_event(value: Any) -> str:
    """Turn normalized event identifiers into readable event labels."""

    raw = _text(value, "Activity").strip()
    normalized = raw.lower().replace("-", "_").replace(" ", "_")
    match = re.match(r"^(sysmon|windows|security)_?(\d+)_?(.*)$", normalized)
    if match:
        family, event_id, remainder = match.groups()
        name = _base_event_name(remainder or "event")
        family_name = "Sysmon" if family == "sysmon" else family.capitalize()
        return f"{family_name} {name.lower()} (Event {event_id})"
    return _EVENT_NAMES.get(normalized, normalized.replace("_", " ").capitalize())


def format_timestamp(value: Any) -> str:
    """Format an ISO timestamp consistently without discarding timezone context."""

    if not value:
        return "Unknown"
    try:
        parsed = parse_timestamp(str(value), alert_id="incident")
    except (AlertInputError, TypeError, ValueError):
        return _text(value)
    zone = parsed.tzname() or "UTC"
    return f"{parsed:%Y-%m-%d %H:%M:%S} {zone}"


def incident_duration(incident: Incident) -> timedelta:
    """Return a non-negative incident duration."""

    try:
        first = parse_timestamp(
            str(incident.get("first_seen", "")), alert_id="incident"
        )
        last = parse_timestamp(str(incident.get("last_seen", "")), alert_id="incident")
    except (AlertInputError, TypeError, ValueError):
        return timedelta(0)
    return max(last - first, timedelta(0))


def format_duration(value: timedelta) -> str:
    """Produce a compact, understandable duration label."""

    seconds = max(0, int(value.total_seconds()))
    if seconds < 60:
        return "under 1 minute" if seconds else "single point in time"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours, remaining_minutes = divmod(minutes, 60)
    if hours < 24:
        tail = f" {remaining_minutes} min" if remaining_minutes else ""
        return f"{hours} hour{'s' if hours != 1 else ''}{tail}"
    days, remaining_hours = divmod(hours, 24)
    tail = f" {remaining_hours} hr" if remaining_hours else ""
    return f"{days} day{'s' if days != 1 else ''}{tail}"


def incident_title(incident: Incident) -> str:
    """Build a short, action-oriented incident title."""

    process = _text(incident.get("process_name"), "").strip()
    target = _text(incident.get("target_process_name"), "").strip()
    host = _text(incident.get("host"))
    event = str(incident.get("event_type", "")).lower()
    if process and target and "access" in event:
        return f"{process} accessed {target}"
    if process and ("create" in event or "start" in event):
        return f"{process} started on {host}"
    if target and "file" in event:
        return f"File activity affected {target}"
    return f"{humanize_event(incident.get('event_type'))} on {host}"


def incident_story(incident: Incident) -> str:
    """Explain what the incident contains in one readable paragraph."""

    count = max(1, int(incident.get("alert_count", 1) or 1))
    event = humanize_event(incident.get("event_type")).lower()
    host = _text(incident.get("host"))
    severity = _text(incident.get("severity"), "unknown").lower()
    process = _text(incident.get("process_name"), "").strip()
    target = _text(incident.get("target_process_name"), "").strip()
    user = _text(incident.get("user"), "").strip()
    duration = format_duration(incident_duration(incident))

    sentence = (
        f"{count} source alert{'s were' if count != 1 else ' was'} grouped into "
        f"this incident after recording {event} on {host} over {duration}."
    )
    context: list[str] = []
    if process:
        context.append(f"process {process}")
    if target:
        context.append(f"target {target}")
    if user:
        context.append(f"user {user}")
    if context:
        sentence += f" Observed context: {', '.join(context)}."
    return f"{sentence} Highest observed severity: {severity}."


def grouping_explanation(incident: Incident) -> str:
    """Explain the deduplication decision without implementation jargon."""

    details = incident.get("deduplication") or {}
    fields = details.get("evidence_fields") or incident.get("grouping_fields") or []
    labels = [str(field).replace("_", " ") for field in fields]
    evidence = ", ".join(labels) if labels else "the available alert context"
    confidence = float(details.get("confidence", 1.0) or 0.0)
    window = details.get("time_window_minutes")
    match_type = str(details.get("match_type", "exact")).replace("_", " ")
    timing = f" within a {window:g}-minute activity window" if window else ""
    return (
        f"The alerts matched on {evidence}{timing}. The {match_type} evidence "
        f"match scored {confidence:.0%}. This score measures grouping certainty, "
        "not the probability that the activity is malicious."
    )


def risk_context(incident: Incident) -> str:
    """Give cautious, contextual guidance without claiming a verdict."""

    searchable = " ".join(
        str(incident.get(field, "")).lower()
        for field in (
            "event_type",
            "process_name",
            "target_process_name",
            "summary",
        )
    )
    if "lsass" in searchable or "credential" in searchable:
        return (
            "Access involving LSASS can be associated with credential access, but "
            "legitimate security and administration tools may behave similarly. "
            "Validate the initiating process, signer, command line, and host context."
        )
    if any(term in searchable for term in ("failed_login", "failed log", "auth")):
        return (
            "Repeated authentication failures may indicate a password error, a stale "
            "service credential, or attempted account access. Compare the user, source, "
            "frequency, and any later successful sign-in."
        )
    if any(term in searchable for term in ("powershell", "pwsh", "cmd.exe")):
        return (
            "Command interpreters are common in administration and attacker activity. "
            "Review the full command line, parent process, user, and related network or "
            "file activity before deciding disposition."
        )
    if any(term in searchable for term in ("malware", "hash", "file_create")):
        return (
            "File or malware telemetry needs artifact validation. Check the hash, file "
            "origin, signer, execution evidence, and whether controls blocked the action."
        )
    return (
        "This grouping highlights repeated related activity; it is not a threat verdict. "
        "Validate the host, account, process lineage, and surrounding telemetry before "
        "closing or escalating it."
    )


def recommended_actions(incident: Incident) -> tuple[str, ...]:
    """Return a short, context-aware analyst checklist."""

    searchable = " ".join(
        str(incident.get(field, "")).lower()
        for field in ("event_type", "process_name", "target_process_name", "summary")
    )
    actions: list[str] = []
    if "lsass" in searchable or "credential" in searchable:
        actions.append(
            "Verify the initiating process path, signer, parent, and command line."
        )
        actions.append(
            "Check the host for other credential-access or lateral-movement signals."
        )
    elif any(term in searchable for term in ("failed_login", "failed log", "auth")):
        actions.append(
            "Compare failures by user and source, then look for a later success."
        )
        actions.append(
            "Confirm whether a service, scheduled task, or user changed credentials."
        )
    elif any(term in searchable for term in ("powershell", "pwsh", "cmd.exe")):
        actions.append("Review the complete command line and parent process chain.")
        actions.append(
            "Correlate nearby file, network, and identity activity on the host."
        )
    elif any(term in searchable for term in ("malware", "hash", "file_create")):
        actions.append(
            "Validate the file hash, path, signer, origin, and execution status."
        )
        actions.append(
            "Confirm whether the security control blocked or quarantined the file."
        )
    else:
        actions.append(
            "Review the source alerts and verify the affected host and user context."
        )
        actions.append(
            "Compare related activity immediately before and after this time window."
        )
    actions.append("Document the evidence used for the final disposition.")
    return tuple(actions[:3])


def build_narrative(incident: Incident) -> IncidentNarrative:
    """Create the complete reusable analyst narrative for an incident."""

    return IncidentNarrative(
        title=incident_title(incident),
        story=incident_story(incident),
        why_it_matters=risk_context(incident),
        why_grouped=grouping_explanation(incident),
        recommended_checks=recommended_actions(incident),
    )


def analyst_view(incident: Incident) -> dict[str, Any]:
    """Return a JSON-ready analyst explanation for exported SMART incidents."""

    narrative = build_narrative(incident)
    return {
        "title": narrative.title,
        "what_happened": narrative.story,
        "why_it_matters": narrative.why_it_matters,
        "why_grouped": narrative.why_grouped,
        "recommended_checks": list(narrative.recommended_checks),
    }


def severity_distribution(
    incidents: Iterable[Incident], *, weight_by_alerts: bool = False
) -> list[tuple[str, int]]:
    """Summarize incident severities in a stable risk-first order."""

    counts: Counter[str] = Counter()
    for incident in incidents:
        severity = _text(incident.get("severity"), "unknown").lower()
        counts[severity] += (
            max(1, int(incident.get("alert_count", 1) or 1)) if weight_by_alerts else 1
        )
    order = ("critical", "high", "medium", "low", "informational", "unknown")
    return [
        (severity.title(), counts[severity]) for severity in order if counts[severity]
    ]


def top_hosts(
    incidents: Iterable[Incident], *, limit: int = 5
) -> list[tuple[str, int]]:
    """Rank hosts by the number of source alerts represented."""

    counts: Counter[str] = Counter()
    for incident in incidents:
        counts[_text(incident.get("host"))] += max(
            1, int(incident.get("alert_count", 1) or 1)
        )
    return sorted(counts.items(), key=lambda item: (-item[1], item[0].lower()))[
        : max(0, limit)
    ]


def alerts_for_incident(incident: Incident, alerts: Iterable[Alert]) -> list[Alert]:
    """Resolve source alerts in the order recorded by the incident."""

    by_id = {str(alert.get("alert_id")): alert for alert in alerts}
    resolved = [
        by_id[str(alert_id)]
        for alert_id in incident.get("alert_ids", [])
        if str(alert_id) in by_id
    ]
    if resolved:
        return resolved
    incident_id = str(incident.get("incident_id", ""))
    return [alert for alert in alerts if alert.get("incident_id") == incident_id]


def timeline_buckets(
    alerts: Iterable[Alert], *, max_buckets: int = 12
) -> list[TimelineBucket]:
    """Aggregate alert timestamps into a compact visual timeline."""

    parsed: list[datetime] = []
    for alert in alerts:
        try:
            parsed.append(
                parse_timestamp(
                    str(alert.get("timestamp", "")),
                    alert_id=str(alert.get("alert_id", "alert")),
                )
            )
        except (AlertInputError, TypeError, ValueError):
            continue
    if not parsed:
        return []
    parsed.sort()
    start, end = parsed[0], parsed[-1]
    if start == end or max_buckets <= 1:
        return [TimelineBucket(start.strftime("%H:%M"), len(parsed), start, end)]

    count = min(
        max(1, max_buckets), max(2, min(len(parsed), math.ceil(math.sqrt(len(parsed)))))
    )
    width = (end - start) / count
    totals = [0] * count
    for stamp in parsed:
        index = min(count - 1, int((stamp - start) / width))
        totals[index] += 1
    multiple_days = start.date() != end.date()
    buckets: list[TimelineBucket] = []
    for index, total in enumerate(totals):
        bucket_start = start + width * index
        bucket_end = end if index == count - 1 else start + width * (index + 1)
        label = bucket_start.strftime("%m-%d %H:%M" if multiple_days else "%H:%M")
        buckets.append(TimelineBucket(label, total, bucket_start, bucket_end))
    return buckets
