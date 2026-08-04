"""Time-aware, evidence-weighted deduplication for the V2 SMART engine."""

from __future__ import annotations

import re
from collections import Counter, OrderedDict, defaultdict, deque
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from pathlib import PureWindowsPath
from .io import Alert, Incident, parse_timestamp
from .insights import analyst_view
from .smart_profile import SmartProfile
from .summaries import SEVERITY_RANK

_MISSING = frozenset({"", "unknown", "none", "null", "-", "n/a"})
_TOKEN = re.compile(r"[a-z0-9_.:/\\-]+")
_GUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_HEX = re.compile(r"\b(?:0x)?[0-9a-f]{8,}\b", re.IGNORECASE)
_NUMBER = re.compile(r"\b\d+\b")
_IDENTITY_FIELDS = (
    "host",
    "file_hash",
    "process_name",
    "target_process_name",
    "event_type",
)


@dataclass(frozen=True, slots=True)
class MatchEvidence:
    field: str
    similarity: float
    weight: float


@dataclass(frozen=True, slots=True)
class MatchResult:
    score: float
    evidence: tuple[MatchEvidence, ...]
    conflicts: tuple[str, ...] = ()

    @property
    def exact(self) -> bool:
        return bool(self.evidence) and all(
            item.similarity == 1.0 for item in self.evidence
        )


@dataclass(slots=True)
class SmartCluster:
    alerts: list[Alert]
    original_positions: list[int]
    match_scores: list[float] = dataclass_field(default_factory=list)
    evidence_fields: set[str] = dataclass_field(default_factory=set)
    representative: Alert | None = None
    latest: Alert | None = None
    first_time: datetime | None = None
    last_time: datetime | None = None
    identity_anchors: dict[str, str] = dataclass_field(default_factory=dict)

    def add(
        self,
        alert: Alert,
        *,
        position: int,
        timestamp: datetime,
        match: MatchResult | None = None,
    ) -> None:
        if not self.alerts:
            self.representative = alert
            self.first_time = timestamp
        self.alerts.append(alert)
        self.original_positions.append(position)
        self.latest = alert
        self.last_time = timestamp
        for field in _IDENTITY_FIELDS:
            value = _value(alert, field)
            if value is not None:
                self.identity_anchors.setdefault(field, value)
        if match is not None:
            self.match_scores.append(match.score)
            self.evidence_fields.update(
                item.field for item in match.evidence if item.similarity >= 0.5
            )


def _value(alert: Alert, field: str) -> str | None:
    raw = alert.get(field)
    if raw is None:
        return None
    text = str(raw).strip().casefold()
    if text in _MISSING:
        return None
    if field in {"process_name", "target_process_name", "parent_process_name"}:
        text = PureWindowsPath(text).name or text
    if field == "command_line":
        text = _GUID.sub("<guid>", text)
        text = _HEX.sub("<hex>", text)
        text = _NUMBER.sub("<n>", text)
    return " ".join(text.split())


def _tokens(value: str) -> set[str]:
    return {token for token in _TOKEN.findall(value) if len(token) > 1}


def _similarity(left: str, right: str, *, fuzzy: bool, field: str) -> float:
    if left == right:
        return 1.0
    if not fuzzy:
        return 0.0
    left_tokens = _tokens(left)
    right_tokens = _tokens(right)
    union = left_tokens | right_tokens
    jaccard = len(left_tokens & right_tokens) / len(union) if union else 0.0
    if field in {"command_line", "description"} or max(len(left), len(right)) > 120:
        return round(jaccard, 4)
    sequence = SequenceMatcher(None, left, right, autojunk=False).ratio()
    return round(max(jaccard, sequence * 0.92), 4)


def compare_alerts(left: Alert, right: Alert, profile: SmartProfile) -> MatchResult:
    """Score two alerts and return the evidence that produced the score."""

    hard_conflicts: list[str] = []
    left_host, right_host = _value(left, "host"), _value(right, "host")
    if left_host and right_host and left_host != right_host:
        hard_conflicts.append("host")
    left_hash, right_hash = _value(left, "file_hash"), _value(right, "file_hash")
    if left_hash and right_hash and left_hash != right_hash:
        hard_conflicts.append("file_hash")
    for process_field in ("process_name", "target_process_name"):
        left_process = _value(left, process_field)
        right_process = _value(right, process_field)
        if left_process and right_process and left_process != right_process:
            hard_conflicts.append(process_field)
    if hard_conflicts:
        return MatchResult(score=0.0, evidence=(), conflicts=tuple(hard_conflicts))

    fuzzy_fields = frozenset(
        {
            "event_type",
            "process_name",
            "target_process_name",
            "parent_process_name",
            "command_line",
            "rule_name",
            "description",
        }
    )
    evidence: list[MatchEvidence] = []
    available_weight = 0.0
    matched_weight = 0.0
    total_weight = sum(weight for _, weight in profile.field_weights)
    for field, weight in profile.field_weights:
        left_value, right_value = _value(left, field), _value(right, field)
        if left_value is None or right_value is None:
            continue
        similarity = _similarity(
            left_value,
            right_value,
            fuzzy=field in fuzzy_fields,
            field=field,
        )
        evidence.append(MatchEvidence(field, similarity, weight))
        available_weight += weight
        matched_weight += weight * similarity

    if available_weight == 0:
        return MatchResult(score=0.0, evidence=())
    meaningful = sum(item.similarity >= 0.55 for item in evidence)
    strong_hash = any(
        item.field == "file_hash" and item.similarity == 1.0 for item in evidence
    )
    if meaningful < profile.min_evidence_fields and not strong_hash:
        return MatchResult(
            score=0.0, evidence=tuple(evidence), conflicts=("insufficient_evidence",)
        )

    event_evidence = next(
        (item for item in evidence if item.field == "event_type"), None
    )
    if event_evidence and event_evidence.similarity < 0.3 and not strong_hash:
        return MatchResult(
            score=0.0, evidence=tuple(evidence), conflicts=("event_type",)
        )
    evidence_coverage = min(1.0, available_weight / max(total_weight * 0.6, 0.01))
    score = (matched_weight / available_weight) * (0.82 + 0.18 * evidence_coverage)
    return MatchResult(score=round(score, 4), evidence=tuple(evidence))


def _cluster_identity_conflicts(alert: Alert, cluster: SmartCluster) -> bool:
    """Protect a cluster from drift when early records omit identity fields."""

    for field, anchor in cluster.identity_anchors.items():
        value = _value(alert, field)
        if value is None:
            continue
        if field in {
            "host",
            "file_hash",
            "process_name",
            "target_process_name",
        }:
            if value != anchor:
                return True
            continue
        if _similarity(value, anchor, fuzzy=True, field=field) < 0.3:
            return True
    return False


def _candidate_keys(alert: Alert, profile: SmartProfile) -> tuple[tuple[str, str], ...]:
    keys: list[tuple[str, str]] = []
    values = {field: _value(alert, field) for field in profile.blocking_fields}
    host = _value(alert, "host") or values.get("host")
    event = _value(alert, "event_type") or values.get("event_type")
    process = _value(alert, "process_name")
    target = _value(alert, "target_process_name")
    rule = _value(alert, "rule_name")
    file_hash = values.get("file_hash")
    source = values.get("source")

    if host and file_hash:
        keys.append(("host-hash", f"{host}|{file_hash}"))
    if host and event and process and target:
        keys.append(("activity-shape", f"{host}|{event}|{process}|{target}"))
    elif host and event and process:
        keys.append(("activity-shape", f"{host}|{event}|{process}"))
    elif host and event:
        keys.append(("host-event", f"{host}|{event}"))
    if not keys and host and rule:
        keys.append(("host-rule", f"{host}|{rule}"))
    if not host and source and event:
        keys.append(("source-event", f"{source}|{event}"))
    if not keys:
        for field, value in values.items():
            if value is not None:
                keys.append((field, value))
                break
    return tuple(keys)


def cluster_alerts(alerts: list[Alert], profile: SmartProfile) -> list[SmartCluster]:
    """Build deterministic clusters using blocks, continuity, and weighted evidence."""

    ordered = sorted(
        enumerate(alerts),
        key=lambda item: (
            parse_timestamp(
                str(item[1]["timestamp"]), alert_id=str(item[1]["alert_id"])
            ),
            item[0],
        ),
    )
    window = timedelta(minutes=profile.time_window_minutes)
    maximum_span = window * 3
    clusters: list[SmartCluster] = []
    index: dict[tuple[str, str], OrderedDict[int, datetime]] = defaultdict(OrderedDict)
    recent: deque[int] = deque(maxlen=profile.max_candidates)

    for position, alert in ordered:
        timestamp = parse_timestamp(
            str(alert["timestamp"]), alert_id=str(alert["alert_id"])
        )
        candidate_ids: list[int] = []
        seen_candidates: set[int] = set()
        keys = _candidate_keys(alert, profile)
        for key in keys:
            bucket = index[key]
            while bucket:
                oldest_time = next(iter(bucket.values()))
                if timestamp - oldest_time <= window:
                    break
                bucket.popitem(last=False)
            for cluster_id in reversed(bucket):
                if cluster_id not in seen_candidates:
                    candidate_ids.append(cluster_id)
                    seen_candidates.add(cluster_id)
                if len(candidate_ids) >= profile.max_candidates:
                    break
        if not candidate_ids:
            candidate_ids.extend(reversed(recent))

        best_cluster: int | None = None
        best_match: MatchResult | None = None
        for cluster_id in candidate_ids[: profile.max_candidates]:
            cluster = clusters[cluster_id]
            if (
                cluster.last_time is None
                or cluster.first_time is None
                or timestamp - cluster.last_time > window
                or timestamp - cluster.first_time > maximum_span
                or cluster.representative is None
                or cluster.latest is None
                or _cluster_identity_conflicts(alert, cluster)
            ):
                continue
            representative_match = compare_alerts(
                alert, cluster.representative, profile
            )
            latest_match = (
                representative_match
                if cluster.latest is cluster.representative
                else compare_alerts(alert, cluster.latest, profile)
            )
            score = max(representative_match.score, latest_match.score)
            if (
                len(cluster.alerts) > 2
                and representative_match.score < profile.threshold - 0.08
            ):
                continue
            selected_match = (
                representative_match
                if representative_match.score >= latest_match.score
                else latest_match
            )
            if score >= profile.threshold and (
                best_match is None or score > best_match.score
            ):
                best_cluster = cluster_id
                best_match = selected_match

        if best_cluster is None:
            cluster = SmartCluster(alerts=[], original_positions=[])
            cluster.add(alert, position=position, timestamp=timestamp)
            clusters.append(cluster)
            cluster_id = len(clusters) - 1
        else:
            cluster_id = best_cluster
            clusters[cluster_id].add(
                alert,
                position=position,
                timestamp=timestamp,
                match=best_match,
            )
        recent.append(cluster_id)
        for key in keys:
            bucket = index[key]
            bucket[cluster_id] = timestamp
            bucket.move_to_end(cluster_id)
            while len(bucket) > profile.max_candidates:
                bucket.popitem(last=False)

    return sorted(clusters, key=lambda cluster: min(cluster.original_positions))


def _context(alerts: list[Alert], field: str) -> str:
    values = [_value(alert, field) for alert in alerts]
    present = [value for value in values if value is not None]
    if not present:
        return "unknown"
    counts = Counter(present)
    value, count = counts.most_common(1)[0]
    return (
        value
        if count == len(present)
        else f"{value} (+{len(set(present)) - 1} variants)"
    )


def _highest_severity(alerts: list[Alert]) -> str:
    return max(
        (str(alert["severity"]) for alert in alerts), key=SEVERITY_RANK.__getitem__
    )


def _cluster_confidence(cluster: SmartCluster) -> float:
    if len(cluster.alerts) == 1:
        return 1.0
    return round(sum(cluster.match_scores) / len(cluster.match_scores), 4)


def _match_type(cluster: SmartCluster) -> str:
    if len(cluster.alerts) == 1:
        return "singleton"
    exact = sum(score >= 0.999 for score in cluster.match_scores)
    if exact == len(cluster.match_scores):
        return "exact"
    if exact:
        return "mixed"
    return "similar"


def build_smart_incidents(
    clusters: list[SmartCluster], profile: SmartProfile
) -> list[Incident]:
    """Create analyst-facing incidents with confidence and matching evidence."""

    incidents: list[Incident] = []
    for index, cluster in enumerate(clusters, start=1):
        alerts = cluster.alerts
        first = min(
            alerts,
            key=lambda alert: parse_timestamp(
                str(alert["timestamp"]), alert_id=str(alert["alert_id"])
            ),
        )
        last = max(
            alerts,
            key=lambda alert: parse_timestamp(
                str(alert["timestamp"]), alert_id=str(alert["alert_id"])
            ),
        )
        host = _context(alerts, "host")
        user = _context(alerts, "user")
        event_type = _context(alerts, "event_type")
        process_name = _context(alerts, "process_name")
        target_process_name = _context(alerts, "target_process_name")
        file_hash = _context(alerts, "file_hash")
        confidence = _cluster_confidence(cluster)
        match_type = _match_type(cluster)
        display_event = event_type.replace("_", " ")
        common_fields: dict[str, str] = {}
        for field in profile.similarity_fields:
            values = {_value(alert, field) for alert in alerts}
            values.discard(None)
            if len(values) == 1:
                common_value = next(iter(values))
                if common_value is not None:
                    common_fields[field] = common_value
        noun = "alert" if len(alerts) == 1 else "alerts"
        incident: Incident = {
            "incident_id": f"INC-{index:04d}",
            "alert_count": len(alerts),
            "grouping_fields": common_fields,
            "host": host,
            "user": user,
            "event_type": event_type,
            "process_name": process_name,
            "target_process_name": target_process_name,
            "file_hash": file_hash,
            "severity": _highest_severity(alerts),
            "first_seen": str(first["timestamp"]),
            "last_seen": str(last["timestamp"]),
            "alert_ids": [str(alert["alert_id"]) for alert in alerts],
            "summary": (
                f"{len(alerts)} {display_event} {noun} on {host}; "
                f"{match_type} evidence match at {confidence:.0%} confidence."
            ),
            "deduplication": {
                "engine": "SMART",
                "profile_id": profile.profile_id,
                "match_type": match_type,
                "confidence": confidence,
                "evidence_fields": sorted(cluster.evidence_fields),
                "time_window_minutes": profile.time_window_minutes,
            },
            "source_formats": sorted(
                {
                    str(alert.get("detected_format", "normalized-json"))
                    for alert in alerts
                }
            ),
        }
        incident["analyst_view"] = analyst_view(incident)
        incidents.append(incident)
    return incidents
