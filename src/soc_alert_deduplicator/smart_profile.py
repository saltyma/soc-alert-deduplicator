"""Data-driven matching profiles for the V2 SMART engine."""

from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .io import Alert, parse_timestamp

PROFILE_FIELDS = (
    "source",
    "host",
    "user",
    "event_type",
    "process_name",
    "target_process_name",
    "parent_process_name",
    "command_line",
    "file_hash",
    "rule_name",
    "description",
)

BASE_WEIGHTS = {
    "source": 0.7,
    "host": 3.0,
    "user": 1.4,
    "event_type": 2.8,
    "process_name": 2.2,
    "target_process_name": 2.2,
    "parent_process_name": 1.0,
    "command_line": 1.6,
    "file_hash": 5.0,
    "rule_name": 2.0,
    "description": 0.8,
}

_OVERRIDE_FIELDS = frozenset(
    {
        "threshold",
        "time_window_minutes",
        "min_evidence_fields",
        "include_fields",
        "exclude_fields",
        "field_weights",
        "max_candidates",
    }
)
_MISSING = frozenset({"", "unknown", "none", "null", "-", "n/a"})


@dataclass(frozen=True, slots=True)
class SmartOverrides:
    threshold: float | None = None
    time_window_minutes: int | None = None
    min_evidence_fields: int | None = None
    include_fields: tuple[str, ...] = ()
    exclude_fields: tuple[str, ...] = ()
    field_weights: tuple[tuple[str, float], ...] = ()
    max_candidates: int | None = None


@dataclass(frozen=True, slots=True)
class SmartProfile:
    """Explainable profile inferred from one alert batch."""

    profile_id: str
    similarity_fields: tuple[str, ...]
    blocking_fields: tuple[str, ...]
    field_weights: tuple[tuple[str, float], ...]
    coverage: tuple[tuple[str, float], ...]
    distinct_ratio: tuple[tuple[str, float], ...]
    threshold: float
    time_window_minutes: int
    min_evidence_fields: int
    max_candidates: int
    rationale: tuple[str, ...]

    def weight_for(self, field: str) -> float:
        return dict(self.field_weights)[field]

    def coverage_for(self, field: str) -> float:
        return dict(self.coverage).get(field, 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "engine": "SMART",
            "version": 2,
            "similarity_fields": list(self.similarity_fields),
            "blocking_fields": list(self.blocking_fields),
            "field_weights": dict(self.field_weights),
            "coverage": dict(self.coverage),
            "distinct_ratio": dict(self.distinct_ratio),
            "threshold": self.threshold,
            "time_window_minutes": self.time_window_minutes,
            "min_evidence_fields": self.min_evidence_fields,
            "max_candidates": self.max_candidates,
            "rationale": list(self.rationale),
        }


def _nonmissing(value: object) -> bool:
    return value is not None and str(value).strip().casefold() not in _MISSING


def _canonical(value: object) -> str:
    return str(value).strip().casefold()


def _profile_stats(alerts: list[Alert]) -> tuple[dict[str, float], dict[str, float]]:
    coverage: dict[str, float] = {}
    distinct_ratio: dict[str, float] = {}
    total = len(alerts)
    for field in PROFILE_FIELDS:
        values = [
            _canonical(alert.get(field))
            for alert in alerts
            if _nonmissing(alert.get(field))
        ]
        coverage[field] = len(values) / total
        distinct_ratio[field] = len(set(values)) / len(values) if values else 0.0
    return coverage, distinct_ratio


def _infer_window(alerts: list[Alert]) -> int:
    timestamps = sorted(
        parse_timestamp(str(alert["timestamp"]), alert_id=str(alert["alert_id"]))
        for alert in alerts
    )
    gaps = [
        (right - left).total_seconds()
        for left, right in zip(timestamps, timestamps[1:])
        if 0 < (right - left).total_seconds() <= 86_400
    ]
    if not gaps:
        return 30
    median_gap = statistics.median(gaps)
    return max(5, min(120, round(median_gap * 20 / 60)))


def _validate_fields(values: Any, *, name: str) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, list) or not all(
        isinstance(value, str) and value in PROFILE_FIELDS for value in values
    ):
        raise ConfigurationError(
            f"{name} must be a list of supported normalized alert fields"
        )
    if len(values) != len(set(values)):
        raise ConfigurationError(f"{name} cannot contain duplicate fields")
    return tuple(values)


def load_smart_overrides(path: Path) -> SmartOverrides:
    """Load optional V2 tuning without requiring a per-source mapping config."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"SMART configuration file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigurationError(
            f"SMART configuration is not valid UTF-8: {path}"
        ) from exc
    except OSError as exc:
        raise ConfigurationError(
            f"cannot read SMART configuration {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"invalid SMART configuration at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("SMART configuration must be a JSON object")
    unknown = sorted(set(payload) - _OVERRIDE_FIELDS)
    if unknown:
        raise ConfigurationError(
            f"unsupported SMART configuration field(s): {', '.join(unknown)}"
        )

    threshold = payload.get("threshold")
    if threshold is not None and (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not 0.5 <= float(threshold) <= 1.0
    ):
        raise ConfigurationError("threshold must be between 0.5 and 1.0")
    window = payload.get("time_window_minutes")
    if window is not None and (
        isinstance(window, bool)
        or not isinstance(window, int)
        or not 1 <= window <= 10_080
    ):
        raise ConfigurationError(
            "time_window_minutes must be an integer from 1 to 10080"
        )
    min_evidence = payload.get("min_evidence_fields")
    if min_evidence is not None and (
        isinstance(min_evidence, bool)
        or not isinstance(min_evidence, int)
        or not 1 <= min_evidence <= 8
    ):
        raise ConfigurationError("min_evidence_fields must be an integer from 1 to 8")
    max_candidates = payload.get("max_candidates")
    if max_candidates is not None and (
        isinstance(max_candidates, bool)
        or not isinstance(max_candidates, int)
        or not 10 <= max_candidates <= 5000
    ):
        raise ConfigurationError("max_candidates must be an integer from 10 to 5000")

    raw_weights = payload.get("field_weights", {})
    if not isinstance(raw_weights, dict):
        raise ConfigurationError("field_weights must be an object")
    weights: list[tuple[str, float]] = []
    for field, value in raw_weights.items():
        if field not in PROFILE_FIELDS:
            raise ConfigurationError(f"unsupported field weight: {field}")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 < float(value) <= 10
        ):
            raise ConfigurationError(
                f"field weight for {field} must be greater than 0 and at most 10"
            )
        weights.append((field, float(value)))

    return SmartOverrides(
        threshold=float(threshold) if threshold is not None else None,
        time_window_minutes=window,
        min_evidence_fields=min_evidence,
        include_fields=_validate_fields(
            payload.get("include_fields"), name="include_fields"
        ),
        exclude_fields=_validate_fields(
            payload.get("exclude_fields"), name="exclude_fields"
        ),
        field_weights=tuple(weights),
        max_candidates=max_candidates,
    )


def infer_smart_profile(
    alerts: list[Alert], overrides: SmartOverrides | None = None
) -> SmartProfile:
    """Infer safe blocking, evidence weights, threshold, and time window."""

    if not alerts:
        raise ConfigurationError(
            "cannot infer a SMART profile from an empty alert batch"
        )
    overrides = overrides or SmartOverrides()
    coverage, distinct_ratio = _profile_stats(alerts)

    selected = [
        field
        for field in PROFILE_FIELDS
        if coverage[field] >= 0.08
        and field not in overrides.exclude_fields
        and (field != "description" or coverage[field] >= 0.4)
    ]
    for field in overrides.include_fields:
        if field not in selected and field not in overrides.exclude_fields:
            selected.append(field)
    for required in ("host", "event_type"):
        if coverage[required] > 0 and required not in selected:
            selected.append(required)
    if not selected:
        selected = ["source", "event_type"]

    custom_weights = dict(overrides.field_weights)
    weights = {
        field: round(
            custom_weights.get(
                field, BASE_WEIGHTS[field] * (0.7 + 0.3 * coverage[field])
            ),
            3,
        )
        for field in selected
    }
    blocking: tuple[str, ...] = tuple(
        field
        for field in ("file_hash", "host", "event_type", "source", "process_name")
        if field in selected
        and coverage[field] >= (0.05 if field == "file_hash" else 0.25)
    )
    if not blocking:
        blocking = (selected[0],)

    average_coverage = statistics.fmean(coverage[field] for field in selected)
    average_repeat = statistics.fmean(1 - distinct_ratio[field] for field in selected)
    threshold = (
        0.86 if average_coverage < 0.45 else 0.76 if average_coverage > 0.75 else 0.80
    )
    if average_repeat > 0.55:
        threshold = max(0.72, threshold - 0.02)
    threshold = overrides.threshold if overrides.threshold is not None else threshold
    window = (
        overrides.time_window_minutes
        if overrides.time_window_minutes is not None
        else _infer_window(alerts)
    )
    min_evidence = (
        overrides.min_evidence_fields
        if overrides.min_evidence_fields is not None
        else 2
        if len(selected) >= 3
        else 1
    )
    max_candidates = overrides.max_candidates or 120
    rationale = (
        f"Profiled {len(alerts)} alerts across {len(selected)} usable evidence fields.",
        f"Average selected-field coverage is {average_coverage:.0%}.",
        f"Observed repetition is {average_repeat:.0%}; threshold set to {threshold:.2f}.",
        f"Median event cadence produced a {window}-minute continuity window.",
    )

    profile_data = {
        "fields": selected,
        "blocking": blocking,
        "weights": weights,
        "threshold": threshold,
        "window": window,
        "evidence": min_evidence,
        "max_candidates": max_candidates,
    }
    profile_id = (
        "SP-"
        + hashlib.sha256(json.dumps(profile_data, sort_keys=True).encode())
        .hexdigest()[:12]
        .upper()
    )
    profile = SmartProfile(
        profile_id=profile_id,
        similarity_fields=tuple(selected),
        blocking_fields=blocking,
        field_weights=tuple((field, weights[field]) for field in selected),
        coverage=tuple((field, round(coverage[field], 4)) for field in PROFILE_FIELDS),
        distinct_ratio=tuple(
            (field, round(distinct_ratio[field], 4)) for field in PROFILE_FIELDS
        ),
        threshold=round(float(threshold), 3),
        time_window_minutes=window,
        min_evidence_fields=min_evidence,
        max_candidates=max_candidates,
        rationale=rationale,
    )
    return replace(profile)
