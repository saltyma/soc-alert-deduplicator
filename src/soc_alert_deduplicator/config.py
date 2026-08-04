"""Configuration loading and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigurationError

GROUPABLE_FIELDS = frozenset(
    {
        "source",
        "host",
        "user",
        "event_type",
        "process_name",
        "target_process_name",
        "parent_process_name",
        "command_line",
        "file_hash",
        "severity",
        "rule_name",
    }
)

_CONFIG_FIELDS = frozenset(
    {"group_by", "case_sensitive", "missing_value", "minimum_match_score"}
)


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated settings used by every processing stage."""

    group_by: tuple[str, ...]
    case_sensitive: bool
    missing_value: str
    minimum_match_score: float


def _read_config_object(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigurationError(f"configuration file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigurationError(
            f"configuration file is not valid UTF-8: {path}"
        ) from exc
    except OSError as exc:
        raise ConfigurationError(
            f"cannot read configuration file {path}: {exc}"
        ) from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"invalid JSON in {path} at line {exc.lineno}, column {exc.colno}: "
            f"{exc.msg}"
        ) from exc

    if not isinstance(payload, dict):
        raise ConfigurationError(
            f"configuration must be a JSON object, got {type(payload).__name__}"
        )
    return payload


def load_settings(path: Path) -> Settings:
    """Load and validate the exact-match compatibility configuration."""

    payload = _read_config_object(path)

    unknown_fields = sorted(set(payload) - _CONFIG_FIELDS)
    if unknown_fields:
        joined = ", ".join(unknown_fields)
        raise ConfigurationError(f"unsupported configuration field(s): {joined}")

    missing_fields = sorted(_CONFIG_FIELDS - set(payload))
    if missing_fields:
        joined = ", ".join(missing_fields)
        raise ConfigurationError(f"missing configuration field(s): {joined}")

    group_by = payload["group_by"]
    if (
        not isinstance(group_by, list)
        or not group_by
        or not all(isinstance(field, str) and field for field in group_by)
    ):
        raise ConfigurationError("group_by must be a nonempty list of field names")

    if len(group_by) != len(set(group_by)):
        raise ConfigurationError("group_by cannot contain duplicate field names")

    unsupported = sorted(set(group_by) - GROUPABLE_FIELDS)
    if unsupported:
        joined = ", ".join(unsupported)
        raise ConfigurationError(f"unsupported group_by field(s): {joined}")

    case_sensitive = payload["case_sensitive"]
    if not isinstance(case_sensitive, bool):
        raise ConfigurationError("case_sensitive must be true or false")

    missing_value = payload["missing_value"]
    if not isinstance(missing_value, str) or not missing_value.strip():
        raise ConfigurationError("missing_value must be a nonempty string")
    missing_value = missing_value.strip()

    threshold = payload["minimum_match_score"]
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ConfigurationError("minimum_match_score must be numeric")
    threshold = float(threshold)
    if threshold != 1.0:
        raise ConfigurationError("minimum_match_score must be 1.0 in exact mode")

    return Settings(
        group_by=tuple(group_by),
        case_sensitive=case_sensitive,
        missing_value=missing_value,
        minimum_match_score=threshold,
    )
