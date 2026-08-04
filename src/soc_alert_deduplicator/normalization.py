"""Canonical values and exact grouping keys."""

from __future__ import annotations

from typing import Any

from .config import Settings
from .io import Alert

GroupKey = tuple[str, ...]


def normalize_value(value: Any, settings: Settings) -> str:
    """Normalize one configured value without mutating its source alert."""

    if value is None:
        text = settings.missing_value
    else:
        text = str(value).strip()
        if not text:
            text = settings.missing_value

    if not settings.case_sensitive:
        text = text.casefold()
    return text


def build_group_key(alert: Alert, settings: Settings) -> GroupKey:
    """Build the ordered exact-match key configured for an alert."""

    return tuple(
        normalize_value(alert.get(field), settings) for field in settings.group_by
    )


def grouping_fields_from_key(key: GroupKey, settings: Settings) -> dict[str, str]:
    """Map a group key back to its configured field names."""

    return dict(zip(settings.group_by, key, strict=True))
