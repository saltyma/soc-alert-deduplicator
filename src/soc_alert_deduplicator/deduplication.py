"""Ordered exact-key alert grouping."""

from __future__ import annotations

from .config import Settings
from .io import Alert
from .normalization import GroupKey, build_group_key

AlertGroup = tuple[GroupKey, list[Alert]]


def group_alerts(alerts: list[Alert], settings: Settings) -> list[AlertGroup]:
    """Group alerts by their normalized tuple in first-appearance order."""

    groups: dict[GroupKey, list[Alert]] = {}
    for alert in alerts:
        key = build_group_key(alert, settings)
        groups.setdefault(key, []).append(alert)
    return list(groups.items())
