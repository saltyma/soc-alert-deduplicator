from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest

from soc_alert_deduplicator.config import Settings
from soc_alert_deduplicator.io import Alert
from soc_alert_deduplicator.normalization import (
    build_group_key,
    grouping_fields_from_key,
    normalize_value,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "unknown"),
        ("", "unknown"),
        ("   ", "unknown"),
        (" WS-001 ", "ws-001"),
        ("ADMIN.LOCAL", "admin.local"),
        (42, "42"),
    ],
)
def test_normalize_value_handles_missing_case_and_whitespace(
    settings: Settings, raw: object, expected: str
) -> None:
    assert normalize_value(raw, settings) == expected


def test_normalize_value_respects_case_sensitive_setting(
    settings: Settings,
) -> None:
    sensitive = replace(settings, case_sensitive=True, missing_value="MISSING")

    assert normalize_value(" WS-001 ", sensitive) == "WS-001"
    assert normalize_value(None, sensitive) == "MISSING"


def test_build_group_key_uses_configured_order_and_keeps_input_unchanged(
    settings: Settings,
    make_alert: Callable[..., Alert],
) -> None:
    alert = make_alert(
        host=" WS-001 ",
        user=None,
        event_type="MALWARE_DETECTION",
        process_name=" Sample.EXE ",
        file_hash=f" {'A' * 64} ",
    )
    original = dict(alert)

    key = build_group_key(alert, settings)

    assert key == (
        "ws-001",
        "unknown",
        "malware_detection",
        "sample.exe",
        "a" * 64,
    )
    assert alert == original


def test_grouping_fields_from_key_preserves_configured_field_order(
    settings: Settings,
) -> None:
    key = ("ws-001", "analyst.lab", "malware_detection", "sample.exe", "a" * 64)

    result = grouping_fields_from_key(key, settings)

    assert list(result) == list(settings.group_by)
    assert tuple(result.values()) == key
