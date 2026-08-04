from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from soc_alert_deduplicator.errors import ConfigurationError
from soc_alert_deduplicator.smart_profile import (
    SmartOverrides,
    infer_smart_profile,
    load_smart_overrides,
)


def test_profile_is_deterministic_and_infers_data_coverage(make_alert: Any) -> None:
    alerts = [
        make_alert(alert_id=f"A-{index}", timestamp=f"2026-06-01T08:{index:02d}:00Z")
        for index in range(6)
    ]

    first = infer_smart_profile(alerts)
    second = infer_smart_profile(list(reversed(alerts)))

    assert first.profile_id == second.profile_id
    assert first.coverage_for("host") == 1.0
    assert "host" in first.blocking_fields
    assert 0.5 <= first.threshold <= 1.0
    assert first.to_dict()["engine"] == "SMART"


def test_profile_honors_optional_tuning_without_schema_mapping(make_alert: Any) -> None:
    alerts = [make_alert(alert_id="A-1"), make_alert(alert_id="A-2")]
    overrides = SmartOverrides(
        threshold=0.91,
        time_window_minutes=17,
        min_evidence_fields=3,
        include_fields=("target_process_name",),
        exclude_fields=("description",),
        field_weights=(("host", 4.5),),
        max_candidates=44,
    )

    profile = infer_smart_profile(alerts, overrides)

    assert profile.threshold == 0.91
    assert profile.time_window_minutes == 17
    assert profile.min_evidence_fields == 3
    assert profile.max_candidates == 44
    assert "target_process_name" in profile.similarity_fields
    assert "description" not in profile.similarity_fields
    assert profile.weight_for("host") == 4.5


def test_load_smart_overrides_validates_and_normalizes_values(tmp_path: Path) -> None:
    path = tmp_path / "smart.json"
    path.write_text(
        json.dumps(
            {
                "threshold": 0.9,
                "time_window_minutes": 15,
                "include_fields": ["command_line"],
                "field_weights": {"command_line": 3},
                "max_candidates": 50,
            }
        ),
        encoding="utf-8",
    )

    overrides = load_smart_overrides(path)

    assert overrides.threshold == 0.9
    assert overrides.include_fields == ("command_line",)
    assert overrides.field_weights == (("command_line", 3.0),)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"unknown": True},
        {"threshold": 0.2},
        {"time_window_minutes": True},
        {"include_fields": ["not_a_field"]},
        {"exclude_fields": ["host", "host"]},
        {"field_weights": {"host": 0}},
        {"max_candidates": 4},
    ],
)
def test_load_smart_overrides_rejects_unsafe_values(
    tmp_path: Path, payload: object
) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_smart_overrides(path)


def test_empty_batch_cannot_produce_a_profile() -> None:
    with pytest.raises(ConfigurationError, match="empty alert batch"):
        infer_smart_profile([])
