from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from soc_alert_deduplicator.config import Settings, load_settings
from soc_alert_deduplicator.errors import ConfigurationError


def valid_config(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "group_by": ["host", "user", "event_type", "process_name", "file_hash"],
        "case_sensitive": False,
        "missing_value": "unknown",
        "minimum_match_score": 1.0,
    }
    payload.update(overrides)
    return payload


def write_config(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_settings_returns_validated_immutable_settings(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "config.json",
        valid_config(case_sensitive=True, missing_value="  UNKNOWN  "),
    )

    settings = load_settings(path)

    assert settings == Settings(
        group_by=("host", "user", "event_type", "process_name", "file_hash"),
        case_sensitive=True,
        missing_value="UNKNOWN",
        minimum_match_score=1.0,
    )
    with pytest.raises(AttributeError):
        settings.case_sensitive = False  # type: ignore[misc]


def test_load_settings_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="configuration file not found"):
        load_settings(tmp_path / "missing.json")


def test_load_settings_rejects_non_utf8(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(ConfigurationError, match="not valid UTF-8"):
        load_settings(path)


def test_load_settings_reports_os_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.json"

    def fail_read_text(*args: object, **kwargs: object) -> str:
        raise OSError("synthetic read failure")

    monkeypatch.setattr(Path, "read_text", fail_read_text)

    with pytest.raises(ConfigurationError, match="synthetic read failure"):
        load_settings(path)


def test_load_settings_reports_json_location(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text('{\n  "group_by": [\n}', encoding="utf-8")

    with pytest.raises(ConfigurationError, match=r"line 3, column 1"):
        load_settings(path)


def test_load_settings_rejects_non_object(tmp_path: Path) -> None:
    path = write_config(tmp_path / "config.json", [])

    with pytest.raises(ConfigurationError, match="must be a JSON object"):
        load_settings(path)


def test_load_settings_rejects_unknown_field(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "config.json",
        valid_config(unexpected=True),
    )

    with pytest.raises(ConfigurationError, match="unsupported.*unexpected"):
        load_settings(path)


@pytest.mark.parametrize(
    "missing_field",
    ["group_by", "case_sensitive", "missing_value", "minimum_match_score"],
)
def test_load_settings_rejects_missing_config_field(
    tmp_path: Path, missing_field: str
) -> None:
    payload = valid_config()
    del payload[missing_field]
    path = write_config(tmp_path / "config.json", payload)

    with pytest.raises(ConfigurationError, match=missing_field):
        load_settings(path)


@pytest.mark.parametrize(
    "group_by",
    [
        "host",
        [],
        [""],
        ["host", 4],
        ["host", "host"],
    ],
)
def test_load_settings_rejects_invalid_group_by(tmp_path: Path, group_by: Any) -> None:
    path = write_config(
        tmp_path / "config.json",
        valid_config(group_by=group_by),
    )

    with pytest.raises(ConfigurationError, match="group_by"):
        load_settings(path)


def test_load_settings_rejects_unsupported_grouping_field(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "config.json",
        valid_config(group_by=["host", "unsupported"]),
    )

    with pytest.raises(ConfigurationError, match="unsupported group_by.*unsupported"):
        load_settings(path)


@pytest.mark.parametrize("value", [None, 0, "false"])
def test_load_settings_rejects_non_boolean_case_sensitive(
    tmp_path: Path, value: Any
) -> None:
    path = write_config(
        tmp_path / "config.json",
        valid_config(case_sensitive=value),
    )

    with pytest.raises(ConfigurationError, match="case_sensitive"):
        load_settings(path)


@pytest.mark.parametrize("value", [None, "", "   ", 7])
def test_load_settings_rejects_invalid_missing_value(
    tmp_path: Path, value: Any
) -> None:
    path = write_config(
        tmp_path / "config.json",
        valid_config(missing_value=value),
    )

    with pytest.raises(ConfigurationError, match="missing_value"):
        load_settings(path)


@pytest.mark.parametrize("value", [True, "1.0", None])
def test_load_settings_rejects_non_numeric_threshold(
    tmp_path: Path, value: Any
) -> None:
    path = write_config(
        tmp_path / "config.json",
        valid_config(minimum_match_score=value),
    )

    with pytest.raises(ConfigurationError, match="must be numeric"):
        load_settings(path)


@pytest.mark.parametrize("value", [0.0, 0.5, 0.99, 1.1])
def test_load_settings_rejects_non_exact_threshold(
    tmp_path: Path, value: float
) -> None:
    path = write_config(
        tmp_path / "config.json",
        valid_config(minimum_match_score=value),
    )

    with pytest.raises(ConfigurationError, match="must be 1.0"):
        load_settings(path)
