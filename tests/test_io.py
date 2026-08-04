from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import soc_alert_deduplicator.io as io_module
from soc_alert_deduplicator.errors import AlertInputError, IncidentOutputError
from soc_alert_deduplicator.io import load_alerts, parse_timestamp, write_incidents


def write_payload(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_parse_timestamp_accepts_z_and_explicit_offset() -> None:
    assert (
        parse_timestamp("2026-06-01T08:15:00Z", alert_id="A-1").utcoffset() is not None
    )
    assert (
        parse_timestamp("2026-06-01T09:15:00+01:00", alert_id="A-2").utcoffset()
        is not None
    )


@pytest.mark.parametrize("value", ["not-a-date", "2026-13-01T08:15:00Z"])
def test_parse_timestamp_rejects_invalid_values(value: str) -> None:
    with pytest.raises(AlertInputError, match="invalid ISO 8601 timestamp"):
        parse_timestamp(value, alert_id="A-1")


def test_parse_timestamp_requires_timezone() -> None:
    with pytest.raises(AlertInputError, match="must include a timezone"):
        parse_timestamp("2026-06-01T08:15:00", alert_id="A-1")


def test_load_alerts_returns_validated_alerts(tmp_path: Path, make_alert: Any) -> None:
    payload = [make_alert(), make_alert(alert_id="ALERT-TEST-002")]

    alerts = load_alerts(write_payload(tmp_path / "alerts.json", payload))

    assert alerts == payload
    assert alerts is not payload


def test_load_alerts_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AlertInputError, match="alert file not found"):
        load_alerts(tmp_path / "missing.json")


def test_load_alerts_rejects_non_utf8(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(AlertInputError, match="not valid UTF-8"):
        load_alerts(path)


def test_load_alerts_reports_os_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_read_text(*args: object, **kwargs: object) -> str:
        raise OSError("synthetic read failure")

    monkeypatch.setattr(Path, "read_text", fail_read_text)

    with pytest.raises(AlertInputError, match="synthetic read failure"):
        load_alerts(tmp_path / "alerts.json")


def test_load_alerts_reports_json_location(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    path.write_text('[\n  {"alert_id": "A-1"}\n', encoding="utf-8")

    with pytest.raises(AlertInputError, match=r"line 3, column 1"):
        load_alerts(path)


def test_load_alerts_rejects_duplicate_json_key(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    path.write_text('[{"alert_id":"A-1","alert_id":"A-2"}]', encoding="utf-8")

    with pytest.raises(AlertInputError, match="duplicate JSON object key.*alert_id"):
        load_alerts(path)


def test_load_alerts_requires_top_level_array(tmp_path: Path) -> None:
    path = write_payload(tmp_path / "alerts.json", {"alerts": []})

    with pytest.raises(AlertInputError, match="must be a JSON array"):
        load_alerts(path)


def test_load_alerts_requires_each_item_to_be_an_object(tmp_path: Path) -> None:
    path = write_payload(tmp_path / "alerts.json", ["not-an-alert"])

    with pytest.raises(AlertInputError, match="index 0 must be a JSON object"):
        load_alerts(path)


@pytest.mark.parametrize(
    "required_field",
    ["alert_id", "timestamp", "source", "host", "event_type", "severity"],
)
def test_load_alerts_rejects_missing_required_field(
    tmp_path: Path, make_alert: Any, required_field: str
) -> None:
    alert = make_alert()
    del alert[required_field]
    path = write_payload(tmp_path / "alerts.json", [alert])

    with pytest.raises(AlertInputError, match=required_field):
        load_alerts(path)


@pytest.mark.parametrize("value", [None, "", "   ", 42])
def test_load_alerts_rejects_invalid_required_text(
    tmp_path: Path, make_alert: Any, value: Any
) -> None:
    path = write_payload(tmp_path / "alerts.json", [make_alert(host=value)])

    with pytest.raises(AlertInputError, match="nonempty string for host"):
        load_alerts(path)


def test_load_alerts_rejects_unsupported_severity(
    tmp_path: Path, make_alert: Any
) -> None:
    path = write_payload(tmp_path / "alerts.json", [make_alert(severity="urgent")])

    with pytest.raises(AlertInputError, match="unsupported severity"):
        load_alerts(path)


@pytest.mark.parametrize(
    "optional_field",
    [
        "user",
        "process_name",
        "parent_process_name",
        "command_line",
        "rule_name",
        "description",
    ],
)
def test_load_alerts_rejects_non_text_optional_field(
    tmp_path: Path, make_alert: Any, optional_field: str
) -> None:
    path = write_payload(tmp_path / "alerts.json", [make_alert(**{optional_field: 7})])

    with pytest.raises(AlertInputError, match=f"field {optional_field}"):
        load_alerts(path)


def test_load_alerts_accepts_null_and_blank_optional_fields(
    tmp_path: Path, make_alert: Any
) -> None:
    path = write_payload(
        tmp_path / "alerts.json",
        [make_alert(user=None, process_name="", file_hash="   ")],
    )

    assert len(load_alerts(path)) == 1


@pytest.mark.parametrize("file_hash", [7, "abc", "g" * 64])
def test_load_alerts_rejects_invalid_file_hash(
    tmp_path: Path, make_alert: Any, file_hash: Any
) -> None:
    path = write_payload(tmp_path / "alerts.json", [make_alert(file_hash=file_hash)])

    expected = "string or null" if not isinstance(file_hash, str) else "SHA-256"
    with pytest.raises(AlertInputError, match=expected):
        load_alerts(path)


def test_load_alerts_rejects_duplicate_alert_id(
    tmp_path: Path, make_alert: Any
) -> None:
    path = write_payload(tmp_path / "alerts.json", [make_alert(), make_alert()])

    with pytest.raises(AlertInputError, match="duplicate alert_id"):
        load_alerts(path)


def test_write_incidents_creates_pretty_utf8_json_with_final_newline(
    tmp_path: Path,
) -> None:
    output = tmp_path / "incidents.json"
    incidents = [{"incident_id": "INC-001", "summary": "Détection"}]

    write_incidents(output, incidents)

    text = output.read_text(encoding="utf-8")
    assert json.loads(text) == incidents
    assert "Détection" in text
    assert text.startswith("[\n  {")
    assert text.endswith("\n")


def test_write_incidents_atomically_replaces_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "incidents.json"
    output.write_text("stale", encoding="utf-8")

    write_incidents(output, [{"incident_id": "INC-001"}])

    assert json.loads(output.read_text(encoding="utf-8")) == [
        {"incident_id": "INC-001"}
    ]
    assert not list(tmp_path.glob(".incidents.json.*.tmp"))


def test_write_incidents_protects_input_paths(tmp_path: Path) -> None:
    protected = tmp_path / "alerts.json"

    with pytest.raises(IncidentOutputError, match="cannot overwrite an input"):
        write_incidents(protected, [], protected_paths=(protected,))


def test_write_incidents_requires_existing_output_directory(tmp_path: Path) -> None:
    with pytest.raises(IncidentOutputError, match="does not exist"):
        write_incidents(tmp_path / "missing" / "incidents.json", [])


def test_write_incidents_requires_directory_parent(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("file", encoding="utf-8")

    with pytest.raises(IncidentOutputError, match="parent is not a directory"):
        write_incidents(parent / "incidents.json", [])


def test_write_incidents_rejects_directory_as_output(tmp_path: Path) -> None:
    output = tmp_path / "incidents.json"
    output.mkdir()

    with pytest.raises(IncidentOutputError, match="output path is a directory"):
        write_incidents(output, [])


def test_write_incidents_wraps_serialization_error_and_removes_temporary_file(
    tmp_path: Path,
) -> None:
    output = tmp_path / "incidents.json"

    with pytest.raises(IncidentOutputError, match="cannot write incident output"):
        write_incidents(output, [{"invalid": object()}])

    assert not output.exists()
    assert not list(tmp_path.glob(".incidents.json.*.tmp"))


def test_write_incidents_wraps_temporary_file_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_temporary_file(*args: object, **kwargs: object) -> Any:
        raise OSError("synthetic write failure")

    monkeypatch.setattr(io_module, "NamedTemporaryFile", fail_temporary_file)

    with pytest.raises(IncidentOutputError, match="synthetic write failure"):
        write_incidents(tmp_path / "incidents.json", [])


def test_write_incidents_does_not_mask_temporary_cleanup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_unlink = Path.unlink
    cleanup_attempts: list[Path] = []

    def fail_unlink(path: Path, *args: object, **kwargs: object) -> None:
        cleanup_attempts.append(path)
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(Path, "unlink", fail_unlink)

    with pytest.raises(IncidentOutputError, match="cannot write incident output"):
        write_incidents(tmp_path / "incidents.json", [{"invalid": object()}])

    assert len(cleanup_attempts) == 1
    monkeypatch.setattr(Path, "unlink", original_unlink)
    original_unlink(cleanup_attempts[0])
