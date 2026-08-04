from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import pytest

import soc_alert_deduplicator.exports as exports_module
from soc_alert_deduplicator.errors import IncidentOutputError
from soc_alert_deduplicator.exports import CSV_FIELDS, write_incidents_csv
from soc_alert_deduplicator.io import Incident


def sample_incident() -> Incident:
    return {
        "incident_id": "INC-001",
        "severity": "critical",
        "alert_count": 2,
        "host": "ws-001",
        "user": "analyst.lab",
        "event_type": "credential_access",
        "process_name": "sample.exe",
        "file_hash": "a" * 64,
        "first_seen": "2026-06-01T08:00:00Z",
        "last_seen": "2026-06-01T08:01:00Z",
        "alert_ids": ["A-1", "A-2"],
        "grouping_fields": {"host": "ws-001", "user": "analyst.lab"},
        "summary": "2 credential_access alerts grouped.",
    }


def test_write_incidents_csv_creates_excel_friendly_stable_export(
    tmp_path: Path,
) -> None:
    output = tmp_path / "incidents.csv"

    write_incidents_csv(output, [sample_incident()])

    assert output.read_bytes().startswith(b"\xef\xbb\xbf")
    with output.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert tuple(rows[0]) == CSV_FIELDS
    assert rows[0]["alert_ids"] == "A-1;A-2"
    assert rows[0]["grouping_fields"] == ('{"host": "ws-001", "user": "analyst.lab"}')
    assert rows[0]["summary"] == "2 credential_access alerts grouped."


def test_write_incidents_csv_replaces_existing_file_atomically(tmp_path: Path) -> None:
    output = tmp_path / "incidents.csv"
    output.write_text("stale", encoding="utf-8")

    write_incidents_csv(output, [])

    assert output.read_text(encoding="utf-8-sig").startswith("incident_id,severity")
    assert not list(tmp_path.glob(".incidents.csv.*.tmp"))


def test_write_incidents_csv_neutralizes_spreadsheet_formulas(tmp_path: Path) -> None:
    output = tmp_path / "incidents.csv"
    incident = sample_incident()
    incident["host"] = '=WEBSERVICE("https://example.invalid")'
    incident["summary"] = "  +malicious formula"

    write_incidents_csv(output, [incident])

    with output.open(encoding="utf-8-sig", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["host"].startswith("'=")
    assert row["summary"].startswith("'  +")


def test_write_incidents_csv_protects_source_files(tmp_path: Path) -> None:
    protected = tmp_path / "alerts.json"

    with pytest.raises(IncidentOutputError, match="protected file"):
        write_incidents_csv(protected, [], protected_paths=(protected,))


def test_write_incidents_csv_requires_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(IncidentOutputError, match="directory does not exist"):
        write_incidents_csv(tmp_path / "missing" / "incidents.csv", [])


def test_write_incidents_csv_requires_directory_parent(tmp_path: Path) -> None:
    parent = tmp_path / "file"
    parent.write_text("not a directory", encoding="utf-8")

    with pytest.raises(IncidentOutputError, match="parent is not a directory"):
        write_incidents_csv(parent / "incidents.csv", [])


def test_write_incidents_csv_rejects_directory_output(tmp_path: Path) -> None:
    output = tmp_path / "incidents.csv"
    output.mkdir()

    with pytest.raises(IncidentOutputError, match="path is a directory"):
        write_incidents_csv(output, [])


def test_write_incidents_csv_wraps_invalid_incident_and_cleans_temp(
    tmp_path: Path,
) -> None:
    output = tmp_path / "incidents.csv"

    with pytest.raises(IncidentOutputError, match="cannot write CSV output"):
        write_incidents_csv(output, [{"incident_id": "incomplete"}])

    assert not output.exists()
    assert not list(tmp_path.glob(".incidents.csv.*.tmp"))


def test_write_incidents_csv_wraps_temporary_file_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_temporary_file(*args: object, **kwargs: object) -> Any:
        raise OSError("synthetic CSV failure")

    monkeypatch.setattr(exports_module, "NamedTemporaryFile", fail_temporary_file)

    with pytest.raises(IncidentOutputError, match="synthetic CSV failure"):
        write_incidents_csv(tmp_path / "incidents.csv", [])


def test_write_incidents_csv_does_not_mask_cleanup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_unlink = Path.unlink
    cleanup_attempts: list[Path] = []

    def fail_unlink(path: Path, *args: object, **kwargs: object) -> None:
        cleanup_attempts.append(path)
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(IncidentOutputError, match="cannot write CSV output"):
        write_incidents_csv(tmp_path / "incidents.csv", [{"invalid": object()}])

    assert len(cleanup_attempts) == 1
    monkeypatch.setattr(Path, "unlink", original_unlink)
    original_unlink(cleanup_attempts[0])
