from __future__ import annotations

import gzip
import json
import zipfile
from pathlib import Path

import pytest

from soc_alert_deduplicator.errors import IncidentOutputError, RawImportError
from soc_alert_deduplicator.universal_import import load_any_alerts, run_normalize


def write_text(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_nested_json_is_mapped_without_a_source_specific_config(tmp_path: Path) -> None:
    source = write_text(
        tmp_path / "elastic.json",
        json.dumps(
            {
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "@timestamp": "2026-07-01T12:00:00Z",
                                "host": {"name": "WEB-01"},
                                "event": {"action": "process_start"},
                                "process": {
                                    "executable": "/usr/bin/bash",
                                    "command_line": "bash -c id",
                                },
                                "user": {"name": "root"},
                                "log": {"level": "warning"},
                            }
                        }
                    ]
                }
            }
        ),
    )

    result = load_any_alerts([source])

    assert result.sources[0].detected_format == "json"
    assert result.alerts[0]["host"] == "WEB-01"
    assert result.alerts[0]["event_type"] == "process_start"
    assert result.alerts[0]["process_name"] == "bash"
    assert result.alerts[0]["severity"] == "medium"


@pytest.mark.parametrize(
    ("name", "content", "expected_format"),
    [
        (
            "alerts.jsonl",
            '{"timestamp":"2026-07-01T12:00:00Z","hostname":"db-01",'
            '"event_name":"login_failed","severity":"8"}\n',
            "json-lines",
        ),
        (
            "alerts.csv",
            "time;computer;action;level\n"
            "2026-07-01T12:00:00Z;db-01;login_failed;high\n",
            "csv",
        ),
        (
            "alerts.tsv",
            "timestamp\thost\tevent_type\tseverity\n"
            "2026-07-01T12:00:00Z\tdb-01\tlogin_failed\thigh\n",
            "tsv",
        ),
        (
            "events.xml",
            "<event><timestamp>2026-07-01T12:00:00Z</timestamp>"
            "<hostname>db-01</hostname><action>login_failed</action>"
            "<level>high</level></event>",
            "xml",
        ),
    ],
)
def test_structured_text_formats_are_detected(
    tmp_path: Path, name: str, content: str, expected_format: str
) -> None:
    result = load_any_alerts([write_text(tmp_path / name, content)])

    assert result.sources[0].detected_format == expected_format
    assert result.alerts[0]["host"] == "db-01"
    assert result.alerts[0]["event_type"] == "login_failed"
    assert result.alerts[0]["severity"] == "high"


@pytest.mark.parametrize(
    ("name", "line", "expected_format"),
    [
        (
            "event.cef",
            "2026-07-01T12:00:00Z CEF:0|Acme|Sensor|2|42|Malware found|9|"
            "dhost=ws-01 suser=alice cs1Label=Process cs1=evil.exe msg=blocked",
            "cef",
        ),
        (
            "event.leef",
            "LEEF:2.0|Acme|Sensor|2|42|^|devTime=2026-07-01T12:00:00Z^"
            "devTimeFormat=yyyy-MM-dd'T'HH:mm:ssX^src=ws-01^sev=8^msg=blocked",
            "leef",
        ),
        (
            "event.syslog",
            "<134>1 2026-07-01T12:00:00Z ws-01 sshd 123 LOGIN - "
            "user=alice action=login_failed",
            "syslog",
        ),
        (
            "event.log",
            "timestamp=2026-07-01T12:00:00Z host=ws-01 action=login_failed "
            "severity=high user=alice",
            "key-value",
        ),
    ],
)
def test_security_line_formats_are_detected(
    tmp_path: Path, name: str, line: str, expected_format: str
) -> None:
    result = load_any_alerts([write_text(tmp_path / name, line + "\n")])

    assert result.sources[0].detected_format == expected_format
    assert len(result.alerts) == 1
    assert result.alerts[0]["source_record"].endswith(":1")


def test_gzip_and_zip_members_are_ingested_with_provenance(tmp_path: Path) -> None:
    line = (
        "timestamp=2026-07-01T12:00:00Z host=ws-01 action=login_failed severity=high\n"
    )
    gz_path = tmp_path / "one.log.gz"
    with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
        handle.write(line)
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("two.log", line.replace("ws-01", "ws-02"))

    result = load_any_alerts([gz_path, zip_path])

    assert len(result.alerts) == 2
    assert len(result.sources) == 2
    assert "!two.log" in result.sources[1].path
    assert {alert["host"] for alert in result.alerts} == {"ws-01", "ws-02"}


def test_duplicate_source_ids_are_made_unique_deterministically(tmp_path: Path) -> None:
    payload = (
        '[{"id":"same","timestamp":"2026-07-01T12:00:00Z",'
        '"host":"ws-01","action":"x","severity":"low"}]'
    )
    first = write_text(tmp_path / "a.json", payload)
    second = write_text(tmp_path / "b.json", payload)

    result = load_any_alerts([first, second])

    ids = [str(alert["alert_id"]) for alert in result.alerts]
    assert ids[0] == "same"
    assert ids[1].startswith("same-")
    assert len(set(ids)) == 2


def test_binary_input_is_rejected_instead_of_silently_guessed(tmp_path: Path) -> None:
    path = tmp_path / "capture.bin"
    path.write_bytes(b"\x00\x01\x02\x03")

    with pytest.raises(RawImportError, match="binary or unsupported"):
        load_any_alerts([path])


def test_run_normalize_writes_validated_json_and_protects_input(tmp_path: Path) -> None:
    source = write_text(
        tmp_path / "events.log",
        "timestamp=2026-07-01T12:00:00Z host=ws-01 action=login_failed severity=high\n",
    )
    output = tmp_path / "normalized.json"

    result = run_normalize([source], output)

    written = json.loads(output.read_text(encoding="utf-8"))
    assert written == result.alerts
    with pytest.raises(IncidentOutputError, match="overwrite an input file"):
        run_normalize([source], source)
