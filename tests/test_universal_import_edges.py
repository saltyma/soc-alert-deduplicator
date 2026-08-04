from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from soc_alert_deduplicator.errors import RawImportError
from soc_alert_deduplicator.universal_import import (
    IngestionResult,
    SourceReport,
    _decode_bytes,
    _extension_pairs,
    _extract_hash,
    _flatten,
    _line_records,
    _looks_delimited,
    _nested_records,
    _normalize_severity,
    _normalize_timestamp,
    _parse_cef_line,
    _parse_delimited,
    _parse_json,
    _parse_json_lines,
    _parse_leef_line,
    _parse_syslog_line,
    _parse_xml,
    _read_limited,
    _records_from_text,
    _split_unescaped_pipes,
    _text,
    _windows_xml_records,
    load_any_alerts,
    main,
)

UTC = timezone.utc
FALLBACK = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_ingestion_warning_flattening_and_scalar_helpers() -> None:
    result = IngestionResult(
        alerts=[],
        sources=(
            SourceReport("a", "json", 1, (), ("one",)),
            SourceReport("b", "csv", 1, (), ("two", "three")),
        ),
    )

    assert result.warnings == ("one", "two", "three")
    assert _text(None) is None
    assert _text(True) == "true"
    assert _text(False) == "false"
    assert _text({"b": 2, "a": 1}) == '{"a": 1, "b": 2}'
    assert _text([1, 2]) == "[1, 2]"
    assert _text(" - ") is None
    assert _flatten(7) == {"value": 7}
    assert _flatten([{"a": 1}], "events") == {"events": [{"a": 1}]}


@pytest.mark.parametrize(
    ("value", "syslog", "expected"),
    [
        ("garbage", False, "informational"),
        ("emergency", False, "critical"),
        ("9", False, "critical"),
        ("6", False, "high"),
        ("3", False, "medium"),
        ("1", False, "low"),
        ("0", False, "informational"),
        ("2", True, "critical"),
        ("3", True, "high"),
        ("4", True, "medium"),
        ("5", True, "low"),
        ("6", True, "informational"),
    ],
)
def test_severity_normalization_branches(
    value: object, syslog: bool, expected: str
) -> None:
    assert _normalize_severity(value, syslog_priority=syslog) == expected


@pytest.mark.parametrize(
    ("value", "prefix"),
    [
        (None, "2026-01-02T03:04:05"),
        ("1700000000", "2023-11-14T22:13:20"),
        ("1700000000000", "2023-11-14T22:13:20"),
        ("1700000000000000", "2023-11-14T22:13:20"),
        ("1700000000000000000", "2023-11-14T22:13:20"),
        ("2026-01-02T04:04:05+01:00", "2026-01-02T04:04:05"),
        ("2026-01-02 03:04:05", "2026-01-02T03:04:05"),
        ("Jan  2 03:04:05", "2026-01-02T03:04:05"),
        ("not-a-time", "2026-01-02T03:04:05"),
    ],
)
def test_timestamp_normalization_branches(value: object, prefix: str) -> None:
    warnings: list[str] = []

    normalized = _normalize_timestamp(value, fallback=FALLBACK, warnings=warnings)

    assert normalized.startswith(prefix)
    if value in {None, "2026-01-02 03:04:05", "Jan  2 03:04:05", "not-a-time"}:
        assert warnings


def test_invalid_numeric_timestamp_uses_fallback() -> None:
    warnings: list[str] = []
    assert _normalize_timestamp(
        "999999999999", fallback=FALLBACK, warnings=warnings
    ).startswith("2026-01-02T03:04:05")
    assert "invalid numeric" in warnings[0]


def test_hash_extraction_rejects_missing_short_and_zero_values() -> None:
    assert _extract_hash(None) is None
    assert _extract_hash("sha256=abc") is None
    assert _extract_hash("0" * 64) is None
    assert _extract_hash("SHA256=" + "A" * 64) == "a" * 64


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ([{"a": 1}, "skip"], [{"a": 1}]),
        ({"alerts": [{"a": 1}, 2]}, [{"a": 1}]),
        ({"data": [{"a": 1}]}, [{"a": 1}]),
        ({"hits": {"hits": [{"_source": {"a": 1}}]}}, [{"_source": {"a": 1}}]),
        ({"single": 1}, [{"single": 1}]),
        ("scalar", []),
    ],
)
def test_nested_record_shapes(
    payload: object, expected: list[dict[str, object]]
) -> None:
    assert _nested_records(payload) == expected


@pytest.mark.parametrize(
    ("parser", "text", "message"),
    [
        (_parse_json, '{"a":1,"a":2}', "duplicate JSON key"),
        (_parse_json, "{", "invalid JSON"),
        (_parse_json, "[]", "no object records"),
        (_parse_json_lines, "\n\n", "no records"),
        (_parse_json_lines, "[1]\n", "is not an object"),
        (_parse_json_lines, "{broken}\n", "line 1"),
    ],
)
def test_json_parser_errors(parser: Any, text: str, message: str) -> None:
    with pytest.raises(RawImportError, match=message):
        parser(text)


def test_delimited_parser_fallback_and_errors() -> None:
    assert _parse_delimited("a,b\n1,2\n", suffix=".unknown")[1] == "csv"
    with pytest.raises(RawImportError, match="header"):
        _parse_delimited("only-one-field\n", suffix=".csv")
    with pytest.raises(RawImportError, match="no data rows"):
        _parse_delimited("a,b\n", suffix=".csv")


def test_pipe_and_extension_parsing_handles_escapes_quotes_and_bad_items() -> None:
    assert _split_unescaped_pipes(r"a\|b|c", maxsplit=1) == [r"a\|b", "c"]
    assert _extension_pairs('a="hello world" b=two') == {
        "a": "hello world",
        "b": "two",
    }
    assert _extension_pairs("a=1^bad^b=2", delimiter="^") == {"a": "1", "b": "2"}


def test_cef_validation_and_prefix_variants() -> None:
    with pytest.raises(RawImportError, match="marker"):
        _parse_cef_line("not cef")
    with pytest.raises(RawImportError, match="header"):
        _parse_cef_line("CEF:0|too|short")
    no_prefix = _parse_cef_line("CEF:0|V|P|1|7|Name|5|msg=ok")
    text_prefix = _parse_cef_line("prefix CEF:0|V|P|1|7|Name|5|msg=ok")
    assert "syslog_prefix" not in no_prefix
    assert text_prefix["syslog_prefix"] == "prefix"


def test_leef_validation_delimiter_and_prefix_variants() -> None:
    with pytest.raises(RawImportError, match="marker"):
        _parse_leef_line("not leef")
    with pytest.raises(RawImportError, match="incomplete"):
        _parse_leef_line("LEEF:2|short")
    tab = _parse_leef_line("LEEF:1.0|V|P|1|7|src=a\tsev=5")
    invalid_hex = _parse_leef_line("prefix LEEF:2.0|V|P|1|7|xZZ|src=a\tsev=5")
    comma = _parse_leef_line("LEEF:2.0|V|P|1|7|,|src=a,sev=5")
    assert tab["src"] == "a"
    assert invalid_hex["syslog_prefix"] == "prefix"
    assert comma["sev"] == "5"


def test_bsd_syslog_and_invalid_header() -> None:
    record = _parse_syslog_line("Jan  2 03:04:05 host app[7]: user=a action=x")
    assert record["host"] == "host"
    assert record["syslog_priority"] == "6"
    with pytest.raises(RawImportError, match="not recognized"):
        _parse_syslog_line("not syslog")


def test_line_record_plain_mixed_blank_and_empty_paths() -> None:
    records, label = _line_records(
        "\n2026-01-02T03:04:05Z plain message\nhost=a action=x\n"
    )
    assert len(records) == 2
    assert label == "mixed-text"
    assert _line_records("plain without time")[1] == "plain-text"
    with pytest.raises(RawImportError, match="no records"):
        _line_records("\n\t")


def test_windows_xml_stream_and_generic_xml_edges() -> None:
    stream = "noise\n<Event>\n<x>1</x>\n</Event>\n<Event><x>2</x></Event>"
    records = _windows_xml_records(stream)
    assert [line for line, _ in records] == [2, 5]
    with pytest.raises(RawImportError, match="unterminated"):
        _windows_xml_records("<Event>\n<x>1</x>")

    parsed, label = _parse_xml(
        '<events><event id="1"><host>a</host></event>'
        '<event id="2"><host>b</host></event></events>'
    )
    assert label == "xml"
    assert parsed == [{"host": "a"}, {"host": "b"}]
    element = ET.fromstring('<event><field type="text">value</field></event>')
    assert _parse_xml(ET.tostring(element, encoding="unicode"))[0][0] == {
        "field": "value",
        "field_type": "text",
    }
    with pytest.raises(RawImportError, match="invalid XML"):
        _parse_xml("<event>")
    with pytest.raises(RawImportError, match="no scalar"):
        _parse_xml("<event />")


def test_detection_helpers_and_fallback_routes() -> None:
    assert not _looks_delimited("one line")
    assert not _looks_delimited("a,b\n1\n")
    assert _looks_delimited("a,b\n1,2\n")
    with pytest.raises(RawImportError, match="empty"):
        _records_from_text("\ufeff \n", suffix=".log")
    assert _records_from_text('{"a":1}\n{"a":2}', suffix=".log")[1] == ("json-lines")


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ("hello".encode("utf-16"), "hello"),
        ("hello".encode("utf-16-le"), "hello"),
        ("hello".encode("utf-16-be"), "hello"),
        ("café".encode("cp1252"), "café"),
    ],
)
def test_text_decoding_supported_encodings(data: bytes, expected: str) -> None:
    assert _decode_bytes(data, origin="memory") == expected


def test_text_decoding_rejects_invalid_utf16_and_control_data() -> None:
    with pytest.raises(RawImportError, match="binary or unsupported"):
        _decode_bytes(b"\xff\xfe\x00", origin="bad-bom")
    with pytest.raises(RawImportError, match="binary or unsupported"):
        _decode_bytes(b"\x00\x01\x00\x02", origin="controls")
    with pytest.raises(RawImportError, match="unsupported text encoding"):
        _decode_bytes(bytes(range(1, 32)), origin="controls-no-null")


def test_read_limit_can_be_enforced_without_large_allocation(monkeypatch: Any) -> None:
    monkeypatch.setattr("soc_alert_deduplicator.universal_import.MAX_EXPANDED_BYTES", 3)
    with pytest.raises(RawImportError, match="exceeds"):
        _read_limited(io.BytesIO(b"four"), origin="memory")


def test_path_and_archive_failures(tmp_path: Path, monkeypatch: Any) -> None:
    with pytest.raises(RawImportError, match="at least one"):
        load_any_alerts([])
    with pytest.raises(RawImportError, match="not found"):
        load_any_alerts([tmp_path / "missing.log"])
    with pytest.raises(RawImportError, match="not a file"):
        load_any_alerts([tmp_path])

    bad_zip = tmp_path / "bad.zip"
    bad_zip.write_bytes(b"not a zip")
    with pytest.raises(RawImportError, match="invalid ZIP"):
        load_any_alerts([bad_zip])

    empty_zip = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty_zip, "w"):
        pass
    with pytest.raises(RawImportError, match="no importable"):
        load_any_alerts([empty_zip])

    many_zip = tmp_path / "many.zip"
    with zipfile.ZipFile(many_zip, "w") as archive:
        for index in range(3):
            archive.writestr(f"{index}.log", "host=a action=x")
    monkeypatch.setattr(
        "soc_alert_deduplicator.universal_import.MAX_ARCHIVE_MEMBERS", 2
    )
    with pytest.raises(RawImportError, match="128-member"):
        load_any_alerts([many_zip])


def test_corrupt_gzip_reports_read_failure(tmp_path: Path) -> None:
    path = tmp_path / "bad.log.gz"
    path.write_bytes(b"not gzip")
    with pytest.raises(RawImportError, match="cannot read"):
        load_any_alerts([path])


def test_normalize_cli_success_warning_and_error(tmp_path: Path, capsys: Any) -> None:
    source = tmp_path / "plain.log"
    source.write_text("message without timestamp\n", encoding="utf-8")
    output = tmp_path / "normalized.json"

    assert main(["--input", str(source), "--output", str(output)]) == 0
    assert "Warnings: 1" in capsys.readouterr().out
    assert json.loads(output.read_text(encoding="utf-8"))[0]["event_type"] == (
        "plain_text_event"
    )

    assert (
        main(["--input", str(tmp_path / "missing.log"), "--output", str(output)]) == 2
    )
    assert "error: input file not found" in capsys.readouterr().err
