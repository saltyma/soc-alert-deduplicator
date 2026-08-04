from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_alert_deduplicator.errors import RawImportError
from soc_alert_deduplicator.io import load_alerts
from soc_alert_deduplicator.raw_import import (
    build_parser,
    import_raw_files,
    main,
    parse_crowdstrike_json,
    parse_windows_event_xml,
    run_import,
)


def windows_event(
    *,
    provider: str = "Microsoft-Windows-Sysmon",
    event_id: str = "10",
    timestamp: str = "2022-01-12T16:25:27.967136500Z",
    computer: str = "win-dc-137.attackrange.local",
    record_id: str = "40591054",
    data: dict[str, str] | None = None,
) -> str:
    fields = data or {}
    event_data = "".join(
        f"<Data Name='{name}'>{value}</Data>" for name, value in fields.items()
    )
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System>"
        f"<Provider Name='{provider}'/>"
        f"<EventID>{event_id}</EventID>"
        f"<TimeCreated SystemTime='{timestamp}'/>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Computer>{computer}</Computer>"
        "</System>"
        f"<EventData>{event_data}</EventData>"
        "</Event>"
    )


def crowdstrike_record(**overrides: object) -> str:
    record: dict[str, object] = {
        "event_simpleName": "ProcessRollup2",
        "id": "d6ef8319-0d98-11ed-acf0-06aeb8794401",
        "timestamp": "1658918561056",
        "aid": "f0778584e83c4efc9cf026bc1e7f0489",
        "UserSid": "S-1-5-18",
        "ImageFileName": "\\Device\\HarddiskVolume1\\Windows\\cmd.exe",
        "ParentBaseFileName": "powershell.exe",
        "CommandLine": "cmd.exe /c whoami",
        "SHA256HashData": "a" * 64,
    }
    record.update(overrides)
    return json.dumps(record)


def test_parse_sysmon_process_access_preserves_context() -> None:
    raw = windows_event(
        data={
            "SourceImage": "C:\\Tools\\procdump.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "User": "ATTACKRANGE\\Administrator",
            "Hashes": f"MD5={'b' * 32},SHA256={'A' * 64},IMPHASH={'c' * 32}",
            "RuleName": "-",
            "CommandLine": "procdump.exe -ma lsass.exe dump.dmp",
        }
    )

    alert = parse_windows_event_xml(
        raw, origin=Path("windows-sysmon.log"), line_number=1
    )

    assert alert == {
        "alert_id": "SPLUNK-windows-sysmon-40591054",
        "timestamp": "2022-01-12T16:25:27.967136500Z",
        "source": "splunk-attack-data/sysmon",
        "host": "win-dc-137.attackrange.local",
        "event_type": "sysmon_10_process_access",
        "severity": "critical",
        "user": "ATTACKRANGE\\Administrator",
        "process_name": "procdump.exe",
        "target_process_name": "lsass.exe",
        "parent_process_name": None,
        "command_line": "procdump.exe -ma lsass.exe dump.dmp",
        "file_hash": "a" * 64,
        "rule_name": "Sysmon Event 10: process access",
        "description": (
            "Imported Microsoft-Windows-Sysmon event 10 from Splunk Attack Data. "
            "Context: C:\\Windows\\System32\\lsass.exe."
        ),
    }


@pytest.mark.parametrize(
    ("event_id", "expected_name", "expected_severity"),
    [
        ("1", "sysmon_1_process_creation", "low"),
        ("8", "sysmon_8_create_remote_thread", "high"),
        ("4", "sysmon_4_sysmon_service_state_changed", "informational"),
        ("99", "sysmon_99_event_99", "informational"),
    ],
)
def test_parse_sysmon_event_mappings(
    event_id: str, expected_name: str, expected_severity: str
) -> None:
    alert = parse_windows_event_xml(
        windows_event(
            event_id=event_id,
            data={
                "Image": "C:\\Windows\\process.exe",
                "ParentImage": "C:\\Windows\\parent.exe",
                "TargetFilename": "C:\\Temp\\artifact.bin",
            },
        ),
        origin=Path("source name.log"),
        line_number=7,
    )

    assert alert["event_type"] == expected_name
    assert alert["severity"] == expected_severity
    assert alert["process_name"] == "process.exe"
    assert alert["parent_process_name"] == "parent.exe"
    assert alert["alert_id"].startswith("SPLUNK-source-name-")
    assert "artifact.bin" in alert["description"]


def test_parse_non_lsass_process_access_is_high() -> None:
    alert = parse_windows_event_xml(
        windows_event(data={"SourceImage": "tool.exe", "TargetImage": "notepad.exe"}),
        origin=Path("sysmon.log"),
        line_number=1,
    )

    assert alert["severity"] == "high"


def test_parse_windows_security_process_creation() -> None:
    alert = parse_windows_event_xml(
        windows_event(
            provider="Microsoft-Windows-Security-Auditing",
            event_id="4688",
            data={
                "SubjectUserName": "Administrator",
                "NewProcessName": "C:\\Tools\\procdump.exe",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
            },
        ),
        origin=Path("procdump_windows-security.log"),
        line_number=3,
    )

    assert alert["source"] == "splunk-attack-data/windows-security"
    assert alert["event_type"] == "windows_security_4688_process_creation"
    assert alert["severity"] == "low"
    assert alert["user"] == "Administrator"
    assert alert["process_name"] == "procdump.exe"
    assert alert["target_process_name"] is None
    assert alert["parent_process_name"] == "explorer.exe"


def test_parse_unknown_windows_provider_and_event() -> None:
    raw = windows_event(provider="Vendor-Provider", event_id="999", data={}).replace(
        "<EventData></EventData>", "<EventData><Data>unnamed</Data></EventData>"
    )
    alert = parse_windows_event_xml(
        raw,
        origin=Path("vendor.log"),
        line_number=1,
    )

    assert alert["event_type"] == "windows_security_999_event_999"
    assert alert["severity"] == "informational"
    assert alert["process_name"] is None
    assert alert["description"].endswith("Splunk Attack Data.")


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("<Event>", "invalid Windows event XML"),
        ("<Other/>", "not a Windows Event XML record"),
        (
            windows_event().replace("<Provider Name='Microsoft-Windows-Sysmon'/>", ""),
            "missing Windows event provider",
        ),
        (
            windows_event().replace("<EventID>10</EventID>", ""),
            "missing Windows event ID",
        ),
        (
            windows_event(event_id="ten"),
            "non-numeric Windows event ID",
        ),
        (
            windows_event().replace(
                "<TimeCreated SystemTime='2022-01-12T16:25:27.967136500Z'/>", ""
            ),
            "missing Windows event timestamp",
        ),
        (
            windows_event().replace(
                "<Computer>win-dc-137.attackrange.local</Computer>", ""
            ),
            "missing Windows event computer",
        ),
        (
            windows_event().replace("<EventRecordID>40591054</EventRecordID>", ""),
            "missing Windows event record ID",
        ),
    ],
)
def test_parse_windows_event_rejects_invalid_records(raw: str, message: str) -> None:
    with pytest.raises(RawImportError, match=message):
        parse_windows_event_xml(raw, origin=Path("bad.log"), line_number=12)


def test_parse_crowdstrike_process_record() -> None:
    alert = parse_crowdstrike_json(
        crowdstrike_record(), origin=Path("crowdstrike_falcon.log"), line_number=2
    )

    assert alert["alert_id"].endswith("d6ef8319-0d98-11ed-acf0-06aeb8794401")
    assert alert["timestamp"] == "2022-07-27T10:42:41.056Z"
    assert alert["source"] == "splunk-attack-data/crowdstrike-falcon"
    assert alert["host"] == "f0778584e83c4efc9cf026bc1e7f0489"
    assert alert["event_type"] == "crowdstrike_process_rollup2"
    assert alert["severity"] == "low"
    assert alert["process_name"] == "cmd.exe"
    assert alert["target_process_name"] is None
    assert alert["parent_process_name"] == "powershell.exe"
    assert alert["file_hash"] == "a" * 64


@pytest.mark.parametrize(
    ("event_name", "target", "expected"),
    [
        ("ProcessHandleOpDetectInfo", None, "critical"),
        ("DmpFileWritten", "C:\\Temp\\lsass.dmp", "critical"),
        ("DmpFileWritten", "C:\\Temp\\other.dmp", "high"),
        ("FileDeleteInfo", "C:\\Temp\\other.tmp", "high"),
        ("UnmappedEvent", None, "medium"),
    ],
)
def test_crowdstrike_severity_mapping(
    event_name: str, target: str | None, expected: str
) -> None:
    alert = parse_crowdstrike_json(
        crowdstrike_record(
            event_simpleName=event_name,
            TargetFileName=target,
            SHA256HashData="0" * 64,
            ImageFileName=None,
            ParentBaseFileName=None,
            ParentImageFileName="C:\\Windows\\parent.exe",
            ComputerName="endpoint-01",
            UserName="analyst",
            CommandLine=None,
        ),
        origin=Path("falcon.log"),
        line_number=1,
    )

    assert alert["severity"] == expected
    assert alert["file_hash"] is None
    assert alert["host"] == "endpoint-01"
    assert alert["user"] == "analyst"
    assert alert["parent_process_name"] == "parent.exe"


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("{", "invalid CrowdStrike JSON"),
        (
            '{"event_simpleName":"A","event_simpleName":"B"}',
            "duplicate CrowdStrike JSON key",
        ),
        ("[]", "must be a CrowdStrike JSON object"),
        (json.dumps({"timestamp": "1"}), "missing CrowdStrike event identity"),
        (
            crowdstrike_record(timestamp=None),
            "missing CrowdStrike timestamp",
        ),
        (
            crowdstrike_record(timestamp="not-a-number"),
            "invalid CrowdStrike timestamp",
        ),
        (
            crowdstrike_record(timestamp="9" * 100),
            "invalid CrowdStrike timestamp",
        ),
    ],
)
def test_parse_crowdstrike_rejects_invalid_records(raw: str, message: str) -> None:
    with pytest.raises(RawImportError, match=message):
        parse_crowdstrike_json(raw, origin=Path("falcon.log"), line_number=9)


def test_import_raw_files_handles_multiline_xml_json_and_blanks(tmp_path: Path) -> None:
    sysmon = tmp_path / "sysmon source.log"
    multiline = windows_event(
        record_id="1",
        data={"CommandLine": "powershell.exe\nWrite-Output test\nGet-Date"},
    )
    sysmon.write_text(f"\n{multiline}\n", encoding="utf-8")
    falcon = tmp_path / "falcon.log"
    falcon.write_text(crowdstrike_record() + "\n", encoding="utf-8")

    alerts = import_raw_files([sysmon, falcon])

    assert len(alerts) == 2
    assert alerts[0]["command_line"] == "powershell.exe\nWrite-Output test\nGet-Date"
    assert alerts[1]["event_type"] == "crowdstrike_process_rollup2"


def test_import_raw_files_rejects_duplicate_ids(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.log"
    record = windows_event(record_id="1")
    source.write_text(f"{record}\n{record}\n", encoding="utf-8")

    with pytest.raises(RawImportError, match="duplicate imported alert ID"):
        import_raw_files([source])


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("plain text\n", "unsupported telemetry record"),
        ("<Event>\n", "unterminated Windows event XML"),
        ("\n\n", "contains no records"),
    ],
)
def test_import_raw_files_rejects_unsupported_or_empty_data(
    tmp_path: Path, content: str, message: str
) -> None:
    source = tmp_path / "input.log"
    source.write_text(content, encoding="utf-8")

    with pytest.raises(RawImportError, match=message):
        import_raw_files([source])


def test_import_raw_files_reports_file_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(RawImportError, match="raw telemetry file not found"):
        import_raw_files([tmp_path / "missing.log"])

    with pytest.raises(RawImportError, match="cannot read raw telemetry file"):
        import_raw_files([tmp_path])

    invalid_utf8 = tmp_path / "invalid.log"
    invalid_utf8.write_bytes(b"\xff\xfe\xff")
    with pytest.raises(RawImportError, match="not valid UTF-8"):
        import_raw_files([invalid_utf8])

    class BrokenReader:
        def __enter__(self) -> BrokenReader:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def __iter__(self) -> BrokenReader:
            return self

        def __next__(self) -> str:
            raise OSError("synthetic iteration failure")

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: BrokenReader())
    with pytest.raises(RawImportError, match="synthetic iteration failure"):
        import_raw_files([tmp_path / "broken.log"])


def test_run_import_writes_alerts_loadable_by_core_pipeline(tmp_path: Path) -> None:
    source = tmp_path / "sysmon.log"
    source.write_text(windows_event(record_id="42"), encoding="utf-8")
    output = tmp_path / "normalized.json"

    count = run_import([source], output)

    assert count == 1
    loaded = load_alerts(output)
    assert loaded[0]["alert_id"] == "SPLUNK-sysmon-42"


def test_run_import_protects_raw_input(tmp_path: Path) -> None:
    source = tmp_path / "sysmon.log"
    original = windows_event(record_id="42")
    source.write_text(original, encoding="utf-8")

    with pytest.raises(RawImportError, match="cannot overwrite a raw input"):
        run_import([source], source)

    assert source.read_text(encoding="utf-8") == original


def test_main_reports_success(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "sysmon.log"
    source.write_text(windows_event(record_id="42"), encoding="utf-8")
    output = tmp_path / "normalized.json"

    exit_code = main(["--input", str(source), "--output", str(output)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Imported 1 raw telemetry records" in captured.out
    assert f"Output written to {output}." in captured.out


def test_main_reports_domain_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "normalized.json"

    exit_code = main(
        ["--input", str(tmp_path / "missing.log"), "--output", str(output)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "error: raw telemetry file not found" in captured.err


def test_build_parser_collects_repeated_inputs() -> None:
    args = build_parser().parse_args(
        ["--input", "one.log", "--input", "two.log", "--output", "alerts.json"]
    )

    assert args.input == [Path("one.log"), Path("two.log")]
    assert args.output == Path("alerts.json")
