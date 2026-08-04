"""Adapters from raw Windows/CrowdStrike telemetry to normalized alerts."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Sequence

from .errors import DeduplicatorError, RawImportError
from .io import Alert, write_incidents

WINDOWS_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = {"event": WINDOWS_EVENT_NS}
_SHA256 = re.compile(r"(?:^|[,;\s])SHA256=([0-9a-fA-F]{64})(?:$|[,;\s])")
_DIRECT_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_NON_SLUG = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")

SYSMON_EVENT_NAMES = {
    1: "process_creation",
    2: "file_creation_time_changed",
    3: "network_connection",
    4: "sysmon_service_state_changed",
    5: "process_terminated",
    6: "driver_loaded",
    7: "image_loaded",
    8: "create_remote_thread",
    9: "raw_access_read",
    10: "process_access",
    11: "file_created",
    12: "registry_object_created_or_deleted",
    13: "registry_value_set",
    14: "registry_object_renamed",
    15: "file_create_stream_hash",
    16: "sysmon_configuration_changed",
    17: "named_pipe_created",
    18: "named_pipe_connected",
    22: "dns_query",
    23: "file_deleted",
    25: "process_tampering",
    26: "file_delete_detected",
}

WINDOWS_SECURITY_EVENT_NAMES = {
    4688: "process_creation",
}


class _DuplicateRawJsonKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateRawJsonKey(key)
        result[key] = value
    return result


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _first_text(values: Sequence[object]) -> str | None:
    for value in values:
        text = _optional_text(value)
        if text is not None and text != "-":
            return text
    return None


def _windows_basename(value: object) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    return PureWindowsPath(text).name or text


def _extract_sha256(value: object) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    direct = _DIRECT_SHA256.fullmatch(text)
    digest = direct.group(0) if direct else None
    if digest is None:
        match = _SHA256.search(text)
        digest = match.group(1) if match else None
    if digest is None or digest == "0" * 64:
        return None
    return digest.lower()


def _slug(value: str) -> str:
    return _NON_SLUG.sub("-", value.casefold()).strip("-")


def _snake_case(value: str) -> str:
    return _CAMEL_BOUNDARY.sub("_", value).replace("-", "_").casefold()


def _xml_data(root: ET.Element) -> dict[str, str]:
    fields: dict[str, str] = {}
    for node in root.findall("event:EventData/event:Data", _NS):
        name = node.get("Name")
        if name:
            fields[name] = node.text or ""
    return fields


def _xml_required_text(
    root: ET.Element, path: str, *, path_name: str, origin: Path, line_number: int
) -> str:
    node = root.find(path, _NS)
    text = node.text.strip() if node is not None and node.text else ""
    if not text:
        raise RawImportError(
            f"{origin.name} line {line_number} is missing Windows event {path_name}"
        )
    return text


def _sysmon_severity(event_id: int, data: dict[str, str]) -> str:
    target = (_windows_basename(data.get("TargetImage")) or "").casefold()
    if event_id == 10 and target == "lsass.exe":
        return "critical"
    if event_id in {8, 9, 10, 25}:
        return "high"
    if event_id in {1, 3, 6, 7, 11, 12, 13, 14, 15, 17, 18, 22, 23, 26}:
        return "low"
    return "informational"


def _xml_context_description(provider: str, event_id: int, data: dict[str, str]) -> str:
    context = _first_text(
        [
            data.get("TargetImage"),
            data.get("TargetFilename"),
            data.get("TargetObject"),
            data.get("DestinationHostname"),
            data.get("QueryName"),
            data.get("NewProcessName"),
            data.get("Image"),
        ]
    )
    description = f"Imported {provider} event {event_id} from Splunk Attack Data."
    return f"{description} Context: {context}." if context else description


def parse_windows_event_xml(text: str, *, origin: Path, line_number: int) -> Alert:
    """Convert one Windows Event XML record into the normalized alert contract."""

    try:
        root = ET.fromstring(text.lstrip("\ufeff"))
    except ET.ParseError as exc:
        raise RawImportError(
            f"invalid Windows event XML in {origin.name} at line {line_number}: {exc}"
        ) from exc

    if root.tag != f"{{{WINDOWS_EVENT_NS}}}Event":
        raise RawImportError(
            f"{origin.name} line {line_number} is not a Windows Event XML record"
        )

    provider_node = root.find("event:System/event:Provider", _NS)
    provider = provider_node.get("Name", "") if provider_node is not None else ""
    if not provider:
        raise RawImportError(
            f"{origin.name} line {line_number} is missing Windows event provider"
        )

    event_id_text = _xml_required_text(
        root,
        "event:System/event:EventID",
        path_name="ID",
        origin=origin,
        line_number=line_number,
    )
    try:
        event_id = int(event_id_text)
    except ValueError as exc:
        raise RawImportError(
            f"{origin.name} line {line_number} has a non-numeric Windows event ID"
        ) from exc

    time_node = root.find("event:System/event:TimeCreated", _NS)
    timestamp = time_node.get("SystemTime", "") if time_node is not None else ""
    if not timestamp:
        raise RawImportError(
            f"{origin.name} line {line_number} is missing Windows event timestamp"
        )
    computer = _xml_required_text(
        root,
        "event:System/event:Computer",
        path_name="computer",
        origin=origin,
        line_number=line_number,
    )
    record_id = _xml_required_text(
        root,
        "event:System/event:EventRecordID",
        path_name="record ID",
        origin=origin,
        line_number=line_number,
    )
    data = _xml_data(root)

    is_sysmon = provider.casefold() == "microsoft-windows-sysmon"
    if is_sysmon:
        event_name = SYSMON_EVENT_NAMES.get(event_id, f"event_{event_id}")
        event_type = f"sysmon_{event_id}_{event_name}"
        source = "splunk-attack-data/sysmon"
        severity = _sysmon_severity(event_id, data)
        process_value = (
            data.get("SourceImage") if event_id in {8, 10} else data.get("Image")
        )
        process_name = _windows_basename(
            _first_text([process_value, data.get("Image"), data.get("NewProcessName")])
        )
        parent_process_name = _windows_basename(data.get("ParentImage"))
        default_rule = f"Sysmon Event {event_id}: {event_name.replace('_', ' ')}"
    else:
        event_name = WINDOWS_SECURITY_EVENT_NAMES.get(event_id, f"event_{event_id}")
        event_type = f"windows_security_{event_id}_{event_name}"
        source = "splunk-attack-data/windows-security"
        severity = "low" if event_id == 4688 else "informational"
        process_name = _windows_basename(
            _first_text([data.get("NewProcessName"), data.get("Image")])
        )
        parent_process_name = _windows_basename(
            _first_text([data.get("ParentProcessName"), data.get("ParentImage")])
        )
        default_rule = f"Windows Security Event {event_id}"

    user = _first_text(
        [
            data.get("User"),
            data.get("TargetUserName"),
            data.get("SubjectUserName"),
            data.get("SourceUser"),
            data.get("TargetUser"),
        ]
    )
    rule_name = _first_text([data.get("RuleName"), default_rule])
    alert: Alert = {
        "alert_id": f"SPLUNK-{_slug(origin.stem)}-{record_id}",
        "timestamp": timestamp,
        "source": source,
        "host": computer,
        "event_type": event_type,
        "severity": severity,
        "user": user,
        "process_name": process_name,
        "target_process_name": _windows_basename(data.get("TargetImage")),
        "parent_process_name": parent_process_name,
        "command_line": _first_text([data.get("CommandLine")]),
        "file_hash": _extract_sha256(
            _first_text([data.get("Hashes"), data.get("ConfigurationFileHash")])
        ),
        "rule_name": rule_name,
        "description": _xml_context_description(provider, event_id, data),
    }
    return alert


def _epoch_milliseconds_to_iso8601(
    value: object, *, origin: Path, line_number: int
) -> str:
    text = _optional_text(value)
    try:
        milliseconds = int(text) if text is not None else None
    except ValueError as exc:
        raise RawImportError(
            f"{origin.name} line {line_number} has an invalid CrowdStrike timestamp"
        ) from exc
    if milliseconds is None:
        raise RawImportError(
            f"{origin.name} line {line_number} is missing CrowdStrike timestamp"
        )
    try:
        timestamp = datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise RawImportError(
            f"{origin.name} line {line_number} has an invalid CrowdStrike timestamp"
        ) from exc
    return timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _crowdstrike_severity(event_name: str, record: dict[str, Any]) -> str:
    target = (_optional_text(record.get("TargetFileName")) or "").casefold()
    if event_name == "ProcessHandleOpDetectInfo" or (
        event_name == "DmpFileWritten" and "lsass" in target
    ):
        return "critical"
    if event_name in {"DmpFileWritten", "FileDeleteInfo"}:
        return "high"
    if event_name in {"ProcessRollup2", "SyntheticProcessRollup2"}:
        return "low"
    return "medium"


def parse_crowdstrike_json(text: str, *, origin: Path, line_number: int) -> Alert:
    """Convert one CrowdStrike Falcon JSON-line record into a normalized alert."""

    try:
        payload = json.loads(
            text.lstrip("\ufeff"), object_pairs_hook=_reject_duplicate_json_keys
        )
    except _DuplicateRawJsonKey as exc:
        raise RawImportError(
            f"duplicate CrowdStrike JSON key in {origin.name} at line "
            f"{line_number}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise RawImportError(
            f"invalid CrowdStrike JSON in {origin.name} at line {line_number}: "
            f"{exc.msg}"
        ) from exc
    if not isinstance(payload, dict):
        raise RawImportError(
            f"{origin.name} line {line_number} must be a CrowdStrike JSON object"
        )

    event_name = _optional_text(payload.get("event_simpleName"))
    record_id = _optional_text(payload.get("id"))
    if event_name is None or record_id is None:
        raise RawImportError(
            f"{origin.name} line {line_number} is missing CrowdStrike event identity"
        )

    process_name = _windows_basename(payload.get("ImageFileName"))
    target_file = _optional_text(payload.get("TargetFileName"))
    context = _first_text(
        [
            target_file,
            payload.get("ImageFileName"),
            payload.get("CommandLine"),
        ]
    )
    description = f"Imported CrowdStrike {event_name} from Splunk Attack Data."
    if context:
        description = f"{description} Context: {context}."

    return {
        "alert_id": f"SPLUNK-{_slug(origin.stem)}-{record_id}",
        "timestamp": _epoch_milliseconds_to_iso8601(
            payload.get("timestamp"), origin=origin, line_number=line_number
        ),
        "source": "splunk-attack-data/crowdstrike-falcon",
        "host": _first_text([payload.get("ComputerName"), payload.get("aid")])
        or "unknown-endpoint",
        "event_type": f"crowdstrike_{_snake_case(event_name)}",
        "severity": _crowdstrike_severity(event_name, payload),
        "user": _first_text([payload.get("UserName"), payload.get("UserSid")]),
        "process_name": process_name,
        "target_process_name": _windows_basename(payload.get("TargetImageFileName")),
        "parent_process_name": _windows_basename(
            _first_text(
                [payload.get("ParentBaseFileName"), payload.get("ParentImageFileName")]
            )
        ),
        "command_line": _first_text([payload.get("CommandLine")]),
        "file_hash": _extract_sha256(payload.get("SHA256HashData")),
        "rule_name": f"CrowdStrike {event_name}",
        "description": description,
    }


def import_raw_files(paths: Sequence[Path]) -> list[Alert]:
    """Import Windows Event XML streams and CrowdStrike JSON-line records."""

    alerts: list[Alert] = []
    seen_ids: set[str] = set()
    for path in paths:
        try:
            handle = path.open("r", encoding="utf-8-sig")
        except FileNotFoundError as exc:
            raise RawImportError(f"raw telemetry file not found: {path}") from exc
        except OSError as exc:
            raise RawImportError(
                f"cannot read raw telemetry file {path}: {exc}"
            ) from exc

        try:
            with handle:
                xml_parts: list[str] = []
                xml_start_line = 0
                for line_number, raw_line in enumerate(handle, start=1):
                    stripped = raw_line.strip()
                    if xml_parts:
                        xml_parts.append(raw_line)
                        if "</Event>" not in raw_line:
                            continue
                        text = "".join(xml_parts).strip()
                        record_line = xml_start_line
                        xml_parts.clear()
                        alert = parse_windows_event_xml(
                            text, origin=path, line_number=record_line
                        )
                    elif not stripped:
                        continue
                    elif stripped.startswith("<Event"):
                        if "</Event>" not in raw_line:
                            xml_parts.append(raw_line)
                            xml_start_line = line_number
                            continue
                        alert = parse_windows_event_xml(
                            stripped, origin=path, line_number=line_number
                        )
                    elif stripped.startswith("{") or stripped.startswith("["):
                        alert = parse_crowdstrike_json(
                            stripped, origin=path, line_number=line_number
                        )
                    else:
                        raise RawImportError(
                            f"unsupported telemetry record in {path.name} at line "
                            f"{line_number}; expected Windows Event XML or JSON Lines"
                        )

                    alert_id = alert["alert_id"]
                    if alert_id in seen_ids:
                        raise RawImportError(
                            f"duplicate imported alert ID {alert_id} in {path.name}"
                        )
                    seen_ids.add(alert_id)
                    alerts.append(alert)

                if xml_parts:
                    raise RawImportError(
                        f"unterminated Windows event XML in {path.name} at line "
                        f"{xml_start_line}"
                    )
        except UnicodeDecodeError as exc:
            raise RawImportError(
                f"raw telemetry file is not valid UTF-8: {path}"
            ) from exc
        except OSError as exc:
            raise RawImportError(
                f"cannot read raw telemetry file {path}: {exc}"
            ) from exc
    if not alerts:
        raise RawImportError("raw telemetry input contains no records")
    return alerts


def run_import(input_paths: Sequence[Path], output_path: Path) -> int:
    """Import raw telemetry, atomically write normalized JSON, and return its count."""

    resolved_output = output_path.resolve(strict=False)
    if any(resolved_output == path.resolve(strict=False) for path in input_paths):
        raise RawImportError(
            f"output path cannot overwrite a raw input file: {output_path}"
        )
    alerts = import_raw_files(input_paths)
    write_incidents(output_path, alerts, protected_paths=tuple(input_paths))
    return len(alerts)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-alert-import-raw",
        description=(
            "Convert newline-delimited Windows Event XML and CrowdStrike JSON "
            "telemetry into normalized alert JSON."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        help="raw .log path; repeat this option to combine files",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="path for the normalized JSON alert array",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        count = run_import(args.input, args.output)
    except DeduplicatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Imported {count} raw telemetry records into normalized alerts.")
    print(f"Output written to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
